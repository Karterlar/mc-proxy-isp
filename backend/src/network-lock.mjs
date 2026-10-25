import path from 'node:path';
import { lstat, readFile, realpath, rm, open } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { UserError, TUN_NETWORK } from './config.mjs';
import { createPrivateDirectory, writePrivate, renamePrivate as rename } from './private-files.mjs';
import { createWindowsNetworkLockAdapter, sanitizeNetworkLockDiagnostic } from './windows-network-lock.mjs';
import { createWfpNetworkLockManager } from './wfp-network-lock.mjs';

const PREFIX = 'ProxyPilot-Lock-';
const copy = value => structuredClone(value);
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(canonical(value))).digest('hex');
const fail = (code, message) => { throw new UserError(code, message); };
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const profileNames = ['Domain', 'Private', 'Public'];
const phases = ['preparing', 'arming', 'armed', 'attaching', 'active', 'unlocking', 'unlocked', 'repairing'];
const ownRule = name => typeof name === 'string' && name.startsWith(PREFIX);
const validProtocol = value => value === undefined || ['TCP', 'UDP'].includes(value);
const sameEndpoint = (a, b) => equal({ ...a, protocol: a.protocol || 'TCP' }, { ...b, protocol: b.protocol || 'TCP' });
const failureCodes = new Set(['ADMIN_REQUIRED', 'PLATFORM_UNSUPPORTED', 'NETWORK_LOCK_TIMEOUT', 'NETWORK_LOCK_WINDOWS_FAILED', 'NETWORK_LOCK_RESPONSE_INVALID',
  'NETWORK_LOCK_INSPECTION_FAILED', 'NETWORK_LOCK_CONFLICT', 'NETWORK_LOCK_EXPORT_FAILED', 'NETWORK_LOCK_IMPORT_FAILED', 'NETWORK_LOCK_VERIFY_FAILED', 'NETWORK_LOCK_RECOVERY_REQUIRED', 'NETWORK_LOCK_RESTORE_FAILED']);
function failureDetails(cause, operation) {
  const diagnostic = sanitizeNetworkLockDiagnostic(cause?.diagnostic, operation || cause?.diagnostic?.operation);
  return { errorCode: failureCodes.has(cause?.code) ? cause.code : 'NETWORK_LOCK_INSPECTION_FAILED',
    ...(['inspect', 'inspect-orphans'].includes(operation || diagnostic?.operation) ? { inspectionFailed: true } : {}), ...(diagnostic ? { diagnostic } : {}) };
}
// PersistentStore represents an unset interface exclusion as this sentinel;
// ActiveStore resolves it to null, serialized by the adapter as ['']. Preserve
// these snapshot forms so
// existing recovery journals and exact restoration checks remain compatible.
const hasInterfaceExclusions = aliases => aliases != null && (!Array.isArray(aliases)
  || (aliases.length > 0 && !(aliases.length === 1 && ['NotConfigured', ''].includes(aliases[0]))));
const policy = state => ({ profiles: state.profiles, rules: state.rules, settings: state.settings, ipsecRules: state.ipsecRules });
const without = (value, keys) => Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
function lockRules(id, endpoint, corePath) {
  const rule = (suffix, values) => ({ name: `${PREFIX}${id}-${suffix}`, enabled: 'True', direction: 'Outbound', action: 'Allow', profile: 'Any', protocol: 'TCP', program: 'Any', remoteAddress: ['Any'], remotePort: ['Any'], interfaceAlias: ['Any'], ...values });
  return [
    rule('isp', { program: path.resolve(corePath), protocol: endpoint.protocol || 'TCP', remoteAddress: [endpoint.ip], remotePort: [String(endpoint.port)] }),
    rule('loopback', { remoteAddress: ['127.0.0.1', '::1'] }),
    rule('tun-tcp', { interfaceAlias: [TUN_NETWORK.interfaceName] }),
    rule('tun-dns', { interfaceAlias: [TUN_NETWORK.interfaceName], protocol: 'UDP', remotePort: ['53'] }),
  ];
}

export function networkLockBinding({ upstream, relay, corePath, proxyPort, vpnNodeHash, physical }) {
  const binding = { upstream: { type: upstream.type, host: upstream.host, port: upstream.port, tls: upstream.tls || null }, corePath: path.resolve(corePath).toLowerCase(), proxyPort };
  // Preserve legacy bindings so existing persistent locks remain recoverable.
  // With a chain, the outer TLS identity is also part of the physical exception.
  if (relay) binding.relay = { type: relay.type, host: relay.host, port: relay.port, tls: relay.tls };
  if (vpnNodeHash !== undefined || physical !== undefined) {
    if (typeof vpnNodeHash !== 'string' || !/^[0-9a-f]{64}$/.test(vpnNodeHash) || typeof physical?.host !== 'string' || !physical.host || physical.host.length > 253 || /[\s\0]/.test(physical.host)
      || !Number.isInteger(physical.port) || physical.port < 1 || physical.port > 65535 || !['TCP', 'UDP'].includes(physical.protocol)) fail('NETWORK_LOCK_INPUT_INVALID', 'Imported network lock requires a verified node hash and physical endpoint protocol');
    binding.vpnNodeHash = vpnNodeHash;
    binding.physical = { host: physical.host, port: physical.port, protocol: physical.protocol };
  }
  return hash(binding);
}

export function createMockNetworkLockAdapter() {
  let state = { admin: true, serviceRunning: true, governed: false, ipsecRules: 0, settings: {},
    profiles: profileNames.map(name => ({ name, enabled: 'True', defaultOutboundAction: 'Allow', disabledInterfaceAliases: [], allowLocalFirewallRules: 'True' })), rules: [], activeProfiles: [], activeAllowRules: [] };
  let backup;
  const observed = () => {
    const out = copy(state);
    out.activeProfiles = copy(out.profiles);
    out.activeAllowRules = out.rules.filter(rule => rule.enabled === 'True' && rule.direction === 'Outbound' && rule.action === 'Allow').map(rule => ({ ...rule, source: 'Local' }));
    return out;
  };
  return {
    inspect: async () => observed(),
    exportPolicy: async () => { backup = copy(state); return Buffer.from('mock-policy'); },
    importPolicy: async () => { state = copy(backup); },
    setProfiles: async profiles => { for (const value of profiles) Object.assign(state.profiles.find(profile => profile.name === value.name), value); },
    disableRules: async names => { for (const name of names) state.rules.find(rule => rule.name === name).enabled = 'False'; },
    addRules: async rules => { state.rules.push(...copy(rules)); },
  };
}

export function createNetworkLockManager({ stateDir, adapter, mock = false, now = Date.now, dependencies = {}, onProgress = () => {}, helperPath, engine = 'legacy-recovery' } = {}) {
  const options={stateDir,adapter,mock,now,dependencies,onProgress,helperPath};
  // Explicit old adapters and mock sessions remain inert test fixtures. A real
  // version-1 journal is recovery-only; new locks never disable foreign rules.
  if(mock||adapter)return createLegacyNetworkLockManager(options);
  // The new native lock is intentionally isolated from the validated proxy
  // path. Normal clients retain legacy inspection/recovery, but cannot create
  // another broad firewall lock. Only explicit development injection opts in.
  if (engine !== 'wfp') {
    const legacy = createLegacyNetworkLockManager(options);
    const describe = result => ({ ...result, canArm: false, developmentPaused: true });
    return {
      ...legacy, canArm: false,
      snapshot: () => describe(legacy.snapshot()),
      status: async input => describe(await legacy.status(input)),
      reload: async () => describe(await legacy.reload()),
      unlock: async input => describe(await legacy.unlock(input)),
      arm: async () => fail('NETWORK_LOCK_DISABLED', 'New network locks are disabled while the validated proxy path remains unchanged'),
    };
  }
  if(!stateDir||!path.isAbsolute(stateDir))fail('NETWORK_LOCK_PATH_INVALID','The network lock needs an absolute private state directory');
  const wfp=createWfpNetworkLockManager(options),legacy=createLegacyNetworkLockManager(options);
  let selected;
  async function select(){
    if(selected)return selected;
    const file=path.join(stateDir,'journal.json');
    let record;
    try {
      const info=await lstat(file);
      if(!info.isFile()||info.isSymbolicLink()||info.size>8*1024*1024||path.resolve(await realpath(file)).toLowerCase()!==path.resolve(file).toLowerCase())throw new Error();
      record=JSON.parse(await readFile(file,'utf8'));
    } catch(cause){if(cause.code!=='ENOENT')fail('NETWORK_LOCK_STATE_INVALID','Network lock recovery records are invalid');}
    if(record?.version===1&&record.phase!=='unlocked')return selected=legacy;
    if(!record){const previous=await legacy.status({force:true});if(previous.state==='conflict')return selected=legacy;if(previous.inspectionFailed)fail('NETWORK_LOCK_INSPECTION_FAILED','Legacy firewall recovery could not be inspected');}
    return selected=wfp;
  }
  const describe=result=>selected===legacy?{...result,engine:'windows-firewall-legacy',legacy:true}:result;
  return {
    snapshot:()=>describe((selected||wfp).snapshot()),
    status:async options=>describe(await (await select()).status(options)),
    reload:async()=>{selected=null;return describe(await (await select()).reload());},
    arm:async input=>{const manager=await select();if(manager===legacy)fail('NETWORK_LOCK_LEGACY_RECOVERY_REQUIRED','Recover and unlock the legacy firewall policy before enabling the new network lock');return manager.arm(input);},
    attachTun:async()=>{const manager=await select();if(manager===legacy)fail('NETWORK_LOCK_LEGACY_RECOVERY_REQUIRED','Recover and unlock the legacy firewall policy before using a new protected session');return manager.attachTun();},
    unlock:async input=>describe(await (await select()).unlock(input)),
  };
}

// Kept solely for old recovery records and injected compatibility test adapters.
export function createLegacyNetworkLockManager({ stateDir, adapter, mock = false, now = Date.now, dependencies = {}, onProgress = () => {} } = {}) {
  if (!mock && (!stateDir || !path.isAbsolute(stateDir))) fail('NETWORK_LOCK_PATH_INVALID', 'The network lock needs an absolute private state directory');
  const directory = stateDir && path.resolve(stateDir);
  const journalPath = directory && path.join(directory, 'journal.json');
  const fs = { lstat, readFile, realpath, rename, rm, open, createPrivateDirectory, writePrivate, ...dependencies };
  const windows = mock ? createMockNetworkLockAdapter() : (adapter || createWindowsNetworkLockAdapter());
  let record = null; let loaded = false; let serial = Promise.resolve(); let cachedAt = null; let lastInspection = null;
  let cached = { state: 'unknown', status: 'unknown', locked: false, persistent: true, canUnlock: false, mock, allowedEndpoint: null };
  const locked = work => { const task = serial.then(work, work); serial = task.catch(() => {}); return task; };
  const progress = (stage, message) => { try { onProgress({ stage, message }); } catch {} };

  async function safe(file) {
    if (!directory || !file || (file !== directory && !file.startsWith(directory + path.sep))) fail('NETWORK_LOCK_PATH_INVALID', 'Unsafe network lock recovery path');
    let current = path.parse(file).root;
    for (const segment of file.slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, segment);
      let info;
      try { info = await fs.lstat(current); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (info.isSymbolicLink() || path.resolve(await fs.realpath(current)).toLowerCase() !== current.toLowerCase()) fail('NETWORK_LOCK_PATH_INVALID', 'Network lock recovery paths must not contain links');
    }
  }
  async function save(value) {
    if (mock) { record = copy(value); return; }
    await safe(journalPath);
    const temporary = path.join(directory, `${randomUUID()}.tmp`);
    try {
      await fs.writePrivate(temporary, JSON.stringify(value));
      const handle = await fs.open(temporary, 'r+');
      try { await handle.sync(); } finally { await handle.close(); }
      await safe(journalPath);
      await fs.rename(temporary, journalPath);
      record = copy(value);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  async function load() {
    if (loaded) return;
    if (!mock) {
      await safe(directory);
      try { const info = await fs.lstat(directory); if (!info.isDirectory()) fail('NETWORK_LOCK_PATH_INVALID', 'Network lock state is not a directory'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; await fs.createPrivateDirectory(directory); }
      await safe(journalPath);
      let found = false;
      try { record = JSON.parse(await fs.readFile(journalPath, 'utf8')); found = true; }
      catch (error) { if (error.code !== 'ENOENT') fail('NETWORK_LOCK_STATE_INVALID', 'Network lock recovery journal is unreadable; firewall policy was not changed'); }
      if (found && (!record || typeof record !== 'object' || Array.isArray(record) || !phases.includes(record.phase))) fail('NETWORK_LOCK_STATE_INVALID', 'Network lock recovery journal is invalid; firewall policy was not changed');
      if (record && (record.version !== 1 || !/^[0-9a-f-]{36}$/.test(record.id) || !/^[0-9a-f]{64}$/.test(record.binding) || !isIP(record.endpoint?.ip || '') || !Number.isInteger(record.endpoint.port) || record.endpoint.port < 1 || record.endpoint.port > 65535 || !validProtocol(record.endpoint.protocol) || !path.isAbsolute(record.corePath || '') || !Array.isArray(record.before?.profiles) || !Array.isArray(record.before?.rules) || !Array.isArray(record.rules) || !equal(record.rules, lockRules(record.id, record.endpoint, record.corePath)))) fail('NETWORK_LOCK_STATE_INVALID', 'Network lock recovery journal is invalid; firewall policy was not changed');
    }
    loaded = true;
  }
  const publish = (state, reason, extra = {}) => {
    cachedAt = now();
    cached = { state, status: state, locked: state === 'locked', persistent: true, canUnlock: Boolean(record && !['unlocked', 'repairing'].includes(record.phase) && state !== 'conflict'), mock,
      allowedEndpoint: record && record.phase !== 'unlocked' ? copy(record.endpoint) : null, binding: record && record.phase !== 'unlocked' ? record.binding : null,
      journalPath: mock ? null : journalPath, ...(reason ? { reason } : {}), ...extra };
    return copy(cached);
  };
  function validateInspection(state) {
    if (!state || !Array.isArray(state.profiles) || !Array.isArray(state.rules) || !Array.isArray(state.activeProfiles) || !Array.isArray(state.activeAllowRules) || !equal(state.profiles.map(profile => profile.name).sort(), [...profileNames].sort()) || !equal(state.activeProfiles.map(profile => profile.name).sort(), [...profileNames].sort()) || typeof state.admin !== 'boolean' || typeof state.governed !== 'boolean' || typeof state.serviceRunning !== 'boolean' || state.rules.some(rule => typeof rule.name !== 'string' || !rule.name) || new Set(state.rules.map(rule => rule.name)).size !== state.rules.length) fail('NETWORK_LOCK_INSPECTION_FAILED', 'Cannot verify the complete Windows firewall policy');
  }
  function governed(state) {
    return state.governed || state.ipsecRules !== 0 || state.activeProfiles.some(profile => profile.allowLocalFirewallRules === 'False' || hasInterfaceExclusions(profile.disabledInterfaceAliases))
      || state.profiles.some(profile => hasInterfaceExclusions(profile.disabledInterfaceAliases))
      || state.activeAllowRules.some(rule => rule.source !== 'Local' || !state.rules.some(local => local.name === rule.name));
  }
  function checkTransition(state) {
    if (governed(state)) return 'An unmanaged firewall policy or IPsec policy is active';
    if (!equal(state.settings, record.before.settings) || state.ipsecRules !== record.before.ipsecRules) return 'Firewall global settings changed outside ProxyPilot';
    const initialRules = record.before.rules;
    const currentForeign = state.rules.filter(rule => !ownRule(rule.name));
    if (currentForeign.length !== initialRules.length) return 'Firewall rules were added or removed outside ProxyPilot';
    for (const original of initialRules) {
      const current = currentForeign.find(rule => rule.name === original.name);
      const changed = original.direction === 'Outbound' && original.action === 'Allow' && original.enabled === 'True';
      if (!current || !equal(without(current, changed ? ['enabled'] : []), without(original, changed ? ['enabled'] : [])) || (changed && !['True', 'False'].includes(current.enabled))) return 'A backed-up firewall rule changed outside ProxyPilot';
    }
    for (const original of record.before.profiles) {
      const current = state.profiles.find(profile => profile.name === original.name);
      if (!current || !equal(without(current, ['enabled', 'defaultOutboundAction']), without(original, ['enabled', 'defaultOutboundAction'])) || ![original.enabled, 'True'].includes(current.enabled) || ![original.defaultOutboundAction, 'Block'].includes(current.defaultOutboundAction)) return 'A backed-up firewall profile changed outside ProxyPilot';
    }
    for (const current of state.rules.filter(rule => ownRule(rule.name))) {
      const expected = record.rules.find(rule => rule.name === current.name);
      if (!expected || !ruleMatches(current, expected)) return 'A ProxyPilot firewall rule was modified or replaced';
      if (record.ruleFingerprints?.[current.name] && hash(current) !== record.ruleFingerprints[current.name]) return 'A ProxyPilot firewall rule changed after activation';
    }
    return null;
  }
  function ruleMatches(current, expected) {
    return Object.entries(expected).every(([key, value]) => {
      if (Array.isArray(value)) return Array.isArray(current[key]) && equal([...current[key]].sort(), [...value].sort());
      if (key === 'program') return typeof current[key] === 'string' && current[key].toLowerCase() === value.toLowerCase();
      return equal(current[key], value);
    });
  }
  function securelyLocked(state) {
    if (!state.serviceRunning || checkTransition(state)) return false;
    if (!state.profiles.every(profile => profile.enabled === 'True' && profile.defaultOutboundAction === 'Block') || !state.activeProfiles.every(profile => profile.enabled === 'True' && profile.defaultOutboundAction === 'Block')) return false;
    if (state.rules.some(rule => !ownRule(rule.name) && rule.direction === 'Outbound' && rule.action === 'Allow' && rule.enabled === 'True')) return false;
    if (state.activeAllowRules.some(rule => !record.rules.some(expected => expected.name === rule.name && ruleMatches(rule, expected)))) return false;
    return record.rules.filter(rule => !rule.name.endsWith('-tun-tcp') && !rule.name.endsWith('-tun-dns')).every(expected => state.activeAllowRules.some(rule => rule.name === expected.name && ruleMatches(rule, expected)));
  }
  async function inspectStatus({ force = false } = {}) {
    await load();
    // UI polling is a snapshot read. Safety decisions explicitly force a fresh
    // inspection; repeated inventory reads can block recovery on slow hosts.
    if (!force && cachedAt !== null) return copy(cached);
    if ((!record || record.phase === 'unlocked') && typeof windows.inspectOrphans === 'function') {
      try {
        const observed = await windows.inspectOrphans();
        if (!observed || !Array.isArray(observed.names) || observed.names.length > 10000
          || observed.names.some(name => !ownRule(name)) || new Set(observed.names).size !== observed.names.length) throw new Error();
        return observed.names.length
          ? publish('conflict', 'Orphaned ProxyPilot firewall rules need recovery; no automatic unlock was attempted')
          : publish('unlocked');
      } catch (cause) { return publish('unknown', 'Windows firewall orphan rules could not be inspected', failureDetails(cause, 'inspect-orphans')); }
    }
    let state;
    try { state = await windows.inspect(); validateInspection(state); lastInspection = state; }
    catch (cause) { return publish(record && record.phase !== 'unlocked' ? 'recovery-required' : 'unknown', 'Windows firewall policy could not be inspected', failureDetails(cause, 'inspect')); }
    if (!record || record.phase === 'unlocked') {
      if (state.rules.some(rule => ownRule(rule.name))) return publish('conflict', 'Orphaned ProxyPilot firewall rules need recovery; no automatic unlock was attempted');
      return publish('unlocked');
    }
    if (record.phase === 'preparing' && !record.backupHash && !state.rules.some(rule => ownRule(rule.name))) return publish('recovery-required', 'Backup preparation was interrupted before any firewall mutation; explicit unlock can clear this preparation');
    if (record.phase === 'repairing') return publish('recovery-required', 'Offline network repair is unfinished; complete it before starting another connection');
    const conflict = checkTransition(state);
    if (conflict) return publish('conflict', conflict);
    if (securelyLocked(state)) return publish('locked', null, { tunAllowed: record.rules.filter(rule => rule.name.endsWith('-tun-tcp') || rule.name.endsWith('-tun-dns')).every(expected => state.activeAllowRules.some(rule => rule.name === expected.name && ruleMatches(rule, expected))) });
    return publish('recovery-required', 'Firewall activation or restoration was interrupted; explicit recovery is required');
  }
  async function requireAdmin(state) { if (!state.admin) fail('ADMIN_REQUIRED', 'Administrator privileges are required for the persistent network lock'); }

  return {
    status: options => locked(() => inspectStatus(options)),
    reload: () => locked(async () => {
      if (!mock) { record = null; loaded = false; }
      cachedAt = null; lastInspection = null;
      return inspectStatus({ force: true });
    }),
    snapshot: () => copy(cached),
    arm: input => locked(async () => {
      await load();
      if (!input || !/^[0-9a-f]{64}$/.test(input.binding || '') || !isIP(input.endpoint?.ip || '') || !Number.isInteger(input.endpoint.port) || input.endpoint.port < 1 || input.endpoint.port > 65535 || !validProtocol(input.endpoint.protocol) || !path.isAbsolute(input.corePath || '')) fail('NETWORK_LOCK_INPUT_INVALID', 'Network lock requires a fixed outermost proxy IP, port, protocol and core path');
      progress('checking-firewall', '正在核验 Windows 防火墙规则与管理策略');
      let state = await windows.inspect(); validateInspection(state); await requireAdmin(state);
      if (record && record.phase !== 'unlocked') {
        if (record.phase === 'repairing') fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'Offline network repair must complete before starting another connection');
        if (record.binding !== input.binding || !sameEndpoint(record.endpoint, input.endpoint) || record.corePath.toLowerCase() !== path.resolve(input.corePath).toLowerCase()) fail('NETWORK_LOCK_ENDPOINT_CHANGED', 'Explicitly unlock before switching the relay, ISP endpoint, imported node, protocol or core');
        if (!securelyLocked(state)) fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'Recover the existing firewall lock before starting a new proxy');
        return publish('locked', null, { tunAllowed: record.rules.slice(2).every(expected => state.activeAllowRules.some(rule => rule.name === expected.name && ruleMatches(rule, expected))) });
      }
      if (!state.serviceRunning || governed(state) || state.rules.some(rule => ownRule(rule.name))) fail('NETWORK_LOCK_POLICY_UNSUPPORTED', 'The firewall service, managed policy, interface exclusions or IPsec rules prevent a verifiable local network lock');
      const id = randomUUID();
      const rules = lockRules(id, input.endpoint, input.corePath);
      const draft = { version: 1, id, binding: input.binding, endpoint: copy(input.endpoint), corePath: path.resolve(input.corePath), phase: 'preparing', createdAt: new Date(now()).toISOString(), before: policy(state), rules, ruleFingerprints: {} };
      // Journal and exported backup both exist and are fsynced before mutation.
      await save(draft);
      progress('backing-up-firewall', '正在持久保存原始防火墙策略和恢复日志');
      const backupPath = mock ? null : path.join(directory, `${id}.wfw`);
      if (!mock) await safe(backupPath);
      const mockBackup = await windows.exportPolicy(backupPath);
      const backup = mock ? mockBackup : await fs.readFile(backupPath);
      if (!mock) { const handle = await fs.open(backupPath, 'r+'); try { await handle.sync(); } finally { await handle.close(); } }
      state = await windows.inspect(); validateInspection(state);
      if (!equal(policy(state), draft.before) || governed(state)) fail('NETWORK_LOCK_CONFLICT', 'Firewall policy changed during backup; activation was cancelled');
      await save({ ...record, backupHash: hash(backup), phase: 'arming' });
      progress('locking-network', '正在启用持久断网锁；核心停止后锁继续保持');
      try {
        await windows.setProfiles(profileNames.map(name => ({ name, enabled: 'True', defaultOutboundAction: 'Block' })));
        await windows.disableRules(record.before.rules.filter(rule => rule.enabled === 'True' && rule.direction === 'Outbound' && rule.action === 'Allow').map(rule => rule.name));
        await windows.addRules(record.rules.slice(0, 2));
        state = await windows.inspect(); validateInspection(state);
        if (!securelyLocked(state)) fail('NETWORK_LOCK_VERIFY_FAILED', 'The persistent firewall lock could not be verified');
        const fingerprints = Object.fromEntries(state.rules.filter(rule => ownRule(rule.name)).map(rule => [rule.name, hash(rule)]));
        await save({ ...record, phase: 'armed', ruleFingerprints: fingerprints });
        return publish('locked', null, { tunAllowed: false });
      } catch (error) { publish('recovery-required', 'Firewall changes remain in place; explicit unlock is required', failureDetails(error)); throw error instanceof UserError ? error : new UserError('NETWORK_LOCK_RECOVERY_REQUIRED', 'Firewall activation was interrupted; recovery journal retained'); }
    }),
    attachTun: () => locked(async () => {
      progress('verifying-tun', '正在限定 TUN 网卡访问并核验断网锁');
      const current = await inspectStatus({ force: true });
      if (!current.locked) fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'A verified persistent lock is required before allowing TUN traffic');
      const state = lastInspection; await requireAdmin(state);
      const missing = record.rules.slice(2).filter(expected => !state.rules.some(rule => rule.name === expected.name));
      if (!missing.length && current.tunAllowed) {
        if (record.phase !== 'active') await save({ ...record, phase: 'active', ruleFingerprints: Object.fromEntries(state.rules.filter(rule => ownRule(rule.name)).map(rule => [rule.name, hash(rule)])) });
        return current;
      }
      if (missing.length) {
        await save({ ...record, phase: 'attaching' });
        try { await windows.addRules(missing); }
        catch { fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'The TUN firewall exception could not be created; direct traffic remains locked'); }
      }
      const observed = await windows.inspect(); validateInspection(observed);
      if (!securelyLocked(observed) || !record.rules.every(expected => observed.activeAllowRules.some(rule => rule.name === expected.name && ruleMatches(rule, expected)))) fail('NETWORK_LOCK_VERIFY_FAILED', 'TUN firewall permissions were not verified');
      await save({ ...record, phase: 'active', ruleFingerprints: Object.fromEntries(observed.rules.filter(rule => ownRule(rule.name)).map(rule => [rule.name, hash(rule)])) });
      return publish('locked', null, { tunAllowed: true });
    }),
    unlock: ({ confirm = false } = {}) => locked(async () => {
      if (confirm !== true) fail('CONFIRMATION_REQUIRED', 'Explicit confirmation is required to restore ordinary networking');
      await load();
      if (!record || record.phase === 'unlocked') return inspectStatus({ force: true });
      if (record.phase === 'repairing') fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'Complete the offline repair before attempting ordinary unlock');
      const state = await windows.inspect(); validateInspection(state); await requireAdmin(state);
      if (record.phase === 'preparing' && !record.backupHash && !state.rules.some(rule => ownRule(rule.name))) { await save({ ...record, phase: 'unlocked' }); return publish('unlocked'); }
      const conflict = checkTransition(state);
      if (conflict) { publish('conflict', conflict); fail('NETWORK_LOCK_CONFLICT', `${conflict}; backed-up policy was not imported`); }
      // A crash after the import but before the final journal update is safe to
      // reconcile without importing again or overwriting later changes.
      if (equal(policy(state), record.before)) { await save({ ...record, phase: 'unlocked' }); return publish('unlocked'); }
      const backupPath = mock ? null : path.join(directory, `${record.id}.wfw`);
      if (!mock) {
        await safe(backupPath);
        if (hash(await fs.readFile(backupPath)) !== record.backupHash) fail('NETWORK_LOCK_BACKUP_INVALID', 'Firewall backup changed; automatic restoration was refused');
      } else if (!record.backupHash) fail('NETWORK_LOCK_BACKUP_INVALID', 'No verified firewall backup is available');
      await save({ ...record, phase: 'unlocking' });
      progress('unlocking-network', '正在恢复原始防火墙策略');
      try {
        await windows.importPolicy(backupPath, state);
        const observed = await windows.inspect(); validateInspection(observed);
        if (!equal(policy(observed), record.before)) fail('NETWORK_LOCK_RESTORE_FAILED', 'Firewall restoration could not be verified; journal retained');
        await save({ ...record, phase: 'unlocked' });
        return publish('unlocked');
      } catch (error) { publish('recovery-required', 'Firewall restoration was interrupted; journal retained', failureDetails(error)); throw error instanceof UserError ? error : new UserError('NETWORK_LOCK_RESTORE_FAILED', 'Firewall restoration failed; journal retained'); }
    }),
  };
}
