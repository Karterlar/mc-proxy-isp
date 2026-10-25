import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { createNetworkLockManager, networkLockBinding } from '../src/network-lock.mjs';
import { UserError } from '../src/config.mjs';
import { relayFixture } from './relay-fixture.mjs';

const copy = value => structuredClone(value);
const input = { binding: 'a'.repeat(64), endpoint: { host: 'gateway.provider.test', ip: '192.0.2.9', port: 1080 }, corePath: path.resolve('test-only/sing-box.exe') };

test('production defaults cannot activate experimental WFP or create another broad lock', async t => {
  await mkdir(path.resolve('.cache'), { recursive: true });
  const root = await mkdtemp(path.resolve('.cache/paused-lock-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const manager = createNetworkLockManager({ stateDir: path.join(root, 'network-lock'), helperPath: path.join(root, 'must-not-run.exe') });
  assert.equal(manager.canArm, false);
  assert.equal(manager.snapshot().canArm, false);
  assert.equal(manager.snapshot().developmentPaused, true);
  await assert.rejects(manager.arm(input), { code: 'NETWORK_LOCK_DISABLED' });
  assert.deepEqual(await readdir(root), []);
});

test('relay binding includes the outer endpoint and TLS identity without including account secrets', () => {
  const data = { upstream: { type: 'http', host: 'isp.test', port: 8080 }, corePath: input.corePath, proxyPort: 17890 };
  const relay = relayFixture();
  const original = networkLockBinding({ ...data, relay });
  assert.notEqual(original, networkLockBinding(data));
  assert.notEqual(original, networkLockBinding({ ...data, relay: { ...relay, host: '192.0.2.51' } }));
  assert.notEqual(original, networkLockBinding({ ...data, relay: { ...relay, tls: { ...relay.tls, serverName: 'different.test' } } }));
  assert.equal(original, networkLockBinding({ ...data, relay: { ...relay, username: 'ignored', password: 'ignored' } }));
});

test('legacy binding bytes stay compatible while imported node identity and physical transport are bound', () => {
  const data = { upstream: { type: 'http', host: 'isp.test', port: 8080 }, corePath: input.corePath, proxyPort: 17890 };
  const legacy = { corePath: input.corePath.toLowerCase(), proxyPort: 17890, upstream: { host: 'isp.test', port: 8080, tls: null, type: 'http' } };
  assert.equal(networkLockBinding(data), createHash('sha256').update(JSON.stringify(legacy)).digest('hex'));
  const imported = { ...data, vpnNodeHash: '1'.repeat(64), physical: { host: 'node.fixture.test', port: 443, protocol: 'UDP' } };
  const binding = networkLockBinding(imported);
  assert.notEqual(binding, networkLockBinding(data));
  assert.notEqual(binding, networkLockBinding({ ...imported, vpnNodeHash: '2'.repeat(64) }));
  for (const changed of [{ host: 'changed.fixture.test' }, { port: 8443 }, { protocol: 'TCP' }]) assert.notEqual(binding, networkLockBinding({ ...imported, physical: { ...imported.physical, ...changed } }));
  assert.equal(binding, networkLockBinding({ ...imported, physical: { ...imported.physical, password: 'not-in-binding' }, upstream: { ...imported.upstream, username: 'ignored', password: 'ignored' } }));
  for (const invalid of [{ vpnNodeHash: null }, { vpnNodeHash: [] }, { vpnNodeHash: 'invalid' }, { physical: undefined }, { vpnNodeHash: undefined }, { physical: { ...imported.physical, protocol: 'Any' } }, { physical: { ...imported.physical, protocol: undefined } }, { physical: { ...imported.physical, port: 0 } }]) {
    assert.throws(() => networkLockBinding({ ...imported, ...invalid }), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  }
});
async function fixture(t, { failAt, managerDependencies = {} } = {}) {
  const temporaryRoot = fileURLToPath(new URL('../../.cache/', import.meta.url));
  await mkdir(temporaryRoot, { recursive: true });
  const root = await mkdtemp(path.join(temporaryRoot, 'proxypilot-lock-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = path.join(root, 'lock');
  let current = {
    admin: true, governed: false, serviceRunning: true, settings: { untouched: 'original' }, ipsecRules: 0,
    profiles: ['Domain', 'Private', 'Public'].map(name => ({ name, enabled: name === 'Private' ? 'False' : 'True', defaultOutboundAction: 'NotConfigured', disabledInterfaceAliases: [], allowLocalFirewallRules: 'NotConfigured', details: { inbound: 'Block' } })),
    rules: [
      { name: 'Existing outbound allow', enabled: 'True', direction: 'Outbound', action: 'Allow', profile: 'Any', program: 'old.exe', details: { ports: ['443'], description: 'preserve' } },
      { name: 'Existing inbound allow', enabled: 'True', direction: 'Inbound', action: 'Allow', details: { ports: ['12345'] } },
      { name: 'Previously disabled outbound', enabled: 'False', direction: 'Outbound', action: 'Allow', details: { protocol: 'UDP' } },
    ],
  };
  const original = copy(current);
  const calls = []; let inspectCalls = 0;
  async function mutation(operation) {
    const journal = JSON.parse(await readFile(path.join(stateDir, 'journal.json'), 'utf8'));
    assert.equal(journal.version, 1);
    assert.ok(journal.backupHash, 'a verified backup must be persisted before any firewall change');
    calls.push(operation);
    if (failAt === operation) throw new Error('simulated crash');
  }
  const adapter = {
    inspect: async () => {
      inspectCalls++;
      return { ...copy(current), activeProfiles: copy(current.profiles), activeAllowRules: current.rules.filter(rule => rule.enabled === 'True' && rule.direction === 'Outbound' && rule.action === 'Allow').map(rule => ({ ...copy(rule), source: rule.source || 'Local' })) };
    },
    exportPolicy: async file => { calls.push('export'); await writeFile(file, JSON.stringify(current)); },
    importPolicy: async file => { await mutation('import'); current = JSON.parse(await readFile(file, 'utf8')); },
    setProfiles: async profiles => { await mutation('profiles'); for (const profile of profiles) Object.assign(current.profiles.find(item => item.name === profile.name), profile); },
    disableRules: async names => { await mutation('disable'); for (const name of names) current.rules.find(rule => rule.name === name).enabled = 'False'; },
    addRules: async rules => { await mutation(rules.some(rule => rule.name.endsWith('-tun-tcp')) ? 'add-tun' : 'add-base'); current.rules.push(...copy(rules)); },
  };
  const options = { stateDir, adapter, dependencies: { createPrivateDirectory: directory => mkdir(directory), ...managerDependencies } };
  return { root, stateDir, adapter, options, manager: createNetworkLockManager(options), original, calls, get state() { return current; }, get inspectCalls() { return inspectCalls; } };
}

test('present null, primitive and unknown-phase lock journals fail before firewall inspection or mutation', async t => {
  for (const value of [null, false, 1, 'invalid', [], { phase: 'PRIVATE_UNKNOWN_PHASE' }]) {
    const f = await fixture(t); await mkdir(f.stateDir);
    await writeFile(path.join(f.stateDir, 'journal.json'), JSON.stringify(value));
    await assert.rejects(f.manager.status({ force: true }), { code: 'NETWORK_LOCK_STATE_INVALID' });
    assert.equal(f.inspectCalls, 0); assert.deepEqual(f.calls, []);
  }
  const f = await fixture(t); await f.manager.arm(input);
  const file = path.join(f.stateDir, 'journal.json'); const record = JSON.parse(await readFile(file, 'utf8'));
  await writeFile(file, JSON.stringify({ ...record, phase: 'PRIVATE_UNKNOWN_PHASE' }));
  const before = f.inspectCalls, mutations = f.calls.length;
  await assert.rejects(createNetworkLockManager(f.options).unlock({ confirm: true }), { code: 'NETWORK_LOCK_STATE_INVALID' });
  assert.equal(f.inspectCalls, before); assert.equal(f.calls.length, mutations);
});

test('persistent lock journals before mutation, limits core endpoint, attaches TUN later and restores exact policy only on confirmation', async t => {
  const f = await fixture(t);
  assert.equal((await f.manager.arm(input)).locked, true);
  assert.deepEqual(f.calls, ['export', 'profiles', 'disable', 'add-base']);
  const isp = f.state.rules.find(rule => rule.name.endsWith('-isp'));
  assert.equal(isp.program, input.corePath); assert.deepEqual(isp.remoteAddress, [input.endpoint.ip]); assert.deepEqual(isp.remotePort, ['1080']);
  assert.equal(f.state.rules.filter(rule => rule.name.includes('-tun-')).length, 0, 'no exception references a not-yet-created adapter');
  await f.manager.attachTun();
  const tun = f.state.rules.filter(rule => rule.name.includes('-tun-'));
  assert.equal(tun.length, 2); assert.ok(tun.every(rule => rule.interfaceAlias[0] === 'ProxyPilot'));
  assert.deepEqual(tun.find(rule => rule.protocol === 'UDP').remotePort, ['53']);
  await assert.rejects(f.manager.unlock(), { code: 'CONFIRMATION_REQUIRED' });
  const restarted = createNetworkLockManager(f.options);
  assert.equal((await restarted.status()).locked, true, 'restarting a manager does not unlock firewall policy');
  assert.equal((await restarted.unlock({ confirm: true })).state, 'unlocked');
  assert.deepEqual(f.state, f.original, 'disabled profiles and NotConfigured policy are restored exactly');
});

test('imported TCP and UDP locks permit only the owned core to the pinned node and survive restart without switching nodes', async t => {
  for (const protocol of ['TCP', 'UDP']) {
    const f = await fixture(t);
    const bindingData = { upstream: { type: 'http', host: 'isp.fixture.test', port: 8080 }, corePath: input.corePath, proxyPort: 17890, vpnNodeHash: '1'.repeat(64), physical: { host: 'node.fixture.test', port: 443, protocol } };
    const imported = { ...input, binding: networkLockBinding(bindingData), endpoint: { host: bindingData.physical.host, ip: '192.0.2.44', port: 443, protocol } };
    const armed = await f.manager.arm(imported);
    assert.equal(armed.locked, true); assert.equal(armed.allowedEndpoint.protocol, protocol);
    const outer = f.state.rules.find(rule => rule.name.endsWith('-isp'));
    assert.equal(outer.protocol, protocol); assert.equal(outer.program, input.corePath);
    assert.deepEqual(outer.remoteAddress, ['192.0.2.44']); assert.deepEqual(outer.remotePort, ['443']);
    assert.ok(f.state.profiles.every(profile => profile.enabled === 'True' && profile.defaultOutboundAction === 'Block'));
    assert.ok(f.state.rules.filter(rule => !rule.name.startsWith('ProxyPilot-Lock-') && rule.direction === 'Outbound' && rule.action === 'Allow').every(rule => rule.enabled === 'False'));
    await f.manager.attachTun();
    assert.deepEqual(f.state.rules.find(rule => rule.name.endsWith('-tun-dns')).remotePort, ['53']);
    const restarted = createNetworkLockManager(f.options);
    assert.equal((await restarted.status({ force: true })).locked, true);
    const writes = f.calls.length;
    assert.equal((await restarted.arm(imported)).locked, true); assert.equal(f.calls.length, writes);
    await assert.rejects(restarted.arm({ ...imported, binding: networkLockBinding({ ...bindingData, vpnNodeHash: '2'.repeat(64) }) }), { code: 'NETWORK_LOCK_ENDPOINT_CHANGED' });
    await assert.rejects(restarted.arm({ ...imported, endpoint: { ...imported.endpoint, protocol: protocol === 'TCP' ? 'UDP' : 'TCP' } }), { code: 'NETWORK_LOCK_ENDPOINT_CHANGED' });
    assert.equal(f.calls.length, writes); assert.equal((await restarted.status({ force: true })).locked, true);
    assert.equal((await restarted.unlock({ confirm: true })).state, 'unlocked'); assert.deepEqual(f.state, f.original);
  }
});

test('legacy TCP journals accept explicit TCP without changing rules while invalid protocols fail before inspection', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const writes = f.calls.length;
  const restarted = createNetworkLockManager(f.options);
  assert.equal((await restarted.arm({ ...input, endpoint: { ...input.endpoint, protocol: 'TCP' } })).locked, true);
  assert.equal(f.calls.length, writes);
  assert.equal((await restarted.status({ force: true })).allowedEndpoint.protocol, undefined);
  for (const protocol of [null, 'Any', 'tcp', '6', 6, []]) {
    const fresh = await fixture(t);
    await assert.rejects(fresh.manager.arm({ ...input, endpoint: { ...input.endpoint, protocol } }), { code: 'NETWORK_LOCK_INPUT_INVALID' });
    assert.equal(fresh.inspectCalls, 0); assert.deepEqual(fresh.calls, []);
  }
});

test('tampered imported endpoint protocols and mismatched rule protocols fail before policy inspection or restoration', async t => {
  const f = await fixture(t); await f.manager.arm({ ...input, endpoint: { ...input.endpoint, protocol: 'UDP' } });
  const file = path.join(f.stateDir, 'journal.json'), record = JSON.parse(await readFile(file, 'utf8'));
  const inspections = f.inspectCalls, writes = f.calls.length;
  for (const protocol of [null, 'Any', 'udp', 17, 'TCP']) {
    await writeFile(file, JSON.stringify({ ...record, endpoint: { ...record.endpoint, protocol } }));
    await assert.rejects(createNetworkLockManager(f.options).unlock({ confirm: true }), { code: 'NETWORK_LOCK_STATE_INVALID' });
  }
  await writeFile(file, JSON.stringify({ ...record, rules: record.rules.map(rule => rule.name.endsWith('-isp') ? { ...rule, protocol: 'TCP' } : rule) }));
  await assert.rejects(createNetworkLockManager(f.options).status({ force: true }), { code: 'NETWORK_LOCK_STATE_INVALID' });
  assert.equal(f.inspectCalls, inspections); assert.equal(f.calls.length, writes);
});

test('an interrupted activation retains partial restrictive changes for explicit recovery', async t => {
  const f = await fixture(t, { failAt: 'disable' });
  await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  assert.ok(f.state.profiles.every(profile => profile.defaultOutboundAction === 'Block'));
  assert.equal(f.calls.includes('import'), false, 'failure never silently restores direct networking');
  const restarted = createNetworkLockManager(f.options);
  assert.equal((await restarted.status()).state, 'recovery-required');
  await restarted.unlock({ confirm: true });
  assert.deepEqual(f.state, f.original);
});

test('unfinished offline repair never authorizes a new connection even when firewall still appears locked', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const journalPath = path.join(f.stateDir, 'journal.json');
  const record = JSON.parse(await readFile(journalPath, 'utf8'));
  await writeFile(journalPath, JSON.stringify({ ...record, phase: 'repairing' }));
  const restarted = createNetworkLockManager(f.options);
  const repairStatus = await restarted.status();
  assert.equal(repairStatus.state, 'recovery-required');
  assert.equal(repairStatus.canUnlock, false);
  const before = f.calls.length;
  await assert.rejects(restarted.arm(input), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  await assert.rejects(restarted.unlock({ confirm: true }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  assert.equal(f.calls.length, before);
});

test('Windows NotConfigured interface sentinel survives arm, TUN attachment, restart and exact restoration', async t => {
  const f = await fixture(t);
  for (const profile of f.state.profiles) profile.disabledInterfaceAliases = ['NotConfigured'];
  const original = copy(f.state);
  // Native ActiveStore resolves the PersistentStore sentinel to null; the
  // adapter's Strings() serializes it as ['']. Reproduce that exact output.
  const inspect = f.adapter.inspect;
  f.adapter.inspect = async () => {
    const observed = await inspect();
    for (const profile of observed.activeProfiles) profile.disabledInterfaceAliases = [''];
    return observed;
  };
  assert.equal((await f.manager.arm(input)).locked, true);
  assert.equal((await f.manager.attachTun()).tunAllowed, true);
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.deepEqual(journal.before.profiles, original.profiles, 'native snapshot must not be rewritten');
  const restarted = createNetworkLockManager(f.options);
  assert.equal((await restarted.status({ force: true })).locked, true);
  assert.equal((await restarted.unlock({ confirm: true })).state, 'unlocked');
  assert.deepEqual(f.state, original, 'restore the original sentinel and all profile settings exactly');
});

test('interface sentinel handling never permits real, wildcard, mixed or malformed exclusions', async t => {
  for (const aliases of [['Ethernet'], ['*'], ['NotConfigured', 'Ethernet'], ['NotConfigured', '*'], ['NotConfigured', 'NotConfigured'], ['notconfigured'], 'NotConfigured', ['', 'Ethernet'], ['', '*'], ['', ''], ['', 'NotConfigured']]) {
    for (const store of ['persistent', 'active']) {
      const f = await fixture(t);
      if (store === 'persistent') f.state.profiles[0].disabledInterfaceAliases = aliases;
      else {
        const inspect = f.adapter.inspect;
        f.adapter.inspect = async () => {
          const observed = await inspect();
          observed.activeProfiles[0].disabledInterfaceAliases = aliases;
          return observed;
        };
      }
      await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_POLICY_UNSUPPORTED' }, `${store}: ${JSON.stringify(aliases)}`);
      assert.deepEqual(f.calls, [], 'refuse before exporting or changing policy');
    }
  }
});

test('crash after import but before journal completion reconciles without importing again', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  let completionFailed = false;
  const interrupted = createNetworkLockManager({ ...f.options, dependencies: { ...f.options.dependencies, writePrivate: async (file, contents) => {
    if (JSON.parse(contents).phase === 'unlocked') { completionFailed = true; throw new Error('crash after successful import'); }
    await writeFile(file, contents, { flag: 'wx' });
  } } });
  await assert.rejects(interrupted.unlock({ confirm: true }), { code: 'NETWORK_LOCK_RESTORE_FAILED' });
  assert.equal(completionFailed, true); assert.deepEqual(f.state, f.original);
  const imports = f.calls.filter(call => call === 'import').length;
  const recovered = createNetworkLockManager(f.options);
  assert.equal((await recovered.unlock({ confirm: true })).state, 'unlocked');
  assert.equal(f.calls.filter(call => call === 'import').length, imports);
});

test('failed policy import retains journal and never marks ordinary networking restored', async t => {
  const f = await fixture(t, { failAt: 'import' });
  await f.manager.arm(input);
  await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_RESTORE_FAILED' });
  assert.equal(f.manager.snapshot().state, 'recovery-required');
  assert.ok(f.state.profiles.every(profile => profile.defaultOutboundAction === 'Block'));
  assert.equal(JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8')).phase, 'unlocking');
});

test('external rules, filter changes and global policy changes prevent destructive backup import', async t => {
  for (const mutate of [
    state => state.rules.push({ name: 'external-new-rule', enabled: 'True', direction: 'Outbound', action: 'Allow' }),
    state => { state.rules[0].details.ports = ['80']; },
    state => { state.settings.untouched = 'external'; },
    state => { state.profiles[0].details.inbound = 'Allow'; },
  ]) {
    const f = await fixture(t); await f.manager.arm(input); mutate(f.state);
    assert.equal((await f.manager.status({ force: true })).state, 'conflict');
    await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_CONFLICT' });
    assert.equal(f.calls.includes('import'), false);
  }
});

test('policy source restrictions, IPsec, firewall exclusions and missing admin refuse before mutation', async t => {
  for (const mutate of [
    state => { state.governed = true; },
    state => { state.rules[0].source = 'GroupPolicy'; },
    state => { state.ipsecRules = 1; },
    state => { state.profiles[0].disabledInterfaceAliases = ['Ethernet']; },
    state => { state.serviceRunning = false; },
  ]) {
    const f = await fixture(t); mutate(f.state);
    await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_POLICY_UNSUPPORTED' });
    assert.deepEqual(f.calls, []);
  }
  const f = await fixture(t); f.state.admin = false;
  await assert.rejects(f.manager.arm(input), { code: 'ADMIN_REQUIRED' });
  assert.deepEqual(f.calls, []);
});

test('a failed durable journal write prevents every firewall mutation', async t => {
  const f = await fixture(t, { managerDependencies: { writePrivate: async () => { throw new Error('disk full'); } } });
  await assert.rejects(f.manager.arm(input), /disk full/);
  assert.deepEqual(f.calls, []); assert.deepEqual(f.state, f.original);
});

test('tampered backup is never imported, and different ISP cannot reuse an existing lock', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  await assert.rejects(f.manager.arm({ ...input, binding: 'b'.repeat(64) }), { code: 'NETWORK_LOCK_ENDPOINT_CHANGED' });
  const backup = (await readdir(f.stateDir)).find(name => name.endsWith('.wfw'));
  await writeFile(path.join(f.stateDir, backup), 'tampered');
  await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_BACKUP_INVALID' });
  assert.equal(f.calls.includes('import'), false);
});

test('firewall stopped or an allow rule re-enabled invalidates lock status without auto repair', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  f.state.rules[0].enabled = 'True';
  assert.equal((await f.manager.status({ force: true })).locked, false);
  f.state.rules[0].enabled = 'False'; f.state.serviceRunning = false;
  assert.equal((await f.manager.status({ force: true })).locked, false);
  assert.equal(f.calls.includes('import'), false);
});

test('mock network lock cannot call injected real adapter or filesystem', async () => {
  const forbidden = () => { throw new Error('mock I/O forbidden'); };
  const manager = createNetworkLockManager({ mock: true, adapter: new Proxy({}, { get: forbidden }), dependencies: new Proxy({}, { ownKeys: () => [] }) });
  await manager.arm(input); await manager.attachTun();
  assert.equal((await manager.status()).locked, true);
  assert.equal((await manager.unlock({ confirm: true })).state, 'unlocked');
});

test('status caches expensive inspections and binding does not include secret values', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const count = f.inspectCalls;
  await f.manager.status(); await f.manager.status();
  assert.equal(f.inspectCalls, count);
  const binding = networkLockBinding({ upstream: { host: 'provider.test', port: 1080, type: 'socks' }, corePath: input.corePath, proxyPort: 17890 });
  assert.match(binding, /^[0-9a-f]{64}$/);
});

test('ordinary status remains a lightweight snapshot while force detects changed policy after a long idle', async t => {
  const f = await fixture(t); let clock = 0;
  const manager = createNetworkLockManager({ ...f.options, now: () => clock });
  await manager.arm(input); const inspected = f.inspectCalls;
  f.state.rules[0].enabled = 'True'; clock = 24 * 60 * 60 * 1000;
  assert.equal((await manager.status()).locked, true, 'polling returns the prior observation and does not authorize a safety operation');
  assert.equal(f.inspectCalls, inspected);
  const fresh = await manager.status({ force: true });
  assert.equal(fresh.state, 'recovery-required'); assert.equal(fresh.locked, false);
  assert.equal(f.inspectCalls, inspected + 1);
  assert.deepEqual(await manager.status(), fresh);
  assert.equal(f.calls.includes('import'), false);
});

test('failed full inspections retain the original safe native cause until a successful fresh inspection', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const inspect = f.adapter.inspect; let reads = 0;
  f.adapter.inspect = async () => {
    reads++;
    throw Object.assign(new Error('PRIVATE firewall value'), { code: 'NETWORK_LOCK_TIMEOUT',
      diagnostic: { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout', raw: 'PRIVATE', nativeCode: 1460 } });
  };
  const failed = await f.manager.status({ force: true });
  assert.equal(failed.state, 'recovery-required'); assert.equal(failed.locked, false);
  assert.equal(failed.inspectionFailed, true); assert.equal(failed.errorCode, 'NETWORK_LOCK_TIMEOUT');
  assert.deepEqual(failed.diagnostic, { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout', nativeCode: 1460 });
  assert.doesNotMatch(JSON.stringify(failed), /PRIVATE/);
  assert.deepEqual(await f.manager.status(), failed); assert.deepEqual(f.manager.snapshot(), failed); assert.equal(reads, 1);
  f.adapter.inspect = inspect;
  const recovered = await f.manager.status({ force: true });
  assert.equal(recovered.locked, true); assert.equal(recovered.inspectionFailed, undefined);
  assert.equal(recovered.errorCode, undefined); assert.equal(recovered.diagnostic, undefined);
  assert.equal(f.calls.includes('import'), false, 'read recovery never unlocks or changes firewall policy');
});

test('idle read failures expose only whitelisted codes and inspection diagnostic fields', async t => {
  const f = await fixture(t);
  f.adapter.inspectOrphans = async () => {
    throw Object.assign(new Error('PRIVATE inventory'), { code: 'PRIVATE_CODE', diagnostic: { operation: 'add', command: 'PRIVATE_COMMAND', rule: 'isp', message: 'PRIVATE' } });
  };
  const result = await f.manager.status({ force: true });
  assert.equal(result.state, 'unknown'); assert.equal(result.inspectionFailed, true);
  assert.equal(result.errorCode, 'NETWORK_LOCK_INSPECTION_FAILED');
  assert.deepEqual(result.diagnostic, { operation: 'inspect-orphans' });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE/); assert.equal(f.inspectCalls, 0); assert.deepEqual(f.calls, []);
});

test('a partial disable timeout preserves its native operation and the original restoration journal', async t => {
  const f = await fixture(t);
  f.adapter.disableRules = async () => {
    f.state.rules[0].enabled = 'False';
    throw Object.assign(new UserError('NETWORK_LOCK_TIMEOUT', 'PRIVATE disabled rule'), {
      diagnostic: { operation: 'disable', command: 'powershell.exe', category: 'OperationTimeout', raw: 'PRIVATE' } });
  };
  await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_TIMEOUT' });
  const state = f.manager.snapshot();
  assert.equal(state.state, 'recovery-required'); assert.equal(state.errorCode, 'NETWORK_LOCK_TIMEOUT');
  assert.equal(state.inspectionFailed, undefined, 'mutation errors are not mislabelled as inspection errors');
  assert.deepEqual(state.diagnostic, { operation: 'disable', command: 'powershell.exe', category: 'OperationTimeout' });
  assert.doesNotMatch(JSON.stringify(state), /PRIVATE/);
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.equal(journal.phase, 'arming'); assert.ok(journal.backupHash); assert.deepEqual(journal.before.rules, f.original.rules);
  assert.ok(f.state.profiles.every(profile => profile.defaultOutboundAction === 'Block')); assert.equal(f.calls.includes('import'), false);
});

test('never-armed status uses only orphan detection and fails closed on orphan rules or unreadable results', async t => {
  const f = await fixture(t); let calls = 0; let response = { names: [] }; let rejected = false;
  f.adapter.inspectOrphans = async () => { calls++; if (rejected) throw new Error('private read error'); return response; };
  assert.equal((await f.manager.status({ force: true })).state, 'unlocked');
  assert.equal(f.inspectCalls, 0); assert.equal(calls, 1);
  response = { names: ['ProxyPilot-Lock-orphan'] };
  const orphan = await f.manager.status({ force: true }); assert.equal(orphan.state, 'conflict'); assert.equal(orphan.canUnlock, false);
  assert.equal(f.calls.length, 0, 'orphan detection never changes policy');
  for (const invalid of [null, {}, { names: ['foreign-rule'] }, { names: ['ProxyPilot-Lock-a', 'ProxyPilot-Lock-a'] }]) {
    response = invalid; assert.equal((await f.manager.status({ force: true })).state, 'unknown');
  }
  rejected = true; const unreadable = await f.manager.status({ force: true });
  assert.equal(unreadable.state, 'unknown'); assert.equal(unreadable.locked, false); assert.doesNotMatch(unreadable.reason, /private/);
  assert.equal(f.inspectCalls, 0);
});

test('lightweight idle status never replaces full arm, locked-state or restore verification', async t => {
  const f = await fixture(t); let light = 0;
  f.adapter.inspectOrphans = async () => { light++; return { names: [] }; };
  await f.manager.status(); assert.equal(light, 1); assert.equal(f.inspectCalls, 0);
  await f.manager.arm(input); const afterArm = f.inspectCalls; assert.ok(afterArm >= 3);
  await f.manager.status({ force: true }); assert.equal(f.inspectCalls, afterArm + 1); assert.equal(light, 1);
  await f.manager.unlock({ confirm: true }); assert.ok(f.inspectCalls > afterArm + 1);
  await f.manager.status({ force: true }); assert.equal(light, 2);
});

test('reload observes an offline repair journal instead of keeping the previously cached lock record', async t => {
  const f = await fixture(t);
  await f.manager.arm(input); await f.manager.attachTun();
  assert.equal((await f.manager.status()).locked, true);
  const repair = createNetworkLockManager(f.options);
  await repair.unlock({ confirm: true });
  assert.equal((await f.manager.status()).locked, true, 'ordinary cached status retains its old snapshot');
  const mutations = f.calls.length;
  assert.equal((await f.manager.reload()).state, 'unlocked');
  assert.equal(f.calls.length, mutations, 'reload only reads and verifies the externally repaired state');
  assert.equal((await f.manager.status()).locked, false);
});

test('mock reload preserves its journal and performs no native operations', async () => {
  const manager = createNetworkLockManager({ mock: true });
  await manager.arm(input); await manager.attachTun();
  assert.equal((await manager.reload()).locked, true);
  assert.equal((await manager.unlock({ confirm: true })).state, 'unlocked');
});
