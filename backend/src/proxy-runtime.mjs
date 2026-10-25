import { spawn as nodeSpawn, execFile as nodeExecFile } from 'node:child_process';
import { readFile, lstat, rm } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { buildSingBox, loadConfig, loadSecrets, validateConfig, validateTransportMode, validateTunRoutingMode, validateVpnProxy, validateCoreApi, FAKE_IP_NETWORK, UserError } from './config.mjs';
import { allocateCoreApiPort, requestCoreConnections, createCoreConnectionObserver, setCoreTrafficBlocked } from './core-connections.mjs';
import { createPrivateDirectory, writePrivate, renamePrivate as rename } from './private-files.mjs';
import { inspectProcess, listProcesses, listenerOwner, createWindowsProcessTools, stopProcess, sameProcess, parseWindowsCommandLine } from './windows-process.mjs';
import { isElevated, inspectTun, inspectExternalVpnTun, clearDnsCache } from './windows-tun.mjs';
import { createNetworkLockManager, networkLockBinding } from './network-lock.mjs';
import { sanitizeNetworkLockDiagnostic } from './windows-network-lock.mjs';
import { validateVpnOutbound } from './vpn-yaml.mjs';
import { validateRoutingApplicationPaths } from './routing-policy.mjs';
import { launchWindowsCore, closeWindowsCore } from './windows-core-process.mjs';

const backendRoot = fileURLToPath(new URL('../', import.meta.url));
const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const clone = value => structuredClone(value);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const normalize = value => path.resolve(value).toLowerCase();
const failed = (code, message) => new UserError(code, message);
const launchWindowMs = 60000;
// Mapping identity is deliberately independent of credentials, node, session and
// listener port: reusing a fake address in a new empty namespace could map an old
// browser cache entry to a different hostname. Profiles isolate by runtime root.
const fakeIpCacheId = digest({ version: 1, core: '1.14.2', ranges: FAKE_IP_NETWORK });
const cacheInitializations = new Map();
const cacheRecoveries = new Set();
const hashCacheFile = file => new Promise((resolve, reject) => {
  const hash = createHash('sha256'), stream = createReadStream(file);
  stream.on('data', bytes => hash.update(bytes)); stream.once('error', reject); stream.once('end', () => resolve(hash.digest('hex')));
});
const coreDiagnostics = [
  ['CORE_FAKE_IP_RECORD_MISSING', /missing fakeip record/i],
  ['CORE_TUN_PERMISSION_DENIED', /(?:permission denied|access (?:is )?denied|operation not permitted)/i],
  ['CORE_TUN_CREATE_FAILED', /(?:failed to (?:create|open|start).{0,100}(?:tun|wintun)|(?:tun|wintun).{0,100}(?:create|open|start).{0,100}failed)/i],
  ['CORE_TUN_ROUTE_FAILED', /(?:route|dns).{0,100}(?:failed|error)|(?:failed|error).{0,100}(?:route|dns)/i],
  ['CORE_LISTEN_FAILED', /address already in use|only one usage of each socket|(?:listen|bind).{0,100}(?:failed|error)/i],
  ['CORE_UPSTREAM_AUTH_FAILED', /proxy authentication required|authentication failed|status (?:code )?407|invalid (?:username|password)/i],
  ['CORE_UPSTREAM_TLS_FAILED', /(?:tls|x509|certificate).{0,100}(?:failed|error|unknown|invalid|expired)|(?:failed|error).{0,100}(?:tls|x509|certificate)/i],
  ['CORE_CONNECTION_RESET', /connection reset by peer|forcibly closed by (?:the )?remote host|wsarecv:\s*(?:connection reset|WSAECONNRESET|10054)\b/i],
  ['CORE_UPSTREAM_CONNECT_FAILED', /connection refused|network is unreachable|i\/o timeout|connection timed out|dial tcp.{0,100}(?:failed|error|timeout)/i],
  ['CORE_RUNTIME_FAILED', /\b(?:fatal|panic)\b/i],
];

function validIdentity(identity) {
  return sameProcess(identity, identity) && Boolean(identity.executable && identity.commandLine)
    && Number.isFinite(Date.parse(identity.createdAt));
}

function validateTunState(value, readinessRequired = true) {
  // Presence-only orphan guards do not grant routing readiness. Older custom
  // HTTP adapters may return only exists; any supplied ready must still be valid.
  if (!value || typeof value.exists !== 'boolean'
    || ((readinessRequired || Object.hasOwn(value, 'ready')) && (typeof value.ready !== 'boolean' || (value.ready && !value.exists)))) {
    throw failed('TUN_STATE_UNAVAILABLE', 'The owned TUN inspection did not return a valid readiness observation');
  }
  return value;
}

function validBrowserConfig(config, allowDiscovery = false) {
  validateConfig(config);
  if (!allowDiscovery && !config.probe.expectedExitIps.length) throw failed('EXPECTED_EXIT_REQUIRED', 'Configure at least one expected ISP exit IP before starting browser protection');
  return config;
}

async function resolveUpstream(host) {
  let timeout;
  try {
    const addresses = await Promise.race([
      lookup(host, { all: true }),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('DNS timeout')), 10000); }),
    ]);
    return (addresses.find(item => item.family === 4) || addresses[0])?.address;
  } finally { clearTimeout(timeout); }
}

export function createProxyRuntime(options = {}) {
  const runtimeRoot = path.resolve(options.runtimeRoot || path.join(backendRoot, 'runtime'));
  const configPath = path.resolve(options.configPath || path.join(runtimeRoot, 'config.json'));
  const secretsPath = path.resolve(options.secretsPath || path.join(runtimeRoot, 'upstream.secrets.env'));
  const corePath = path.resolve(options.corePath || path.join(backendRoot, '.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe'));
  const mode = options.mode || 'managed';
  if (!['managed', 'external'].includes(mode)) throw failed('PROXY_MODE_INVALID', 'Unsupported proxy management mode');
  // Only the internal onboarding verifier opts into an unpinned HTTP session.
  // This constructor flag is never read from user configuration or start input.
  const setupDiscovery = options.setupDiscovery === true;
  const defaultTransport = validateTransportMode(options.transportMode || (mode === 'external' || setupDiscovery ? 'http' : 'tun'));
  if (setupDiscovery && (mode !== 'managed' || defaultTransport !== 'http')) throw failed('PROXY_SETUP_HTTP_ONLY', 'Setup discovery requires an isolated managed HTTP proxy');
  if (mode === 'external' && defaultTransport !== 'http') throw failed('PROXY_MODE_INVALID', 'An external listener cannot be verified as managed system TUN');
  const mock = options.mock === true;
  const ownedStateCacheMs = options.ownedStateCacheMs ?? 2000;
  if (!Number.isInteger(ownedStateCacheMs) || ownedStateCacheMs < 0 || ownedStateCacheMs > 5000) throw failed('PROXY_STATE_INVALID', 'Invalid owned inspection cache lifetime');
  const dependencies = {
    loadConfig, loadSecrets, createPrivateDirectory, writePrivate, readFile, lstat, rename, rm, hashCacheFile,
    spawn: nodeSpawn, execFile: nodeExecFile, inspectProcess, listProcesses, listenerOwner, stopProcess, isElevated, inspectTun, inspectExternalVpnTun, resolveUpstream,
    clearDnsCache: () => clearDnsCache({ execFile: dependencies.execFile }),
    allocateCoreApiPort, requestCoreConnections, setCoreTrafficBlocked,
    closeCore: (identity, options = {}) => closeWindowsCore(identity, { ...options, execFile: dependencies.execFile }),
    delay, now: Date.now, uuid: randomUUID, ...options.dependencies,
  };
  dependencies.launchCore ??= options.dependencies?.spawn
    ? (file, config) => dependencies.spawn(file, ['run', '-c', config], { windowsHide: true, detached: true, stdio: ['ignore', 'ignore', 'pipe'] })
    : (file, config, settings) => launchWindowsCore(file, config, { ...settings, spawn: dependencies.spawn });
  // Test and custom adapters that supply individual ownership reads retain their
  // implementation. Production combines them in one fixed, read-only PS call.
  dependencies.inspectWindowsOwnedState ??= ['inspectProcess', 'listenerOwner', 'inspectTun'].some(key => Object.hasOwn(options.dependencies || {}, key))
    ? null : createWindowsProcessTools({ execFile: dependencies.execFile }).inspectOwnedState;
  const stateRoot = path.join(runtimeRoot, '.proxy-manager');
  const manifestPath = path.join(stateRoot, 'active.json');
  const cacheRoot = path.join(stateRoot, 'fakeip-cache-v1');
  const fakeIpCache = { id: fakeIpCacheId, path: path.join(cacheRoot, 'mapping.db') };
  const connectionObserver = createCoreConnectionObserver({ request: api => dependencies.requestCoreConnections(api), now: () => dependencies.now() });
  const networkLock = mock || setupDiscovery
    ? createNetworkLockManager({ mock: true, onProgress: options.onProgress })
    : options.networkLock || createNetworkLockManager({ stateDir: path.join(runtimeRoot, '.network-lock'), onProgress: options.onProgress });
  let lockState = networkLock.snapshot();
  const progress = (stage, message) => { try { options.onProgress?.({ stage, message }); } catch {} };
  let active = null; let recovered = false; let child = null; let childExit = null; let childError = null; let childOutput = null; let markChildStop = null;
  let controlledSessionId = null;
  let serial = Promise.resolve(); let mockRunning = false; let mockHash = null; let mockSelected = null; let mockLockRequired = false; let stopping = false; let lastPort = options.mockPort || 17890;
  let lastTransport = defaultTransport; let mockVpnProxy; let mockVpnNode; let mockRoutingMode = 'safe-rules';
  let mutationGeneration = 0; let mutationsPending = 0; let statusRead = null; let ownedStateRead = null;
  let ownedStateCache = null, ownedInspectionGeneration = 0, childFailed = false, mockTrafficBlocked = false;
  function invalidateOwnedState() { ownedStateCache = null; ownedStateRead = null; ownedInspectionGeneration++; }
  function heldChildAlive(observed, held = child) {
    return Boolean(held && held === child && !childFailed && held.pid === observed?.identity?.pid
      && held.exitCode === null && held.signalCode === null);
  }
  const mockConfig = { version: 1, listen: { host: '127.0.0.1', port: lastPort }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' }, probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: ['203.0.113.8'], timeoutMs: 5000 } };
  const result = (running, tunReady = running) => {
    const transport = active?.transportMode || lastTransport;
    const tun = running === true && transport === 'tun' && tunReady === true && active?.dnsCacheCleared !== false;
    return {
      running, managed: mode === 'managed' && (running || Boolean(active)), port: active?.config.listen.port || lastPort,
      mock, mode: transport, tunReady: tun, configHash: mock ? mockHash : active?.configHash || null,
      ...(transport === 'tun' ? { routingMode: mock ? mockRoutingMode : active?.routingMode || (active?.routingPolicyVersion === 1 ? 'safe-rules' : 'global') } : {}),
      sessionId: mock ? null : active?.sessionId || null,
      trafficBlocked: running && (mock ? mockTrafficBlocked : active?.trafficBlocked === true),
      trafficBlockConfirmed: running && (mock ? mockTrafficBlocked : active?.trafficBlocked === true && active?.trafficBlockConfirmed === true),
      vpnNodeHash: mock ? mockVpnNode ? digest(mockVpnNode) : null : active?.vpnNodeHash || null,
      networkLock: clone(lockState),
      coreObservation: { available: Boolean(running && !mock && active?.coreApi), ...connectionObserver.status() },
      ...((mock ? mockSelected : active?.config)?.connectionMode === 'vpn-compat' ? { compatibility: { strategy: (mock ? mockVpnProxy : active?.vpnProxy)?.type === 'http' ? 'http-proxy' : (mock ? mockVpnProxy : active?.vpnProxy)?.type === 'socks' ? 'socks-proxy' : 'system', ...((mock ? mockVpnProxy : active?.vpnProxy) ? { proxy: clone(mock ? mockVpnProxy : active.vpnProxy) } : {}) } } : {}),
      ...((mock ? mockSelected : active?.config)?.connectionMode === 'vpn-import' ? { compatibility: { strategy: 'imported-node' } } : {}),
      protections: { systemRouting: tun && !mock, dnsHijack: tun && !mock, dnsTransport: tun ? 'doh-via-isp' : null,
        ipv6Captured: tun && !mock, nonDnsUdpBlocked: tun && !mock, killSwitch: lockState.locked && !mock && !lockState.mock,
        persistentKillSwitch: true, leakTestVerified: false },
      dnsCompatibility: { persistentFakeIp: Boolean(tun && !mock && active?.fakeIpCacheId),
        pureIp: 'requires-provider-support', sniffDestinationOverride: false, echDomainRecovery: false },
    };
  };
  // These fixed reasons describe a read, not a process exit. In particular a
  // superseded read must not revoke a newer session or pretend its TUN vanished.
  const ownedResult = (running, tunReady, status, reason) => ({ ...result(running, tunReady),
    ownedInspection: { status, reason }, ...(status === 'superseded' ? { inspectionSuperseded: true } : {}) });
  const readTunState = async () => validateTunState(await dependencies.inspectTun());
  const readTunPresence = async () => validateTunState(await dependencies.inspectTun(), false);
  const run = (work, { mutating = true } = {}) => {
    if (mutating) { mutationGeneration++; mutationsPending++; statusRead = null; invalidateOwnedState(); }
    const next = serial.then(work).finally(() => { if (mutating) mutationsPending--; });
    serial = next.catch(() => {}); return next;
  };
  const sessionPath = id => path.join(runtimeRoot, `.proxy-session-${id}`);
  const generatedPath = id => path.join(sessionPath(id), 'sing-box.json');
  const nodePhysical = node => ({ host: node.server, port: node.server_port, protocol: ['hysteria2', 'tuic'].includes(node.type) ? 'UDP' : 'TCP' });
  const lockBinding = (config, vpnNode) => networkLockBinding({ upstream: config.upstream, relay: config.relay, corePath, proxyPort: config.listen.port,
    ...(config.connectionMode === 'vpn-import' ? { vpnNodeHash: digest(validateVpnOutbound(vpnNode)), physical: nodePhysical(vpnNode) } : {}) });
  const lockReady = (config, required, vpnNode) => lockState.state === 'unlocked'
    ? !required
    : lockState.locked && lockState.tunAllowed === true && lockState.binding === lockBinding(config, vpnNode);

  async function assertCompatibilityReady() {
    lockState = await networkLock.status({ force: true });
    if (lockState.state !== 'unlocked' || lockState.locked) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before using VPN compatibility mode');
    // inspectTun selects only this project's ProxyPilot interface. External
    // VPN interfaces remain permitted and are never modified or stopped.
    if (!mock && !setupDiscovery && (await readTunPresence()).exists) throw failed('TUN_INTERFACE_IN_USE', 'Recover the orphaned ProxyPilot TUN before using VPN compatibility mode');
    return { ready: true };
  }

  async function assertGlobalReady() {
    if (mock) return { ready: true };
    const state = await dependencies.inspectExternalVpnTun();
    if (typeof state?.active !== 'boolean' || !Number.isSafeInteger(state?.count) || state.count < 0 || state.active !== (state.count > 0)) {
      throw failed('VPN_INTERFACE_STATE_UNAVAILABLE', 'Unable to verify external VPN interfaces before global routing');
    }
    if (state.active) throw failed('GLOBAL_VPN_CONFLICT', 'Stop the external VPN before enabling MC Proxy global routing; no external process or interface was changed');
    return { ready: true };
  }

  async function readConfig() {
    const config = validBrowserConfig(clone(mock ? mockConfig : await dependencies.loadConfig(configPath)), setupDiscovery);
    lastPort = config.listen.port;
    return config;
  }

  async function ensurePrivateDirectory(directory) {
    try {
      const stat = await dependencies.lstat(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw failed('RUNTIME_UNSAFE', 'The private runtime path must be a real directory');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await dependencies.createPrivateDirectory(directory);
    }
  }

  async function inspectFakeIpCache({ initialize = false } = {}) {
    await ensurePrivateDirectory(cacheRoot);
    const recovery = await readCacheRecovery();
    if (recovery && recovery.phase !== 'complete') throw failed('FAKEIP_CACHE_RECOVERY_REQUIRED', 'Resume the explicitly confirmed Fake-IP recovery before creating a new mapping');
    const identityPath = path.join(cacheRoot, 'identity.json');
    try {
      const saved = await readCacheIdentity(identityPath);
      const claim = await readCacheRecovery(path.join(cacheRoot, `claim-${saved.generation || 'legacy'}.json`));
      if (claim && (recovery?.archiveId !== claim.archiveId || recovery.phase !== 'complete')) throw failed('FAKEIP_CACHE_RECOVERY_REQUIRED', 'An explicit mapping recovery claim is pending; resume it before starting');
      if (!saved.clean && initialize) throw failed('FAKEIP_CACHE_RECOVERY_REQUIRED', 'Close affected browsers and applications before explicitly recovering an unclean Fake-IP mapping; it was not reset');
      const info = await dependencies.lstat(fakeIpCache.path);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error();
      if (initialize && saved.clean && saved.dbHash !== undefined && saved.dbHash !== await dependencies.hashCacheFile(fakeIpCache.path)) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The previously clean mapping changed; it was not opened or silently rebuilt');
    } catch (cause) {
      if (cause.code === 'FAKEIP_CACHE_RECOVERY_REQUIRED') throw cause;
      if (cause.code !== 'ENOENT' || !initialize) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private Fake-IP mapping is missing or unsafe; it was not reset');
      // Exclusive creation refuses a leftover or unknown DB. Missing an existing
      // identity or mapping must never silently start a second allocation pool.
      try {
        await dependencies.lstat(identityPath);
        throw new Error();
      } catch (identityError) {
        if (identityError.code !== 'ENOENT') throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The existing Fake-IP mapping was not replaced');
      }
      try {
        await dependencies.writePrivate(fakeIpCache.path, Buffer.alloc(0));
        await dependencies.writePrivate(identityPath, JSON.stringify({ version: 1, id: fakeIpCacheId, clean: true, generation: randomUUID(), dbHash: digest(Buffer.alloc(0).toString()) }));
      } catch { throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'Cannot initialize private Fake-IP persistence without replacing existing data'); }
    }
    return fakeIpCache;
  }

  async function markFakeIpCache(clean) {
    const temporary = path.join(cacheRoot, `identity-${dependencies.uuid()}.tmp`);
    await regularCacheFile(fakeIpCache.path);
    await dependencies.writePrivate(temporary, JSON.stringify({ ...await readCacheIdentity(path.join(cacheRoot, 'identity.json')), clean, ...(clean ? { dbHash: await dependencies.hashCacheFile(fakeIpCache.path) } : {}) }));
    try { await dependencies.rename(temporary, path.join(cacheRoot, 'identity.json')); }
    catch (cause) { await dependencies.rm(temporary, { force: true }); throw cause; }
  }

  async function regularCacheFile(file, { optional = false } = {}) {
    try {
      const info = await dependencies.lstat(file);
      if (!info.isFile() || info.isSymbolicLink()) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private cache contains an unsafe file');
      return info;
    } catch (cause) { if (optional && cause.code === 'ENOENT') return null; throw cause; }
  }

  async function readCacheIdentity(file) {
    const info = await regularCacheFile(file);
    if (info.size > 4096) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private mapping identity is invalid');
    const value = JSON.parse(await dependencies.readFile(file, 'utf8'));
    if (Object.keys(value).some(key => !['version', 'id', 'clean', 'generation', 'dbHash'].includes(key)) || value.version !== 1 || value.id !== fakeIpCacheId || typeof value.clean !== 'boolean'
      || (value.generation !== undefined && !uuidPattern.test(value.generation)) || (value.dbHash !== undefined && !/^[a-f0-9]{64}$/.test(value.dbHash))) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private mapping identity cannot be verified');
    return value;
  }

  async function readCacheRecovery(file = path.join(cacheRoot, 'recovery.json')) {
    const info = await regularCacheFile(file, { optional: true });
    if (!info) return null;
    if (info.size > 16384) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private cache recovery record is invalid');
    let record;
    try { record = JSON.parse(await dependencies.readFile(file, 'utf8')); } catch { throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private cache recovery record is unreadable'); }
    if (Object.keys(record).some(key => !['version', 'id', 'archiveId', 'phase', 'controller', 'generation'].includes(key)) || record.version !== 1 || record.id !== fakeIpCacheId
      || !uuidPattern.test(record.archiveId) || !['prepared', 'dns-cleared', 'complete'].includes(record.phase) || !validIdentity(record.controller)
      || (record.generation !== undefined && record.generation !== 'legacy' && !uuidPattern.test(record.generation))) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The private cache recovery record is invalid');
    const directory = path.join(cacheRoot, `archive-${record.archiveId}`);
    const archive = await dependencies.lstat(directory);
    if (!archive.isDirectory() || archive.isSymbolicLink()) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The cache archive must be a private real directory');
    if (record.phase === 'complete') {
      await regularCacheFile(path.join(directory, 'mapping.db'));
      const identity = await readCacheIdentity(path.join(directory, 'identity.json'));
      if ((identity.generation || 'legacy') !== (record.generation || 'legacy')) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The archived mapping generation does not match its journal');
    }
    return record;
  }

  async function writeCacheRecovery(record, { initial = false } = {}) {
    const file = path.join(cacheRoot, 'recovery.json');
    if (initial) return dependencies.writePrivate(file, JSON.stringify(record));
    const temporary = path.join(cacheRoot, `recovery-${dependencies.uuid()}.tmp`);
    await dependencies.writePrivate(temporary, JSON.stringify(record));
    try { await dependencies.rename(temporary, file); }
    catch (cause) { await dependencies.rm(temporary, { force: true }); throw cause; }
  }

  async function recoverFakeIpCache(request = {}) {
    return run(async () => {
      if (request.confirm !== true || request.applicationsClosed !== true) throw failed('FAKEIP_CACHE_CONFIRM_REQUIRED', 'Confirm affected browsers and applications are normally closed before replacing their mapping generation');
      if (mock) return { status: 'mocked', recovered: true, archived: false, mock: true, requiresReconnect: true };
      if (mode !== 'managed' || setupDiscovery) throw failed('PROXY_MODE_INVALID', 'Only the main managed runtime may recover its mapping');
      if (cacheRecoveries.has(cacheRoot)) throw failed('FAKEIP_CACHE_RECOVERY_IN_PROGRESS', 'Another cache recovery is still in progress');
      cacheRecoveries.add(cacheRoot);
      try {
        await recover();
        if (active) throw failed('PROXY_STILL_RUNNING', 'Stop the owned core before recovering its mapping');
        if ((await readTunPresence()).exists) throw failed('TUN_INTERFACE_IN_USE', 'Recover the owned TUN before replacing its mapping');
        // Refuse a foreign listener and any unrecorded process using an owned
        // session path. This only inspects; no user or external core is stopped.
        if (await dependencies.listenerOwner((await readConfig()).listen.port)) throw failed('PROXY_PORT_IN_USE', 'The configured proxy listener must be unused before cache recovery');
        for (const identity of await dependencies.listProcesses(path.basename(corePath))) {
          if (normalize(identity.executable || '') !== normalize(corePath)) continue;
          if (!validIdentity(identity)) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'A possible owned core identity cannot be verified');
          const args = parseWindowsCommandLine(identity.commandLine);
          if (args.length === 4 && args[1] === 'run' && args[2] === '-c' && normalize(path.dirname(path.dirname(args[3]))) === normalize(runtimeRoot)
            && /^\.proxy-session-[0-9a-f-]+$/i.test(path.basename(path.dirname(args[3])))) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'An unrecorded core uses this runtime; inspect its ownership before cache recovery');
        }
        await ensurePrivateDirectory(cacheRoot);
        let record = await readCacheRecovery();
        const identityPath = path.join(cacheRoot, 'identity.json');
        if (record?.phase === 'complete' && !await regularCacheFile(identityPath, { optional: true }) && !await regularCacheFile(fakeIpCache.path, { optional: true })) return { status: 'recovered', recovered: true, archived: true, mock: false, requiresReconnect: true };
        const controller = await dependencies.inspectProcess(process.pid);
        if (!validIdentity(controller) || controller.pid !== process.pid) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'Cannot bind the cache recovery controller');
        if (!record || record.phase === 'complete') {
          const identity = await readCacheIdentity(identityPath);
          const claim = await readCacheRecovery(path.join(cacheRoot, `claim-${identity.generation || 'legacy'}.json`));
          if (claim) record = record?.archiveId === claim.archiveId ? record : claim;
        }
        if (record && record.phase !== 'complete') {
          const prior = await dependencies.inspectProcess(record.controller.pid);
          if (prior && sameProcess(record.controller, prior) && !sameProcess(controller, prior)) throw failed('PROXY_CONTROLLER_ACTIVE', 'Another live controller owns this cache recovery');
          record = { ...record, controller };
        } else {
          const identity = await readCacheIdentity(identityPath); await regularCacheFile(fakeIpCache.path);
          const archiveId = dependencies.uuid();
          if (!uuidPattern.test(archiveId)) throw failed('RUNTIME_UNSAFE', 'Cannot create a private cache archive');
          await dependencies.createPrivateDirectory(path.join(cacheRoot, `archive-${archiveId}`));
          const next = { version: 1, id: fakeIpCacheId, archiveId, generation: identity.generation || 'legacy', phase: 'prepared', controller };
          // One immutable claim per mapping generation also serializes different
          // processes. Completed journals cannot be overwritten by a competing
          // controller before this exclusive claim succeeds.
          try { await dependencies.writePrivate(path.join(cacheRoot, `claim-${next.generation}.json`), JSON.stringify(next)); }
          catch (cause) { if (cause.code === 'EEXIST') throw failed('FAKEIP_CACHE_RECOVERY_IN_PROGRESS', 'Another controller claimed this mapping generation'); throw cause; }
          await writeCacheRecovery(next, { initial: !record }); record = next;
        }
        const selectedArchive = path.join(cacheRoot, `archive-${record.archiveId}`);
        for (const name of ['mapping.db', 'identity.json']) {
          const source = path.join(cacheRoot, name), target = path.join(selectedArchive, name);
          const old = await regularCacheFile(source, { optional: true }), saved = await regularCacheFile(target, { optional: true });
          if (Boolean(old) === Boolean(saved)) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The pending archive does not contain exactly one copy of each original');
          if (name === 'identity.json' && ((await readCacheIdentity(old ? source : target)).generation || 'legacy') !== (record.generation || 'legacy')) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'The pending recovery is bound to a different mapping generation');
        }
        if (record.phase === 'prepared') {
          progress('clearing-dns-cache', '正在清理已关闭应用的 DNS 缓存，准备归档旧域名映射');
          try { if ((await dependencies.clearDnsCache())?.cleared !== true) throw new Error(); }
          catch { throw failed('DNS_CACHE_CLEAR_FAILED', 'DNS clearing failed; the original mapping and pending recovery were retained'); }
          record = { ...record, phase: 'dns-cleared' }; await writeCacheRecovery(record);
        }
        const archive = path.join(cacheRoot, `archive-${record.archiveId}`);
        // Persisted DNS confirmation precedes either rename. A retry checks
        // both locations and moves only missing archive members, never replaces.
        for (const name of ['mapping.db', 'identity.json']) {
          const source = path.join(cacheRoot, name), target = path.join(archive, name);
          const old = await regularCacheFile(source, { optional: true }), saved = await regularCacheFile(target, { optional: true });
          if (Boolean(old) === Boolean(saved)) throw failed('FAKE_IP_CACHE_UNAVAILABLE', 'A cache archive member is missing or conflicts; no record was replaced');
          if (name === 'identity.json') await readCacheIdentity(old ? source : target);
          if (old) await dependencies.rename(source, target);
        }
        record = { ...record, phase: 'complete' };
        const archivedJournal = path.join(archive, 'recovery.json');
        if (!await regularCacheFile(archivedJournal, { optional: true })) await dependencies.writePrivate(archivedJournal, JSON.stringify(record));
        await writeCacheRecovery(record);
        return { status: 'recovered', recovered: true, archived: true, mock: false, requiresReconnect: true };
      } catch (cause) {
        if (cause instanceof UserError) throw cause;
        throw failed('FAKEIP_CACHE_RECOVERY_FAILED', 'Cache recovery did not complete; its original mapping and recovery journal were retained for explicit retry');
      } finally { cacheRecoveries.delete(cacheRoot); }
    });
  }

  async function ensureFakeIpCache({ initialize = false } = {}) {
    if (!initialize) return inspectFakeIpCache();
    // Two controllers in the same process may reach configuration validation
    // together. Share only initialization; launch-intent exclusivity still picks
    // the owner, and later starts always recheck the existing mapping files.
    const current = cacheInitializations.get(cacheRoot);
    if (current) { await current; return inspectFakeIpCache(); }
    const pending = inspectFakeIpCache({ initialize: true });
    cacheInitializations.set(cacheRoot, pending);
    try { return await pending; } finally { if (cacheInitializations.get(cacheRoot) === pending) cacheInitializations.delete(cacheRoot); }
  }

  const renderOptions = manifest => ({ mode: manifest.transportMode,
    ...(manifest.trafficGateVersion === 1 ? { trafficGate: true } : {}),
    ...(manifest.routingMode ? { routingMode: manifest.routingMode } : {}),
    legacyTunPolicy: manifest.routingPolicyVersion === undefined,
    ...(manifest.routingApplicationPaths ? { applicationPaths: manifest.routingApplicationPaths } : {}),
    ...(manifest.coreApi ? { coreApi: manifest.coreApi } : {}),
    ...(manifest.fakeIpCacheId ? { fakeIpCache } : {}),
    ...(manifest.vpnProxy ? { vpnProxy: manifest.vpnProxy } : {}),
    ...(manifest.vpnNode ? { vpnNode: manifest.vpnNode, vpnNodeIp: manifest.vpnNodeIp } : {}) });

  async function executeCore(args, signal) {
    return new Promise((resolve, reject) => {
      dependencies.execFile(corePath, args, { windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024, ...(signal ? { signal } : {}) }, (error, stdout) => {
        if (signal?.aborted) return reject(failed('CONNECTION_CANCELED', 'The connection was canceled'));
        if (error?.code === 'ENOENT') return reject(failed('CORE_NOT_FOUND', 'The sing-box 1.14.2 core was not found; install the pinned core or correct CorePath before checking the ISP connection'));
        if (error) return reject(failed('CORE_CHECK_FAILED', 'The pinned sing-box core could not validate the local configuration'));
        resolve(String(stdout));
      });
    });
  }

  function matchesCommand(identity, id) {
    if (!validIdentity(identity) || normalize(identity.executable) !== normalize(corePath)) return false;
    let args;
    try { args = parseWindowsCommandLine(identity.commandLine); } catch { return false; }
    return args.length === 4 && normalize(args[0]) === normalize(corePath) && args[1] === 'run' && args[2] === '-c' && normalize(args[3]) === normalize(generatedPath(id));
  }

  function matchesLaunch(identity, manifest) {
    const created = Date.parse(identity?.createdAt);
    return matchesCommand(identity, manifest.sessionId) && identity.parentPid === manifest.launch.parent.pid
      && created >= manifest.launch.notBefore && created <= manifest.launch.notAfter;
  }

  async function assertControllerAvailable(manifest) {
    const controller = manifest.controller || manifest.launch?.parent;
    if (!controller || controlledSessionId === manifest.sessionId) return;
    const current = await dependencies.inspectProcess(controller.pid);
    if (current && sameProcess(controller, current)) throw failed('PROXY_CONTROLLER_ACTIVE', 'Another live MC Proxy controller owns this runtime; close that controller before recovering or starting a session');
  }

  async function writeManifest(manifest, { initial = false } = {}) {
    if (initial) {
      // Exclusive creation prevents two controllers that both observed an empty
      // runtime from overwriting each other's newly committed launch intent.
      try { await dependencies.writePrivate(manifestPath, JSON.stringify(manifest)); }
      catch (error) {
        if (error.code === 'EEXIST') throw failed('PROXY_CONTROLLER_ACTIVE', 'Another controller claimed the runtime before startup; no process was started');
        throw error;
      }
      return;
    }
    const temporary = path.join(stateRoot, `active-${dependencies.uuid()}.tmp`);
    await dependencies.writePrivate(temporary, JSON.stringify(manifest));
    try { await dependencies.rename(temporary, manifestPath); }
    catch (error) { await dependencies.rm(temporary, { force: true }); throw error; }
  }

  async function cleanup(manifest) {
    if (!manifest || !uuidPattern.test(manifest.sessionId)) throw failed('RUNTIME_UNSAFE', 'Refusing to remove an unrecognized runtime directory');
    let saved;
    try { saved = JSON.parse(await dependencies.readFile(manifestPath, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw failed('PROXY_STATE_INVALID', 'The proxy ownership record cannot be verified before cleanup'); }
    if (saved?.sessionId === manifest.sessionId) await assertControllerAvailable(saved);
    const directory = sessionPath(manifest.sessionId);
    // Derive the deletion target from a validated UUID; never trust a path in the manifest.
    if (path.dirname(directory) !== runtimeRoot) throw failed('RUNTIME_UNSAFE', 'Refusing to remove a directory outside the runtime');
    try {
      const info = await dependencies.lstat(directory);
      if (!info.isDirectory() || info.isSymbolicLink()) throw failed('RUNTIME_UNSAFE', 'Refusing to remove an unsafe runtime directory');
      await dependencies.rm(directory, { recursive: true, force: true });
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (saved?.sessionId === manifest.sessionId) await dependencies.rm(manifestPath, { force: true });
    if (active === manifest) active = null;
    invalidateOwnedState();
    if (!active) connectionObserver.reset(null);
    if (controlledSessionId === manifest.sessionId) controlledSessionId = null;
  }

  async function recover() {
    if ((recovered && active) || mock || mode === 'external') return;
    await ensurePrivateDirectory(runtimeRoot);
    await ensurePrivateDirectory(stateRoot);
    let manifest;
    try { manifest = JSON.parse(await dependencies.readFile(manifestPath, 'utf8')); }
    catch (error) {
      if (error.code === 'ENOENT') { recovered = true; return; }
      throw failed('PROXY_STATE_INVALID', 'The saved proxy state is unreadable; no process was adopted');
    }
    try {
      if (![1, 2, 3].includes(manifest.version) || !uuidPattern.test(manifest.sessionId)) throw new Error();
      if (manifest.controller && !validIdentity(manifest.controller)) throw new Error();
      if (manifest.version === 3) {
        const launch = manifest.launch;
        if (!['starting', 'active'].includes(manifest.phase) || !validIdentity(launch?.parent)
          || !Number.isSafeInteger(launch.notBefore) || !Number.isSafeInteger(launch.notAfter)
          || launch.notAfter - launch.notBefore !== launchWindowMs
          || Date.parse(launch.parent.createdAt) > launch.notBefore
          || (manifest.phase === 'starting' ? manifest.identity !== null : !matchesLaunch(manifest.identity, manifest))) throw new Error();
      } else if (!matchesCommand(manifest.identity, manifest.sessionId)) throw new Error();
      manifest.transportMode = manifest.version === 1 ? 'http' : validateTransportMode(manifest.transportMode);
      if (manifest.routingPolicyVersion !== undefined && (manifest.routingPolicyVersion !== 1 || manifest.transportMode !== 'tun')) throw new Error();
      if (manifest.routingMode !== undefined) {
        if (manifest.transportMode !== 'tun' || manifest.routingPolicyVersion !== 1) throw new Error();
        validateTunRoutingMode(manifest.routingMode);
      }
      if (manifest.routingApplicationPaths !== undefined) {
        if (manifest.routingPolicyVersion !== 1 || digest(validateRoutingApplicationPaths(manifest.routingApplicationPaths)) !== digest(manifest.routingApplicationPaths)) throw new Error();
      }
      if (manifest.coreApi !== undefined) validateCoreApi(manifest.coreApi, manifest.config?.listen?.port);
      if (manifest.trafficGateVersion !== undefined && (manifest.trafficGateVersion !== 1 || manifest.transportMode !== 'tun' || !manifest.coreApi
        || typeof manifest.trafficBlocked !== 'boolean' || typeof manifest.trafficBlockConfirmed !== 'boolean')) throw new Error();
      if (['trafficBlocked', 'trafficBlockConfirmed', 'trafficBlockReason'].some(key => Object.hasOwn(manifest, key)) && manifest.trafficGateVersion !== 1) throw new Error();
      if (manifest.trafficBlockReason !== undefined && !/^[A-Za-z0-9_-]{1,80}$/.test(manifest.trafficBlockReason)) throw new Error();
      if (manifest.fakeIpCacheId !== undefined) {
        if (manifest.fakeIpCacheId !== fakeIpCacheId || manifest.transportMode !== 'tun') throw new Error();
        await ensureFakeIpCache();
      }
      if (manifest.consoleManaged !== undefined && (manifest.consoleManaged !== true || manifest.transportMode !== 'tun' || manifest.fakeIpCacheId !== fakeIpCacheId)) throw new Error();
      if (manifest.dnsCacheCleared !== undefined && (typeof manifest.dnsCacheCleared !== 'boolean' || manifest.transportMode !== 'tun')) throw new Error();
      if (manifest.networkLockRequired !== undefined && typeof manifest.networkLockRequired !== 'boolean') throw new Error();
      // Earlier TUN sessions always armed the persistent lock at startup.
      manifest.networkLockRequired ??= manifest.transportMode === 'tun';
      if (setupDiscovery && manifest.transportMode !== 'http') throw new Error();
      validBrowserConfig(manifest.config, setupDiscovery);
      if (manifest.config.connectionMode === 'vpn-compat' && (manifest.transportMode !== 'http' || manifest.networkLockRequired)) throw new Error();
      if (manifest.config.connectionMode === 'vpn-import' && manifest.transportMode !== 'tun' && manifest.networkLockRequired) throw new Error();
      if (manifest.vpnProxy !== undefined) {
        if (manifest.config.connectionMode !== 'vpn-compat' || manifest.transportMode !== 'http') throw new Error();
        validateVpnProxy(manifest.vpnProxy, manifest.config.listen.port);
      }
      if (manifest.config.connectionMode === 'vpn-import') {
        if (manifest.vpnProxy !== undefined || !isIP(manifest.vpnNodeIp || '')) throw new Error();
        const node = validateVpnOutbound(manifest.vpnNode);
        if (digest(node) !== manifest.vpnNodeHash || (isIP(node.server) && node.server !== manifest.vpnNodeIp)) throw new Error();
        manifest.vpnNode = node;
      } else if (manifest.vpnNode !== undefined || manifest.vpnNodeHash !== undefined || manifest.vpnNodeIp !== undefined) throw new Error();
      if (digest(manifest.config) !== manifest.configHash) throw new Error();
      const info = await dependencies.lstat(sessionPath(manifest.sessionId));
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error();
      const configInfo = await dependencies.lstat(generatedPath(manifest.sessionId));
      if (!configInfo.isFile() || configInfo.isSymbolicLink()) throw new Error();
      const rendered = await dependencies.readFile(generatedPath(manifest.sessionId), 'utf8');
      if (digest(rendered) !== manifest.renderedHash) throw new Error();
      const renderedConfig = JSON.parse(rendered);
      const expectedExperimental = {
        ...(manifest.coreApi ? { clash_api: { external_controller: `127.0.0.1:${manifest.coreApi.port}`, secret: manifest.coreApi.secret, access_control_allow_origin: ['http://127.0.0.1'], ...(manifest.trafficGateVersion === 1 ? { default_mode: 'mc-active' } : {}) } } : {}),
        ...(manifest.fakeIpCacheId ? { cache_file: { enabled: true, path: fakeIpCache.path, cache_id: fakeIpCacheId, store_fakeip: true } } : {}),
      };
      if (digest(renderedConfig.experimental || {}) !== digest(expectedExperimental)) throw new Error();
      if (manifest.trafficGateVersion === 1 && [renderedConfig.route?.rules?.[0], renderedConfig.dns?.rules?.[0]].some(rule => digest(rule) !== digest({ clash_mode: 'mc-blocked', action: 'reject' }))) throw new Error();
      if (renderedConfig.inbounds.some(inbound => inbound.type === 'tun') !== (manifest.transportMode === 'tun')) throw new Error();
      if (['vpn-compat', 'vpn-import'].includes(manifest.config.connectionMode)) {
        const placeholder = manifest.config.upstream.auth === 'password' ? { ISP_USERNAME: 'recovery-placeholder', ISP_PASSWORD: 'recovery-placeholder' } : {};
        const expected = buildSingBox(manifest.config, placeholder, renderOptions(manifest));
        const withoutCredentials = value => { const copy = clone(value); for (const outbound of copy.outbounds || []) { delete outbound.username; delete outbound.password; } return copy; };
        if (digest(withoutCredentials(renderedConfig)) !== digest(withoutCredentials(expected))) throw new Error();
      }
    } catch (cause) {
      if (['FAKE_IP_CACHE_UNAVAILABLE', 'FAKEIP_CACHE_RECOVERY_REQUIRED'].includes(cause.code)) throw cause;
      throw failed('PROXY_STATE_INVALID', 'The saved proxy state does not match this project; no process was adopted');
    }
    // Readiness and process identity do not grant permission to steal a live
    // controller's session. This also covers phase=active before TUN is ready.
    await assertControllerAvailable(manifest);
    if (manifest.version === 3 && manifest.phase === 'starting') {
      // The write-ahead intent survives a crash before the child's PID is recorded.
      // A random private session path is necessary but not sufficient: also require
      // the recorded parent and the short launch window, then recheck full identity.
      const candidates = (await dependencies.listProcesses(path.basename(corePath)))
        .filter(identity => matchesCommand(identity, manifest.sessionId));
      if (candidates.length > 1) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'More than one process matches the interrupted launch; no process was adopted or stopped');
      if (candidates.length === 1) {
        const candidate = candidates[0];
        if (!matchesLaunch(candidate, manifest)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The interrupted launch candidate has a different parent or creation time; no process was adopted or stopped');
        const currentParent = await dependencies.inspectProcess(manifest.launch.parent.pid);
        if (currentParent && !sameProcess(manifest.launch.parent, currentParent)
          && Date.parse(currentParent.createdAt) <= Date.parse(candidate.createdAt)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The recorded parent PID was reused before this candidate was created; no process was adopted or stopped');
        const current = await dependencies.inspectProcess(candidate.pid);
        if (current && (!sameProcess(candidate, current) || current.parentPid !== candidate.parentPid)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The interrupted launch identity changed during recovery; no process was adopted or stopped');
        if (current) {
          manifest.identity = current; manifest.phase = 'active';
          await writeManifest(manifest);
        }
      }
      if (!manifest.identity) {
        if (manifest.consoleManaged && manifest.launch.parent.pid !== manifest.controller?.pid) {
          const helper = await dependencies.inspectProcess(manifest.launch.parent.pid);
          if (helper && sameProcess(manifest.launch.parent, helper)) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'The recorded launcher is still live; its interrupted launch must finish before recovery');
        }
        await cleanup(manifest); recovered = true; return;
      }
    }
    const current = await dependencies.inspectProcess(manifest.identity.pid);
    if (current && !sameProcess(manifest.identity, current)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The saved proxy process identity changed; no process was adopted or stopped');
    if (!current) { await cleanup(manifest); recovered = true; return; }
    const controller = await dependencies.inspectProcess(process.pid);
    if (!validIdentity(controller) || controller.pid !== process.pid) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'Cannot record the recovering controller identity');
    manifest.controller = controller;
    await writeManifest(manifest);
    controlledSessionId = manifest.sessionId;
    active = manifest; lastPort = manifest.config.listen.port; lastTransport = manifest.transportMode; recovered = true;
    invalidateOwnedState();
    if (active.trafficBlocked) {
      active.trafficBlockConfirmed = false;
      const gate = await dependencies.setCoreTrafficBlocked(active.coreApi, true);
      if (gate?.blocked !== true || gate.confirmed !== true) throw failed('CORE_TRAFFIC_GATE_FAILED', 'The retained traffic block could not be confirmed');
      active.trafficBlockConfirmed = true; await writeManifest(active);
    }
    connectionObserver.reset(manifest.coreApi ? manifest.sessionId : null);
  }

  function notifyFailure(code) {
    invalidateOwnedState();
    if (stopping) return;
    try { Promise.resolve(options.onFailure?.({ code, message: 'The managed ISP proxy stopped unexpectedly' })).catch(() => {}); } catch {}
  }

  function detachChild() {
    invalidateOwnedState(); childFailed = true;
    if (child && childExit) child.off('exit', childExit);
    if (child && childError) child.off('error', childError);
    if (child?.stderr && childOutput) { child.stderr.off('data', childOutput); child.stderr.resume?.(); }
    child = null; childExit = null; childError = null; childOutput = null; markChildStop = null;
  }

  function assertLockInspection(observed = lockState) {
    if (!observed.inspectionFailed && (!observed.errorCode || ['unlocked', 'locked'].includes(observed.state))) return;
    const code = ['NETWORK_LOCK_TIMEOUT', 'NETWORK_LOCK_WINDOWS_FAILED', 'NETWORK_LOCK_RESPONSE_INVALID'].includes(observed.errorCode)
      ? observed.errorCode : 'NETWORK_LOCK_INSPECTION_FAILED';
    const cause = failed(code, 'Windows firewall inspection failed; the persistent policy was retained');
    cause.diagnostic = sanitizeNetworkLockDiagnostic(observed.diagnostic);
    throw cause;
  }

  async function getStatus({ force = false, inspectedLock } = {}) {
    invalidateOwnedState();
    if (mock) { lockState = inspectedLock || await networkLock.status({ force }); assertLockInspection(); return result(mockRunning, mockSelected && lockReady(mockSelected, mockLockRequired, mockVpnNode)); }
    await recover();
    lockState = inspectedLock || await networkLock.status({ force });
    assertLockInspection();
    if (mode === 'external') {
      const config = await readConfig();
      return result(Boolean(await dependencies.listenerOwner(config.listen.port)));
    }
    if (!active) return ownedResult(false, false, 'unavailable', 'session-absent');
    const current = await dependencies.inspectProcess(active.identity.pid);
    if (!current) { const old = active; await cleanup(old); detachChild(); notifyFailure('PROXY_EXITED'); return result(false); }
    if (!sameProcess(active.identity, current)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The managed proxy identity changed; no process was stopped');
    const owner = await dependencies.listenerOwner(active.config.listen.port);
    if (!owner) return ownedResult(false, false, 'not-ready', 'listener-absent');
    if (!sameProcess(active.identity, owner)) return ownedResult(false, false, 'not-ready', 'listener-identity-mismatch');
    if (!owner.listenAddresses?.includes('127.0.0.1')) return ownedResult(false, false, 'not-ready', 'listener-not-loopback');
    // Preserve process ownership when routes disappear. The controller can then
    // block/stop even a freshly recovered session without claiming TUN is ready.
    if (active.transportMode === 'tun') return ownedTunResult(active, await readTunState());
    return ownedResult(true, false, 'verified', 'verified');
  }

  function ownedTunResult(observed, tun) {
    validateTunState(tun);
    const bound = lockReady(observed.config, observed.networkLockRequired, observed.vpnNode);
    const ready = tun.exists === true && tun.ready === true && bound === true && observed.dnsCacheCleared !== false;
    const reason = !tun.exists ? 'tun-absent' : !tun.ready ? 'tun-not-ready' : !bound ? 'lock-binding-not-ready'
      : observed.dnsCacheCleared === false ? 'dns-cache-not-cleared' : 'verified';
    return ownedResult(true, ready, ready ? 'verified' : 'not-ready', reason);
  }

  function readStatus({ force = false } = {}) {
    if (statusRead && statusRead.generation === mutationGeneration && (!force || statusRead.force)) return statusRead.promise;
    const reading = { generation: mutationGeneration, force };
    reading.promise = (async () => {
      await run(() => reading.generation === mutationGeneration ? recover() : undefined, { mutating: false });
      if (reading.generation !== mutationGeneration) return ownedResult(false, false, 'superseded', 'session-changed');
      // Policy reads are read-only and may be slow. They must not hold the
      // owned-process mutation queue needed to stop a core while keeping its lock.
      const inspectedLock = await networkLock.status({ force });
      assertLockInspection(inspectedLock);
      return run(() => reading.generation === mutationGeneration
        ? getStatus({ inspectedLock }) : ownedResult(false, false, 'superseded', 'session-changed'), { mutating: false });
    })();
    statusRead = reading;
    void reading.promise.finally(() => { if (statusRead === reading) statusRead = null; }).catch(() => {});
    return reading.promise;
  }

  function inspectOwnedState() {
    if (mutationsPending || stopping) return Promise.resolve(ownedResult(false, false, 'superseded', 'mutation-pending'));
    if (mock) return Promise.resolve(result(mockRunning, mockSelected && lockReady(mockSelected, mockLockRequired, mockVpnNode)));
    const observed = active; const generation = mutationGeneration;
    if (!observed) return Promise.resolve(ownedResult(false, false, 'unavailable', 'session-absent'));
    if (ownedStateRead?.active === observed && ownedStateRead.generation === generation) return ownedStateRead.promise;
    const inspectionGeneration = ownedInspectionGeneration;
    const reading = { active: observed, generation };
    reading.promise = (async () => {
      const lock = networkLock.snapshot();
      if (lock.inspectionFailed || !['unlocked', 'locked'].includes(lock.state)) return ownedResult(false, false, 'unavailable', 'lock-inspection-unavailable');
      const cached = ownedStateCache?.active === observed && ownedStateCache.generation === generation
        && ownedStateCache.inspectionGeneration === inspectionGeneration && heldChildAlive(observed, ownedStateCache.child)
        && dependencies.now() >= ownedStateCache.checkedAt && dependencies.now() - ownedStateCache.checkedAt < ownedStateCacheMs ? ownedStateCache : null;
      const evidence = cached?.evidence || (dependencies.inspectWindowsOwnedState
        ? await dependencies.inspectWindowsOwnedState({ pid: observed.identity.pid, port: observed.config.listen.port, tun: observed.transportMode === 'tun' })
        : await Promise.all([
          dependencies.inspectProcess(observed.identity.pid), dependencies.listenerOwner(observed.config.listen.port),
          observed.transportMode === 'tun' ? dependencies.inspectTun() : undefined,
        ]).then(([identity, owner, tun]) => ({ identity, owner, tun })));
      const { identity, owner, tun } = evidence;
      const currentLock = networkLock.snapshot();
      if (active !== observed || active.sessionId !== observed.sessionId || generation !== mutationGeneration || inspectionGeneration !== ownedInspectionGeneration || mutationsPending || stopping) {
        return ownedResult(false, false, 'superseded', 'session-changed');
      }
      if (currentLock.inspectionFailed || !['unlocked', 'locked'].includes(currentLock.state)) return ownedResult(false, false, 'unavailable', 'lock-inspection-unavailable');
      lockState = currentLock;
      if (!identity) return ownedResult(false, false, 'not-ready', 'process-absent');
      if (!sameProcess(observed.identity, identity)) return ownedResult(false, false, 'not-ready', 'process-identity-mismatch');
      if (!owner) return ownedResult(false, false, 'not-ready', 'listener-absent');
      if (!sameProcess(observed.identity, owner)) return ownedResult(false, false, 'not-ready', 'listener-identity-mismatch');
      if (!owner.listenAddresses?.includes('127.0.0.1')) return ownedResult(false, false, 'not-ready', 'listener-not-loopback');
      const result = observed.transportMode === 'tun' ? ownedTunResult(observed, tun) : ownedResult(true, false, 'verified', 'verified');
      if (!cached && result.ownedInspection.status === 'verified' && ownedStateCacheMs && heldChildAlive(observed)) {
        ownedStateCache = { active: observed, child, generation, inspectionGeneration, checkedAt: dependencies.now(), evidence: clone(evidence) };
      }
      if (result.ownedInspection.status !== 'verified') ownedStateCache = null;
      return result;
    })();
    ownedStateRead = reading;
    void reading.promise.catch(() => { if (ownedStateRead === reading) invalidateOwnedState(); });
    void reading.promise.finally(() => { if (ownedStateRead === reading) ownedStateRead = null; }).catch(() => {});
    return reading.promise;
  }

  async function applyTrafficGate(manifest, blocked, reason = 'policy-required') {
    if (manifest?.transportMode !== 'tun' || manifest.trafficGateVersion !== 1 || !manifest.coreApi) throw failed('CORE_TRAFFIC_GATE_UNAVAILABLE', 'This owned TUN has no traffic gate; reconnect with the current client');
    invalidateOwnedState();
    if (blocked) {
      manifest.trafficBlocked = true; manifest.trafficBlockConfirmed = false;
      manifest.trafficBlockReason = /^[A-Za-z0-9_-]{1,80}$/.test(reason) ? reason : 'policy-required';
      let journalFailure;
      try { await writeManifest(manifest); } catch (cause) { journalFailure = cause; }
      try {
        const applied = await dependencies.setCoreTrafficBlocked(manifest.coreApi, true);
        if (applied?.blocked !== true || applied.confirmed !== true || journalFailure) throw new Error();
        manifest.trafficBlockConfirmed = true; await writeManifest(manifest);
      } catch {
        manifest.trafficBlockConfirmed = false;
        throw failed('CORE_TRAFFIC_GATE_FAILED', 'The owned TUN remains present, but traffic blocking could not be confirmed');
      }
    } else {
      try {
        const applied = await dependencies.setCoreTrafficBlocked(manifest.coreApi, false);
        if (applied?.blocked !== false || applied.confirmed !== true) throw new Error();
        const next = { ...manifest, trafficBlocked: false, trafficBlockConfirmed: false }; delete next.trafficBlockReason;
        await writeManifest(next);
        Object.assign(manifest, next); delete manifest.trafficBlockReason;
      } catch {
        // Keep the durable block intent when resumption or its journal fails.
        manifest.trafficBlocked = true; manifest.trafficBlockConfirmed = false;
        try { await dependencies.setCoreTrafficBlocked(manifest.coreApi, true); } catch {}
        await writeManifest(manifest).catch(() => {});
        throw failed('CORE_TRAFFIC_GATE_FAILED', 'The owned TUN remains present; traffic resumption did not complete');
      }
    }
    return result(true);
  }

  async function changeTrafficGate(blocked, reason) {
    if (mock) return run(() => {
      if (!mockRunning || lastTransport !== 'tun') throw failed('CORE_TRAFFIC_GATE_UNAVAILABLE', 'A running owned TUN is required');
      mockTrafficBlocked = blocked; return result(true);
    });
    const cached = ownedStateCache, beforeInspectionGeneration = ownedInspectionGeneration;
    return run(async () => {
      // A block queued during start/resume must inspect the resulting session,
      // rather than reject the pre-queue "mutation pending" snapshot.
      await recover();
      const observed = active;
      if (!observed || observed.transportMode !== 'tun') throw failed('CORE_TRAFFIC_GATE_UNAVAILABLE', 'A running owned TUN is required');
      const reusable = cached?.active === observed && cached.inspectionGeneration === beforeInspectionGeneration
        && ownedInspectionGeneration === beforeInspectionGeneration + 1 && heldChildAlive(observed, cached.child)
        && dependencies.now() >= cached.checkedAt && dependencies.now() - cached.checkedAt < ownedStateCacheMs;
      const evidence = reusable ? cached.evidence : dependencies.inspectWindowsOwnedState
        ? await dependencies.inspectWindowsOwnedState({pid:observed.identity.pid,port:observed.config.listen.port,tun:true})
        : await Promise.all([dependencies.inspectProcess(observed.identity.pid),dependencies.listenerOwner(observed.config.listen.port)]).then(([identity,owner])=>({identity,owner}));
      if (active !== observed || !sameProcess(observed.identity,evidence?.identity) || !sameProcess(observed.identity,evidence?.owner)
        || !evidence.owner.listenAddresses?.includes('127.0.0.1')) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'The owned TUN changed before the traffic gate operation');
      if (!blocked) {
        lockState=networkLock.snapshot();assertLockInspection();
        const tun=dependencies.inspectWindowsOwnedState?evidence.tun:await readTunState();
        if(!ownedTunResult(observed,tun).tunReady)throw failed('TUN_NOT_READY','The owned TUN routes or protection must be verified before traffic resumes');
      }
      return applyTrafficGate(observed, blocked, reason);
    });
  }

  async function start(request) {
    const signal = request?.signal;
    const checkCanceled = () => { if (signal?.aborted) throw failed('CONNECTION_CANCELED', 'The connection was canceled'); };
    const readCancelable = async promise => {
      if (!signal) return promise;
      let cancel;
      try { return await Promise.race([promise, new Promise((_, reject) => { cancel = () => reject(failed('CONNECTION_CANCELED', 'The connection was canceled')); signal.addEventListener('abort', cancel, { once: true }); if (signal.aborted) cancel(); })]); }
      finally { signal.removeEventListener('abort', cancel); }
    };
    return run(async () => {
      checkCanceled();
      if (mode !== 'managed') throw failed('PROXY_EXTERNAL', 'External proxies cannot be started or adopted by this controller');
      const legacy = request && Object.hasOwn(request, 'version');
      let transport = validateTransportMode(legacy ? defaultTransport : request?.mode || defaultTransport);
      if (setupDiscovery && transport !== 'http') throw failed('PROXY_SETUP_HTTP_ONLY', 'Setup discovery cannot enable system routing');
      const requestedConfig = legacy ? request : request?.config;
      const selected = validBrowserConfig(clone(requestedConfig || await readCancelable(readConfig())), setupDiscovery);
      checkCanceled();
      const compatibility = ['vpn-compat', 'vpn-import'].includes(selected.connectionMode);
      const imported = selected.connectionMode === 'vpn-import';
      // Import defaults to application routing; global routing is explicit.
      if (imported && (legacy || request?.mode === undefined)) transport = 'http';
      if (selected.connectionMode === 'vpn-compat' && transport !== 'http') throw failed('VPN_COMPAT_HTTP_ONLY', 'VPN compatibility mode cannot enable system TUN');
      if (transport !== 'tun' && request?.routingMode !== undefined) throw failed('ROUTING_MODE_INVALID', 'HTTP mode has no system routing policy');
      const routingMode = transport === 'tun' ? validateTunRoutingMode(request?.routingMode === undefined ? 'safe-rules' : request.routingMode) : undefined;
      const requestedVpnProxy = legacy ? undefined : request?.vpnProxy;
      if (requestedVpnProxy !== undefined && selected.connectionMode !== 'vpn-compat') throw failed('VPN_PROXY_INVALID', 'A local VPN route requires VPN compatibility mode');
      const vpnProxy = requestedVpnProxy === undefined ? undefined : clone(validateVpnProxy(requestedVpnProxy, selected.listen.port));
      const requestedVpnNode = legacy ? undefined : request?.vpnNode;
      if (requestedVpnNode !== undefined && !imported) throw failed('VPN_NODE_INVALID', 'An imported VPN node requires VPN import mode');
      if (imported && requestedVpnNode === undefined) throw failed('VPN_NODE_REQUIRED', 'Select and verify an imported VPN node before starting');
      const vpnNode = requestedVpnNode === undefined ? undefined : validateVpnOutbound(requestedVpnNode);
      const applicationPaths = validateRoutingApplicationPaths(legacy || request?.applicationPaths === undefined ? [] : request.applicationPaths);
      if (applicationPaths.length && transport !== 'tun') throw failed('ROUTING_POLICY_INVALID', 'Application route rules require owned system TUN');
      const physical = vpnNode ? nodePhysical(vpnNode) : selected.relay || selected.upstream;
      lastPort = selected.listen.port;
      if (compatibility && transport === 'http') await readCancelable(assertCompatibilityReady());
      if (transport === 'tun') await readCancelable(assertGlobalReady());
      checkCanceled();
      if (transport === 'tun') {
        lockState = await networkLock.status({ force: true });
        if (lockState.state !== 'unlocked' && (!lockState.locked || lockState.binding !== lockBinding(selected, vpnNode))) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before changing the proxy');
      }
      if (mock) {
        lockState = await networkLock.status({ force: true });
        if (transport === 'tun' && lockState.state !== 'unlocked') {
          if (!lockState.locked || lockState.binding !== lockBinding(selected, vpnNode)) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before changing the proxy');
          lockState = await networkLock.attachTun();
        }
        mockSelected = selected; mockVpnProxy = vpnProxy; mockVpnNode = vpnNode; mockLockRequired = transport === 'tun' && lockState.locked;
        checkCanceled();mockTrafficBlocked = false;mockRunning = true; mockHash = digest(selected); lastTransport = transport; mockRoutingMode = routingMode; return result(true);
      }
      await recover();
      checkCanceled();
      if (active) {
        const status = await getStatus();
        if (status.running && active.transportMode === 'tun' && !status.tunReady) throw failed('TUN_NOT_READY', 'The owned TUN lost its routes or DNS configuration; stop it before retrying');
        if (status.running && active.configHash === digest(selected) && active.transportMode === transport && digest(active.vpnProxy || null) === digest(vpnProxy || null) && digest(active.vpnNode || null) === digest(vpnNode || null)
          && digest(active.routingApplicationPaths || []) === digest(applicationPaths)
          && (transport !== 'tun' || (active.routingMode || (active.routingPolicyVersion === 1 ? 'safe-rules' : 'global')) === routingMode)) {
          checkCanceled();if (active.trafficGateVersion === 1) await applyTrafficGate(active, false);
          checkCanceled();return result(true);
        }
        if (active) throw failed('PROXY_ALREADY_MANAGED', 'Stop the existing managed proxy before changing its configuration');
      }
      if (transport === 'tun') {
        if (!await readCancelable(dependencies.isElevated())) throw failed('ADMIN_REQUIRED', 'Restart MC Proxy as administrator before enabling system TUN');
        if ((await readCancelable(readTunPresence())).exists) throw failed('TUN_INTERFACE_IN_USE', 'The ProxyPilot TUN interface already exists; no interface was changed');
      }
      if (await readCancelable(dependencies.listenerOwner(selected.listen.port))) throw failed('PROXY_PORT_IN_USE', 'The configured port is already occupied; no process was started');
      checkCanceled();const version = await executeCore(['version'],signal);checkCanceled();
      if (!/^sing-box version 1\.14\.2(?:\s|$)/m.test(version)) throw failed('CORE_VERSION_INVALID', 'The managed proxy requires the pinned sing-box 1.14.2 core');
      const binding = lockBinding(selected, vpnNode);
      let endpointIp = isIP(physical.host) ? physical.host : null;
      if (!setupDiscovery) progress('checking-firewall', '正在核验现有断网锁与 Windows 防火墙策略');
      lockState = await readCancelable(networkLock.status({ force: true }));
      checkCanceled();
      if (compatibility && transport === 'http' && (lockState.state !== 'unlocked' || lockState.locked)) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before using VPN compatibility mode');
      if (transport === 'tun' && lockState.state !== 'unlocked') {
        if (!lockState.locked || lockState.binding !== binding) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before changing the proxy');
        endpointIp = lockState.allowedEndpoint?.ip;
        if (!isIP(endpointIp || '') || lockState.allowedEndpoint.host !== physical.host || lockState.allowedEndpoint.port !== physical.port
          || (lockState.allowedEndpoint.protocol || 'TCP') !== (physical.protocol || 'TCP')
          || (isIP(physical.host) && endpointIp !== physical.host)) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'The persistent lock endpoint does not match the configured physical proxy');
      }
      if (transport === 'tun' && !imported && !endpointIp) {
        try { endpointIp = await readCancelable(dependencies.resolveUpstream(physical.host)); }
        catch { checkCanceled();throw failed('UPSTREAM_RESOLVE_FAILED', 'Cannot resolve the provider hostname before enabling TUN'); }
        if (!isIP(endpointIp || '')) throw failed('UPSTREAM_RESOLVE_FAILED', 'The provider hostname did not resolve to an IP address');
      }
      if (imported && !endpointIp) {
        try { endpointIp = await readCancelable(dependencies.resolveUpstream(physical.host)); }
        catch { checkCanceled();throw failed('VPN_NODE_RESOLVE_FAILED', 'Cannot resolve the imported VPN server'); }
        if (!isIP(endpointIp || '')) throw failed('VPN_NODE_RESOLVE_FAILED', 'The imported VPN server did not resolve to an IP address');
      }
      const secrets = await readCancelable(dependencies.loadSecrets(secretsPath, selected));
      checkCanceled();
      const coreApi = setupDiscovery ? undefined : validateCoreApi({ port: await dependencies.allocateCoreApiPort(), secret: randomBytes(32).toString('hex') }, selected.listen.port);
      if (coreApi && await dependencies.listenerOwner(coreApi.port)) throw failed('CORE_API_UNAVAILABLE', 'The private observation port is already occupied');
      if (transport === 'tun') await ensureFakeIpCache({ initialize: true });
      const rendered = `${JSON.stringify(buildSingBox(selected, secrets, { mode: transport, upstreamIp: selected.relay ? undefined : endpointIp,
        applicationPaths, ...(routingMode ? { routingMode } : {}),
        ...(coreApi ? { coreApi } : {}), ...(transport === 'tun' ? { fakeIpCache, trafficGate: true } : {}),
        ...(vpnProxy ? { vpnProxy } : {}), ...(vpnNode ? { vpnNode, vpnNodeIp: endpointIp } : {}) }), null, 2)}\n`;
      const sessionId = dependencies.uuid();
      if (!uuidPattern.test(sessionId)) throw failed('RUNTIME_UNSAFE', 'Unable to create a private proxy session');
      const pending = { version: 3, phase: 'starting', transportMode: transport, ...(coreApi ? { coreApi } : {}),
        ...(transport === 'tun' ? { routingPolicyVersion: 1, routingMode, routingApplicationPaths: applicationPaths, trafficGateVersion: 1, trafficBlocked: false, trafficBlockConfirmed: false } : {}),
        networkLockRequired: transport === 'tun' && lockState.locked, ...(transport === 'tun' ? { dnsCacheCleared: false, fakeIpCacheId, consoleManaged: true } : {}),
        ...(vpnProxy ? { vpnProxy } : {}), ...(vpnNode ? { vpnNode, vpnNodeIp: endpointIp, vpnNodeHash: digest(vpnNode) } : {}), sessionId, config: selected, configHash: digest(selected), renderedHash: digest(rendered), identity: null, launch: null };
      let spawned = null; let observed = null, cacheClaimed = false, launchAttempted = false;
      try {
        checkCanceled();
        await dependencies.createPrivateDirectory(sessionPath(sessionId));
        await dependencies.writePrivate(generatedPath(sessionId), rendered);
        await executeCore(['check', '-c', generatedPath(sessionId)],signal);checkCanceled();
        const parent = await dependencies.inspectProcess(process.pid);
        const notBefore = dependencies.now();
        if (!validIdentity(parent) || parent.pid !== process.pid || Date.parse(parent.createdAt) > notBefore) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'Cannot record the controller identity before launching the core');
        pending.launch = { parent, notBefore, notAfter: notBefore + launchWindowMs };
        pending.controller = parent;
        // Commit the launch intent before creating any detached process. A restart
        // can now recover even when it never received or saved the child's PID.
        await writeManifest(pending, { initial: true });
        controlledSessionId = sessionId;
        // Refresh the bounded launch window after the private intent is saved.
        // Network policy is armed only through the separate manual operation.
        pending.launch.notBefore = dependencies.now();
        pending.launch.notAfter = pending.launch.notBefore + launchWindowMs;
        await writeManifest(pending);
        // Recheck after hostname resolution and core validation, immediately
        // before opening TUN. Never stop an external VPN to resolve a conflict.
        if (transport === 'tun') await assertGlobalReady();
        checkCanceled();
        progress('starting-core', transport === 'tun' ? '正在启动系统 TUN 代理核心' : '正在建立独立 ISP 检查连接');
        let launchError = false; let exited = false;
        let ready = false; let expectedStop = false; let diagnosticTail = ''; const emitted = new Set();
        const diagnostic = (code, operation, detail = {}) => {
          try { Promise.resolve(options.onDiagnostic?.({ code, operation, diagnostic: detail })).catch(() => {}); } catch {}
        };
        if (transport === 'tun') {
          await markFakeIpCache(false);
          cacheClaimed=true;
          checkCanceled();
          launchAttempted=true;
          const launching = dependencies.launchCore(corePath, generatedPath(sessionId), { prepare: async helperPid => {
            checkCanceled();
            const helper = await dependencies.inspectProcess(helperPid);
            const time = dependencies.now();
            if (!validIdentity(helper) || helper.pid !== helperPid || helper.parentPid !== process.pid || Date.parse(helper.createdAt) > time) throw failed('CORE_OWNERSHIP_UNVERIFIED', 'Cannot bind the private core launcher identity');
            pending.launch = { parent: helper, notBefore: time, notAfter: time + launchWindowMs };
            await writeManifest(pending);
            checkCanceled();
          } });
          spawned = launching && typeof launching.then === 'function' ? await launching : launching;
        } else spawned = dependencies.spawn(corePath, ['run', '-c', generatedPath(sessionId)], { windowsHide: true, detached: true, stdio: ['ignore', 'ignore', 'pipe'] });
        child = spawned;childFailed=false;
        // Keep the intent with this child: Windows may deliver its exit event
        // after the stop-process command has already returned.
        markChildStop = expected => { expectedStop = expected; };
        childError = () => { launchError = true;childFailed=true;invalidateOwnedState(); if (!expectedStop) notifyFailure(ready && pending.consoleManaged ? 'CORE_CONSOLE_CLOSE_FAILED' : 'CORE_START_FAILED'); else diagnostic('CORE_CONSOLE_CLOSE_FAILED', 'core-stop'); };
        childExit = (exitCode, signal) => {
          exited = true;
          childFailed=true;invalidateOwnedState();
          diagnostic(expectedStop ? 'CORE_PROCESS_STOPPED' : 'CORE_PROCESS_EXITED', expectedStop ? 'core-stop' : 'core-exit', { exitCode: Number.isSafeInteger(exitCode) ? exitCode : null,
            signal: ['SIGINT', 'SIGTERM', 'SIGKILL', 'SIGABRT', 'SIGSEGV', 'SIGHUP', 'SIGBREAK'].includes(signal) ? signal : null });
          if (!expectedStop) notifyFailure('PROXY_EXITED');
        };
        childOutput = chunk => {
          diagnosticTail = (diagnosticTail + String(chunk)).slice(-4096);
          for (const [code, pattern] of coreDiagnostics) {
            if (!emitted.has(code) && pattern.test(diagnosticTail)) { emitted.add(code); invalidateOwnedState();diagnostic(code, ready ? 'core-runtime' : 'core-start'); }
          }
        };
        child.stderr?.on('data', childOutput);
        child.stderr?.unref?.();
        child.on('error', childError); child.on('exit', childExit);
        await new Promise((resolve, reject) => {
          child.once('spawn', resolve);
          child.once('error', () => reject(failed('CORE_START_FAILED', 'The pinned sing-box core could not be started')));
        });
        for (let attempt = 0; attempt < 40; attempt++) {
          checkCanceled();
          if (launchError || exited) break;
          observed = await dependencies.inspectProcess(spawned.pid);
          if (observed && !matchesLaunch(observed, pending)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The started process identity could not be verified');
          if (observed) {
            if (pending.identity && !sameProcess(pending.identity, observed)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The started process identity changed before readiness');
            pending.identity = observed;
            pending.phase = 'active';
            // Persist ownership before readiness; a controller restart can safely finish cleanup.
            if (!active) { await writeManifest(pending); active = pending; }
            checkCanceled();
            const owner = await dependencies.listenerOwner(selected.listen.port);
            checkCanceled();
            if (owner && !sameProcess(observed, owner)) throw failed('PROXY_PORT_IN_USE', 'Another process acquired the proxy port during startup');
            if (owner?.listenAddresses?.includes('127.0.0.1') && (transport !== 'tun' || (await readTunState()).ready)) {
              if (transport === 'tun') progress('verifying-tun', '正在核验 TUN 网卡、双栈路由和 DNS');
              if (transport === 'tun' && pending.networkLockRequired) lockState = await networkLock.attachTun();
              if (transport === 'tun') {
                if (launchError || exited) throw failed('CORE_START_FAILED', 'The owned core exited before the startup DNS cache hook');
                progress('clearing-dns-cache', '正在清理旧 DNS 缓存，使新请求使用 TUN 的域名映射');
                try {
                  const cleared = await dependencies.clearDnsCache();
                  if (cleared?.cleared !== true) throw new Error();
                } catch {
                  diagnostic('DNS_CACHE_CLEAR_FAILED', 'clearing-dns-cache');
                  throw failed('DNS_CACHE_CLEAR_FAILED', 'Windows DNS cache clearing failed; the owned core must stop before retrying');
                }
                if (launchError || exited) throw failed('CORE_START_FAILED', 'The owned core exited while its startup DNS cache hook was pending');
                await writeManifest({ ...pending, dnsCacheCleared: true });
                pending.dnsCacheCleared = true;
                checkCanceled();
                if (launchError || exited) throw failed('CORE_START_FAILED', 'The owned core exited before startup completed');
                // Fake-IP cache also stores Clash mode. Reset any retained
                // blocked mode only on this authorized start, before exit probes.
                await applyTrafficGate(pending, false);checkCanceled();
              }
              lastTransport = transport;
              connectionObserver.reset(coreApi ? sessionId : null);
              ready = true;
              spawned.unref?.();
              return result(true);
            }
          }
          await dependencies.delay(150);
        }
        throw failed(transport === 'tun' ? 'TUN_NOT_READY' : 'CORE_START_FAILED', 'The managed proxy listener and required TUN routes did not become ready');
      } catch (error) {
        if (error.mayHaveStarted) { recovered = false; throw failed('CORE_OWNERSHIP_UNVERIFIED', 'The private launcher may have created a core; retain its launch intent for recovery'); }
        // Never use child.kill(): on Windows a reused PID must be excluded by full identity.
        if (pending.identity) {
          const current = await dependencies.inspectProcess(pending.identity.pid);
          if (current && sameProcess(pending.identity, current)) {
            markChildStop?.(true);
            let cleanCanceledClose=false;
            try {
              if (signal?.aborted && pending.consoleManaged) {
                try { const closed=await dependencies.closeCore(pending.identity,{stopProcess:dependencies.stopProcess});cleanCanceledClose=closed?.closed===true&&closed.exitCode===0; } catch {}
              }
              if(!cleanCanceledClose)await dependencies.stopProcess(pending.identity);
            }
            catch (cause) { markChildStop?.(false); throw cause; }
            const remaining = await dependencies.inspectProcess(pending.identity.pid);
            if (remaining && sameProcess(pending.identity, remaining)) {
              markChildStop?.(false);
              throw failed('PROCESS_STOP_TIMEOUT', 'The failed core is still running; its private ownership and configuration were retained');
            }
            if(cleanCanceledClose&&pending.fakeIpCacheId)await markFakeIpCache(true);
          }
          else if (current) throw failed('PROCESS_IDENTITY_MISMATCH', 'The failed proxy identity changed; manual inspection is required');
        } else if (spawned?.pid && spawned.exitCode == null && spawned.signalCode == null) {
          // A process may have started before Windows identity inspection failed. Keep its
          // private configuration for diagnosis; never guess ownership or delete under it.
          recovered = false;
          spawned.unref?.();
          detachChild();
          throw failed('CORE_OWNERSHIP_UNVERIFIED', 'The core process may still be running; its saved launch intent must be recovered before retrying');
        }
        detachChild();
        await cleanup(pending);
        if(cacheClaimed&&!launchAttempted)await markFakeIpCache(true);
        // No persistent mapping is claimed clean after a force-stop. Only the
        // native normal-close helper may certify a cache-bearing core shutdown.
        checkCanceled();if (error instanceof UserError) throw error;
        throw failed('CORE_START_FAILED', 'The managed proxy could not be started; credentials were not logged');
      }
    });
  }

  async function armNetworkLock() {
    return run(async () => {
      if (networkLock.canArm === false) throw failed('NETWORK_LOCK_DISABLED', 'New network locks are paused; the proxy session is unchanged');
      if (mode !== 'managed' || setupDiscovery) throw failed('NETWORK_LOCK_TUN_REQUIRED', 'The network lock requires an owned system TUN connection');
      const status = await getStatus({ force: true });
      if (!status.running) throw failed('PROXY_NOT_RUNNING', 'Establish the system TUN connection before enabling the network lock');
      if (status.mode !== 'tun') throw failed('NETWORK_LOCK_TUN_REQUIRED', 'The network lock requires an owned system TUN connection');
      if (!mock && active.dnsCacheCleared === false) throw failed('DNS_CACHE_CLEAR_FAILED', 'Finish recovery of the incomplete TUN startup before enabling the network lock');
      const selected = mock ? mockSelected : active.config;
      const vpnNode = mock ? mockVpnNode : active.vpnNode;
      const physical = selected.connectionMode === 'vpn-import' ? nodePhysical(validateVpnOutbound(vpnNode)) : selected.relay || selected.upstream;
      let endpointIp;
      if (mock) endpointIp = isIP(physical.host) ? physical.host : '192.0.2.1';
      else {
        if (!await dependencies.isElevated()) throw failed('ADMIN_REQUIRED', 'Administrator privileges are required for the persistent network lock');
        if (!(await readTunState()).ready) throw failed('TUN_NOT_READY', 'Verify the owned TUN routes and DNS before enabling the network lock');
        // Read the pinned endpoint actually given to the owned core. Current
        // settings and a second hostname lookup must not widen its exception.
        let rendered;
        try {
          const info = await dependencies.lstat(generatedPath(active.sessionId));
          if (!info.isFile() || info.isSymbolicLink()) throw new Error();
          rendered = await dependencies.readFile(generatedPath(active.sessionId), 'utf8');
          if (digest(rendered) !== active.renderedHash) throw new Error();
          const outbound = JSON.parse(rendered).outbounds.find(item => item.tag === (selected.connectionMode === 'vpn-import' ? 'vpn-entry' : selected.relay ? 'relay-entry' : 'isp-upstream'));
          if (!outbound || outbound.server_port !== physical.port || !isIP(outbound.server || '')
            || (isIP(physical.host) && outbound.server !== physical.host)) throw new Error();
          endpointIp = outbound.server;
        } catch { throw failed('PROXY_STATE_INVALID', 'The owned core configuration could not be verified before enabling the network lock'); }
        if (lockState.state !== 'unlocked' && (!lockState.locked || lockState.binding !== lockBinding(selected, vpnNode))) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Explicitly recover or unlock the existing network lock before enabling it');
        // Record the protection requirement before policy mutation. A partial
        // activation or an externally removed lock cannot look ready on restart.
        const next = { ...active, networkLockRequired: true };
        await writeManifest(next); active = next;
      }
      if (mock) mockLockRequired = true;
      try {
        lockState = await networkLock.arm({ binding: lockBinding(selected, vpnNode), endpoint: { host: physical.host, ip: endpointIp, port: physical.port, ...(physical.protocol ? { protocol: physical.protocol } : {}) }, corePath });
        lockState = await networkLock.attachTun();
      } catch (error) { lockState = networkLock.snapshot(); throw error; }
      return getStatus({ force: true });
    });
  }

  async function connections() {
    if (mock) return { status: 'mocked', active: 0, observed: 0, observedAt: null, code: null, connections: [] };
    const observed = active, generation = mutationGeneration;
    if (!observed?.coreApi || mutationsPending || stopping) return { status: 'unavailable', active: 0, observed: 0, observedAt: null, code: null, connections: [] };
    const assertCurrent = async () => {
      if (active !== observed || mutationGeneration !== generation || mutationsPending || stopping || !(await inspectOwnedState()).running
        || active !== observed || mutationGeneration !== generation || mutationsPending || stopping) throw failed('SESSION_CHANGED', 'The observed core session changed');
      const owner = await dependencies.listenerOwner(observed.coreApi.port);
      if (!owner || !sameProcess(observed.identity, owner) || !owner.listenAddresses?.includes('127.0.0.1')) throw failed('CORE_API_UNAVAILABLE', 'The observation listener is not owned by this core');
      if (active !== observed || mutationGeneration !== generation || mutationsPending || stopping) throw failed('SESSION_CHANGED', 'The observation session changed during listener inspection');
    };
    try { return await connectionObserver.read({ api: observed.coreApi, sessionId: observed.sessionId, assertCurrent }); }
    catch (cause) {
      if (active !== observed || generation !== mutationGeneration) connectionObserver.reset(active?.coreApi ? active.sessionId : null);
      throw cause;
    }
  }

  async function stop() {
    return run(async () => {
      if (mode !== 'managed') throw failed('PROXY_EXTERNAL', 'External proxies cannot be stopped by this controller');
      if (mock) { mockRunning = false; mockHash = null; lockState = networkLock.snapshot(); return result(false); }
      await recover();
      lockState = networkLock.snapshot();
      if (!active) return result(false);
      const current = await dependencies.inspectProcess(active.identity.pid);
      if (current && !sameProcess(active.identity, current)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The managed proxy identity changed; no process was stopped');
      const stopIntent = markChildStop;
      if (current) stopIntent?.(true);
      stopping = true;
      let cleanClose = false;
      try {
        if (current && active.consoleManaged) {
          try { const closed = await dependencies.closeCore(active.identity, { stopProcess: dependencies.stopProcess }); cleanClose = closed?.closed === true && closed.exitCode === 0; }
          catch { try { options.onDiagnostic?.({ code: 'CORE_CONSOLE_CLOSE_FAILED', operation: 'core-stop' }); } catch {} }
        }
        if (current && !cleanClose) await dependencies.stopProcess(active.identity);
      }
      catch (cause) { stopIntent?.(false); throw cause; }
      finally { stopping = false; }
      const afterStop = await dependencies.inspectProcess(active.identity.pid);
      if (afterStop && sameProcess(active.identity, afterStop)) {
        stopIntent?.(false);
        throw failed('PROCESS_STOP_TIMEOUT', 'The managed proxy has not fully stopped');
      }
      if (cleanClose && active.fakeIpCacheId) await markFakeIpCache(true);
      await cleanup(active);
      detachChild();
      // A stopped core does not release the lock. Re-read our cheap WFP
      // namespace before claiming protection still holds after the stop.
      return result(false);
    });
  }

  return {
    readConfig, start, stop, armNetworkLock, assertCompatibilityReady, assertGlobalReady, networkLock, recoverFakeIpCache,
    holdTraffic: ({ reason } = {}) => changeTrafficGate(true, reason), resumeTraffic: () => changeTrafficGate(false), invalidateOwnedState,
    resumeImportedNode: ({ config, nodes } = {}) => run(async () => {
      validBrowserConfig(config, setupDiscovery);
      lockState = await networkLock.status({ force: true });
      if (config.connectionMode !== 'vpn-import' || !lockState.locked || !Array.isArray(nodes)) throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'Only the exact protected imported node may resume a locked global session');
      for (const candidate of nodes) {
        const node = validateVpnOutbound(candidate.outbound);
        const physical = nodePhysical(node), endpoint = lockState.allowedEndpoint;
        if (lockState.binding === lockBinding(config, node) && isIP(endpoint?.ip || '') && endpoint.host === physical.host && endpoint.port === physical.port
          && (endpoint.protocol || 'TCP') === physical.protocol && (!isIP(physical.host) || physical.host === endpoint.ip)) return clone(node);
      }
      throw failed('NETWORK_LOCK_RECOVERY_REQUIRED', 'The saved imported nodes do not match the protected physical endpoint');
    }),
    status: readStatus, inspectOwnedState, connections,
    assertSafeToUnlock: () => run(async () => {
      if (mock) {
        if (mockRunning) throw failed('PROXY_STILL_RUNNING', 'Stop the proxy before unlocking ordinary networking');
        return { safe: true };
      }
      await recover();
      if (active) {
        const current = await dependencies.inspectProcess(active.identity.pid);
        if (current && !sameProcess(active.identity, current)) throw failed('PROCESS_IDENTITY_MISMATCH', 'The saved core identity changed; unlock requires manual inspection');
        if (current) throw failed('PROXY_STILL_RUNNING', 'Stop the owned core before unlocking ordinary networking');
        await cleanup(active);
      }
      // Older releases did not persist launch intent. Their unowned adapters, or
      // an interface that survives process exit, must still prevent unsafe unlock.
      if ((await readTunPresence()).exists) throw failed('TUN_INTERFACE_IN_USE', 'A ProxyPilot TUN interface still exists; stop or recover its core before unlocking');
      return { safe: true };
    }),
    async dispose({ stop: stopOwned = false } = {}) { if (stopOwned) await stop(); detachChild(); },
  };
}
