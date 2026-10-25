import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { startController } from '../src/local-controller.mjs';
import { createBrowserManager } from '../src/browser-session.mjs';
import { createEnvironmentManager } from '../src/environment-manager.mjs';
import { createClaudeCleanupManager } from '../src/claude-cleanup.mjs';
import { createOnboardingManager } from '../src/onboarding.mjs';
import { createSetupVerifier } from '../src/setup-verification.mjs';
import { createQualityReportStore } from '../src/quality-report.mjs';
import { createRelayManager } from '../src/relay-client.mjs';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { connectionReady } from '../../frontend/workspace-view.js';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const within = promise => new Promise(resolve => {
  const timer = setTimeout(() => resolve({ completed: false }), 500);
  promise.then(value => { clearTimeout(timer); resolve({ completed: true, value }); }, error => { clearTimeout(timer); resolve({ completed: true, error }); });
});

// Native adapters and remote requests are never used. Deadlines below detect
// a blocked queue, rather than establishing a host/network performance SLA.
async function fixture(t, options = {}) {
  const runtimeRoot = path.resolve('.cache/controller-performance-test-never-created');
  const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' },
    probe: { expectedExitIps: ['203.0.113.8'], exitUrl: 'https://fixture.invalid/ip', timeoutMs: 1000 } };
  const f = { running: false, stopped: 0, probeCalls: 0, systemProbeCalls: 0, statusCalls: 0, forcedStatusCalls: 0, ownedCalls: 0, browserCalls: 0, configCalls: 0, clock: Date.now(), probeHook: null, systemProbeHook: null, ownedHook: null };
  const snapshot = () => ({ running: f.running, managed: f.running, mode: options.mode || 'http', port: 17890, tunReady: true, protections: { systemRouting: true },
    configHash: f.running ? createHash('sha256').update(JSON.stringify(config)).digest('hex') : null });
  const runtime = {
    readConfig: async () => { f.configCalls++; return structuredClone(config); },
    status: async (settings = {}) => { f.statusCalls++; if (settings.force) f.forcedStatusCalls++; return snapshot(); },
    inspectOwnedState: async () => { f.ownedCalls++; return await f.ownedHook?.() || snapshot(); },
    start: async () => { f.running = true; return snapshot(); },
    stop: async () => { f.stopped++; f.running = false; },
  };
  let gatewayRunning = false;
  const browsers = createBrowserManager({ runtimeRoot, mock: true });
  f.server = await startController({ port: 0, mock: false, runtime, healthIntervalMs: options.healthIntervalMs ?? 50, autoReport: false,
    ...(options.manualClock ? { now: () => f.clock } : {}),
    runtimeRoot, browsers: { ...browsers, status: async () => { f.browserCalls++; return browsers.status(); } },
    environment: createEnvironmentManager({ stateDir: path.join(runtimeRoot, '.environment'), mock: true }),
    claudeCleanup: createClaudeCleanupManager({ mock: true }), onboarding: createOnboardingManager({ mock: true }),
    setupVerifier: createSetupVerifier({ mock: true }), qualityReports: createQualityReportStore({ mock: true }),
    relayManager: createRelayManager({ mock: true }), vpnConfigStore: createImportedVpnStore({ stateDir: path.join(runtimeRoot, '.vpn-config'), mock: true }),
    applicationGateway: {
      status: () => ({ running: gatewayRunning, policy: 'private-direct-public-isp' }),
      start: async () => { gatewayRunning = true; return { port: 17990, url: 'http://127.0.0.1:17990' }; },
      stop: async () => { gatewayRunning = false; },
    },
    probe: async () => { f.probeCalls++; await f.probeHook?.(); return { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }; },
    loadSecrets: async () => ({}),
    probeSystemExit: async () => {
      assert.equal(options.mode, 'tun', 'The HTTP fixture must not probe the system network');
      f.systemProbeCalls++; await f.systemProbeHook?.(); return { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 };
    },
    requestViaProxy: () => assert.fail('This fixture must not contact any remote service'),
  });
  const base = `http://127.0.0.1:${f.server.address().port}`;
  f.get = async pathname => {
    const response = await fetch(base + pathname, { headers: f.server.controlHeaders() });
    return { status: response.status, body: await response.json() };
  };
  f.post = async (pathname, body) => {
    const response = await fetch(base + pathname, { method: 'POST', headers: { ...f.server.controlHeaders(), 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  t.after(() => f.server.shutdown());
  assert.equal((await f.post('/api/proxy/start', { mode: options.mode || 'http', confirm: true })).status, 200);
  assert.equal(connectionReady((await f.get('/api/status')).body.data), true);
  f.holdHealth = async ({ failureCode } = {}) => {
    const entered = deferred(), release = deferred();
    f.probeHook = async () => {
      f.probeHook = null; entered.resolve(); await release.promise;
      if (failureCode) throw Object.assign(new Error('PRIVATE_OLD_HEALTH_FAILURE'), { code: failureCode });
    };
    t.after(() => release.resolve());
    if (options.manualClock) f.clock += options.healthIntervalMs ?? 50;
    await entered.promise;
    return release;
  };
  return f;
}

async function healthSettled(f) {
  for (let attempt = 0; attempt < 100; attempt++) {
    const snapshot = (await f.get('/api/snapshot')).body.data;
    if (snapshot.health?.state !== 'checking') return snapshot;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.fail('The isolated health check did not settle');
}

test('background health work does not turn a current verified connection into a globally busy UI', { timeout: 3000 }, async t => {
  const f = await fixture(t), release = await f.holdHealth();
  let read;
  try { read = await f.get('/api/status'); }
  finally { release.resolve(); }
  assert.equal(read.status, 200);
  assert.equal(read.body.data.proxy.exitStatus, 'verified');
  assert.equal(connectionReady(read.body.data), true, 'A background check must not disable all verified application actions merely because it is in flight');
});

test('a cached application lease can finish while background health is awaiting an independent probe', { timeout: 3000 }, async t => {
  const f = await fixture(t), release = await f.holdHealth();
  const probes = f.probeCalls;
  const pending = f.server.applicationProxy();
  const result = await within(pending);
  release.resolve(); await pending;
  assert.equal(result.completed, true, 'The still-valid session-bound lease must not wait behind a background HTTPS request');
  assert.equal(result.error, undefined);
  assert.equal(result.value.exitStatus, 'verified');
  assert.equal(f.probeCalls, probes, 'A current bound proof is reused without another outbound request');
});

test('explicit session end can stop its owned core before a stalled background probe completes', { timeout: 3000 }, async t => {
  const f = await fixture(t), release = await f.holdHealth();
  const pending = f.post('/api/session/end', { confirm: true });
  const result = await within(pending);
  release.resolve(); await pending;
  assert.equal(result.completed, true, 'Owned stop must not wait for a read-only background network request');
  assert.equal(result.error, undefined);
  assert.equal(result.value.status, 200);
  assert.equal(f.running, false); assert.equal(f.stopped, 1);
});

test('health failure from a stopped session cannot clear or stop a newly started session', { timeout: 3000 }, async t => {
  const f = await fixture(t), release = await f.holdHealth({ failureCode: 'PROXY_TIMEOUT' });
  assert.equal((await f.post('/api/session/end', { confirm: true })).status, 200);
  assert.equal((await f.post('/api/proxy/start', { mode: 'http', confirm: true })).status, 200);
  await f.server.applicationProxy();
  const before = (await f.get('/api/snapshot')).body.data;
  assert.equal(before.proxy.exitStatus, 'verified');
  release.resolve();
  let after;
  for (let attempt = 0; attempt < 100; attempt++) {
    after = (await f.get('/api/snapshot')).body.data;
    if (after.health?.state !== 'checking') break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(f.stopped, 1, 'Only the explicitly ended old session may be stopped');
  assert.equal(f.running, true, 'An old background error must not stop the replacement core');
  assert.equal(after.revision, before.revision, 'An old failure must not invalidate the new session');
  assert.equal(after.proxy.exitStatus, 'verified', 'The new proof must survive an unrelated old failure');
  assert.equal(after.lastError, null);
});

test('late successful health verification cannot renew the replacement session proof or lend it an old result', { timeout: 3000 }, async t => {
  const f = await fixture(t), release = await f.holdHealth();
  assert.equal((await f.post('/api/session/end', { confirm: true })).status, 200);
  assert.equal((await f.post('/api/proxy/start', { mode: 'http', confirm: true })).status, 200);
  const lease = await f.server.applicationProxy();
  const before = (await f.get('/api/snapshot')).body.data;
  assert.equal(f.probeCalls, 3, 'Replacement startup verifies independently of the old in-flight health result');
  release.resolve();
  let after;
  for (let attempt = 0; attempt < 100; attempt++) {
    after = (await f.get('/api/snapshot')).body.data;
    if (after.health?.state !== 'checking') break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(f.running, true); assert.equal(f.stopped, 1);
  assert.equal(after.revision, before.revision);
  assert.deepEqual(after.proxy.exit, before.proxy.exit, 'Only the independently verified replacement proof remains published');
  assert.equal(after.proxy.exitStatus, 'verified'); assert.equal(after.lastError, null);
  assert.equal((await f.server.applicationProxy()).binding, lease.binding);
  assert.equal(f.probeCalls, 3, 'Neither late success nor a cached lease performs another outbound verification');
});

test('a superseded background owned-state read cannot publish offline over a replacement session', { timeout: 3000 }, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  f.ownedHook = async () => {
    f.ownedHook = null; entered.resolve(); await release.promise;
    // Production inspectOwnedState refuses an in-flight read whose runtime
    // mutation generation changed; it conservatively returns running=false.
    return { running: false, managed: false, mode: 'http', port: 17890 };
  };
  await entered.promise;
  assert.equal((await f.post('/api/session/end', { confirm: true })).status, 200);
  assert.equal((await f.post('/api/proxy/start', { mode: 'http', confirm: true })).status, 200);
  const before = (await f.get('/api/snapshot')).body.data;
  assert.equal(before.proxy.exitStatus, 'verified');
  release.resolve();
  let after;
  for (let attempt = 0; attempt < 100; attempt++) {
    after = (await f.get('/api/snapshot')).body.data;
    if (after.health?.state !== 'checking') break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(f.running, true); assert.equal(f.stopped, 1);
  assert.equal(after.revision, before.revision, 'A superseded native read cannot invalidate the current binding');
  assert.equal(after.proxy.running, true, 'The current controller state must not adopt an old offline result');
  assert.equal(after.proxy.exitStatus, 'verified'); assert.equal(after.lastError, null);
});

test('repeated fresh TUN application leases use one owned check each without full status or browser inventory', async t => {
  const f = await fixture(t, { mode: 'tun', healthIntervalMs: 0 });
  const before = { ...f };
  for (let i = 0; i < 3; i++) assert.equal((await f.server.applicationProxy()).exitStatus, 'verified');
  assert.equal(f.ownedCalls - before.ownedCalls, 3, 'Each cached action still freshly checks its owned core');
  assert.equal(f.statusCalls, before.statusCalls, 'Cached actions must not repeat slow full runtime inspections');
  assert.equal(f.forcedStatusCalls, before.forcedStatusCalls);
  assert.equal(f.browserCalls, before.browserCalls, 'A proxy lease does not need another browser inventory');
  assert.equal(f.probeCalls, before.probeCalls); assert.equal(f.systemProbeCalls, before.systemProbeCalls);
});

test('UI snapshots are cached reads that never invoke native adapters or outbound probes', async t => {
  const f = await fixture(t, { healthIntervalMs: 0 }), before = { ...f };
  const reads = await Promise.all(Array.from({ length: 8 }, () => f.get('/api/snapshot')));
  assert.ok(reads.every(read => read.status === 200 && read.body.data.proxy.exitStatus === 'verified'));
  assert.equal(f.statusCalls, before.statusCalls); assert.equal(f.ownedCalls, before.ownedCalls);
  assert.equal(f.browserCalls, before.browserCalls); assert.equal(f.configCalls, before.configCalls);
  assert.equal(f.probeCalls, before.probeCalls); assert.equal(f.systemProbeCalls, before.systemProbeCalls);
});

test('one temporary TUN health timeout preserves the original unexpired proof without disconnecting or renewing it', { timeout: 3000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true });
  await f.server.applicationProxy();
  const before = (await f.get('/api/snapshot')).body.data;
  const release = await f.holdHealth({ failureCode: 'PROXY_TIMEOUT' });
  release.resolve(); const after = await healthSettled(f);
  assert.equal(f.stopped, 0, 'A failed check endpoint is not proof that the owned TUN route has failed');
  assert.equal(f.running, true); assert.equal(after.proxy.running, true);
  assert.equal(after.applicationProxy.running, true, 'Existing explicit application connections keep their owned gateway');
  assert.equal(after.proxy.exitStatus, 'verified'); assert.deepEqual(after.proxy.exit, before.proxy.exit);
  assert.equal(after.proxy.systemNetwork.observedAt, before.proxy.systemNetwork.observedAt);
  assert.equal(after.health.state, 'degraded'); assert.equal(after.health.errorCode, 'PROXY_TIMEOUT');
  assert.equal((await f.server.applicationProxy()).exitStatus, 'verified');
  assert.equal(f.probeCalls, 2, 'The unchanged, still-valid proof does not require an immediate redundant probe');
});

test('expired proof stays unverified and denies a new lease after soft failures while retaining the running TUN route', { timeout: 3000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true });
  await f.server.applicationProxy();
  const release = await f.holdHealth({ failureCode: 'PROBE_TIMEOUT' });
  f.clock += 90_001; release.resolve();
  const after = await healthSettled(f);
  assert.equal(f.running, true); assert.equal(f.stopped, 0);
  assert.equal(after.applicationProxy.running, true);
  assert.equal(after.proxy.exitStatus, 'unverified'); assert.equal(after.proxy.systemNetwork.status, 'unverified');
  assert.equal(connectionReady(after), false);
  f.probeHook = async () => { throw Object.assign(new Error('PRIVATE_RECHECK_TIMEOUT'), { code: 'PROBE_TIMEOUT' }); };
  await assert.rejects(f.server.applicationProxy(), { code: 'PROBE_TIMEOUT' });
  assert.equal(f.running, true); assert.equal(f.stopped, 0, 'Denying a new application is independent of dismantling existing TUN routing');
  const refused = (await f.get('/api/snapshot')).body.data;
  assert.equal(refused.proxy.exitStatus, 'unverified'); assert.equal(refused.applicationProxy.running, true);
  assert.equal(f.probeCalls, 3);
});

test('a temporary system DNS health failure retains only the previous proof and keeps its TUN session running', { timeout: 3000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true });
  const before = (await f.get('/api/snapshot')).body.data;
  const release = await f.holdHealth();
  f.systemProbeHook = async () => { throw Object.assign(new Error('PRIVATE_DNS_FAILURE'), { code: 'SYSTEM_DNS_FAILED' }); };
  release.resolve(); const after = await healthSettled(f);
  assert.equal(f.running, true); assert.equal(f.stopped, 0);
  assert.deepEqual(after.proxy.exit, before.proxy.exit);
  assert.equal(after.proxy.systemNetwork.observedAt, before.proxy.systemNetwork.observedAt);
  assert.equal(after.health.state, 'degraded'); assert.equal(after.health.errorCode, 'SYSTEM_DNS_FAILED');
});

test('a confirmed ISP mismatch remains a hard health failure and stops the owned TUN session', { timeout: 3000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true });
  const release = await f.holdHealth({ failureCode: 'EXIT_IP_MISMATCH' });
  release.resolve(); const after = await healthSettled(f);
  assert.equal(f.running, false); assert.equal(f.stopped, 1);
  assert.equal(after.proxy.exitStatus, 'unverified'); assert.equal(connectionReady(after), false);
});

test('loss of the actual local TUN remains a hard failure rather than a degraded check endpoint', { timeout: 3000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true }), entered = deferred();
  f.ownedHook = async () => {
    f.ownedHook = null; entered.resolve();
    return { running: true, managed: true, mode: 'tun', port: 17890, tunReady: false };
  };
  f.clock += 50; await entered.promise;
  const after = await healthSettled(f);
  assert.equal(f.running, false); assert.equal(f.stopped, 1);
  assert.equal(after.proxy.exitStatus, 'unverified'); assert.equal(connectionReady(after), false);
});

test('temporary owned inspection failures preserve the TUN route but cannot authorize a new application', { timeout: 5000 }, async t => {
  for (const code of ['PROCESS_QUERY_FAILED', 'TUN_STATE_UNAVAILABLE']) {
    const f = await fixture(t, { mode: 'tun', manualClock: true });
    await f.server.applicationProxy();
    const before = (await f.get('/api/snapshot')).body.data;
    const entered = deferred(), release = deferred();
    t.after(() => release.resolve());
    f.ownedHook = async () => {
      entered.resolve(); await release.promise;
      throw Object.assign(new Error('PRIVATE_NATIVE_QUERY_FAILURE'), { code });
    };
    f.clock += 50; await entered.promise;
    release.resolve(); const after = await healthSettled(f);
    assert.equal(f.running, true); assert.equal(f.stopped, 0);
    assert.equal(after.applicationProxy.running, true);
    assert.deepEqual(after.proxy.exit, before.proxy.exit, 'An uncertain local read cannot renew the original exit proof');
    assert.equal(after.proxy.systemNetwork.observedAt, before.proxy.systemNetwork.observedAt);
    assert.equal(after.health.state, 'degraded'); assert.equal(after.health.errorCode, code);
    await assert.rejects(f.server.applicationProxy(), { code });
    assert.equal(f.running, true); assert.equal(f.stopped, 0);
    assert.equal(f.probeCalls, 1, 'No outbound proof is produced without the fresh owned identity check');
  }
});

test('repeated soft failures do not extend proof lifetime and a later successful check restores verification', { timeout: 5000 }, async t => {
  const f = await fixture(t, { mode: 'tun', manualClock: true });
  const original = (await f.get('/api/snapshot')).body.data;
  for (const failureCode of ['PROXY_TIMEOUT', 'PROBE_RESPONSE_FAILED']) {
    const release = await f.holdHealth({ failureCode });
    release.resolve(); const failed = await healthSettled(f);
    assert.equal(f.running, true); assert.equal(f.stopped, 0);
    assert.deepEqual(failed.proxy.exit, original.proxy.exit);
    assert.equal(failed.proxy.systemNetwork.observedAt, original.proxy.systemNetwork.observedAt);
    assert.equal(failed.health.state, 'degraded');
  }
  f.clock += 90_001;
  const expired = (await f.get('/api/snapshot')).body.data;
  assert.equal(expired.proxy.exitStatus, 'unverified'); assert.equal(connectionReady(expired), false);
  const release = await f.holdHealth();
  const checking = (await f.get('/api/snapshot')).body.data;
  assert.equal(checking.proxy.exitStatus, 'unverified', 'A pending retry cannot resurrect the expired evidence');
  release.resolve(); const restored = await healthSettled(f);
  assert.equal(f.running, true); assert.equal(f.stopped, 0);
  assert.equal(restored.proxy.exitStatus, 'verified'); assert.equal(restored.proxy.systemNetwork.status, 'verified');
  assert.notEqual(restored.proxy.exit.observedAt, original.proxy.exit.observedAt);
  assert.equal(restored.health.state, 'idle'); assert.equal(restored.health.errorCode, null);
  assert.equal((await f.server.applicationProxy()).exitStatus, 'verified');
  assert.equal(f.probeCalls, 4, 'Startup, two failed checks and one successful retry are the only explicit proxy probes');
  assert.equal(f.systemProbeCalls, 2, 'Only startup and the successful retry may complete a system exit proof');
});
