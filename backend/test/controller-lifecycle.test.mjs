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

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const fingerprint = input => createHash('sha256').update(JSON.stringify(input)).digest('hex');

// All adapters are in-memory. Even "real" verification below is an injected
// deterministic result; the only listening socket is this loopback controller.
async function fixture(t, options = {}) {
  const runtimeRoot = path.resolve('.cache/controller-lifecycle-test-never-created');
  const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' },
    probe: { expectedExitIps: ['203.0.113.8'], exitUrl: 'https://fixture.invalid/ip', timeoutMs: 1000 } };
  const f = { running: false, browserRunning: false, stopped: 0, probeCalls: 0, statusHook: null, probeHook: null, connectionReads: 0, failedStops: 0, clock: Date.now() };
  const runtime = {
    readConfig: async () => structuredClone(config),
    status: async () => {
      await f.statusHook?.();
      return { running: f.running, managed: f.running, port: 17890, mode: 'http', configHash: f.running ? fingerprint(config) : null };
    },
    start: async () => { f.running = true; return runtime.status(); },
    stop: async () => { f.stopped++; if (f.failedStops-- > 0) throw Object.assign(new Error('PRIVATE_STOP_MESSAGE'), { code: 'PROCESS_STOP_TIMEOUT' }); f.running = false; },
    connections: async () => { f.connectionReads++; return { status: 'observed', active: 1, observed: 2, connections: [{ kind: 'isp', transport: 'tcp', status: 'active' }] }; },
  };
  const plans = createBrowserManager({ mock: true, runtimeRoot });
  f.server = await startController({ port: 0, mock: false, runtime, appVersion: '1.3.3', healthIntervalMs: options.healthIntervalMs ?? 0, autoReport: false,
    ...(options.manualClock ? { now: () => f.clock } : {}),
    browsers: { ...plans, status: async () => ({ running: f.browserRunning }), close: async () => { f.browserRunning = false; } },
    environment: createEnvironmentManager({ mock: true, stateDir: path.join(runtimeRoot, '.environment') }), claudeCleanup: createClaudeCleanupManager({ mock: true }),
    onboarding: createOnboardingManager({ mock: true }), setupVerifier: createSetupVerifier({ mock: true }),
    qualityReports: createQualityReportStore({ mock: true }), relayManager: createRelayManager({ mock: true }),
    vpnConfigStore: createImportedVpnStore({ mock: true, stateDir: path.join(runtimeRoot, '.vpn-config') }), loadSecrets: async () => ({}),
    probe: async () => { f.probeCalls++; await f.probeHook?.(); return { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }; },
    probeSystemExit: () => assert.fail('HTTP lifecycle fixture must not use a system network probe'),
    requestViaProxy: () => assert.fail('No remote service requests are permitted in this fixture'),
  });
  t.after(() => new Promise(resolve => f.server.close(resolve)));
  const base = `http://127.0.0.1:${f.server.address().port}`;
  f.get = async (pathname, settings = {}) => {
    const response = await fetch(base + pathname, { ...settings, headers: { ...f.server.controlHeaders(), ...settings.headers } });
    return { status: response.status, body: await response.json() };
  };
  f.post = (pathname, body = {}) => f.get(pathname, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await f.post('/api/proxy/start', { mode: 'http', confirm: true })).status, 200);
  return f;
}

test('suspend during the initial native state read cannot be absorbed into a new verification revision', { timeout: 3000 }, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  f.statusHook = async () => { f.statusHook = null; entered.resolve(); await release.promise; };
  const pending = f.post('/api/probes'); await entered.promise;
  f.server.suspendNetwork(); release.resolve();
  const response = await pending;
  const snapshot = (await f.get('/api/snapshot')).body.data;
  assert.notEqual(response.status, 200, 'A pre-suspend request must not publish success after absorbing the revision change');
  assert.equal(snapshot.networkLifecycle.state, 'suspended'); assert.equal(snapshot.proxy.exitStatus, 'unverified');
  assert.equal(f.running, true, 'Suspending invalidates verification without stopping the owned core');
});

test('a late ordinary probe after suspend cannot stop a browser session core or publish its exit', { timeout: 3000 }, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  f.browserRunning = true;
  f.probeHook = async () => { f.probeHook = null; entered.resolve(); await release.promise; };
  const pending = f.post('/api/probes'); await entered.promise;
  f.server.suspendNetwork(); release.resolve();
  assert.notEqual((await pending).status, 200);
  assert.equal(f.running, true, 'A superseded probe must leave the current core available for resume revalidation');
  assert.equal(f.stopped, 0);
  assert.equal((await f.get('/api/snapshot')).body.data.proxy.exitStatus, 'unverified');
});

test('resume and overlapping adapter changes coalesce; a subsequent suspend supersedes late revalidation', { timeout: 3000 }, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  f.server.suspendNetwork();
  f.probeHook = async () => { f.probeHook = null; entered.resolve(); await release.promise; };
  const resume = f.server.networkChanged('resume'); await entered.promise;
  const changed = f.server.networkChanged('adapter-change'); assert.equal(changed, resume);
  f.server.suspendNetwork(); release.resolve();
  const result = await resume;
  assert.equal(result.networkLifecycle.state, 'suspended'); assert.equal(result.proxy.exitStatus, 'unverified');
  assert.equal(f.running, true); assert.equal(f.stopped, 0);
  const resumed = await f.server.networkChanged('resume');
  assert.equal(resumed.networkLifecycle.state, 'stable'); assert.equal(resumed.proxy.exitStatus, 'verified');
  assert.equal(f.probeCalls, 3, 'Only startup, the superseded refresh and a single successful resume may probe');
});

test('a temporary resume failure retains the owned route but cannot borrow the previous network proof or issue a lease', { timeout: 3000 }, async t => {
  const f = await fixture(t);
  f.server.suspendNetwork();
  f.probeHook = async () => { throw Object.assign(new Error('PRIVATE_PROBE_MESSAGE'), { code: 'PROXY_TIMEOUT' }); };
  const result = await f.server.networkChanged('resume');
  assert.equal(result.networkLifecycle.state, 'unverified'); assert.equal(result.proxy.exitStatus, 'unverified');
  assert.equal(f.running, true); assert.equal(f.stopped, 0); assert.doesNotMatch(JSON.stringify(result.lastError), /PRIVATE/);
  assert.equal(result.proxy.exit, null); assert.equal(result.health.state, 'degraded');
  const probes = f.probeCalls;
  await assert.rejects(f.server.applicationProxy(), { code: 'NETWORK_RECHECK_REQUIRED' });
  assert.equal(f.probeCalls, probes, 'A new app cannot use a pre-resume proof or initiate its own unrelated network refresh');
  assert.equal(f.running, true); assert.equal(f.stopped, 0);
});

test('a successful bounded health retry restores only the changed network proof after a temporary resume failure', { timeout: 3000 }, async t => {
  const f = await fixture(t, { healthIntervalMs: 50, manualClock: true });
  const original = structuredClone(f.server.state.proxy.exit);
  f.server.suspendNetwork();
  f.probeHook = async () => { throw Object.assign(new Error('PRIVATE_RESUME_TIMEOUT'), { code: 'PROXY_TIMEOUT' }); };
  const failed = await f.server.networkChanged('resume');
  assert.equal(failed.networkLifecycle.state, 'unverified'); assert.equal(failed.proxy.exitStatus, 'unverified');
  assert.equal(f.running, true); assert.equal(f.stopped, 0); assert.equal(f.probeCalls, 2);
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  f.probeHook = async () => { f.probeHook = null; entered.resolve(); await release.promise; };
  f.clock += 50; await entered.promise;
  const pending = (await f.get('/api/snapshot')).body.data;
  assert.equal(pending.health.state, 'checking'); assert.equal(pending.networkLifecycle.state, 'unverified');
  assert.equal(pending.proxy.exitStatus, 'unverified'); assert.equal(pending.proxy.exit, null);
  await assert.rejects(f.server.applicationProxy(), { code: 'NETWORK_RECHECK_REQUIRED' });
  release.resolve();
  let restored;
  for (let attempt = 0; attempt < 100; attempt++) {
    restored = (await f.get('/api/snapshot')).body.data;
    if (restored.networkLifecycle.state === 'stable') break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(restored.networkLifecycle.state, 'stable'); assert.equal(restored.proxy.exitStatus, 'verified');
  assert.equal(restored.health.state, 'idle'); assert.equal(restored.lastError, null);
  assert.equal(f.running, true); assert.equal(f.stopped, 0); assert.equal(f.probeCalls, 3);
  assert.notEqual(f.server.state.proxy.exit.binding, original.binding);
  assert.equal(f.server.state.proxy.exit.checkedAt, f.clock);
  assert.notEqual(f.server.state.proxy.exit.checkedAt, original.checkedAt, 'Only the successful new-generation probe may establish a fresh deadline');
});

test('connection observations and share preview are authenticated reads without verification traffic', async t => {
  const f = await fixture(t); const before = f.probeCalls;
  f.server.state.lastError = { code: 'NETWORK_LOCK_TIMEOUT', message: 'PRIVATE_ERROR', diagnostic: { ip: '192.0.2.5', path: 'C:\\PRIVATE_PATH' } };
  const connections = await f.get('/api/connections');
  assert.equal(connections.status, 200); assert.equal(connections.body.data.active, 1); assert.equal(f.connectionReads, 1);
  const summary = await f.get('/api/diagnostics/summary');
  assert.equal(summary.status, 200); assert.equal(summary.body.data.version, '1.3.3'); assert.equal(summary.body.data.code, 'NETWORK_LOCK_TIMEOUT');
  assert.doesNotMatch(JSON.stringify(summary.body.data), /PRIVATE|192\.0|203\.0|127\.0|fixture\.invalid|:\/\//);
  assert.equal(f.probeCalls, before);
  for (const pathname of ['/api/connections', '/api/diagnostics/summary']) {
    assert.equal((await f.get(pathname, { headers: { 'x-mc-control-token': '' } })).status, 401);
  }
});

test('new operations refused during suspended state do not stop an otherwise owned browser runtime', { timeout: 3000 }, async t => {
  const f = await fixture(t); f.browserRunning = true;
  f.server.suspendNetwork(); const before = f.probeCalls;
  const result = await f.post('/api/probes');
  assert.equal(result.status, 409); assert.equal(result.body.error.code, 'NETWORK_RECHECK_REQUIRED');
  assert.equal(f.running, true); assert.equal(f.stopped, 0); assert.equal(f.probeCalls, before);
  const snapshot = (await f.get('/api/snapshot')).body.data;
  assert.equal(snapshot.networkLifecycle.state, 'suspended'); assert.equal(snapshot.proxy.exitStatus, 'unverified');
});

test('failed current-network cleanup retries owned stop while nonstable health verification stays paused', { timeout: 3000 }, async t => {
  const f = await fixture(t, { healthIntervalMs: 100 });
  f.server.suspendNetwork(); f.failedStops = 1;
  f.probeHook = async () => { throw Object.assign(new Error('PRIVATE_PROBE_MESSAGE'), { code: 'EXIT_IP_MISMATCH' }); };
  const result = await f.server.networkChanged('resume'); const before = f.probeCalls;
  assert.equal(result.networkLifecycle.state, 'unverified'); assert.equal(result.blockPending, true);
  for (let attempt = 0; attempt < 80 && f.running; attempt++) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(f.running, false, 'Nonstable network state must not disable pending owned-core cleanup');
  assert.equal(f.stopped, 2); assert.equal(f.probeCalls, before, 'A cleanup retry must not generate another network request');
  assert.equal((await f.get('/api/snapshot')).body.data.blockPending, false);
});

test('late health failure after suspend and coalesced network changes cannot stop the next generation or revoke its proof', { timeout: 3000 }, async t => {
  const f = await fixture(t, { healthIntervalMs: 100 }), entered = deferred(), release = deferred();
  f.probeHook = async () => {
    f.probeHook = null; entered.resolve(); await release.promise;
    throw Object.assign(new Error('PRIVATE_OLD_HEALTH_FAILURE'), { code: 'PROXY_TIMEOUT' });
  };
  await entered.promise;
  f.server.suspendNetwork();
  const resumed = f.server.networkChanged('resume');
  const changed = f.server.networkChanged('adapter-change');
  assert.equal(changed, resumed, 'Network changes while health is in flight must share the queued refresh');
  release.resolve();
  const result = await resumed;
  assert.equal(f.running, true, 'A failed health result from before suspend must not stop the current owned core');
  assert.equal(f.stopped, 0);
  assert.equal(result.networkLifecycle.state, 'stable');
  assert.equal(result.proxy.exitStatus, 'verified');
  assert.equal(result.lastError, null);
  const snapshot = (await f.get('/api/snapshot')).body.data;
  assert.equal(snapshot.proxy.exitStatus, 'verified', 'The superseded health result must not revoke the new proof');
  assert.equal(snapshot.proxy.requestedStop, false);
});
