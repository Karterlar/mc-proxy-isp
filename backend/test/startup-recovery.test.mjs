import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { startController } from '../src/local-controller.mjs';

async function fixture(t, stage = 'onboarding', healthIntervalMs = 0) {
  const calls = { onboardingStatus: 0, configuration: 0, save: 0, preferences: 0, recovery: 0, runtimeStatus: 0, readConfig: 0, start: 0, browser: 0, verify: 0, probe: 0 };
  const f = { failing: true, calls };
  const failure = code => Object.assign(new Error('private recovery evidence must not escape'), { code });
  const configuration = { available: true, pinned: true, expectedExitIps: ['203.0.113.8'] };
  const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' }, probe: { exitUrl: 'https://example.test/ip', expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
  const onboarding = {
    status: async () => { calls.onboardingStatus++; if (f.failing && stage === 'onboarding') throw failure('ONBOARDING_RECOVERY_REQUIRED'); return { firstRun: false, completedAt: '2026-10-02T00:00:00Z', preferences: { autoOptimize: false, browser: 'chrome', fresh: true } }; },
    configuration: async () => { calls.configuration++; return configuration; },
    saveConfiguration: async () => { calls.save++; return configuration; },
    preferences: async () => { calls.preferences++; return {}; },
  };
  const runtime = {
    status: async () => { calls.runtimeStatus++; return { running: false, managed: false, port: 17890 }; },
    readConfig: async () => { calls.readConfig++; return structuredClone(config); },
    start: async () => { calls.start++; throw new Error('must not start'); },
    stop: async () => ({ running: false }), dispose: async () => {},
  };
  f.server = await startController({ port: 0, mock: true, healthIntervalMs, onboarding, runtime,
    setupVerifier: { recoverAndStop: async () => { calls.recovery++; if (f.failing && stage === 'setup') throw failure('PROCESS_IDENTITY_MISMATCH'); }, verify: async () => { calls.verify++; throw new Error('must not probe'); } },
    environment: { initialize: async () => ({ status: 'not_checked' }), status: () => ({ status: 'not_checked' }) },
    browsers: { status: async () => ({ running: false }), listBrowsers: async () => [], close: async () => {}, launch: async () => { calls.browser++; } },
    probe: async () => { calls.probe++; throw new Error('must not probe'); },
  });
  t.after(() => new Promise(resolve => f.server.close(resolve)));
  const base = `http://127.0.0.1:${f.server.address().port}`;
  f.get = async pathname => { const response = await fetch(base + pathname, { headers: f.server.controlHeaders() }); return { status: response.status, body: await response.json() }; };
  f.post = async (pathname, body = {}) => { const response = await fetch(base + pathname, { method: 'POST', headers: { ...f.server.controlHeaders(), 'content-type': 'application/json' }, body: JSON.stringify(body) }); return { status: response.status, body: await response.json() }; };
  f.base = base;
  return f;
}

test('failed configuration recovery leaves the UI server visible without reading a partial pair', async t => {
  const f = await fixture(t);
  assert.equal((await fetch(f.base + '/')).status, 200);
  const status = await f.get('/api/status');
  const onboarding = await f.get('/api/onboarding');
  assert.equal(status.status, 200); assert.equal(onboarding.status, 200);
  assert.equal(status.body.data.startupRecovery.required, true);
  assert.equal(status.body.data.startupRecovery.error.code, 'ONBOARDING_RECOVERY_REQUIRED');
  assert.equal(onboarding.body.data.onboarding.recoveryRequired, true);
  assert.equal(onboarding.body.data.configuration.available, false);
  assert.equal(onboarding.body.data.startupRecovery.required, true);
  assert.equal(JSON.stringify([status.body, onboarding.body]).includes('private recovery evidence'), false);
  assert.equal(f.calls.onboardingStatus, 1, 'GET never retries or changes the failed journal');
  for (const key of ['configuration', 'recovery', 'runtimeStatus', 'readConfig']) assert.equal(f.calls[key], 0, key);
});

test('failed setup-core recovery is surfaced before any current ISP configuration read', async t => {
  const f = await fixture(t, 'setup');
  const status = await f.get('/api/status');
  assert.equal(status.body.data.startupRecovery.error.code, 'PROCESS_IDENTITY_MISMATCH');
  assert.equal(f.calls.recovery, 1);
  for (const key of ['configuration', 'runtimeStatus', 'readConfig']) assert.equal(f.calls[key], 0, key);
});

test('recovery guard blocks configuration, quality, proxy and browser actions before dependencies', async t => {
  const f = await fixture(t);
  for (const [route, body] of [
    ['/api/configuration/save', {}], ['/api/quality/check', {}], ['/api/proxy/start', { confirm: true }],
    ['/api/browser/plan', {}], ['/api/browser/launch', { confirm: true }], ['/api/onboarding/preferences', { completed: true }],
    ['/api/probes', {}], ['/api/environment/optimize', { confirm: true }],
  ]) {
    const result = await f.post(route, body);
    assert.equal(result.status, 409, route);
    assert.equal(result.body.error.code, 'STARTUP_RECOVERY_REQUIRED', route);
  }
  for (const key of ['configuration', 'save', 'preferences', 'runtimeStatus', 'readConfig', 'start', 'browser', 'verify', 'probe']) assert.equal(f.calls[key], 0, key);
});

test('health checks stay dormant until startup recovery is explicitly retried after repair', async t => {
  const f = await fixture(t, 'onboarding', 10);
  await delay(60);
  assert.equal(f.calls.onboardingStatus, 1);
  assert.equal(f.calls.runtimeStatus, 0); assert.equal(f.calls.readConfig, 0);
  f.failing = false;
  // Application restart performs the same initialize step. No polling request
  // is permitted to clear this guard implicitly.
  await f.server.initialize();
  const status = await f.get('/api/status');
  assert.equal(status.body.data.startupRecovery.required, false);
  assert.equal(status.body.data.lastError, null);
  assert.equal((await f.get('/api/onboarding')).body.data.configuration.available, true);
  assert.equal((await f.post('/api/configuration/save')).status, 200);
  assert.equal(f.calls.save, 1);
});
