import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
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
const fingerprint = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function until(predicate, description) {
  for (let attempt = 0; attempt < 200; attempt++) { if (predicate()) return; await delay(5); }
  assert.fail(description);
}

async function fixture(t) {
  const sockets = new Set();
  let coreConnects = 0, running = false, reads = 0, clock = 0;
  const core = http.createServer();
  core.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  core.on('connect', (_request, socket) => { coreConnects++; socket.write('HTTP/1.1 200 Connection established\r\n\r\n'); socket.on('data', data => socket.write(data)); });
  await new Promise(resolve => core.listen(0, '127.0.0.1', resolve));
  const port = core.address().port;
  const config = { version: 1, listen: { host: '127.0.0.1', port }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' },
    probe: { expectedExitIps: ['203.0.113.8'], exitUrl: 'https://fixture.invalid/ip', timeoutMs: 1000 } };
  const owned = () => ({ running, managed: running, mode: 'http', port, sessionId: 'loopback-burst-fixture', configHash: fingerprint(config) });
  const f = { read: async () => owned() };
  const runtime = { readConfig: async () => structuredClone(config), status: async () => owned(),
    inspectOwnedState: async () => { reads++; return f.read(); },
    start: async () => { running = true; return owned(); }, stop: async () => { running = false; } };
  const neverCreated = path.resolve('.cache/gateway-burst-memory-only');
  const controller = await startController({ port: 0, mock: false, healthIntervalMs: 0, autoReport: false, runtimeRoot: neverCreated, runtime,
    now: () => clock, loadSecrets: async () => ({}), probe: async () => ({ ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }),
    browsers: createBrowserManager({ runtimeRoot: neverCreated, mock: true }), environment: createEnvironmentManager({ stateDir: neverCreated, mock: true }),
    claudeCleanup: createClaudeCleanupManager({ mock: true }), onboarding: createOnboardingManager({ mock: true }), setupVerifier: createSetupVerifier({ mock: true }),
    qualityReports: createQualityReportStore({ mock: true }), relayManager: createRelayManager({ mock: true }), vpnConfigStore: createImportedVpnStore({ stateDir: neverCreated, mock: true }),
    requestViaProxy: () => assert.fail('no external site request'), directHttpsRequest: () => assert.fail('no system site request'),
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await controller.shutdown();
    await new Promise(resolve => core.close(resolve));
  });
  const started = await fetch(`http://127.0.0.1:${controller.address().port}/api/proxy/start`, {
    method: 'POST', headers: { ...controller.controlHeaders(), 'content-type': 'application/json' }, body: JSON.stringify({ confirm: true, mode: 'http' }),
  });
  assert.equal(started.status, 200, JSON.stringify(await started.json()));
  const lease = await controller.applicationProxy();
  f.controller = controller;
  f.reads = () => reads; f.coreConnects = () => coreConnects;
  f.expire = () => { clock += 90_001; };
  f.connect = () => new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: lease.port }); sockets.add(socket);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('loopback fixture timed out')); }, 2000);
    let data = '';
    socket.on('error', reject); socket.once('close', () => { sockets.delete(socket); clearTimeout(timer); });
    socket.once('connect', () => socket.write('CONNECT public.fixture.invalid:443 HTTP/1.1\r\nHost: public.fixture.invalid:443\r\n\r\n'));
    const response = bytes => {
      data += bytes.toString(); if (!data.includes('\r\n\r\n')) return;
      clearTimeout(timer); socket.off('data', response);
      const status = Number(/^HTTP\/1\.1 (\d+)/.exec(data)?.[1]); socket.destroy(); resolve(status);
    };
    socket.on('data', response);
  });
  return f;
}

test('50 concurrent CONNECTs share one current owned read and preserve the 32 pending limit', async t => {
  const f = await fixture(t), held = deferred();
  const before = f.reads(), read = f.read;
  f.read = async () => { await held.promise; return read(); };
  t.after(() => held.resolve());
  let overloads = 0;
  const clients = Promise.all(Array.from({ length: 50 }, () => f.connect().then(status => { if (status === 503) overloads++; return status; })));
  await until(() => overloads === 18, 'all 50 requests must reach the bounded gateway');
  assert.equal(f.reads() - before, 1); assert.equal(f.coreConnects(), 0);
  held.resolve(); const statuses = await clients;
  assert.equal(statuses.filter(status => status === 200).length, 32);
  assert.equal(statuses.filter(status => status === 503).length, 18);
  assert.equal(f.reads() - before, 1); assert.equal(f.coreConnects(), 32);
});

test('consecutive bursts share each in-flight read but completed ownership results are never cached', async t => {
  const f = await fixture(t), before = f.reads();
  const read = f.read; f.read = async () => { await delay(30); return read(); };
  for (let wave = 1; wave <= 5; wave++) {
    const statuses = await Promise.all(Array.from({ length: 10 }, () => f.connect()));
    assert.deepEqual(statuses, Array(10).fill(200));
    assert.equal(f.reads() - before, wave, 'each completed wave requires one fresh authority check');
  }
  assert.equal(f.coreConnects(), 50);
});

test('unknown identity and expired evidence cannot reuse an earlier burst result or reach the core', async t => {
  const f = await fixture(t), before = f.reads(), read = f.read;
  f.read = async () => { await delay(30); return read(); };
  assert.deepEqual(await Promise.all(Array.from({ length: 10 }, () => f.connect())), Array(10).fill(200));
  const reached = f.coreConnects();
  f.read = async () => { await delay(30); throw Object.assign(new Error('PRIVATE_NATIVE_COMMAND'), { code: 'PROCESS_QUERY_FAILED' }); };
  assert.deepEqual(await Promise.all(Array.from({ length: 10 }, () => f.connect())), Array(10).fill(502));
  assert.equal(f.reads() - before, 2); assert.equal(f.coreConnects(), reached);
  f.read = read; f.expire();
  assert.equal(await f.connect(), 502); assert.equal(f.reads() - before, 2); assert.equal(f.coreConnects(), reached);
});
