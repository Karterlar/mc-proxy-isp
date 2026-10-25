import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createCoreConnectionObserver, requestCoreConnections, setCoreTrafficBlocked } from '../src/core-connections.mjs';

const api = { port: 17991, secret: 'a'.repeat(64) };
const raw = (id = 'core-1', metadata = {}) => ({ id, upload: 42, download: 123, rule: 'credential-private.invalid => isp-upstream',
  chains: ['isp-upstream', 'vpn-entry'], metadata: { type: 'tun/system-tun', network: 'tcp', host: 'api.anthropic.com', processPath: 'C:\\Users\\private-user\\Claude.exe (private-user)', sourceIP: '192.0.2.5', destinationPort: '443', ...metadata } });

test('connection observation exposes bounded fixed categories, without raw host, credentials or private paths', async () => {
  const observer = createCoreConnectionObserver({ request: async () => ({ connections: [raw()] }), now: () => 1000 });
  const result = await observer.read({ api, sessionId: 'session-1' });
  assert.equal(result.status, 'observed'); assert.equal(result.active, 1);
  assert.deepEqual(result.connections[0], { id: result.connections[0].id, application: 'claude', target: 'ai-service', inbound: 'tun', network: 'tcp',
    route: 'isp', destinationForm: 'domain', domainAvailable: true, upload: 42, download: 123, active: true, observedAt: '1970-01-01T00:00:01.000Z' });
  assert.doesNotMatch(JSON.stringify(result), /anthropic|private-user|credential|192\.0\.2|vpn-entry|aaaaa/);
});

test('same-session concurrent reads share one request and remember only observed closed connections', async () => {
  let finish, calls = 0; const held = new Promise(resolve => { finish = resolve; });
  const observer = createCoreConnectionObserver({ request: async () => { calls++; await held; return { connections: calls === 1 ? [raw()] : [] }; } });
  const first = observer.read({ api, sessionId: 'session-1' }), second = observer.read({ api, sessionId: 'session-1' });
  finish(); assert.deepEqual(await first, await second); assert.equal(calls, 1);
  const closed = await observer.read({ api, sessionId: 'session-1' });
  assert.equal(closed.active, 0); assert.equal(closed.connections[0].active, false);
});

test('old session results cannot mutate the new session observation', async () => {
  let finish; const held = new Promise(resolve => { finish = resolve; });
  const observer = createCoreConnectionObserver({ request: async () => { await held; return { connections: [raw()] }; } });
  const first = observer.read({ api, sessionId: 'old' }); observer.reset('new'); finish();
  await assert.rejects(first, { code: 'SESSION_CHANGED' });
  assert.deepEqual(observer.snapshot().connections, []); assert.equal(observer.status().status, 'idle');
});

test('IPv6 literal observation describes the compatibility boundary without claiming SNI destination replacement', async () => {
  const observer = createCoreConnectionObserver({ request: async () => ({ connections: [raw('v6', { destinationIP: '2001:db8::1', processPath: 'C:\\node.exe' })] }) });
  const result = await observer.read({ api, sessionId: 'test' });
  assert.equal(result.connections[0].application, 'node'); assert.equal(result.connections[0].domainAvailable, true);
  assert.equal(result.connections[0].destinationForm, 'ipv6-literal');
  assert.equal(result.connections[0].diagnostic, 'IP_LITERAL_REQUIRES_PROVIDER_SUPPORT');
  assert.doesNotMatch(JSON.stringify(result), /2001:db8|anthropic/);
});

test('memory history is limited and malformed responses or failed reads never remain live', async () => {
  let response = { connections: Array.from({ length: 300 }, (_, i) => raw(`core-${i}`)) }, clock = 1000;
  const observer = createCoreConnectionObserver({ request: async () => response, now: () => clock });
  assert.equal((await observer.read({ api, sessionId: 'test' })).connections.length, 128);
  response = { connections: null }; await assert.rejects(observer.read({ api, sessionId: 'test' }), { code: 'CORE_API_RESPONSE_INVALID' });
  assert.equal(observer.status().active, 0); assert.ok(observer.snapshot().connections.every(value => !value.active));
  response = { connections: [] }; clock += 300001;
  assert.equal((await observer.read({ api, sessionId: 'test' })).connections.length, 0);
});

test('current-session checks run on both sides of the request and reject an ownership change', async () => {
  let checks = 0, requests = 0;
  const observer = createCoreConnectionObserver({ request: async () => { requests++; return { connections: [raw()] }; } });
  await assert.rejects(observer.read({ api, sessionId: 'test', assertCurrent: async () => { if (++checks === 2) throw Object.assign(new Error(), { code: 'SESSION_CHANGED' }); } }), { code: 'SESSION_CHANGED' });
  assert.equal(requests, 1); assert.deepEqual(observer.snapshot().connections, []);
});

test('real loopback request authenticates only the fixed read endpoint, rejects denied and oversized responses', async t => {
  let mode = 'ok', headers;
  const server = http.createServer((request, response) => {
    headers = request.headers; assert.equal(request.method, 'GET'); assert.equal(request.url, '/connections');
    if (mode === 'denied') { response.writeHead(401); response.end(); }
    else if (mode === 'large') response.end('x'.repeat(1024 * 1024 + 1));
    else response.end(JSON.stringify({ connections: [] }));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => new Promise(resolve => server.close(resolve)));
  const endpoint = { ...api, port: server.address().port };
  assert.deepEqual(await requestCoreConnections(endpoint), { connections: [] }); assert.equal(headers.authorization, `Bearer ${api.secret}`);
  mode = 'denied'; await assert.rejects(requestCoreConnections(endpoint), { code: 'CORE_API_AUTH_FAILED' });
  mode = 'large'; await assert.rejects(requestCoreConnections(endpoint), { code: 'CORE_API_RESPONSE_INVALID' });
});

async function gateFixture(t, respond) {
  const calls = [], sockets = new Set();
  const server = http.createServer(async (request, response) => {
    let body = ''; for await (const chunk of request) body += chunk;
    assert.equal(request.headers.authorization, `Bearer ${api.secret}`);
    calls.push({ method: request.method, path: request.url, body });
    await respond(request, response, body, calls);
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { calls, sockets, endpoint: { ...api, port: server.address().port } };
}

test('authenticated traffic gate confirms PATCH through GET before draining connections; resume never drains', async t => {
  let mode;
  const f = await gateFixture(t, (request, response, body) => {
    if (request.method === 'PATCH') { mode = JSON.parse(body).mode; response.writeHead(204); response.end(); }
    else if (request.method === 'GET') response.end(JSON.stringify({ mode }));
    else { assert.equal(request.method, 'DELETE'); response.writeHead(204); response.end(); }
  });
  assert.deepEqual(await setCoreTrafficBlocked(f.endpoint, true), { blocked: true, confirmed: true });
  assert.deepEqual(f.calls, [{ method: 'PATCH', path: '/configs', body: '{"mode":"mc-blocked"}' }, { method: 'GET', path: '/configs', body: '' }, { method: 'DELETE', path: '/connections', body: '' }]);
  f.calls.length = 0;
  assert.deepEqual(await setCoreTrafficBlocked(f.endpoint, false), { blocked: false, confirmed: true });
  assert.deepEqual(f.calls, [{ method: 'PATCH', path: '/configs', body: '{"mode":"mc-active"}' }, { method: 'GET', path: '/configs', body: '' }]);
});

test('traffic gate rejects denied, unconfirmed, malformed, oversized or undrained responses without fake success', async t => {
  for (const variant of ['patch-denied', 'wrong-mode', 'malformed', 'oversized', 'drain-denied', 'truncated']) {
    const f = await gateFixture(t, (request, response) => {
      if (variant === 'patch-denied' && request.method === 'PATCH' || variant === 'drain-denied' && request.method === 'DELETE') { response.writeHead(403); response.end('PRIVATE_REASON'); }
      else if (request.method === 'GET') {
        if (variant === 'truncated') { response.writeHead(200, { 'content-length': '1000' }); response.write('{"mode":'); response.destroy(); }
        else response.end(variant === 'wrong-mode' ? '{"mode":"mc-active"}' : variant === 'malformed' ? 'PRIVATE_INVALID_JSON' : variant === 'oversized' ? 'x'.repeat(4097) : '{"mode":"mc-blocked"}');
      } else { response.writeHead(204); response.end(); }
    });
    await assert.rejects(setCoreTrafficBlocked(f.endpoint, true), cause => cause.code === 'CORE_TRAFFIC_GATE_FAILED' && !cause.message.includes('PRIVATE_'));
    assert.equal(f.calls.length, variant === 'patch-denied' ? 1 : variant === 'drain-denied' ? 3 : 2);
    if (variant !== 'drain-denied') assert.ok(f.calls.every(call => call.method !== 'DELETE'));
  }
  await assert.rejects(setCoreTrafficBlocked({ ...api, host: 'public.example.test' }, true), { code: 'CORE_API_INVALID' });
  await assert.rejects(setCoreTrafficBlocked(api, 'blocked'), { code: 'CORE_TRAFFIC_GATE_FAILED' });
});

test('traffic gate bounds an unanswered operation and destroys its loopback socket before any later step', { timeout: 4000 }, async t => {
  const f = await gateFixture(t, () => {}), started = performance.now();
  await assert.rejects(setCoreTrafficBlocked(f.endpoint, true), { code: 'CORE_TRAFFIC_GATE_FAILED' });
  assert.ok(performance.now() - started >= 1800 && performance.now() - started < 3000);
  assert.deepEqual(f.calls.map(call => `${call.method} ${call.path}`), ['PATCH /configs']);
  for (let i = 0; i < 100 && f.sockets.size; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(f.sockets.size, 0);
});
