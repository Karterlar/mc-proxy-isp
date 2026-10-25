import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { createApplicationProxy, isLocalApplicationHost } from '../src/application-proxy.mjs';
import { connectTunnel } from '../src/probe.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function listen(t, server) {
  const sockets = new Set(); server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return server.address().port;
}
async function fixture(t, options = {}) {
  const calls = [];
  const core = http.createServer((request, response) => { calls.push({ type: 'http', url: request.url, headers: request.headers }); response.end('ISP fixture'); });
  core.on('connect', (request, socket, head) => {
    socket.once('end', () => socket.destroy());
    calls.push({ type: 'connect', url: request.url });
    if (options.reject) return socket.end('HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n');
    if (options.hold) { socket.resume(); options.hold.resolve(socket); return; }
    socket.write('HTTP/1.1 200 Connection established\r\n\r\n'); if (head.length) socket.write(head);
    socket.on('data', data => socket.write(data));
  });
  const upstreamPort = await listen(t, core);
  const proxy = createApplicationProxy({ authorize: async () => true, resolve: () => assert.fail('public destinations must not use local DNS'), timeoutMs: 500, ...options.proxy });
  const started = await proxy.start({ upstreamPort, revision: 1 });
  t.after(() => proxy.stop());
  return { proxy, core, calls, upstreamPort, port: started.port };
}
function get(port, url, headers = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path: url, headers }, response => {
      let body = ''; response.on('data', data => { body += data; }); response.on('end', () => resolve({ status: response.statusCode, body }));
    });
    request.once('error', reject); request.setTimeout(1000, () => request.destroy(new Error('fixture request timeout'))); request.end();
  });
}
function connect(port, authority) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port }); let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('fixture CONNECT timeout')); }, 1000);
    socket.on('error', reject); socket.once('connect', () => socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
    const read = data => { buffer = Buffer.concat([buffer, data]); if (!buffer.includes('\r\n\r\n')) return; clearTimeout(timer); socket.removeListener('data', read); resolve({ socket, status: Number(/^HTTP\/1\.1 (\d+)/.exec(buffer.toString())[1]) }); };
    socket.on('data', read); socket.once('close', () => { clearTimeout(timer); reject(new Error('fixture CONNECT closed')); });
  });
}

async function waitFor(predicate, message) {
  for (let attempt = 0; attempt < 100; attempt++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
  assert.fail(message);
}

test('literal private targets and validated LAN DNS go directly to local services without ISP or proxy credentials', async t => {
  for (const host of ['localhost', '10.1.2.3', '172.16.1.1', '192.168.2.3', '::1', 'fd00::1', '::ffff:127.0.0.1']) assert.equal(isLocalApplicationHost(host), true);
  for (const host of ['public.fixture.invalid', '172.32.0.1', '192.0.2.1', '::ffff:192.0.2.1']) assert.equal(isLocalApplicationHost(host), false);
  const requests = [];
  const localPort = await listen(t, http.createServer((request, response) => { requests.push({ url: request.url, headers: request.headers }); response.end('local fixture'); }));
  const echoPort = await listen(t, net.createServer(socket => socket.pipe(socket)));
  const f = await fixture(t, { proxy: { resolve: async host => { assert.equal(host, 'mcp.lan'); return [{ address: '192.0.2.5', family: 4 }, { address: '127.0.0.1', family: 4 }]; } } });
  const response = await get(f.port, `http://mcp.lan:${localPort}/rpc?x=1`, { host: 'incorrect-host', 'proxy-authorization': 'PRIVATE_TOKEN' });
  assert.deepEqual(response, { status: 200, body: 'local fixture' }); assert.equal(requests[0].url, '/rpc?x=1');
  assert.equal(requests[0].headers.host, `mcp.lan:${localPort}`); assert.equal(requests[0].headers['proxy-authorization'], undefined);
  const tunnel = await connect(f.port, `localhost:${echoPort}`); assert.equal(tunnel.status, 200);
  const echoed = once(tunnel.socket, 'data'); tunnel.socket.write('PRIVATE_LOCAL_PAYLOAD'); assert.equal((await echoed)[0].toString(), 'PRIVATE_LOCAL_PAYLOAD'); tunnel.socket.destroy();
  assert.deepEqual(f.calls, []); assert.equal(f.proxy.status().local, 2); assert.equal(f.proxy.status().isp, 0);
});

test('public HTTP and CONNECT use only the owned loopback core, including explicit port 80 and IPv6', async t => {
  const f = await fixture(t);
  const response = await get(f.port, 'http://public.fixture.invalid:8080/path?x=1', { 'proxy-authorization': 'PRIVATE_TOKEN' });
  assert.deepEqual(response, { status: 200, body: 'ISP fixture' });
  assert.equal(f.calls[0].url, 'http://public.fixture.invalid:8080/path?x=1'); assert.equal(f.calls[0].headers.host, 'public.fixture.invalid:8080');
  assert.equal(f.calls[0].headers['proxy-authorization'], undefined);
  for (const authority of ['public.fixture.invalid:80', '[2001:db8::3]:443']) {
    const tunnel = await connect(f.port, authority); assert.equal(tunnel.status, 200); tunnel.socket.destroy();
  }
  assert.deepEqual(f.calls.filter(item => item.type === 'connect').map(item => item.url), ['public.fixture.invalid:80', '[2001:db8::3]:443']);
});

test('Fake-IP IPv6 is sent to the owned core rather than the private LAN bypass', async t => {
  for (const host of ['fc00::1', 'FC00:3FFF:ffff:ffff:ffff:ffff:ffff:ffff', '[fc00::2]']) assert.equal(isLocalApplicationHost(host), false);
  for (const host of ['fc00:4000::1', 'fd00::1', '::1']) assert.equal(isLocalApplicationHost(host), true);
  const f = await fixture(t);
  const authority = '[fc00::1234]:443';
  const tunnel = await connect(f.port, authority); assert.equal(tunnel.status, 200);
  const echoed = once(tunnel.socket, 'data'); tunnel.socket.write('FAKE_IP_CORE_PAYLOAD');
  assert.equal((await echoed)[0].toString(), 'FAKE_IP_CORE_PAYLOAD'); tunnel.socket.destroy();
  assert.deepEqual(f.calls, [{ type: 'connect', url: authority }]);
  assert.equal(f.proxy.status().isp, 1); assert.equal(f.proxy.status().local, 0);
});

test('private DNS with only public answers and recursion through own/core mapped-loopback ports are rejected before dialing', async t => {
  const f = await fixture(t, { proxy: { resolve: async () => [{ address: '192.0.2.7', family: 4 }] } });
  assert.equal((await get(f.port, 'http://mcp.lan:8080/rpc')).status, 502);
  for (const authority of [`127.0.0.1:${f.port}`, `[::ffff:127.0.0.1]:${f.upstreamPort}`, `localhost:${f.upstreamPort}`]) {
    const result = await connect(f.port, authority); assert.equal(result.status, 502); result.socket.destroy();
  }
  assert.deepEqual(f.calls, []);
});

test('owned core refusal or disappearance never retries through public DNS or a direct target', async t => {
  const f = await fixture(t, { reject: true });
  const rejected = await connect(f.port, 'public.fixture.invalid:443'); assert.equal(rejected.status, 502); rejected.socket.destroy();
  await new Promise(resolve => f.core.close(resolve));
  assert.equal((await get(f.port, 'http://public.fixture.invalid/path')).status, 502);
  assert.equal(f.calls.filter(item => item.type === 'connect').length, 1);
});

test('CONNECT failures retain only safe stage code and numeric upstream status', async t => {
  const failures = [];
  const f = await fixture(t, { reject: true, proxy: { onFailure: event => failures.push(event) } });
  const rejected = await connect(f.port, 'PRIVATE_ENDPOINT_SECRET.invalid:443'); rejected.socket.destroy();
  assert.equal(rejected.status, 502);
  assert.deepEqual(failures, [{ code: 'PROXY_CONNECT_REJECTED', diagnostic: { httpStatus: 502 } }]);
  assert.equal(f.proxy.status().lastFailure.code, 'PROXY_CONNECT_REJECTED'); assert.equal(f.proxy.status().lastFailure.httpStatus, 502);
  assert.doesNotMatch(JSON.stringify([failures, f.proxy.status()]), /PRIVATE_ENDPOINT_SECRET|CONNECT |password/);
});

test('stop closes active and pending public CONNECT sockets immediately rather than waiting for the handshake timeout', async t => {
  const held = deferred(); const f = await fixture(t, { hold: held });
  const pending = connect(f.port, 'public.fixture.invalid:443').catch(() => null);
  const upstream = await held.promise; const closed = once(upstream, 'close');
  await f.proxy.stop(); await closed; await pending;
  assert.equal(f.proxy.status().running, false);
  const active = await fixture(t); const tunnel = await connect(active.port, 'public.fixture.invalid:443');
  const clientClosed = once(tunnel.socket, 'close'); await active.proxy.stop(); await clientClosed;
});

test('a stopped or restarted lease cannot be borrowed by an old request awaiting authorization or LAN DNS', async t => {
  for (const phase of ['authorize', 'dns']) {
    const entered = deferred(), release = deferred(); let held = true;
    const f = await fixture(t, { proxy: {
      authorize: async () => { if (held && phase === 'authorize') { entered.resolve(); await release.promise; } return true; },
      resolve: async () => { if (held && phase === 'dns') { entered.resolve(); await release.promise; } return [{ address: '127.0.0.1', family: 4 }]; },
    } });
    const pending = get(f.port, phase === 'dns' ? `http://mcp.lan:${f.upstreamPort}/old` : 'http://public.fixture.invalid/old').catch(() => null);
    await entered.promise; await f.proxy.stop(); held = false;
    const restarted = await f.proxy.start({ upstreamPort: f.upstreamPort, revision: 2 }); release.resolve(); await pending;
    const fresh = await get(restarted.port, 'http://public.fixture.invalid/new'); assert.equal(fresh.status, 200);
    assert.deepEqual(f.calls.map(item => item.url), ['http://public.fixture.invalid/new']);
  }
});

test('connectTunnel registers its socket before handshake and scrubs a throwing registration callback', async t => {
  const held = deferred(); const f = await fixture(t, { hold: held }); let registered;
  const pending = connectTunnel({ host: 'public.fixture.invalid', port: 443, proxyPort: f.upstreamPort, timeoutMs: 500, onSocket: socket => { registered = socket; } });
  assert.ok(registered); const upstream = await held.promise; const closed = once(upstream, 'close'); registered.destroy();
  await assert.rejects(pending, { code: 'PROXY_CLOSED' }); await closed;
  await assert.rejects(connectTunnel({ host: 'public.fixture.invalid', port: 443, proxyPort: f.upstreamPort, timeoutMs: 500,
    onSocket: () => { throw new Error('PRIVATE_REGISTRATION_SECRET'); } }), cause => cause.code === 'PROXY_UNREACHABLE' && !cause.message.includes('PRIVATE_'));
});

test('active binding updates retain one port and concurrent initial starts keep only the newest lease', async t => {
  const revisions = [];
  const f = await fixture(t, { proxy: { authorize: context => { revisions.push(context.revision); return true; } } });
  const first = f.proxy.start({ upstreamPort: f.upstreamPort, revision: 2 });
  const last = f.proxy.start({ upstreamPort: f.upstreamPort, revision: 3 });
  const results = await Promise.allSettled([first, last]);
  assert.equal(results[0].status, 'fulfilled'); assert.equal(results[0].value.port, f.port);
  assert.equal(results[1].status, 'fulfilled'); assert.equal(results[1].value.port, f.proxy.status().port);
  assert.equal(results[1].value.port, f.port);
  assert.equal((await get(results[1].value.port, 'http://public.fixture.invalid/newest')).status, 200);
  assert.deepEqual(revisions, [3]);
  await f.proxy.stop();
  const old = f.proxy.start({ upstreamPort: f.upstreamPort, revision: 4 });
  const newest = f.proxy.start({ upstreamPort: f.upstreamPort, revision: 5 });
  await assert.rejects(old, { code: 'APPLICATION_PROXY_INVALID' }); await newest;
  await f.proxy.stop();
  const pending = f.proxy.start({ upstreamPort: f.upstreamPort, revision: 6 });
  const stopped = f.proxy.stop();
  await assert.rejects(pending, { code: 'APPLICATION_PROXY_INVALID' }); await stopped;
  assert.equal(f.proxy.status().running, false);
});

test('pause retains the endpoint, closes old CONNECT streams and refuses HTTP, CONNECT, Upgrade and private bypass until reverified', async t => {
  let localRequests = 0; const revisions = [];
  const localPort = await listen(t, http.createServer((_, response) => { localRequests++; response.end('local'); }));
  const f = await fixture(t, { proxy: { authorize: context => { revisions.push(context.revision); return true; } } });
  const old = await connect(f.port, 'public.fixture.invalid:443'); assert.equal(old.status, 200);
  const closed = once(old.socket, 'close');
  f.proxy.pause(); await closed;
  assert.equal(f.proxy.status().running, true); assert.equal(f.proxy.status().accepting, false); assert.equal(f.proxy.status().port, f.port);
  const before = f.calls.length;
  for (const url of ['http://public.fixture.invalid/paused', `http://localhost:${localPort}/private`]) {
    assert.equal((await get(f.port, url)).status, 502);
    assert.equal((await get(f.port, url, { connection: 'Upgrade', upgrade: 'websocket' })).status, 502);
  }
  for (const target of ['public.fixture.invalid:443', `localhost:${localPort}`]) {
    const refused = await connect(f.port, target); assert.equal(refused.status, 502); refused.socket.destroy();
  }
  assert.equal(localRequests, 0); assert.equal(f.calls.length, before); assert.deepEqual(revisions, [1]);
  const resumed = await f.proxy.start({ upstreamPort: f.upstreamPort, revision: 2 });
  assert.equal(resumed.port, f.port); assert.equal(resumed.accepting, true);
  assert.equal((await get(f.port, 'http://public.fixture.invalid/resumed')).status, 200);
  assert.equal((await get(f.port, `http://localhost:${localPort}/local`)).status, 200);
  const tunnel = await connect(f.port, 'public.fixture.invalid:443'); assert.equal(tunnel.status, 200); tunnel.socket.destroy();
  assert.equal(localRequests, 1); assert.deepEqual(revisions, [1, 2, 2, 2]);
});

test('pause cancels pending authorization and active streaming HTTP before preserving the listener', { timeout: 3000 }, async t => {
  const entered = deferred(), release = deferred(), streamClosed = deferred(); let held = false, grantSignal;
  const f = await fixture(t, { proxy: { authorize: async context => {
    if (held) { grantSignal = context.signal; entered.resolve(); await release.promise; } return true;
  } } });
  f.core.removeAllListeners('request');
  f.core.on('request', (_, response) => { response.once('close', streamClosed.resolve); response.writeHead(200); response.write('stream'); });
  const response = await new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port: f.port, path: 'http://public.fixture.invalid/stream' }, resolve); request.once('error', reject);
  });
  response.on('error', () => {}); response.resume();
  const responseClosed = new Promise(resolve => response.once('close', resolve));
  held = true; const pending = get(f.port, 'http://public.fixture.invalid/pending').catch(() => null); await entered.promise;
  f.proxy.pause(); assert.equal(grantSignal.aborted, true); release.resolve();
  await Promise.all([pending, responseClosed, streamClosed.promise]);
  await waitFor(() => f.proxy.status().capacity.activeRequests === 0, 'Paused requests retained capacity');
  assert.equal(f.proxy.status().port, f.port); assert.equal(f.calls.length, 0);
});

test('pause destroys an established private Upgrade stream while keeping the same endpoint', { timeout: 3000 }, async t => {
  const origin = http.createServer(); let upgraded;
  origin.on('upgrade', (_, socket) => { upgraded = socket; socket.once('end', () => socket.destroy()); socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n'); });
  const localPort = await listen(t, origin), f = await fixture(t);
  const client = net.connect(f.port, '127.0.0.1'); client.on('error', () => {}); t.after(() => client.destroy()); await once(client, 'connect');
  const response = once(client, 'data');
  client.write(`GET http://localhost:${localPort}/stream HTTP/1.1\r\nHost: localhost:${localPort}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`);
  assert.match((await response)[0].toString(), /^HTTP\/1\.1 101/);
  const closed = Promise.all([once(client, 'close'), once(upgraded, 'close')]);
  f.proxy.pause(); await closed;
  assert.equal(f.proxy.status().port, f.port); assert.equal(f.proxy.status().accepting, false);
  assert.deepEqual(f.calls, []);
});

test('disconnecting an HTTP response promptly cancels its streaming upstream', { timeout: 3000 }, async t => {
  const f = await fixture(t); const closed = deferred();
  f.core.removeAllListeners('request');
  f.core.on('request', (_, response) => { response.once('close', closed.resolve); response.writeHead(200); response.write('fixture stream'); });
  await new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port: f.port, path: 'http://public.fixture.invalid/stream' }, response => {
      response.once('data', () => { response.destroy(); resolve(); }); response.on('error', () => {});
    }); request.once('error', reject);
  });
  let timer;
  try { await Promise.race([closed.promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('abandoned upstream remained open')), 500); })]); }
  finally { clearTimeout(timer); }
});

test('authorization timeout rejects a request without contacting the owned core', async t => {
  const f = await fixture(t, { proxy: { timeoutMs: 25, authorize: () => new Promise(() => {}) } });
  assert.equal((await get(f.port, 'http://public.fixture.invalid/held')).status, 502);
  assert.deepEqual(f.calls, []);
});

test('authorization has its own budget while HTTP and CONNECT retain the shorter socket budget', async t => {
  let authorizations = 0;
  const f = await fixture(t, { proxy: { timeoutMs: 20, authorizationTimeoutMs: 100, authorize: async () => {
    authorizations++; await new Promise(resolve => setTimeout(resolve, 50)); return true;
  } } });
  assert.equal((await get(f.port, 'http://public.fixture.invalid/slow-authorization')).status, 200);
  const tunnel = await connect(f.port, 'public.fixture.invalid:443');
  assert.equal(tunnel.status, 200); tunnel.socket.destroy();
  assert.equal(authorizations, 2);
  assert.deepEqual(f.calls.map(item => item.type), ['http', 'connect']);
});

test('an explicit authorization deadline still rejects an unresolved grant without upstream traffic', async t => {
  const f = await fixture(t, { proxy: { timeoutMs: 20, authorizationTimeoutMs: 100, authorize: () => new Promise(() => {}) } });
  const started = performance.now();
  assert.equal((await get(f.port, 'http://public.fixture.invalid/held')).status, 502);
  assert.ok(performance.now() - started >= 75, 'Authorization used the short socket deadline instead of its own budget');
  assert.equal(f.proxy.status().lastFailure.code, 'APPLICATION_PROXY_TIMEOUT');
  assert.equal(f.proxy.status().capacity.pendingRequests, 0); assert.deepEqual(f.calls, []);
});

test('a delayed negative authorization remains a binding rejection rather than forwarding after the socket deadline', async t => {
  const f = await fixture(t, { proxy: { timeoutMs: 20, authorizationTimeoutMs: 100, authorize: async () => {
    await new Promise(resolve => setTimeout(resolve, 50)); return false;
  } } });
  assert.equal((await get(f.port, 'http://public.fixture.invalid/denied')).status, 502);
  assert.equal(f.proxy.status().lastFailure.code, 'APPLICATION_LEASE_INVALID'); assert.deepEqual(f.calls, []);
});

test('stop or replacement binding cancels the longer authorization wait before any late upstream dial', async t => {
  for (const replace of [false, true]) {
    const entered = deferred(), release = deferred(); let held = true, signal;
    const f = await fixture(t, { proxy: { timeoutMs: 20, authorizationTimeoutMs: 100, authorize: async context => {
      if (held) { signal = context.signal; entered.resolve(); await release.promise; } return true;
    } } });
    const pending = get(f.port, 'http://public.fixture.invalid/old').catch(() => null);
    await entered.promise;
    const port = replace ? (await f.proxy.start({ upstreamPort: f.upstreamPort, revision: 2 })).port : null;
    if (!replace) await f.proxy.stop();
    assert.equal(signal.aborted, true); held = false; release.resolve(); await pending;
    if (replace) {
      assert.equal((await get(port, 'http://public.fixture.invalid/fresh')).status, 200);
      assert.deepEqual(f.calls.map(item => item.url), ['http://public.fixture.invalid/fresh']);
    } else assert.deepEqual(f.calls, []);
    assert.equal(f.proxy.status().capacity.pendingRequests, 0);
  }
});

test('authorization budget rejects invalid values without starting a proxy', () => {
  for (const authorizationTimeoutMs of [0, -1, 1.5, Infinity, NaN, '100', 3_600_001, null]) {
    assert.throws(() => createApplicationProxy({ authorizationTimeoutMs }), { code: 'APPLICATION_PROXY_INVALID' });
  }
});

test('a truncated upstream HTTP response closes its client without an unhandled stream error', { timeout: 3000 }, async t => {
  const f = await fixture(t);
  f.core.removeAllListeners('request');
  f.core.on('request', (_, response) => {
    response.writeHead(200, { 'content-length': '1000' }); response.write('partial');
    setTimeout(() => response.destroy(), 20);
  });
  const complete = await new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port: f.port, path: 'http://public.fixture.invalid/truncated' }, response => {
      response.resume(); response.once('aborted', () => resolve(false)); response.once('error', () => resolve(false)); response.once('end', () => resolve(response.complete));
    });
    request.once('error', reject); request.setTimeout(500, () => request.destroy(new Error('truncated response remained open')));
  });
  assert.equal(complete, false);
});

test('SSE stays live past stage deadlines while capacity rejects only new connections and cancellation closes upstream', { timeout: 3000 }, async t => {
  const f = await fixture(t, { proxy: { maxConnections: 1, responseTimeoutMs: 30, streamIdleTimeoutMs: 60 } });
  const closed = deferred(); let sent = 0;
  f.core.removeAllListeners('request');
  f.core.on('request', (_, response) => {
    response.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
    response.flushHeaders();
    const timer = setInterval(() => { response.write(`data: ${++sent}\n\n`); }, 10);
    response.once('close', () => { clearInterval(timer); closed.resolve(); });
  });
  const stream = await new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port: f.port, path: 'http://public.fixture.invalid/events', agent: false }, resolve);
    request.once('error', reject);
  });
  t.after(() => stream.destroy());
  let received = '';
  stream.on('data', data => { received += data; }); stream.on('error', () => {});
  assert.equal(stream.headers['content-type'], 'text/event-stream');
  const rejected = await get(f.port, 'http://public.fixture.invalid/new');
  assert.equal(rejected.status, 503); assert.equal(f.proxy.status().lastFailure.code, 'APPLICATION_PROXY_OVERLOADED');
  await waitFor(() => received.includes('data: 12\n\n'), 'Existing SSE was interrupted by the capacity or total duration');
  assert.equal(stream.destroyed, false);
  assert.equal(f.proxy.status().capacity.activeConnections, 1); assert.equal(f.proxy.status().capacity.pendingRequests, 0);
  stream.destroy(); await closed.promise;
  await waitFor(() => f.proxy.status().capacity.activeConnections === 0, 'Cancelled SSE client was not removed');
});

test('pending authorization has a separate bound and disconnect aborts it before any late upstream dial', { timeout: 3000 }, async t => {
  const entered = deferred(), release = deferred(); let calls = 0, signal;
  const f = await fixture(t, { proxy: { maxPendingRequests: 1, maxConnections: 8, authorize: async context => {
    if (++calls === 1) { signal = context.signal; entered.resolve(); await release.promise; } return true;
  } } });
  const request = http.get({ host: '127.0.0.1', port: f.port, path: 'http://public.fixture.invalid/abandoned', agent: false });
  request.on('error', () => {}); await entered.promise;
  assert.equal(f.proxy.status().capacity.pendingRequests, 1);
  assert.equal((await get(f.port, 'http://public.fixture.invalid/overload')).status, 503);
  assert.equal(calls, 1); assert.deepEqual(f.calls, []);
  request.destroy();
  await waitFor(() => signal.aborted && f.proxy.status().capacity.pendingRequests === 0, 'Abandoned authorization retained a pending slot');
  release.resolve();
  assert.equal((await get(f.port, 'http://public.fixture.invalid/fresh')).status, 200);
  assert.deepEqual(f.calls.map(item => item.url), ['http://public.fixture.invalid/fresh']);
});

test('existing CONNECT survives overload and stop leaves no active or pending slots', { timeout: 3000 }, async t => {
  const f = await fixture(t, { proxy: { maxConnections: 1 } });
  const established = await connect(f.port, 'public.fixture.invalid:443'); assert.equal(established.status, 200);
  const rejected = await connect(f.port, 'public.fixture.invalid:443'); assert.equal(rejected.status, 503); rejected.socket.destroy();
  const echoed = once(established.socket, 'data'); established.socket.write('existing-tunnel');
  assert.equal((await echoed)[0].toString(), 'existing-tunnel');
  await f.proxy.stop();
  await waitFor(() => f.proxy.status().capacity.activeConnections === 0, 'Stopped client capacity was not released');
  assert.equal(f.proxy.status().capacity.pendingRequests, 0);
});

test('upstream response header deadline reports a safe stage error and closes the owned request', { timeout: 3000 }, async t => {
  const f = await fixture(t, { proxy: { responseTimeoutMs: 25, streamIdleTimeoutMs: 1000 } });
  const closed = deferred();
  f.core.removeAllListeners('request'); f.core.on('request', request => request.socket.once('close', closed.resolve));
  assert.equal((await get(f.port, 'http://public.fixture.invalid/never-headers')).status, 502);
  await closed.promise; assert.equal(f.proxy.status().lastFailure.code, 'APPLICATION_RESPONSE_TIMEOUT');
  assert.equal(f.proxy.status().failed, 1);
});

test('real WebSocket upgrade, masked frames and close use the ISP CONNECT path without a total-session deadline', { timeout: 3000 }, async t => {
  const serverClosed = deferred(); let originRequests = 0;
  const origin = http.createServer();
  origin.on('upgrade', (request, socket) => {
    // A real WebSocket peer closes a TCP stream that ends without a close frame.
    socket.once('end', () => socket.destroy());
    originRequests++; assert.equal(request.url, '/socket'); assert.equal(request.headers['proxy-authorization'], undefined);
    const accept = createHash('sha1').update(request.headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('data', frame => {
      assert.equal(frame[0], 0x81); assert.equal(frame[1] & 0x80, 0x80);
      const length = frame[1] & 0x7f; assert.ok(length < 126);
      const payload = Buffer.from(frame.subarray(6, 6 + length));
      for (let i = 0; i < payload.length; i++) payload[i] ^= frame[2 + i % 4];
      socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
    });
    socket.once('close', serverClosed.resolve);
  });
  const originPort = await listen(t, origin);
  const f = await fixture(t, { proxy: { responseTimeoutMs: 100, streamIdleTimeoutMs: 20, maxConnections: 1 } });
  f.core.removeAllListeners('connect');
  f.core.on('connect', (request, client, head) => {
    f.calls.push({ type: 'connect', url: request.url }); assert.equal(request.url, `websocket.fixture.invalid:${originPort}`);
    const upstream = net.connect(originPort, '127.0.0.1'); upstream.on('error', () => client.destroy());
    upstream.once('connect', () => { client.write('HTTP/1.1 200 Connection established\r\n\r\n'); if (head.length) upstream.write(head); client.pipe(upstream); upstream.pipe(client); });
    client.once('close', () => upstream.destroy()); upstream.once('close', () => client.destroy());
  });
  const socket = net.connect(f.port, '127.0.0.1'); t.after(() => socket.destroy());
  await once(socket, 'connect');
  const key = Buffer.from('fixture-ws-key16').toString('base64');
  const upgraded = once(socket, 'data');
  socket.write(`GET http://websocket.fixture.invalid:${originPort}/socket HTTP/1.1\r\nHost: websocket.fixture.invalid:${originPort}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ${key}\r\nProxy-Authorization: PRIVATE_TOKEN\r\n\r\n`);
  const response = (await upgraded)[0].toString(); assert.match(response, /^HTTP\/1\.1 101/);
  assert.ok(response.includes(createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')));
  assert.equal((await get(f.port, 'http://public.fixture.invalid/new')).status, 503);
  await new Promise(resolve => setTimeout(resolve, 140));
  const payload = Buffer.from('still-open'), mask = Buffer.from([1, 2, 3, 4]), masked = Buffer.from(payload);
  for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i % 4];
  const echoed = once(socket, 'data'); socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | masked.length]), mask, masked]));
  const frame = (await echoed)[0]; assert.equal(frame[0], 0x81); assert.equal(frame.subarray(2).toString(), payload.toString());
  assert.equal(originRequests, 1); assert.deepEqual(f.calls, [{ type: 'connect', url: `websocket.fixture.invalid:${originPort}` }]);
  socket.destroy(); await serverClosed.promise;
  await waitFor(() => f.proxy.status().capacity.activeConnections === 0, 'Upgraded socket slot leaked');
});

test('application proxy rejects invalid capacity or stage limits', () => {
  for (const options of [{ maxConnections: 0 }, { maxPendingRequests: 4097 }, { timeoutMs: Infinity }, { responseTimeoutMs: -1 }, { streamIdleTimeoutMs: '300000' }]) {
    assert.throws(() => createApplicationProxy(options), { code: 'APPLICATION_PROXY_INVALID' });
  }
});

test('HTTP pipelining cannot create more active upstreams than the connection budget', { timeout: 3000 }, async t => {
  const f = await fixture(t, { proxy: { maxConnections: 2, maxPendingRequests: 8 } });
  const responses = [];
  f.core.removeAllListeners('request'); f.core.on('request', (_, response) => responses.push(response));
  const client = net.connect(f.port, '127.0.0.1'); t.after(() => client.destroy());
  await once(client, 'connect'); let received = ''; client.on('data', data => { received += data; });
  client.write(Array.from({ length: 3 }, (_, index) => `GET http://public.fixture.invalid/${index} HTTP/1.1\r\nHost: public.fixture.invalid\r\n\r\n`).join(''));
  await waitFor(() => responses.length === 2 && f.proxy.status().lastFailure?.code === 'APPLICATION_PROXY_OVERLOADED', 'Pipelined requests bypassed the active request budget');
  assert.equal(f.proxy.status().capacity.activeRequests, 2);
  for (const response of responses) response.end('completed');
  await waitFor(() => received.includes('503 Service Unavailable'), 'Pipelined overload did not have an explicit response');
  assert.equal(responses.length, 2);
  await waitFor(() => f.proxy.status().capacity.activeRequests === 0, 'Completed pipelined requests leaked capacity');
});

test('completed HTTP requests release owned upstream sockets instead of accumulating global agent pools', { timeout: 3000 }, async t => {
  const f = await fixture(t); let open = 0;
  f.core.on('connection', socket => { open++; socket.once('close', () => { open--; }); });
  for (let index = 0; index < 4; index++) assert.equal((await get(f.port, `http://public.fixture.invalid/${index}`)).status, 200);
  await waitFor(() => open === 0, 'Completed upstream HTTP sockets remained pooled');
  assert.equal(f.proxy.status().capacity.activeRequests, 0);
});

test('Upgrade response deadline survives partial headers and releases its active slot', { timeout: 3000 }, async t => {
  const target = http.createServer();
  target.on('upgrade', (_, socket) => { socket.once('end', () => socket.destroy()); socket.write('HTTP/1.1 101 Switching Protocols\r\n'); });
  const targetPort = await listen(t, target);
  const f = await fixture(t, { proxy: { responseTimeoutMs: 30 } });
  const client = net.connect(f.port, '127.0.0.1'); t.after(() => client.destroy());
  client.on('data', () => {}); await once(client, 'connect'); const closed = once(client, 'close');
  client.write(`GET http://localhost:${targetPort}/ws HTTP/1.1\r\nHost: localhost:${targetPort}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`);
  await closed;
  assert.equal(f.proxy.status().lastFailure.code, 'APPLICATION_RESPONSE_TIMEOUT');
  await waitFor(() => f.proxy.status().capacity.activeRequests === 0, 'Timed-out upgrade retained a request slot');
  assert.deepEqual(f.calls, []);
});

test('TCP half-close preserves the remote final response before releasing the CONNECT slot', { timeout: 3000 }, async t => {
  let body = '';
  const targetPort = await listen(t, net.createServer({ allowHalfOpen: true }, socket => {
    socket.on('data', data => { body += data; }); socket.once('end', () => socket.end('final-reply'));
  }));
  const f = await fixture(t); const result = await connect(f.port, `localhost:${targetPort}`); assert.equal(result.status, 200);
  const response = once(result.socket, 'data'); const closed = once(result.socket, 'close');
  result.socket.end('request-complete');
  assert.equal((await response)[0].toString(), 'final-reply'); await closed;
  assert.equal(body, 'request-complete');
  await waitFor(() => f.proxy.status().capacity.activeRequests === 0, 'Half-closed tunnel retained a request slot');
});
