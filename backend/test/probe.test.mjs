import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { requestViaProxy, connectTunnel, sanitizeProbeFailure } from '../src/probe.mjs';
import { relayTlsFixture } from './relay-tls-fixture.mjs';

async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
const close = server => new Promise(resolve => server.close(resolve));

test('failed local proxy never connects to a directly reachable destination, regardless of NO_PROXY', async () => {
  let directConnections = 0;
  const target = net.createServer(socket => { directConnections++; socket.destroy(); });
  const targetPort = await listen(target);
  const portReservation = net.createServer(); const downPort = await listen(portReservation); await close(portReservation);
  const previous = process.env.NO_PROXY; process.env.NO_PROXY = '*';
  try {
    await assert.rejects(requestViaProxy(`https://127.0.0.1:${targetPort}`, { proxyPort: downPort, timeoutMs: 1000 }), /no direct fallback/);
    assert.equal(directConnections, 0);
  } finally { if (previous === undefined) delete process.env.NO_PROXY; else process.env.NO_PROXY = previous; await close(target); }
});
test('proxy rejection does not expose a malicious response body or retry direct', async () => {
  const proxy = net.createServer(socket => socket.once('data', () => socket.end('HTTP/1.1 407 SECRET_PROVIDER_TOKEN\r\n\r\nSECRET_PROVIDER_TOKEN')));
  const proxyPort = await listen(proxy);
  try {
    await assert.rejects(connectTunnel({ host: 'unresolved.invalid', port: 443, proxyPort, timeoutMs: 1000 }), error => {
      assert.equal(error.code, 'PROXY_CONNECT_REJECTED');
      assert.deepEqual(error.diagnostic, { stage: 'proxy-connect', connectHttpStatus: 407, httpStatus: 407 });
      assert.doesNotMatch(error.message, /SECRET_PROVIDER_TOKEN/);
      return true;
    });
  } finally { await close(proxy); }
});

test('CONNECT 502 is a proxy-connect failure and never a target HTTP response', async () => {
  const proxy = net.createServer(socket => socket.once('data', () => socket.end('HTTP/1.1 502 PRIVATE_UPSTREAM_REASON\r\n\r\nPRIVATE_UPSTREAM_BODY')));
  const proxyPort = await listen(proxy);
  try {
    await assert.rejects(requestViaProxy('https://unresolved.invalid/', { proxyPort, timeoutMs: 1000, responseDetails: true }), cause => {
      assert.equal(cause.code, 'PROXY_CONNECT_REJECTED');
      assert.deepEqual(sanitizeProbeFailure(cause), { code: 'PROXY_CONNECT_REJECTED', diagnostic: { stage: 'proxy-connect', connectHttpStatus: 502 } });
      assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|targetHttpStatus/);
      return true;
    });
  } finally { await close(proxy); }
});

test('validated loopback TLS returning HTTP 500 is distinct from CONNECT rejection', async t => {
  let requests = 0;
  const sockets = new Set();
  const target = https.createServer({ key: relayTlsFixture.sameHostLeaf.key, cert: relayTlsFixture.sameHostLeaf.cert }, (_, response) => {
    requests++; response.writeHead(500); response.end('PRIVATE_TARGET_RESPONSE');
  });
  const targetPort = await listen(target);
  const proxy = http.createServer();
  proxy.on('connect', (_, client, head) => {
    const upstream = net.connect({ host: '127.0.0.1', port: targetPort });
    for (const socket of [client, upstream]) { sockets.add(socket); socket.on('error', () => socket.destroy()); socket.once('close', () => sockets.delete(socket)); }
    upstream.once('connect', () => { client.write('HTTP/1.1 200 Connection established\r\n\r\n'); if (head.length) upstream.write(head); client.pipe(upstream); upstream.pipe(client); });
    client.once('close', () => upstream.destroy()); upstream.once('close', () => client.destroy());
  });
  const proxyPort = await listen(proxy);
  t.after(async () => { for (const socket of sockets) socket.destroy(); await Promise.all([close(proxy), close(target)]); });
  const options = { proxyPort, timeoutMs: 2000, ca: relayTlsFixture.ca.cert, method: 'HEAD' };
  const details = await requestViaProxy(`https://localhost:${targetPort}/`, { ...options, responseDetails: true });
  assert.deepEqual(details, { statusCode: 500, body: '' });
  await assert.rejects(requestViaProxy(`https://localhost:${targetPort}/`, options), cause => {
    assert.equal(cause.code, 'PROBE_HTTP_STATUS');
    assert.deepEqual(cause.diagnostic, { stage: 'target-response', targetHttpStatus: 500 });
    assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|connectHttpStatus/); return true;
  });
  assert.equal(requests, 2);
});

test('invalid TLS after accepted CONNECT retains the TLS stage without inventing a target status', async () => {
  const proxy = net.createServer(socket => socket.once('data', () => socket.end('HTTP/1.1 200 Connection established\r\n\r\nPRIVATE_NOT_TLS')));
  const proxyPort = await listen(proxy);
  try {
    await assert.rejects(requestViaProxy('https://unresolved.invalid/', { proxyPort, timeoutMs: 1000 }), cause => {
      assert.equal(cause.code, 'PROBE_TLS_OR_SOCKET_FAILED');
      assert.deepEqual(sanitizeProbeFailure(cause), { code: 'PROBE_TLS_OR_SOCKET_FAILED', diagnostic: { stage: 'tls' } });
      assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|HttpStatus/); return true;
    });
  } finally { await close(proxy); }
});

test('safe probe diagnostics enforce fixed codes, bounded numeric status and layer-specific evidence', () => {
  assert.equal(sanitizeProbeFailure({ code: 'PRIVATE_ARBITRARY_CODE', message: 'private' }), null);
  assert.deepEqual(sanitizeProbeFailure({ code: 'PROXY_CONNECT_REJECTED', diagnostic: { httpStatus: 502, stage: 'target-response', targetHttpStatus: 500, token: 'PRIVATE' } }),
    { code: 'PROXY_CONNECT_REJECTED', diagnostic: { stage: 'proxy-connect', connectHttpStatus: 502 } });
  assert.deepEqual(sanitizeProbeFailure({ code: 'PROBE_HTTP_STATUS', diagnostic: { httpStatus: 500 } }),
    { code: 'PROBE_HTTP_STATUS', diagnostic: { stage: 'target-response' } });
  for (const status of ['502', 0, 600, NaN, Infinity]) {
    assert.deepEqual(sanitizeProbeFailure({ code: 'PROXY_CONNECT_REJECTED', diagnostic: { connectHttpStatus: status } }),
      { code: 'PROXY_CONNECT_REJECTED', diagnostic: { stage: 'proxy-connect' } });
  }
  assert.deepEqual(sanitizeProbeFailure({ code: 'PROBE_TIMEOUT', diagnostic: { stage: 'target-response', targetHttpStatus: 200, message: 'PRIVATE' } }),
    { code: 'PROBE_TIMEOUT', diagnostic: { stage: 'target-response', targetHttpStatus: 200 } });
});
test('CONNECT sends target hostname unchanged without doing local target DNS', async () => {
  let firstLine;
  const proxy = net.createServer(socket => socket.once('data', data => { firstLine = data.toString().split('\r\n')[0]; socket.write('HTTP/1.1 200 Connection established\r\n\r\n'); }));
  const proxyPort = await listen(proxy);
  try {
    const tunnel = await connectTunnel({ host: 'does-not-resolve.invalid', port: 443, proxyPort, timeoutMs: 1000 });
    assert.equal(firstLine, 'CONNECT does-not-resolve.invalid:443 HTTP/1.1');
    tunnel.destroy();
  } finally { await close(proxy); }
});

test('CONNECT bounds only response headers and preserves a large coalesced first tunnel payload', async () => {
  const payload = Buffer.alloc(32768, 123);
  const proxy = net.createServer(socket => socket.once('data', () => socket.end(Buffer.concat([
    Buffer.from('HTTP/1.1 200 Connection established\r\n\r\n'), payload,
  ]))));
  const proxyPort = await listen(proxy);
  try {
    const tunnel = await connectTunnel({ host: 'does-not-resolve.invalid', port: 443, proxyPort, timeoutMs: 1000 });
    const chunks = []; for await (const chunk of tunnel) chunks.push(chunk);
    assert.deepEqual(Buffer.concat(chunks), payload);
  } finally { await close(proxy); }
});

test('oversized incomplete CONNECT headers are rejected with a sanitized error', async () => {
  const proxy = net.createServer(socket => socket.once('data', () => socket.end('HTTP/1.1 200 PRIVATE_TOKEN\r\nX-Padding: ' + 'x'.repeat(17000))));
  const proxyPort = await listen(proxy);
  try { await assert.rejects(connectTunnel({ host: 'does-not-resolve.invalid', port: 443, proxyPort, timeoutMs: 1000 }), cause => cause.code === 'PROXY_RESPONSE_INVALID' && !cause.message.includes('PRIVATE_TOKEN')); }
  finally { await close(proxy); }
});

test('pre-aborted CONNECT and HTTPS probes create no socket and never retry the reachable target directly', async t => {
  let connections = 0;
  const server = net.createServer(socket => { connections++; socket.destroy(); });
  const port = await listen(server); t.after(() => close(server));
  const controller = new AbortController(); controller.abort();
  await assert.rejects(connectTunnel({ host: 'public.fixture.invalid', port: 443, proxyPort: port, timeoutMs: 1000, signal: controller.signal,
    onSocket: () => assert.fail('pre-aborted probe must not create a socket') }), { code: 'CONNECTION_CANCELED' });
  await assert.rejects(requestViaProxy(`https://127.0.0.1:${port}/`, { proxyPort: port, timeoutMs: 1000, signal: controller.signal }), { code: 'CONNECTION_CANCELED' });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(connections, 0);
});

test('abort during CONNECT destroys the registered socket and consumes cancellation without an unhandled rejection', { timeout: 3000 }, async t => {
  let arrived, peer, local;
  const entered = new Promise(resolve => { arrived = resolve; });
  const server = net.createServer(socket => { peer = socket; socket.on('error', () => {}); socket.once('data', arrived); });
  const port = await listen(server); t.after(async () => { peer?.destroy(); await close(server); });
  const controller = new AbortController();
  const pending = connectTunnel({ host: 'does-not-resolve.invalid', port: 443, proxyPort: port, timeoutMs: 2000, signal: controller.signal, onSocket: socket => { local = socket; } });
  const canceled = assert.rejects(pending, { code: 'CONNECTION_CANCELED' }); await entered;
  const closed = once(peer, 'close'); controller.abort(); await canceled;
  assert.equal(local.destroyed, true); await closed;
});

test('abort during TLS closes the CONNECT stream before the handshake deadline', { timeout: 3000 }, async t => {
  let reached, peer;
  const tlsStarted = new Promise(resolve => { reached = resolve; });
  const proxy = net.createServer(socket => {
    peer = socket; socket.on('error', () => {});
    socket.once('data', () => { socket.write('HTTP/1.1 200 Connection established\r\n\r\n'); socket.once('data', reached); });
  });
  const proxyPort = await listen(proxy); t.after(async () => { peer?.destroy(); await close(proxy); });
  const controller = new AbortController();
  const pending = requestViaProxy('https://does-not-resolve.invalid/', { proxyPort, timeoutMs: 2000, signal: controller.signal });
  const canceled = assert.rejects(pending, { code: 'CONNECTION_CANCELED' }); await tlsStarted;
  const closed = once(peer, 'close'); controller.abort(); await canceled; await closed;
});

test('abort after trusted TLS response headers closes both HTTP response and ISP tunnel', { timeout: 3000 }, async t => {
  const sockets = new Set(); let arrived, remoteResponse;
  const entered = new Promise(resolve => { arrived = resolve; });
  const target = https.createServer({ key: relayTlsFixture.sameHostLeaf.key, cert: relayTlsFixture.sameHostLeaf.cert }, (_, response) => {
    remoteResponse = response; response.writeHead(200); response.write('{"ip":'); arrived();
  });
  const targetPort = await listen(target), proxy = http.createServer();
  proxy.on('connect', (_, client) => {
    const remote = net.connect(targetPort, '127.0.0.1');
    for (const socket of [client, remote]) { sockets.add(socket); socket.on('error', () => socket.destroy()); socket.once('close', () => sockets.delete(socket)); }
    remote.once('connect', () => { client.write('HTTP/1.1 200 Connection established\r\n\r\n'); client.pipe(remote); remote.pipe(client); });
    client.once('close', () => remote.destroy()); remote.once('close', () => client.destroy());
  });
  const proxyPort = await listen(proxy); t.after(async () => { for (const socket of sockets) socket.destroy(); await Promise.all([close(proxy), close(target)]); });
  const controller = new AbortController();
  const pending = requestViaProxy(`https://localhost:${targetPort}/`, { proxyPort, ca: relayTlsFixture.ca.cert, timeoutMs: 2000, signal: controller.signal });
  const canceled = assert.rejects(pending, { code: 'CONNECTION_CANCELED' }); await entered;
  const closed = new Promise(resolve => remoteResponse.once('close', resolve)); controller.abort(); await canceled; await closed;
  for (let i = 0; i < 100 && sockets.size; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(sockets.size, 0);
});
