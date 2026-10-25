import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import net from 'node:net';
import { once, EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { directHttpsRequest, probeSystemExit } from '../src/system-network-probe.mjs';
import { relayTlsFixture } from './relay-tls-fixture.mjs';

const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 },
  upstream: { type: 'http', host: '192.0.2.1', port: 8080, auth: 'password' },
  probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
const close = server => new Promise(resolve => server.close(resolve));

function responseTransport({ body = '{"ip":"203.0.113.8"}', statusCode = 200, inspect = () => {}, hang = false, cause } = {}) {
  return (url, options, callback) => {
    inspect(url, options);
    const request = new EventEmitter();
    request.destroy = () => {}; request.end = () => queueMicrotask(() => {
      if (cause) return request.emit('error', cause);
      if (hang) return;
      const response = new PassThrough(); response.statusCode = statusCode;
      callback(response);
      if (!response.destroyed) response.end(body);
    });
    return request;
  };
}

test('system probe uses the saved HTTPS endpoint and pinned ISP, caps time and sends no loopback proxy option', async () => {
  let calls = 0;
  const selected = { ...config, probe: { ...config.probe, timeoutMs: 120000 } };
  const result = await probeSystemExit(selected, { request: async (url, options) => {
    calls++; assert.equal(url.href, new URL(config.probe.exitUrl).href); assert.deepEqual(options, { timeoutMs: 10000, signal: undefined });
    return '203.0.113.8\n';
  } });
  assert.equal(calls, 1); assert.equal(result.status, 'verified'); assert.equal(result.ok, true); assert.equal(result.exitIp, '203.0.113.8');
  assert.match(result.scope, /system DNS and routing/);
  const ipv6 = { ...config, probe: { ...config.probe, expectedExitIps: ['2001:db8::8'] } };
  assert.equal((await probeSystemExit(ipv6, { request: async () => '{"ip":"2001:0db8:0:0:0:0:0:8"}' })).ok, true);
});

test('system probe refuses an unpinned configuration before requesting and redacts mismatch or invalid response content', async () => {
  await assert.rejects(probeSystemExit({ ...config, probe: { ...config.probe, expectedExitIps: [] } }, { request: () => assert.fail('unverified config must not probe') }), { code: 'EXPECTED_EXIT_REQUIRED' });
  for (const [body, code] of [['198.51.100.77', 'SYSTEM_EXIT_MISMATCH'], ['SECRET_PROVIDER_TOKEN', 'SYSTEM_RESPONSE_INVALID'], ['{"ip":"SECRET_PROVIDER_TOKEN"}', 'SYSTEM_RESPONSE_INVALID'], ['x'.repeat(16385), 'SYSTEM_RESPONSE_INVALID']]) {
    await assert.rejects(probeSystemExit(config, { request: async () => body }), cause => {
      assert.equal(cause.code, code); assert.doesNotMatch(cause.message, /198\.51\.100\.77|SECRET_PROVIDER_TOKEN/); return true;
    });
  }
});

test('direct system transport uses a fresh agent without proxy environment or custom DNS', async () => {
  let agent;
  const body = await directHttpsRequest(config.probe.exitUrl, { requestHttps: responseTransport({ inspect: (url, options) => {
    assert.equal(url.hostname, 'api.ipify.org'); assert.equal(options.method, 'GET'); assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.minVersion, 'TLSv1.2'); assert.equal(options.lookup, undefined); assert.equal(options.proxyPort, undefined);
    agent = options.agent; assert.notEqual(agent, https.globalAgent); assert.deepEqual(agent.options.proxyEnv, {}); assert.equal(agent.options.keepAlive, false);
  } }) });
  assert.equal(body, '{"ip":"203.0.113.8"}');
});

test('pre-aborted system HTTPS refuses before invoking the transport or creating an agent connection', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(directHttpsRequest(config.probe.exitUrl, { signal: controller.signal, requestHttps: () => assert.fail('canceled transport must stay offline') }), { code: 'CONNECTION_CANCELED' });
  await assert.rejects(probeSystemExit(config, { signal: controller.signal, request: (url, options) => {
    assert.equal(options.signal, controller.signal); return directHttpsRequest(url, { ...options, requestHttps: () => assert.fail('canceled transport must stay offline') });
  } }), { code: 'CONNECTION_CANCELED' });
});

test('system HTTPS cancellation destroys the owned request and partial response without waiting for timeout', async () => {
  const controller = new AbortController(); let request, response, notify;
  const entered = new Promise(resolve => { notify = resolve; });
  const pending = directHttpsRequest(config.probe.exitUrl, { timeoutMs: 1000, signal: controller.signal,
    requestHttps: (_url, _options, callback) => {
      request = new EventEmitter(); request.destroyed = false; request.destroy = () => { request.destroyed = true; };
      request.end = () => queueMicrotask(() => { response = new PassThrough(); response.statusCode = 200; callback(response); response.write('{"ip":'); notify(); });
      return request;
    },
  });
  const canceled = assert.rejects(pending, { code: 'CONNECTION_CANCELED' }); await entered;
  controller.abort(); await canceled;
  assert.equal(request.destroyed, true); assert.equal(response.destroyed, true);
});

test('DNS, timeout, TLS and unreachable errors become fixed diagnostics without private native messages', async () => {
  for (const [nativeCode, code] of [['ENOTFOUND', 'SYSTEM_DNS_FAILED'], ['EAI_AGAIN', 'SYSTEM_DNS_FAILED'], ['ETIMEDOUT', 'SYSTEM_NETWORK_TIMEOUT'], ['ERR_TLS_CERT_ALTNAME_INVALID', 'SYSTEM_TLS_FAILED'], ['SELF_SIGNED_CERT_IN_CHAIN', 'SYSTEM_TLS_FAILED'], ['ECONNREFUSED', 'SYSTEM_NETWORK_UNREACHABLE']]) {
    await assert.rejects(probeSystemExit(config, { request: url => directHttpsRequest(url, { requestHttps: responseTransport({ cause: Object.assign(new Error('SECRET_PROVIDER_TOKEN at 192.0.2.250'), { code: nativeCode }) }) }) }), cause => {
      assert.equal(cause.code, code); assert.doesNotMatch(cause.message, /SECRET_PROVIDER_TOKEN|192\.0\.2\.250/); return true;
    });
  }
});

test('HTTP redirects and errors are not followed; only their numeric status is retained', async () => {
  let requests = 0;
  for (const statusCode of [302, 404, 500]) {
    await assert.rejects(probeSystemExit(config, { request: url => directHttpsRequest(url, { requestHttps: responseTransport({
      statusCode, body: 'SECRET_PROVIDER_TOKEN', inspect: () => { requests++; },
    }) }) }), cause => {
      assert.equal(cause.code, 'SYSTEM_HTTP_STATUS'); assert.deepEqual(cause.diagnostic, { httpStatus: statusCode });
      assert.doesNotMatch(cause.message, /SECRET_PROVIDER_TOKEN/); return true;
    });
  }
  assert.equal(requests, 3);
});

test('direct transport bounds stalled requests and response bytes', async () => {
  await assert.rejects(directHttpsRequest(config.probe.exitUrl, { timeoutMs: 20, requestHttps: responseTransport({ hang: true }) }), { code: 'SYSTEM_NETWORK_TIMEOUT' });
  await assert.rejects(directHttpsRequest(config.probe.exitUrl, { requestHttps: responseTransport({ body: Buffer.alloc(16385) }) }), { code: 'SYSTEM_RESPONSE_INVALID' });
});

test('explicit HEAD details classify unauthenticated endpoints without following redirects or sending authentication', async () => {
  for (const statusCode of [302, 401, 403, 500]) {
    const result = await directHttpsRequest('https://fixed.example.test/', { method: 'HEAD', responseDetails: true, requestHttps: responseTransport({ statusCode, body: '', inspect: (_, options) => {
      assert.equal(options.method, 'HEAD'); assert.equal(options.headers.authorization, undefined); assert.equal(options.headers.cookie, undefined);
    } }) });
    assert.deepEqual(result, { body: '', statusCode });
  }
  await assert.rejects(directHttpsRequest('https://fixed.example.test/', { method: 'POST' }), { code: 'SYSTEM_RESPONSE_INVALID' });
});

test('local HTTPS succeeds through the system socket despite a proxy global agent and proxy environment', async () => {
  let proxyConnections = 0; let targetRequests = 0;
  const proxy = net.createServer(socket => { proxyConnections++; socket.destroy(); });
  const destination = https.createServer({ key: relayTlsFixture.sameHostLeaf.key, cert: relayTlsFixture.sameHostLeaf.cert }, (request, response) => {
    targetRequests++; response.statusCode = request.url === '/missing' ? 404 : 200; response.end('{"ip":"203.0.113.8"}');
  });
  const proxyPort = await listen(proxy); const port = await listen(destination);
  const priorAgent = https.globalAgent; const priorProxy = process.env.HTTPS_PROXY;
  const hostileProxy = `http://127.0.0.1:${proxyPort}`;
  process.env.HTTPS_PROXY = hostileProxy;
  const hostileAgent = new https.Agent({ proxyEnv: { HTTPS_PROXY: hostileProxy }, keepAlive: false });
  https.globalAgent = hostileAgent;
  try {
    const selected = { ...config, probe: { ...config.probe, exitUrl: `https://localhost:${port}/` } };
    const result = await probeSystemExit(selected, { request: url => directHttpsRequest(url, { requestHttps: (target, options, callback) => https.request(target, { ...options, ca: relayTlsFixture.ca.cert }, callback) }) });
    assert.equal(result.exitIp, '203.0.113.8'); assert.equal(targetRequests, 1); assert.equal(proxyConnections, 0);
    await assert.rejects(directHttpsRequest(`https://localhost:${port}/missing`, { requestHttps: (target, options, callback) => https.request(target, { ...options, ca: relayTlsFixture.ca.cert }, callback) }), cause => {
      assert.equal(cause.code, 'SYSTEM_HTTP_STATUS'); assert.deepEqual(cause.diagnostic, { httpStatus: 404 }); return true;
    });
    assert.equal(targetRequests, 2); assert.equal(proxyConnections, 0);
  } finally {
    https.globalAgent = priorAgent; hostileAgent.destroy();
    if (priorProxy === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = priorProxy;
    await close(destination); await close(proxy);
  }
});
