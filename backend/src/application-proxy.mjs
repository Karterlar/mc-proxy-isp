import http from 'node:http';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { connectTunnel } from './probe.mjs';
import { FAKE_IP_NETWORK, UserError } from './config.mjs';

const fakeIpv6 = new net.BlockList();
const [fakeIpv6Address, fakeIpv6Prefix] = FAKE_IP_NETWORK.ipv6.split('/');
fakeIpv6.addSubnet(fakeIpv6Address, Number(fakeIpv6Prefix), 'ipv6');

// This proxy is scoped to applications explicitly launched by MC Proxy. Only
// literal private addresses and validated .local/.lan names bypass the ISP.
export function isLocalApplicationHost(host) {
  host = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.lan')) return true;
  if (net.isIP(host) === 4) {
    const [a, b] = host.split('.').map(Number);
    return a === 127 || a === 10 || a === 192 && b === 168 || a === 172 && b >= 16 && b <= 31;
  }
  if (net.isIP(host) === 6) {
    const canonical = new URL(`http://[${host}]/`).hostname.slice(1, -1);
    // Fake-IP is a captured public destination, even though its assigned range is ULA.
    if (fakeIpv6.check(canonical, 'ipv6')) return false;
    if (canonical === '::1' || /^f[cd][0-9a-f]{2}:/.test(canonical)) return true;
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(canonical);
    if (mapped) return isLocalApplicationHost([parseInt(mapped[1], 16) >> 8, parseInt(mapped[1], 16) & 255, parseInt(mapped[2], 16) >> 8, parseInt(mapped[2], 16) & 255].join('.'));
  }
  return false;
}

function destination(authority, connect = false) {
  if (typeof authority !== 'string' || /[\s\x00-\x1f\x7f]/.test(authority)) throw new Error('invalid destination');
  const url = new URL(connect ? `http://${authority}` : authority);
  const port = connect ? Number(authority.slice(authority.lastIndexOf(':') + 1)) : Number(url.port || 80);
  if (url.protocol !== 'http:' || url.username || url.password || !url.hostname || !Number.isInteger(port) || port < 1 || port > 65535 || connect && (!/^(?:\[[^\]]+\]|[^:/?#]+):\d+$/.test(authority) || url.pathname !== '/' || url.search || url.hash)) throw new Error('invalid destination');
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port, url };
}

export function createApplicationProxy({ authorize = () => false, resolve = lookup, timeoutMs = 8000, authorizationTimeoutMs = timeoutMs, responseTimeoutMs = 120_000,
  streamIdleTimeoutMs = 300_000, maxConnections = 128, maxPendingRequests = 32, onRoute = () => {}, onFailure = () => {} } = {}) {
  if (![timeoutMs, authorizationTimeoutMs, responseTimeoutMs, streamIdleTimeoutMs].every(value => Number.isInteger(value) && value >= 1 && value <= 3_600_000)
    || ![maxConnections, maxPendingRequests].every(value => Number.isInteger(value) && value >= 1 && value <= 4096)) {
    throw new UserError('APPLICATION_PROXY_INVALID', 'Application proxy limits are invalid');
  }
  let server, binding, listenAbort; let generation = 0;
  const sockets = new Set(), clients = new Set(), pending = new Set(), activeRequests = new Set(), rejectedClients = new WeakSet();
  let totals = { isp: 0, local: 0, failed: 0 };
  let lastFailure = null;
  const failure = code => new UserError(code, 'Application proxy refused the request; no public direct fallback was attempted');
  const recordFailure = cause => {
    if (cause?.code === 'APPLICATION_REQUEST_ABORTED') return;
    const codes = ['APPLICATION_LEASE_INVALID', 'APPLICATION_PROXY_RECURSION', 'APPLICATION_PRIVATE_DNS_FAILED', 'APPLICATION_PROXY_TIMEOUT', 'APPLICATION_RESPONSE_TIMEOUT', 'APPLICATION_PROXY_OVERLOADED', 'PROXY_CONNECT_REJECTED', 'PROXY_UNREACHABLE', 'PROXY_CLOSED', 'PROXY_TIMEOUT', 'PROXY_RESPONSE_INVALID', 'PROCESS_QUERY_FAILED', 'TUN_STATE_UNAVAILABLE'];
    const code = codes.includes(cause?.code) ? cause.code : 'APPLICATION_CONNECT_FAILED';
    const httpStatus = cause?.diagnostic?.httpStatus;
    let diagnostic = Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599 ? { httpStatus } : undefined;
    if (cause?.diagnostic?.operation === 'owned-state' && ['timeout', 'query-failed'].includes(cause.diagnostic.category)) {
      diagnostic = { ...diagnostic, operation: 'owned-state', category: cause.diagnostic.category };
      if (Number.isSafeInteger(cause.diagnostic.elapsedMs) && cause.diagnostic.elapsedMs >= 0 && cause.diagnostic.elapsedMs <= 120_000) diagnostic.elapsedMs = cause.diagnostic.elapsedMs;
    }
    totals.failed++; lastFailure = { code, at: new Date().toISOString(), ...(diagnostic || {}) };
    try { onFailure({ code, ...(diagnostic ? { diagnostic } : {}) }); } catch {}
  };
  const track = socket => { if (!sockets.has(socket)) { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); } return socket; };
  function begin(client) {
    if (rejectedClients.has(client)) throw failure('APPLICATION_REQUEST_ABORTED');
    if (pending.size >= maxPendingRequests || activeRequests.size >= maxConnections) throw failure('APPLICATION_PROXY_OVERLOADED');
    const controller = new AbortController();
    const cancel = () => controller.abort(failure('APPLICATION_REQUEST_ABORTED'));
    const operation = {
      signal: controller.signal, cancel,
      check() { if (controller.signal.aborted || client.destroyed) throw failure('APPLICATION_REQUEST_ABORTED'); },
      wait(promise, budget = timeoutMs) {
        operation.check();
        let timer, aborted;
        return Promise.race([promise, new Promise((_, reject) => {
          timer = setTimeout(() => reject(failure('APPLICATION_PROXY_TIMEOUT')), budget);
          aborted = () => reject(failure('APPLICATION_REQUEST_ABORTED'));
          controller.signal.addEventListener('abort', aborted, { once: true });
        })]).finally(() => { clearTimeout(timer); controller.signal.removeEventListener('abort', aborted); });
      },
      release() { pending.delete(operation); },
      finish() { operation.release(); activeRequests.delete(operation); client.off('close', closed); },
    };
    const closed = () => { cancel(); operation.finish(); };
    client.once('close', closed); pending.add(operation); activeRequests.add(operation); return operation;
  }
  const assertBinding = lease => { if (!lease || binding !== lease || !server) throw failure('APPLICATION_LEASE_INVALID'); };
  async function route(target, operation) {
    operation.check();
    const lease = binding; assertBinding(lease);
    if (!await operation.wait(Promise.resolve(authorize({ ...lease, signal: operation.signal })), authorizationTimeoutMs)) throw failure('APPLICATION_LEASE_INVALID');
    operation.check();
    assertBinding(lease);
    const local = isLocalApplicationHost(target.host);
    let host = target.host;
    if (local && !net.isIP(host)) {
      if (host === 'localhost' || host.endsWith('.localhost')) host = '127.0.0.1';
      else {
        const answers = await operation.wait(resolve(host, { all: true, signal: operation.signal }));
        host = (answers.find(item => net.isIP(item.address) && isLocalApplicationHost(item.address)))?.address;
        if (!host) throw failure('APPLICATION_PRIVATE_DNS_FAILED');
      }
    }
    operation.check(); assertBinding(lease);
    // Refuse both forms of proxy recursion, including IPv4-mapped loopback.
    if (local && [lease.upstreamPort, server.address().port].includes(target.port)) throw failure('APPLICATION_PROXY_RECURSION');
    const kind = local ? 'local' : 'isp'; totals[kind]++; try { onRoute({ kind }); } catch {}
    return { local, host, lease };
  }
  async function tunnel(target, operation) {
    const choice = await route(target, operation);
    assertBinding(choice.lease);
    let socket;
    const registered = value => { socket = track(value); };
    const cancel = () => socket?.destroy(); operation.signal.addEventListener('abort', cancel, { once: true });
    try {
      const remote = !choice.local ? await operation.wait(connectTunnel({ host: target.host, port: target.port, proxyPort: choice.lease.upstreamPort, timeoutMs, onSocket: registered }))
        : await operation.wait(new Promise((resolveConnection, reject) => {
          registered(net.connect({ host: choice.host, port: target.port }));
          socket.once('error', reject); socket.once('close', () => reject(new Error('connection closed')));
          socket.once('connect', () => resolveConnection(socket));
        }));
      operation.check();
      if (binding !== choice.lease) throw failure('APPLICATION_LEASE_INVALID');
      return remote;
    } catch (cause) { socket?.destroy(); throw cause; }
    finally { operation.signal.removeEventListener('abort', cancel); }
  }
  function headers(request, target) {
    const result = { ...request.headers, host: target.url.host }; delete result['proxy-authorization']; delete result['proxy-connection']; return result;
  }
  function responseHeaders(remote) {
    const result = { ...remote.headers };
    const named = String(result.connection || '').split(',').map(value => value.trim().toLowerCase());
    for (const key of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', ...named]) delete result[key];
    return result;
  }
  const failureStatus = cause => cause?.code === 'APPLICATION_PROXY_OVERLOADED' ? 503 : 502;
  const failed = (client, cause) => { recordFailure(cause); if (!client.destroyed && client.writable) client.end(`HTTP/1.1 ${failureStatus(cause)} ${failureStatus(cause) === 503 ? 'Service Unavailable' : 'Bad Gateway'}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`); };
  function pause() {
    generation++;
    binding = null;
    for (const operation of activeRequests) { operation.cancel(); operation.finish(); }
    for (const socket of sockets) socket.destroy();
  }
  async function stop() {
    const current = server, abort = listenAbort;
    pause(); server = null; listenAbort = null;
    abort?.abort();
    if (current) await new Promise(resolveClose => { current.close(resolveClose); current.closeAllConnections(); });
  }
  return {
    async start({ upstreamPort, revision } = {}) {
      if (!Number.isInteger(upstreamPort) || upstreamPort < 1024 || upstreamPort > 65535 || !Number.isInteger(revision)) throw new UserError('APPLICATION_PROXY_INVALID', 'An owned verified upstream is required');
      if (server?.listening) {
        if (binding?.upstreamPort !== upstreamPort || binding?.revision !== revision) { pause(); binding = { upstreamPort, revision }; }
        return this.status();
      }
      const attempt = generation + 1;
      await stop();
      if (generation !== attempt) throw new UserError('APPLICATION_PROXY_INVALID', 'The application proxy start was superseded');
      totals = { isp: 0, local: 0, failed: 0 }; lastFailure = null; binding = { upstreamPort, revision };
      const created = http.createServer({ maxHeaderSize: 16384 }, async (request, response) => {
        let operation, outbound, timer, reported = false, receivedResponse = false;
        const clearResponseTimer = () => clearTimeout(timer);
        const report = cause => {
          clearResponseTimer();
          if (!reported) { reported = true; recordFailure(cause); }
          if (response.destroyed || request.socket.writableEnded) return;
          if (response.headersSent) response.destroy(); else { response.writeHead(failureStatus(cause), { connection: 'close' }); response.end(); }
        };
        const cancel = () => { operation?.cancel(); outbound?.destroy(); clearResponseTimer(); };
        response.once('close', () => { if (!response.writableFinished) cancel(); else clearResponseTimer(); operation?.finish(); });
        request.once('aborted', cancel);
        try {
          operation = begin(request.socket);
          const target = destination(request.url), choice = await route(target, operation);
          assertBinding(choice.lease);
          if (request.destroyed || response.destroyed) return;
          outbound = http.request({ host: choice.local ? choice.host : '127.0.0.1', port: choice.local ? target.port : choice.lease.upstreamPort,
            // No process-global agent or unbounded pool may redirect/reuse this
            // owned connection. Streaming remains on its existing socket.
            agent: false, method: request.method, path: choice.local ? target.url.pathname + target.url.search : target.url.href, headers: headers(request, target) }, remote => {
              receivedResponse = true; clearResponseTimer();
              remote.once('error', () => response.destroy()); remote.once('aborted', () => response.destroy());
              if (response.destroyed) { remote.destroy(); return; }
              response.writeHead(remote.statusCode, responseHeaders(remote)); response.flushHeaders(); remote.pipe(response);
            });
          const connected = new Promise((ready, reject) => {
            outbound.once('socket', socket => {
              track(socket);
              if (binding !== choice.lease) socket.destroy();
              if (socket.connecting) socket.once('connect', ready); else ready();
            });
            outbound.once('error', reject); outbound.once('close', () => reject(failure('APPLICATION_REQUEST_ABORTED')));
          });
          outbound.once('error', report);
          outbound.once('finish', () => {
            if (!receivedResponse && !response.destroyed) timer = setTimeout(() => outbound.destroy(failure('APPLICATION_RESPONSE_TIMEOUT')), responseTimeoutMs);
          });
          outbound.setTimeout(streamIdleTimeoutMs, () => outbound.destroy(failure('APPLICATION_PROXY_TIMEOUT')));
          request.pipe(outbound);
          await operation.wait(connected); operation.check();
        } catch (cause) { outbound?.destroy(); report(cause); }
        finally { operation?.release(); if (!outbound || response.destroyed) operation?.finish(); }
      });
      server = created; const abort = new AbortController(); listenAbort = abort;
      created.on('error', () => { if (server === created) void stop().catch(() => {}); });
      created.headersTimeout = Math.max(1000, Math.min(timeoutMs, 30_000));
      server.on('connection', client => {
        track(client);
        if (clients.size >= maxConnections) { rejectedClients.add(client); failed(client, failure('APPLICATION_PROXY_OVERLOADED')); client.destroySoon(); return; }
        client.setMaxListeners(Math.max(10, maxConnections + 8));
        clients.add(client); client.once('close', () => clients.delete(client));
      });
      server.on('connect', async (request, client, head) => {
        let operation, established = false;
        try {
          operation = begin(client);
          const lease = binding;
          const remote = await tunnel(destination(request.url, true), operation);
          if (client.destroyed || binding !== lease) { remote.destroy(); return; }
          client.write('HTTP/1.1 200 Connection established\r\n\r\n'); if (head.length) remote.write(head);
          established = true;
          client.pipe(remote); remote.pipe(client); client.once('close', () => remote.destroy()); remote.once('close', () => client.destroy());
        } catch (cause) { failed(client, cause); }
        finally { operation?.release(); if (!established) operation?.finish(); }
      });
      server.on('upgrade', async (request, client, head) => {
        let operation, established = false;
        try {
          operation = begin(client);
          const lease = binding;
          const target = destination(request.url), remote = await tunnel(target, operation);
          if (client.destroyed || binding !== lease) { remote.destroy(); return; }
          // Bound only the HTTP Upgrade response, never the subsequent frames.
          let initial = Buffer.alloc(0);
          const complete = () => { clearTimeout(timer); remote.off('data', initialResponse); initial = Buffer.alloc(0); };
          const rejectUpgrade = code => { complete(); failed(client, failure(code)); remote.destroy(); };
          const initialResponse = chunk => {
            initial = Buffer.concat([initial, chunk.subarray(0, Math.max(0, 16385 - initial.length))]);
            const end = initial.indexOf('\r\n\r\n');
            if (end >= 0 && end + 4 <= 16384) complete();
            else if (initial.length > 16384) rejectUpgrade('PROXY_RESPONSE_INVALID');
          };
          const timer = setTimeout(() => rejectUpgrade('APPLICATION_RESPONSE_TIMEOUT'), responseTimeoutMs);
          remote.on('data', initialResponse); remote.once('close', complete); client.once('close', complete);
          remote.write(`${request.method} ${target.url.pathname + target.url.search} HTTP/1.1\r\n${Object.entries(headers(request, target)).map(([key, value]) => `${key}: ${value}`).join('\r\n')}\r\n\r\n`);
          if (head.length) remote.write(head); client.pipe(remote); remote.pipe(client);
          established = true;
          client.once('close', () => remote.destroy()); remote.once('close', () => client.destroy());
        } catch (cause) { failed(client, cause); }
        finally { operation?.release(); if (!established) operation?.finish(); }
      });
      server.on('clientError', (_, socket) => socket.destroy());
      try {
        await new Promise((ready, reject) => {
          const closed = () => reject(new UserError('APPLICATION_PROXY_INVALID', 'The application proxy start was canceled'));
          created.once('error', reject); created.once('close', closed);
          created.listen({ host: '127.0.0.1', port: 0, exclusive: true, signal: abort.signal }, () => { created.off('error', reject); created.off('close', closed); ready(); });
        });
        if (generation !== attempt || server !== created) throw new UserError('APPLICATION_PROXY_INVALID', 'The application proxy start was canceled');
      } catch (cause) { if (server === created) await stop(); throw cause; }
      return this.status();
    },
    status() { const port = server?.address()?.port; return { running: Boolean(port), accepting: Boolean(port && binding), port: port || null, endpoint: port ? `127.0.0.1:${port}` : null, url: port ? `http://127.0.0.1:${port}` : null, policy: 'private-direct-public-isp', ...totals, lastFailure,
      capacity: { activeConnections: clients.size, activeRequests: activeRequests.size, pendingRequests: pending.size, maxConnections, maxPendingRequests } }; },
    stop, pause,
  };
}
