import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { UserError } from './config.mjs';

const connectCodes = new Set(['PROXY_TIMEOUT', 'PROXY_CONNECT_REJECTED', 'PROXY_UNREACHABLE', 'PROXY_CLOSED', 'PROXY_RESPONSE_INVALID']);
const responseCodes = new Set(['PROBE_HTTP_STATUS', 'PROBE_RESPONSE_TOO_LARGE', 'PROBE_RESPONSE_FAILED']);
const probeCodes = new Set([...connectCodes, ...responseCodes, 'PROBE_TIMEOUT', 'PROBE_TLS_OR_SOCKET_FAILED', 'PROBE_REQUEST_FAILED']);
const validHttpStatus = value => Number.isInteger(value) && value >= 100 && value <= 599;

// Expose only fixed error categories and evidence from the appropriate layer.
// A CONNECT status is never evidence of a response from the HTTPS destination.
export function sanitizeProbeFailure(cause) {
  if (!probeCodes.has(cause?.code)) return null;
  const code = cause.code, supplied = cause.diagnostic;
  const stage = connectCodes.has(code) ? 'proxy-connect' : code === 'PROBE_TLS_OR_SOCKET_FAILED' ? 'tls'
    : responseCodes.has(code) ? 'target-response' : ['tls', 'target-response'].includes(supplied?.stage) ? supplied.stage : null;
  const diagnostic = stage ? { stage } : {};
  if (stage === 'proxy-connect' && code === 'PROXY_CONNECT_REJECTED') {
    // httpStatus is the historical CONNECT-only alias.
    const status = supplied?.connectHttpStatus ?? supplied?.httpStatus;
    if (validHttpStatus(status)) diagnostic.connectHttpStatus = status;
  }
  if (stage === 'target-response' && validHttpStatus(supplied?.targetHttpStatus)) diagnostic.targetHttpStatus = supplied.targetHttpStatus;
  return { code, ...(Object.keys(diagnostic).length ? { diagnostic } : {}) };
}

// Explicit loopback socket: HTTPS_PROXY, ALL_PROXY and NO_PROXY are never consulted.
export function connectTunnel({ host, port, proxyPort, timeoutMs, onSocket, signal }) {
  if (signal?.aborted) return Promise.reject(new UserError('CONNECTION_CANCELED', 'Connection canceled'));
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: proxyPort });
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => fail('PROXY_TIMEOUT'), timeoutMs);
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); socket.removeListener('data', onData); socket.removeListener('error', onError); socket.removeListener('end', onEnd); socket.removeListener('close', onEnd); };
    const fail = (code, httpStatus) => { cleanup(); socket.destroy(); const cause = new UserError(code, 'Proxy tunnel failed; no direct fallback was attempted');
      cause.diagnostic = { stage: 'proxy-connect', ...(validHttpStatus(httpStatus) ? { httpStatus, connectHttpStatus: httpStatus } : {}) }; reject(cause); };
    const onError = () => fail('PROXY_UNREACHABLE');
    const abort = () => fail('CONNECTION_CANCELED');
    const onEnd = () => fail('PROXY_CLOSED');
    const onData = data => {
      buffer = Buffer.concat([buffer, data]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) { if (buffer.length > 16384) fail('PROXY_RESPONSE_INVALID'); return; }
      if (end + 4 > 16384) return fail('PROXY_RESPONSE_INVALID');
      const status = /^HTTP\/1\.[01] (\d{3})(?: |\r)/.exec(buffer.toString('latin1'));
      if (!status || status[1] !== '200') return fail('PROXY_CONNECT_REJECTED', status ? Number(status[1]) : undefined);
      cleanup();
      socket.pause();
      if (buffer.length > end + 4) socket.unshift(buffer.subarray(end + 4));
      resolve(socket);
      // Let the awaiting caller attach TLS/read handlers before flowing again;
      // idle tunnels must still consume FIN and report peer closure.
      queueMicrotask(() => { if (!socket.destroyed) socket.resume(); });
    };
    socket.on('error', onError).on('data', onData).on('end', onEnd).on('close', onEnd);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    socket.once('connect', () => {
      const authority = `${net.isIP(host) === 6 ? `[${host}]` : host}:${port}`;
      socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
    });
    try { onSocket?.(socket); } catch { fail('PROXY_UNREACHABLE'); }
  });
}
export async function requestViaProxy(url, { proxyPort, timeoutMs, ca, method = 'GET', responseDetails = false, signal } = {}) {
  if (!(url instanceof URL)) url = new URL(url);
  if (url.protocol !== 'https:') throw new UserError('PROBE_URL_INVALID', 'Probe requires HTTPS');
  if (!['GET', 'HEAD'].includes(method)) throw new UserError('PROBE_METHOD_INVALID', 'Only GET and HEAD probes are supported');
  const started = Date.now();
  const targetHost = url.hostname.replace(/^\[|\]$/g, '');
  const tunnel = await connectTunnel({ host: targetHost, port: Number(url.port || 443), proxyPort, timeoutMs, signal });
  return new Promise((resolve, reject) => {
    let settled = false;
    let request;
    let stage = 'tls', targetHttpStatus;
    const agent = new https.Agent({ keepAlive: false });
    let secure;
    const abort = () => fail('CONNECTION_CANCELED');
    const cleanup = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); agent.destroy(); secure?.destroy(); tunnel.destroy(); };
    const fail = code => {
      if (settled) return;
      settled = true; cleanup(); request?.destroy();
      const cause = new UserError(code, 'HTTPS probe failed through the proxy; no direct fallback was attempted');
      cause.diagnostic = { stage: code === 'PROBE_TLS_OR_SOCKET_FAILED' ? 'tls' : stage,
        ...(code !== 'PROBE_TLS_OR_SOCKET_FAILED' && validHttpStatus(targetHttpStatus) ? { targetHttpStatus } : {}) };
      reject(cause);
    };
    const timer = setTimeout(() => fail('PROBE_TIMEOUT'), Math.max(1, timeoutMs - (Date.now() - started)));
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    // All TLS traffic uses the established CONNECT socket. This agent cannot dial another socket.
    agent.createConnection = () => {
      secure = tls.connect({ socket: tunnel, host: targetHost, servername: net.isIP(targetHost) ? undefined : targetHost, rejectUnauthorized: true, minVersion: 'TLSv1.2', ...(ca ? { ca } : {}) });
      secure.once('secureConnect', () => { stage = 'target-response'; });
      secure.once('error', () => fail('PROBE_TLS_OR_SOCKET_FAILED'));
      return secure;
    };
      request = https.request(url, { agent, method, headers: { accept: 'application/json, text/plain', 'user-agent': 'ProxyPilot/2.0', connection: 'close' } }, response => {
        stage = 'target-response'; targetHttpStatus = response.statusCode;
        if (!responseDetails && response.statusCode !== 200) { response.resume(); return fail('PROBE_HTTP_STATUS'); }
        const chunks = []; let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > 16384) return fail('PROBE_RESPONSE_TOO_LARGE');
          chunks.push(chunk);
        });
        response.once('error', () => fail('PROBE_RESPONSE_FAILED'));
        response.once('end', () => {
          if (settled) return;
          settled = true;
          const body = Buffer.concat(chunks).toString('utf8');
          cleanup(); resolve(responseDetails ? { body, statusCode: response.statusCode } : body);
        });
      });
      request.once('error', () => fail('PROBE_REQUEST_FAILED'));
      request.end();
  });
}
function canonicalIp(ip) {
  if (net.isIP(ip) === 6) return new URL(`http://[${ip}]/`).hostname;
  return ip;
}
export async function probe(config, proxyPort = config.listen.port, { signal } = {}) {
  const started = Date.now();
  const body = await requestViaProxy(new URL(config.probe.exitUrl), { proxyPort, timeoutMs: config.probe.timeoutMs, signal });
  let ip;
  try { ip = JSON.parse(body).ip; } catch { ip = body.trim(); }
  if (typeof ip !== 'string' || !net.isIP(ip)) throw new UserError('PROBE_IP_INVALID', 'Exit endpoint did not return an IP address');
  const allowed = config.probe.expectedExitIps;
  if (allowed.length && !allowed.some(expected => canonicalIp(expected) === canonicalIp(ip))) throw new UserError('EXIT_IP_MISMATCH', `Observed exit IP ${ip} is not in the configured allowlist`);
  return { ok: allowed.length > 0, status: allowed.length ? 'verified' : 'discovered_unverified', exitIp: ip, elapsedMs: Date.now() - started, scope: 'One HTTPS request via the configured loopback proxy; no application or system-wide guarantee' };
}
