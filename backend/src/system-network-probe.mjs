import https from 'node:https';
import { isIP } from 'node:net';
import { UserError, validateConfig } from './config.mjs';
import { equalIp } from './network-report.mjs';

const MAX_BODY = 16384;
const MESSAGES = Object.freeze({
  CONNECTION_CANCELED: 'Connection canceled',
  SYSTEM_DNS_FAILED: 'System DNS could not resolve the exit verification endpoint',
  SYSTEM_NETWORK_TIMEOUT: 'System HTTPS exit verification timed out',
  SYSTEM_TLS_FAILED: 'System HTTPS exit verification failed TLS validation',
  SYSTEM_NETWORK_UNREACHABLE: 'The exit verification endpoint is unreachable through system networking',
  SYSTEM_EXIT_MISMATCH: 'The system network exit is outside the configured ISP allowlist',
  SYSTEM_RESPONSE_INVALID: 'The system exit verification endpoint returned an invalid response',
  SYSTEM_HTTP_STATUS: 'The system exit verification endpoint did not return HTTP 200',
});
const failure = (code, diagnostic) => {
  const cause = new UserError(code, MESSAGES[code]);
  if (code === 'SYSTEM_HTTP_STATUS' && Number.isInteger(diagnostic?.httpStatus) && diagnostic.httpStatus >= 100 && diagnostic.httpStatus <= 599) cause.diagnostic = { httpStatus: diagnostic.httpStatus };
  return cause;
};
function classify(cause) {
  const code = typeof cause?.code === 'string' ? cause.code : '';
  if (Object.hasOwn(MESSAGES, code)) return code;
  if (['ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'EAI_NODATA', 'EAI_NONAME'].includes(code)) return 'SYSTEM_DNS_FAILED';
  if (['ETIMEDOUT', 'ESOCKETTIMEDOUT'].includes(code)) return 'SYSTEM_NETWORK_TIMEOUT';
  if (/^(?:ERR_TLS_|ERR_SSL_|ERR_OSSL_|CERT_)/.test(code) || ['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(code)) return 'SYSTEM_TLS_FAILED';
  return 'SYSTEM_NETWORK_UNREACHABLE';
}

// A fresh owned agent uses default OS DNS/routing and explicitly has no proxy
// environment. Call this only after the controller verifies its owned TUN.
export function directHttpsRequest(url, { timeoutMs = 10000, requestHttps = https.request, method = 'GET', responseDetails = false, signal } = {}) {
  if (signal?.aborted) return Promise.reject(failure('CONNECTION_CANCELED'));
  try { url = url instanceof URL ? url : new URL(url); }
  catch { return Promise.reject(failure('SYSTEM_RESPONSE_INVALID')); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || !['GET', 'HEAD'].includes(method)) return Promise.reject(failure('SYSTEM_RESPONSE_INVALID'));
  return new Promise((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false, proxyEnv: {} });
    let request; let response; let settled = false;
    const finish = (cause, body) => {
      if (settled) return; settled = true;
      clearTimeout(timer); signal?.removeEventListener('abort', abort); response?.destroy(); request?.destroy(); agent.destroy();
      cause ? reject(failure(classify(cause), cause.diagnostic)) : resolve(body);
    };
    const timer = setTimeout(() => finish(failure('SYSTEM_NETWORK_TIMEOUT')), Math.max(1, Math.min(10000, Number.isFinite(timeoutMs) ? timeoutMs : 10000)));
    const abort = () => finish(failure('CONNECTION_CANCELED'));
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    try {
      request = requestHttps(url, { agent, method, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        headers: { accept: 'application/json, text/plain', 'user-agent': 'ProxyPilot/2.0', connection: 'close' } }, incoming => {
        response = incoming;
        incoming.once('error', cause => finish(cause));
        incoming.once('aborted', () => finish(failure('SYSTEM_NETWORK_UNREACHABLE')));
        if (!responseDetails && incoming.statusCode !== 200) return finish(failure('SYSTEM_HTTP_STATUS', { httpStatus: incoming.statusCode }));
        const chunks = []; let length = 0;
        incoming.on('data', chunk => {
          if (settled) return;
          length += chunk.length;
          if (length > MAX_BODY) return finish(failure('SYSTEM_RESPONSE_INVALID'));
          chunks.push(chunk);
        });
        incoming.once('end', () => finish(null, responseDetails ? { body: Buffer.concat(chunks).toString('utf8'), statusCode: incoming.statusCode } : Buffer.concat(chunks).toString('utf8')));
      });
      request.once('error', cause => finish(cause));
      request.end();
    } catch (cause) { finish(cause); }
  });
}

export async function probeSystemExit(config, { request = directHttpsRequest, signal } = {}) {
  validateConfig(config);
  if (!config.probe.expectedExitIps.length) throw new UserError('EXPECTED_EXIT_REQUIRED', 'Configure the expected ISP exit before checking system networking');
  const started = Date.now(); let body;
  try { body = await request(new URL(config.probe.exitUrl), { timeoutMs: Math.min(config.probe.timeoutMs, 10000), signal }); }
  catch (cause) { throw failure(classify(cause), cause.diagnostic); }
  if (typeof body !== 'string' || Buffer.byteLength(body) > MAX_BODY) throw failure('SYSTEM_RESPONSE_INVALID');
  let ip;
  try { ip = JSON.parse(body).ip; } catch { ip = body.trim(); }
  if (typeof ip !== 'string' || !isIP(ip)) throw failure('SYSTEM_RESPONSE_INVALID');
  if (!config.probe.expectedExitIps.some(expected => equalIp(expected, ip))) throw failure('SYSTEM_EXIT_MISMATCH');
  return { ok: true, status: 'verified', exitIp: ip, elapsedMs: Date.now() - started,
    scope: 'One HTTPS request using system DNS and routing without a local proxy; applications with their own network settings still require verification' };
}
