import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { UserError, validHost } from './config.mjs';
import { connectTunnel } from './probe.mjs';
import { vpnOutboundIdentity } from './vpn-yaml.mjs';

const fail = code => { throw new UserError(code, 'Subscription refresh failed safely; the previous configuration was retained'); };
const MAX_BYTES = 1024 * 1024;
// Only the standardized numeric counters are public metadata. Raw headers and
// subscription URLs never become status fields or diagnostic report content.
export function parseSubscriptionUserInfo(value) {
  if (typeof value !== 'string' || value.length > 1024 || /[\r\n\u0000]/.test(value)) return null;
  const usage = {};
  for (const part of value.split(';')) {
    const match = /^\s*(upload|download|total|expire)\s*=\s*(\d+)\s*$/.exec(part);
    if (!match) { if (/^\s*(upload|download|total|expire)\s*=/.test(part)) return null; continue; }
    const [, key, raw] = match, number = Number(raw);
    if (Object.hasOwn(usage, key) || !Number.isSafeInteger(number) || number < 0 || key === 'expire' && number > 253_402_300_799) return null;
    usage[key] = number;
  }
  return Object.keys(usage).length ? usage : null;
}
export function validateSubscriptionUrl(value) {
  if (typeof value !== 'string' || value.length > 8192 || /[\u0000-\u0020\u007f-\u009f]/.test(value)) fail('VPN_SUBSCRIPTION_URL_INVALID');
  let url; try { url = new URL(value); } catch { fail('VPN_SUBSCRIPTION_URL_INVALID'); }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || !validHost(host)
    || !isIP(host) && (!host.includes('.') || /\.(?:localhost|local|lan)$/.test(host))
    || isIP(host) === 4 && /^(?:0\.|10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|198\.(?:18|19)\.)/.test(host)
    || isIP(host) === 6 && !/^[23][0-9a-f]{3}:/.test(host)) fail('VPN_SUBSCRIPTION_URL_INVALID');
  return url.href;
}

// This agent can only use the already established loopback CONNECT tunnel.
// It cannot resolve or dial the subscription host directly, and never follows redirects.
export async function requestSubscription(url, { proxyPort, timeoutMs = 10_000, maxBytes = MAX_BYTES, signal, includeMetadata = false } = {}) {
  url = new URL(validateSubscriptionUrl(String(url)));
  if (!Number.isInteger(proxyPort) || proxyPort < 1024 || proxyPort > 65535) fail('VPN_SUBSCRIPTION_PROXY_REQUIRED');
  timeoutMs = Math.max(1, Math.min(10_000, Number.isFinite(timeoutMs) ? timeoutMs : 10_000));
  maxBytes = Math.max(1, Math.min(MAX_BYTES, Number.isFinite(maxBytes) ? maxBytes : MAX_BYTES));
  const sockets = new Set(), agent = new https.Agent({ keepAlive: false });
  let request, timer, expired = false;
  const close = () => { request?.destroy(); agent.destroy(); for (const socket of sockets) socket.destroy(); };
  const abort = () => close(); signal?.addEventListener('abort', abort, { once: true });
  timer = setTimeout(() => { expired = true; close(); }, Math.max(1, Math.min(10_000, timeoutMs)));
  try {
    if (signal?.aborted) fail('VPN_SUBSCRIPTION_TIMEOUT');
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const tunnel = await connectTunnel({ host, port: Number(url.port || 443), proxyPort, timeoutMs: Math.max(1, Math.min(10_000, timeoutMs)), onSocket: socket => sockets.add(socket) });
    if (signal?.aborted || tunnel.destroyed) fail('VPN_SUBSCRIPTION_TIMEOUT');
    agent.createConnection = () => {
      const secure = tls.connect({ socket: tunnel, servername: isIP(host) ? undefined : host, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
      sockets.add(secure); return secure;
    };
    return await new Promise((resolve, reject) => {
      const rejectSafe = code => { close(); reject(new UserError(code, 'Subscription download failed without a direct fallback')); };
      request = https.request(url, { agent, method: 'GET', signal, headers: { accept: 'application/json, application/yaml, text/plain', 'accept-encoding': 'identity', 'user-agent': 'MC-Proxy/2.0', connection: 'close' } }, response => {
        if (response.statusCode !== 200) return rejectSafe('VPN_SUBSCRIPTION_HTTP_STATUS');
        if (response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') return rejectSafe('VPN_SUBSCRIPTION_RESPONSE_INVALID');
        if (Number(response.headers['content-length']) > Math.min(MAX_BYTES, maxBytes)) return rejectSafe('VPN_SUBSCRIPTION_TOO_LARGE');
        let length = 0; const chunks = [];
        response.on('data', chunk => { length += chunk.length; if (length > Math.min(MAX_BYTES, maxBytes)) rejectSafe('VPN_SUBSCRIPTION_TOO_LARGE'); else chunks.push(chunk); });
        response.once('error', () => rejectSafe('VPN_SUBSCRIPTION_REQUEST_FAILED'));
        response.once('end', () => {
          try {
            const body = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
            resolve(includeMetadata ? { body, usage: parseSubscriptionUserInfo(response.headers['subscription-userinfo']) } : body);
          }
          catch { rejectSafe('VPN_SUBSCRIPTION_RESPONSE_INVALID'); }
        });
      });
      request.once('error', () => rejectSafe(signal?.aborted || expired ? 'VPN_SUBSCRIPTION_TIMEOUT' : 'VPN_SUBSCRIPTION_REQUEST_FAILED'));
      request.end();
    });
  } catch (cause) {
    if (cause instanceof UserError && cause.code.startsWith('VPN_SUBSCRIPTION_')) throw cause;
    fail(signal?.aborted || expired ? 'VPN_SUBSCRIPTION_TIMEOUT' : 'VPN_SUBSCRIPTION_REQUEST_FAILED');
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); close(); }
}

export function createVpnSubscriptionManager({ store, getProxyLease, request = requestSubscription, now = Date.now, timeoutMs = 10_000 } = {}) {
  if (!store?.load || !store?.import || typeof getProxyLease !== 'function') fail('VPN_SUBSCRIPTION_PROXY_REQUIRED');
  let serial = Promise.resolve();
  timeoutMs = Math.max(1, Math.min(10_000, Number.isFinite(timeoutMs) ? timeoutMs : 10_000));
  const lease = async () => {
    let value; try { value = await getProxyLease(); } catch { fail('VPN_SUBSCRIPTION_PROXY_REQUIRED'); }
    let endpoint; try { endpoint = new URL(value?.url); } catch { fail('VPN_SUBSCRIPTION_PROXY_REQUIRED'); }
    if (value?.mock || value?.exitStatus !== 'verified' || !/^[a-f0-9]{64}$/.test(value.binding || '') || !Number.isSafeInteger(value.revision) || value.revision < 0
      || !Number.isInteger(value.corePort) || value.corePort < 1024 || value.corePort > 65535
      || endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' || !endpoint.port || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash
      || Number(endpoint.port) < 1024 || Number(endpoint.port) > 65535) fail('VPN_SUBSCRIPTION_PROXY_REQUIRED');
    return { binding: value.binding, revision: value.revision, url: endpoint.href, corePort: value.corePort, proxyPort: Number(endpoint.port) };
  };
  return {
    status: async () => (await store.status()).subscription,
    clear: options => store.clearSubscription(options),
    refresh: (options = {}) => {
      const action = async () => {
        const previous = await store.load(), expectedId = options.expectedId === undefined ? previous?.id || null : options.expectedId;
        if (expectedId !== (previous?.id || null)) fail('VPN_IMPORT_CONFLICT');
        const url = validateSubscriptionUrl(options.url ?? previous?.subscription?.url);
        const before = await lease(), controller = new AbortController();
        let timer, expired = false;
        const deadline = new Promise((resolve, reject) => { timer = setTimeout(() => { expired = true; reject(new UserError('VPN_SUBSCRIPTION_TIMEOUT', 'Subscription refresh exceeded its bounded deadline')); controller.abort(); }, timeoutMs); });
        let response;
        try { response = await Promise.race([Promise.resolve().then(() => request(url, { proxyPort: before.proxyPort, timeoutMs, maxBytes: MAX_BYTES, signal: controller.signal, includeMetadata: true })), deadline]); }
        catch (cause) { if (cause instanceof UserError && cause.code.startsWith('VPN_SUBSCRIPTION_')) throw cause; fail('VPN_SUBSCRIPTION_REQUEST_FAILED'); }
        finally { clearTimeout(timer); controller.abort(); }
        if (expired) fail('VPN_SUBSCRIPTION_TIMEOUT');
        const body = typeof response === 'string' ? response : response?.body;
        const usage = response && typeof response === 'object' && response.usage ? parseSubscriptionUserInfo(Object.entries(response.usage).map(([key, value]) => `${key}=${value}`).join(';')) : null;
        if (typeof body !== 'string') fail('VPN_SUBSCRIPTION_RESPONSE_INVALID');
        if (Buffer.byteLength(body, 'utf8') > MAX_BYTES) fail('VPN_SUBSCRIPTION_TOO_LARGE');
        if (vpnOutboundIdentity(before) !== vpnOutboundIdentity(await lease())) fail('VPN_SUBSCRIPTION_ROUTE_CHANGED');
        return store.import(body, { expectedId, expectedContent: vpnOutboundIdentity(previous), subscription: { url, lastUpdatedAt: new Date(now()).toISOString(), ...(usage ? { usage } : {}) } });
      };
      const result = serial.then(action, action); serial = result.catch(() => {}); return result;
    },
  };
}
