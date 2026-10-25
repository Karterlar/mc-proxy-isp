import { isIP } from 'node:net';
import { requestViaProxy, sanitizeProbeFailure } from './probe.mjs';
import { UserError } from './config.mjs';

export const IP_SOURCES = Object.freeze([
  { id: 'ipify', label: 'ipify', url: 'https://api.ipify.org?format=json', format: 'json' },
  { id: 'cloudflare', label: 'Cloudflare Trace', url: 'https://www.cloudflare.com/cdn-cgi/trace', format: 'trace' },
  { id: 'ipwhois', label: 'IPWhois · 出口位置与时区', url: 'https://ipwho.is/', format: 'geo' },
]);
export const CONNECTIVITY_SOURCES = Object.freeze([
  { id: 'cleanip', label: 'CleanIP', url: 'https://cleanip.io/claude' },
  { id: 'ippure', label: 'IPPure', url: 'https://ippure.com/claude' },
  { id: 'ping0', label: 'Ping0', url: 'https://ping0.cc' },
]);
export const equalIp = (a, b) => isIP(a) && isIP(b) && (isIP(a) === 6 ? new URL(`http://[${a}]/`).hostname : a) === (isIP(b) === 6 ? new URL(`http://[${b}]/`).hostname : b);

export function parseIpResponse(source, body) {
  let data, ip;
  if (source.format === 'trace') ip = String(body).split(/\r?\n/).find(line => line.startsWith('ip='))?.slice(3);
  else { data = JSON.parse(body); ip = data.ip; if (source.format === 'geo' && data.success !== true) throw new Error('Invalid location response'); }
  if (typeof ip !== 'string' || !isIP(ip)) throw new Error('Invalid IP response');
  const timezone = data?.timezone?.id;
  const geo = source.format === 'geo' && typeof timezone === 'string' && timezone.length < 100 && /^[A-Za-z_]+\/[A-Za-z_/-]+$/.test(timezone)
    ? { ip, countryCode: /^[A-Z]{2}$/.test(data.country_code) ? data.country_code : null, timezone, city: typeof data.city === 'string' ? data.city.slice(0, 100) : null, source: source.url } : null;
  return { ip, geo };
}

export function verifiedExitGeography(geo, exitIp, expectedExitIps) {
  if (!geo || !equalIp(geo.ip, exitIp) || !Array.isArray(expectedExitIps) || !expectedExitIps.some(ip => equalIp(ip, geo.ip))
    || !/^[A-Z]{2}$/.test(geo.countryCode || '') || typeof geo.timezone !== 'string' || geo.timezone.length >= 100) return false;
  try { new Intl.DateTimeFormat('en-US', { timeZone: geo.timezone }); return true; } catch { return false; }
}

// Environment localization is independent of optional website reports. Its
// only remote request uses the already verified proxy and fixed geo endpoint.
export async function requestExitGeography({ exitIp, expectedExitIps, proxyPort, request = requestViaProxy, assertCurrent = () => {} } = {}) {
  const source = IP_SOURCES.find(item => item.format === 'geo');
  const unverified = () => new UserError('GEO_UNVERIFIED', 'The verified proxy did not provide valid matching exit geography');
  assertCurrent();
  if (!isIP(exitIp || '') || !Array.isArray(expectedExitIps) || !expectedExitIps.some(ip => equalIp(ip, exitIp))
    || !Number.isInteger(proxyPort) || proxyPort < 1024 || proxyPort > 65535) throw unverified();
  let geo;
  try {
    const body = await request(new URL(source.url), { proxyPort, timeoutMs: 10_000 });
    assertCurrent();
    if (typeof body !== 'string' || Buffer.byteLength(body) > 16384) throw unverified();
    geo = parseIpResponse(source, body).geo;
    if (!verifiedExitGeography(geo, exitIp, expectedExitIps)) throw unverified();
  } catch {
    assertCurrent();
    throw unverified();
  }
  assertCurrent();
  return { ...geo, verified: true };
}

export async function createNetworkReport({ exit, expectedExitIps, proxyPort, request = requestViaProxy, mock = false, includeSites = true, assertCurrent = () => {} }) {
  const sources = [...IP_SOURCES, ...(includeSites ? CONNECTIVITY_SOURCES : [])];
  const results = await Promise.all(sources.map(async source => {
    const started = Date.now();
    const row = { id: source.id, label: source.label, url: source.url, kind: source.format ? 'exit-ip' : 'connectivity' };
    let receivedHttpStatus;
    try {
      assertCurrent();
      if (mock) return { ...row, status: 'mocked', elapsedMs: 0, ...(source.format ? { exitIp: exit.exitIp } : {}) };
      const response = await request(new URL(source.url), { proxyPort, timeoutMs: 10_000, ...(source.format ? {} : { method: 'HEAD', responseDetails: true }) });
      assertCurrent();
      if (!source.format) {
        const httpStatus = response.statusCode;
        if (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599) throw new Error('Invalid HTTP status');
        return { ...row, status: httpStatus >= 200 && httpStatus < 400 ? 'reachable' : 'restricted', stage: 'target-response', transportReachable: true,
          httpStatus, targetHttpStatus: httpStatus, elapsedMs: Date.now() - started, scope: '仅 HTTPS 连通性；不等于网站业务、IP 信誉或登录可用' };
      }
      // The non-details request contract returns a body only after validated
      // TLS and HTTP 200. An invalid IP payload is a response failure, not a
      // failed CONNECT or TLS handshake.
      receivedHttpStatus = 200;
      const parsed = parseIpResponse(source, response);
      const matched = expectedExitIps.some(ip => equalIp(ip, parsed.ip)) && equalIp(exit.exitIp, parsed.ip);
      return { ...row, status: matched ? 'verified' : 'mismatch', exitIp: parsed.ip, elapsedMs: Date.now() - started, ...(parsed.geo ? { geo: { ...parsed.geo, verified: matched } } : {}) };
    } catch (cause) {
      assertCurrent();
      const safe = sanitizeProbeFailure(cause);
      const diagnostic = safe?.diagnostic || (receivedHttpStatus ? { stage: 'target-response', targetHttpStatus: receivedHttpStatus } : {});
      return { ...row, status: 'failed', transportReachable: Number.isInteger(diagnostic.targetHttpStatus), errorCode: safe?.code || 'SITE_UNREACHABLE_OR_INVALID',
        ...diagnostic, elapsedMs: Date.now() - started };
    }
  }));
  const all = [exit, ...results];
  const observed = results.filter(row => row.exitIp && row.status !== 'mocked');
  const mismatch = observed.some(row => row.status === 'mismatch');
  const matched = observed.filter(row => row.status === 'verified').length;
  const complete = results.every(row => ['verified', 'reachable'].includes(row.status));
  return {
    generatedAt: new Date().toISOString(), results: all,
    geo: mock ? null : (results.find(row => row.geo?.verified)?.geo || null),
    summary: { total: all.length, reachable: all.filter(row => ['verified', 'reachable'].includes(row.status)).length, matched, observed: observed.length, consistent: !mock && !mismatch && matched >= 2, status: mock ? 'mocked' : mismatch ? 'fail' : complete ? 'pass' : 'partial' },
    scope: '多个 HTTPS 请求经过 ISP；地理位置来自第三方数据库。TUN、DNS、IPv6 和 WebRTC 的实际泄露验证须另做本机故障测试。',
  };
}
