import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP, BlockList } from 'node:net';
import { browserConsistencyChecks, validateIdentityUaCh, validDeviceMemory } from './browser-consistency.mjs';

const ASSETS = Object.freeze({ 'browser-observation.html': 'text/html; charset=utf-8', 'browser-observation.js': 'text/javascript; charset=utf-8', 'browser-observation.css': 'text/css; charset=utf-8', 'browser-identity-probe.js': 'text/javascript; charset=utf-8' });
export const OBSERVATION_LIMITS = Object.freeze({ bodyBytes: 32768, sessionMs: 300000, measurementMs: 45000 });
export const OBSERVATION_SOURCES = Object.freeze([
  { id: 'ipify-v4', url: 'https://api4.ipify.org/?format=json', family: 4, format: 'json' },
  { id: 'cloudflare', url: 'https://www.cloudflare.com/cdn-cgi/trace', family: 0, format: 'trace' },
  { id: 'ipify-v6', url: 'https://api6.ipify.org/?format=json', family: 6, format: 'json' },
]);
const fail = (code, status = 400) => Object.assign(new Error(code), { code, status });
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const keys = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key));
const text = (value, limit = 256) => typeof value === 'string' && value.length <= limit && !/[\x00-\x1f\x7f]/.test(value);
const count = value => Number.isInteger(value) && value >= 0 && value <= 1000;
const finite = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100000;
const ipKey = value => isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.toLowerCase() : value;
const bindingKey = value => JSON.stringify([value?.revision, value?.configHash, value?.exitBinding]);
const clone = value => value == null ? value : JSON.parse(JSON.stringify(value));
const HTTP_IDENTITY_HEADERS = ['user-agent', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-platform', 'sec-ch-ua-mobile', 'sec-ch-ua-platform-version', 'sec-ch-ua-full-version-list', 'device-memory', 'sec-ch-device-memory'];
const targetContext = active => ({ workspaceId: active?.workspaceId ?? null, identityRevision: active?.identityRevision ?? null, managedLaunchVerified: active?.managedLaunchVerified === true });
function identityTarget(value = {}) {
  if (!keys(value, ['workspaceId', 'identityRevision', 'expectedIdentity'])) throw fail('OBSERVATION_CONTEXT_INVALID');
  const workspaceId = value.workspaceId ?? null, identityRevision = value.identityRevision ?? null, identity = value.expectedIdentity ?? null;
  if (workspaceId !== null && !(typeof workspaceId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(workspaceId))
    || identityRevision !== null && !(typeof identityRevision === 'string' && /^[a-f0-9]{64}$/.test(identityRevision))) throw fail('OBSERVATION_CONTEXT_INVALID');
  if (identity !== null && (!keys(identity, ['platform', 'platformVersion', 'cores', 'engineVersion', 'nativeGraphics', 'seed']) || identity.platform !== 'windows'
    || typeof identity.platformVersion !== 'string' || !/^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(identity.platformVersion)
    || !Number.isInteger(identity.cores) || identity.cores < 1 || identity.cores > 1024 || typeof identity.engineVersion !== 'string' || !/^\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(identity.engineVersion)
    || typeof identity.nativeGraphics !== 'boolean' || 'seed' in identity && (!Number.isInteger(identity.seed) || identity.seed < 0 || identity.seed > 4294967295))) throw fail('OBSERVATION_CONTEXT_INVALID');
  // The seed is private profile state. The diagnostic page only needs its revision.
  const expectedIdentity = identity === null ? null : Object.fromEntries(Object.entries(identity).filter(([key]) => key !== 'seed'));
  return { workspaceId, identityRevision, expectedIdentity };
}
const validBinding = value => keys(value, ['revision', 'configHash', 'exitBinding']) && Number.isSafeInteger(value.revision) && value.revision >= 0
  && text(value.configHash, 128) && value.configHash.length > 0 && text(value.exitBinding, 2048) && value.exitBinding.length > 0;
const maskedIp = ip => isIP(ip) === 4 ? `${ip.split('.').slice(0, 2).join('.')}.*.*` : `${ip.split(':').slice(0, 2).join(':')}:…`;
const languageMatches = (actual, expected) => {
  try {
    const observed = new Intl.Locale(actual), target = new Intl.Locale(expected);
    // A generic target such as "en" allows en-US; an explicit region/script
    // must match. A secondary language never proves the primary locale changed.
    return observed.baseName === target.baseName || target.baseName === target.language && observed.language === target.language;
  } catch { return false; }
};

const publicDomain = value => text(value, 190) && value.includes('.') && !isIP(value) && !/(?:^|\.)(?:localhost|local|internal|invalid|test)$/i.test(value)
  && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
function resolverRanges(values = []) {
  if (!Array.isArray(values) || values.length > 32) throw fail('DNS_OBSERVATION_CONFIG_INVALID');
  const block = new BlockList();
  for (const value of values) {
    if (!text(value, 80)) throw fail('DNS_OBSERVATION_CONFIG_INVALID');
    const [address, prefix, ...extra] = value.split('/'), family = isIP(address);
    if (!family || extra.length || prefix !== undefined && (!/^\d+$/.test(prefix) || +prefix > (family === 4 ? 32 : 128))) throw fail('DNS_OBSERVATION_CONFIG_INVALID');
    if (prefix === undefined) block.addAddress(address, family === 4 ? 'ipv4' : 'ipv6');
    else block.addSubnet(address, +prefix, family === 4 ? 'ipv4' : 'ipv6');
  }
  return block;
}
export function validateDnsObservationConfig(value) {
  if (value == null) return null;
  if (!keys(value, ['queryDomain', 'receiptOrigin', 'allowedResolvers', 'deniedResolvers']) || !publicDomain(value.queryDomain)) throw fail('DNS_OBSERVATION_CONFIG_INVALID');
  let url; try { url = new URL(value.receiptOrigin); } catch { throw fail('DNS_OBSERVATION_CONFIG_INVALID'); }
  if (url.protocol !== 'https:' || !publicDomain(url.hostname) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw fail('DNS_OBSERVATION_CONFIG_INVALID');
  const allowedResolvers = value.allowedResolvers || [], deniedResolvers = value.deniedResolvers || [];
  resolverRanges(allowedResolvers); resolverRanges(deniedResolvers);
  return { queryDomain: value.queryDomain.toLowerCase(), receiptOrigin: url.origin, allowedResolvers: [...allowedResolvers], deniedResolvers: [...deniedResolvers] };
}

function normalizeDnsObservation(input, session, mock) {
  if (!keys(input, ['status', 'reason', 'probeId', 'complete', 'queries', 'resolverIps']) || !['measured', 'failed', 'unverified'].includes(input.status)
    || ('reason' in input && !/^[A-Z_]{1,64}$/.test(input.reason))) throw fail('OBSERVATION_REPORT_INVALID');
  const probe = session.dnsProbe;
  if (!probe) {
    if (input.status !== 'unverified' || input.reason !== 'CONTROLLED_DNS_TEST_NOT_CONFIGURED' || Object.keys(input).length !== 2) throw fail('OBSERVATION_REPORT_INVALID');
    return { ...input, measured: false, verified: false };
  }
  if (input.probeId !== probe.probeId || typeof input.complete !== 'boolean' || !Number.isInteger(input.queries) || input.queries < 0 || input.queries > 4
    || !Array.isArray(input.resolverIps) || input.resolverIps.length > 64 || !input.resolverIps.every(ip => typeof ip === 'string' && isIP(ip))
    || input.status === 'measured' && (!input.resolverIps.length || !input.queries)) throw fail('OBSERVATION_REPORT_INVALID');
  const allowed = resolverRanges(probe.allowedResolvers), denied = resolverRanges(probe.deniedResolvers), resolvers = [...new Set(input.resolverIps)];
  const unexpected = resolvers.filter(ip => denied.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6') || probe.allowedResolvers.length && !allowed.check(ip, isIP(ip) === 4 ? 'ipv4' : 'ipv6'));
  const measured = !mock && input.status === 'measured';
  const verified = measured && input.complete && input.queries === 4 && probe.allowedResolvers.length > 0 && !unexpected.length;
  return { status: mock ? 'mocked' : measured && unexpected.length ? 'mismatch' : verified ? 'verified' : input.status === 'failed' ? 'failed' : 'unverified',
    measured, verified, complete: input.complete, queries: input.queries, resolverCount: resolvers.length, unexpectedResolvers: unexpected.length,
    resolvers: resolvers.map(ip => ({ ...(unexpected.includes(ip) || !probe.allowedResolvers.length ? { maskedIp: maskedIp(ip) } : { ip }), allowed: Boolean(probe.allowedResolvers.length) && !unexpected.includes(ip) })),
    reason: mock ? 'MOCK_NOT_REAL_DNS' : !measured ? input.reason || 'DNS_RECEIPT_NOT_MEASURED' : !probe.allowedResolvers.length ? 'DNS_POLICY_NOT_CONFIGURED' : input.complete && input.queries === 4 ? unexpected.length ? 'DNS_RESOLVER_POLICY_MISMATCH' : 'AUTHORITATIVE_RECEIPT_MATCHED' : 'DNS_RECEIPT_INCOMPLETE' };
}

// Reports are browser self-observations, never an authentication or network unlock signal.
export function normalizeBrowserObservation(input, session, { mock = false, now = Date.now } = {}) {
  if (!keys(input, ['schemaVersion', 'binding', 'elapsedMs', 'browser', 'checks']) || input.schemaVersion !== 1
    || !validBinding(input.binding) || bindingKey(input.binding) !== bindingKey(session.binding)
    || !finite(input.elapsedMs) || input.elapsedMs > OBSERVATION_LIMITS.measurementMs + 1000) throw fail('OBSERVATION_REPORT_INVALID');
  const browser = input.browser;
  if (!keys(browser, ['userAgent', 'language', 'languages', 'timezone', 'platform', 'hardwareConcurrency', 'deviceMemory', 'viewport', 'permissions', 'uaCh'])
    || !text(browser.userAgent, 512) || !text(browser.language, 64) || !text(browser.timezone, 100) || !text(browser.platform, 100)
    || !Array.isArray(browser.languages) || browser.languages.length > 16 || !browser.languages.every(item => text(item, 64))
    || !keys(browser.viewport, ['width', 'height', 'screenWidth', 'screenHeight', 'pixelRatio'])
    || !Object.values(browser.viewport).every(finite) || Object.keys(browser.viewport).length !== 5
    || !Array.isArray(browser.permissions) || browser.permissions.length > 3
    || !browser.permissions.every(item => keys(item, ['name', 'state']) && ['geolocation', 'camera', 'microphone'].includes(item.name) && ['granted', 'denied', 'prompt', 'unverified'].includes(item.state))
    || 'hardwareConcurrency' in browser && (!Number.isInteger(browser.hardwareConcurrency) || browser.hardwareConcurrency < 0 || browser.hardwareConcurrency > 1024)
    || 'deviceMemory' in browser && !validDeviceMemory(browser.deviceMemory)) throw fail('OBSERVATION_REPORT_INVALID');
  validateIdentityUaCh(browser.uaCh);
  const checks = input.checks;
  if (!keys(checks, ['https', 'ipv6', 'webrtc', 'dns', 'canvas', 'consistency']) || !['https', 'ipv6', 'webrtc', 'dns', 'canvas'].every(key => Object.hasOwn(checks, key))
    || !Array.isArray(checks.https) || checks.https.length !== 2) throw fail('OBSERVATION_REPORT_INVALID');
  function exit(source, expectedId) {
    if (!keys(source, ['id', 'status', 'ip', 'elapsedMs', 'errorCode']) || source.id !== expectedId
      || !['measured', 'failed', 'unverified'].includes(source.status) || !finite(source.elapsedMs)
      || ('errorCode' in source && !/^[A-Z_]{1,64}$/.test(source.errorCode))) throw fail('OBSERVATION_REPORT_INVALID');
    if (source.status !== 'measured') {
      if ('ip' in source) throw fail('OBSERVATION_REPORT_INVALID');
      return { id: source.id, status: source.status, elapsedMs: source.elapsedMs, ...(source.errorCode ? { errorCode: source.errorCode } : {}) };
    }
    const family = isIP(source.ip || '');
    if (!family || expectedId === 'ipify-v4' && family !== 4 || expectedId === 'ipify-v6' && family !== 6) throw fail('OBSERVATION_REPORT_INVALID');
    const expectedMatch = session.expectedExitIps.some(ip => ipKey(ip) === ipKey(source.ip));
    return { id: source.id, status: mock ? 'unverified' : 'measured', family, expectedMatch: !mock && expectedMatch,
      ...(expectedMatch ? { ip: source.ip } : { maskedIp: maskedIp(source.ip) }), elapsedMs: source.elapsedMs };
  }
  const https = [exit(checks.https[0], 'ipify-v4'), exit(checks.https[1], 'cloudflare')];
  const ipv6 = exit(checks.ipv6, 'ipify-v6');
  const dns = normalizeDnsObservation(checks.dns, session, mock);
  const rtc = checks.webrtc;
  if (!keys(rtc, ['status', 'complete', 'counts', 'errorCode']) || !['measured', 'failed', 'unverified'].includes(rtc.status)
    || typeof rtc.complete !== 'boolean' || !keys(rtc.counts, ['public', 'unexpectedPublic', 'private', 'mdns', 'relay'])
    || Object.keys(rtc.counts).length !== 5 || !Object.values(rtc.counts).every(count) || rtc.counts.unexpectedPublic > rtc.counts.public
    || ('errorCode' in rtc && !/^[A-Z_]{1,64}$/.test(rtc.errorCode))
    || !keys(checks.canvas, ['status', 'hash', 'reason', 'repeatHash']) || !['measured', 'failed', 'unverified'].includes(checks.canvas.status)
    || ('reason' in checks.canvas && !/^[A-Z_]{1,64}$/.test(checks.canvas.reason))
    || (checks.canvas.status === 'measured' ? !/^[a-f0-9]{64}$/.test(checks.canvas.hash || '') : 'hash' in checks.canvas || 'repeatHash' in checks.canvas)
    || 'repeatHash' in checks.canvas && !/^[a-f0-9]{64}$/.test(checks.canvas.repeatHash)) throw fail('OBSERVATION_REPORT_INVALID');
  const consistency = browserConsistencyChecks({ input: checks.consistency, browser, headers: session.headerObservation || null, expectedIdentity: session.expectedIdentity || null, mock });
  // No candidates is not proof of WebRTC privacy; UDP failure/browser policy can hide evidence.
  const webrtc = { ...rtc, status: mock || !rtc.counts.public && !rtc.counts.private && !rtc.counts.mdns ? 'unverified' : rtc.status };
  const measured = https.filter(row => row.status === 'measured');
  const checkRows = [
    { id: 'https-exit', label: '浏览器 HTTPS 出口', status: mock ? 'mocked' : measured.some(row => !row.expectedMatch) ? 'mismatch' : measured.length === 2 ? 'verified' : 'unverified',
      detail: measured.length === 2 ? '两个外部服务观测当前浏览器的 HTTPS 路径。' : '出口服务失败或受 CORS/网络限制；未改用直连重试。', value: https.map(row => row.ip || row.maskedIp || row.errorCode || row.status).join(' / ') },
    { id: 'language', label: '浏览器语言', status: mock ? 'mocked' : session.language ? languageMatches(browser.language, session.language) && (!browser.languages.length || languageMatches(browser.languages[0], session.language)) ? 'verified' : 'mismatch' : 'unverified', detail: 'navigator 主语言实测；仅在备选语言中包含目标语言不算匹配。', value: `主语言 ${browser.language || '未取得'} / 偏好 ${browser.languages.join(', ') || '未取得'}` },
    { id: 'timezone', label: '浏览器时区', status: mock ? 'mocked' : session.timezone ? browser.timezone === session.timezone ? 'verified' : 'mismatch' : 'unverified', detail: 'Intl 实测；未设置目标时仅记录观测。', value: browser.timezone },
    { id: 'ipv6', label: '浏览器 IPv6 出口', status: mock ? 'mocked' : ipv6.status === 'measured' ? ipv6.expectedMatch ? 'verified' : 'mismatch' : 'unverified', detail: ipv6.status === 'measured' ? '独立 IPv6 HTTPS 端点返回有效地址。' : 'IPv6端点未取得有效观测；不能据此证明系统IPv6已关闭，也不代表DNS泄漏。', value: ipv6.ip || ipv6.maskedIp || ipv6.errorCode || ipv6.status },
    { id: 'webrtc', label: 'WebRTC / ICE', status: mock ? 'mocked' : rtc.counts.unexpectedPublic ? 'mismatch' : 'unverified', detail: rtc.counts.unexpectedPublic ? '发现不匹配预期ISP的公网候选；请与未开代理时的公网基线比较。' : '无异常候选不证明无泄漏；浏览器策略、UDP阻断和STUN可达性会影响结果。', value: `公网 ${rtc.counts.public} / 非预期 ${rtc.counts.unexpectedPublic} / 局域 ${rtc.counts.private} / mDNS ${rtc.counts.mdns}` },
    { id: 'dns', label: '真实 DNS 泄漏', status: dns.status, detail: dns.verified ? '四个唯一域名均取得权威DNS回执，递归解析器匹配已配置的允许范围；仅覆盖本次浏览器请求。'
      : dns.measured ? dns.unexpectedResolvers ? '权威回执发现不符合允许策略的解析器；请核对本地公网基线与DNS路由。' : '已取得权威DNS查询回执，但缺少允许解析器策略或回执不完整，未判无泄漏。'
      : session.dnsProbe ? '浏览器未取得有效的权威DNS回执；网络/CORS/服务失败都不能判为无泄漏。' : '未配置受控权威DNS与唯一查询回执；fake-ip/DoH配置、出口IP及IPv6失败均不是DNS无泄漏实证。',
      ...(dns.resolverCount ? { value: `已测解析器 ${dns.resolverCount} / 非预期 ${dns.unexpectedResolvers} / 已观察查询 ${dns.queries}/4` } : {}) },
    { id: 'permissions', label: '检查页面权限', status: 'unverified', detail: '仅查询当前页面权限状态，不请求定位、摄像头或麦克风；页面安全策略可使状态为denied。', value: browser.permissions.map(item => `${item.name}: ${item.state}`).join(' / ') },
    { id: 'viewport', label: '浏览器窗口', status: mock ? 'mocked' : 'measured', detail: '当前检测标签页实测，仅用于本机诊断。', value: `${browser.viewport.width} × ${browser.viewport.height} / DPR ${browser.viewport.pixelRatio}` },
    { id: 'ua-ch', label: 'UA / UA-CH 读数', status: browser.uaCh.status === 'measured' ? mock ? 'mocked' : 'measured' : 'unverified', detail: '读取成功仅记为已采集；一致性在下方分别比较，不证明受管身份或匿名性。', value: browser.userAgent },
    { id: 'canvas', label: '可选 Canvas 摘要', status: checks.canvas.status === 'measured' ? mock ? 'mocked' : checks.canvas.repeatHash && checks.canvas.repeatHash !== checks.canvas.hash ? 'mismatch' : 'measured' : 'unverified', detail: '只计算本页新画测试图；重复摘要相同仅覆盖本次读取，不证明重启后稳定或无法追踪。', ...(checks.canvas.hash ? { value: `${checks.canvas.hash}${checks.canvas.repeatHash ? checks.canvas.repeatHash === checks.canvas.hash ? ' · 本次重复读取一致' : ' · 本次重复读取不同' : ''}` } : {}) },
    ...consistency.checks,
  ];
  return {
    schemaVersion: 1, binding: clone(session.binding), observedAt: new Date(now()).toISOString(), elapsedMs: input.elapsedMs,
    source: { kind: mock ? 'fixture' : 'browser-self-report', requestedBrowser: session.browser || 'unspecified', managedIdentityVerified: false, managedLaunchVerified: !mock && session.managedLaunchVerified === true, workspaceId: session.workspaceId ?? null, identityRevision: session.identityRevision ?? null },
    configured: { language: session.language || null, timezone: session.timezone || null, expectedExitIps: [...session.expectedExitIps], expectedIdentity: session.expectedIdentity ? Object.fromEntries(Object.entries(session.expectedIdentity).filter(([key]) => key !== 'seed')) : null },
    expectedExitIps: [...session.expectedExitIps], browser: clone(browser), checks: checkRows, measurements: { https, ipv6, webrtc, dns, canvas: clone(checks.canvas), consistency: consistency.measurements },
    summary: { status: mock ? 'unverified' : checkRows.some(row => row.status === 'mismatch') ? 'mismatch' : measured.length === 2 ? 'measured' : 'partial',
      httpsExpectedMatch: !mock && measured.length === 2 && measured.every(row => row.expectedMatch),
      webrtcUnexpectedPublic: rtc.counts.unexpectedPublic > 0, dnsVerified: dns.verified, authority: 'diagnostic-only' },
    scope: '浏览器页面自报观测；不证明受管浏览器身份，也不授予授权或解锁。IPv6失败不等于DNS泄漏；WebRTC需结合未开代理时公网基线。',
  };
}

export function createBrowserObservation({ getContext = () => ({}), isCurrent = () => true, now = Date.now, assetsRoot = fileURLToPath(new URL('../../frontend/', import.meta.url)), mock = false, dnsProbe = null } = {}) {
  const dnsConfiguration = validateDnsObservationConfig(dnsProbe);
  let server = null, starting = null, origin = null, session = null, report = null, closed = false, target = identityTarget();
  const safeHeaders = (type, frame = false) => ({ 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cross-Origin-Resource-Policy': 'same-origin',
    'Accept-CH': 'Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Device-Memory, Sec-CH-Device-Memory',
    'Content-Security-Policy': `default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; frame-src 'self'; connect-src 'self' https://api4.ipify.org https://api6.ipify.org https://www.cloudflare.com${dnsConfiguration ? ` ${dnsConfiguration.receiptOrigin} https://*.${dnsConfiguration.queryDomain}` : ''}; img-src 'none'; frame-ancestors '${frame ? 'self' : 'none'}'; base-uri 'none'; form-action 'none'`,
    'Permissions-Policy': 'geolocation=(), camera=(), microphone=()' });
  const respond = (res, status, data) => { res.writeHead(status, safeHeaders('application/json; charset=utf-8')); res.end(JSON.stringify(data)); };
  async function current() {
    if (!session || closed || now() >= session.expiresAt) { session = null; report = null; return false; }
    const active = session;
    const valid = await isCurrent(clone(active.binding), targetContext(active));
    if (active !== session) return false;
    if (!valid) { session = null; report = null; return false; }
    return true;
  }
  async function handle(req, res) {
    try {
      if (!origin || req.headers.host !== new URL(origin).host || (req.headers.origin && req.headers.origin !== origin)
        || ['cross-site', 'same-site'].includes(req.headers['sec-fetch-site'])) throw fail('OBSERVATION_ORIGIN_REJECTED', 403);
      const url = new URL(req.url, origin);
      if (url.origin !== origin) throw fail('OBSERVATION_ORIGIN_REJECTED', 403);
      if (url.search || url.hash || !await current()) throw fail('OBSERVATION_SESSION_EXPIRED', 410);
      const active = session;
      const prefix = `/s/${active.token}/`;
      if (!url.pathname.startsWith(prefix)) throw fail('OBSERVATION_TOKEN_INVALID', 404);
      const resource = url.pathname.slice(prefix.length);
      if (req.method === 'GET' && resource === 'context') {
        const additional = await getContext(clone(active.binding));
        if (active !== session || !await current()) throw fail('OBSERVATION_SESSION_EXPIRED', 410);
        report = null; active.headerObservation = null;
        if (dnsConfiguration) {
          const probeId = randomBytes(16).toString('hex');
          active.dnsProbe = { ...dnsConfiguration, probeId, queryNames: ['a', 'b', 'c', 'd'].map(letter => `${letter}-${probeId}.${dnsConfiguration.queryDomain}`) };
        }
        // Only explicit UI context is allowed; controller/private runtime state never enters this page.
        return respond(res, 200, { schemaVersion: 1, binding: clone(active.binding), expiresAt: new Date(active.expiresAt).toISOString(),
          expectedExitIps: active.expectedExitIps, browser: active.browser, language: active.language, timezone: active.timezone, mock,
          workspaceId: active.workspaceId, identityRevision: active.identityRevision, expectedIdentity: clone(active.expectedIdentity), managedLaunchVerified: active.managedLaunchVerified,
          identityChecks: true,
          mode: text(additional?.mode, 32) ? additional.mode : null, sources: OBSERVATION_SOURCES,
          stun: 'stun:stun.cloudflare.com:3478', measurementMs: OBSERVATION_LIMITS.measurementMs,
          dnsProbe: active.dnsProbe ? { probeId: active.dnsProbe.probeId, queryNames: active.dnsProbe.queryNames, receiptUrl: `${active.dnsProbe.receiptOrigin}/v1/probes/${active.dnsProbe.probeId}` } : null });
      }
      if (req.method === 'GET' && resource === 'headers') {
        active.headerObservation = Object.fromEntries(HTTP_IDENTITY_HEADERS.filter(name => typeof req.headers[name] === 'string' && text(req.headers[name], 1024)).map(name => [name, req.headers[name]]));
        return respond(res, 200, { status: 'measured', headers: clone(active.headerObservation) });
      }
      if (req.method === 'GET' && resource === 'identity-frame') {
        res.writeHead(200, safeHeaders('text/html; charset=utf-8', true));
        return res.end('<!doctype html><html><head><meta charset="utf-8"><title>MC Proxy identity probe</title><script type="module" src="./browser-identity-probe.js"></script></head><body data-identity-probe="frame"></body></html>');
      }
      if (req.method === 'POST' && resource === 'report') {
        if (req.headers.origin !== origin || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) throw fail('OBSERVATION_ORIGIN_REJECTED', 403);
        if (+req.headers['content-length'] > OBSERVATION_LIMITS.bodyBytes) throw fail('OBSERVATION_REPORT_TOO_LARGE', 413);
        let bytes = 0; const chunks = [];
        for await (const chunk of req) { bytes += chunk.length; if (bytes > OBSERVATION_LIMITS.bodyBytes) throw fail('OBSERVATION_REPORT_TOO_LARGE', 413); chunks.push(chunk); }
        if (active !== session || !await current()) throw fail('OBSERVATION_SESSION_EXPIRED', 410);
        let input; try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw fail('OBSERVATION_REPORT_INVALID'); }
        report = normalizeBrowserObservation(input, active, { mock, now });
        return respond(res, 200, { saved: true, report: clone(report) });
      }
      const asset = resource === '' ? 'browser-observation.html' : resource;
      if (req.method !== 'GET' || !Object.hasOwn(ASSETS, asset)) throw fail('OBSERVATION_NOT_FOUND', 404);
      const body = await readFile(path.join(assetsRoot, asset));
      if (active !== session || !await current()) throw fail('OBSERVATION_SESSION_EXPIRED', 410);
      res.writeHead(200, safeHeaders(ASSETS[asset])); res.end(body);
    } catch (cause) { if (!res.headersSent && !res.destroyed) respond(res, cause.status || 500, { error: { code: cause.code || 'OBSERVATION_FAILED' } }); else res.end(); }
  }
  async function start() {
    if (closed) throw fail('OBSERVATION_CLOSED', 409);
    if (server) return;
    if (!starting) starting = (async () => {
      const instance = http.createServer((req, res) => { void handle(req, res); });
      instance.requestTimeout = 10000; instance.headersTimeout = 10000; instance.keepAliveTimeout = 1000;
      await new Promise((resolve, reject) => { instance.once('error', reject); instance.listen(0, '127.0.0.1', resolve); });
      server = instance; origin = `http://127.0.0.1:${instance.address().port}`;
    })();
    await starting;
  }
  return {
    async endpoint() { await start(); return { origin, port: new URL(origin).port * 1 }; },
    updateTarget(value) {
      if (closed) throw fail('OBSERVATION_CLOSED', 409);
      const next = identityTarget(value);
      if (JSON.stringify(next) !== JSON.stringify(target)) { session = null; report = null; }
      target = next; return clone(target);
    },
    async markManagedLaunch(value = {}) {
      const next = identityTarget(value), active = session;
      if (!active || closed || now() >= active.expiresAt || next.workspaceId !== active.workspaceId) throw fail('OBSERVATION_SESSION_CHANGED', 409);
      const attaching = active.identityRevision === null && active.managedLaunchVerified === false;
      if (!next.identityRevision || !attaching && next.identityRevision !== active.identityRevision
        || !attaching && value.expectedIdentity !== undefined && JSON.stringify(next.expectedIdentity) !== JSON.stringify(active.expectedIdentity)) throw fail('OBSERVATION_SESSION_CHANGED', 409);
      const candidate = { ...active, identityRevision: next.identityRevision, expectedIdentity: value.expectedIdentity === undefined ? active.expectedIdentity : next.expectedIdentity, managedLaunchVerified: true };
      if (!await isCurrent(clone(candidate.binding), targetContext(candidate)) || active !== session || now() >= active.expiresAt) throw fail('OBSERVATION_SESSION_CHANGED', 409);
      if (attaching) report = null;
      Object.assign(active, { identityRevision: candidate.identityRevision, expectedIdentity: candidate.expectedIdentity, managedLaunchVerified: true });
      target = { workspaceId: candidate.workspaceId, identityRevision: candidate.identityRevision, expectedIdentity: clone(candidate.expectedIdentity) };
      if (report) report.source.managedLaunchVerified = !mock;
      return { workspaceId: candidate.workspaceId, identityRevision: candidate.identityRevision, managedLaunchVerified: true };
    },
    async createSession(input = {}) {
      if (!keys(input, ['binding', 'expectedExitIps', 'browser', 'language', 'timezone', 'workspaceId', 'identityRevision', 'expectedIdentity'])) throw fail('OBSERVATION_CONTEXT_INVALID');
      const { binding, expectedExitIps, browser = 'unspecified', language = '', timezone = '', workspaceId = target.workspaceId, identityRevision = target.identityRevision, expectedIdentity = target.expectedIdentity } = input;
      const selected = identityTarget({ workspaceId, identityRevision, expectedIdentity });
      if (!validBinding(binding) || !Array.isArray(expectedExitIps) || !expectedExitIps.length || expectedExitIps.length > 16 || !expectedExitIps.every(ip => typeof ip === 'string' && isIP(ip))
        || !text(browser, 64) || !text(language, 64) || !text(timezone, 100)) throw fail('OBSERVATION_CONTEXT_INVALID');
      if (!await isCurrent(clone(binding), { ...targetContext(selected), managedLaunchVerified: false })) throw fail('OBSERVATION_SESSION_CHANGED', 409);
      await start();
      if (closed || !await isCurrent(clone(binding), { ...targetContext(selected), managedLaunchVerified: false })) throw fail('OBSERVATION_SESSION_CHANGED', 409);
      session = { token: randomBytes(24).toString('base64url'), binding: clone(binding), expectedExitIps: [...new Set(expectedExitIps)], browser, language, timezone, ...selected, managedLaunchVerified: false, headerObservation: null,
        createdAt: now(), expiresAt: now() + OBSERVATION_LIMITS.sessionMs };
      if (dnsConfiguration) {
        const probeId = randomBytes(16).toString('hex');
        session.dnsProbe = { ...dnsConfiguration, probeId, queryNames: ['a', 'b', 'c', 'd'].map(letter => `${letter}-${probeId}.${dnsConfiguration.queryDomain}`) };
      }
      report = null;
      return { url: `${origin}/s/${session.token}/`, token: session.token, expiresAt: new Date(session.expiresAt).toISOString(), status: 'waiting' };
    },
    snapshot() {
      const valid = session && !closed && now() < session.expiresAt && isCurrent(clone(session.binding), targetContext(session));
      if (valid && typeof valid.then === 'function') return { status: 'unverified', report: null, reason: 'OBSERVATION_CURRENT_CHECK_PENDING' };
      if (!valid) { session = null; report = null; return { status: 'unverified', report: null, reason: 'OBSERVATION_REQUIRED_OR_EXPIRED' }; }
      return { status: mock ? 'mocked' : report ? 'completed' : 'waiting', url: `${origin}/s/${session.token}/`, binding: clone(session.binding), ...targetContext(session), expiresAt: new Date(session.expiresAt).toISOString(), report: clone(report) };
    },
    async current() { if (!await current()) return { status: 'unverified', report: null }; return this.snapshot(); },
    invalidate() { session = null; report = null; },
    async close() { closed = true; session = null; report = null; if (starting) await starting; if (server) { await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); server = null; } },
  };
}
