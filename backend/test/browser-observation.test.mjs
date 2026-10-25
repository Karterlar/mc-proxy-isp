import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createBrowserObservation, normalizeBrowserObservation, OBSERVATION_SOURCES, validateDnsObservationConfig } from '../src/browser-observation.mjs';
import { classifyIceCandidate, observeWebRtc, runBrowserObservation, observeDns } from '../../frontend/browser-observation.js';

const binding = { revision: 3, configHash: 'configuration-fixture', exitBinding: 'exit-fixture' };
const session = { binding, expectedExitIps: ['203.0.113.8'], browser: 'chrome', language: 'en-US', timezone: 'Asia/Tokyo' };
function fixture() {
  return { schemaVersion: 1, binding: { ...binding }, elapsedMs: 500, browser: { userAgent: 'Fixture Chromium', language: 'en-US', languages: ['en-US', 'en'], timezone: 'Asia/Tokyo', platform: 'Win32',
    viewport: { width: 1000, height: 800, screenWidth: 1920, screenHeight: 1080, pixelRatio: 1 }, permissions: [{ name: 'geolocation', state: 'denied' }], uaCh: { status: 'unverified' } },
    checks: { https: [{ id: 'ipify-v4', status: 'measured', ip: '203.0.113.8', elapsedMs: 100 }, { id: 'cloudflare', status: 'measured', ip: '203.0.113.8', elapsedMs: 101 }],
      ipv6: { id: 'ipify-v6', status: 'failed', elapsedMs: 102, errorCode: 'NETWORK_CORS_OR_RESPONSE_FAILED' },
      webrtc: { status: 'measured', complete: true, counts: { public: 0, unexpectedPublic: 0, private: 0, mdns: 0, relay: 0 } },
      dns: { status: 'unverified', reason: 'CONTROLLED_DNS_TEST_NOT_CONFIGURED' }, canvas: { status: 'unverified', reason: 'OPTIONAL_TEST_NOT_SELECTED' } } };
}
const reportRequest = (url, body, headers = {}) => fetch(`${url}report`, { method: 'POST', headers: { Origin: new URL(url).origin, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('browser reports keep configured targets separate and never manufacture DNS, IPv6 or no-ICE passes', () => {
  const result = normalizeBrowserObservation(fixture(), session);
  assert.equal(result.summary.httpsExpectedMatch, true);
  assert.equal(result.summary.authority, 'diagnostic-only');
  assert.equal(result.source.managedIdentityVerified, false);
  for (const id of ['dns', 'ipv6', 'webrtc']) assert.equal(result.checks.find(row => row.id === id).status, 'unverified');
  assert.equal(result.measurements.webrtc.status, 'unverified');
  assert.equal(result.checks.find(row => row.id === 'language').status, 'verified');
  const wrong = fixture(); wrong.browser.timezone = 'Asia/Shanghai';
  assert.equal(normalizeBrowserObservation(wrong, session).checks.find(row => row.id === 'timezone').status, 'mismatch');
  const mock = normalizeBrowserObservation(fixture(), session, { mock: true });
  assert.equal(mock.summary.httpsExpectedMatch, false); assert.equal(mock.source.kind, 'fixture');
  assert.equal(mock.checks.find(row => row.id === 'https-exit').status, 'mocked');
});

test('unexpected public addresses are redacted, IPv6 mismatch is retained, and ICE raw addresses/schema spoofing are refused', () => {
  const input = fixture(); input.checks.https[0].ip = '203.0.113.99';
  input.checks.ipv6 = { id: 'ipify-v6', status: 'measured', elapsedMs: 30, ip: '2001:db8::23' };
  input.checks.webrtc.counts = { public: 1, unexpectedPublic: 1, private: 1, mdns: 1, relay: 0 };
  const result = normalizeBrowserObservation(input, session);
  assert.doesNotMatch(JSON.stringify(result), /203\.0\.113\.99|2001:db8::23/);
  assert.equal(result.summary.status, 'mismatch'); assert.equal(result.checks.find(row => row.id === 'webrtc').status, 'mismatch');
  const raw = fixture(); raw.checks.webrtc.addresses = ['203.0.113.99']; assert.throws(() => normalizeBrowserObservation(raw, session));
  const dns = fixture(); dns.checks.dns.status = 'verified'; assert.throws(() => normalizeBrowserObservation(dns, session));
  const old = fixture(); old.binding.revision--; assert.throws(() => normalizeBrowserObservation(old, session));
  const scope = fixture(); scope.secret = 'private-value'; assert.throws(() => normalizeBrowserObservation(scope, session));
});

test('primary language must match the target and all regional mismatches reach the summary', () => {
  const input = fixture(); input.browser.language = 'zh-CN'; input.browser.languages = ['zh-CN', 'en-US'];
  let result = normalizeBrowserObservation(input, session);
  assert.equal(result.checks.find(row => row.id === 'language').status, 'mismatch');
  assert.equal(result.summary.status, 'mismatch');
  input.browser.language = 'EN-us'; input.browser.languages = ['en-US', 'zh-CN'];
  assert.equal(normalizeBrowserObservation(input, session).checks.find(row => row.id === 'language').status, 'verified');
  input.browser.languages = ['zh-CN', 'en-US'];
  assert.equal(normalizeBrowserObservation(input, session).checks.find(row => row.id === 'language').status, 'mismatch');
  input.browser.languages = ['en-US'];
  assert.equal(normalizeBrowserObservation(input, { ...session, language: 'en' }).checks.find(row => row.id === 'language').status, 'verified');
  assert.equal(normalizeBrowserObservation(input, { ...session, language: 'en-GB' }).checks.find(row => row.id === 'language').status, 'mismatch');
  input.browser.language = 'iw-IL'; input.browser.languages = ['he-IL'];
  assert.equal(normalizeBrowserObservation(input, { ...session, language: 'he-IL' }).checks.find(row => row.id === 'language').status, 'verified');
  input.browser.language = 'en-US'; input.browser.languages = ['en-US']; input.browser.timezone = 'Asia/Shanghai';
  result = normalizeBrowserObservation(input, session);
  assert.equal(result.checks.find(row => row.id === 'timezone').status, 'mismatch');
  assert.equal(result.summary.status, 'mismatch');
});

test('real localhost service enforces Host/Origin/token/CSP/body/binding and discards replaced/expired sessions', async t => {
  let clock = Date.now(), revision = 3;
  const manager = createBrowserObservation({ now: () => clock, isCurrent: value => value.revision === revision, getContext: () => ({ mode: 'tun', credentials: 'PRIVATE_CREDENTIAL' }) });
  t.after(() => manager.close());
  const first = await manager.createSession(session);
  assert.match(first.url, /^http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]{32}\/$/);
  assert.equal(manager.snapshot().status, 'waiting');
  const page = await fetch(first.url); assert.equal(page.status, 200);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff'); assert.equal(page.headers.get('cache-control'), 'no-store');
  const wrongHost = await new Promise((resolve, reject) => http.get(first.url, { headers: { Host: 'attacker.example' } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject));
  assert.equal(wrongHost, 403);
  assert.equal((await fetch(`${first.url}context`, { headers: { Origin: 'https://attacker.example' } })).status, 403);
  const context = await (await fetch(`${first.url}context`)).json(); assert.equal(context.mode, 'tun'); assert.doesNotMatch(JSON.stringify(context), /PRIVATE_CREDENTIAL/);
  assert.equal((await reportRequest(first.url, fixture(), { Origin: 'https://attacker.example' })).status, 403);
  assert.equal((await reportRequest(first.url, { data: 'x'.repeat(33000) })).status, 413);
  const invalid = fixture(); invalid.binding.configHash = 'old'; assert.equal((await reportRequest(first.url, invalid)).status, 400);
  const receipt = await reportRequest(first.url, fixture()); assert.equal(receipt.status, 200); assert.equal((await receipt.json()).saved, true);
  assert.equal(manager.snapshot().status, 'completed');
  const next = await manager.createSession(session); assert.equal(manager.snapshot().report, null);
  assert.equal((await fetch(first.url)).status, 404);
  revision++; assert.equal(manager.snapshot().status, 'unverified'); assert.equal((await fetch(next.url)).status, 410);
  revision = 3; const expires = await manager.createSession(session); clock += 300001;
  assert.equal((await fetch(expires.url)).status, 410); assert.equal(manager.snapshot().report, null);
});

test('ICE classification distinguishes local/mDNS/public addresses; no candidates remains unverified and peer closes', async () => {
  const candidate = (ip, type = 'host') => `candidate:1 1 udp 100 ${ip} 50000 typ ${type}`;
  assert.equal(classifyIceCandidate(candidate('192.168.1.1')).kind, 'private');
  assert.equal(classifyIceCandidate(candidate('test.local')).kind, 'mdns');
  assert.equal(classifyIceCandidate(candidate('::ffff:192.168.1.2')).kind, 'private');
  assert.equal(classifyIceCandidate(candidate('::1')).kind, 'private');
  assert.equal(classifyIceCandidate(candidate('::2')).kind, 'public');
  assert.equal(classifyIceCandidate(candidate('203.0.113.8'), session.expectedExitIps).unexpected, false);
  assert.equal(classifyIceCandidate(candidate('203.0.113.99'), session.expectedExitIps).unexpected, true);
  let closed = 0;
  const rtcFactory = () => ({ createDataChannel() {}, createOffer: async () => ({}), setLocalDescription() { queueMicrotask(() => this.onicecandidate({ candidate: null })); }, close() { closed++; } });
  const result = await observeWebRtc({ rtcFactory }); assert.equal(result.report.status, 'unverified'); assert.equal(result.report.complete, true); assert.equal(closed, 1);
});

test('browser measurement uses its own fixed HTTPS path, returns failures without direct fallback and only submits ICE counts', async () => {
  const calls = [], context = { ...session, sources: OBSERVATION_SOURCES, measurementMs: 45000, stun: 'stun:stun.cloudflare.com:3478' };
  const nav = { userAgent: 'Fixture Chromium', language: 'en-US', languages: ['en-US'], platform: 'Win32', permissions: { query: async () => ({ state: 'prompt' }) } };
  const win = { innerWidth: 1000, innerHeight: 800, screen: { width: 1920, height: 1080 }, devicePixelRatio: 1 };
  const rtcFactory = () => ({ createDataChannel() {}, createOffer: async () => ({}), setLocalDescription() { queueMicrotask(() => { this.onicecandidate({ candidate: { candidate: 'candidate:1 1 udp 100 203.0.113.99 50000 typ srflx' } }); this.onicecandidate({ candidate: null }); }); }, close() {} });
  const result = await runBrowserObservation({ context, navigator: nav, window: win, rtcFactory, fetch: async (url, options) => {
    calls.push(url); assert.equal(options.credentials, 'omit'); assert.equal(options.mode, 'cors'); assert.equal(options.referrerPolicy, 'no-referrer');
    if (url.includes('api6')) throw new Error('IPv6 unavailable');
    return { ok: true, text: async () => url.includes('cloudflare') ? 'ip=203.0.113.8\nloc=JP\n' : '{"ip":"203.0.113.8"}' };
  } });
  assert.equal(calls.length, 3); assert.equal(result.report.checks.ipv6.status, 'failed');
  assert.equal(result.report.checks.dns.status, 'unverified'); assert.equal(result.report.checks.webrtc.counts.unexpectedPublic, 1);
  assert.doesNotMatch(JSON.stringify(result.report), /203\.0\.113\.99/); assert.match(JSON.stringify(result.localReadings), /203\.0\.113\.99/);
  assert.equal(normalizeBrowserObservation(result.report, session).summary.status, 'mismatch');
});

test('controlled DNS protocol issues unique browser queries, matches authority receipt and rejects stale/incomplete/unapproved evidence', async t => {
  const dnsProbe = { queryDomain: 'probe.example.com', receiptOrigin: 'https://receipt.example.com', allowedResolvers: ['1.1.1.0/24'] };
  assert.equal(validateDnsObservationConfig(dnsProbe).receiptOrigin, dnsProbe.receiptOrigin);
  for (const bad of [{ ...dnsProbe, receiptOrigin: 'http://receipt.example.com' }, { ...dnsProbe, receiptOrigin: 'https://127.0.0.1' }, { ...dnsProbe, queryDomain: 'localhost' }, { ...dnsProbe, allowedResolvers: ['1.1.1.0/33'] }]) assert.throws(() => validateDnsObservationConfig(bad));
  const manager = createBrowserObservation({ dnsProbe }); t.after(() => manager.close());
  const open = await manager.createSession(session);
  const context = await (await fetch(`${open.url}context`)).json();
  assert.match(context.dnsProbe.probeId, /^[a-f0-9]{32}$/); assert.equal(new Set(context.dnsProbe.queryNames).size, 4);
  const seen = [], receipt = { version: 1, probeId: context.dnsProbe.probeId, complete: true, queries: context.dnsProbe.queryNames.map(name => ({ name, resolverIps: ['1.1.1.1'] })) };
  const good = await observeDns(context.dnsProbe, { fetch: async (url, options) => {
    seen.push(url); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
    if (url.endsWith('/mc-dns-probe')) { assert.equal(options.mode, 'cors'); return {}; }
    assert.equal(options.mode, 'cors'); return { ok: true, status: 200, text: async () => JSON.stringify(receipt) };
  }, wait: async () => {} });
  assert.equal(seen.length, 5); assert.equal(good.report.complete, true); assert.deepEqual(good.report.resolverIps, ['1.1.1.1']);
  const input = fixture(); input.checks.dns = good.report;
  const saved = await reportRequest(open.url, input); assert.equal(saved.status, 200);
  const result = await saved.json(); assert.equal(result.report.summary.dnsVerified, true); assert.equal(result.report.checks.find(row => row.id === 'dns').status, 'verified');
  const contextNext = await (await fetch(`${open.url}context`)).json(); assert.notEqual(contextNext.dnsProbe.probeId, context.dnsProbe.probeId);
  assert.equal(manager.snapshot().status, 'waiting'); assert.equal(manager.snapshot().report, null);
  assert.equal((await reportRequest(open.url, input)).status, 400);
  const stale = await observeDns(context.dnsProbe, { fetch: async url => ({ ok: true, status: 200, text: async () => JSON.stringify({ ...receipt, probeId: 'a'.repeat(32) }) }), wait: async () => {} });
  assert.equal(stale.report.status, 'failed');
  const diagnosticSession = { ...session, dnsProbe: { ...dnsProbe, probeId: context.dnsProbe.probeId } };
  const incomplete = fixture(); incomplete.checks.dns = { ...good.report, complete: false, queries: 1 };
  assert.equal(normalizeBrowserObservation(incomplete, diagnosticSession).summary.dnsVerified, false);
  const mismatch = fixture(); mismatch.checks.dns = { ...good.report, resolverIps: ['114.114.114.114'] };
  const mismatched = normalizeBrowserObservation(mismatch, diagnosticSession); assert.equal(mismatched.checks.find(row => row.id === 'dns').status, 'mismatch');
  assert.doesNotMatch(JSON.stringify(mismatched), /114\.114\.114\.114/);
  const noPolicy = normalizeBrowserObservation(input, { ...diagnosticSession, dnsProbe: { ...diagnosticSession.dnsProbe, allowedResolvers: [] } });
  assert.equal(noPolicy.summary.dnsVerified, false); assert.equal(noPolicy.measurements.dns.measured, true);
});

test('UA and canvas values are measured, never promoted to verified solely because collection succeeds', () => {
  const input = fixture(); input.browser.uaCh = { status: 'measured', platform: 'Windows', platformVersion: '19.0.0' };
  input.checks.canvas = { status: 'measured', hash: 'a'.repeat(64), repeatHash: 'a'.repeat(64) };
  const result = normalizeBrowserObservation(input, session);
  assert.equal(result.checks.find(check => check.id === 'ua-ch').status, 'measured');
  assert.equal(result.checks.find(check => check.id === 'canvas').status, 'measured');
  assert.equal(result.checks.find(check => check.id === 'identity-http').status, 'unverified');
  assert.equal(result.checks.find(check => check.id === 'identity-target').status, 'unverified');
  input.checks.canvas.repeatHash = 'b'.repeat(64);
  assert.equal(normalizeBrowserObservation(input, session).checks.find(check => check.id === 'canvas').status, 'mismatch');
  input.checks.canvas.repeatHash = 'not-a-digest'; assert.throws(() => normalizeBrowserObservation(input, session), { code: 'OBSERVATION_REPORT_INVALID' });
});

test('identity target and service port persist across invalidation while HTTP evidence is recorded by the server only', async t => {
  const workspaceId = 'd5003344-ea48-48c1-843e-a82b0870f565', revision = 'a'.repeat(64), expectedIdentity = { platform: 'windows', platformVersion: '19.0.0', cores: 8, engineVersion: '150.0.7871.186', nativeGraphics: false, seed: 777123456 };
  let active = { workspaceId, identityRevision: revision };
  const manager = createBrowserObservation({ isCurrent: (_, context) => !context.managedLaunchVerified || context.workspaceId === active.workspaceId && context.identityRevision === active.identityRevision });
  t.after(() => manager.close());
  const endpoint = await manager.endpoint(); assert.equal(typeof endpoint.port, 'number');
  manager.updateTarget({ workspaceId, identityRevision: revision, expectedIdentity });
  const open = await manager.createSession(session);
  const context = await (await fetch(`${open.url}context`)).json();
  assert.equal(context.workspaceId, workspaceId); assert.equal(context.identityRevision, revision); assert.equal(context.identityChecks, true);
  assert.doesNotMatch(JSON.stringify(context), /777123456|"seed"/);
  await manager.markManagedLaunch({ workspaceId, identityRevision: revision });
  const response = await fetch(`${open.url}headers`, { headers: { 'User-Agent': 'Actual request UA', 'Accept-Language': 'en-US', 'Device-Memory': '32', 'Sec-CH-Device-Memory': '32', Cookie: 'private-session', Authorization: 'private-auth', 'X-Ignore': 'private-extra' } });
  assert.equal(response.headers.get('accept-ch'), 'Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Device-Memory, Sec-CH-Device-Memory');
  assert.equal((await response.json()).headers['user-agent'], 'Actual request UA');
  const input = fixture(); const saved = await (await reportRequest(open.url, input)).json();
  assert.equal(saved.report.source.managedIdentityVerified, false); assert.equal(saved.report.source.managedLaunchVerified, true);
  assert.equal(saved.report.source.workspaceId, workspaceId); assert.equal(saved.report.measurements.consistency.headers['user-agent'], 'Actual request UA');
  assert.equal(saved.report.measurements.consistency.headers['device-memory'], '32');
  assert.equal(saved.report.measurements.consistency.headers['sec-ch-device-memory'], '32');
  assert.doesNotMatch(JSON.stringify(saved), /private-session|private-auth|private-extra|777123456|"seed"/);
  assert.equal(saved.report.checks.find(check => check.id === 'identity-http').status, 'mismatch');
  const forged = fixture(); forged.checks.consistency = { version: 1, contexts: {}, headers: { 'user-agent': 'forged' } };
  assert.equal((await reportRequest(open.url, forged)).status, 400);
  const frame = await fetch(`${open.url}identity-frame`); assert.equal(frame.status, 200);
  assert.match(frame.headers.get('content-security-policy'), /frame-ancestors 'self'/);
  assert.match(frame.headers.get('content-security-policy'), /worker-src 'self'/);
  assert.equal((await fetch(`${open.url}identity-frame`, { headers: { Origin: 'https://external.example' } })).status, 403);
  active = { ...active, identityRevision: 'b'.repeat(64) };
  assert.equal(manager.snapshot().report, null); assert.equal((await fetch(open.url)).status, 410);
  manager.invalidate(); assert.deepEqual(await manager.endpoint(), endpoint);
});

test('page memory is optional for old reports, validated for new reports, and retained through collection', async () => {
  assert.doesNotThrow(() => normalizeBrowserObservation(fixture(), session));
  const input = fixture(); input.browser.deviceMemory = 32;
  assert.equal(normalizeBrowserObservation(input, session).browser.deviceMemory, 32);
  input.browser.deviceMemory = 16;
  const mismatch = normalizeBrowserObservation(input, { ...session, headerObservation: { 'sec-ch-device-memory': '32' } });
  assert.equal(mismatch.checks.find(check => check.id === 'identity-http').status, 'mismatch');
  assert.equal(mismatch.summary.status, 'mismatch');
  for (const value of [0, -1, 1025, null, '32']) { input.browser.deviceMemory = value; assert.throws(() => normalizeBrowserObservation(input, session), { code: 'OBSERVATION_REPORT_INVALID' }); }
  const context = { ...session, sources: OBSERVATION_SOURCES, measurementMs: 45000, stun: 'stun:stun.cloudflare.com:3478' };
  const nav = { userAgent: 'Fixture Chromium', language: 'en-US', languages: ['en-US'], platform: 'Win32', deviceMemory: 32 };
  const win = { innerWidth: 1000, innerHeight: 800 };
  const result = await runBrowserObservation({ context, navigator: nav, window: win, rtcFactory: () => { throw Error('unsupported'); }, fetch: async () => { throw Error('offline'); } });
  assert.equal(result.report.browser.deviceMemory, 32);
});

test('first launch can bind an unbound session once and stale or changed targets reject reports', async t => {
  const workspaceId = 'd5003344-ea48-48c1-843e-a82b0870f565', identityRevision = 'a'.repeat(64), expectedIdentity = { platform: 'windows', platformVersion: '19.0.0', cores: 8, engineVersion: '150.0.7871.186', nativeGraphics: false };
  let currentRevision = null;
  const manager = createBrowserObservation({ isCurrent: (_, target) => !target.managedLaunchVerified || target.identityRevision === currentRevision }); t.after(() => manager.close());
  const first = await manager.createSession({ ...session, workspaceId, identityRevision: null });
  await reportRequest(first.url, fixture()); assert.equal(manager.snapshot().status, 'completed');
  currentRevision = identityRevision;
  await manager.markManagedLaunch({ workspaceId, identityRevision, expectedIdentity });
  assert.equal(manager.snapshot().report, null); assert.equal(manager.snapshot().identityRevision, identityRevision);
  assert.equal((await fetch(first.url)).status, 200);
  await assert.rejects(manager.markManagedLaunch({ workspaceId, identityRevision: 'b'.repeat(64) }), { code: 'OBSERVATION_SESSION_CHANGED' });
  manager.updateTarget({ workspaceId, identityRevision: 'b'.repeat(64), expectedIdentity });
  assert.equal((await fetch(first.url)).status, 410);
  for (const invalid of [{ workspaceId: '../other' }, { identityRevision: 'bad' }, { expectedIdentity: { ...expectedIdentity, engineVersion: 'mocked' } }, { expectedIdentity: { ...expectedIdentity, credentials: 'secret' } }]) assert.throws(() => manager.updateTarget(invalid), { code: 'OBSERVATION_CONTEXT_INVALID' });
  await assert.rejects(manager.createSession({ ...session, secret: 'unexpected' }), { code: 'OBSERVATION_CONTEXT_INVALID' });
});
