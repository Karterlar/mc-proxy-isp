import test from 'node:test';
import assert from 'node:assert/strict';
import { createNetworkReport, parseIpResponse, IP_SOURCES, requestExitGeography, verifiedExitGeography } from '../src/network-report.mjs';

const input = { exit: { id: 'exit-ip', status: 'verified', exitIp: '203.0.113.8' }, expectedExitIps: ['203.0.113.8'], proxyPort: 17890 };
const good = async (url, options) => {
  assert.equal(options.proxyPort, 17890);
  if (url.hostname === 'api.ipify.org') return '{"ip":"203.0.113.8"}';
  if (url.hostname === 'www.cloudflare.com') return 'ip=203.0.113.8\nloc=JP\n';
  if (url.hostname === 'ipwho.is') return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', city: 'Tokyo', timezone: { id: 'Asia/Tokyo' } });
  assert.equal(options.method, 'HEAD'); return { statusCode: 302, body: '' };
};
test('multiple independent IP responses produce consensus and country/city timezone evidence', async () => {
  const result = await createNetworkReport({ ...input, request: good });
  assert.equal(result.summary.status, 'pass'); assert.equal(result.summary.consistent, true);
  assert.equal(result.geo.city, 'Tokyo'); assert.equal(result.geo.timezone, 'Asia/Tokyo');
  assert.equal(result.geo.verified, true); assert.equal(result.results.length, 7);
});
test('exit mismatches fail the report even when expected allowlist contains both IPs', async () => {
  const result = await createNetworkReport({ ...input, expectedExitIps: ['203.0.113.8', '203.0.113.9'], request: (url, options) => url.hostname === 'api.ipify.org' ? '{"ip":"203.0.113.9"}' : good(url, options) });
  assert.equal(result.summary.status, 'fail'); assert.equal(result.summary.consistent, false);
});
test('failed geolocation and restricted websites do not invent location or full success', async () => {
  const result = await createNetworkReport({ ...input, request: (url, options) => url.hostname === 'ipwho.is' ? '{"success":false}' : options.method === 'HEAD' ? { statusCode: 403 } : good(url, options) });
  assert.equal(result.summary.status, 'partial'); assert.equal(result.summary.consistent, true); assert.equal(result.geo, null);
});

test('reports distinguish CONNECT rejection, TLS failure and actual target HTTP 500 without returning private response data', async () => {
  const result = await createNetworkReport({ ...input, request: async (url, options) => {
    if (url.hostname === 'cleanip.io') throw Object.assign(new Error('PRIVATE_CONNECT_BODY'), { code: 'PROXY_CONNECT_REJECTED', diagnostic: { httpStatus: 502, targetHttpStatus: 500, token: 'PRIVATE_TOKEN' } });
    if (url.hostname === 'ippure.com') throw Object.assign(new Error('PRIVATE_CERT_DETAIL'), { code: 'PROBE_TLS_OR_SOCKET_FAILED', diagnostic: { httpStatus: 500, stage: 'target-response' } });
    if (url.hostname === 'ping0.cc') return { statusCode: 500, body: 'PRIVATE_TARGET_RESPONSE' };
    return good(url, options);
  } });
  const [connect, tls, target] = ['cleanip', 'ippure', 'ping0'].map(id => result.results.find(row => row.id === id));
  assert.equal(result.summary.status, 'partial'); assert.equal(result.summary.consistent, true);
  assert.equal(connect.errorCode, 'PROXY_CONNECT_REJECTED'); assert.equal(connect.stage, 'proxy-connect'); assert.equal(connect.connectHttpStatus, 502);
  assert.equal(connect.targetHttpStatus, undefined); assert.equal(connect.transportReachable, false);
  assert.equal(tls.errorCode, 'PROBE_TLS_OR_SOCKET_FAILED'); assert.equal(tls.stage, 'tls'); assert.equal(tls.targetHttpStatus, undefined);
  assert.equal(target.stage, 'target-response'); assert.equal(target.targetHttpStatus, 500); assert.equal(target.httpStatus, 500); assert.equal(target.transportReachable, true);
  assert.equal(target.status, 'restricted');
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_|token|CERT_DETAIL/);
});

test('report unknown and invalid statuses remain generic rather than inventing target HTTP evidence', async () => {
  const result = await createNetworkReport({ ...input, request: async (url, options) => {
    if (url.hostname === 'cleanip.io') throw Object.assign(new Error('PRIVATE_UNKNOWN'), { code: 'PRIVATE_CODE', diagnostic: { stage: 'target-response', targetHttpStatus: 500 } });
    if (url.hostname === 'ippure.com') return { statusCode: '500', body: 'PRIVATE_RESPONSE' };
    return good(url, options);
  } });
  for (const id of ['cleanip', 'ippure']) {
    const row = result.results.find(item => item.id === id);
    assert.equal(row.status, 'failed'); assert.equal(row.errorCode, 'SITE_UNREACHABLE_OR_INVALID');
    assert.equal(row.stage, undefined); assert.equal(row.targetHttpStatus, undefined);
  }
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_/);
});

test('an invalid exit payload or received HTTP error retains established TLS transport without claiming a valid IP', async () => {
  const result = await createNetworkReport({ ...input, includeSites: false, request: async (url, options) => {
    if (url.hostname === 'api.ipify.org') return '{"ip":"PRIVATE_INVALID_IP"}';
    if (url.hostname === 'ipwho.is') throw Object.assign(new Error('PRIVATE_HTTP_BODY'), { code: 'PROBE_HTTP_STATUS', diagnostic: { stage: 'target-response', targetHttpStatus: 500 } });
    return good(url, options);
  } });
  for (const [id, targetHttpStatus] of [['ipify', 200], ['ipwhois', 500]]) {
    const row = result.results.find(item => item.id === id);
    assert.equal(row.status, 'failed'); assert.equal(row.stage, 'target-response');
    assert.equal(row.transportReachable, true); assert.equal(row.targetHttpStatus, targetHttpStatus); assert.equal(row.exitIp, undefined);
  }
  assert.equal(result.summary.status, 'partial'); assert.equal(result.summary.consistent, false);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_/);
});
test('mock report never networks or emits real location', async () => {
  const result = await createNetworkReport({ ...input, mock: true, request: () => assert.fail() });
  assert.equal(result.summary.status, 'mocked'); assert.equal(result.geo, null); assert.equal(result.summary.consistent, false);
});
test('malformed IP and cancelled report are rejected', async () => {
  assert.throws(() => parseIpResponse(IP_SOURCES[0], '{"ip":"not-ip"}'));
  await assert.rejects(createNetworkReport({ ...input, request: good, assertCurrent: () => { throw new Error('stopped'); } }), /stopped/);
});

test('environment geography requests only fixed IPWhois through the verified local proxy and validates matching IP/country/timezone', async () => {
  const calls = [];
  const result = await requestExitGeography({ exitIp: input.exit.exitIp, expectedExitIps: input.expectedExitIps, proxyPort: input.proxyPort,
    request: async (url, options) => { calls.push([url.href, options]); return good(url, options); } });
  assert.deepEqual(calls, [['https://ipwho.is/', { proxyPort: 17890, timeoutMs: 10000 }]]);
  assert.equal(result.verified, true); assert.equal(result.countryCode, 'JP'); assert.equal(result.timezone, 'Asia/Tokyo');
  assert.equal(verifiedExitGeography(result, input.exit.exitIp, input.expectedExitIps), true);
  assert.equal(verifiedExitGeography({ ...result, timezone: 'Planet/Unknown' }, input.exit.exitIp, input.expectedExitIps), false);
});

test('missing, mismatched, invalid and failed geography stays redacted without fallback or website requests', async () => {
  const valid = { success: true, ip: input.exit.exitIp, country_code: 'JP', city: 'PRIVATE_CITY', timezone: { id: 'Asia/Tokyo' } };
  const bodies = ['PRIVATE_RESPONSE', '{}', JSON.stringify({ ...valid, success: false }), JSON.stringify({ ...valid, ip: '203.0.113.9' }),
    JSON.stringify({ ...valid, country_code: null }), JSON.stringify({ ...valid, country_code: 'private-country' }), JSON.stringify({ ...valid, timezone: { id: 'Planet/Unknown' } }), JSON.stringify({ ...valid, timezone: null })];
  for (const body of bodies) {
    let calls = 0;
    await assert.rejects(requestExitGeography({ exitIp: input.exit.exitIp, expectedExitIps: input.expectedExitIps, proxyPort: input.proxyPort,
      request: async url => { calls++; assert.equal(url.hostname, 'ipwho.is'); return body; } }), cause => cause.code === 'GEO_UNVERIFIED' && !/PRIVATE_|203\.0\.113\./.test(cause.message));
    assert.equal(calls, 1);
  }
  await assert.rejects(requestExitGeography({ exitIp: input.exit.exitIp, expectedExitIps: input.expectedExitIps, proxyPort: input.proxyPort,
    request: async () => { throw new Error('PRIVATE_TRANSPORT_ERROR'); } }), cause => cause.code === 'GEO_UNVERIFIED' && !cause.message.includes('PRIVATE_TRANSPORT_ERROR'));
  await assert.rejects(requestExitGeography({ exitIp: input.exit.exitIp, expectedExitIps: [], proxyPort: input.proxyPort, request: () => assert.fail('unpinned exit must not request') }), { code: 'GEO_UNVERIFIED' });
});

test('late geography never absorbs a changed session into a generic geo error', async () => {
  let current = true;
  await assert.rejects(requestExitGeography({ exitIp: input.exit.exitIp, expectedExitIps: input.expectedExitIps, proxyPort: input.proxyPort,
    request: async (url, options) => { current = false; return good(url, options); },
    assertCurrent: () => { if (!current) throw Object.assign(new Error('session stopped'), { code: 'SESSION_CHANGED' }); } }), { code: 'SESSION_CHANGED' });
});
