import test from 'node:test';
import assert from 'node:assert/strict';
import { buildLayeredDiagnosis } from '../src/layered-diagnostics.mjs';
const connected = { proxy: { running: true, managed: true, mode: 'tun', connectionMode: 'vpn-import', exitStatus: 'verified', systemNetwork: { status: 'verified' } } };
test('website rejection is separated from the verified ISP and cannot diagnose a VPN subscription', () => {
  const result = buildLayeredDiagnosis(connected, { status: 'failed', checks: [{ httpStatus: 403, transportReachable: true }] });
  assert.equal(result.layers.find(x => x.id === 'isp').status, 'verified');
  assert.equal(result.layers.find(x => x.id === 'target').status, 'restricted');
  assert.equal(result.layers.find(x => x.id === 'entry').status, 'configured');
  assert.ok(!JSON.stringify(result).includes('已到期'));
});
test('ambiguous timeout never becomes an ISP authentication or VPN failure', () => {
  const result = buildLayeredDiagnosis({ ...connected, lastError: { code: 'PROXY_TIMEOUT', message: 'private-password' } }, { status: 'failed', checks: [{ code: 'PROBE_TLS_OR_SOCKET_FAILED' }] });
  assert.equal(result.layers.find(x => x.id === 'isp').status, 'verified');
  assert.ok(!JSON.stringify(result).includes('private-password'));
});
test('only explicit structured upstream evidence marks ISP authentication failed', () => {
  const result = buildLayeredDiagnosis({ ...connected, lastError: { code: 'ISP_AUTH_REJECTED' } });
  assert.equal(result.layers.find(x => x.id === 'isp').code, 'ISP_AUTH_REJECTED');
});
test('configured WebRTC and unmeasured DNS cannot produce a verified browser layer', () => {
  const result = buildLayeredDiagnosis({ ...connected, browserObservation: { status: 'completed', report: { checks: [{ status: 'verified' }, { status: 'configured' }, { status: 'unverified' }] } } });
  assert.equal(result.layers.find(x => x.id === 'browser').status, 'unverified');
  assert.equal(buildLayeredDiagnosis({ ...connected, browserObservation: { status: 'stale' } }).layers.find(x => x.id === 'browser').status, 'unverified');
  assert.equal(buildLayeredDiagnosis({ ...connected, browserObservation: { status: 'completed', report: { checks: [] } } }).layers.find(x => x.id === 'browser').status, 'unverified');
  assert.equal(buildLayeredDiagnosis({ proxy: { ...connected.proxy, requestedStop: true } }).layers.find(x => x.id === 'system').status, 'unverified');
});
