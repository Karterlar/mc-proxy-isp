import test from 'node:test';
import assert from 'node:assert/strict';
import { browserConsistencyChecks, normalizeConsistencyInput } from '../src/browser-consistency.mjs';
import { collectIdentitySurface } from '../../frontend/browser-identity-probe.js';

const expectedIdentity = { platform: 'windows', platformVersion: '19.0.0', cores: 8, engineVersion: '150.0.7871.186', nativeGraphics: false };
const surface = () => ({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36', language: 'en-US', languages: ['en-US', 'en'], timezone: 'Asia/Tokyo', platform: 'Win32', hardwareConcurrency: 8, deviceMemory: 32,
  uaCh: { status: 'measured', platform: 'Windows', platformVersion: '19.0.0', architecture: 'x86', bitness: '64', mobile: false, brands: [{ brand: 'Chromium', version: '150.0.7871.186' }, { brand: 'Not=A?Brand', version: '24.0.0.0' }] } });
function fixture() {
  const main = surface(), browser = { ...main, viewport: { width: 1000, height: 800, screenWidth: 1920, screenHeight: 1080, pixelRatio: 1 } };
  const input = { version: 1, contexts: { iframe: { status: 'measured', surface: { ...surface(), screen: { width: 1920, height: 1080, pixelRatio: 1 } } }, dedicatedWorker: { status: 'measured', surface: surface() }, sharedWorker: { status: 'measured', surface: surface() } } };
  const headers = { 'user-agent': main.userAgent, 'accept-language': 'en-US,en;q=0.9', 'sec-ch-ua-platform': '"Windows"', 'sec-ch-ua-platform-version': '"19.0.0"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-full-version-list': '"Not=A?Brand";v="24.0.0.0", "Chromium";v="150.0.7871.186"', 'sec-ch-device-memory': '32' };
  return { input, browser, headers, expectedIdentity };
}

test('matching values only pass when their cross-context or expected-target evidence is present', () => {
  const values = fixture(), result = browserConsistencyChecks(values);
  assert.equal(result.checks.length, 6); assert.ok(result.checks.every(check => check.status === 'verified'));
  const absent = browserConsistencyChecks({ browser: values.browser });
  assert.ok(absent.checks.every(check => check.status === 'unverified'));
  const partial = fixture(); delete partial.headers['sec-ch-ua-platform-version'];
  partial.input.contexts.sharedWorker = { status: 'unverified', reason: 'CONTEXT_API_UNSUPPORTED' };
  const incomplete = browserConsistencyChecks(partial);
  assert.equal(incomplete.checks.find(check => check.id === 'identity-http').status, 'unverified');
  assert.equal(incomplete.checks.find(check => check.id === 'identity-sharedWorker').status, 'unverified');
  assert.ok(browserConsistencyChecks({ ...values, mock: true }).checks.every(check => check.status === 'mocked'));
});

test('native platform contract, HTTP headers, Worker and screen contradictions remain visible', () => {
  const values = fixture(); values.input.contexts.dedicatedWorker.surface.hardwareConcurrency = 16;
  values.input.contexts.sharedWorker.surface.uaCh.platformVersion = '18.0.0';
  values.input.contexts.iframe.surface.screen.pixelRatio = 2;
  values.headers['user-agent'] = 'Different browser';
  values.browser.uaCh.platformVersion = '10.0.26200';
  const result = browserConsistencyChecks(values);
  for (const id of ['identity-dedicatedWorker', 'identity-sharedWorker', 'identity-http', 'identity-target', 'identity-screen']) assert.equal(result.checks.find(check => check.id === id).status, 'mismatch', id);
  assert.match(result.checks.find(check => check.id === 'identity-target').detail, /平台版本/);
});

test('unsupported and forged schemas cannot be silently promoted to matching observations', () => {
  for (const mutate of [value => value.secret = 'not allowed', value => value.contexts.extra = {}, value => value.contexts.iframe.status = 'verified', value => value.contexts.iframe.surface.cookies = 'private', value => value.contexts.iframe.surface.hardwareConcurrency = -1, value => value.contexts.dedicatedWorker.surface.uaCh.extra = true, value => value.contexts.sharedWorker = { status: 'unverified', surface: surface() }]) {
    const input = fixture().input; mutate(input);
    assert.throws(() => normalizeConsistencyInput(input), { code: 'OBSERVATION_REPORT_INVALID' });
  }
  const values = fixture(); values.browser.hardwareConcurrency = 0;
  assert.equal(browserConsistencyChecks(values).checks.find(check => check.id === 'identity-target').status, 'unverified');
  assert.equal(browserConsistencyChecks(values).checks.find(check => check.id === 'identity-dedicatedWorker').status, 'unverified');
});

test('device memory is compared with every measured context and both Client Hint header generations', () => {
  for (const header of ['device-memory', 'sec-ch-device-memory']) {
    const values = fixture(); delete values.headers['sec-ch-device-memory']; values.headers[header] = '32';
    assert.equal(browserConsistencyChecks(values).checks.find(check => check.id === 'identity-http').status, 'verified');
    values.headers[header] = '16';
    const mismatch = browserConsistencyChecks(values).checks.find(check => check.id === 'identity-http');
    assert.equal(mismatch.status, 'mismatch'); assert.ok(mismatch.detail.includes(header));
  }
  const values = fixture(); values.headers['device-memory'] = '16';
  assert.equal(browserConsistencyChecks(values).checks.find(check => check.id === 'identity-http').status, 'mismatch', 'legacy and current hints cannot contradict each other unnoticed');
  for (const name of ['iframe', 'dedicatedWorker', 'sharedWorker']) {
    const inconsistent = fixture(); inconsistent.input.contexts[name].surface.deviceMemory = 16;
    const check = browserConsistencyChecks(inconsistent).checks.find(item => item.id === `identity-${name}`);
    assert.equal(check.status, 'mismatch'); assert.match(check.detail, /deviceMemory/);
  }
});

test('legacy and unsupported memory observations remain accepted but unverified; invalid values are rejected', async () => {
  const values = fixture(); delete values.browser.deviceMemory; delete values.headers['sec-ch-device-memory'];
  for (const entry of Object.values(values.input.contexts)) delete entry.surface.deviceMemory;
  assert.doesNotThrow(() => normalizeConsistencyInput(values.input));
  const result = browserConsistencyChecks(values);
  for (const id of ['identity-iframe', 'identity-dedicatedWorker', 'identity-sharedWorker', 'identity-http']) assert.equal(result.checks.find(check => check.id === id).status, 'unverified');
  for (const invalid of [0, -1, 1025, Infinity, NaN, '32', null]) {
    const invalidInput = fixture().input; invalidInput.contexts.iframe.surface.deviceMemory = invalid;
    assert.throws(() => normalizeConsistencyInput(invalidInput), { code: 'OBSERVATION_REPORT_INVALID' });
  }
  const nav = { ...surface(), userAgentData: undefined };
  assert.equal((await collectIdentitySurface({ navigator: nav })).deviceMemory, 32);
  delete nav.deviceMemory;
  assert.equal(Object.hasOwn(await collectIdentitySurface({ navigator: nav }), 'deviceMemory'), false, 'unsupported APIs never become a manufactured zero');
});
