import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { distributionPolicy, assertDistributionLaunch } from '../license-config.mjs';

test('developer edition stays completely unrestricted without a license trust anchor', () => {
  const policy = distributionPolicy({ edition: 'developer', licenseConfig: { mode: 'required' } });
  assert.equal(policy.productName, 'MC Proxy Developer'); assert.equal(policy.mockAllowed, true);
  assert.deepEqual(policy.licenseConfig, { version: 1, mode: 'development' });
  assert.doesNotThrow(() => assertDistributionLaunch(policy, { argv: ['--mock', '--smoke-test'] }));
});
test('licensed edition accepts only its embedded required HTTPS/public-key configuration', () => {
  const pair = generateKeyPairSync('ed25519');
  const config = { version: 1, mode: 'required', serviceUrl: 'https://license.example.test', publicKeys: { primary: pair.publicKey.export({ type: 'spki', format: 'pem' }) } };
  const policy = distributionPolicy({ edition: 'licensed', licenseConfig: config });
  assert.equal(policy.productName, 'MC Proxy'); assert.equal(policy.mockAllowed, false); assert.deepEqual(policy.licenseConfig, config);
  for (const invalid of [undefined, { version: 1, mode: 'development' }, { ...config, serviceUrl: 'http://license.example.test' }, { ...config, privateKey: 'PRIVATE' }]) {
    assert.deepEqual(distributionPolicy({ edition: 'licensed', licenseConfig: invalid }).licenseConfig, { version: 1, mode: 'required' });
  }
  assert.deepEqual(distributionPolicy(undefined).licenseConfig, { version: 1, mode: 'required' });
});
test('licensed launch flags and ambient mock environment cannot bypass authorization', () => {
  const policy = distributionPolicy({ edition: 'licensed' });
  for (const options of [{ argv: ['--mock'] }, { argv: ['--smoke-test'] }, { env: { PROXYPILOT_MOCK: '1' } }]) {
    assert.throws(() => assertDistributionLaunch(policy, options), { code: 'LICENSE_RELEASE_MOCK_UNAVAILABLE' });
  }
  assert.doesNotThrow(() => assertDistributionLaunch(policy, {}));
});
