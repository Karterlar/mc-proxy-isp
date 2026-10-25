import { validateLicenseConfig } from '../backend/src/license-format.mjs';

// Build-time metadata lives in the app archive. Renderer requests, external
// JSON and launch flags cannot change a licensed edition's trust anchor.
export function distributionPolicy(distribution) {
  const edition = distribution?.edition === 'developer' ? 'developer' : 'licensed';
  const productName = edition === 'developer' ? 'MC Proxy Developer' : 'MC Proxy';
  let licenseConfig = { version: 1, mode: 'development' };
  if (edition === 'licensed') {
    try {
      licenseConfig = validateLicenseConfig(distribution?.licenseConfig);
      if (licenseConfig.mode !== 'required') throw new Error();
    } catch { licenseConfig = { version: 1, mode: 'required' }; }
  }
  return { edition, productName, mockAllowed: edition === 'developer', licenseConfig };
}

export function assertDistributionLaunch(policy, { argv = [], env = {} } = {}) {
  if (!policy.mockAllowed && (argv.includes('--mock') || argv.includes('--smoke-test') || env.PROXYPILOT_MOCK === '1')) {
    throw Object.assign(new Error('正式版不接受开发演示参数，请使用开发者版进行测试。'), { code: 'LICENSE_RELEASE_MOCK_UNAVAILABLE' });
  }
}
