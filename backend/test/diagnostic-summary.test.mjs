import test from 'node:test';
import assert from 'node:assert/strict';
import { createDiagnosticShareSummary } from '../src/diagnostic-summary.mjs';
import { sanitizeSetupDiagnostic } from '../src/setup-diagnostic.mjs';

test('setup diagnostics retain only fixed failure stages and native categories', () => {
  const privateFields = { message: 'PRIVATE_MESSAGE', stack: 'PRIVATE_STACK', path: 'PRIVATE_PATH', syscall: 'PRIVATE_COMMAND', password: 'PRIVATE_PASSWORD' };
  assert.deepEqual(sanitizeSetupDiagnostic({ setupStage: 'starting-proxy', nativeCode: 'EACCES', nativeError: 'TypeError', ...privateFields }),
    { setupStage: 'starting-proxy', nativeCode: 'EACCES', nativeError: 'TypeError' });
  for (const nativeError of ['Error', 'TypeError', 'ReferenceError', 'SyntaxError', 'RangeError', 'AggregateError', 'EvalError', 'URIError']) {
    assert.deepEqual(sanitizeSetupDiagnostic({ nativeError, ...privateFields }), { nativeError });
  }
  assert.deepEqual(sanitizeSetupDiagnostic({ nativeCode: 'ERR_INVALID_ARG_TYPE' }), { nativeCode: 'ERR_INVALID_ARG_TYPE' });
  for (const value of [null, undefined, {}, { setupStage: 'PRIVATE_STAGE', nativeCode: 'PRIVATE_CODE', nativeError: 'PRIVATE_ERROR', ...privateFields }]) {
    assert.equal(sanitizeSetupDiagnostic(value), null);
  }
});

test('share preview preserves setup failure evidence and rejects arbitrary native exception data', () => {
  for (const code of ['OUTPUT_UNAVAILABLE', 'SETUP_VERIFICATION_FAILED']) {
    for (const stage of ['checking-isp', 'starting-core', 'recovering-proxy']) {
      const summary = createDiagnosticShareSummary({ status: { phase: 'error', lastError: { code, stage, message: 'PRIVATE_ERROR', diagnostic: {
        setupStage: 'recovering-proxy', nativeCode: 'EPERM', nativeError: 'Error', path: 'PRIVATE_PATH', stack: 'PRIVATE_STACK', url: 'https://PRIVATE_HOST/',
      } } } });
      assert.equal(summary.code, code); assert.equal(summary.stage, stage);
      assert.deepEqual(summary.diagnostic, { setupStage: 'recovering-proxy', nativeCode: 'EPERM', nativeError: 'Error' });
      assert.doesNotMatch(JSON.stringify(summary), /PRIVATE|path|stack|https:/);
    }
  }
  const summary = createDiagnosticShareSummary({ status: { lastError: { code: 'SETUP_VERIFICATION_FAILED', diagnostic: {
    setupStage: 'PRIVATE_STAGE', nativeCode: 'PRIVATE_CODE', nativeError: 'PRIVATE_ERROR', message: 'PRIVATE_MESSAGE',
  } } } });
  assert.equal(summary.diagnostic, undefined); assert.doesNotMatch(JSON.stringify(summary), /PRIVATE/);
});

test('share preview retains useful failure and counts while omitting all recovery identity and secrets', () => {
  const summary = createDiagnosticShareSummary({ version: '1.3.3', status: {
    service: { mock: false }, phase: 'failed', operation: { stage: 'locking-network', message: 'PRIVATE_MESSAGE' },
    configuration: { connectionMode: 'vpn-import', upstream: { host: 'PRIVATE_HOST', username: 'PRIVATE_USERNAME', password: 'PRIVATE_PASSWORD' } },
    proxy: { mode: 'tun', endpoint: '127.0.0.1:17890', exitStatus: 'verified', exitIp: '203.0.113.8', corePath: 'C:\\PRIVATE_PATH\\core.exe', systemNetwork: { status: 'verified', ip: '203.0.113.8' } },
    networkLock: { state: 'recovery-required', allowedEndpoint: { ip: '192.0.2.1' } },
    lastError: { code: 'NETWORK_LOCK_TIMEOUT', message: 'PRIVATE_ERROR', operation: 'PRIVATE_STAGE', diagnostic: { commandLine: 'PRIVATE_COMMAND' } },
    applicationProxy: { isp: 7, local: 2, failed: 1, url: 'http://PRIVATE_USER:PRIVATE_PASS@PRIVATE_HOST/', capacity: { activeConnections: 3, pendingRequests: 1 } },
    vpnConfig: { id: 'PRIVATE_ID', supported: 43, unsupported: 2, nodes: [{ name: 'PRIVATE_NAME', index: 1 }] },
    vpnLatency: { candidateCount: 43, tested: 3, verifiedEligible: 2, results: [{ nodeIndex: 1, latencyMs: 18, host: 'PRIVATE_HOST' }] },
  } });
  assert.equal(summary.code, 'NETWORK_LOCK_TIMEOUT'); assert.equal(summary.stage, 'locking-network');
  assert.equal(summary.connectionMode, 'vpn-import'); assert.equal(summary.transportMode, 'tun');
  assert.deepEqual(summary.counts, { ispRequests: 7, localRequests: 2, failedRequests: 1, activeConnections: 3, activeRequests: 0, pendingRequests: 1,
    importedSupported: 43, importedUnsupported: 2, candidates: 43, tested: 3, verified: 2 });
  assert.doesNotMatch(JSON.stringify(summary), /PRIVATE|203\.0|192\.0|127\.0|:\/\/|corePath|username|password|nodeIndex|latencyMs/);
});

test('unknown strings are not a covert channel through version, stage, code or enums', () => {
  const summary = createDiagnosticShareSummary({ version: '1.3.3-PRIVATE_SECRET', status: {
    phase: 'PRIVATE_PHASE', lastError: { code: 'PRIVATE_CODE' }, configuration: { connectionMode: 'PRIVATE_MODE' },
    proxy: { mode: 'PRIVATE_TRANSPORT', exitStatus: 'PRIVATE_EXIT', systemNetwork: { status: 'PRIVATE_NETWORK' } },
    networkLock: { state: 'PRIVATE_LOCK' }, applicationProxy: { isp: '999', local: -1, failed: Infinity, capacity: { activeConnections: 2 ** 40 } },
  } });
  assert.equal(summary.version, 'unknown'); assert.equal(summary.stage, 'unknown'); assert.equal(summary.code, 'OPERATION_FAILED');
  assert.equal(summary.counts.ispRequests, 0); assert.equal(summary.counts.localRequests, 0); assert.equal(summary.counts.failedRequests, 0);
  assert.equal(summary.counts.activeConnections, 1_000_000); assert.doesNotMatch(JSON.stringify(summary), /PRIVATE/);
});

test('gateway failures and simulation are explicit and absent errors stay absent', () => {
  const summary = createDiagnosticShareSummary({ version: '1.3.3', status: { service: { mock: true }, phase: 'ready',
    applicationProxy: { lastFailure: { code: 'APPLICATION_PROXY_OVERLOADED', at: 'PRIVATE_AT', target: 'PRIVATE_TARGET' } } } });
  assert.equal(summary.simulation, true); assert.equal(summary.code, 'APPLICATION_PROXY_OVERLOADED');
  assert.equal(createDiagnosticShareSummary().code, null);
  assert.equal(createDiagnosticShareSummary({ status: null }).stage, 'unknown');
  assert.equal(createDiagnosticShareSummary({ status: { phase: 'error', lastError: { code: 'NETWORK_RECHECK_REQUIRED', stage: 'verifying-network-change' } } }).stage, 'verifying-network-change');
});

test('browser evidence exports only fixed result enums and never the session identity or fingerprint', () => {
  const summary = createDiagnosticShareSummary({ status: {
    browser: { browser: 'fingerprint', profile: 'PRIVATE_PROFILE', seed: 'PRIVATE_SEED' },
    browserOptions: [{ id: 'fingerprint', runtime: { state: 'ready', verified: true, executable: 'PRIVATE_PATH' } }],
    fingerprintInstall: { status: 'failed', failedStage: 'extracting', code: 'PRIVATE_CODE', message: 'PRIVATE_ERROR' },
    browserObservation: { status: 'completed', url: 'http://127.0.0.1:45678/s/PRIVATE_TOKEN/', binding: { configHash: 'PRIVATE_HASH' }, report: {
      source: { kind: 'browser-self-report' }, browser: { userAgent: 'PRIVATE_UA' }, expectedExitIps: ['203.0.113.8'],
      checks: [{ id: 'https-exit', status: 'verified', value: '203.0.113.8' }, { id: 'webrtc', status: 'mismatch', value: 'PRIVATE_PUBLIC_IP' },
        { id: 'dns', status: 'PRIVATE_STATE' }, { id: 'PRIVATE_ID', status: 'PRIVATE_STATE' }],
    } },
  } });
  assert.equal(summary.browser.selected, 'fingerprint'); assert.equal(summary.browser.engineVerified, true);
  assert.equal(summary.browser.installation.failedStage, 'extracting'); assert.equal(summary.browser.installation.code, 'FINGERPRINT_ENGINE_INSTALL_FAILED');
  assert.equal(summary.browser.checks['https-exit'], 'verified'); assert.equal(summary.browser.checks.webrtc, 'mismatch');
  assert.equal(summary.browser.checks.dns, 'unverified'); assert.equal(Object.keys(summary.browser.checks).length, 10);
  assert.doesNotMatch(JSON.stringify(summary), /PRIVATE|203\.0|127\.0|:\/\/|userAgent|profile|seed|configHash/);
});
