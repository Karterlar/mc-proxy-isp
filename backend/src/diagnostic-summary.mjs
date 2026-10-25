import { sanitizeSetupDiagnostic } from './setup-diagnostic.mjs';

const modes = ['relay', 'vpn-compat', 'vpn-import'];
const stages = new Set(['idle', 'offline', 'starting', 'stopping', 'error', 'connecting', 'connected', 'disconnecting', 'failed', 'checking', 'ready',
  'checking-firewall', 'backing-up-firewall', 'locking-network', 'starting-core', 'checking-core', 'verifying-exit',
  'verifying-system-network', 'checking-environment', 'adopting-current-environment', 'optimizing-environment',
  'detecting-network', 'screening-imported-nodes', 'checking-imported-node', 'checking-isp', 'recovering-proxy', 'saving-isp', 'checking-quality',
  'repairing-network', 'starting-application', 'stopping-core', 'restoring-environment', 'screening', 'verifying', 'verifying-network-change']);
const codes = new Set([
  'NETWORK_LOCK_TIMEOUT', 'NETWORK_LOCK_WINDOWS_FAILED', 'NETWORK_LOCK_INSPECTION_FAILED', 'NETWORK_LOCK_RECOVERY_REQUIRED',
  'NETWORK_LOCK_RESTORE_FAILED', 'NETWORK_LOCK_VERIFY_FAILED', 'NETWORK_LOCK_CONFLICT', 'NETWORK_LOCK_STATE_INVALID',
  'NETWORK_LOCK_BACKUP_INVALID', 'PROCESS_UNREADABLE', 'PROCESS_IDENTITY_MISMATCH', 'CORE_NOT_FOUND', 'CORE_NOT_READY',
  'CORE_CHECK_FAILED', 'CORE_START_FAILED', 'CORE_STOP_FAILED', 'CORE_EXITED', 'PROXY_NOT_RUNNING', 'PROXY_UNREACHABLE',
  'FAKE_IP_CACHE_UNAVAILABLE', 'FAKEIP_CACHE_RECOVERY_REQUIRED', 'CORE_CONSOLE_START_FAILED', 'CORE_CONSOLE_CLOSE_FAILED',
  'CORE_CONSOLE_CLOSE_TIMEOUT', 'CORE_CONSOLE_IDENTITY_FAILED', 'CORE_CONSOLE_UNAVAILABLE', 'CORE_CONSOLE_NOT_PRIVATE',
  'PROXY_CONNECT_REJECTED', 'PROXY_TIMEOUT', 'PROXY_CLOSED', 'PROXY_RESPONSE_INVALID', 'TUN_NOT_READY', 'TUN_STATE_UNAVAILABLE',
  'DNS_CACHE_CLEAR_FAILED', 'SYSTEM_DNS_FAILED', 'SYSTEM_NETWORK_TIMEOUT', 'SYSTEM_NETWORK_UNREACHABLE',
  'SYSTEM_TLS_FAILED', 'SYSTEM_EXIT_MISMATCH', 'SYSTEM_RESPONSE_INVALID', 'SYSTEM_HTTP_STATUS', 'EXIT_IP_MISMATCH',
  'MULTI_EXIT_MISMATCH', 'VPN_IMPORT_NO_ROUTE', 'VPN_IMPORT_CONFIGURATION_CHANGED', 'VPN_COMPAT_NO_ROUTE',
  'GLOBAL_VPN_CONFLICT', 'GLOBAL_VPN_CHECK_FAILED', 'SETUP_CHECK_FAILED', 'SETUP_EXIT_MISMATCH', 'SETUP_PROXY_STOP_FAILED',
  'OUTPUT_UNAVAILABLE', 'SETUP_VERIFICATION_FAILED',
  'RELAY_AUTH_FAILED', 'RELAY_TLS_FAILED', 'RELAY_TIMEOUT', 'RELAY_UNREACHABLE', 'ISP_AUTH_REJECTED', 'ISP_CONNECT_REJECTED',
  'ISP_TIMEOUT', 'CHAIN_TIMEOUT', 'CHAIN_UNKNOWN_FAILURE', 'APPLICATION_LEASE_INVALID', 'APPLICATION_PROXY_RECURSION',
  'APPLICATION_PRIVATE_DNS_FAILED', 'APPLICATION_PROXY_TIMEOUT', 'APPLICATION_PROXY_OVERLOADED',
  'APPLICATION_RESPONSE_TIMEOUT', 'APPLICATION_CONNECT_FAILED', 'APPLICATION_TARGETS_FAILED', 'APPLICATION_TARGETS_REACHABLE',
  'ENVIRONMENT_PERMISSION_DENIED', 'ENVIRONMENT_TIMEOUT', 'ENVIRONMENT_WINDOWS_FAILED', 'ENVIRONMENT_CONFLICT',
  'ENVIRONMENT_RESTORE_REQUIRED', 'ENVIRONMENT_VERIFY_FAILED', 'ENVIRONMENT_PARTIAL', 'ENVIRONMENT_DAILY_REQUIRED', 'ENVIRONMENT_PROFILE_INVALID', 'ENVIRONMENT_PROFILE_FOREIGN', 'ENVIRONMENT_PROFILE_CONFLICT', 'SERVICE_UNAVAILABLE', 'SERVICE_REPAIRING', 'NETWORK_RECHECK_REQUIRED', 'MOCKED',
  'BROWSER_FINGERPRINT_NOT_INSTALLED', 'BROWSER_FINGERPRINT_BUNDLE_REQUIRED', 'BROWSER_FINGERPRINT_BINARY_CHANGED', 'BROWSER_FINGERPRINT_FILES_CHANGED',
  'BROWSER_FINGERPRINT_INVENTORY_INVALID', 'BROWSER_FINGERPRINT_PLATFORM_UNSUPPORTED', 'BROWSER_FINGERPRINT_ARCH_INVALID',
  'BROWSER_FINGERPRINT_SEED_INVALID', 'BROWSER_FINGERPRINT_SEED_CHANGED', 'BROWSER_FINGERPRINT_STATE_INVALID',
  'BROWSER_FINGERPRINT_FRESH_ROTATION_UNSUPPORTED', 'FINGERPRINT_ENGINE_INSTALL_FAILED', 'BROWSER_FINGERPRINT_INSTALL_FAILED', 'BROWSER_FINGERPRINT_INSTALL_CANCELLED',
  'OBSERVATION_CONTEXT_INVALID', 'OBSERVATION_SESSION_CHANGED', 'OBSERVATION_SESSION_EXPIRED',
]);
const count = value => Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 1_000_000) : 0;
const select = (value, allowed, fallback) => allowed.includes(value) ? value : fallback;

// This is a shareable preview, separate from private recovery manifests. Never
// spread an input object or include arbitrary error messages, identifiers or URLs.
export function createDiagnosticShareSummary({ version, status = {} } = {}) {
  if (!status || typeof status !== 'object' || Array.isArray(status)) status = {};
  const proxy = status.proxy || {}, gateway = status.applicationProxy || {}, latency = status.vpnLatency || {};
  const observation = status.browserObservation || {}, report = observation.report || {};
  const fingerprint = (Array.isArray(status.browserOptions) ? status.browserOptions : []).find(item => item?.id === 'fingerprint')?.runtime || {};
  const evidenceStatus = value => select(value, ['verified', 'mismatch', 'failed', 'unverified', 'unsupported', 'configured', 'mocked', 'stale'], 'unverified');
  const last = status.lastError || gateway.lastFailure;
  const stage = status.operation?.stage || last?.stage || status.phase;
  const setupDiagnostic = sanitizeSetupDiagnostic(last?.diagnostic);
  return {
    schemaVersion: 1, product: 'MC Proxy',
    version: typeof version === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(version) ? version : 'unknown',
    simulation: status.service?.mock === true,
    connectionMode: select(proxy.connectionMode || status.configuration?.connectionMode, modes, 'unknown'),
    transportMode: select(proxy.mode, ['http', 'tun'], 'unknown'),
    routingMode: select(proxy.routingMode, ['safe-rules', 'global'], 'not-applicable'),
    stage: stages.has(stage) ? stage : 'unknown',
    code: !last ? null : codes.has(last.code) ? last.code : 'OPERATION_FAILED',
    ...(setupDiagnostic ? { diagnostic: setupDiagnostic } : {}),
    exitStatus: select(proxy.exitStatus || status.exitStatus, ['verified', 'unverified', 'mocked'], 'unverified'),
    systemNetwork: select(proxy.systemNetwork?.status, ['verified', 'unverified', 'not-applicable', 'offline', 'mocked'], 'unverified'),
    networkLock: select(status.networkLock?.state, ['locked', 'unlocked', 'recovery-required', 'locking', 'unlocking'], 'unknown'),
    browser: {
      selected: select(status.browser?.browser, ['chrome', 'edge', 'fingerprint'], 'none'),
      fingerprintEngine: select(fingerprint.state, ['ready', 'missing', 'invalid', 'unsupported', 'unavailable'], 'unknown'),
      engineVerified: fingerprint.verified === true,
      installation: {
        status: select(status.fingerprintInstall?.status, ['idle', 'downloading', 'verifying', 'extracting', 'copying-bundle', 'installed', 'failed'], 'unknown'),
        failedStage: select(status.fingerprintInstall?.failedStage, ['downloading', 'verifying', 'extracting', 'copying-bundle'], 'none'),
        code: !status.fingerprintInstall?.code ? null : codes.has(status.fingerprintInstall.code) ? status.fingerprintInstall.code : 'FINGERPRINT_ENGINE_INSTALL_FAILED',
      },
      observation: select(observation.status, ['waiting', 'completed', 'unverified', 'mocked', 'stale', 'failed'], 'unverified'),
      source: select(report.source?.kind, ['browser-self-report', 'fixture'], 'none'),
      // Only bounded result enums are shareable. Raw UA, IP, ICE candidates,
      // URLs, profile paths and seed values stay out of this preview.
      checks: Object.fromEntries(['https-exit', 'language', 'timezone', 'ipv6', 'webrtc', 'dns', 'permissions', 'viewport', 'ua-ch', 'canvas']
        .map(id => [id, evidenceStatus((Array.isArray(report.checks) ? report.checks : []).find(row => row?.id === id)?.status)])),
    },
    counts: {
      ispRequests: count(gateway.isp), localRequests: count(gateway.local), failedRequests: count(gateway.failed),
      activeConnections: count(gateway.capacity?.activeConnections), activeRequests: count(gateway.capacity?.activeRequests), pendingRequests: count(gateway.capacity?.pendingRequests),
      importedSupported: count(status.vpnConfig?.supported), importedUnsupported: count(status.vpnConfig?.unsupported),
      candidates: count(latency.candidateCount), tested: count(latency.tested), verified: count(latency.verifiedEligible),
    },
  };
}
