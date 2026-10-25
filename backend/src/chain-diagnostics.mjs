import path from 'node:path';
import { isIP } from 'node:net';
import { X509Certificate, createHash } from 'node:crypto';
import { UserError, validHost } from './config.mjs';

const failureDescriptions = Object.freeze({
  PROVIDER_NOT_CONFIGURED: ['configuration', '填写有效 ISP 信息后重新保存并检测。'],
  RELAY_NOT_CONFIGURED: ['configuration', '导入正式中转配置后重新导出诊断包。'],
  RELAY_AUTH_REJECTED: ['relay-authentication', '中转账号被拒绝；检查中转授权，不要修改 ISP 密码碰运气。'],
  RELAY_CERTIFICATE_REJECTED: ['relay-tls', '中转证书、名称或有效期不匹配；核对正式配置与电脑时间，不要关闭证书校验。'],
  RELAY_UNREACHABLE: ['relay-connect', '确认中转服务、防火墙及当前网络可达；保留日志。'],
  RELAY_TIMEOUT: ['relay-connect', '中转连接超时；确认已关闭其他 VPN，再查看物理路由及服务器状态。'],
  ISP_AUTH_REJECTED: ['isp-authentication', '检查 ISP 账号、密码、套餐有效期及供应商的源 IP 白名单。'],
  ISP_CONNECT_REJECTED: ['isp-connect', '中转可达，但 ISP 拒绝目标连接；检查端口、协议及供应商限制。'],
  ISP_TIMEOUT: ['isp-connect', 'ISP 上游请求超时；核对服务器到 ISP 的连通性。'],
  CHAIN_CONNECT_REJECTED_UNKNOWN_STAGE: ['chain', '链路拒绝连接；此错误无法单独定位中转或 ISP 认证，请保留中转侧错误码。'],
  CHAIN_TIMEOUT: ['chain', '完整链路超时；先查看中转预检，再查看 ISP 配置和服务日志。'],
  LOCAL_PROXY_UNREACHABLE: ['local', '先在 MC Proxy 完成连接，再运行连接后诊断。'],
  EXIT_IP_MISMATCH: ['exit', '观察到的出口与保存的 ISP 出口不符；保持断网锁，检查动态出口或配置变更。'],
  CHAIN_UNKNOWN_FAILURE: ['unknown', '诊断信息不足；保留日志，不自动直连或解除断网锁。'],
});

// Classify structured evidence only. Never return arbitrary upstream messages,
// URLs, command lines or error objects: they may contain proxy credentials.
export function classifyChainFailure(error = {}, stage = '') {
  let code = error?.code;
  if (!Object.hasOwn(failureDescriptions, code)) {
    const httpStatus = Number(error?.statusCode);
    if (['RELAY_AUTH_FAILED', 'RELAY_DISABLED'].includes(code)) code = 'RELAY_AUTH_REJECTED';
    else if (code === 'RELAY_TLS_FAILED') code = 'RELAY_CERTIFICATE_REJECTED';
    else if (httpStatus === 407 && stage === 'relay') code = 'RELAY_AUTH_REJECTED';
    else if (httpStatus === 407 && stage === 'isp') code = 'ISP_AUTH_REJECTED';
    else if (['ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'CERT_SIGNATURE_FAILURE', 'ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED', 'RELAY_TLS_FAILED'].includes(code) && stage === 'relay') code = 'RELAY_CERTIFICATE_REJECTED';
    else if (['ETIMEDOUT', 'PROXY_TIMEOUT', 'PROBE_TIMEOUT'].includes(code)) code = stage === 'relay' ? 'RELAY_TIMEOUT' : stage === 'isp' ? 'ISP_TIMEOUT' : 'CHAIN_TIMEOUT';
    else if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND'].includes(code) && stage === 'relay') code = 'RELAY_UNREACHABLE';
    else if (code === 'PROXY_UNREACHABLE') code = 'LOCAL_PROXY_UNREACHABLE';
    else if (code === 'PROXY_CONNECT_REJECTED') code = stage === 'isp' ? 'ISP_CONNECT_REJECTED' : 'CHAIN_CONNECT_REJECTED_UNKNOWN_STAGE';
    else code = 'CHAIN_UNKNOWN_FAILURE';
  }
  const [failureStage, action] = failureDescriptions[code];
  return { code, stage: failureStage, action };
}

const safeAbsolutePath = (value, label) => {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\x00-\x1f\x7f]/.test(value)) throw new UserError('DIAGNOSTICS_INVALID', `${label} must be an absolute local path`);
  return path.resolve(value);
};

/** A portable, deliberately credential-free view of the CURRENT saved config.
 * No TLS certificate or password is written; the leaf DER SHA-256 pin is derived
 * from the very certificate consumed by the production core.
 */
export function createChainDiagnosticManifest({ config, corePath, runtimeRoot, appPath, lastFailure, now = () => new Date() } = {}) {
  const connectionMode = config?.connectionMode || 'relay';
  if (!['relay', 'vpn-compat', 'vpn-import'].includes(connectionMode)) throw new UserError('DIAGNOSTICS_INVALID', 'Unsupported connection mode');
  const vpnCompatibility = ['vpn-compat', 'vpn-import'].includes(connectionMode);
  const importedVpn = connectionMode === 'vpn-import';
  const vpnAction = importedVpn
    ? '在 MC Proxy 内选择已导入节点，重新检测 VPN → ISP 完整链路；无需运行外部 VPN。本离线 TUN 脚本不适用于导入线路。'
    : '保持外部 VPN 开启，在 MC Proxy 内重新检测完整 ISP 链路；TUN 离线脚本不验证 VPN 兼容模式。';
  let relay = null;
  if (!vpnCompatibility && config?.relay) {
    const entry = config.relay;
    if (!isIP(entry.host || '') || !Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535 || !validHost(entry.tls?.serverName) || !entry.tls?.enabled || typeof entry.tls?.certificate !== 'string') throw new UserError('DIAGNOSTICS_INVALID', 'The relay must have its current fixed IP and verified certificate');
    let certificate;
    try { certificate = new X509Certificate(entry.tls.certificate); }
    catch { throw new UserError('DIAGNOSTICS_INVALID', 'Cannot derive the relay certificate fingerprint'); }
    relay = { host: entry.host, port: entry.port, serverName: entry.tls.serverName, certificateSha256: createHash('sha256').update(certificate.raw).digest('hex').toUpperCase() };
  }
  const up = config?.upstream;
  const configured = !!up && validHost(up.host) && Number.isInteger(up.port) && up.port > 0 && up.port <= 65535 && ['http', 'socks'].includes(up.type) && ['none', 'password'].includes(up.auth);
  const selectedCore = safeAbsolutePath(corePath, 'corePath');
  const selectedRoot = safeAbsolutePath(runtimeRoot, 'runtimeRoot');
  const selectedApp = safeAbsolutePath(appPath, 'appPath');
  if (selectedApp && path.extname(selectedApp).toLowerCase() !== '.exe') throw new UserError('DIAGNOSTICS_INVALID', 'Recovery app must be an executable');
  const proxyPort = config?.listen?.port;
  const expectedExitIps = config?.probe?.expectedExitIps;
  return {
    version: 1, brand: 'MC Proxy', createdAt: now().toISOString(), connectionMode, relay,
    isp: configured ? { configured: true, type: up.type, host: up.host, port: up.port, authentication: up.auth } : { configured: false },
    localProxy: { host: '127.0.0.1', port: Number.isInteger(proxyPort) && proxyPort >= 1024 && proxyPort <= 65535 ? proxyPort : null },
    runtime: { corePath: selectedCore, expectedCoreVersion: '1.14.2', transportMode: vpnCompatibility ? 'http' : 'tun', wintunPath: null, wintunDelivery: vpnCompatibility ? 'not-applicable' : 'embedded-in-core', runtimeRoot: selectedRoot },
    recovery: { appPath: selectedApp, firewallDirectory: selectedRoot ? path.join(selectedRoot, '.network-lock') : null, automaticUnlock: false },
    expectedExitIps: Array.isArray(expectedExitIps) ? expectedExitIps.filter(ip => typeof ip === 'string' && isIP(ip)) : [],
    checks: { timeoutMs: 7000 },
    lastFailure: lastFailure ? { ...classifyChainFailure(lastFailure, lastFailure.stage), ...(vpnCompatibility ? { action: vpnAction } : {}), historical: true } : null,
    limitations: ['Preflight never changes routes, firewall, environment, VPN state, or credentials.', 'Service HTTPS reachability is not account login or product availability.', ...(vpnCompatibility ? [
      importedVpn ? 'The app establishes the imported VPN to ISP chain. No external VPN is required. Use MC Proxy network detection; these offline TUN checks do not apply.' : 'Keep the external VPN enabled. Use MC Proxy to detect and verify the ISP path; these offline TUN checks do not apply.',
      'Only applications configured to use the local HTTP proxy are covered; system-wide traffic is not verified.',
      ...(importedVpn ? ['Imported node credentials, endpoints and raw YAML are excluded from this bundle.'] : []),
      'Export again after changing ISP, connection mode, or installation path.',
    ] : ['Export again after changing ISP, relay, certificate, or installation path.'])],
  };
}
