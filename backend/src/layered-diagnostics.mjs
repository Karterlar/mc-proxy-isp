// Read-only interpretation of structured observations. A downstream timeout
// cannot identify the VPN or ISP without an independent upstream error code.
const explicitFailures = Object.freeze({
  RELAY_AUTH_FAILED: ['entry', '中转账号认证被拒绝，请核对中转账号状态。'],
  RELAY_DISABLED: ['entry', '中转账号已停用。'],
  RELAY_TLS_FAILED: ['entry', '中转证书核验失败；不要关闭证书验证。'],
  RELAY_TIMEOUT: ['entry', '中转入口超时，尚未确认 ISP 状态。'],
  RELAY_UNREACHABLE: ['entry', '中转入口不可达，尚未确认 ISP 状态。'],
  ISP_AUTH_REJECTED: ['isp', 'ISP 认证被拒绝，请核对套餐、密码及源 IP 白名单。'],
  ISP_CONNECT_REJECTED: ['isp', 'ISP 拒绝目标连接，请核对端口、协议和供应商限制。'],
  ISP_TIMEOUT: ['isp', '已定位 ISP 上游连接超时，请核对供应商状态。'],
  EXIT_IP_MISMATCH: ['isp', '观测出口与指定 ISP 不符，当前检测结果不能复用。'],
  SYSTEM_DNS_FAILED: ['system', '系统默认 DNS 解析失败；本地 HTTP 代理成功不证明系统路径成功。'],
  SYSTEM_EXIT_MISMATCH: ['system', '系统默认网络出口与指定 ISP 不符。'],
  SYSTEM_TLS_FAILED: ['system', '系统路径 TLS 连接失败；不能据此断定 ISP 已停用。'],
});
export function buildLayeredDiagnosis(status = {}, targetCheck = null) {
  const proxy = status.proxy || {}, mode = proxy.connectionMode || status.configuration?.connectionMode;
  const simulation = status.service?.mock === true;
  const chainReady = !simulation && proxy.running && proxy.managed && !proxy.requestedStop && proxy.exitStatus === 'verified';
  const layers = [
    { id: 'entry', label: mode === 'relay' ? '中转入口' : 'VPN 入口', status: simulation ? 'mocked' : chainReady ? 'configured' : 'unverified', detail: chainReady ? '完整受管链路已核验；入口本身的独立测速与账号有效期仍需相应证据。' : '入口尚无当前连通证据；不会自动切到直连。' },
    { id: 'isp', label: '指定 ISP 出口', status: simulation ? 'mocked' : chainReady ? 'verified' : 'unverified', detail: chainReady ? '受管核心的 HTTPS 出口与指定 ISP 匹配。' : '当前完整链路与 ISP 出口未核验。' },
    { id: 'system', label: '系统 TUN / DNS 路径', status: simulation ? 'mocked' : chainReady && proxy.mode === 'tun' && proxy.systemNetwork?.status === 'verified' ? 'verified' : 'unverified', detail: proxy.mode !== 'tun' ? '当前为应用代理模式，普通应用和既有浏览器路径须单独检查。' : chainReady && proxy.systemNetwork?.status === 'verified' ? '系统默认 DNS 与路由的 HTTPS 请求已到指定出口；完整 DNS 泄漏测试另列。' : 'TUN 配置状态不等于系统真实请求已通过。' },
    { id: 'browser', label: '真实浏览器 / WebRTC', status: 'unverified', detail: '需在被检查的真实窗口完成观测；后台 Node 探测不能代替浏览器读数。' },
    { id: 'target', label: '目标网站响应', status: 'unverified', detail: '尚未发起本次目标检测；出口匹配不代表账号登录或产品可用。' },
  ];
  const observation = status.browserObservation;
  if (observation?.status === 'completed' && Array.isArray(observation.report?.checks)) {
    const checks = observation.report.checks;
    const bad = checks.some(item => ['failed', 'mismatch'].includes(item.status));
    const incomplete = !chainReady || checks.length !== 10 || checks.some(item => !['verified'].includes(item.status));
    Object.assign(layers[3], { status: bad ? 'failed' : incomplete ? 'unverified' : 'verified', detail: bad ? '真实窗口观测存在失败或与目标不一致，请查看逐项结果。' : incomplete ? '部分浏览器读数已测；未执行或受策略限制的项目仍不能判为通过。' : '本次列出的浏览器观测项目已完成；结果仅属于该窗口与当前会话。' });
  } else if (observation?.status === 'stale') layers[3].detail = '旧浏览器观测已过期或路线改变，请在当前窗口重新检测。';
  if (simulation) layers[3].status = 'mocked';
  const failure = explicitFailures[status.lastError?.code];
  if (failure) Object.assign(layers.find(item => item.id === failure[0]), { status: 'failed', detail: failure[1], code: status.lastError.code });
  if (targetCheck && Array.isArray(targetCheck.checks)) {
    const rows = targetCheck.checks, restricted = rows.some(row => [403, 429].includes(row.targetHttpStatus || row.httpStatus));
    const reachable = rows.length > 0 && rows.every(row => row.transportReachable === true);
    Object.assign(layers[4], { status: simulation || targetCheck.status === 'mocked' ? 'mocked' : restricted ? 'restricted' : targetCheck.status === 'reachable' ? 'verified' : 'failed', detail: restricted ? '已收到网站 403/429 响应，传输已到目标；这不等于 VPN 或 ISP 断连。' : reachable ? '目标已有 HTTP 响应；业务账号、OAuth 与模型调用仍未测试。' : '目标连接未完成，单凭超时、EOF 或 TLS 错误无法独立区分 VPN 与 ISP，请查看分段错误。' });
  }
  const failed = layers.filter(row => row.status === 'failed').length;
  const restricted = layers.some(row => row.status === 'restricted');
  return { summary: simulation ? '模拟结果，尚未执行真实网络与浏览器测试。' : failed ? `有 ${failed} 层证据未通过；请从对应层排查。` : restricted ? '链路已收到网站限制响应，请检查目标网站状态。' : '按层查看当前证据；配置成功与真实观测分别记录。', layers };
}
