// Derive presentation from the controller's current state. A listening proxy,
// a saved report, or a reachable website alone is not a verified connection.
import { browserLabels } from './browser-tools.js';
import { environmentDiagnosticText, environmentVerificationView } from './environment-feedback.js';
export const sessionPreferenceDefaults = { autoOptimize: true, browser: 'chrome', fresh: false, fingerprintFresh: false, externalReport: false, takeoverMode: 'global', relayRoutingMode: 'global' };

// Fingerprint region settings have their own saved form. Preference snapshots
// must not write a stale copy after that form changes the current store.
export const sessionPreferencePayload = values => Object.fromEntries(Object.entries(values).filter(([key]) => !['fingerprintLanguage','fingerprintTimezone','fingerprintNativeGraphics'].includes(key)));

// Write complete snapshots in order: a later successful edit also retries any
// earlier failed edit. Refreshes never replace local edits that are not saved.
export function createPreferenceWriter({ request, onSaved = () => {}, onState = () => {} }) {
  let values = { ...sessionPreferenceDefaults }, revision = 0, savedRevision = 0, tail = Promise.resolve();
  return {
    values: () => ({ ...values }),
    hydrate(saved = {}) {
      if (revision === 0) values = { ...sessionPreferenceDefaults, ...saved };
      return { ...values };
    },
    write(changes, { completed = false } = {}) {
      values = { ...values, ...changes };
      const snapshot = { ...values }, current = ++revision;
      onState('saving');
      const write = tail.catch(() => {}).then(() => request({ ...snapshot, ...(completed ? { completed: true } : {}) }));
      tail = write.then(result => {
        savedRevision = current;
        onSaved(result, snapshot);
        if (current === revision) onState('saved');
        return result;
      }, error => {
        if (current === revision) onState('failed', error);
        throw error;
      });
      return tail;
    },
    flush: () => tail,
    dirty: () => revision !== savedRevision,
  };
}

export function preferredTakeoverMode(source, preferences = sessionPreferenceDefaults) {
  if (source === 'vpn-compat') return 'application';
  if (source === 'vpn-import') return ['global', 'smart', 'application'].includes(preferences.takeoverMode) ? preferences.takeoverMode : 'global';
  return ['global', 'smart'].includes(preferences.relayRoutingMode) ? preferences.relayRoutingMode : 'global';
}

export function connectionReady(status, connected = true) {
  const proxy = status?.proxy || {};
  const mock = status?.service?.mock === true;
  return connected && !proxy.trafficBlocked && !['pending', 'failed', 'blocked'].includes(proxy.trafficHoldStatus) && !status?.connectionCancellation?.requested && (!status?.statusRead || status.statusRead.state === 'fresh' || status.statusRead.connectionChecked === true) && proxy.running === true && proxy.enabled === true && !proxy.requestedStop
    && (!status?.networkLifecycle || status.networkLifecycle.state === 'stable')
    && (proxy.exitStatus === 'verified' || mock && proxy.exitStatus === 'mocked')
    && (mock || proxy.mode !== 'tun' || proxy.systemNetwork?.status === 'verified');
}

export function connectionControls({ status = {}, busy = false, operationKind = null, ending = false, quitting = false } = {}) {
  const connecting = status.connectionCancellation?.active === true || busy && ['connect', 'resume'].includes(operationKind);
  const stopping = ending || status.connectionCancellation?.requested === true;
  const readWork = ['application', 'application-check', 'probe', 'diagnostics', 'browser'].includes(operationKind);
  const sessionRunning = status.proxy?.running === true || status.browser?.running === true;
  return { connecting, stopping, sessionRunning, canEnd: !quitting && !stopping && (connecting || sessionRunning && (!busy || readWork)), canQuit: !quitting && !stopping && (!busy || connecting), canResume: !busy && !quitting && !stopping && status.license?.allowed === true && status.proxy?.trafficBlocked === true };
}

export function systemExitReady(status, connected = true) {
  const coverage = status?.applicationProxy?.coverage;
  return connectionReady(status, connected) && status?.service?.mock !== true
    && status?.proxy?.mode === 'tun' && coverage?.mode === 'tun' && coverage.systemExitVerified === true;
}

export function systemProtectionReady(status, connected = true) {
  return connectionReady(status, connected) && status?.service?.mock !== true
    && status?.proxy?.mode === 'tun' && status?.networkLock?.locked === true
    && (status?.protection?.systemProtected === true || status?.applicationProxy?.coverage?.systemProtected === true);
}

// The concept's evidence card uses existing observations, never a new probe.
export function connectionEvidenceView({ status = {}, active = false, state = 'idle' } = {}) {
  const proxy = status?.proxy || {}, mock = status?.service?.mock === true;
  const ip = typeof proxy.exit?.ip === 'string' ? proxy.exit.ip : '';
  const system = proxy.systemNetwork || {}, report = status?.report;
  const geo = active && !mock && report?.stale === false && report.summary?.consistent === true
    && report.geo?.verified === true && report.geo.ip === ip ? report.geo : null;
  const location = geo && typeof geo.city === 'string' && geo.city.trim() ? geo.city.slice(0, 80) : null;
  const country = geo && /^[A-Z]{2}$/.test(geo.countryCode || '') ? geo.countryCode : '';
  const observed = active && !mock && Number.isFinite(Date.parse(proxy.exit?.observedAt));
  const same = active && !mock && ip && system.status === 'verified' && system.ip === ip;
  return {
    exitLocation: active ? mock ? '连接演示' : location || '出口已核验' : state === 'blocked' ? '授权不可用' : state === 'canceling' ? '正在取消连接' : state === 'connecting' ? '正在建立连接' : state === 'offline' ? '服务未连接' : state === 'checking' ? '正在确认状态' : state === 'unverified' ? '出口待核验' : '准备开始连接',
    exitRegion: country,
    exitEvidenceTitle: active ? mock ? '模拟结果 · 未实测' : same ? '代理与系统出口一致' : proxy.mode === 'tun' ? '代理与系统已核验' : '显式代理出口已核验' : state === 'unverified' ? '当前证据需要更新' : '等待出口核验',
    proofProxyIp: active ? mock ? '模拟 · 未实测' : ip || '已核验' : '等待结果',
    proofSystemIp: active ? mock ? '模拟 · 未实测' : proxy.mode !== 'tun' ? '未接管系统' : system.status === 'verified' ? system.ip || '已核验' : '等待结果' : '等待结果',
    proofCheckedAt: observed ? `最近核验 ${new Date(proxy.exit.observedAt).toLocaleTimeString('zh-CN', { hour12: false })}` : active ? mock ? '未建立真实链路' : '当前会话已核验' : '连接后自动核验',
    routeExitDetail: active ? mock ? '模拟 · 未实测' : '当前 IP 已核验' : '等待核验',
  };
}

export function failureDetails(status, recentFailure) {
  const lock = status?.networkLock;
  const candidates = [recentFailure, status?.lastError, lock?.errorCode ? {
    code: lock.errorCode, message: '断网锁检查或操作未完成。恢复记录已保留。',
    at: lock.lastCheckedAt, diagnostic: lock.diagnostic,
  } : null].filter(item => item && /^[A-Z][A-Z0-9_]{0,79}$/.test(item.code || ''));
  candidates.sort((a, b) => (Date.parse(b.at) || 0) - (Date.parse(a.at) || 0));
  const failure = candidates[0];
  if (!failure) return '当前未记录错误。登录与模型访问仍须实际测试；可打开客户端日志查看历史记录。';
  const parts = [failure.code];
  if (Number.isFinite(Date.parse(failure.at))) parts.push(new Date(failure.at).toISOString());
  if (typeof failure.stage === 'string' && /^[a-z-]{1,80}$/.test(failure.stage)) parts.push(`阶段：${failure.stage}`);
  if (typeof failure.message === 'string') parts.push(failure.message.slice(0, 400));
  const environmentDetail = environmentDiagnosticText(failure.diagnostic);
  if (environmentDetail) parts.push(environmentDetail);
  for (const key of ['operation', 'command', 'category']) {
    const value = failure.diagnostic?.[key];
    if (typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,39}$/.test(value)) parts.push(`${key}：${value}`);
  }
  const appendProbe = (diagnostic, label = '') => {
    const stages = { 'proxy-connect': '代理建隧道', tls: 'TLS', 'target-response': '目标响应' };
    if (Object.hasOwn(stages, diagnostic?.stage || '')) parts.push(`${label}${stages[diagnostic.stage]}`);
    for (const [key, title] of [['connectHttpStatus', 'CONNECT'], ['targetHttpStatus', '目标 HTTP']]) {
      const value = diagnostic?.[key];
      if (Number.isInteger(value) && value >= 100 && value <= 599) parts.push(`${label}${title}：${value}`);
    }
  };
  appendProbe(failure.diagnostic);
  for (const check of (Array.isArray(failure.diagnostic?.checks) ? failure.diagnostic.checks : []).slice(0, 2)) {
    if (!['ipify', 'cloudflare'].includes(check?.source) || !/^[A-Z][A-Z0-9_]{0,79}$/.test(check.code || '')) continue;
    parts.push(`${check.source}：${check.code}`); appendProbe(check, `${check.source} · `);
  }
  return parts.join('\n');
}

export function connectionView({ status, connected = true, readError = null, configuration = {}, vpnConfirmed = false, relayConfigured = false, targetMode = 'http', targetRoutingMode = 'global' }) {
  const proxy = status?.proxy || {}, mock = status?.service?.mock === true;
  const source = proxy.running ? proxy.connectionMode || configuration.connectionMode : configuration.connectionMode;
  const imported = source === 'vpn-import', external = source === 'vpn-compat', compat = imported || external;
  const running = proxy.running === true, tun = running && proxy.mode === 'tun', active = connectionReady(status, connected);
  const connecting = status?.connectionCancellation?.active === true, canceling = status?.connectionCancellation?.requested === true;
  const held = proxy.trafficBlocked === true || ['pending', 'failed', 'blocked'].includes(proxy.trafficHoldStatus);
  const pending = connected && status?.statusRead && status.statusRead.connectionChecked !== true
    && (['checking', 'busy'].includes(status.statusRead.state) || running && status.statusRead.state === 'cached' && status.health?.state !== 'degraded');
  const unavailable = !connected && (!readError || readError.code === 'CONTROLLER_UNAVAILABLE');
  const state = unavailable ? 'offline' : held ? 'blocked' : canceling ? 'canceling' : connecting ? 'connecting' : !connected || pending ? 'checking' : active ? 'connected' : running ? 'unverified' : 'idle';
  const lock = status?.networkLock || {}, environment = status?.environment || {};
  const supportsLock = !external && (!imported || tun || lock.locked || targetMode === 'tun');
  const lockLabels = { unlocked: '未开启', locked: '已开启', conflict: '策略冲突', unavailable: '不可用', unsupported: '不支持', locking: '开启中', 'recovery-required': '需要恢复' };
  const scope = tun || !running && (!compat || imported && targetMode === 'tun') ? (running ? proxy.routingMode : targetRoutingMode) === 'safe-rules' ? '智能规则 TUN' : '全局 TUN' : '显式 HTTP 代理';
  const sourceLabel = imported ? '导入配置' : external ? '外部 VPN' : 'VPS 中转';
  const prefix = mock ? '模拟 · ' : '';
  const applied = status?.browser?.running === true && status.browser.webrtc?.configured === true && !status.browser.webrtc?.restartRequired;
  let detail;
  if (held) detail = proxy.trafficHoldStatus === 'failed' ? '授权已不可用，TUN 保留中，但阻断尚未可靠完成。请查看日志与修复状态；不能认定当前公网流量已受保护。' : proxy.trafficHoldStatus === 'pending' ? '授权已不可用，正在保留 TUN 并阻断公网流量；完成前不允许启动应用。' : '授权已不可用，代理流量已阻断，TUN 保留。导入有效许可后可手动恢复代理连接；结束连接将恢复普通网络，可能使用真实 IP 直连。';
  else if (canceling) detail = '已请求取消连接，正在停止受管核心并清理会话；完成前不要再次建立连接。';
  else if (connecting) detail = '正在建立连接并核验出口。可点击“取消连接”；只读诊断与日志仍可查看。';
  else if (!connected) detail = readError?.code === 'CONTROLLER_REQUEST_TIMEOUT' ? '本地服务读取超时，当前连接结果待确认；这不表示代理核心已经停止。请刷新状态或查看日志。' : '当前连接结果未知。请刷新状态，或打开诊断与恢复。';
  else if (pending) detail = '本地服务可响应，正在更新连接核验。当前显示上次记录；完成前不据此启动应用。';
  else if (running && !active) detail = proxy.requestedStop ? '连接正在停止。清理完成前，请勿再次启动。' : status.health?.state === 'degraded' ? '本次核验未完成，现有连接保持运行，后台将重试。出口证明已过期时暂不允许新应用启动，请查看诊断。' : '核心仍在运行，出口或系统网络尚未通过核验，请查看诊断。';
  else if (imported) detail = active ? `${prefix}导入节点 → ISP，无需开启外部 VPN。${mock ? '未建立真实链路。' : 'ISP 出口已核验。'}${tun ? `${scope} 已接管系统默认网络。` : '只有接入本地代理的应用使用此链路。'}` : '导入节点 → ISP，无需开启外部 VPN。连接前核验完整出口。';
  else if (external) detail = active ? `${prefix}外部 VPN → ISP，不经 VPS。${mock ? '未建立真实链路。' : 'ISP 出口已核验。'}仅接入代理的应用使用此链路。` : vpnConfirmed ? '外部 VPN → ISP，不经 VPS。保持 VPN 开启，连接前探测路线并核验出口。' : '外部 VPN → ISP，不经 VPS。请在连接来源设置中确认 VPN 已开启。';
  else detail = active ? mock ? '这是模拟流程，未建立真实网络链路。' : `${relayConfigured ? 'VPS → ISP，' : ''}${tun ? '系统默认网络出口已核验。' : 'ISP 出口已核验，当前使用显式代理。'}` : configuration.available ? '连接前核验 VPS 与 ISP；连接后可手动开启断网锁。' : '请先保存连接配置，再建立链路。';

  if(lock.developmentPaused&&!running&&configuration.available)detail='连接前核验入口与 ISP 出口。新断网锁开发已暂停，连接与应用接入不依赖它。';
  let lockDetail = !supportsLock ? '应用分流不接管全系统，系统默认浏览器登录需要另行确认。断网锁为可选功能。' : lock.locked ? '断网锁已启用。结束连接后仍保留阻断，请手动解除以恢复普通网络。' : lock.status === 'conflict' ? '防火墙策略存在外部改动，已禁止覆盖。请核对系统策略与恢复记录。' : lock.status === 'unlocked' ? '当前未开启，可选手动开启。应用启动不强制开锁；无锁时，代理断开后普通应用可能恢复直连。' : '尚未确认断网锁状态，请查看运行权限与恢复记录。';
  if(lock.developmentPaused)lockDetail=lock.locked?'旧断网锁仍然生效，请先结束连接，再通过网络修复恢复。新断网锁开发已暂停。':'断网锁开发已暂停，优先保持已验证的连接功能。未开启断网锁时，代理断开后普通应用可能恢复直连。旧锁记录仍可通过网络修复恢复。';
  else if(lock.legacy)lockDetail='检测到旧版防火墙保护记录，请先结束连接并使用网络修复。';
  else if(supportsLock&&lock.engine==='wfp'&&lock.locked)lockDetail+=' 独立规则覆盖此 Windows 主机的 IPv4 / IPv6；不覆盖虚拟机转发或系统过滤服务启动前阶段。';
  if (typeof lock.reason === 'string' && lock.reason) lockDetail += ` ${lock.reason}`;
  const restoreNeeded = environment.backup?.restoreNeeded === true;
  const environmentVerification = environmentVerificationView(environment);
  const environmentReview = environmentVerification?.needsReview ?? (['error', 'failed', 'partial', 'conflict', 'recovery-required'].includes(environment.status) || environment.optimization?.status === 'partial');
  const lockRecovery = lock.locked ? '断网锁仍开启' : lock.status === 'unlocked' ? '断网锁未开启' : compat ? '此线路不支持断网锁' : '断网锁状态待确认';
  const recovery = [environmentVerification?.needsReview ? environmentVerification.changed && environmentVerification.status === 'matched' ? `${environmentVerification.label} · 设置有变化` : environmentVerification.saved ? '环境待重新核验' : environmentVerification.status === 'partial' ? '当前环境部分匹配 · 成功项保留' : '当前环境待核验' : !environmentVerification && environment.optimization?.status === 'partial' ? '环境部分完成 · 成功项保留' : restoreNeeded ? '系统环境待复原' : environmentReview ? '系统环境待检查' : '系统环境无需复原', lockRecovery];
  const dns = tun ? mock ? '模拟 TUN DNS，未改变系统。' : `TUN DNS 接管已配置，DoH 经 ISP。${proxy.systemNetwork?.status === 'verified' ? '系统默认网络出口已核验。' : '系统默认网络出口待确认。'}实际泄露测试尚未完成。` : compat ? '应用分流不接管系统 DNS。普通应用仍使用自己的网络设置。' : 'DNS 接管将在 TUN 启动时配置，实际泄露验证待完成。';
  return {
    state, active, scope, sourceLabel,
    fields: {
      connectionTitle: held ? proxy.trafficHoldStatus === 'failed' ? '公网阻断待处理' : proxy.trafficHoldStatus === 'pending' ? '正在阻断代理流量' : '授权不可用 · 流量已阻断' : canceling ? '正在取消连接' : connecting ? '正在建立连接' : state === 'offline' ? '本地服务未连接' : state === 'checking' ? readError?.code === 'CONTROLLER_REQUEST_TIMEOUT' ? '读取状态超时' : '状态正在确认' : active ? mock ? '模拟连接已就绪' : '连接已就绪' : running ? proxy.requestedStop ? '正在停止连接' : status.health?.state === 'degraded' ? '连接运行中 · 出口待核验' : '连接需要重新验证' : '准备建立连接',
      connectionModeLabel: held ? `${sourceLabel} · ${proxy.trafficHoldStatus === 'failed' ? '阻断待处理' : proxy.trafficHoldStatus === 'pending' ? '阻断中' : '流量已阻断'}` : canceling ? `${sourceLabel} · 正在取消` : connecting ? `${sourceLabel} · 正在连接` : connected && !pending ? `${prefix}${sourceLabel} · ${active ? '已连接' : running ? '待核验' : '未连接'}` : '状态待确认',
      connectionDetail: detail,
      exitIp: active ? mock ? '模拟数据' : proxy.exit?.ip || '已验证' : '等待核验',
      workspaceScope: scope,
      workspaceRecoverySummary: connected && !pending ? recovery.join(' · ') : unavailable ? '服务未连接，请检查实际系统状态' : '状态待更新，请查看上次记录与恢复日志',
      lockSummary: !supportsLock ? '未接管系统' : lockLabels[lock.status] || '待确认',
      networkLockStatus: !supportsLock ? '未接管系统' : `${prefix}${lockLabels[lock.status] || '待确认'}`,
      networkLockDetail: lockDetail,
      webrtcProfileStatus: mock ? '模拟 · 未实测' : applied ? '已配置 · 待实测' : '待所选浏览器启动',
      webrtcFlagStatus: mock ? '模拟 · 未实测' : applied ? '已配置 · 待实测' : '待所选浏览器启动',
      webrtcTunStatus: tun ? mock ? '模拟 · 未实测' : '已配置阻断 · 待实测' : compat ? '应用分流未接管' : '待 TUN 启动',
      dnsStatus: dns,
      networkScopeHint: tun || !compat ? '系统出口核验覆盖默认网络；应用独立代理仍需确认。' : imported ? '核验覆盖本地 HTTP 链路，未接管全系统；不能证明外部 VPN 已关闭。' : '出口核验覆盖本地 HTTP 代理，不代表全系统或外部 VPN 的保护已验证。',
      offlineToolsHint: imported ? '导入节点由 MC Proxy 自行连接。需要独立验收时，请自行关闭外部 VPN 后再验证。诊断不会修改系统代理。' : external ? '保持外部 VPN 开启。诊断和恢复工具可留存错误，不会自动改变 VPN 或系统代理。' : '诊断可检查入口、出口并保留错误日志。网络异常时，使用下方恢复工具。',
      browserStatus: status?.browser?.running ? `${browserLabels[status.browser.browser] || '受管浏览器'}正在运行；关闭时保留资料，清理须另行确认。` : '尚未启动。指纹浏览器默认保留资料与固定身份；纯净空间另建资料。',
    },
  };
}
