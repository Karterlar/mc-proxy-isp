import test from 'node:test';
import assert from 'node:assert/strict';
import { connectionReady, connectionControls, connectionView, connectionEvidenceView, systemProtectionReady, systemExitReady, failureDetails } from '../../frontend/workspace-view.js';

const status = mode => ({ service: { mock: false }, proxy: { running: true, enabled: true, mode, connectionMode: 'vpn-import', exitStatus: 'verified', exit: { ip: '203.0.113.8' }, systemNetwork: { status: 'verified' } }, networkLock: { status: 'unlocked' } });

test('partially applied environment keeps verified connection available with a retained-settings notice', () => {
  const current = { ...status('tun'), environment: { status: 'partial', optimization: { status: 'partial', operation: 'restore' }, backup: { canRestore: true, restoreNeeded: true } } };
  assert.equal(connectionReady(current), true);
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /部分完成.*成功项保留/);
  assert.doesNotMatch(connectionView({ status: current }).fields.workspaceRecoverySummary, /无需复原/);
});

test('workspace environment status uses fresh verification instead of retained operation failures', () => {
  const current = { ...status('tun'), environment: { status: 'optimized', optimization: { status: 'partial' }, verification: { status: 'matched', source: 'live', fieldResults: [{ field: 'languages', status: 'matched' }] }, backup: { restoreNeeded: false } } };
  assert.equal(connectionReady(current), true);
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /无需复原/);
  assert.doesNotMatch(connectionView({ status: current }).fields.workspaceRecoverySummary, /部分完成|待检查/);
  current.environment.verification.source = 'saved';
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /待重新核验/);
  current.environment.verification = { status: 'unverified', source: 'live', fieldResults: [{ field: 'languages', status: 'unknown' }] };
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /当前环境待核验/);
  assert.equal(connectionReady(current), true);
});

test('workspace keeps no-target setup neutral and flags changes without denying a matching environment', () => {
  const current = { ...status('tun'), environment: { status: 'ready', optimization: { status: 'not-requested' }, verification: { status: 'unverified', source: 'live', fieldResults: [] } } };
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /无需复原/);
  current.environment = { status: 'conflict', optimization: { status: 'partial' }, verification: { status: 'matched', source: 'live', fieldResults: [{ field: 'languages', status: 'matched' }] } };
  const summary = connectionView({ status: current }).fields.workspaceRecoverySummary;
  assert.match(summary, /当前已匹配.*设置有变化/);
  assert.doesNotMatch(summary, /未匹配|待核验|部分完成/);
  assert.equal(connectionReady(current), true);
});

test('browser session status names the running engine instead of calling Chrome fingerprint', () => {
  for (const [browser,label] of [['fingerprint','指纹浏览器'],['chrome','Chrome'],['edge','Edge']]) {
    const view=connectionView({status:{...status('tun'),browser:{running:true,browser}},connected:true});
    assert.ok(view.fields.browserStatus.startsWith(label+'正在运行'));
    if (browser!=='fingerprint') assert.ok(!view.fields.browserStatus.includes('指纹'));
  }
});

test('concept evidence uses only current matching geography and never turns demo or expired data into proof', () => {
  const current = status('tun');
  current.proxy.exit.observedAt = '2026-10-06T10:00:00Z';
  current.proxy.systemNetwork.ip = current.proxy.exit.ip;
  current.report = { stale: false, summary: { consistent: true }, geo: { verified: true, ip: current.proxy.exit.ip, city: 'Tokyo', countryCode: 'JP' } };
  const input = { status: current, active: true, state: 'connected' };
  assert.equal(connectionEvidenceView(input).exitLocation, 'Tokyo');
  assert.equal(connectionEvidenceView(input).proofSystemIp, current.proxy.exit.ip);
  assert.match(connectionEvidenceView(input).exitEvidenceTitle, /一致/);
  for (const report of [{ ...current.report, stale: true }, { ...current.report, geo: { ...current.report.geo, ip: '192.0.2.2' } }]) {
    assert.equal(connectionEvidenceView({ ...input, status: { ...current, report } }).exitLocation, '出口已核验');
  }
  const expired = connectionEvidenceView({ ...input, active: false, state: 'unverified' });
  assert.equal(expired.proofProxyIp, '等待结果'); assert.equal(expired.exitRegion, '');
  const simulated = connectionEvidenceView({ ...input, status: { ...current, service: { mock: true } } });
  assert.equal(simulated.exitLocation, '连接演示'); assert.match(simulated.proofProxyIp, /未实测/);
  assert.equal(connectionEvidenceView({ ...input, status: { ...current, proxy: { ...current.proxy, mode: 'http' } } }).proofSystemIp, '未接管系统');
});

test('failure text distinguishes CONNECT and target status and drops private diagnostic values', () => {
  const text = failureDetails({ lastError: { code: 'SETUP_CHECK_FAILED', diagnostic: { checks: [
    { source: 'ipify', code: 'PROXY_CONNECT_REJECTED', stage: 'proxy-connect', connectHttpStatus: 502, password: 'PRIVATE_SECRET' },
    { source: 'cloudflare', code: 'PROBE_HTTP_STATUS', stage: 'target-response', targetHttpStatus: 500, message: 'PRIVATE_MESSAGE' },
  ] } } });
  assert.match(text, /CONNECT：502/); assert.match(text, /目标 HTTP：500/); assert.doesNotMatch(text, /PRIVATE_/);
});
test('connection readiness requires a running core and current exit and TUN verification', () => {
  const current = status('tun');
  assert.equal(connectionReady(current), true);
  assert.equal(connectionReady(current, false), false);
  for (const change of [{ running: false }, { requestedStop: true }, { enabled: false }, { exitStatus: 'failed' }, { systemNetwork: { status: 'unverified' } }]) {
    assert.equal(connectionReady({ ...current, proxy: { ...current.proxy, ...change } }), false);
  }
});

test('connection controls allow cancel and read-work disconnect, without interrupting recovery or cleanup mutations', () => {
  const current = status('tun');
  const beginning = connectionControls({ status: { proxy: { running: false } }, busy: true, operationKind: 'connect' });
  assert.equal(beginning.canEnd, true); assert.equal(beginning.connecting, true); assert.equal(beginning.canQuit, true);
  for (const kind of ['application', 'application-check', 'probe', 'diagnostics', 'browser']) assert.equal(connectionControls({ status: current, busy: true, operationKind: kind }).canEnd, true);
  for (const kind of ['repair', 'environment', 'general', 'vpn-import', 'browser-settings']) {
    const view = connectionControls({ status: current, busy: true, operationKind: kind });
    assert.equal(view.canEnd, false); assert.equal(view.canQuit, false);
  }
  const requested = { ...current, connectionCancellation: { active: true, requested: true } };
  assert.equal(connectionControls({ status: requested }).canEnd, false); assert.equal(connectionControls({ status: requested }).canQuit, false);
  assert.equal(connectionControls({ status: current, ending: true }).canEnd, false);
  assert.equal(connectionControls({ status: current, quitting: true }).canEnd, false);
});

test('an expired hold keeps TUN visibly separate from a ready or stopped connection, and resume needs a new allowed license', () => {
  for (const trafficHoldStatus of ['pending', 'failed', 'blocked']) {
    const current = { ...status('tun'), proxy: { ...status('tun').proxy, trafficBlocked: trafficHoldStatus === 'blocked', trafficHoldStatus }, license: { allowed: false } };
    assert.equal(connectionReady(current), false);
    const view = connectionView({ status: current }); assert.equal(view.state, 'blocked'); assert.equal(view.active, false); assert.equal(view.fields.exitIp, '等待核验');
    assert.equal(connectionControls({ status: current }).canResume, false);
    if (trafficHoldStatus === 'failed') { assert.match(view.fields.connectionDetail, /不能认定/); assert.doesNotMatch(view.fields.connectionTitle, /已阻断|已就绪/); }
    else if (trafficHoldStatus === 'pending') assert.match(view.fields.connectionTitle, /正在阻断/);
    else {
      assert.match(view.fields.connectionDetail, /真实 IP 直连/);
      assert.equal(connectionControls({ status: { ...current, license: { allowed: true } } }).canResume, true);
      assert.equal(connectionControls({ status: { ...current, license: { allowed: true } }, busy: true }).canResume, false);
    }
  }
  const canceling = { ...status('tun'), connectionCancellation: { active: true, requested: true } };
  assert.equal(connectionReady(canceling), false); assert.equal(connectionView({ status: canceling }).state, 'canceling');
});

test('background health checks keep verified UI actions available without authorizing expired or busy sessions', () => {
  const current = { ...status('tun'), health: { state: 'checking' }, statusRead: { state: 'cached', connectionChecked: true } };
  assert.equal(connectionReady(current), true);
  assert.equal(connectionView({ status: current }).active, true);
  for (const change of [
    { statusRead: { state: 'cached', connectionChecked: false } },
    { statusRead: { state: 'busy', connectionChecked: false } },
    { proxy: { ...current.proxy, exitStatus: 'unverified' } },
    { proxy: { ...current.proxy, requestedStop: true } },
    { proxy: { ...current.proxy, systemNetwork: { status: 'unverified' } } },
  ]) assert.equal(connectionReady({ ...current, ...change }), false);
});

test('a degraded check distinguishes a running unverified route from a disconnected proxy', () => {
  const current = { ...status('tun'), health: { state: 'degraded', errorCode: 'PROBE_TIMEOUT' }, statusRead: { state: 'cached', connectionChecked: false } };
  current.proxy = { ...current.proxy, exitStatus: 'unverified', systemNetwork: { status: 'unverified' } };
  const view = connectionView({ status: current });
  assert.equal(view.state, 'unverified'); assert.equal(view.active, false);
  assert.match(view.fields.connectionTitle, /连接运行中/);
  assert.equal(view.fields.connectionModeLabel, '导入配置 · 待核验');
  assert.match(view.fields.connectionDetail, /现有连接保持运行/);
  assert.equal(view.fields.exitIp, '等待核验'); assert.equal(connectionReady(current), false);
  const fresh = { ...status('tun'), health: current.health, statusRead: { state: 'cached', connectionChecked: true } };
  assert.equal(connectionReady(fresh), true, 'A failed observation alone does not erase a still-current proof');
  assert.equal(connectionView({ status: fresh }).active, true);
});

test('an idle snapshot keeps connection preparation guidance without claiming an active lease', () => {
  for (const connectionMode of ['vpn-compat', 'vpn-import']) {
    const current = { ...status('http'), statusRead: { state: 'cached', connectionChecked: false }, proxy: { running: false, enabled: false, connectionMode } };
    const view = connectionView({ status: current, configuration: { connectionMode, available: true } });
    assert.equal(view.state, 'idle'); assert.equal(view.active, false); assert.equal(connectionReady(current), false);
    assert.match(view.fields.connectionDetail, connectionMode === 'vpn-import' ? /无需开启外部 VPN/ : /不经 VPS/);
  }
});
test('application and global capture describe their actual running scope', () => {
  const app = connectionView({ status: status('http') });
  assert.equal(app.scope, '显式 HTTP 代理');
  assert.match(app.fields.networkScopeHint, /未接管全系统/);
  const global = connectionView({ status: status('tun') });
  assert.equal(global.scope, '全局 TUN');
  assert.match(global.fields.connectionDetail, /全局 TUN/);
  assert.match(global.fields.networkLockDetail, /手动开启/);
});

test('paused lock keeps verified connection usable and directs old protection to recovery', () => {
  const current=status('tun');current.networkLock={status:'unlocked',locked:false,canArm:false,developmentPaused:true};
  const view=connectionView({status:current});
  assert.equal(view.active,true);assert.equal(connectionReady(current),true);
  assert.match(view.fields.networkLockDetail,/开发已暂停/);assert.doesNotMatch(view.fields.networkLockDetail,/可选手动开启/);
  current.networkLock={...current.networkLock,status:'locked',locked:true};
  assert.match(connectionView({status:current}).fields.networkLockDetail,/旧断网锁.*网络修复/);
});
test('loss of controller connectivity cannot retain a ready title or verified IP', () => {
  const view = connectionView({ status: status('tun'), connected: false });
  assert.equal(view.active, false);
  assert.equal(view.state, 'offline');
  assert.equal(view.fields.connectionModeLabel, '状态待确认');
  assert.equal(view.fields.exitIp, '等待核验');
});
test('disconnect keeps outstanding environment and firewall recovery visible', () => {
  const current = status('http');
  current.proxy = { ...current.proxy, running: false, requestedStop: true };
  current.environment = { backup: { canRestore: true, restoreNeeded: true } };
  current.networkLock = { status: 'locked', locked: true };
  const view = connectionView({ status: current, configuration: { connectionMode: 'relay' } });
  assert.match(view.fields.workspaceRecoverySummary, /系统环境待复原/);
  assert.match(view.fields.workspaceRecoverySummary, /断网锁仍开启/);
});
test('unknown recovery state is not presented as restored or unlocked', () => {
  const current = { service: { mock: false }, proxy: { running: false }, environment: { status: 'error' }, networkLock: { status: 'conflict' } };
  const view = connectionView({ status: current, configuration: { connectionMode: 'relay' } });
  assert.match(view.fields.workspaceRecoverySummary, /系统环境待检查/);
  assert.match(view.fields.workspaceRecoverySummary, /断网锁状态待确认/);
  assert.doesNotMatch(view.fields.workspaceRecoverySummary, /无需复原|断网锁未开启/);
});


test('browser login protection requires current TUN and persistent lock together', () => {
  const current = status('tun'); current.networkLock = { status: 'locked', locked: true };
  current.protection = { systemProtected: true };
  assert.equal(systemProtectionReady(current), true);
  assert.equal(systemProtectionReady(current, false), false);
  for (const item of [
    { ...current, service: { mock: true } },
    { ...current, networkLock: { status: 'unlocked', locked: false } },
    { ...current, protection: { systemProtected: false } },
    { ...current, proxy: { ...current.proxy, mode: 'http' } },
    { ...current, proxy: { ...current.proxy, systemNetwork: { status: 'unverified' } } },
    { ...current, proxy: { ...current.proxy, requestedStop: true } },
  ]) assert.equal(systemProtectionReady(item), false);
});

test('verified active TUN admits applications without requiring the optional lock', () => {
  const current = status('tun');
  current.applicationProxy = { coverage: { mode: 'tun', systemExitVerified: true, systemProtected: false } };
  assert.equal(systemExitReady(current), true);
  assert.equal(systemProtectionReady(current), false);
  assert.equal(systemExitReady({ ...current, proxy: { ...current.proxy, mode: 'http' } }), false);
  assert.equal(systemExitReady({ ...current, applicationProxy: { coverage: { mode: 'tun', systemExitVerified: false } } }), false);
  assert.match(connectionView({ status: current }).fields.networkLockDetail, /不强制开锁/);
});

test('a slow status read is uncertain rather than evidence the local service stopped', () => {
  const view = connectionView({ status: status('tun'), connected: false, readError: { code: 'CONTROLLER_REQUEST_TIMEOUT' } });
  assert.equal(view.state, 'checking');
  assert.equal(view.fields.connectionTitle, '读取状态超时');
  assert.match(view.fields.connectionDetail, /不表示代理核心已经停止/);
  assert.equal(view.active, false);
  assert.equal(connectionView({ status: status('tun'), connected: false, readError: { code: 'CONTROLLER_UNAVAILABLE' } }).state, 'offline');
});

test('public cached display cannot authorize an application or claim a ready connection', () => {
  for (const state of ['busy', 'checking', 'cached']) {
    const current = { ...status('tun'), statusRead: { state, checkedAt: '2026-10-05T10:00:00Z' } };
    assert.equal(connectionReady(current), false);
    const view = connectionView({ status: current });
    assert.equal(view.state, 'checking');
    assert.equal(view.fields.connectionTitle, '状态正在确认');
    assert.match(view.fields.connectionDetail, /本地服务可响应/);
    assert.equal(view.fields.exitIp, '等待核验');
  }
});

test('diagnostics show the most recent fixed public failure and omit unapproved details', () => {
  const view = failureDetails({ lastError: { code: 'NETWORK_LOCK_TIMEOUT', message: '防火墙操作超时。', at: '2026-10-05T15:02:21Z', diagnostic: { operation: 'disable', command: 'powershell.exe', category: 'OperationTimeout', password: 'private-credential', endpoint: 'private-provider' } } },
    { code: 'PROCESS_UNREADABLE', message: '进程身份无法读取。', at: '2026-10-05T15:03:25Z' });
  assert.match(view, /PROCESS_UNREADABLE/);
  assert.doesNotMatch(view, /NETWORK_LOCK_TIMEOUT|private/);
  assert.match(failureDetails({ networkLock: { errorCode: 'NETWORK_LOCK_TIMEOUT', diagnostic: { operation: 'disable', password: 'private-credential' } } }), /operation：disable/);
  assert.doesNotMatch(failureDetails({ networkLock: { errorCode: 'NETWORK_LOCK_TIMEOUT', diagnostic: { password: 'private-credential' } } }), /private/);
  const environment = failureDetails({}, { code: 'ENVIRONMENT_VERIFY_FAILED', diagnostic: { environmentStage: 'apply-culture', environmentFields: ['culture', 'password'], rollbackEnvironmentFields: ['languages'], actualCulture: 'private-value' } });
  assert.match(environment, /失败步骤：写入区域格式；尚未匹配：区域格式；自动回滚尚未匹配：语言与输入法列表/);
  assert.doesNotMatch(environment, /private|password/);
});

test('a reusable original snapshot alone is not an outstanding restoration', () => {
  const current = { ...status('http'), environment: { status: 'ready', backup: { canRestore: true, restoreNeeded: false } } };
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /系统环境无需复原/);
  current.environment.backup.restoreNeeded = true;
  assert.match(connectionView({ status: current }).fields.workspaceRecoverySummary, /系统环境待复原/);
});
