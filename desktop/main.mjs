import { app, BrowserWindow, Menu, Tray, dialog, ipcMain, nativeImage, powerMonitor, screen, session, shell } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile, copyFile, lstat, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { startController, CONTROL_ERROR_CODES } from '../backend/src/local-controller.mjs';
import { createPrivateDirectory, writePrivate } from '../backend/src/private-files.mjs';
import { WINDOW_LAYOUTS, fitWindow, parseLaunchOptions, classifyNavigation, trustedSender, controllerRequestHeaders, exitNotice, desktopError } from './window-policy.mjs';
import { createWindowLayoutStore } from './window-layout.mjs';
import { launchNetworkRepair } from './network-repair.mjs';
import { createApplicationManager } from './application-manager.mjs';
import { createClientLog } from './client-log.mjs';
import { createNetworkLifecycle } from './network-lifecycle.mjs';
import { distributionPolicy, assertDistributionLaunch } from './license-config.mjs';
import { DISTRIBUTION } from './distribution.mjs';
import { createLicenseAdmin } from './licensing-admin.mjs';
import { prepareFingerprintBrowserFromBundle } from '../backend/src/fingerprint-browser-install.mjs';
import { FINGERPRINT_BROWSER_CACHE_DIRECTORY, FINGERPRINT_BROWSER_INSTALL_DIRECTORY } from '../backend/src/fingerprint-browser-runtime.mjs';
import { startupAccess, restartElevated, verifyAdminStartupHandoff, completeAdminStartupHandoff } from './admin-startup.mjs';
import { matchesAdminFileUrl } from './admin-file-policy.mjs';
import { createClaudeBackgroundManager } from './claude-background.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const distribution = distributionPolicy(DISTRIBUTION);
const PRODUCT_NAME = distribution.productName;
const requestedMock = distribution.mockAllowed && (process.argv.includes('--mock') || process.env.PROXYPILOT_MOCK === '1');
app.setName(PRODUCT_NAME);
app.setAppUserModelId(`com.mcproxy.desktop.${distribution.edition}`);
if (app.commandLine.hasSwitch('user-data-dir')) app.setPath('userData', path.resolve(app.commandLine.getSwitchValue('user-data-dir')));
if (!requestedMock && !app.commandLine.hasSwitch('user-data-dir')) app.setPath('userData', process.env.PORTABLE_EXECUTABLE_DIR
  ? path.join(path.resolve(process.env.PORTABLE_EXECUTABLE_DIR), `${PRODUCT_NAME} Data`)
  : path.join(app.getPath('appData'), PRODUCT_NAME));
if (requestedMock && !app.isPackaged && !app.commandLine.hasSwitch('user-data-dir')) app.setPath('userData', path.join(root, '.cache', process.argv.includes('--smoke-test') ? 'desktop-smoke' : 'desktop-mock', 'user-data'));
// Mock and real clients never share the Chromium profile or single-instance lock.
if (requestedMock && app.isPackaged && !app.commandLine.hasSwitch('user-data-dir')) app.setPath('userData', path.join(app.getPath('appData'), 'MC Proxy Mock'));
app.enableSandbox();
app.commandLine.appendSwitch('webrtc-ip-handling-policy', 'disable_non_proxied_udp');
app.commandLine.appendSwitch('disable-quic');

let options;
let controller;
let applications;
let mainWindow;
let tray;
let origin;
let quitting = false;
let exitBusy = false;
let applicationBusy = false;
let networkRepairPending = null, networkRepairState = null;
let trayTimer;
let networkLifecycle;
let licenseAdmin;
let showedTrayHint = false;
let secondInstanceEvents = 0;
let windowPreset='custom', windowSaveTimer, windowPresetBounds;
let adminGate = false, adminRestartBusy = false;
let adminStartupAuthorized = false;
let adminAccess = null;
let adminRestartAbort, adminRestartTask;
const pendingAdminHandoffs = new Set();
const windowLayouts=createWindowLayoutStore(path.join(app.getPath('userData'),'window-layout.json'));
function currentWindowLayout(){const bounds=mainWindow?.getBounds();const matches=bounds&&windowPresetBounds&&bounds.width===windowPresetBounds.width&&bounds.height===windowPresetBounds.height;return {preset:matches?windowPreset:'custom',bounds};}
function saveWindowLayout(){clearTimeout(windowSaveTimer);windowSaveTimer=setTimeout(()=>{if(mainWindow&&!mainWindow.isDestroyed())void windowLayouts.write(currentWindowLayout()).catch(()=>{});},400);windowSaveTimer.unref?.();}
const reportWindows = new Set();
const logPath = path.join(app.getPath('userData'), 'desktop.log');
const clientLog = createClientLog({ directory: app.getPath('userData'), knownCodes: CONTROL_ERROR_CODES });
const log = (event, cause) => clientLog.write(event, cause);

async function stableCorePath() {
  if (options.corePath) return path.resolve(options.corePath);
  if (!app.isPackaged) return path.join(root, 'backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe');
  const source = path.join(process.resourcesPath, 'core', 'sing-box-1.14.2');
  // A portable EXE can unpack to a different temporary directory on each run.
  // The managed core needs a stable identity for crash recovery and firewall rules.
  const target = path.join(app.getPath('userData'), 'core', 'sing-box-1.14.2');
  await mkdir(path.dirname(target), { recursive: true });
  try {
    const stat = await lstat(target);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('The managed core directory is not a normal directory');
  } catch (cause) {
    if (cause.code !== 'ENOENT') throw cause;
    await createPrivateDirectory(target);
  }
  for (const name of ['sing-box.exe', 'libcronet.dll', 'LICENSE']) {
    const from = path.join(source, name), to = path.join(target, name);
    const sourceHash = createHash('sha256').update(await readFile(from)).digest('hex');
    try {
      const targetHash = createHash('sha256').update(await readFile(to)).digest('hex');
      if (sourceHash !== targetHash) throw new Error(`The installed ${name} does not match this release. Preserve the existing recovery records and inspect the installation.`);
    } catch (cause) {
      if (cause.code !== 'ENOENT') throw cause;
      await copyFile(from, to, 1 /* COPYFILE_EXCL: never overwrite an active binary. */);
    }
  }
  return path.join(target, 'sing-box.exe');
}

function showWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show(); mainWindow.focus();
}

function localState() {
  return { ...controller?.state, operation: controller?.state?.operation || (networkRepairPending ? { stage: 'repairing-network' } : applicationBusy ? { stage: 'starting-application' } : null), networkLock: controller?.runtime?.networkLock?.snapshot?.() || {} };
}

function updateTray() {
  if (!tray) return;
  const state = localState();
  const locked = state.networkLock.locked || state.networkLock.state === 'locked';
  const unresolved = state.networkLock.state && !['unlocked', 'unavailable', 'locked'].includes(state.networkLock.state);
  const status = state.proxy?.running ? '代理已连接' : locked ? '断网锁保护中' : unresolved ? '网络状态待恢复' : '尚未连接';
  tray.setToolTip(`${PRODUCT_NAME} · ${options.mock ? '演示模式 · ' : ''}${status}`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: `${PRODUCT_NAME} · ${status}`, enabled: false },
    { label: '打开主窗口', click: showWindow },
    { label: '网络修复 · 恢复普通联网…', click: () => { void requestNetworkRepair().catch(cause => log('network repair launch failed', cause)); } },
    { type: 'separator' },
    { label: '退出 MC Proxy…', click: () => { void requestQuit().catch(cause => log('desktop quit request failed', cause)); } },
  ]));
}

async function requestQuit({ acceptance = false } = {}) {
  if (licenseAdmin?.isBusy()) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
  if (exitBusy || quitting) return;
  if (applicationBusy) throw Object.assign(new Error('请等待应用启动或退出完成后再退出客户端。'), { code: 'DESKTOP_BUSY' });
  exitBusy = true;
  try {
    const current = localState();
    const notice = exitNotice(!networkRepairPending && controller?.isConnecting?.() ? { ...current, operation: null } : current);
    if (notice.blocked) {
      showWindow();
      await dialog.showMessageBox(mainWindow, { type: 'info', title: PRODUCT_NAME, message: notice.message, buttons: ['返回'] });
      return;
    }
    if (!acceptance && notice.requiresConfirmation) {
      showWindow();
      const answer = await dialog.showMessageBox(mainWindow, { type: 'warning', title: '退出 MC Proxy', message: notice.message, detail: notice.detail, buttons: ['继续运行', '结束会话并退出'], defaultId: 0, cancelId: 0, noLink: true });
      if (answer.response !== 1) return;
    }
    await controller?.shutdown();
    clearTimeout(windowSaveTimer);
    await windowLayouts.write(currentWindowLayout()).catch(() => {});
    quitting = true;
    networkLifecycle?.stop();
    clearInterval(trayTimer);
    for (const window of reportWindows) window.destroy();
    tray?.destroy();
    await log('desktop shutdown complete');
    await clientLog.flush();
    app.quit();
  } catch (cause) {
    await log('safe shutdown incomplete', cause);
    showWindow();
    if (!acceptance) await dialog.showMessageBox(mainWindow, { type: 'error', title: PRODUCT_NAME, message: '安全退出尚未完成，MC Proxy 已继续运行。', detail: '请回到主窗口结束独立浏览器与代理会话，然后重试。断网锁没有被自动解除。', buttons: ['返回主窗口'] });
    else throw cause;
  } finally { exitBusy = false; }
}

async function requestNetworkRepair() {
  if (networkRepairPending) return finishPendingNetworkRepair(networkRepairPending);
  if (exitBusy || quitting || applicationBusy || localState().operation && !controller?.isConnecting?.()) throw Object.assign(new Error('请等待当前操作结束后再修复网络。'), { code: 'DESKTOP_BUSY' });
  exitBusy = true;
  let sessionsStopped = false;
  try {
    const prompt = {
      type: 'warning', title: '网络修复', message: '结束代理会话并恢复普通联网？',
      detail: options.mock ? '演示模式只模拟修复，不更改系统。' : '请接受管理员权限提示。修复工具就绪后，将安全结束代理与独立浏览器，并依据原始恢复记录撤销断网锁。客户端会保持打开并显示结果；已变化或缺失的原有允许规则保持原样，备份与差异报告会保留。',
      buttons: ['取消', '修复网络'], defaultId: 0, cancelId: 0, noLink: true,
    };
    const answer = await (mainWindow ? dialog.showMessageBox(mainWindow, prompt) : dialog.showMessageBox(prompt));
    if (answer.response !== 1) return { cancelled: true };
    let result, repairFailure, keepRepairGate = false;
    try {
      result = await launchNetworkRepair({
        scriptPath: app.isPackaged ? path.join(process.resourcesPath, 'offline-chain-test', 'Repair-Network.ps1') : path.join(root, 'tools/offline-chain-test/Repair-Network.ps1'),
        runtimeRoot: options.runtimeRoot, waitForPid: process.pid, mock: options.mock,
        stopSessions: async () => {
          await log('network repair helper ready');
          await controller?.beginNetworkRepair(); sessionsStopped = Boolean(controller);
        },
      });
      if (result.pending === true) {
        const { completion, ...pending } = result;
        const job = { pending, nativeFinished: false, result: null, failure: null, settling: null };
        networkRepairPending = job; networkRepairState = pending; keepRepairGate = true;
        void completion.then(done => { job.nativeFinished = true; job.result = done; }, cause => { job.nativeFinished = true; job.failure = cause; })
          .then(() => finishPendingNetworkRepair(job)).catch(cause => log('network repair pending completion failed', cause));
        await log('network repair remains pending');
        return pending;
      }
    } catch (cause) {
      repairFailure = cause;
      throw cause;
    } finally {
      if (sessionsStopped && !keepRepairGate) {
        try { await controller.finishNetworkRepair(); }
        catch (cause) {
          await log('network repair state reload incomplete', cause);
          if (!repairFailure) {
            if (result?.reportPath) cause.reportPath = result.reportPath;
            throw cause;
          }
        }
      }
      updateTray();
    }
    if (result.completed) {
      networkRepairState = result;
      await log('network repair complete', { code: result.code, diagnostic: { skippedAllowRules: result.skippedAllowRules } });
      showWindow();
      const complete = { type: result.skippedAllowRules ? 'warning' : 'info', title: '网络修复完成', message: '断网锁已解除，请测试普通联网。',
        detail: `${result.skippedAllowRules ? `保留了 ${result.skippedAllowRules} 条已变化或缺失的原有允许规则，未覆盖外部改动。\n\n` : ''}修复报告：${result.reportPath}`, buttons: ['完成'] };
      await (mainWindow ? dialog.showMessageBox(mainWindow, complete) : dialog.showMessageBox(complete));
    }
    return result;
  } catch (cause) {
    await log('network repair incomplete', cause);
    showWindow();
    const failure = { type: 'error', title: '网络修复未完成', message: cause.message,
      detail: `${cause.reportPath ? `修复报告：${cause.reportPath}\n\n` : ''}客户端已继续运行，恢复记录已保留。也可结束客户端后双击发行目录中的 Repair-Network.cmd。`, buttons: ['返回'] };
    await (mainWindow ? dialog.showMessageBox(mainWindow, failure) : dialog.showMessageBox(failure));
    throw cause;
  } finally { exitBusy = false; }
}

async function finishPendingNetworkRepair(job) {
  if (!job.nativeFinished) return networkRepairState;
  if (!job.settling) {
    job.settling = (async () => {
      // Only the helper's actual termination releases its repair gate. Failed
      // state reload keeps this job pending so a retry cannot spawn another one.
      await controller?.finishNetworkRepair();
      if (job.failure) {
        const code = /^[A-Z][A-Z0-9_]{0,79}$/.test(job.failure.code || '') ? job.failure.code : 'NETWORK_REPAIR_FAILED';
        networkRepairState = { ...job.pending, pending: false, completed: true, success: false, code };
        await log('network repair incomplete', job.failure);
      } else {
        networkRepairState = job.result;
        await log('network repair complete', { code: job.result.code, diagnostic: { skippedAllowRules: job.result.skippedAllowRules } });
      }
      if (networkRepairPending === job) networkRepairPending = null;
    })().catch(async cause => {
      networkRepairState = { ...job.pending, reloadRequired: true, code: 'NETWORK_REPAIR_RELOAD_REQUIRED' };
      await log('network repair state reload incomplete', cause);
    }).finally(() => { job.settling = null; updateTray(); });
  }
  await job.settling;
  return networkRepairState;
}

async function handleLink(url) {
  const kind = classifyNavigation(url, origin);
  if (kind === 'app') { showWindow(); return; }
  if (kind === 'external') {
    const services = { 'https://cleanip.io/claude': 'cleanip', 'https://ippure.com/claude': 'ippure', 'https://ping0.cc/': 'ping0', 'https://claude.ai/': 'claude', 'https://www.tiktok.com/': 'tiktok' };
    showWindow();
    if (exitBusy || quitting || applicationBusy || localState().operation) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
    applicationBusy = true;
    try { await controller.openWebsite(services[url]); }
    catch (cause) {
      await log('managed website open incomplete', cause);
      await dialog.showMessageBox(mainWindow, { type: 'info', title: PRODUCT_NAME, message: '尚未打开受管浏览器。', detail: '请在“应用接入”检查连接和浏览器状态。已有独立浏览器时，请在该窗口访问网站。此链接不会转交系统普通浏览器。', buttons: ['返回'] });
    } finally { applicationBusy = false; }
    return;
  }
  if (kind !== 'report') return;
  const area = screen.getDisplayMatching(mainWindow.getBounds()).workArea;
  const report = new BrowserWindow({ width: Math.min(720, area.width - 24), height: Math.min(840, area.height - 24), title: 'MC Proxy · 连通质量报告', icon: path.join(root, 'frontend/assets/mc-proxy.ico'), backgroundColor: '#f5f7f6', autoHideMenuBar: true, parent: mainWindow, show: false, webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false, session: mainWindow.webContents.session, webSecurity: true, devTools: !app.isPackaged } });
  reportWindows.add(report);
  report.on('closed', () => reportWindows.delete(report));
  report.webContents.setWindowOpenHandler(({ url: next }) => { void handleLink(next).catch(cause => log('report link failed', cause)); return { action: 'deny' }; });
  report.webContents.on('will-navigate', (event, next) => { if (next !== url) { event.preventDefault(); void handleLink(next).catch(cause => log('report navigation failed', cause)); } });
  report.webContents.on('will-attach-webview', event => event.preventDefault());
  report.once('ready-to-show', () => report.show());
  await report.loadURL(url);
}

function installIpc() {
  const claudeBackground = createClaudeBackgroundManager({ userData: app.getPath('userData'), mock: options.mock, openPath: target => shell.openPath(target) });
  const runClaudeBackground = async action => {
    if (exitBusy || quitting || applicationBusy || localState().operation || licenseAdmin?.isBusy()) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
    applicationBusy = true;
    try { return await action(); }
    finally { applicationBusy = false; }
  };
  const changeClaudeStartup = restore => runClaudeBackground(async () => {
    if (!options.mock) {
      const answer = await dialog.showMessageBox(mainWindow, { type: 'warning', title: restore ? '恢复 Claude 后台服务开机设置' : '禁止 Claude 后台服务开机自启',
        message: restore ? '恢复 MC Proxy 为此服务保留的原始开机设置？' : '禁止官方 Claude Cowork 后台服务在下次开机自动启动？',
        detail: restore ? '只恢复本软件成功修改的设置；服务被更新或被其他软件改动时停止操作。不会启动或结束当前服务。'
          : '仅使用 Windows 标准服务管理修改 CoworkVMService 的启动方式，不结束当前服务或任务。下次重启后本地 Cowork 功能可能不可用；Windows 拒绝时不会修改注册表或绕过系统保护。后台服务存在本身不能证明它正在收集数据。',
        buttons: ['取消', restore ? '恢复原设置' : '禁止开机自启'], defaultId: 0, cancelId: 0, noLink: true });
      if (answer.response !== 1) return { changed: false, canceled: true, code: 'CLAUDE_STARTUP_CANCELED' };
    }
    return restore ? claudeBackground.restoreStartup() : claudeBackground.disableStartup();
  });
  const handlers = {
    'mc-window:minimize': () => mainWindow.minimize(),
    'mc-window:close': () => mainWindow.close(),
    'mc-window:quit': () => requestQuit(),
    'mc-window:repair-network': () => requestNetworkRepair(),
    'mc-claude:background': () => runClaudeBackground(() => claudeBackground.inspect()),
    'mc-claude:services': () => runClaudeBackground(() => claudeBackground.openServices()),
    'mc-claude:disable-startup': () => changeClaudeStartup(false),
    'mc-claude:restore-startup': () => changeClaudeStartup(true),
    'mc-window:layout': preset => {
      if(typeof preset!=='string'||!Object.hasOwn(WINDOW_LAYOUTS,preset))throw Object.assign(new Error(),{code:'DESKTOP_IPC_INVALID'});
      const preferred=WINDOW_LAYOUTS[preset],area=screen.getDisplayMatching(mainWindow.getBounds()).workArea;
      const {minWidth,minHeight,...bounds}=fitWindow(area,preferred);
      windowPreset=preset;windowPresetBounds=bounds;
      mainWindow.setMinimumSize(minWidth,minHeight);mainWindow.setBounds(bounds);windowPresetBounds=mainWindow.getBounds();saveWindowLayout();
      return {...currentWindowLayout(),clamped:bounds.width!==preferred.width||bounds.height!==preferred.height};
    },
    'mc-applications:list': () => applications.discover(),
    'mc-applications:launch': async id => {
      if (exitBusy || quitting || applicationBusy || localState().operation) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
      applicationBusy = true;
      try { return await applications.start(id); }
      finally { applicationBusy = false; }
    },
    'mc-applications:stop': async id => {
      const labels = { 'claude-desktop': 'Claude Desktop', 'claude-code': 'Claude Code', 'codex-desktop': 'Codex Desktop', 'codex-cli': 'Codex CLI', terminal: '代理终端' };
      if (typeof id !== 'string' || !Object.hasOwn(labels, id)) throw Object.assign(new Error(), { code: 'APPLICATION_TARGET_INVALID' });
      if (exitBusy || quitting || applicationBusy || localState().operation) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
      applicationBusy = true;
      try {
        if (!options.mock) {
          const answer = await dialog.showMessageBox(mainWindow, { type: 'warning', title: `安全退出 ${labels[id]}`, message: '请先保存内容并结束正在执行的任务。', detail: '将请求应用正常关闭。应用拒绝关闭或进程身份不明确时保留原进程；不会强制结束。', buttons: ['继续运行', '安全退出该应用'], defaultId: 0, cancelId: 0, noLink: true });
          if (answer.response !== 1) return { stopped: false, canceled: true, id };
        }
        return await applications.stop(id);
      } finally { applicationBusy = false; }
    },
    'mc-window:info': () => ({ name: PRODUCT_NAME, edition: distribution.edition, version: app.getVersion(), closeBehavior: 'tray', mock: options.mock, adminAccess, windowLayout:currentWindowLayout(), clientLog: clientLog.status(), networkMonitor: networkLifecycle?.status() || { enabled: false }, networkRepair: networkRepairState || { pending: false, completed: false } }),
    'mc-window:client-log': async () => {
      const actual = await realpath(logPath);
      const info = await lstat(logPath);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink > 1 || actual.toLowerCase() !== path.resolve(logPath).toLowerCase()) throw Object.assign(new Error(), { code: 'DESKTOP_LOG_UNAVAILABLE' });
      if (await shell.openPath(logPath)) throw Object.assign(new Error(), { code: 'DESKTOP_LOG_UNAVAILABLE' });
      return { opened: true };
    },
    'mc-window:diagnostics': async () => {
      const directory = path.join(options.runtimeRoot, 'offline-diagnostics');
      const actual = await realpath(directory);
      if ((await lstat(directory)).isSymbolicLink() || actual.toLowerCase() !== path.resolve(directory).toLowerCase()) throw new Error('Diagnostics directory identity changed');
      const message = await shell.openPath(directory);
      if (message) throw new Error('Unable to open the diagnostics folder');
      return { opened: true };
    },
    'mc-window:support-report': async () => {
      if (exitBusy || quitting || applicationBusy || localState().operation) throw Object.assign(new Error(), { code: 'DESKTOP_BUSY' });
      applicationBusy = true;
      try {
        const report = await controller.createSupportReport();
        const answer = await dialog.showSaveDialog(mainWindow, { title: '保存脱敏故障报告（选择新文件名）', defaultPath: path.join(app.getPath('downloads'), `MC-Proxy-support-${new Date().toISOString().replace(/[:.]/g, '-')}.json`), filters: [{ name: '脱敏故障报告', extensions: ['json'] }] });
        if (answer.canceled || !answer.filePath) return { canceled: true };
        if (path.extname(answer.filePath).toLowerCase() !== '.json') throw Object.assign(new Error(), { code: 'SUPPORT_OUTPUT_INVALID' });
        // Native picker supplies the destination; renderer never supplies a path or report contents.
        try { await writePrivate(answer.filePath, JSON.stringify(report, null, 2) + '\n'); }
        catch (cause) { throw Object.assign(new Error(), { code: cause.code === 'EEXIST' ? 'SUPPORT_OUTPUT_EXISTS' : 'SUPPORT_OUTPUT_FAILED' }); }
        return { saved: true };
      } finally { applicationBusy = false; }
    },
  };
  if (distribution.edition === 'developer') Object.assign(handlers, {
    'mc-license-admin:status': () => licenseAdmin.status(),
    'mc-license-admin:select-store': () => licenseAdmin.selectStore(),
    'mc-license-admin:create-store': () => licenseAdmin.createStore(),
    'mc-license-admin:generate': input => licenseAdmin.generate(input),
    'mc-license-admin:export-delivery': input => licenseAdmin.exportDelivery(input),
  });
  for (const [channel, action] of Object.entries(handlers)) ipcMain.handle(channel, async (event, ...args) => {
    try {
      if (!trustedSender(event, mainWindow?.webContents, origin)) throw Object.assign(new Error(), { code: 'DESKTOP_IPC_UNTRUSTED' });
      if ((!['mc-applications:launch', 'mc-applications:stop', 'mc-window:layout', 'mc-license-admin:generate', 'mc-license-admin:export-delivery'].includes(channel) && args.length) || args.length > 1) throw Object.assign(new Error(), { code: 'DESKTOP_IPC_INVALID' });
      return { ok: true, data: await action(...args) };
    } catch (cause) {
      const error = desktopError(cause);
      await log('desktop action incomplete', { code: error.code });
      return { ok: false, error };
    }
  });
}

async function createWindow() {
  const savedLayout=options.smoke?null:await windowLayouts.read();
  const display = savedLayout?screen.getDisplayMatching(savedLayout.bounds):screen.getDisplayNearestPoint(screen.getCursorScreenPoint());
  const isolatedSession = session.fromPartition('mc-proxy-ui');
  await isolatedSession.setProxy({ mode: 'direct' });
  isolatedSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  isolatedSession.setPermissionCheckHandler(() => false);
  isolatedSession.on('will-download', event => event.preventDefault());
  isolatedSession.webRequest.onBeforeRequest((details, callback) => {
    let allowed = false;
    try { allowed = new URL(details.url).origin === origin || details.url.startsWith('data:image/'); } catch {}
    callback({ cancel: !allowed });
  });
  isolatedSession.webRequest.onBeforeSendHeaders({ urls: [`${origin}/api/*`] }, (details, callback) => {
    callback({ requestHeaders: controllerRequestHeaders(details, { webContents: mainWindow?.webContents, origin, headers: controller.controlHeaders() }) });
  });
  const initialBounds=fitWindow(display.workArea,savedLayout?.bounds||WINDOW_LAYOUTS.wide);
  windowPreset=savedLayout?.preset||'wide';
  if(savedLayout){windowPreset=savedLayout.preset;const b=savedLayout.bounds,a=display.workArea;if(b.x>=a.x&&b.y>=a.y&&b.x+initialBounds.width<=a.x+a.width&&b.y+initialBounds.height<=a.y+a.height){initialBounds.x=b.x;initialBounds.y=b.y;}}
  mainWindow = new BrowserWindow({ ...initialBounds, useContentSize: true, title: PRODUCT_NAME, frame: false, backgroundColor: '#050c18', icon: path.join(root, 'frontend/assets/mc-proxy.ico'), show: false, resizable: true, maximizable: false, fullscreenable: false, autoHideMenuBar: true, webPreferences: { preload: path.join(root, 'desktop/preload.cjs'), nodeIntegration: false, nodeIntegrationInWorker: false, contextIsolation: true, sandbox: true, webSecurity: true, allowRunningInsecureContent: false, webviewTag: false, devTools: !app.isPackaged, session: isolatedSession } });
  windowPresetBounds=mainWindow.getBounds();
  mainWindow.on('resize',saveWindowLayout);mainWindow.on('move',saveWindowLayout);
  mainWindow.on('resized',()=>{const b=mainWindow.getBounds();if(b.width!==windowPresetBounds?.width||b.height!==windowPresetBounds?.height)windowPreset='custom';saveWindowLayout();});
  mainWindow.removeMenu();
  mainWindow.on('page-title-updated', event => event.preventDefault());
  mainWindow.webContents.setWindowOpenHandler(({ url }) => { void handleLink(url).catch(cause => log('link failed', cause)); return { action: 'deny' }; });
  mainWindow.webContents.on('will-navigate', (event, url) => { if (classifyNavigation(url, origin) !== 'app') { event.preventDefault(); void handleLink(url).catch(cause => log('navigation failed', cause)); } });
  mainWindow.webContents.on('will-redirect', (event, url) => { if (classifyNavigation(url, origin) !== 'app') event.preventDefault(); });
  mainWindow.webContents.on('will-attach-webview', event => event.preventDefault());
  mainWindow.webContents.on('render-process-gone', async (_event, details) => {
    await log('renderer stopped', { code: 'DESKTOP_RENDERER_STOPPED' });
    if (!quitting) {
      const answer = await dialog.showMessageBox({ type: 'warning', title: PRODUCT_NAME, message: '显示窗口已停止，后台代理与保护状态仍由 MC Proxy 管理。', buttons: ['重新打开窗口', '保留后台运行'], defaultId: 0, cancelId: 1 });
      if (answer.response === 0) { await mainWindow.loadURL(`${origin}/`); showWindow(); }
    }
  });
  mainWindow.on('close', event => {
    if (quitting) return;
    event.preventDefault();
    mainWindow.hide();
    if (!showedTrayHint && tray) {
      showedTrayHint = true;
      tray.displayBalloon({ title: PRODUCT_NAME, content: '窗口已收起到托盘。代理与断网锁保持当前状态，双击图标可重新打开。', respectQuietTime: true });
    }
  });
  mainWindow.once('ready-to-show', showWindow);
  installIpc();
  await mainWindow.loadURL(`${origin}/`);
  const trayIcon = nativeImage.createFromPath(path.join(root, 'frontend/assets/mc-proxy-256.png')).resize({ width: 32, height: 32 });
  if (trayIcon.isEmpty()) throw new Error('MC Proxy desktop icon is missing');
  tray = new Tray(trayIcon);
  tray.on('double-click', showWindow);
  tray.on('click', showWindow);
  updateTray();
  trayTimer = setInterval(updateTray, 3000);
  trayTimer.unref();
  // A display disconnect or DPI/work-area change must not strand the window.
  const refit = area => {
    const { minWidth, minHeight, ...bounds } = fitWindow(area,mainWindow.getBounds());
    mainWindow.setMinimumSize(minWidth, minHeight);
    mainWindow.setBounds(bounds);
  };
  screen.on('display-removed', () => refit(screen.getPrimaryDisplay().workArea));
  screen.on('display-metrics-changed', () => {
    const area = screen.getDisplayMatching(mainWindow.getBounds()).workArea;
    const bounds = mainWindow.getBounds();
    if (bounds.height > area.height || bounds.width > area.width || bounds.x < area.x || bounds.y < area.y || bounds.x + bounds.width > area.x + area.width || bounds.y + bounds.height > area.y + area.height) refit(area);
  });
}

function handoffPath(argv = process.argv) {
  const flags = argv.filter(value => value.startsWith('--admin-startup-handoff='));
  if (flags.length > 1) throw Object.assign(new Error('管理员启动请求无效。'), { code: 'ADMIN_STARTUP_INVALID' });
  return flags[0]?.slice('--admin-startup-handoff='.length);
}

async function closeAdminGate() {
  if (quitting) return;
  quitting = true;
  adminRestartAbort?.abort();
  await adminRestartTask?.catch(() => {});
  mainWindow?.destroy();
  app.quit();
}

async function acknowledgeAdminHandoff(file) {
  if (!file) return;
  await verifyAdminStartupHandoff(file, { userData: app.getPath('userData') });
  if (!controller || !mainWindow || mainWindow.isDestroyed()) { pendingAdminHandoffs.add(file); return; }
  showWindow();
  if (!mainWindow.isVisible()) throw Object.assign(new Error('管理员窗口尚未显示。'), { code: 'ADMIN_STARTUP_INCOMPLETE' });
  await completeAdminStartupHandoff(file, { userData: app.getPath('userData') });
  pendingAdminHandoffs.delete(file);
}

async function createAdminGate(reason) {
  adminGate = true;
  const page = path.join(root, 'frontend', 'admin-required.html');
  const gateSession = session.fromPartition('mc-proxy-admin-gate');
  await gateSession.setProxy({ mode: 'direct' });
  gateSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  gateSession.setPermissionCheckHandler(() => false);
  gateSession.on('will-download', event => event.preventDefault());
  const resources = ['admin-required.html', 'admin-required.css', 'admin-required.js', 'assets/mc-proxy.svg', 'assets/MonaSans-VF.woff2'].map(file => path.join(root, 'frontend', file));
  gateSession.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !resources.some(file => matchesAdminFileUrl(details.url, file)) }));
  const area = screen.getDisplayNearestPoint(screen.getCursorScreenPoint()).workArea;
  mainWindow = new BrowserWindow({ ...fitWindow(area, { width: 620, height: 680 }), useContentSize: true, title: PRODUCT_NAME, frame: false, show: false,
    backgroundColor: '#0a1122', icon: path.join(root, 'frontend/assets/mc-proxy.ico'), maximizable: false, fullscreenable: false, autoHideMenuBar: true,
    webPreferences: { preload: path.join(root, 'desktop/admin-preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false,
      nodeIntegrationInWorker: false, webSecurity: true, allowRunningInsecureContent: false, webviewTag: false, devTools: !app.isPackaged, session: gateSession } });
  mainWindow.removeMenu();
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => { if (!matchesAdminFileUrl(url, page)) event.preventDefault(); });
  mainWindow.webContents.on('will-redirect', event => event.preventDefault());
  mainWindow.webContents.on('will-attach-webview', event => event.preventDefault());
  mainWindow.on('close', event => { event.preventDefault(); closeAdminGate(); });
  mainWindow.once('ready-to-show', showWindow);
  const handlers = {
    'mc-admin:info': () => ({ productName: PRODUCT_NAME, version: app.getVersion(), reason, adminAccess }),
    'mc-admin:minimize': () => mainWindow.minimize(),
    'mc-admin:close': () => { setTimeout(closeAdminGate, 50); return { closed: true }; },
    'mc-admin:restart': async () => {
      if (adminRestartBusy || quitting || reason === 'account-changed') return { started: false, errorCode: reason === 'account-changed' ? 'ADMIN_ACCOUNT_CHANGED' : 'DESKTOP_BUSY' };
      adminRestartBusy = true;
      adminRestartAbort = new AbortController();
      try {
        const argv = app.isPackaged ? [] : [root];
        for (const [name, value] of [['runtime-root', options.runtimeRoot], ['config-path', options.configPath], ['secrets-path', options.secretsPath], ['core-path', options.corePath], ['control-port', String(options.port)]])
          if (value !== undefined) argv.push(`--${name}`, String(value));
        const executable = await realpath(app.isPackaged ? (process.env.PORTABLE_EXECUTABLE_FILE || process.execPath) : process.execPath);
        adminRestartTask = restartElevated({ executable,
          argv, userData: app.getPath('userData'), signal: adminRestartAbort.signal });
        const result = await adminRestartTask;
        if (result.ready) setTimeout(closeAdminGate, 100);
        return { started: result.ready === true, canceled: result.code === 'ADMIN_RESTART_CANCELED', errorCode: result.code };
      } finally { adminRestartBusy = false; adminRestartAbort = undefined; adminRestartTask = undefined; }
    },
  };
  for (const [channel, handler] of Object.entries(handlers)) ipcMain.handle(channel, async event => {
    if (!adminGate || event.sender !== mainWindow?.webContents || event.senderFrame !== mainWindow.webContents.mainFrame || !matchesAdminFileUrl(event.senderFrame.url, page))
      return { ok: false, error: { code: 'DESKTOP_IPC_UNTRUSTED' } };
    try { return { ok: true, data: await handler() }; }
    catch { return { ok: false, error: { code: 'ADMIN_STARTUP_INCOMPLETE' } }; }
  });
  await mainWindow.loadFile(page);
  showWindow();
}

async function runAcceptance() {
  // Only reachable with explicit --mock --smoke-test. No production config,
  // environment change, external browser, TUN or firewall operation is invoked.
  await mkdir(path.resolve(options.captureDir), { recursive: true });
  await new Promise(resolve => setTimeout(resolve, 1800));
  const results = { app: PRODUCT_NAME, version: app.getVersion(), electron: process.versions.electron, mock: true, screenshots: [], security: await mainWindow.webContents.executeJavaScript(`(async()=>({ desktop:window.mcDesktop?.isDesktop, node:typeof window.require, process:typeof window.process, keys:Object.keys(window.mcDesktop||{}), info:await window.mcDesktop?.getInfo() }))()`) };
  results.controllerAuthorization = await mainWindow.webContents.executeJavaScript(`(async()=>{
    const read=await fetch('/api/status'), readBody=await read.json();
    const write=await fetch('/api/onboarding/preferences',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({externalReport:false})}), writeBody=await write.json();
    return {read:read.status===200&&readBody.ok===true,write:write.status===200&&writeBody.ok===true};
  })()`);
  results.windowLayouts=[];
  for(const preset of Object.keys(WINDOW_LAYOUTS)){
    await mainWindow.webContents.executeJavaScript(`(()=>{const menu=document.querySelector('#layoutMenu');if(menu.hidden)document.querySelector('#layoutButton').click();})()`);
    await new Promise(resolve=>setTimeout(resolve,100));
    await mainWindow.webContents.executeJavaScript(`(()=>{const option=document.querySelector('button[data-layout-preset="${preset}"]');if(!option||option.disabled)throw new Error('Layout option is disabled');option.querySelector('.window-layout-copy').click();})()`);
    await new Promise(resolve=>setTimeout(resolve,500));
    const layout=await mainWindow.webContents.executeJavaScript(`(async()=>({info:(await window.mcDesktop.getInfo()).windowLayout,checked:document.querySelector('button[data-layout-preset][aria-pressed="true"]')?.dataset.layoutPreset,text:document.querySelector('#windowLayoutStatus').textContent,overflow:document.documentElement.scrollWidth>innerWidth}))()`);
    results.windowLayouts.push({preset,...layout});
    if(layout.info.preset!==preset||layout.checked!==preset||layout.overflow)throw new Error('Window layout acceptance failed');
    await writeFile(path.join(options.captureDir,`layout-${preset}.png`),(await mainWindow.webContents.capturePage()).toPNG());
    await mainWindow.webContents.executeJavaScript(`document.querySelector('#layoutCloseButton').click()`);
  }
  for (const size of [[1080, 800], [480, 900], [420, 760], [380, 650]]) {
    mainWindow.setContentSize(...size);
    await new Promise(resolve => setTimeout(resolve, 200));
    const name = `window-${size[0]}x${size[1]}.png`;
    await writeFile(path.join(options.captureDir, name), (await mainWindow.webContents.capturePage()).toPNG());
    results.screenshots.push({ name, ...await mainWindow.webContents.executeJavaScript('({width:innerWidth,height:innerHeight,documentWidth:document.documentElement.scrollWidth,documentHeight:document.documentElement.scrollHeight})') });
  }
  results.closeBehavior = 'tray';
  results.userData = app.getPath('userData');
  results.runtimeRoot = options.runtimeRoot;
  mainWindow.close();
  results.hiddenOnClose = !mainWindow.isVisible();
  results.controllerAliveAfterClose = controller.listening;
  const initialPort = controller.address().port;
  // Launch a second real application process against this exact mock profile.
  // It must exit without creating another controller and wake the existing UI.
  const childExecutable = app.isPackaged && process.env.PORTABLE_EXECUTABLE_FILE ? process.env.PORTABLE_EXECUTABLE_FILE : process.execPath;
  results.singleInstanceLaunchKind = childExecutable === process.execPath ? 'inner-executable' : 'portable-launcher';
  const child = spawn(childExecutable, [...(app.isPackaged ? [] : [root]), '--mock', `--user-data-dir=${app.getPath('userData')}`], { cwd: path.dirname(childExecutable), stdio: 'ignore', windowsHide: true });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('Second desktop instance did not exit')); }, 30000);
    child.once('error', cause => { clearTimeout(timer); reject(cause); });
    child.once('exit', code => { clearTimeout(timer); code === 0 ? resolve() : reject(new Error(`Second desktop instance exited with code ${code}`)); });
  });
  await new Promise(resolve => setTimeout(resolve, 250));
  results.singleInstance = secondInstanceEvents === 1 && controller.address().port === initialPort;
  results.reopened = mainWindow.isVisible();
  // Exercise the actual portable wrapper twice: a shared extraction directory
  // would let the second launch remove the first process's ASAR/DLL files.
  await mainWindow.loadURL(`${origin}/`);
  results.rendererSurvivedSecondLaunch = await mainWindow.webContents.executeJavaScript('Boolean(window.mcDesktop?.isDesktop)');
  results.sandbox = mainWindow.webContents.getLastWebPreferences().sandbox;
  results.contextIsolation = mainWindow.webContents.getLastWebPreferences().contextIsolation;
  results.nodeIntegration = mainWindow.webContents.getLastWebPreferences().nodeIntegration;
  await writeFile(path.join(options.captureDir, 'desktop-smoke.json'), JSON.stringify(results, null, 2));
  if (!results.security.desktop || results.security.node !== 'undefined' || results.security.process !== 'undefined' || !results.controllerAuthorization.read || !results.controllerAuthorization.write || !results.hiddenOnClose || !results.controllerAliveAfterClose || !results.reopened || !results.singleInstance || !results.rendererSurvivedSecondLaunch || !results.sandbox || !results.contextIsolation || results.nodeIntegration) throw new Error('Desktop acceptance failed; inspect desktop-smoke.json');
  await requestQuit({ acceptance: true });
}

{
  app.on('second-instance', (_event, argv) => { secondInstanceEvents++; showWindow(); void Promise.resolve().then(() => acknowledgeAdminHandoff(handoffPath(argv))).catch(cause => log('desktop admin handoff incomplete', cause)); });
  app.on('activate', showWindow);
  app.on('window-all-closed', () => { /* Keep the controller and tray alive. */ });
  app.on('before-quit', event => { if (!quitting) { event.preventDefault(); if (adminGate) closeAdminGate(); else void requestQuit().catch(cause => log('desktop quit request failed', cause)); } });
  app.whenReady().then(async () => {
    assertDistributionLaunch(distribution, { argv: process.argv, env: process.env });
    options = parseLaunchOptions(process.argv, { root, userData: app.getPath('userData'), packaged: app.isPackaged, env: process.env });
    options.runtimeRoot = path.resolve(options.runtimeRoot);
    const access = await startupAccess({ mock: options.mock });
    adminAccess = access.verification || null;
    if (!access.allowed) { await createAdminGate(access.reason === 'ADMIN_CHECK_FAILED' ? 'check-failed' : access.reason === 'ADMIN_CAPABILITY_DENIED' ? 'capability-denied' : 'admin-required'); return; }
    const handoff = handoffPath();
    if (handoff) {
      try { await verifyAdminStartupHandoff(handoff, { userData: app.getPath('userData') }); }
      catch (cause) { await createAdminGate(cause.code === 'ADMIN_ACCOUNT_CHANGED' ? 'account-changed' : 'check-failed'); return; }
    }
    // A locked permissions window must not consume the real client's instance
    // lock: the elevated successor needs to reach the existing business path.
    if (!app.requestSingleInstanceLock()) { quitting = true; app.quit(); return; }
    adminStartupAuthorized = true;
    if (!options.mock && adminAccess?.checked) await log('desktop permission verified', { code: 'ADMIN_VERIFIED', diagnostic: adminAccess });
    licenseAdmin = createLicenseAdmin({ enabled: distribution.edition === 'developer', mock: options.mock,
      settingsPath: path.join(app.getPath('userData'), 'licensing-admin.json'),
      chooseStore: async () => {
        const answer = await dialog.showOpenDialog(mainWindow, { title: '选择已有签发库（包含 server-config.json 的私有目录）',
          properties: ['openDirectory'], ...(!app.isPackaged ? { defaultPath: path.join(root, '.cache/billing-offline-1.5.0') } : {}) });
        return answer.canceled ? null : answer.filePaths[0];
      },
      chooseNewStore: async () => {
        const confirmation = await dialog.showMessageBox(mainWindow, { type: 'warning', title: '创建新的签发库',
          message: '现有正式版安装包不信任新签发库的公钥。', detail: '本次已发布的安装包请使用原有签发库。只有准备重新构建正式版时才创建新库；新库私钥和台账须私有备份。',
          buttons: ['返回并选择原有库', '创建新的签发库'], defaultId: 0, cancelId: 0, noLink: true });
        if (confirmation.response !== 1) return null;
        const answer = await dialog.showSaveDialog(mainWindow, { title: '选择新的私有签发目录（必须尚不存在）',
          defaultPath: path.join(app.getPath('documents'), 'MC-Proxy-Licensing') });
        return answer.canceled ? null : answer.filePath;
      },
      chooseLicenseInput: async () => {
        const answer = await dialog.showOpenDialog(mainWindow, { title: '选择已为此客户签发的有效许可', properties: ['openFile'], filters: [{ name: '签名许可', extensions: ['json'] }] });
        return answer.canceled ? null : answer.filePaths[0];
      },
      chooseOutput: async name => {
        const answer = await dialog.showSaveDialog(mainWindow, { title: name.endsWith('.mcproxy.json') ? '保存客户单文件交付（选择新文件名）' : '保存客户签名许可（选择新文件名）',
          defaultPath: path.join(app.getPath('documents'), name), filters: [{ name: '签名许可', extensions: ['json'] }] });
        return answer.canceled ? null : answer.filePath;
      },
    });
    const corePath = options.mock ? options.corePath : await stableCorePath();
    const licenseConfig = distribution.licenseConfig;
    // Only public engine resources get a revision directory. Browser profiles,
    // seeds, workspaces, connection configuration and licensing stay put.
    const fingerprintRoot = app.isPackaged ? path.join(options.runtimeRoot, FINGERPRINT_BROWSER_INSTALL_DIRECTORY) : path.join(root, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY);
    const fingerprintBundleRoot = app.isPackaged ? path.join(process.resourcesPath, 'fingerprint-browser') : undefined;
    if (fingerprintBundleRoot && !options.mock) {
      // The engine contains only verified public resources. Profiles and prior
      // client configuration remain in user data, independent of uninstall.
      // A damaged component must not block access to connection/recovery UI.
      try { await prepareFingerprintBrowserFromBundle(fingerprintBundleRoot, fingerprintRoot); }
      catch (cause) { await log('bundled fingerprint browser preparation failed', cause); }
    }
    controller = await startController({ host: '127.0.0.1', port: options.port, runtimeRoot: options.runtimeRoot, configPath: options.configPath, secretsPath: options.secretsPath, corePath, mock: options.mock, appVersion: app.getVersion(),
      fingerprintRoot, fingerprintBundleRoot,
      licenseConfig,
      getApplicationPaths: () => applications?.routingPaths() || [],
      onDiagnostic: event => { void log('controller diagnostic', event); },
      requireRelay: !options.mock,
      diagnosticsSourceDirectory: app.isPackaged ? path.join(process.resourcesPath, 'offline-chain-test') : path.join(root, 'tools/offline-chain-test'),
      recoveryAppPath: app.isPackaged ? (process.env.PORTABLE_EXECUTABLE_FILE || process.execPath) : path.join(root, 'dist/p0-unsigned/win-unpacked/MC Proxy.exe'),
    });
    applications = createApplicationManager({ mock: options.mock, applicationProxy: () => controller.applicationProxy() });
    networkLifecycle = createNetworkLifecycle({ mock: options.mock, controller, powerMonitor, onFailure: event => { void log('network lifecycle incomplete', event); } });
    origin = `http://127.0.0.1:${controller.address().port}`;
    await createWindow();
    await log('desktop ready');
    if (handoff) pendingAdminHandoffs.add(handoff);
    for (const file of pendingAdminHandoffs) await acknowledgeAdminHandoff(file).catch(cause => log('desktop admin handoff incomplete', cause));
    if (options.smoke) await runAcceptance();
  }).catch(async cause => {
    await log('desktop startup or acceptance failed', cause);
    if (options?.smoke) {
      await mkdir(path.resolve(options.captureDir), { recursive: true }).catch(() => {});
      await writeFile(path.join(options.captureDir, 'desktop-error.txt'), `${cause.stack || cause}\n`).catch(() => {});
    } else {
      const answer = await dialog.showMessageBox({ type: 'error', title: 'MC Proxy 启动未完成',
        message: '请保留现有配置和恢复记录。', detail: `${cause.code || cause.message}\n\n日志：${logPath}`,
        buttons: options && adminStartupAuthorized ? ['退出', '打开网络修复'] : ['退出'], defaultId: 0, cancelId: 0 });
      if (answer.response === 1) {
        try { await requestNetworkRepair(); } catch {}
      }
    }
    try { await controller?.shutdown(); } catch { showWindow(); return; }
    networkLifecycle?.stop();
    await clientLog.flush();
    quitting = true;
    app.exit(1);
  });
}
