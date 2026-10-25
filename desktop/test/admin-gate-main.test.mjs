import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { fitWindow } from '../window-policy.mjs';
import { matchesAdminFileUrl } from '../admin-file-policy.mjs';
import { FINGERPRINT_BROWSER_CACHE_DIRECTORY, FINGERPRINT_BROWSER_INSTALL_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';

// Run actual main-process function bodies with inert dependencies. No Electron,
// UAC, process, customer profile, licensing store, or filesystem mutation runs.
const source = await readFile(new URL('../main.mjs', import.meta.url), 'utf8');
function fragment(start, end) {
  const from = source.indexOf(start), to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `main function boundary: ${start}`);
  return source.slice(from, to);
}
const gateSource = fragment('function handoffPath(', 'async function runAcceptance(');
const showSource = fragment('function showWindow()', 'function localState()');
const startupStart = source.indexOf('app.whenReady().then(') + 'app.whenReady().then('.length;
const startupEnd = source.indexOf(').catch(async cause => {', startupStart);
const bootSource = source.slice(startupStart, startupEnd);

function harness({ packaged = false, portable = false, access = true, handoff = false, accessReason = 'ADMIN_REQUIRED' } = {}) {
  const actions = [], handlers = new Map(), timers = [];
  const root = path.resolve('D:/synthetic app'), userData = path.resolve('D:/synthetic user/data');
  class FakeWindow {
    constructor(settings) {
      actions.push('window'); this.settings = settings; this.visible = false; this.destroyed = false;
      this.events = new Map(); this.webContents = { mainFrame: { url: '' }, setWindowOpenHandler: value => { this.openHandler = value; }, on: () => {} };
    }
    on(name, callback) { this.events.set(name, callback); }
    once(name, callback) { this.events.set(name, callback); }
    async loadFile(file) { this.webContents.mainFrame.url = pathToFileURL(file).href; }
    removeMenu() {}
    isDestroyed() { return this.destroyed; }
    isMinimized() { return false; }
    isVisible() { return this.visible; }
    show() { actions.push('show'); this.visible = true; }
    focus() {}
    minimize() { actions.push('minimize'); }
    destroy() { actions.push('destroy'); this.destroyed = true; }
  }
  const controller = { address: () => ({ port: 14000 }), shutdown: () => assert.fail('gate must not shut down a proxy') };
  const state = vm.createContext({
    path, pathToFileURL, fitWindow, matchesAdminFileUrl, AbortController, Set, Promise,
    FINGERPRINT_BROWSER_CACHE_DIRECTORY, FINGERPRINT_BROWSER_INSTALL_DIRECTORY,
    root, PRODUCT_NAME: 'MC Proxy', distribution: { edition: 'licensed', licenseConfig: { mode: 'required' } },
    process: { argv: ['MC Proxy.exe', ...(handoff ? ['--admin-startup-handoff=D:/synthetic request.json'] : [])], env: portable ? { PORTABLE_EXECUTABLE_FILE: 'D:/synthetic portable.exe' } : {}, execPath: 'D:/synthetic Electron.exe', resourcesPath: 'D:/synthetic resources' },
    app: { isPackaged: packaged, getPath: name => name === 'userData' ? userData : path.resolve('D:/synthetic ' + name), getVersion: () => '1.6.3',
      requestSingleInstanceLock: () => { actions.push('instance-lock'); return true; }, quit: () => actions.push('quit') },
    BrowserWindow: FakeWindow, session: { fromPartition: () => ({ setProxy: async () => {}, setPermissionRequestHandler: () => {}, setPermissionCheckHandler: () => {}, on: () => {}, webRequest: { onBeforeRequest: () => {} } }) },
    screen: { getDisplayNearestPoint: () => ({ workArea: { x: 0, y: 0, width: 1400, height: 1000 } }), getCursorScreenPoint: () => ({ x: 0, y: 0 }) },
    ipcMain: { handle: (channel, callback) => handlers.set(channel, callback) },
    options: { runtimeRoot: 'D:/synthetic runtime', port: 0, mock: false },
    adminGate: false, adminRestartBusy: false, adminRestartAbort: undefined, adminRestartTask: undefined, adminAccess: null,
    pendingAdminHandoffs: new Set(), quitting: false, mainWindow: undefined, controller: undefined,
    setTimeout: callback => { timers.push(callback); return timers.length; },
    realpath: async file => file,
    verifyAdminStartupHandoff: async () => { actions.push('verify-handoff'); },
    completeAdminStartupHandoff: async () => { actions.push('ack-handoff'); },
    restartElevated: async options => { actions.push('restart'); state.restartOptions = options; return { ready: false, code: 'ADMIN_RESTART_CANCELED' }; },
    assertDistributionLaunch: () => {}, parseLaunchOptions: () => ({ runtimeRoot: 'D:/synthetic runtime', port: 0, mock: false }),
    startupAccess: async () => ({ allowed: access, reason: access ? null : accessReason }),
    createLicenseAdmin: () => { actions.push('license-admin'); return {}; },
    stableCorePath: async () => { actions.push('core'); return 'D:/synthetic core.exe'; },
    prepareFingerprintBrowserFromBundle: async () => { actions.push('fingerprint'); },
    startController: async () => { actions.push('controller-and-license'); return controller; },
    createApplicationManager: () => ({}), createNetworkLifecycle: () => ({}), powerMonitor: {},
    createWindow: async () => { state.mainWindow = new FakeWindow({}); state.mainWindow.show(); },
    log: async () => { actions.push('log-unavailable'); return false; },
    requestQuit: () => assert.fail('gate must not call business quit'),
    windowLayouts: { write: () => assert.fail('gate must not write business layout') },
  });
  vm.runInContext(showSource + gateSource, state);
  const boot = vm.runInContext('(' + bootSource + ')', state);
  return { state, actions, handlers, timers, boot, userData, root };
}

test('real startup shows only the permissions gate before core, fingerprint, license and instance-lock initialization', async () => {
  const h = harness({ access: false, packaged: true });
  await h.boot();
  assert.deepEqual(h.actions, ['window', 'show']);
  assert.equal(h.state.adminGate, true);
  assert.equal(h.state.controller, undefined);
  assert.deepEqual([...h.handlers.keys()].sort(), ['mc-admin:close', 'mc-admin:info', 'mc-admin:minimize', 'mc-admin:restart']);
  const window = h.state.mainWindow;
  const untrusted = { sender: window.webContents, senderFrame: { url: window.webContents.mainFrame.url } };
  assert.equal((await h.handlers.get('mc-admin:restart')(untrusted)).error.code, 'DESKTOP_IPC_UNTRUSTED');
  assert.equal(h.actions.includes('restart'), false);
});

test('capability denial and an incomplete token check lock the main startup with separate reasons', async () => {
  for (const [accessReason,reason] of [['ADMIN_CAPABILITY_DENIED','capability-denied'],['ADMIN_CHECK_FAILED','check-failed']]) {
    const h=harness({access:false,packaged:true,accessReason});
    await h.boot();
    assert.deepEqual(h.actions,['window','show']);
    const window=h.state.mainWindow;
    const event={sender:window.webContents,senderFrame:window.webContents.mainFrame};
    assert.equal((await h.handlers.get('mc-admin:info')(event)).data.reason,reason);
    assert.equal(h.state.controller,undefined);
  }
});

test('real gate IPC accepts the same portable tilde file URL and still rejects query, hash, remote and outside pages', async () => {
  const h = harness({ access: false, packaged: true, portable: true });
  h.state.root = path.resolve('D:/ADMINI~1/Temp/portable app');
  await h.boot();
  const window = h.state.mainWindow, original = window.webContents.mainFrame.url;
  const literalTilde = original.replace(/%7e/gi, '~');
  assert.notEqual(original, literalTilde, 'synthetic portable URL must exercise Node/Chromium tilde encoding');
  window.webContents.mainFrame.url = literalTilde;
  const event = { sender: window.webContents, senderFrame: window.webContents.mainFrame };
  assert.equal((await h.handlers.get('mc-admin:info')(event)).ok, true);
  for (const bad of [literalTilde + '?x=1', literalTilde + '#fragment', 'https://fixture.invalid/admin-required.html', literalTilde.replace('admin-required.html', 'index.html')]) {
    window.webContents.mainFrame.url = bad;
    assert.equal((await h.handlers.get('mc-admin:info')(event)).error.code, 'DESKTOP_IPC_UNTRUSTED');
  }
  assert.equal(h.actions.includes('restart'), false);
});

test('real startup rejects a switched UAC account before touching any business component and continues when logging returns false', async () => {
  const denied = harness({ packaged: true, handoff: true });
  denied.state.verifyAdminStartupHandoff = async () => { denied.actions.push('verify-handoff'); throw Object.assign(new Error(), { code: 'ADMIN_ACCOUNT_CHANGED' }); };
  await denied.boot();
  assert.deepEqual(denied.actions, ['verify-handoff', 'window', 'show']);
  const event = { sender: denied.state.mainWindow.webContents, senderFrame: denied.state.mainWindow.webContents.mainFrame };
  assert.equal((await denied.handlers.get('mc-admin:info')(event)).data.reason, 'account-changed');
  assert.equal((await denied.handlers.get('mc-admin:restart')(event)).data.errorCode, 'ADMIN_ACCOUNT_CHANGED');
  assert.equal(denied.actions.includes('restart'), false);
  const allowed = harness({ packaged: true });
  await allowed.boot();
  assert.deepEqual(allowed.actions, ['instance-lock', 'license-admin', 'core', 'fingerprint', 'controller-and-license', 'window', 'show', 'log-unavailable']);
  assert.equal(allowed.actions.includes('quit'), false);
});

test('real permission restart preserves source/installed/portable executable selection, fixed options and same user data', async () => {
  for (const flags of [{}, { packaged: true }, { packaged: true, portable: true }]) {
    const h = harness({ ...flags, access: false }); await h.boot();
    const event = { sender: h.state.mainWindow.webContents, senderFrame: h.state.mainWindow.webContents.mainFrame };
    const result = await h.handlers.get('mc-admin:restart')(event);
    assert.equal(result.ok, true); assert.equal(result.data.canceled, true); assert.equal(result.data.started, false);
    const launch = h.state.restartOptions;
    assert.equal(launch.userData, h.userData);
    assert.equal(launch.executable, flags.portable ? 'D:/synthetic portable.exe' : 'D:/synthetic Electron.exe');
    assert.deepEqual(Array.from(launch.argv), [...(flags.packaged ? [] : [h.root]), '--runtime-root', path.resolve('D:/synthetic runtime'), '--control-port', '0']);
    assert.equal(h.state.mainWindow.isVisible(), true); assert.equal(h.state.adminRestartBusy, false);
    assert.equal(h.actions.includes('quit'), false); assert.equal(h.timers.length, 0);
  }
});

test('real gate close aborts a pending restart and waits for cleanup without invoking proxy shutdown or layout persistence', async () => {
  const h = harness({ access: false }); await h.boot();
  h.state.restartElevated = options => new Promise(resolve => options.signal.addEventListener('abort', () => { h.actions.push('abort-cleanup'); resolve({ ready: false, code: 'ADMIN_RESTART_CANCELED' }); }, { once: true }));
  const event = { sender: h.state.mainWindow.webContents, senderFrame: h.state.mainWindow.webContents.mainFrame };
  const restart = h.handlers.get('mc-admin:restart')(event);
  await new Promise(resolve => setImmediate(resolve));
  await h.state.closeAdminGate(); await restart;
  assert.deepEqual(h.actions.slice(-3), ['abort-cleanup', 'destroy', 'quit']);
  assert.equal(h.state.quitting, true);
});

test('real handoff acknowledgment requires the verified business window to be visibly shown', async () => {
  const h = harness();
  await h.state.acknowledgeAdminHandoff('D:/request.json');
  assert.equal(h.state.pendingAdminHandoffs.has('D:/request.json'), true);
  assert.equal(h.actions.includes('ack-handoff'), false);
  await h.boot();
  assert.equal(h.state.mainWindow.isVisible(), true);
  assert.equal(h.actions.includes('ack-handoff'), true);
  assert.equal(h.state.pendingAdminHandoffs.size, 0);
  h.state.mainWindow.visible = false; h.state.mainWindow.show = () => {};
  await assert.rejects(h.state.acknowledgeAdminHandoff('D:/other-request.json'), { code: 'ADMIN_STARTUP_INCOMPLETE' });
  assert.equal(h.actions.filter(action => action === 'ack-handoff').length, 1);
});
