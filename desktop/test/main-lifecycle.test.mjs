import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import { desktopError, exitNotice, trustedSender, PRODUCT_NAME, classifyNavigation, fitWindow, WINDOW_LAYOUTS } from '../window-policy.mjs';
import { createClaudeBackgroundManager } from '../claude-background.mjs';

// Exercise the main process functions with inert Electron dependencies. No
// controller, native dialog, application process or system setting is started.
async function harness(start = async () => ({ started: true }), stop = async () => ({ stopped: true }), { edition = 'developer' } = {}) {
  const source = await readFile(new URL('../main.mjs', import.meta.url), 'utf8');
  const section = (start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
  const handlers = new Map(), events = [];
  const claudeManager = createClaudeBackgroundManager({ userData: path.resolve('.cache/claude-inert-test'), mock: true });
  const webContents = { mainFrame: { url: 'http://127.0.0.1:14000/' }, isDestroyed: () => false };
  const state = vm.createContext({
    PRODUCT_NAME, distribution: { edition }, licenseAdmin: { status: async () => ({ enabled: true }), isBusy: () => false,
      selectStore: async () => { events.push('select-signing-store'); return { configured: true }; },
      createStore: async () => { events.push('create-signing-store'); return { configured: true }; },
      generate: async input => { events.push('sign-customer'); return { saved: true, action: input.action }; } },
    desktopError, exitNotice, trustedSender, origin: 'http://127.0.0.1:14000',
    createClaudeBackgroundManager: () => claudeManager, claudeManager, shell: { openPath: () => assert.fail('mock must not open native services') },
    controller: { state: { proxy: { running: true } }, shutdown: async () => { events.push('shutdown'); } },
    applications: { start, stop, discover: async () => { events.push('discover'); return { apps: [] }; } },
    mainWindow: { webContents, getBounds:()=>({x:0,y:0,width:1080,height:800}),setBounds:bounds=>events.push(bounds),setMinimumSize:()=>{} }, options: { mock: true }, applicationBusy: false, exitBusy: false, quitting: false, networkRepairPending: null, networkRepairState: null,
    WINDOW_LAYOUTS,fitWindow,screen:{getDisplayMatching:()=>({workArea:{x:-1000,y:0,width:1000,height:720}})},windowPreset:'custom',windowPresetBounds:undefined,windowSaveTimer:undefined,clearTimeout,windowLayouts:{write:async()=>{}},saveWindowLayout:()=>{},currentWindowLayout:()=>({preset:'custom',bounds:{width:1080,height:800,x:0,y:0}}),
    ipcMain: { handle: (channel, action) => handlers.set(channel, action) }, app: { getVersion: () => 'test', getPath: () => path.resolve('.cache/claude-inert-test'), quit: () => { events.push('quit'); } },
    dialog: { showMessageBox: async (...args) => { events.push(args.at(-1).message); return { response: 0 }; } },
    showWindow: () => {}, updateTray: () => {}, log: async (event, cause) => { events.push(`${event}:${cause?.code || ''}`); },
    launchNetworkRepair: () => { assert.fail('must not start repair'); }, reportWindows: new Set(), clearInterval, trayTimer: undefined, tray: undefined,
    path, root: 'D:/MC-test', process: { pid: 123 }, logPath: path.resolve('D:/MC-test/desktop.log'),
    clientLog: { status: () => ({ ok: true, errorCode: null, lastFailureAt: null }), flush: async () => {} }, networkLifecycle: undefined, adminAccess: null,
  });
  vm.runInContext([
    section('function localState()', 'function updateTray()'),
    section('async function requestQuit(', 'async function requestNetworkRepair()'),
    section('async function requestNetworkRepair()', 'async function handleLink('),
    section('function installIpc()', 'async function createWindow()'),
    'installIpc();',
  ].join('\n'), state);
  return { state, handlers, events, event: { sender: webContents, senderFrame: webContents.mainFrame } };
}

test('window layout IPC only accepts fixed presets and clamps them to the current display',async()=>{
  const h=await harness(),change=h.handlers.get('mc-window:layout');
  assert.equal((await change(h.event,'wide')).ok,true);
  const bounds=h.events.find(e=>typeof e==='object');assert.ok(bounds.x>=-1000&&bounds.x+bounds.width<=0&&bounds.height<=720);
  for(const arg of ['unknown',{width:100000},null])assert.equal((await change(h.event,arg)).error.code,'DESKTOP_IPC_INVALID');
  assert.equal((await change(h.event,'wide','extra')).error.code,'DESKTOP_IPC_INVALID');
  assert.equal((await change({sender:{},senderFrame:h.event.senderFrame},'wide')).error.code,'DESKTOP_IPC_UNTRUSTED');
});

test('signing IPC only exists in the developer edition and rejects untrusted pages and surplus arguments', async () => {
  const licensed = await harness(undefined, undefined, { edition: 'licensed' });
  assert.equal([...licensed.handlers.keys()].some(name => name.startsWith('mc-license-admin:')), false);
  const h = await harness();
  assert.equal((await h.handlers.get('mc-license-admin:status')(h.event)).data.enabled, true);
  const sign = h.handlers.get('mc-license-admin:generate');
  assert.equal((await sign({ sender: {}, senderFrame: h.event.senderFrame }, { action: 'trial' })).error.code, 'DESKTOP_IPC_UNTRUSTED');
  assert.equal((await sign(h.event, { action: 'trial' }, 'extra')).error.code, 'DESKTOP_IPC_INVALID');
  assert.equal((await h.handlers.get('mc-license-admin:select-store')(h.event, 'renderer-path')).error.code, 'DESKTOP_IPC_INVALID');
  assert.equal(h.events.includes('sign-customer'), false);
  assert.equal((await sign(h.event, { action: 'trial' })).data.saved, true);
});

test('application launch blocks quit, repair and duplicate launch until verification and launch finish', async () => {
  let release, calls = 0;
  const pending = new Promise(resolve => { release = resolve; });
  const h = await harness(async () => { calls++; await pending; return { started: true }; });
  const launch = h.handlers.get('mc-applications:launch');
  const first = launch(h.event, 'terminal');
  assert.equal(h.state.applicationBusy, true);
  assert.equal(vm.runInContext('localState().operation.stage', h.state), 'starting-application');
  assert.equal((await h.handlers.get('mc-window:quit')(h.event)).error.code, 'DESKTOP_BUSY');
  assert.equal(h.events.includes('shutdown'), false);
  const repair = await h.handlers.get('mc-window:repair-network')(h.event);
  assert.equal(repair.error.code, 'DESKTOP_BUSY');
  assert.equal((await launch(h.event, 'terminal')).error.code, 'DESKTOP_BUSY');
  assert.equal(calls, 1);
  release(); assert.equal((await first).data.started, true);
  assert.equal(h.state.applicationBusy, false);
  assert.equal(vm.runInContext('localState().operation', h.state), null);
});

test('main IPC failures release launch state and expose no raw host exception', async () => {
  const h = await harness(async () => { throw Object.assign(new Error('private-user-path secret'), { code: 'APPLICATION_LAUNCH_FAILED' }); });
  const result = await h.handlers.get('mc-applications:launch')(h.event, 'terminal');
  assert.equal(result.ok, false); assert.equal(result.error.code, 'APPLICATION_LAUNCH_FAILED');
  assert.doesNotMatch(result.error.message, /private|secret/);
  assert.equal(h.state.applicationBusy, false);
  assert.equal((await h.handlers.get('mc-window:info')(h.event)).data.version, 'test');
});

test('desktop info exposes bounded log failure state without paths, causes or network metadata', async () => {
  const h = await harness();
  h.state.clientLog.status = () => ({ ok: false, errorCode: 'DESKTOP_LOG_WRITE_FAILED', lastFailureAt: '2026-10-06T00:00:00.000Z' });
  h.state.networkLifecycle = { status: () => ({ enabled: true, phase: 'failed', errorCode: 'NETWORK_OBSERVATION_FAILED' }) };
  const info = (await h.handlers.get('mc-window:info')(h.event)).data;
  assert.equal(info.clientLog.errorCode, 'DESKTOP_LOG_WRITE_FAILED'); assert.equal(info.networkMonitor.errorCode, 'NETWORK_OBSERVATION_FAILED');
  assert.doesNotMatch(JSON.stringify(info), /D:\/|desktop\.log|address|cause|stack/);
});

test('main IPC rejects untrusted senders and extra arguments before running an action', async () => {
  const h = await harness();
  const list = h.handlers.get('mc-applications:list');
  assert.equal((await list(null)).error.code, 'DESKTOP_IPC_UNTRUSTED');
  assert.equal((await list({ ...h.event, senderFrame: { url: 'http://127.0.0.1:14000/' } })).error.code, 'DESKTOP_IPC_UNTRUSTED');
  assert.equal((await list(h.event, 'unexpected')).error.code, 'DESKTOP_IPC_INVALID');
  assert.equal(h.events.includes('discover'), false);
  assert.equal((await list(h.event)).ok, true);
  assert.equal(h.events.includes('discover'), true);
});

test('main IPC cannot launch an application while exit or repair is already pending', async () => {
  const h = await harness(async () => { assert.fail('must not start'); });
  h.state.exitBusy = true;
  assert.equal((await h.handlers.get('mc-applications:launch')(h.event, 'terminal')).error.code, 'DESKTOP_BUSY');
  h.state.exitBusy = false; h.state.quitting = true;
  assert.equal((await h.handlers.get('mc-applications:launch')(h.event, 'terminal')).error.code, 'DESKTOP_BUSY');
  assert.equal(h.state.applicationBusy, false);
});

test('Claude service IPC is manual, fixed, protected by sender and argument checks, and blocked by existing operations', async () => {
  const h = await harness(); let calls = 0;
  h.state.claudeManager.inspect = async () => { calls++; return { state: 'running', mock: true }; };
  const inspect = h.handlers.get('mc-claude:background'), open = h.handlers.get('mc-claude:services');
  assert.equal(calls, 0, 'installing IPC must not inspect services');
  assert.equal(h.handlers.has('mc-claude:disable-startup-compat'), false);
  for (const action of [inspect, open, h.handlers.get('mc-claude:disable-startup'), h.handlers.get('mc-claude:restore-startup')]) {
    assert.equal((await action({ sender: {}, senderFrame: h.event.senderFrame })).error.code, 'DESKTOP_IPC_UNTRUSTED');
    assert.equal((await action(h.event, 'renderer-selected-service')).error.code, 'DESKTOP_IPC_INVALID');
    assert.equal((await action(h.event, 'one', 'two')).error.code, 'DESKTOP_IPC_INVALID');
    for (const gate of ['exitBusy', 'quitting', 'applicationBusy']) {
      h.state[gate] = true; assert.equal((await action(h.event)).error.code, 'DESKTOP_BUSY'); h.state[gate] = false;
    }
    h.state.controller.state.operation = { stage: 'restoring' };
    assert.equal((await action(h.event)).error.code, 'DESKTOP_BUSY'); delete h.state.controller.state.operation;
    h.state.licenseAdmin.isBusy = () => true;
    assert.equal((await action(h.event)).error.code, 'DESKTOP_BUSY'); h.state.licenseAdmin.isBusy = () => false;
  }
  assert.equal(calls, 0);
  assert.equal((await inspect(h.event)).data.mock, true); assert.equal(calls, 1);
  assert.equal((await open(h.event)).data.opened, false); assert.equal(h.state.applicationBusy, false);
});

test('Claude service inspection prevents overlapping native work and releases its gate on failure without leaking host errors', async () => {
  const h = await harness(); let release;
  h.state.claudeManager.inspect = () => new Promise(resolve => { release = resolve; });
  const inspect = h.handlers.get('mc-claude:background'), first = inspect(h.event);
  assert.equal(h.state.applicationBusy, true);
  assert.equal((await h.handlers.get('mc-claude:services')(h.event)).error.code, 'DESKTOP_BUSY');
  assert.equal((await h.handlers.get('mc-applications:launch')(h.event, 'terminal')).error.code, 'DESKTOP_BUSY');
  release({ state: 'unknown' }); assert.equal((await first).ok, true); assert.equal(h.state.applicationBusy, false);
  h.state.claudeManager.inspect = async () => { throw Object.assign(new Error('secret service path'), { code: 'CLAUDE_BACKGROUND_CHECK_FAILED' }); };
  const failed = await inspect(h.event);
  assert.equal(failed.error.code, 'CLAUDE_BACKGROUND_CHECK_FAILED'); assert.doesNotMatch(JSON.stringify(failed), /secret|path/);
  assert.equal(h.state.applicationBusy, false);
});

test('Claude startup mutation confirms in the native main process with default cancel and never stops a service or task', async () => {
  const h = await harness(); h.state.options.mock = false; let changes = 0;
  h.state.claudeManager.disableStartup = async () => { changes++; return { changed: true, state: 'running', startMode: 'disabled' }; };
  h.state.claudeManager.restoreStartup = async () => { changes++; return { changed: true, state: 'running', startMode: 'automatic' }; };
  for (const channel of ['mc-claude:disable-startup', 'mc-claude:restore-startup']) {
    h.state.dialog.showMessageBox = async (_window, options) => {
      assert.equal(options.defaultId, 0); assert.equal(options.cancelId, 0); assert.equal(options.buttons[0], '取消');
      if (channel === 'mc-claude:disable-startup') assert.match(options.detail, /Windows 拒绝时不会修改注册表或绕过系统保护/);
      return { response: 0 };
    };
    const canceled = await h.handlers.get(channel)(h.event);
    assert.equal(canceled.data.canceled, true); assert.equal(canceled.data.changed, false); assert.equal(changes, 0);
    h.state.dialog.showMessageBox = async () => ({ response: 1 });
    assert.equal((await h.handlers.get(channel)(h.event)).data.state, 'running'); assert.equal(changes, 1); changes = 0;
  }
  assert.equal(h.events.includes('shutdown'), false); assert.equal(h.state.applicationBusy, false);
});

test('network repair preserves its primary failure when reloading state also fails', async () => {
  const h = await harness();
  h.state.dialog.showMessageBox = async () => ({ response: 1 });
  h.state.controller.beginNetworkRepair = async () => {};
  h.state.controller.finishNetworkRepair = async () => { throw Object.assign(new Error('reload failed'), { code: 'NETWORK_LOCK_TIMEOUT' }); };
  h.state.launchNetworkRepair = async ({ stopSessions }) => {
    await stopSessions();
    throw Object.assign(new Error('browser identity unreadable'), { code: 'PROCESS_UNREADABLE', reportPath: 'D:/MC-test/result.json' });
  };
  await assert.rejects(h.state.requestNetworkRepair(), error => error.code === 'PROCESS_UNREADABLE' && error.reportPath.endsWith('result.json'));
  assert.equal(h.state.exitBusy, false);
  assert.ok(h.events.some(item => item.includes('network repair state reload incomplete:NETWORK_LOCK_TIMEOUT')));
  assert.ok(h.events.some(item => item.includes('network repair incomplete:PROCESS_UNREADABLE')));
});

test('a successful helper with failed state reload preserves the repair report', async () => {
  const h = await harness();
  h.state.dialog.showMessageBox = async () => ({ response: 1 });
  h.state.controller.beginNetworkRepair = async () => {};
  h.state.controller.finishNetworkRepair = async () => { throw Object.assign(new Error('reload failed'), { code: 'NETWORK_LOCK_TIMEOUT' }); };
  h.state.launchNetworkRepair = async ({ stopSessions }) => { await stopSessions(); return { completed: true, reportPath: 'D:/MC-test/result.json' }; };
  await assert.rejects(h.state.requestNetworkRepair(), error => error.code === 'NETWORK_LOCK_TIMEOUT' && error.reportPath.endsWith('result.json'));
  assert.equal(h.state.exitBusy, false);
});

test('pending repair retains mutation gates, rejects quit and duplicate helpers, and exposes polling state', async () => {
  const h=await harness();let resolve, helpers=0, reloads=0;
  const completion=new Promise(done=>{resolve=done;});
  h.state.dialog.showMessageBox=async()=>({response:1});
  h.state.controller.beginNetworkRepair=async()=>{};
  h.state.controller.finishNetworkRepair=async()=>{reloads++;};
  h.state.launchNetworkRepair=async({stopSessions})=>{helpers++;await stopSessions();return {pending:true,completed:false,requestId:'request-1',reportPath:'D:/MC-test/result.json',completion};};
  const first=await h.state.requestNetworkRepair();assert.equal(first.pending,true);assert.equal('completion'in first,false);
  assert.equal(h.state.exitBusy,false);assert.equal(vm.runInContext('localState().operation.stage',h.state),'repairing-network');
  assert.equal((await h.state.requestNetworkRepair()).requestId,'request-1');assert.equal(helpers,1);assert.equal(reloads,0);
  assert.equal((await h.handlers.get('mc-window:info')(h.event)).data.networkRepair.pending,true);
  assert.equal((await h.handlers.get('mc-applications:launch')(h.event,'terminal')).error.code,'DESKTOP_BUSY');
  await h.state.requestQuit();assert.equal(h.events.includes('shutdown'),false);
  resolve({pending:false,completed:true,success:true,requestId:'request-1',reportPath:first.reportPath,code:'LOCAL_FIREWALL_RESTORED'});
  await new Promise(done=>setImmediate(done));
  assert.equal(reloads,1);assert.equal(h.state.networkRepairPending,null);
  assert.equal((await h.handlers.get('mc-window:info')(h.event)).data.networkRepair.success,true);
});

test('finished repair with reload failure remains pending and retries reload without another helper', async () => {
  const h=await harness();let resolve, helpers=0, reloads=0;
  const completion=new Promise(done=>{resolve=done;});
  h.state.dialog.showMessageBox=async()=>({response:1});h.state.controller.beginNetworkRepair=async()=>{};
  h.state.controller.finishNetworkRepair=async()=>{if(++reloads===1)throw new Error('controlled reload failure');};
  h.state.launchNetworkRepair=async({stopSessions})=>{helpers++;await stopSessions();return {pending:true,completed:false,requestId:'request-2',reportPath:'D:/MC-test/result.json',completion};};
  await h.state.requestNetworkRepair();resolve({completed:true,success:true,requestId:'request-2',code:'LOCAL_WFP_LOCK_RELEASED'});
  await new Promise(done=>setImmediate(done));
  assert.equal(h.state.networkRepairState.reloadRequired,true);assert.equal(h.state.networkRepairState.pending,true);
  assert.equal((await h.state.requestNetworkRepair()).completed,true);assert.equal(reloads,2);assert.equal(helpers,1);
});

test('safe quit permits cancellable connection startup but never a pending firewall helper',async()=>{
  const h=await harness();h.state.dialog.showMessageBox=async()=>({response:1});
  h.state.controller.isConnecting=()=>true;h.state.controller.state.operation={stage:'starting-core'};
  await h.state.requestQuit();assert.equal(h.events.includes('shutdown'),true);assert.equal(h.events.includes('quit'),true);
});

test('client log IPC opens only the verified fixed log and rejects arguments and changed identity', async () => {
  const h = await harness(), opened = [];
  h.state.realpath = async file => file;
  h.state.lstat = async () => ({ isFile: () => true, isSymbolicLink: () => false });
  h.state.shell = { openPath: async file => { opened.push(file); return ''; } };
  const open = h.handlers.get('mc-window:client-log');
  assert.equal((await open(h.event, 'D:/secret.txt')).error.code, 'DESKTOP_IPC_INVALID');
  assert.equal((await open(h.event)).ok, true);
  assert.deepEqual(opened, [path.resolve('D:/MC-test/desktop.log')]);
  h.state.realpath = async () => 'D:/secret.txt';
  assert.equal((await open(h.event)).error.code, 'DESKTOP_LOG_UNAVAILABLE');
  assert.equal(opened.length, 1);
});


test('safe application stop blocks quit and duplicate work, validates target, and always releases busy state', async () => {
  let release, calls = 0;
  const pending = new Promise(resolve => { release = resolve; });
  const h = await harness(undefined, async id => { calls++; assert.equal(id, 'claude-desktop'); await pending; return { stopped: true }; });
  const stop = h.handlers.get('mc-applications:stop');
  assert.equal((await stop(h.event, 'unknown')).error.code, 'APPLICATION_TARGET_INVALID');
  assert.equal((await stop(h.event, 'claude-desktop', 'extra')).error.code, 'DESKTOP_IPC_INVALID');
  const first = stop(h.event, 'claude-desktop');
  assert.equal((await h.handlers.get('mc-window:quit')(h.event)).error.code, 'DESKTOP_BUSY');
  assert.equal(h.events.includes('shutdown'), false);
  assert.equal((await stop(h.event, 'claude-desktop')).error.code, 'DESKTOP_BUSY');
  release(); assert.equal((await first).data.stopped, true);
  assert.equal(calls, 1); assert.equal(h.state.applicationBusy, false);
});

test('external report links use the managed browser and never fall back to the system browser', async () => {
  const source = await readFile(new URL('../main.mjs', import.meta.url), 'utf8');
  const body = source.slice(source.indexOf('async function handleLink('), source.indexOf('function installIpc()'));
  const opened = [], notices = [];
  const state = vm.createContext({ classifyNavigation, origin: 'http://127.0.0.1:14000',
    showWindow() {}, exitBusy: false, quitting: false, applicationBusy: false, localState: () => ({}),
    controller: { openWebsite: async service => { opened.push(service); if (service === 'claude') throw new Error('unavailable'); } },
    shell: { openExternal: () => assert.fail('must never use an unprotected system browser') },
    mainWindow: {}, PRODUCT_NAME, log: async () => {}, dialog: { showMessageBox: async (...args) => { notices.push(args.at(-1)); } },
  });
  vm.runInContext(body, state);
  await state.handleLink('https://ping0.cc/'); assert.deepEqual(opened, ['ping0']);
  await state.handleLink('https://claude.ai/'); assert.equal(notices.length, 1);
  await state.handleLink('https://untrusted.example/'); assert.deepEqual(opened, ['ping0', 'claude']);
  assert.equal(state.applicationBusy, false);
});
