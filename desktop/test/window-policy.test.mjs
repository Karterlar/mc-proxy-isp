import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fitWindow, parseLaunchOptions, classifyNavigation, trustedSender, controllerRequestHeaders, exitNotice, desktopError } from '../window-policy.mjs';

test('workspace window fits 100%, 125% and 150% scaled work areas, including secondary monitors and compact screens', () => {
  for (const [area, expected] of [
    [{ x: 0, y: 0, width: 1920, height: 1040 }, { width: 1080, height: 800, x: 420, y: 120 }],
    [{ x: 0, y: 0, width: 1536, height: 824 }, { width: 1080, height: 800, x: 228, y: 12 }],
    [{ x: 0, y: 0, width: 1280, height: 680 }, { width: 1080, height: 656, x: 100, y: 12 }],
    [{ x: -1280, y: -20, width: 1280, height: 680 }, { width: 1080, height: 656, x: -1180, y: -8 }],
    [{ x: 0, y: 0, width: 720, height: 960 }, { width: 696, height: 800, x: 12, y: 80 }],
    [{ x: 0, y: 0, width: 320, height: 480 }, { width: 296, height: 456, x: 12, y: 12 }],
  ]) {
    const window = fitWindow(area);
    assert.deepEqual(window, { ...expected, minWidth: Math.min(380, expected.width), minHeight: Math.min(650, expected.height) });
    assert.ok(window.width <= 1080);
    assert.ok(window.height <= 800);
    assert.ok(window.x >= area.x && window.y >= area.y);
    assert.ok(window.x + window.width <= area.x + area.width);
    assert.ok(window.y + window.height <= area.y + area.height);
    assert.ok(window.minHeight <= window.height && window.minWidth <= window.width);
  }
});

test('desktop origin cannot be impersonated by credentials, suffixes, privileged schemes or arbitrary routes', () => {
  const origin = 'http://127.0.0.1:41234';
  assert.equal(classifyNavigation(`${origin}/`, origin), 'app');
  assert.equal(classifyNavigation(`${origin}/index.html`, origin), 'app');
  assert.equal(classifyNavigation(`${origin}/reports/quality/01234567-89ab-4def-8abc-0123456789ab/ping0`, origin), 'report');
  assert.equal(classifyNavigation('https://cleanip.io/claude', origin), 'external');
  for (const url of ['http://127.0.0.1:41235/', 'http://127.0.0.1.evil.test:41234/', 'http://x@127.0.0.1:41234/', `${origin}/api/status`, `${origin}/?remote=1`, 'file:///C:/Windows/System32/cmd.exe', 'javascript:alert(1)', 'https://cleanip.io.evil.test/claude', 'https://cleanip.io/claude?redirect=evil', 'https://cleanip.io/unknown']) assert.equal(classifyNavigation(url, origin), 'blocked');
});

test('desktop IPC only trusts the primary app frame of the exact window', () => {
  const origin = 'http://127.0.0.1:41234';
  const frame = { url: `${origin}/` };
  const contents = { mainFrame: frame };
  assert.equal(trustedSender({ sender: contents, senderFrame: frame }, contents, origin), true);
  assert.equal(trustedSender({ sender: {}, senderFrame: frame }, contents, origin), false);
  assert.equal(trustedSender({ sender: contents, senderFrame: { url: frame.url } }, contents, origin), false);
  frame.url = 'https://example.com/';
  assert.equal(trustedSender({ sender: contents, senderFrame: frame }, contents, origin), false);
  assert.equal(trustedSender(null, null, origin), false);
  assert.equal(trustedSender({ sender: contents, senderFrame: frame }, { ...contents, isDestroyed: () => true }, origin), false);
  assert.equal(trustedSender({ get sender() { throw new Error('destroyed frame'); } }, contents, origin), false);
});

test('control credential is injected only for the current primary app frame and exact controller origin', () => {
  const origin = 'http://127.0.0.1:41234', frame = { url: origin + '/' }, contents = { id: 3, mainFrame: frame };
  const settings = { origin, webContents: contents, headers: { 'x-mc-control-token': 'PRIVATE_SESSION' } };
  const details = { url: origin + '/api/status', webContentsId: 3, frame, initiatorOrigin: origin, requestHeaders: { accept: 'application/json', 'X-MC-Control-Token': 'FORGED' } };
  assert.equal(controllerRequestHeaders(details, settings)['x-mc-control-token'], 'PRIVATE_SESSION');
  for (const patch of [{ webContentsId: 4 }, { frame: { url: frame.url } }, { frame: null }, { initiatorOrigin: 'https://evil.example' }, { url: 'https://evil.example/api/status' }, { url: origin + '/app.js' }]) {
    assert.deepEqual(controllerRequestHeaders({ ...details, ...patch }, settings), { accept: 'application/json' });
  }
  frame.url = origin + '/reports/quality/01234567-89ab-4def-8abc-0123456789ab/ping0';
  assert.equal(controllerRequestHeaders(details, settings)['x-mc-control-token'], undefined);
});

test('quit semantics retain lock and require confirmation for active, locked or incomplete lock state', () => {
  assert.equal(exitNotice({}).requiresConfirmation, false);
  assert.equal(exitNotice({ operation: { stage: 'checking' } }).blocked, true);
  assert.equal(exitNotice({ proxy: { running: true } }).requiresConfirmation, true);
  assert.equal(exitNotice({ browser: { running: true } }).requiresConfirmation, true);
  for (const state of ['locked', 'locking', 'error', 'restore-failed', 'conflict', 'unknown']) {
    const notice = exitNotice({ networkLock: { state } });
    assert.equal(notice.requiresConfirmation, true);
    assert.match(notice.detail, /不会自动恢复直连/);
  }
});

test('mock has an isolated runtime, packaged runtime remains outside ASAR, and acceptance rejects live mode', () => {
  const context = { root: 'D:/ExampleProject', userData: 'C:/Users/test/MC Proxy' };
  assert.equal(parseLaunchOptions(['--mock'], context).runtimeRoot, 'D:/ExampleProject/.cache/desktop-mock/runtime');
  const mock = parseLaunchOptions(['--mock'], { ...context, env: { MC_PROXY_RUNTIME_ROOT: 'D:/production/runtime', PROXYPILOT_CONFIG_PATH: 'D:/production/config.json', PROXYPILOT_SECRETS_PATH: 'D:/production/passwords.env' } });
  assert.equal(mock.configPath, undefined);
  assert.equal(mock.secretsPath, undefined);
  assert.equal(mock.runtimeRoot, 'D:/ExampleProject/.cache/desktop-mock/runtime');
  assert.equal(parseLaunchOptions([], { ...context, env: { MC_PROXY_RUNTIME_ROOT: 'D:/production/runtime' } }).runtimeRoot, 'D:/production/runtime');
  assert.equal(parseLaunchOptions([], { ...context, packaged: true }).runtimeRoot, 'C:/Users/test/MC Proxy/runtime');
  assert.equal(parseLaunchOptions(['--runtime-root', 'D:/data', '--control-port', '17800'], context).port, 17800);
  assert.throws(() => parseLaunchOptions(['--smoke-test'], context), /must use --mock/);
  assert.throws(() => parseLaunchOptions(['--control-port', '80'], context), /Control port/);
  assert.throws(() => parseLaunchOptions(['--runtime-root'], context), /requires a value/);
});

test('desktop error replies expose only stable public metadata and fixed user guidance', () => {
  const publicError = desktopError({ code: 'APPLICATION_LAUNCH_FAILED', message: 'password=private; C:/secret/config.json', details: { private: true } });
  assert.equal(publicError.code, 'APPLICATION_LAUNCH_FAILED');
  assert.match(publicError.message, /应用未能启动/);
  assert.doesNotMatch(JSON.stringify(publicError), /password|private|secret/);
  assert.equal(desktopError({ code: 'not a code', message: 'secret' }).code, 'DESKTOP_ACTION_FAILED');
  assert.equal(desktopError(null).code, 'DESKTOP_ACTION_FAILED');
  const fixedMode = desktopError({ code: 'CARD_RESOURCE_MODE_FIXED', message: 'private payment record', details: { secret: true } });
  assert.equal(fixedMode.code, 'CARD_RESOURCE_MODE_FIXED');
  assert.match(fixedMode.message, /原付款订单/); assert.doesNotMatch(JSON.stringify(fixedMode), /private|secret/);
  for (const code of ['CLAUDE_BACKGROUND_CHECK_FAILED', 'CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED', 'CLAUDE_SERVICES_OPEN_FAILED', 'CLAUDE_BACKGROUND_BUSY',
    'CLAUDE_STARTUP_ADMIN_REQUIRED', 'CLAUDE_STARTUP_IDENTITY_UNVERIFIED', 'CLAUDE_STARTUP_ACCESS_DENIED', 'CLAUDE_STARTUP_CONFLICT', 'CLAUDE_STARTUP_UNCONFIRMED', 'CLAUDE_STARTUP_RECORD_FAILED', 'CLAUDE_STARTUP_REGISTRY_UNREADABLE']) {
    const fixedService = desktopError({ code, message: 'password=secret C:/Users/private', details: { path: 'private' } });
    assert.equal(fixedService.code, code); assert.match(fixedService.message, /Claude|服务管理/);
    assert.doesNotMatch(JSON.stringify(fixedService), /password|private|secret|Users/);
  }
});
