import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { createApplicationManager, proxyEnvironment } from '../application-manager.mjs';

function fixture({ running = false, codexRunning = false, codexUnknown = false, otherChatGPT = false, codexInstalled = true,
  codexPath = 'C:\\Roaming\\npm\\codex.cmd', exitStatus = 'verified', coverage = { mode: 'tun', systemExitVerified: true, killSwitch: true, systemProtected: true }, modified = false, proxyGate, targetCheck, proxyData, processData, processQueryFailure = false, processTools, launchFailure = false, hangLaunch = false } = {}) {
  const paths = ['C:\\User\\.local\\bin\\claude.exe', 'C:\\Apps\\Claude\\app\\claude.exe', codexPath, ...(codexInstalled ? ['C:\\Apps\\Codex\\app\\ChatGPT.exe'] : [])];
  const environment = { SystemRoot: 'C:\\Windows', USERPROFILE: 'C:\\User', LOCALAPPDATA: 'C:\\Local', APPDATA: 'C:\\Roaming', https_proxy: 'http://old:10', NO_PROXY: '*', ALL_PROXY: 'socks://old:20', NODE_OPTIONS: '--require old.js', MARKER: 'preserved' };
  let spawned = [], children = [], executions = [], queries = [], nativeCalls = [], closed = [], targetChecks = [], checks = 0, reads = 0;
  const identities = [
    { pid: 1, parentPid: 9, createdAt: '2026-10-05T00:00:00.000Z', executable: paths[1], commandLine: `"${paths[1]}"` },
    { pid: 2, parentPid: 9, createdAt: '2026-10-05T00:00:00.000Z', executable: 'C:\\Apps\\Codex\\app\\ChatGPT.exe', commandLine: 'private fixture command' },
  ];
  const manager = createApplicationManager({ platform: 'win32', environment,
    applicationProxy: async id => { checks++; await proxyGate?.(id); return proxyData ? proxyData(checks) : { exitStatus, coverage, binding: 'a'.repeat(64), revision: 1, corePort: 17890, url: 'http://127.0.0.1:18999' }; },
    checkTargets: async service => { targetChecks.push(service); return targetCheck ? targetCheck(service) : { service, path: 'proxy', status: 'reachable', transportReady: true }; },
    processTools: processTools || {
      listProcesses: async name => identities.filter(item => path.win32.basename(item.executable).toLowerCase() === name.toLowerCase()),
      inspectProcess: async pid => identities.find(item => item.pid === pid),
      stopProcess: async (identity, options) => { closed.push({ identity, options }); return { stopped: true }; },
    },
    stat: async candidate => { if (!paths.includes(candidate)) throw new Error('absent'); reads++; return { isFile: () => true, isSymbolicLink: () => false, size: modified && reads > 3 ? 2 : 1, mtimeMs: 1 }; },
    canonical: async candidate => candidate, list: async () => [],
    run: async (file, args, options) => {
      nativeCalls.push({ file, args, options });
      if(args.includes('-EncodedCommand'))executions.push({file,args,options});
      if(args.some(arg => arg.includes('Get-Process'))) { queries.push({file,args,options}); if(processQueryFailure)throw new Error('private WMI error'); }
      const processes = [];
      if (running && !closed.some(item => item.identity.pid === 1)) processes.push({ ProcessName: 'claude', Id: 1, Path: paths[1] });
      if (codexRunning && !closed.some(item => item.identity.pid === 2)) processes.push({ ProcessName: 'ChatGPT', Id: 2, Path: 'C:\\Apps\\Codex\\app\\ChatGPT.exe' });
      if (codexUnknown) processes.push({ ProcessName: 'ChatGPT', Id: 3, Path: null });
      if (otherChatGPT) processes.push({ ProcessName: 'ChatGPT', Id: 4, Path: 'C:\\Apps\\OtherChatGPT\\ChatGPT.exe' });
      return { stdout: args.some(arg => arg.includes('Get-AppxPackage')) ? JSON.stringify([{ Name: 'Claude', InstallLocation: 'C:\\Apps\\Claude' }, ...(codexInstalled ? [{ Name: 'OpenAI.Codex', InstallLocation: 'C:\\Apps\\Codex' }] : [])])
        : args.some(arg => arg.includes('Get-Process')) ? (typeof processData === 'function' ? processData() : processData) ?? JSON.stringify(processes)
        : args[0] === 'codex' ? codexPath : '' };
    },
    launchTimeoutMs: 20,
    launch: (file, args, options) => { if(launchFailure)throw new Error('private installation path');spawned.push({ file, args, options }); const child = new EventEmitter(); children.push(child); child.unref = () => {}; child.kill=()=>assert.fail('never kill user app'); if(!hangLaunch)queueMicrotask(() => child.emit('spawn')); return child; },
  });
  return { manager, environment, spawned, children, executions, queries, nativeCalls, closed, targetChecks, identities, get checks() { return checks; } };
}

test('trusted routing paths include only discovered executables while public inventory remains path-free', async () => {
  const { manager } = fixture({ running: true });
  const paths = await manager.routingPaths();
  assert.ok(paths.includes('C:\\User\\.local\\bin\\claude.exe'));
  assert.ok(paths.includes('C:\\Apps\\Claude\\app\\claude.exe'));
  assert.ok(paths.every(value => /\.exe$/i.test(value) && !/node\.exe$/i.test(value)));
  assert.doesNotMatch(JSON.stringify(await manager.discover()), /C:\\\\|\.exe|\.cmd/);
  assert.deepEqual(await createApplicationManager({ mock: true }).routingPaths(), []);
});

test('discovery separates embedded CLI and Desktop without exposing executable paths', async () => {
  const { manager } = fixture({ running: true });
  const inventory = await manager.discover();
  assert.equal(inventory.applications.find(item => item.id === 'claude-desktop').running, 1);
  assert.equal(inventory.applications.find(item => item.id === 'claude-code').running, 0);
  assert.equal(inventory.applications.find(item => item.id === 'codex-cli').installed, true);
  assert.doesNotMatch(JSON.stringify(inventory), /C:\\|old\.js/);
});

test('CLI launch uses freshly verified local proxy in a new terminal without changing parent environment', async () => {
  const context = fixture(); const original = { ...context.environment };
  assert.equal((await context.manager.start('claude-code')).started, true);
  assert.equal(context.checks, 1);
  assert.deepEqual(context.environment, original);
  assert.equal(context.spawned.length, 0);
  const launch = context.executions[0], childEnv = launch.options.env;
  for (const key of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy']) assert.equal(childEnv[key], 'http://127.0.0.1:18999');
  assert.equal(childEnv.ALL_PROXY, undefined); assert.equal(childEnv.NODE_OPTIONS, undefined);
  assert.equal(childEnv.NO_PROXY, childEnv.no_proxy); assert.doesNotMatch(childEnv.NO_PROXY, /\*/);
  assert.equal(childEnv.MARKER, 'preserved');
  assert.equal(launch.options.windowsHide, true);
  const helper = Buffer.from(launch.args.at(-1), 'base64').toString('utf16le');
  assert.match(helper, /Start-Process.*-WindowStyle Normal/);
  assert.match(helper, /'-NoExit'/);
  const encoded = [...helper.matchAll(/'([A-Za-z0-9+/=]+)'/g)].at(-1)[1];
  const script = Buffer.from(encoded, 'base64').toString('utf16le');
  assert.match(script, /& 'C:\\User\\\.local\\bin\\claude\.exe'/);
  assert.ok(launch.args.includes('-NoProfile')); assert.ok(launch.args.includes('-NonInteractive'));
});

test('Desktop launch preserves existing profile and passes Chromium proxy; running Desktop requires user restart', async () => {
  const context = fixture(); await context.manager.start('claude-desktop');
  const launch = context.spawned[0];
  assert.equal(launch.file, 'C:\\Apps\\Claude\\app\\claude.exe');
  assert.ok(launch.args.includes('--proxy-server=http://127.0.0.1:18999'));
  assert.doesNotMatch(launch.args.join(' '), /user-data-dir|profile-directory/);
  const active = fixture({ running: true });
  await assert.rejects(active.manager.start('claude-desktop'), { code: 'APPLICATION_RESTART_REQUIRED' });
  assert.equal(active.spawned.length, 0); assert.equal(active.checks, 0);
});

test('invalid target, unverified exit, and changed binary never launch a process', async () => {
  const context = fixture(); await assert.rejects(context.manager.start('cmd & injected'), { code: 'APPLICATION_TARGET_INVALID' }); assert.equal(context.checks, 0);
  const unverified = fixture({ exitStatus: 'unverified' }); await assert.rejects(unverified.manager.start('terminal'), { code: 'APPLICATION_PROXY_UNVERIFIED' }); assert.equal(unverified.spawned.length, 0);
  const changed = fixture({ modified: true }); await assert.rejects(changed.manager.start('claude-code'), { code: 'APPLICATION_BINARY_CHANGED' }); assert.equal(changed.spawned.length, 0);
  assert.throws(() => proxyEnvironment({}, 'http://external:80'), { code: 'APPLICATION_PROXY_INVALID' });
});

test('fixed controller authorization errors retain their actual code without exposing private details or launching', async () => {
  for (const code of ['PROXY_TIMEOUT', 'SESSION_CHANGED', 'NETWORK_LOCK_TIMEOUT', 'EXIT_IP_MISMATCH']) {
    for (const id of ['claude-desktop', 'codex-cli', 'terminal']) {
      const context = fixture({ proxyGate: async () => {
        throw Object.assign(new Error('PRIVATE_NATIVE_MESSAGE password=fixture-secret https://private.invalid/'), {
          code, diagnostic: { path: 'C:\\PRIVATE', ip: '192.0.2.1' }, secret: 'fixture-secret',
        });
      } });
      await assert.rejects(context.manager.start(id), error => {
        assert.equal(error.code, code);
        assert.doesNotMatch(error.message, /PRIVATE|fixture-secret|192\.0\.2|private\.invalid/);
        assert.equal(error.diagnostic, undefined); assert.equal(error.secret, undefined);
        return true;
      });
      assert.equal(context.spawned.length, 0); assert.equal(context.executions.length, 0);
    }
  }
});

test('unknown controller codes stay masked and cannot pose as fixed authorization failures', async () => {
  const context = fixture({ proxyGate: async () => { throw Object.assign(new Error('PRIVATE_FAILURE'), { code: 'PRIVATE_CREDENTIAL_IN_CODE' }); } });
  await assert.rejects(context.manager.start('claude-desktop'), error => {
    assert.equal(error.code, 'APPLICATION_SYSTEM_PROTECTION_REQUIRED');
    assert.doesNotMatch(error.message, /PRIVATE/); return true;
  });
  assert.equal(context.spawned.length, 0); assert.equal(context.executions.length, 0);
});

test('mock performs no discovery or launch of real applications', async () => {
  const manager = createApplicationManager({ mock: true, applicationProxy: async () => ({}), launch: () => assert.fail('no native launch'), stat: () => assert.fail('no real discovery') });
  assert.equal((await manager.discover()).mock, true);
  assert.deepEqual(await manager.start('claude-desktop'), { started: true, mock: true, id: 'claude-desktop' });
});

test('proxy URL bounds return a stable error and never mutate the original environment', () => {
  const env = { HTTP_PROXY: 'old' };
  for (const url of [undefined, {}, 'http://127.0.0.1:80', 'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://user@127.0.0.1:18000', 'http://127.0.0.1:18000/']) assert.throws(() => proxyEnvironment(env, url), { code: 'APPLICATION_PROXY_INVALID' });
  assert.deepEqual(env, { HTTP_PROXY: 'old' });
  assert.equal(proxyEnvironment(env, 'http://127.0.0.1:65535').HTTP_PROXY, 'http://127.0.0.1:65535');
});

test('discovery and launches cannot reset each other while exit verification is pending', async () => {
  let release; const gate = new Promise(resolve => { release = resolve; });
  const context = fixture({ proxyGate: () => gate });
  const first = context.manager.start('claude-code');
  await new Promise(resolve => setImmediate(resolve)); assert.equal(context.checks, 1);
  let completed = false; const second = context.manager.discover().then(() => { completed = true; });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(completed, false);
  release(); await first; await second;
  assert.equal(context.executions.length, 1);
  await assert.rejects(context.manager.start({ id: 'terminal' }), { code: 'APPLICATION_TARGET_INVALID' });
  assert.equal((await context.manager.discover()).processStatus, 'observed');
});

test('invalid native process metadata cannot authorize a Desktop restart', async () => {
  for (const processData of ['', 'null', '[null]', '42', '{"ProcessName":"claude","Id":"wrong"}', '[{"ProcessName":"claude","Id":4294967296}]']) {
    const context = fixture({ processData });
    assert.equal((await context.manager.discover()).processStatus, 'unknown');
    await assert.rejects(context.manager.start('claude-desktop'), { code: 'APPLICATION_PROCESS_STATE_UNKNOWN' });
    assert.equal(context.spawned.length, 0);
  }
});

test('Codex Desktop uses the package ChatGPT entry and has separate public startup state from CLI', async () => {
  const context = fixture();
  const inventory = await context.manager.discover();
  const desktop = inventory.applications.find(item => item.id === 'codex-desktop'), cli = inventory.applications.find(item => item.id === 'codex-cli');
  assert.equal(desktop.kind, 'desktop'); assert.equal(desktop.installed, true); assert.equal(desktop.launchable, true); assert.equal(desktop.blockedReason, null);
  assert.equal(cli.kind, 'cli'); assert.equal(cli.installed, true); assert.equal(cli.launchable, true);
  await context.manager.start('codex-desktop');
  assert.equal(context.spawned[0].file, 'C:\\Apps\\Codex\\app\\ChatGPT.exe');
  assert.ok(context.spawned[0].args.includes('--proxy-server=http://127.0.0.1:18999'));
  assert.doesNotMatch(context.spawned[0].args.join(' '), /user-data-dir|profile-directory/);
  assert.doesNotMatch(JSON.stringify(inventory), /C:\\|old\.js/);
});

test('running or unidentified Codex Desktop blocks new startup without stopping current applications', async () => {
  for (const [options, blockedReason, code] of [
    [{ codexRunning: true }, 'running-requires-restart', 'APPLICATION_RESTART_REQUIRED'],
    [{ codexUnknown: true }, 'process-state-unknown', 'APPLICATION_PROCESS_STATE_UNKNOWN'],
  ]) {
    const context = fixture(options), desktop = (await context.manager.discover()).applications.find(item => item.id === 'codex-desktop');
    assert.equal(desktop.installed, true); assert.equal(desktop.launchable, false); assert.equal(desktop.blockedReason, blockedReason);
    await assert.rejects(context.manager.start('codex-desktop'), { code });
    assert.equal(context.spawned.length, 0); assert.equal(context.checks, 0);
    assert.equal((await context.manager.start('codex-cli')).started, true);
  }
  const other = fixture({ otherChatGPT: true });
  assert.equal((await other.manager.discover()).applications.find(item => item.id === 'codex-desktop').launchable, true);
});

test('Codex Desktop started during discovery is detected before final authorization and spawning', async () => {
  let snapshots = 0;
  const context = fixture({ processData: () => ++snapshots > 1 ? JSON.stringify({ ProcessName: 'ChatGPT', Id: 9, Path: 'C:\\Apps\\Codex\\app\\ChatGPT.exe' }) : '[]' });
  await assert.rejects(context.manager.start('codex-desktop'), { code: 'APPLICATION_RESTART_REQUIRED' });
  assert.equal(context.spawned.length, 0); assert.equal(context.checks, 0);
});

test('Codex CLI command shim with spaces and metacharacters remains a single quoted PowerShell target', async () => {
  const codexPath = "C:\\CLI O'Brien & Tools!\\codex.cmd";
  const context = fixture({ codexPath }); await context.manager.start('codex-cli');
  const launch = context.executions[0];
  const helper = Buffer.from(launch.args.at(-1), 'base64').toString('utf16le');
  const encoded = [...helper.matchAll(/'([A-Za-z0-9+/=]+)'/g)].at(-1)[1];
  const script = Buffer.from(encoded, 'base64').toString('utf16le');
  assert.match(script, /& 'C:\\CLI O''Brien & Tools!\\codex\.cmd'/);
  assert.equal(script.split('\n').filter(line => line.startsWith('& ')).length, 1);
  assert.ok(launch.args.includes('-EncodedCommand')); assert.equal(launch.options.env.HTTPS_PROXY, 'http://127.0.0.1:18999');
  assert.equal(context.spawned.length, 0);
});

test('Windows PowerShell executes the generated command-shim target with its process-local proxy', { skip: process.platform !== 'win32' }, async t => {
  const directory = await mkdtemp(path.join(import.meta.dirname, '.application-shim-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const shimDirectory = path.join(directory, "CLI O'Brien & Tools!");
  await mkdir(shimDirectory);
  const codexPath = path.join(shimDirectory, 'codex.cmd');
  await writeFile(codexPath, '@echo off\r\necho CMD_SHIM_FIXTURE:%HTTPS_PROXY%\r\n');
  const context = fixture({ codexPath }); await context.manager.start('codex-cli');
  const helper = Buffer.from(context.executions[0].args.at(-1), 'base64').toString('utf16le');
  const encoded = [...helper.matchAll(/'([A-Za-z0-9+/=]+)'/g)].at(-1)[1];
  // Execute just the captured terminal body in a hidden process. The shim only
  // echoes a fixture marker; no visible terminal, real CLI or network is used.
  const { stdout } = await promisify(execFile)(path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], { env: proxyEnvironment(process.env, 'http://127.0.0.1:18999'), windowsHide: true, timeout: 5000, maxBuffer: 32768 });
  assert.match(stdout, /CMD_SHIM_FIXTURE:http:\/\/127\.0\.0\.1:18999/);
});

test('Desktop synchronous launch failure and missing spawn acknowledgment are bounded and do not expose native errors', async () => {
  const failed = fixture({ launchFailure: true });
  await assert.rejects(failed.manager.start('claude-desktop'), error => error.code === 'APPLICATION_LAUNCH_FAILED' && !error.message.includes('private installation'));
  const hung = fixture({ hangLaunch: true });
  await assert.rejects(hung.manager.start('claude-desktop'), { code: 'APPLICATION_LAUNCH_TIMEOUT' });
  assert.equal((await hung.manager.discover()).processStatus, 'observed');
});

test('successful empty snapshots and UTF-8 BOM are observed, while query failures remain unknown', async () => {
  for (const processData of ['[]', '\uFEFF[]']) {
    const context = fixture({ processData });
    assert.equal((await context.manager.discover()).processStatus, 'observed');
    await context.manager.start('codex-desktop');
    assert.equal(context.spawned.length, 1);
  }
  const failed = fixture({ processQueryFailure: true });
  const inventory = await failed.manager.discover();
  assert.equal(inventory.processStatus, 'unknown');
  assert.equal(inventory.applications.find(item => item.id === 'codex-desktop').stoppable, false);
  await assert.rejects(failed.manager.start('codex-desktop'), { code: 'APPLICATION_PROCESS_STATE_UNKNOWN' });
  await assert.rejects(failed.manager.stop('codex-desktop'), { code: 'APPLICATION_PROCESS_STATE_UNKNOWN' });
  assert.equal(failed.spawned.length, 0); assert.equal(failed.closed.length, 0);
});

test('Windows PowerShell inventory handles absent names and Unicode paths without querying user applications', { skip: process.platform !== 'win32' }, async () => {
  const context = fixture(); await context.manager.discover();
  const query = context.queries[0].args.at(-1);
  const run = promisify(execFile), ps = context.queries[0].file;
  // Only this function stub supplies synthetic entries. The real Get-Process is
  // never invoked, and no installed application or profile is inspected.
  for (const [body, expected] of [
    ['return', []],
    ["[pscustomobject]@{ProcessName='claude';Id=17;Path='C:\\合成 应用\\Claude.exe'}", [{ ProcessName: 'claude', Id: 17, Path: 'C:\\合成 应用\\Claude.exe' }]],
  ]) {
    const script = `function Get-Process { param([string[]]$Name,[string]$ErrorAction); if ($Name) { throw 'SYNTHETIC_NO_NAME_MATCH' }; ${body} }\n${query}`;
    const { stdout } = await run(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 32768 });
    assert.deepEqual(JSON.parse(stdout.replace(/^\uFEFF/, '').trim()), expected);
  }
});

test('application OAuth startup requires verified system TUN while an explicit proxy terminal remains available', async () => {
  for (const coverage of [undefined, {}, { mode: 'http', systemExitVerified: true, systemProtected: true }, { mode: 'tun', systemExitVerified: false, systemProtected: true }]) {
    const context = fixture({ coverage: coverage ?? null });
    for (const id of ['claude-desktop', 'claude-code', 'codex-desktop', 'codex-cli']) await assert.rejects(context.manager.start(id), { code: 'APPLICATION_SYSTEM_PROTECTION_REQUIRED' });
    assert.equal(context.spawned.length, 0); assert.equal(context.executions.length, 0);
    await context.manager.start('terminal');
    const helper = Buffer.from(context.executions[0].args.at(-1), 'base64').toString('utf16le');
    const encoded = [...helper.matchAll(/'([A-Za-z0-9+/=]+)'/g)].at(-1)[1];
    const script = Buffer.from(encoded, 'base64').toString('utf16le');
    assert.match(script, /默认浏览器可能使用真实公网出口/);
    assert.doesNotMatch(script, /BROWSER\s*=|已核验.*全系统/);
  }
  let requested;
  const protectedContext = fixture({ proxyGate: async id => { requested = id; } });
  await protectedContext.manager.start('codex-desktop');
  assert.equal(requested, 'codex-desktop');
  assert.equal(protectedContext.spawned.length, 1);
});

test('verified system TUN admits all four apps without a lock and retains independent proxy parameters', async () => {
  const context = fixture({ coverage: { mode: 'tun', systemExitVerified: true, killSwitch: false, systemProtected: false } });
  for (const id of ['claude-desktop', 'claude-code', 'codex-desktop', 'codex-cli']) assert.equal((await context.manager.start(id)).started, true);
  assert.deepEqual(context.targetChecks, []);
  assert.equal(context.checks, 4);
  assert.equal(context.spawned.length, 2); assert.equal(context.executions.length, 2);
  for (const child of context.spawned) {
    assert.ok(child.args.includes('--proxy-server=http://127.0.0.1:18999'));
    assert.ok(child.args.includes('--disable-quic'));
    assert.equal(child.options.env.HTTPS_PROXY, 'http://127.0.0.1:18999');
  }
  for (const helper of context.executions) {
    assert.equal(helper.options.env.HTTP_PROXY, 'http://127.0.0.1:18999');
    const outer = Buffer.from(helper.args.at(-1), 'base64').toString('utf16le');
    const encoded = [...outer.matchAll(/'([A-Za-z0-9+/=]+)'/g)].at(-1)[1];
    const body = Buffer.from(encoded, 'base64').toString('utf16le');
    assert.match(body, /未开启时断线可能恢复直连/);
  }
});

test('safe Desktop stop validates identity, closes only main roots and does not require a proxy', async () => {
  for (const options of [{ running: true }, { codexRunning: true }]) {
    const context = fixture({ ...options, exitStatus: 'unverified' });
    const id = options.running ? 'claude-desktop' : 'codex-desktop';
    const row = (await context.manager.discover()).applications.find(item => item.id === id);
    assert.equal(row.stoppable, true); assert.equal(row.stopBlockedReason, null);
    assert.deepEqual(await context.manager.stop(id), { stopped: true, mock: false, id });
    assert.equal(context.closed.length, 1);
    assert.deepEqual(context.closed[0].options, { graceful: true, timeoutMs: 5000 });
    assert.equal(context.checks, 0);
    assert.doesNotMatch(JSON.stringify(row), /private fixture|C:\\/);
  }
  const context = fixture({ running: true });
  context.identities.push({ ...context.identities[0], pid: 20, parentPid: 1, commandLine: 'renderer fixture' });
  await context.manager.stop('claude-desktop');
  assert.deepEqual(context.closed.map(item => item.identity.pid), [1]);
});

test('an application exit or normal Desktop close does not revoke or renew its independent proxy session', async () => {
  const lease = { exitStatus: 'verified', coverage: { mode: 'tun', systemExitVerified: true }, binding: 'a'.repeat(64), revision: 7, corePort: 17890, url: 'http://127.0.0.1:18999' };
  const original = structuredClone(lease);
  for (const id of ['claude-desktop', 'codex-desktop']) {
    const context = fixture({ proxyData: () => lease });
    await context.manager.start(id);
    const environment = { ...context.environment };
    context.children[0].emit('exit', 0, null);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(await context.manager.stop(id), { stopped: true, alreadyExited: true, mock: false, id });
    assert.equal(context.checks, 1, 'App exit must not trigger another controller probe or lease mutation');
    assert.equal(context.closed.length, 0, 'A completed app is never replaced by stopping another process');
    assert.deepEqual(lease, original); assert.deepEqual(context.environment, environment);
  }
  const existing = fixture({ running: true, proxyGate: () => assert.fail('Closing an app must not perform controller authorization') });
  await existing.manager.stop('claude-desktop');
  assert.equal(existing.closed.length, 1); assert.equal(existing.checks, 0);
  assert.deepEqual(lease, original);
});

test('unsafe, unreadable or reused Desktop identities never receive a close request', async () => {
  for (const scenario of ['unreadable', 'reused', 'incomplete', 'missing']) {
    let closes = 0;
    const identity = { pid: 1, parentPid: 9, createdAt: '2026-10-05T00:00:00.000Z', executable: 'C:\\Apps\\Claude\\app\\claude.exe', commandLine: 'fixture secret argument' };
    const context = fixture({ running: true, processTools: {
      listProcesses: async () => { if (scenario === 'unreadable') throw new Error('private native details'); return scenario === 'missing' ? [] : [{ ...identity, ...(scenario === 'incomplete' ? { commandLine: '' } : {}) }]; },
      inspectProcess: async () => ({ ...identity, createdAt: '2026-10-05T00:01:00.000Z' }),
      stopProcess: async () => { closes++; assert.fail('identity mismatch must never close'); },
    } });
    await assert.rejects(context.manager.stop('claude-desktop'), error => error.code === (scenario === 'unreadable' ? 'APPLICATION_PROCESS_STATE_UNKNOWN' : 'APPLICATION_PROCESS_IDENTITY_CHANGED') && !/private|secret/.test(error.message));
    assert.equal(closes, 0); assert.equal(context.checks, 0);
  }
  const unrecognized = fixture({ running: true, processData: JSON.stringify([{ ProcessName: 'claude', Id: 3, Path: 'C:\\Different\\claude.exe' }]) });
  const row = (await unrecognized.manager.discover()).applications.find(item => item.id === 'claude-desktop');
  assert.equal(row.stoppable, false); assert.equal(row.stopBlockedReason, 'process-identity-unverified');
  await assert.rejects(unrecognized.manager.stop('claude-desktop'), { code: 'APPLICATION_PROCESS_IDENTITY_CHANGED' });
});

test('busy Desktop close and unreadable completion are reported without force kill or raw errors', async () => {
  for (const code of ['BROWSER_CLOSE_TIMEOUT', 'PROCESS_IDENTITY_MISMATCH', 'OTHER_NATIVE_ERROR']) {
    let closes = 0;
    const identity = { pid: 2, parentPid: 9, createdAt: '2026-10-05T00:00:00.000Z', executable: 'C:\\Apps\\Codex\\app\\ChatGPT.exe', commandLine: 'fixture' };
    const context = fixture({ codexRunning: true, processTools: {
      listProcesses: async () => [identity], inspectProcess: async () => identity,
      stopProcess: async (_identity, options) => { closes++; assert.equal(options.graceful, true); throw Object.assign(new Error('private path credential'), { code }); },
    } });
    const expected = code === 'BROWSER_CLOSE_TIMEOUT' ? 'APPLICATION_CLOSE_TIMEOUT' : code === 'PROCESS_IDENTITY_MISMATCH' ? 'APPLICATION_PROCESS_IDENTITY_CHANGED' : 'APPLICATION_CLOSE_FAILED';
    await assert.rejects(context.manager.stop('codex-desktop'), error => error.code === expected && !/private|credential/.test(error.message));
    assert.equal(closes, 1);
    assert.equal((await context.manager.discover()).applications.find(item => item.id === 'codex-desktop').running, 1);
  }
  let snapshots = 0;
  const identity = { pid: 1, parentPid: 9, createdAt: '2026-10-05T00:00:00.000Z', executable: 'C:\\Apps\\Claude\\app\\claude.exe', commandLine: 'fixture' };
  const context = fixture({ running: true, processData: () => ++snapshots === 1 ? JSON.stringify([{ ProcessName: 'claude', Id: 1, Path: identity.executable }]) : 'null', processTools: {
    listProcesses: async () => [identity], inspectProcess: async () => identity, stopProcess: async () => ({ stopped: true }),
  } });
  await assert.rejects(context.manager.stop('claude-desktop'), { code: 'APPLICATION_PROCESS_STATE_UNKNOWN' });
});

test('CLI and terminal stop never inspect or terminate unrelated user sessions; already exited and mock stop are explicit', async () => {
  const context = fixture({ processTools: { listProcesses: () => assert.fail('no CLI scanning'), stopProcess: () => assert.fail('no CLI stopping') } });
  for (const id of ['claude-code', 'codex-cli', 'terminal']) await assert.rejects(context.manager.stop(id), { code: 'APPLICATION_CLOSE_MANUALLY' });
  assert.equal(context.queries.length, 0);
  await assert.rejects(context.manager.stop('injected-app'), { code: 'APPLICATION_TARGET_INVALID' });
  assert.deepEqual(await context.manager.stop('codex-desktop'), { stopped: true, alreadyExited: true, mock: false, id: 'codex-desktop' });
  const mock = createApplicationManager({ mock: true, processTools: { listProcesses: () => assert.fail('no mock native queries') } });
  assert.deepEqual(await mock.stop('codex-desktop'), { stopped: true, mock: true, id: 'codex-desktop' });
});

test('application startup does not send business HEAD requests or wait on manual diagnostics', async () => {
  const context = fixture({ targetCheck: () => assert.fail('startup must not send an external HEAD') });
  for (const id of ['claude-desktop', 'claude-code', 'codex-desktop', 'codex-cli', 'terminal']) await context.manager.start(id);
  assert.deepEqual(context.targetChecks, []);
  assert.equal(context.checks, 5);
  for (const status of ['partial', 'failed', 'mocked', undefined]) {
    const context = fixture({ targetCheck: service => ({ service, path: 'proxy', status, transportReady: false }) });
    assert.equal((await context.manager.start('claude-desktop')).started, true);
    assert.deepEqual(context.targetChecks, []);
  }
  for (const targetCheck of [() => ({ service: 'codex', path: 'proxy', status: 'reachable', transportReady: true }), () => { throw new Error('private model token fixture'); }]) {
    const context = fixture({ targetCheck });
    assert.equal((await context.manager.start('claude-code')).started, true);
    assert.equal(context.executions.length, 1); assert.deepEqual(context.targetChecks, []);
  }
});

test('final fresh authorization rejects lost TUN verification and incomplete session binding', async () => {
  const original = { exitStatus: 'verified', coverage: { mode: 'tun', systemExitVerified: true, systemProtected: false }, binding: 'a'.repeat(64), revision: 1, corePort: 17890, url: 'http://127.0.0.1:18999' };
  for (const [lease, code] of [
    [{ ...original, coverage: { mode: 'tun', systemExitVerified: false, systemProtected: true } }, 'APPLICATION_SYSTEM_PROTECTION_REQUIRED'],
    [{ ...original, coverage: { mode: 'http', systemExitVerified: true, systemProtected: true } }, 'APPLICATION_SYSTEM_PROTECTION_REQUIRED'],
    [{ ...original, exitStatus: 'unverified' }, 'APPLICATION_PROXY_UNVERIFIED'],
    [{ ...original, revision: undefined }, 'APPLICATION_PROXY_UNVERIFIED'],
    [{ ...original, binding: undefined }, 'APPLICATION_PROXY_UNVERIFIED'],
    [{ ...original, corePort: undefined }, 'APPLICATION_PROXY_UNVERIFIED'],
    [{ ...original, url: 'http://user@127.0.0.1:18999' }, 'APPLICATION_PROXY_INVALID'],
    [{ ...original, url: 'http://public.invalid:18999' }, 'APPLICATION_PROXY_INVALID'],
  ]) {
    const context = fixture({ proxyData: () => lease });
    await assert.rejects(context.manager.start('codex-desktop'), { code });
    assert.equal(context.spawned.length, 0); assert.equal(context.checks, 1);
  }
  // There is no stale, pre-HEAD lease to compare against: the current complete
  // authorization is obtained only after local discovery has finished.
  const current = fixture({ proxyData: () => ({ ...original, revision: 2, corePort: 17891, binding: 'b'.repeat(64), url: 'http://127.0.0.1:19000' }) });
  await current.manager.start('codex-desktop');
  assert.ok(current.spawned[0].args.includes('--proxy-server=http://127.0.0.1:19000'));
  assert.equal(current.checks, 1);
});

test('app admission requires an opaque complete lease, and a lock change alone does not invalidate verified TUN', async () => {
  const original = { exitStatus: 'verified', coverage: { mode: 'tun', systemExitVerified: true, killSwitch: true, systemProtected: true }, binding: 'a'.repeat(64), revision: 1, corePort: 17890, url: 'http://127.0.0.1:18999' };
  for (const patch of [{ binding: undefined }, { binding: 'session identity' }, { revision: undefined }, { revision: -1 }, { corePort: undefined }, { corePort: 65536 }]) {
    const context = fixture({ proxyData: () => ({ ...original, ...patch }) });
    await assert.rejects(context.manager.start('claude-code'), { code: 'APPLICATION_PROXY_UNVERIFIED' });
    assert.equal(context.executions.length, 0); assert.deepEqual(context.targetChecks, []);
  }
  const context = fixture({ proxyData: () => ({ ...original, coverage: { ...original.coverage, killSwitch: false, systemProtected: false } }) });
  assert.equal((await context.manager.start('codex-desktop')).started, true);
  assert.equal(context.spawned.length, 1);
});

test('fresh TUN lease is obtained after final process inspection and failures never launch', async () => {
  let snapshots = 0;
  const context = fixture({
    processData: () => { snapshots++; return '[]'; },
    proxyGate: async () => { assert.equal(snapshots, 2); throw new Error('private stale session'); },
  });
  await assert.rejects(context.manager.start('codex-desktop'), error => error.code === 'APPLICATION_SYSTEM_PROTECTION_REQUIRED' && !/private/.test(error.message));
  assert.equal(context.spawned.length, 0); assert.equal(context.checks, 1); assert.deepEqual(context.targetChecks, []);
});

test('startup makes no business-success claim and leaves 403 or 421 evidence to explicit diagnostics', async () => {
  for (const [id, httpStatus, status] of [['claude-desktop', 403, 'partial'], ['codex-cli', 421, 'failed']]) {
    const context = fixture({ targetCheck: service => ({ service, path: 'proxy', status, code: 'APPLICATION_TARGETS_FAILED', transportReady: true,
      checks: [{ httpStatus, transportReachable: true, details: 'private token must not appear' }], raw: 'private native output' }) });
    const result = await context.manager.start(id);
    assert.equal(result.started, true);
    assert.deepEqual(result, { started: true, mock: false, id });
    assert.deepEqual(context.targetChecks, []);
    assert.doesNotMatch(JSON.stringify(result), /private|token|native output|业务成功/);
    assert.equal(context.checks, 1);
  }
});

test('cached target reachability cannot substitute for fresh verified TUN and session binding', async () => {
  for (const [options, code] of [
    [{ exitStatus: 'unverified' }, 'APPLICATION_PROXY_UNVERIFIED'],
    [{ coverage: { mode: 'http', systemExitVerified: true } }, 'APPLICATION_SYSTEM_PROTECTION_REQUIRED'],
    [{ coverage: { mode: 'tun', systemExitVerified: false } }, 'APPLICATION_SYSTEM_PROTECTION_REQUIRED'],
    [{ proxyData: () => ({ exitStatus: 'verified', coverage: { mode: 'tun', systemExitVerified: true }, url: 'http://127.0.0.1:18999' }) }, 'APPLICATION_PROXY_UNVERIFIED'],
  ]) {
    const context = fixture({ ...options, targetCheck: service => ({ service, path: 'proxy', status: 'reachable', transportReady: true }) });
    await assert.rejects(context.manager.start('codex-desktop'), { code });
    assert.equal(context.spawned.length, 0); assert.equal(context.executions.length, 0);
    assert.deepEqual(context.targetChecks, []);
  }
  const unprotected = fixture({ coverage: { systemProtected: false }, targetCheck: service => ({ service, path: 'proxy', transportReady: true }) });
  await assert.rejects(unprotected.manager.start('claude-desktop'), { code: 'APPLICATION_SYSTEM_PROTECTION_REQUIRED' });
  assert.deepEqual(unprotected.targetChecks, []);
});

test('startup performs one installation discovery and one final authorization without repeated native inventory', async () => {
  for (const id of ['claude-desktop', 'codex-desktop', 'claude-code', 'codex-cli']) {
    const context = fixture();
    await context.manager.start(id);
    assert.equal(context.nativeCalls.filter(call => call.file.endsWith('where.exe')).length, 2);
    assert.equal(context.nativeCalls.filter(call => call.args.some(arg => arg.includes('Get-AppxPackage'))).length, 1);
    assert.equal(context.queries.length, id.endsWith('-desktop') ? 2 : 1);
    assert.equal(context.checks, 1);
    assert.deepEqual(context.targetChecks, []);
  }
});
