import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { startupAccess, restartElevated, verifyAdminStartupHandoff, completeAdminStartupHandoff, quoteWindowsArgument } from '../admin-startup.mjs';

test('startup access is fail closed and only an explicit mock bypasses inspection', async () => {
  const check = value => startupAccess({ platform: 'win32', isElevated: async () => value });
  assert.deepEqual(await check(true), { allowed: true, reason: null });
  assert.deepEqual(await check(false), { allowed: false, reason: 'ADMIN_REQUIRED' });
  for (const value of [null, undefined, 1, 'true', {}]) assert.deepEqual(await check(value), { allowed: false, reason: 'ADMIN_CHECK_FAILED' });
  assert.deepEqual(await startupAccess({ platform: 'win32', isElevated: async () => { throw new Error('private error'); } }), { allowed: false, reason: 'ADMIN_CHECK_FAILED' });
  assert.deepEqual(await startupAccess({ mock: true, isElevated: async () => assert.fail('mock must not inspect') }), { allowed: true, reason: null });
  assert.deepEqual(await startupAccess({ platform: 'darwin', isElevated: async () => assert.fail('unsupported platform must not inspect') }), { allowed: false, reason: 'PLATFORM_UNSUPPORTED' });
});

async function fixture(t) {
  const parent = fileURLToPath(new URL('../../.cache/admin-startup-tests/', import.meta.url));
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(path.join(parent, 'mc-admin-startup-test-'));
  const executable = path.join(root, 'MC Proxy $() ` test.exe');
  await writeFile(executable, 'owned executable fixture, never executed');
  const userData = path.join(root, 'user data'), userProfile = path.join(root, 'original user');
  const current = { sid: 'S-1-5-21-123-456-789-1001', userProfile };
  let clock = 10000;
  const getIdentity = async () => ({ ...current }), now = () => clock;
  const dependencies = { getIdentity, createPrivateDirectory: async directory => {
    await mkdir(directory);
    await writeFile(path.join(directory, '.gitignore'), '*\n', { flag: 'wx' });
  }, delay: async ms => { clock += ms; } };
  const options = { executable, userData, temporaryRoot: root, timeoutMs: 1000, pollMs: 100, now, dependencies };
  const verifyOptions = { userData, temporaryRoot: root, now, platform: 'win32', isElevated: async () => true, dependencies };
  t.after(async () => {
    assert.ok(path.basename(root).startsWith('mc-admin-startup-test-'));
    assert.equal(path.dirname(path.resolve(root)).toLowerCase(), path.resolve(parent).toLowerCase());
    await rm(root, { recursive: true, force: true });
  });
  return { root, options, verifyOptions, current, now, advance: ms => { clock += ms; } };
}

function payloadFor(args, settings) {
  assert.deepEqual(args.slice(0, 2), ['-NoProfile', '-NonInteractive']);
  assert.equal(args[2], '-EncodedCommand');
  const script = Buffer.from(args[3], 'base64').toString('utf16le');
  assert.match(script, /-Verb RunAs -WindowStyle Hidden/);
  assert.doesNotMatch(script, /MC Proxy \$\(\)/);
  assert.equal(settings.windowsHide, true);
  return JSON.parse(Buffer.from(settings.env.MC_PROXY_ADMIN_STARTUP_PAYLOAD, 'base64').toString('utf8'));
}

function requestPathFor(payload) {
  return payload.argv.find(value => value.startsWith('--admin-startup-handoff=')).slice('--admin-startup-handoff='.length);
}

test('UAC launch success is insufficient; only a verified visible-window acknowledgment succeeds', async t => {
  const f = await fixture(t);
  let calls = 0, requestPath;
  f.options.argv = [f.root, '--runtime-root', path.join(f.root, 'runtime'), '--core-path', path.join(f.root, 'NO-CORE.exe'), '--control-port', '0'];
  f.options.dependencies.executeFile = async (_exe, args, settings) => {
    calls++;
    const payload = payloadFor(args, settings);
    assert.equal(payload.executable, f.options.executable);
    assert.deepEqual(payload.argv.slice(0, 7), f.options.argv);
    assert.ok(payload.argv.includes(`--user-data-dir=${f.options.userData}`));
    requestPath = requestPathFor(payload);
    const verified = await verifyAdminStartupHandoff(requestPath, f.verifyOptions);
    assert.equal(verified.request.userSid, f.current.sid);
    assert.equal(verified.request.userProfile, f.current.userProfile);
    assert.deepEqual(await completeAdminStartupHandoff(requestPath, f.verifyOptions), { ready: true });
    assert.deepEqual(await completeAdminStartupHandoff(requestPath, f.verifyOptions), { ready: true });
    return { stdout: '{"launched":true}' };
  };
  assert.deepEqual(await restartElevated(f.options), { ready: true, code: null });
  assert.equal(calls, 1);
  assert.equal((await readdir(f.root)).some(value => value.startsWith('MC-Proxy-admin-startup-')), false);
});

test('an elevated process that exits before a visible window leaves the permissions window open', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async (_exe, args, settings) => { payloadFor(args, settings); return { stdout: '{"launched":true}' }; };
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_TIMEOUT' });
});

test('cancelled UAC and helper failure are fixed, non-successful outcomes', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async () => ({ stdout: '{"launched":false,"code":"ADMIN_RESTART_CANCELED"}' });
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_CANCELED' });
  f.options.dependencies.executeFile = async () => { throw new Error('do not return private paths or arguments'); };
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_FAILED' });
});

test('a UAC account switch cannot acknowledge startup or initialize a new user session', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async (_exe, args, settings) => {
    const requestPath = requestPathFor(payloadFor(args, settings));
    const other = { ...f.verifyOptions, dependencies: { ...f.verifyOptions.dependencies, getIdentity: async () => ({ sid: 'S-1-5-21-123-456-789-1002', userProfile: path.join(f.root, 'other user') }) } };
    await assert.rejects(verifyAdminStartupHandoff(requestPath, other), { code: 'ADMIN_ACCOUNT_CHANGED' });
    await assert.rejects(completeAdminStartupHandoff(requestPath, other), { code: 'ADMIN_ACCOUNT_CHANGED' });
    assert.equal((await readdir(path.dirname(requestPath))).includes('ready.json'), false);
    return { stdout: '{"launched":true}' };
  };
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_TIMEOUT' });
  assert.equal((await readdir(f.root)).includes('user data'), false);
});

test('handoff cannot acknowledge an ordinary or unknown token, wrong user-data path, or expired request', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async (_exe, args, settings) => {
    const requestPath = requestPathFor(payloadFor(args, settings));
    await assert.rejects(verifyAdminStartupHandoff(requestPath, { ...f.verifyOptions, isElevated: async () => false }), { code: 'ADMIN_REQUIRED' });
    await assert.rejects(verifyAdminStartupHandoff(requestPath, { ...f.verifyOptions, isElevated: async () => null }), { code: 'ADMIN_CHECK_FAILED' });
    await assert.rejects(verifyAdminStartupHandoff(requestPath, { ...f.verifyOptions, userData: path.join(f.root, 'other data') }), { code: 'ADMIN_HANDOFF_INVALID' });
    f.advance(1100);
    await assert.rejects(verifyAdminStartupHandoff(requestPath, f.verifyOptions), { code: 'ADMIN_HANDOFF_EXPIRED' });
    return { stdout: '{"launched":true}' };
  };
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_TIMEOUT' });
});

test('an acknowledgment from a different attempt is rejected', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async (_exe, args, settings) => {
    const requestPath = requestPathFor(payloadFor(args, settings));
    await writeFile(path.join(path.dirname(requestPath), 'ready.json'), JSON.stringify({ version: 1, nonce: '00000000-0000-4000-8000-000000000000', ready: true }));
    return { stdout: '{"launched":true}' };
  };
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_HANDOFF_INVALID' });
});

test('arbitrary switches and prior handoff paths cannot be forwarded to the privileged process', async t => {
  const f = await fixture(t);
  f.options.dependencies.executeFile = async () => assert.fail('invalid argument must not invoke UAC');
  for (const argv of [['--no-sandbox'], ['--inspect'], ['--remote-debugging-port=9222'], ['--user-data-dir=other'], ['--admin-startup-handoff=other'], ['--runtime-root', 'relative'], ['--control-port', '99999']]) {
    await assert.rejects(restartElevated({ ...f.options, argv }), { code: 'ADMIN_RESTART_INVALID' });
  }
  assert.equal((await readdir(f.root)).some(value => value.startsWith('MC-Proxy-admin-startup-')), false);
});

test('Windows argument quoting treats quotes, dollar expressions and trailing slashes as literal data', () => {
  assert.equal(quoteWindowsArgument('C:\\MC Proxy\\'), '"C:\\MC Proxy\\\\"');
  assert.equal(quoteWindowsArgument('literal "quoted" value'), '"literal \\"quoted\\" value"');
  assert.equal(quoteWindowsArgument('$() `value'), '"$() `value"');
  assert.throws(() => quoteWindowsArgument('bad\nvalue'), { code: 'ADMIN_RESTART_INVALID' });
});

test('a previously aborted request neither inspects identity nor creates files or invokes UAC', async t => {
  const f = await fixture(t), abort = new AbortController();
  abort.abort();
  f.options.dependencies.getIdentity = async () => assert.fail('an aborted request must not inspect identity');
  f.options.dependencies.createPrivateDirectory = async () => assert.fail('an aborted request must not create directories');
  f.options.dependencies.executeFile = async () => assert.fail('an aborted request must not invoke UAC');
  assert.deepEqual(await restartElevated({ ...f.options, signal: abort.signal }), { ready: false, code: 'ADMIN_RESTART_CANCELED' });
});

test('cancellation during request creation removes only its owned files before any UAC call', async t => {
  const f = await fixture(t), abort = new AbortController();
  f.options.dependencies.fs = { writeFile: async (file, data, options) => {
    await writeFile(file, data, options);
    if (path.basename(file) === 'request.json') abort.abort();
  } };
  f.options.dependencies.executeFile = async () => assert.fail('cancellation precedes UAC');
  assert.deepEqual(await restartElevated({ ...f.options, signal: abort.signal }), { ready: false, code: 'ADMIN_RESTART_CANCELED' });
  assert.equal((await readdir(f.root)).some(value => value.startsWith('MC-Proxy-admin-startup-')), false);
});

test('cancelled ownership cannot be overridden by a ready file', async t => {
  const f = await fixture(t), abort = new AbortController();
  f.options.dependencies.executeFile = async (_exe, args, settings) => {
    await completeAdminStartupHandoff(requestPathFor(payloadFor(args, settings)), f.verifyOptions);
    abort.abort();
    return { stdout: '{"launched":true}' };
  };
  assert.deepEqual(await restartElevated({ ...f.options, signal: abort.signal }), { ready: false, code: 'ADMIN_RESTART_CANCELED' });
  assert.equal((await readdir(f.root)).some(value => value.startsWith('MC-Proxy-admin-startup-')), false);
});

test('cleanup retains an unexpected gitignore instead of recursively removing the directory', async t => {
  const f = await fixture(t);
  let directory;
  f.options.dependencies.createPrivateDirectory = async target => {
    directory = target;
    await mkdir(target);
    await writeFile(path.join(target, '.gitignore'), 'changed\n');
  };
  f.options.dependencies.executeFile = async () => ({ stdout: '{"launched":false,"code":"ADMIN_RESTART_CANCELED"}' });
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_CANCELED' });
  assert.deepEqual(await readdir(directory), ['.gitignore']);
  assert.equal(await readFile(path.join(directory, '.gitignore'), 'utf8'), 'changed\n');
});

test('a failed exclusive directory creation never cleans up an earlier attempt', async t => {
  const f = await fixture(t), nonce = '00000000-0000-4000-8000-000000000001';
  const directory = path.join(f.root, 'MC-Proxy-admin-startup-' + nonce);
  await mkdir(directory);
  await writeFile(path.join(directory, 'request.json'), 'existing attempt');
  f.options.dependencies.randomUUID = () => nonce;
  f.options.dependencies.executeFile = async () => assert.fail('an existing directory must prevent UAC');
  assert.deepEqual(await restartElevated(f.options), { ready: false, code: 'ADMIN_RESTART_FAILED' });
  assert.equal(await readFile(path.join(directory, 'request.json'), 'utf8'), 'existing attempt');
});

test('the actual PowerShell helper parses on Windows 5.1 and quotes data without evaluating it', { skip: process.platform !== 'win32' }, async t => {
  const f = await fixture(t);
  let helper;
  f.options.dependencies.executeFile = async (_exe, args) => {
    helper = Buffer.from(args[3], 'base64').toString('utf16le');
    return { stdout: '{"launched":false,"code":"ADMIN_RESTART_CANCELED"}' };
  };
  await restartElevated(f.options);
  const values = ['C:\\MC Proxy\\', 'literal "quoted" value', '$([Environment]::Exit(99)) `value'];
  const helperBase64 = Buffer.from(helper, 'utf8').toString('base64'), valuesBase64 = Buffer.from(JSON.stringify(values)).toString('base64');
  const script = `
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${helperBase64}'))
$tokens=$null;$errors=$null
[void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'Helper syntax is invalid'}
$start=$text.IndexOf('function Quote-Argument')
$end=$text.IndexOf([char]10+'try {',$start)
. ([scriptblock]::Create($text.Substring($start,$end-$start)))
$values=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${valuesBase64}')) | ConvertFrom-Json
@($values | ForEach-Object { Quote-Argument ([string]$_) }) | ConvertTo-Json -Compress
`;
  const output = execFileSync(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 16384 });
  assert.deepEqual(JSON.parse(output.replace(/^\uFEFF/, '').trim()), values.map(quoteWindowsArgument));
});
