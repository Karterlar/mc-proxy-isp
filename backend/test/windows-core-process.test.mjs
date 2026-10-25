import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { PassThrough } from 'node:stream';
import { launchWindowsCore, closeWindowsCore } from '../src/windows-core-process.mjs';

const tick = () => new Promise(resolve => setImmediate(resolve));
function helperFixture() {
  const helper = new EventEmitter(); helper.pid = 201; helper.stdin = new PassThrough(); helper.stdout = new PassThrough(); helper.unref = () => {};
  let input = '', invocation;
  helper.stdin.on('data', chunk => { input += chunk; });
  const spawn = (file, args, options) => { invocation = { file, args, options }; return helper; };
  return { helper, spawn, input: () => input, invocation: () => invocation };
}

test('private core launcher commits parent before one start and retains original handle through EOF', async () => {
  const f = helperFixture(); let prepared = 0;
  const pending = launchWindowsCore('C:\\Owned Core\\sing-box.exe', 'C:\\Private Session\\sing-box.json', { spawn: f.spawn, prepare: async pid => { assert.equal(pid, 201); prepared++; } });
  f.helper.stdout.write('MC_CORE:READY\nMC_CORE:READY\n'); await tick();
  assert.equal(prepared, 1); assert.equal(f.input(), 'start\n');
  const invocation = f.invocation(), script = Buffer.from(invocation.args.at(-1), 'base64').toString('utf16le');
  assert.equal(invocation.file, 'powershell.exe'); assert.equal(invocation.options.windowsHide, true);
  assert.match(script, /0x10\|0x200/); assert.match(script, /Finish\(\$launch\)/); assert.doesNotMatch(script, /GetProcessById/);
  const request = JSON.parse(Buffer.from(invocation.options.env.MC_PROXY_CORE_CONSOLE_INPUT, 'base64').toString('utf8'));
  assert.equal(request.config, 'C:\\Private Session\\sing-box.json');
  f.helper.stdout.write('MC_CORE:CREATED:2026-10-06T00:00:00.0000000Z\nMC_CORE:PID:301\n');
  const child = await pending; const exited = once(child, 'exit');
  child.stderr.resume(); f.helper.stdout.write('MC_CORE:EXIT:0\n');
  assert.deepEqual(await exited, [0, null]); assert.equal(child.exitCode, 0); f.helper.emit('close');
});

test('synchronous prepare errors and helper exit during prepare cannot launch late', async () => {
  for (const delayed of [false, true]) {
    const f = helperFixture(); let finish;
    const gate = new Promise(resolve => { finish = resolve; });
    const pending = launchWindowsCore('core.exe', 'owned.json', { spawn: f.spawn, prepare: () => { if (!delayed) throw new Error('private message'); return gate; } });
    const rejected = assert.rejects(pending, cause => cause.code === 'CORE_CONSOLE_START_FAILED' && cause.mayHaveStarted === false && !cause.message.includes('private message'));
    f.helper.stdout.write('MC_CORE:READY\n'); await tick();
    if (delayed) { f.helper.emit('close'); finish(); }
    await rejected; await tick(); assert.equal(f.input(), '');
  }
});

test('all errors after sending start preserve mayHaveStarted even before PID acknowledgement', async () => {
  for (const event of ['close', 'error', 'overflow', 'stdin-error']) {
    const f = helperFixture();
    const pending = launchWindowsCore('core.exe', 'owned.json', { spawn: f.spawn, prepare: () => {} });
    const rejected = assert.rejects(pending, cause => cause.code === 'CORE_CONSOLE_START_FAILED' && cause.mayHaveStarted === true);
    f.helper.stdout.write('MC_CORE:READY\n'); await tick(); assert.equal(f.input(), 'start\n');
    if (event === 'overflow') f.helper.stdout.write('x'.repeat(65537));
    else if (event === 'stdin-error') f.helper.stdin.emit('error', new Error('pipe ended'));
    else f.helper.emit(event, new Error('helper ended'));
    await rejected;
  }
});

test('multiple valid stderr lines may exceed 64KiB while malformed single-line output is bounded', async () => {
  const f = helperFixture(); const pending = launchWindowsCore('core.exe', 'owned.json', { spawn: f.spawn, prepare: () => {} });
  f.helper.stdout.write('MC_CORE:READY\n'); await tick(); f.helper.stdout.write('MC_CORE:PID:301\n');
  const child = await pending; child.stderr.resume(); const errors = []; child.on('error', cause => errors.push(cause.code));
  const line = `MC_CORE:STDERR:${Buffer.alloc(4096, 120).toString('base64')}\n`;
  f.helper.stdout.write(line.repeat(20)); await tick(); assert.deepEqual(errors, []);
  f.helper.stdout.write('x'.repeat(65537)); assert.deepEqual(errors, ['CORE_CONSOLE_CLOSE_FAILED']);
  assert.equal(f.helper.stdout.destroyed, true); f.helper.emit('close');
});

test('close signals only the private target group after held-handle identity checks and rejects already-exited targets', async () => {
  let invocation;
  const identity = { pid: 301, executable: 'C:\\Owned Core\\sing-box.exe', createdAt: '2026-10-06T00:00:00.0000000Z' };
  const result = await closeWindowsCore(identity, { execFile: (file, args, options, callback) => {
    invocation = { file, args, options }; callback(null, JSON.stringify({ closed: true, exitCode: 0 }));
  } });
  assert.deepEqual(result, { closed: true, exitCode: 0 });
  const script = Buffer.from(invocation.args.at(-1), 'base64').toString('utf16le');
  assert.match(script, /OpenProcess\(0x100000\|0x1000/); assert.match(script, /GetProcessTimes/); assert.match(script, /QueryFullProcessImageNameW/);
  assert.match(script, /GetConsoleProcessList/); assert.match(script, /count>2/); assert.match(script, /GenerateConsoleCtrlEvent\(1,pid\)/);
  assert.match(script, /WaitForSingleObject\(handle,0\)==0\) throw/); assert.doesNotMatch(script, /TerminateProcess|taskkill|Stop-Process|GenerateConsoleCtrlEvent\(0,0\)/);
  assert.equal(invocation.options.windowsHide, true);
});

test('close failures use fixed safe categories and require verified zero exit', async () => {
  const identity = { pid: 301, executable: 'core.exe', createdAt: '2026-10-06T00:00:00Z' };
  for (const [response, code] of [[{ closed: true, exitCode: 1 }, 'CORE_CONSOLE_CLOSE_FAILED'], [{ closed: false, code: 'CORE_CONSOLE_NOT_PRIVATE' }, 'CORE_CONSOLE_NOT_PRIVATE'], [{ closed: false, code: 'private error' }, 'CORE_CONSOLE_CLOSE_FAILED'], ['not json', 'CORE_CONSOLE_CLOSE_FAILED']]) {
    await assert.rejects(closeWindowsCore(identity, { execFile: (_, __, ___, callback) => callback(new Error('private error'), typeof response === 'string' ? response : JSON.stringify(response)) }), cause => cause.code === code && !cause.message.includes('private error'));
  }
});
