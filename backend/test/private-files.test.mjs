import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createPrivateDirectory, renamePrivate } from '../src/private-files.mjs';

test('private Windows directory ACL commands are hidden and bounded before private output is written', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'proxypilot-private-acl-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const calls = [];
  const directory = path.join(root, 'private');
  const systemRoot = 'C:\\Windows';
  await createPrivateDirectory(directory, { platform: 'win32', systemRoot, run: (file, args, options) => {
    calls.push({ file, args }); assert.equal(options.timeout, 15000); assert.equal(options.maxBuffer, 65536); assert.equal(options.windowsHide, true);
    return { status: 0, stdout: path.win32.basename(file) === 'whoami.exe' ? '"synthetic-user","S-1-5-21-123-456-789-1001"' : '' };
  } });
  assert.deepEqual(calls.map(call => call.file), ['C:\\Windows\\System32\\whoami.exe', 'C:\\Windows\\System32\\icacls.exe']);
  assert.ok(calls.every(call => path.win32.isAbsolute(call.file)), 'native tools must not be resolved through PATH');
  assert.deepEqual(calls[0].args, ['/user', '/fo', 'csv', '/nh']);
  assert.deepEqual(calls[1].args, [directory, '/inheritance:r', '/grant:r', '*S-1-5-21-123-456-789-1001:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']);
  assert.equal(await readFile(path.join(directory, '.gitignore'), 'utf8'), '*\n');
});

test('ACL timeout or failed user lookup never writes private output or exposes native error text', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'proxypilot-private-acl-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [index, failedCommand] of ['whoami.exe', 'icacls.exe'].entries()) {
    const directory = path.join(root, `failed-${index}`);
    await assert.rejects(createPrivateDirectory(directory, { platform: 'win32', run: file => path.win32.basename(file) === failedCommand
      ? { status: 0, stdout: 'S-1-5-21-123-456-789-1001', error: Object.assign(new Error('PRIVATE_NATIVE_ERROR'), { code: 'ETIMEDOUT' }) }
      : { status: 0, stdout: 'S-1-5-21-123-456-789-1001' } }), cause => cause.code === 'ACL_FAILED' && !cause.message.includes('PRIVATE_NATIVE_ERROR'));
    assert.deepEqual(await readdir(directory), []);
  }
  const directory = path.join(root, 'bad-exit'); let calls = 0;
  await assert.rejects(createPrivateDirectory(directory, { platform: 'win32', run: () => { calls++; return { status: 1, stdout: 'S-1-5-21-123-456-789-1001' }; } }), { code: 'ACL_FAILED' });
  assert.equal(calls, 1); assert.deepEqual(await readdir(directory), []);
});

test('asynchronous ACL checks keep the event loop free and defer output until restrictions succeed', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'proxypilot-private-async-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const directory = path.join(root, 'private');
  let allowAcl, enteredAcl;
  const aclStarted = new Promise(resolve => { enteredAcl = resolve; });
  const aclResult = new Promise(resolve => { allowAcl = resolve; });
  const pending = createPrivateDirectory(directory, { platform: 'win32', run: async file => {
    if (path.win32.basename(file) === 'whoami.exe') return { status: 0, stdout: 'S-1-5-21-123-456-789-1001' };
    enteredAcl(); await aclResult; return { status: 0, stdout: '' };
  } });
  await aclStarted;
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(await readdir(directory), []);
  allowAcl(); await pending;
  assert.equal(await readFile(path.join(directory, '.gitignore'), 'utf8'), '*\n');
  const rejected = path.join(root, 'rejected');
  await assert.rejects(createPrivateDirectory(rejected, { platform: 'win32', run: async () => { throw new Error('PRIVATE_NATIVE_ERROR'); } }),
    cause => cause.code === 'ACL_FAILED' && !cause.message.includes('PRIVATE_NATIVE_ERROR'));
  assert.deepEqual(await readdir(rejected), []);
});

test('Windows journal replacement retries temporary sharing failures and retains bounded failures', async () => {
  const calls = []; const waits = []; let denied = 2;
  const rename = async (...args) => { calls.push(args); if (denied-- > 0) throw Object.assign(new Error('sharing'), { code: 'EPERM' }); };
  await renamePrivate('staged.tmp', 'journal.json', { rename, platform: 'win32', wait: async ms => waits.push(ms) });
  assert.deepEqual(waits, [25, 50]); assert.equal(calls.length, 3);
  assert.ok(calls.every(args => args[0] === 'staged.tmp' && args[1] === 'journal.json'));
  calls.length = 0; denied = 99;
  await assert.rejects(renamePrivate('staged.tmp', 'journal.json', { rename, platform: 'win32', wait: async () => {} }), { code: 'EPERM' });
  assert.equal(calls.length, 5);
  calls.length = 0;
  await assert.rejects(renamePrivate('staged.tmp', 'journal.json', { rename, platform: 'linux', wait: async () => { throw new Error('unexpected retry'); } }), { code: 'EPERM' });
  assert.equal(calls.length, 1);
});
