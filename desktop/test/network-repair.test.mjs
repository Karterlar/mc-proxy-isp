import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { mkdtemp, writeFile, readFile, rename, rm, symlink, readdir, mkdir } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { launchNetworkRepair } from '../network-repair.mjs';

async function fixture(t) {
  const runtimeRoot = await mkdtemp(path.resolve(import.meta.dirname, '.repair-'));
  t.after(() => rm(runtimeRoot, { recursive: true, force: true }));
  const scriptPath = path.join(runtimeRoot, 'Repair-Network.ps1');
  await writeFile(scriptPath, '# fixture');
  return { runtimeRoot, scriptPath, waitForPid: 123 };
}

function helper(options, events, { failure, afterReady = true, stale = false, report = {}, readyDelayMs = 0, completionDelayMs = 0, cleanupDirectory = false } = {}) {
  let launched;
  const spawnProcess = (file, args, spawnOptions) => {
    events.push('spawn'); launched = { file, args, spawnOptions };
    const requestId = args[args.indexOf('-DesktopRequestId') + 1];
    const requestFile = suffix => path.join(options.runtimeRoot, 'network-repair', `desktop-${requestId}.${suffix}`);
    const child = new EventEmitter();
    queueMicrotask(async () => {
      try {
        if (afterReady) {
          if (readyDelayMs) await delay(readyDelayMs);
          // Match the helper's same-directory atomic ready publication.
          events.push('ready'); await writeFile(requestFile('ready.tmp'), requestId, { flag: 'wx' });
          await rename(requestFile('ready.tmp'), requestFile('ready'));
          let signal;
          while (!signal) {
            try { signal = await readFile(requestFile('continue'), 'utf8'); }
            catch (cause) { if (cause.code !== 'ENOENT') throw cause; await delay(5); }
          }
          events.push(signal === requestId ? 'released' : 'canceled');
        }
        if (completionDelayMs) await delay(completionDelayMs);
        await writeFile(requestFile('result.json'), JSON.stringify({ desktopRequestId: stale ? 'earlier-request' : requestId,
          success: !failure, code: failure || 'LOCAL_FIREWALL_RESTORED', lockReleased: !failure, exitCode: failure ? 2 : 0, skippedAllowRules: 3, ...report }));
        if (cleanupDirectory) { await mkdir(requestFile('ready')); await writeFile(path.join(requestFile('ready'), 'retained'), 'fixture'); }
        events.push('complete'); child.emit('close', failure ? 2 : 0);
      } catch (cause) { child.emit('error', cause); }
    });
    return child;
  };
  return { spawnProcess, launched: () => launched };
}

test('repair waits for elevated helper readiness, ends sessions and reports completion without detaching', async t => {
  const options = await fixture(t); const events = [];
  const fake = helper(options, events);
  const result = await launchNetworkRepair({ ...options, ...fake, stopSessions: async () => { events.push('stopped'); } });
  assert.deepEqual(events, ['spawn', 'ready', 'stopped', 'released', 'complete']);
  assert.equal(result.completed, true); assert.equal(result.success, true); assert.equal(result.skippedAllowRules, 3);
  assert.match(result.reportPath, /desktop-[a-f0-9-]+\.result\.json$/);
  const launched = fake.launched();
  assert.equal(path.basename(launched.file), 'powershell.exe');
  assert.equal(launched.args[launched.args.indexOf('-RuntimeRoot') + 1], options.runtimeRoot);
  assert.deepEqual(launched.args.slice(-3), ['-DesktopPid', '123', '-PreserveChangedRules']);
  assert.equal(launched.args.includes('-WaitForPid'), false); assert.equal(launched.args.includes('-ShowResult'), false);
  assert.equal(launched.spawnOptions.windowsHide, true);
  assert.equal(launched.spawnOptions.detached, undefined);
  assert.equal(launched.spawnOptions.shell, undefined);
});

test('canceled UAC is surfaced before any session stop', async t => {
  const options = await fixture(t); const events = [];
  await assert.rejects(launchNetworkRepair({ ...options, ...helper(options, events, { afterReady: false, failure: 'UAC_CANCELED_OR_ELEVATION_FAILED' }),
    stopSessions: async () => { events.push('stopped'); } }), /管理员授权被取消/);
  assert.deepEqual(events, ['spawn', 'complete']);
});

test('WFP recovery result is accepted only after session stop and confirmed owned lock removal', async t => {
  const options = await fixture(t); const events = [];
  const result = await launchNetworkRepair({ ...options,
    ...helper(options, events, { report: { code: 'LOCAL_WFP_LOCK_RELEASED', skippedAllowRules: 0 } }),
    stopSessions: async () => { events.push('stopped'); } });
  assert.deepEqual(events, ['spawn', 'ready', 'stopped', 'released', 'complete']);
  assert.equal(result.code, 'LOCAL_WFP_LOCK_RELEASED'); assert.equal(result.success, true);
  const invalid = await fixture(t);
  await assert.rejects(launchNetworkRepair({ ...invalid,
    ...helper(invalid, [], { report: { code: 'LOCAL_WFP_LOCK_RELEASED', lockReleased: false } }),
    stopSessions: async () => {} }), /未完成/);
});

test('failed session stop cancels helper instead of releasing firewall mutation', async t => {
  const options = await fixture(t); const events = [];
  await assert.rejects(launchNetworkRepair({ ...options, ...helper(options, events, { failure: 'DESKTOP_REPAIR_CANCELED' }),
    stopSessions: async () => { throw new Error('stop incomplete'); } }), /stop incomplete/);
  assert.equal(events.includes('complete'), true);
  assert.equal(events.includes('released'), false); assert.equal(events.includes('canceled'), true);
  const files = await readdir(path.join(options.runtimeRoot, 'network-repair'));
  assert.equal(files.some(name => name.endsWith('.ready') || name.endsWith('.continue') || name.endsWith('.tmp')), false);
  assert.equal(files.some(name => name.endsWith('.result.json')), true);
});

test('failed helper or a stale report cannot claim restoration after sessions stop', async t => {
  for (const outcome of [{ failure: 'RECOVERY_BACKUP_HASH_MISMATCH' }, { stale: true }]) {
    const options = await fixture(t); const events = [];
    await assert.rejects(launchNetworkRepair({ ...options, ...helper(options, events, outcome), stopSessions: async () => {} }), /未完成|未返回/);
  }
});

test('invalid input and linked helper never launch repair', async t => {
  const options = await fixture(t); let launches = 0;
  const spawnProcess = () => { launches++; throw new Error('unexpected launch'); };
  await assert.rejects(launchNetworkRepair({ ...options, waitForPid: 0, spawnProcess, stopSessions: async () => {} }), /无效/);
  const link = path.join(options.runtimeRoot, 'linked-directory');
  await symlink(options.runtimeRoot, link, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(launchNetworkRepair({ ...options, scriptPath: path.join(link, 'Repair-Network.ps1'), spawnProcess, stopSessions: async () => {} }), /包含链接/);
  assert.equal(launches, 0);
});

test('mock repair touches no disk, stops no sessions and spawns no commands', async () => {
  const forbidden = () => { throw new Error('host action'); };
  assert.deepEqual(await launchNetworkRepair({ mock: true, stopSessions: forbidden, spawnProcess: forbidden }), { launched: false, mock: true });
});

test('helper launch errors leave sessions running without claiming restoration', async t => {
  const options = await fixture(t); let stopped = false;
  await assert.rejects(launchNetworkRepair({ ...options, stopSessions: async () => { stopped = true; }, spawnProcess: () => {
    const child = new EventEmitter(); queueMicrotask(() => { child.emit('error', new Error('denied')); child.emit('close', -4058); }); return child;
  } }), /无法启动/);
  assert.equal(stopped, false);
});

test('malformed helper reports cannot claim successful restoration', async t => {
  for (const report of [{ success: 'true' }, { lockReleased: 'true' }, { skippedAllowRules: '3' },
    { skippedAllowRules: -1 }, { exitCode: '0' }, { code: 'UNEXPECTED_SUCCESS' }]) {
    const options = await fixture(t);
    await assert.rejects(launchNetworkRepair({ ...options, ...helper(options, [], { report }), stopSessions: async () => {} }), /未返回本次修复结果/);
  }
});

test('readiness timeout cancels before stopping sessions and waits for helper acknowledgment', async t => {
  const options = await fixture(t); const events = [];
  await assert.rejects(launchNetworkRepair({ ...options, readyTimeoutMs: 1, cancelTimeoutMs: 1000,
    ...helper(options, events, { readyDelayMs: 200, failure: 'DESKTOP_REPAIR_CANCELED' }),
    stopSessions: async () => { events.push('stopped'); } }), /超时/);
  assert.deepEqual(events, ['spawn', 'ready', 'canceled', 'complete']);
});

test('cleanup failure preserves cancellation outcome and recovery report', async t => {
  const options = await fixture(t);
  await assert.rejects(launchNetworkRepair({ ...options,
    ...helper(options, [], { afterReady: false, failure: 'UAC_CANCELED_OR_ELEVATION_FAILED', cleanupDirectory: true }),
    stopSessions: async () => { assert.fail('must not stop'); } }), /管理员授权被取消/);
  const files = await readdir(path.join(options.runtimeRoot, 'network-repair'));
  assert.equal(files.some(name => name.endsWith('.result.json')), true);
});

test('synchronous launch failure exposes no raw host error and stops no sessions', async t => {
  const options = await fixture(t);
  await assert.rejects(launchNetworkRepair({ ...options,
    spawnProcess: () => { throw new Error('private-host-path-or-secret'); },
    stopSessions: async () => { assert.fail('must not stop'); } }), cause => {
      assert.match(cause.message, /无法启动/); assert.doesNotMatch(cause.message, /private-host/); return true;
    });
});

test('a slow authorized helper returns pending without killing it and preserves a correlated completion', async t => {
  const options = await fixture(t), events = [];
  const pending = await launchNetworkRepair({ ...options, completionTimeoutMs: 5,
    ...helper(options, events, { completionDelayMs: 60 }), stopSessions: async () => { events.push('stopped'); } });
  assert.equal(pending.pending, true); assert.equal(pending.completed, false);
  assert.match(pending.requestId, /^[a-f0-9-]{36}$/);assert.ok(pending.reportPath.includes(pending.requestId));
  assert.deepEqual(events.slice(0,3), ['spawn','ready','stopped']);assert.equal(events.includes('complete'),false);
  assert.equal(await readFile(pending.reportPath.replace(/result\.json$/,'continue'),'utf8'),pending.requestId);
  const completed = await pending.completion;
  assert.equal(completed.completed, true);assert.equal(completed.requestId, pending.requestId);
  assert.deepEqual(events, ['spawn','ready','stopped','released','complete']);
});

test('a pending helper failure stays associated with its request and cannot claim successful restoration', async t => {
  const options = await fixture(t);
  const pending = await launchNetworkRepair({ ...options, completionTimeoutMs: 5,
    ...helper(options, [], { completionDelayMs: 60, failure: 'PROCESS_UNREADABLE' }), stopSessions: async () => {} });
  assert.equal(pending.pending, true);
  await assert.rejects(pending.completion, cause => cause.code === 'PROCESS_UNREADABLE' && cause.reportPath === pending.reportPath);
});
