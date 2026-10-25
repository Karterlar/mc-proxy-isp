import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, readdir, stat, link, rm, open } from 'node:fs/promises';
import { createClientLog } from '../client-log.mjs';
import { CONTROL_ERROR_CODES } from '../../backend/src/local-controller.mjs';

test('client log retains bounded CONNECT and target statuses without raw upstream details', async t => {
  const { root: directory } = await fixture(t);
  const log = createClientLog({ directory, knownCodes: ['PROXY_CONNECT_REJECTED', 'SETUP_CHECK_FAILED'] });
  await log.write('controller diagnostic', { code: 'PROXY_CONNECT_REJECTED', diagnostic: { stage: 'proxy-connect', connectHttpStatus: 502, targetHttpStatus: 500, message: 'PRIVATE_UPSTREAM_SECRET' } });
  await log.write('controller diagnostic', { code: 'SETUP_CHECK_FAILED', diagnostic: { checks: [
    { source: 'ipify', code: 'PROBE_HTTP_STATUS', stage: 'target-response', targetHttpStatus: 500, url: 'PRIVATE_UPSTREAM_SECRET' },
    { source: 'private-server-name', code: 'PROXY_CONNECT_REJECTED', connectHttpStatus: 407 },
  ] } });
  const text = await readFile(log.path, 'utf8'), entries = text.trim().split('\n').map(JSON.parse);
  assert.deepEqual(entries[0].diagnostic, { stage: 'proxy-connect', connectHttpStatus: 502 });
  assert.deepEqual(entries[1].diagnostic.checks, [{ source: 'ipify', code: 'PROBE_HTTP_STATUS', stage: 'target-response', targetHttpStatus: 500 }]);
  assert.doesNotMatch(text, /PRIVATE_UPSTREAM_SECRET|private-server-name/);
});

async function fixture(t) {
  const prefix = path.resolve(import.meta.dirname, '.client-log-test-'), root = await mkdtemp(prefix);
  assert.ok(path.resolve(root).startsWith(prefix));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, file: path.join(root, 'desktop.log') };
}

test('partial environment results retain their production code and country field without profile values', async t => {
  const { root: directory } = await fixture(t), log = createClientLog({ directory, knownCodes: CONTROL_ERROR_CODES });
  await log.write('controller diagnostic', { code: 'ENVIRONMENT_PARTIAL', operation: 'environment-optimization', diagnostic: {
    environmentFields: ['languages', 'homeGeoId', 'PRIVATE_FIELD'], countryCode: 'PRIVATE_COUNTRY', profile: 'PRIVATE_PROFILE',
  } });
  const text = await readFile(log.path, 'utf8'), entry = JSON.parse(text);
  assert.equal(entry.code, 'ENVIRONMENT_PARTIAL');
  assert.deepEqual(entry.diagnostic.environmentFields, ['languages', 'homeGeoId']);
  assert.doesNotMatch(text, /PRIVATE/);
});

test('setup failure logs retain production codes and bounded native evidence without exception text', async t => {
  const { root: directory } = await fixture(t), log = createClientLog({ directory, knownCodes: CONTROL_ERROR_CODES });
  for (const code of ['OUTPUT_UNAVAILABLE', 'SETUP_VERIFICATION_FAILED']) {
    await log.write('controller diagnostic', { code, operation: 'checking-imported-node', message: 'PRIVATE_MESSAGE', stack: 'PRIVATE_STACK', diagnostic: {
      setupStage: 'starting-proxy', nativeCode: 'EACCES', nativeError: 'Error', path: 'PRIVATE_PATH', syscall: 'PRIVATE_COMMAND', password: 'PRIVATE_PASSWORD',
    } });
  }
  await log.write('controller diagnostic', { code: 'SETUP_VERIFICATION_FAILED', diagnostic: {
    setupStage: 'PRIVATE_STAGE', nativeCode: 'PRIVATE_CODE', nativeError: 'PRIVATE_ERROR', rawOutput: 'PRIVATE_OUTPUT',
  } });
  const text = await readFile(log.path, 'utf8'), records = text.trim().split('\n').map(JSON.parse);
  assert.deepEqual(records.map(record => record.code), ['OUTPUT_UNAVAILABLE', 'SETUP_VERIFICATION_FAILED', 'SETUP_VERIFICATION_FAILED']);
  for (const record of records.slice(0, 2)) {
    assert.equal(record.stage, 'checking-imported-node');
    assert.deepEqual(record.diagnostic, { setupStage: 'starting-proxy', nativeCode: 'EACCES', nativeError: 'Error' });
  }
  assert.equal(records[2].diagnostic, undefined); assert.doesNotMatch(text, /PRIVATE|password|stack|syscall|rawOutput/);
});

test('Cowork service failures retain precise fixed errors without service identity or raw native output', async t => {
  const { root: directory } = await fixture(t), log = createClientLog({ directory });
  await log.write('desktop action incomplete', { code: 'CLAUDE_STARTUP_ACCESS_DENIED', diagnostic: { servicePath: 'PRIVATE_PATH', rawOutput: 'PRIVATE_NATIVE_OUTPUT' } });
  const text = await readFile(log.path, 'utf8');
  assert.equal(JSON.parse(text).code, 'CLAUDE_STARTUP_ACCESS_DENIED');
  assert.doesNotMatch(text, /PRIVATE/);
});

test('concurrent writes retain ordered valid records and rotate only three fixed bounded files', async t => {
  const f = await fixture(t); let clock = 0;
  const log = createClientLog({ directory: f.root, maxBytes: 256, now: () => clock++ });
  assert.equal(log.status().ok, true);
  const results = await Promise.all(Array.from({ length: 25 }, () => log.write('desktop ready')));
  assert.ok(results.every(Boolean)); await log.flush();
  assert.deepEqual((await readdir(f.root)).sort(), ['desktop.log', 'desktop.log.1', 'desktop.log.2']);
  const entries = [];
  for (const name of ['desktop.log.2', 'desktop.log.1', 'desktop.log']) {
    assert.ok((await stat(path.join(f.root, name))).size <= 256);
    entries.push(...(await readFile(path.join(f.root, name), 'utf8')).trim().split('\n').map(line => JSON.parse(line)));
  }
  const times = entries.map(entry => Date.parse(entry.at));
  assert.deepEqual(times, [...times].sort((a, b) => a - b)); assert.equal(times.at(-1), 24);
  assert.ok(entries.length < 25); assert.equal(log.status().ok, true);
});

test('log records fixed code and sanitized diagnostics while dropping raw exceptions, unknown events and private values', async t => {
  const f = await fixture(t), log = createClientLog({ directory: f.root, knownCodes: ['ENVIRONMENT_VERIFY_FAILED', 'NETWORK_LOCK_WINDOWS_FAILED'] });
  await log.write('PRIVATE_PASSWORD_AND_URI', { code: 'PRIVATE_CODE', message: 'https://user:password@private.invalid/', stack: 'PRIVATE_STACK', operation: 'bad PRIVATE_STAGE',
    diagnostic: { url: 'PRIVATE_URL', username: 'PRIVATE_USERNAME' } });
  await log.write('controller diagnostic', { code: 'NETWORK_LOCK_WINDOWS_FAILED', operation: 'checking-firewall', diagnostic: { operation: 'add', command: 'New-NetFirewallRule',
    category: 'InvalidOperation', rule: 'loopback', hResult: -2147217407, target: 'PRIVATE_TARGET' } });
  await log.write('controller diagnostic', { code: 'ENVIRONMENT_VERIFY_FAILED', operation: 'environment-optimization', diagnostic: { environmentStage: 'apply-input-method',
    environmentFields: ['defaultInputMethod', 'PRIVATE_VALUE', 'culture'], rollbackEnvironmentFields: ['languages'], httpStatus: 403, signal: 'SIGTERM', exitCode: 1, password: 'PRIVATE_PASSWORD' } });
  await log.write('network repair complete', { code: 'LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES', diagnostic: { skippedAllowRules: 2 } });
  const contents = await readFile(f.file, 'utf8'); assert.doesNotMatch(contents, /PRIVATE_|private\.invalid|username|password|stack/);
  const records = contents.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(records[0].code, 'OPERATION_FAILED'); assert.equal(records[1].stage, 'checking-firewall');
  assert.equal(records[1].diagnostic.command, 'New-NetFirewallRule'); assert.equal(records[1].diagnostic.hResult, -2147217407);
  assert.deepEqual(records[2].diagnostic.environmentFields, ['defaultInputMethod', 'culture']); assert.equal(records[2].diagnostic.httpStatus, 403);
  assert.equal(records[3].code, 'LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES'); assert.equal(records[3].diagnostic.skippedAllowRules, 2);
});

test('verified startup permission logs retain only token and capability facts', async t => {
  const f=await fixture(t),log=createClientLog({directory:f.root});
  await log.write('desktop permission verified',{code:'ADMIN_VERIFIED',diagnostic:{checked:true,elevated:true,adminMember:true,
    integrity:'high',tokenMatched:true,capabilityVerified:true,userSid:'PRIVATE_SID',processId:123,executable:'PRIVATE_PATH',capabilityError:0}});
  const text=await readFile(f.file,'utf8'),record=JSON.parse(text.trim());
  assert.equal(record.event,'desktop permission verified'); assert.equal(record.code,'ADMIN_VERIFIED');
  assert.deepEqual(record.diagnostic,{checked:true,elevated:true,adminMember:true,tokenMatched:true,capabilityVerified:true,integrity:'high'});
  assert.doesNotMatch(text,/PRIVATE|userSid|processId|executable|capabilityError/);
});

test('linked or non-regular rotation targets are refused before any owned log changes', async t => {
  const f = await fixture(t); await writeFile(f.file, 'retain active log\n');
  const old = await readFile(f.file);
  const linked = createClientLog({ directory: f.root, dependencies: { lstat: async target => {
    if (target.endsWith('.1')) return { isFile: () => true, isSymbolicLink: () => true };
    return (await import('node:fs/promises')).lstat(target);
  } } });
  assert.equal(await linked.write('desktop ready'), false); assert.equal(linked.status().errorCode, 'DESKTOP_LOG_UNSAFE');
  assert.deepEqual(await readFile(f.file), old);
  const outside = path.join(f.root, 'unrelated-owned-fixture.txt'); await writeFile(outside, 'unrelated fixture'); await link(outside, `${f.file}.1`);
  const hardLinked = createClientLog({ directory: f.root });
  assert.equal(await hardLinked.write('desktop ready'), false); assert.equal(hardLinked.status().errorCode, 'DESKTOP_LOG_UNSAFE');
  assert.deepEqual(await readFile(f.file), old); assert.equal(await readFile(outside, 'utf8'), 'unrelated fixture');
});

test('write failure is visible without private error text and serial queue recovers for later writes', async t => {
  const f = await fixture(t); let failed = true;
  const log = createClientLog({ directory: f.root, dependencies: { open: async (...args) => {
    if (failed) throw new Error('PRIVATE_PATH_AND_PASSWORD'); return open(...args);
  } } });
  assert.equal(await log.write('desktop ready'), false); assert.equal(log.status().errorCode, 'DESKTOP_LOG_WRITE_FAILED');
  assert.ok(log.status().lastFailureAt); assert.doesNotMatch(JSON.stringify(log.status()), /PRIVATE_/);
  failed = false; assert.equal(await log.write('desktop ready'), true); assert.equal(log.status().ok, true);
  assert.equal(log.status().errorCode, null); assert.ok(log.status().lastFailureAt);
  assert.equal(log.status().lastFailureCode, 'DESKTOP_LOG_WRITE_FAILED');
});

test('pending log work has a fixed cap and dropped records remain visible after successful queued work', async t => {
  const f = await fixture(t); let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const log = createClientLog({ directory: f.root, dependencies: { open: async (...args) => { await blocked; return open(...args); } } });
  const pending = Array.from({ length: 256 }, () => log.write('desktop ready'));
  assert.equal(await log.write('desktop ready'), false); assert.equal(log.status().errorCode, 'DESKTOP_LOG_OVERLOADED');
  release(); assert.ok((await Promise.all(pending)).every(Boolean)); await log.flush();
  assert.equal(log.status().lastFailureCode, 'DESKTOP_LOG_OVERLOADED');
});

test('legacy oversized files keep a bounded recent tail and short filesystem writes complete before flush', async t => {
  const f = await fixture(t); await writeFile(f.file, Array.from({ length: 200 }, (_, index) => `legacy line ${index}\n`).join(''));
  const log = createClientLog({ directory: f.root, maxBytes: 256, dependencies: { open: async (...args) => {
    const handle = await open(...args), write = handle.write.bind(handle);
    handle.write = (bytes, offset, length, position) => write(bytes, offset, Math.min(length, 7), position);
    return handle;
  } } });
  assert.equal(await log.write('desktop ready'), true); await log.flush();
  for (const name of await readdir(f.root)) assert.ok((await stat(path.join(f.root, name))).size <= 256);
  const all = await Promise.all((await readdir(f.root)).map(name => readFile(path.join(f.root, name), 'utf8')));
  assert.ok(all.some(value => value.includes('legacy line 199'))); assert.ok(all.some(value => value.includes('desktop ready')));
});
