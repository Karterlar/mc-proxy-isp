import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { getClaudeBackground, openClaudeServices, createClaudeBackgroundManager } from '../claude-background.mjs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createPrivateDirectory, writePrivate } from '../../backend/src/private-files.mjs';

const observation = {
  present: true, name: 'CoworkVMService', state: 'Running', startMode: 'Auto', systemAccount: true,
  executable: 'C:\\Program Files\\WindowsApps\\Claude_2.31226.1.0_x64__pzs8sxrjxfjjc\\app\\resources\\cowork-svc.exe',
  programFiles: 'C:\\Program Files', signatureStatus: 'Valid', signer: 'Anthropic, PBC',
  fileHash: 'a'.repeat(64), signerThumbprint: 'b'.repeat(40), userSid: 'S-1-5-21-123-456-789-1001',
  machineGuid: '12345678-1234-4234-8234-123456789abc', elevated: true, delayedAuto: false,
  registryStart: 2, registryDelayedPresent: false, registryDelayedValue: null, readStatus: 'ok',
};
const inspect = value => getClaudeBackground({ platform: 'win32', executeFile: async () => ({ stdout: JSON.stringify({ ok: true, observation: value }) }) });

test('Claude service replies require the exact service, official package path and valid Anthropic signature without exposing host metadata', async () => {
  assert.deepEqual(await inspect(observation), { present: true, state: 'running', startMode: 'automatic',
    identity: 'verified', systemAccount: true, mock: false, trusted: true, canRestore: false, startupManaged: false,
    registryStart: 2, readStatus: 'ok', code: 'CLAUDE_BACKGROUND_VERIFIED' });
  assert.deepEqual(await inspect({ ...observation, state: 'Stopped', startMode: 'Manual', systemAccount: false }),
    { present: true, state: 'stopped', startMode: 'manual', identity: 'verified', systemAccount: false, mock: false, trusted: true, canRestore: false, startupManaged: false,
      registryStart: 2, readStatus: 'ok', code: 'CLAUDE_BACKGROUND_VERIFIED' });
  for (const patch of [
    { executable: 'C:\\Users\\test\\cowork-svc.exe' },
    { executable: observation.executable + ' --argument' },
    { executable: '"' + observation.executable + '" --argument' },
    { executable: observation.executable.replace('pzs8sxrjxfjjc', 'wrongpublisher') },
    { executable: observation.executable.replace('resources\\', 'resources\\..\\resources\\') },
    { executable: observation.executable.replace('WindowsApps', 'WindowsApps-fake') },
    { signer: 'Unknown Vendor' }, { signatureStatus: 'HashMismatch' },
  ]) {
    const result = await inspect({ ...observation, ...patch });
    assert.equal(result.trusted, false); assert.equal(result.identity, 'unverified');
    assert.doesNotMatch(JSON.stringify(result), /WindowsApps|cowork-svc\.exe|Unknown Vendor|Users|executable|signer|signatureStatus/);
  }
  assert.equal((await inspect({ ...observation, name: 'CoworkVMService-imposter' })).code, 'CLAUDE_BACKGROUND_CHECK_FAILED');
  assert.equal((await inspect({ ...observation, state: 'Start Pending', startMode: 'Bogus' })).state, 'unknown');
  assert.equal((await inspect({ ...observation, state: 'Start Pending', startMode: 'Disabled' })).startMode, 'disabled');
  const unverified = await inspect({ ...observation, signatureStatus: 'Unavailable' });
  assert.equal(unverified.trusted, 'unverified'); assert.equal(unverified.code, 'CLAUDE_BACKGROUND_CHECK_FAILED');
});

test('the fixed read-only query handles missing services, platform limits, malformed data and private process errors safely', async () => {
  const missing = await inspect({ present: false });
  assert.equal(missing.present, false); assert.equal(missing.state, 'stopped'); assert.equal(missing.code, 'CLAUDE_BACKGROUND_NOT_FOUND');
  for (const executeFile of [async () => { throw new Error('secret private C:\\Users\\owner'); }, async () => ({ stdout: 'malformed private data' })]) {
    const result = await getClaudeBackground({ platform: 'win32', executeFile });
    assert.equal(result.state, 'unknown'); assert.equal(result.code, 'CLAUDE_BACKGROUND_CHECK_FAILED');
    assert.doesNotMatch(JSON.stringify(result), /secret|private|Users|owner/);
  }
  const fixed = await getClaudeBackground({ platform: 'win32', systemRoot: 'C:\\Windows', executeFile: async (executable, args, options) => {
    assert.equal(executable, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
    assert.match(args[3], /-Filter "Name='CoworkVMService'"/);
    assert.doesNotMatch(args[3], /Stop-Service|Set-Service|Start-Service|Stop-Process|taskkill|Win32_Process/);
    const request = JSON.parse(Buffer.from(options.env.MC_PROXY_CLAUDE_SERVICE_INPUT, 'base64').toString());
    assert.deepEqual(request, { operation: 'inspect' });
    assert.equal(options.windowsHide, true); assert.equal(options.timeout, 15_000);
    return { stdout: '\uFEFF' + JSON.stringify({ ok: true, observation }) };
  } });
  assert.equal(fixed.trusted, true);
  const never = () => assert.fail('must not invoke an OS command');
  assert.equal((await getClaudeBackground({ platform: 'darwin', executeFile: never })).code, 'CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
  assert.equal((await getClaudeBackground({ mock: true, executeFile: never })).mock, true);
  assert.equal((await getClaudeBackground({ platform: 'win32', systemRoot: 'relative', executeFile: never })).code, 'CLAUDE_BACKGROUND_CHECK_FAILED');
});

async function fixture(t, initial = {}, overrides = {}) {
  const cache = path.resolve('.cache'); await mkdir(cache, { recursive: true });
  const userData = await mkdtemp(path.join(cache, 'claude-service-unit-'));
  t.after(async () => { assert.equal(path.dirname(userData), cache); assert.match(path.basename(userData), /^claude-service-unit-/); await rm(userData, { recursive: true, force: true }); });
  let actual = { ...observation, ...initial, registryStart: initial.registryStart ?? { Auto: 2, Manual: 3, Disabled: 4 }[initial.startMode || 'Auto'],
    registryDelayedPresent: initial.registryDelayedPresent ?? initial.delayedAuto === true,
    registryDelayedValue: initial.registryDelayedValue ?? (initial.registryDelayedPresent === true ? initial.delayedAuto ? 1 : 0 : initial.delayedAuto ? 1 : null) }; const requests = [];
  const executeFile = async (_file, _args, options) => {
    const request = JSON.parse(Buffer.from(options.env.MC_PROXY_CLAUDE_SERVICE_INPUT, 'base64').toString()); requests.push(request);
    if (overrides.native) { const reply = await overrides.native(request, actual); if (reply) return { stdout: JSON.stringify(reply) }; }
    if (request.operation === 'disable') actual = { ...actual, startMode: 'Disabled', registryStart: 4 };
    if (request.operation === 'restore') actual = { ...actual, startMode: request.restoreMode === 'demand' ? 'Manual' : 'Auto', delayedAuto: request.restoreMode === 'delayed-auto',
      registryStart: request.restoreMode === 'demand' ? 3 : 2, registryDelayedPresent: true, registryDelayedValue: request.restoreMode === 'delayed-auto' ? 1 : 0 };
    return { stdout: JSON.stringify({ ok: true, observation: actual }) };
  };
  const manager = createClaudeBackgroundManager({ userData, platform: 'win32', executeFile,
    createDirectory: directory => createPrivateDirectory(directory, { platform: 'linux' }), ...overrides.dependencies });
  return { manager, requests, file: path.join(userData, 'claude-background', 'startup.json'), get actual() { return actual; }, set actual(value) { actual = value; } };
}

test('startup changes preserve the original automatic, delayed-automatic and manual modes without stopping a running service', async t => {
  for (const original of [{ startMode: 'Auto', delayedAuto: false }, { startMode: 'Auto', delayedAuto: true }, { startMode: 'Manual', delayedAuto: false }]) {
    const f = await fixture(t, original); assert.equal(f.requests.length, 0);
    const disabled = await f.manager.disableStartup();
    assert.equal(disabled.code, 'CLAUDE_STARTUP_DISABLED'); assert.equal(disabled.startMode, 'disabled'); assert.equal(disabled.state, 'running'); assert.equal(disabled.canRestore, true);
    const record = JSON.parse(await readFile(f.file, 'utf8'));
    assert.equal(record.phase, 'applied'); assert.equal(record.originalMode, original.startMode); assert.equal(record.delayedAuto, original.delayedAuto);
    assert.equal((await f.manager.inspect()).startupManaged, true);
    assert.equal((await f.manager.disableStartup()).changed, false);
    assert.equal(f.requests.filter(request => request.operation === 'disable').length, 1);
    const restored = await f.manager.restoreStartup();
    assert.equal(restored.code, 'CLAUDE_STARTUP_RESTORED'); assert.equal(restored.canRestore, false); assert.equal(restored.state, 'running');
    assert.equal(f.actual.startMode, original.startMode); assert.equal(f.actual.delayedAuto, original.delayedAuto);
    assert.equal(JSON.parse(await readFile(f.file, 'utf8')).phase, 'restored');
    assert.doesNotMatch(JSON.stringify(disabled) + JSON.stringify(restored), /WindowsApps|S-1-5|machineGuid|fileHash|signerThumbprint|startup\.json/);
  }
});

test('untrusted identity, non-admin tokens and already-disabled settings cause no native mutation', async t => {
  for (const [patch, code] of [[{ elevated: false }, 'CLAUDE_STARTUP_ADMIN_REQUIRED'], [{ signer: 'Fake Vendor' }, 'CLAUDE_STARTUP_IDENTITY_UNVERIFIED'], [{ fileHash: '' }, 'CLAUDE_STARTUP_IDENTITY_UNVERIFIED']]) {
    const f = await fixture(t, patch); await assert.rejects(f.manager.disableStartup(), cause => cause.code === code);
    assert.equal(f.requests.some(request => request.operation !== 'inspect'), false);
    await assert.rejects(readFile(f.file), cause => cause.code === 'ENOENT');
  }
  const disabled = await fixture(t, { startMode: 'Disabled' });
  assert.equal((await disabled.manager.disableStartup()).code, 'CLAUDE_STARTUP_ALREADY_DISABLED');
  await assert.rejects(disabled.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
  assert.equal(disabled.requests.some(request => request.operation !== 'inspect'), false);
});

test('restoration rejects foreign user or machine bindings, service updates and external mode changes', async t => {
  for (const patch of [{ userSid: 'S-1-5-21-123-456-789-1002' }, { machineGuid: '92345678-1234-4234-8234-123456789abc' },
    { fileHash: 'c'.repeat(64) }, { signerThumbprint: 'd'.repeat(40) }, { executable: observation.executable.replace('2.31226.1.0', '2.31227.1.0') }, { startMode: 'Manual' }]) {
    const f = await fixture(t); await f.manager.disableStartup(); f.actual = { ...f.actual, ...patch };
    assert.equal((await f.manager.inspect()).canRestore, false);
    await assert.rejects(f.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
    assert.equal(f.requests.some(request => request.operation === 'restore'), false);
    assert.equal(JSON.parse(await readFile(f.file, 'utf8')).phase, 'applied');
  }
});

test('protected-service denial is private and retryable only after confirming nothing changed', async t => {
  const f = await fixture(t, {}, { native: async request => request.operation === 'disable' ? { ok: false, code: 'CLAUDE_STARTUP_ACCESS_DENIED', raw: 'secret native path' } : null });
  await assert.rejects(f.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_ACCESS_DENIED' && !cause.message);
  assert.equal(JSON.parse(await readFile(f.file, 'utf8')).phase, 'restored');
  assert.equal((await f.manager.inspect()).startMode, 'automatic');
  assert.equal((await f.manager.inspect()).canRestore, false);
});

test('mutation waits for safe intent persistence and keeps uncertain changes unrecoverable automatically', async t => {
  const noRecord = await fixture(t, {}, { dependencies: { createDirectory: async () => { throw new Error('private ACL denied'); } } });
  await assert.rejects(noRecord.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_RECORD_FAILED');
  assert.equal(noRecord.requests.some(request => request.operation !== 'inspect'), false);
  const noCommit = await fixture(t, {}, { dependencies: { writeFile: async (file, content) => {
    if (JSON.parse(content).phase === 'applied') throw new Error('private journal locked'); await writePrivate(file, content);
  } } });
  await assert.rejects(noCommit.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_UNCONFIRMED');
  assert.equal(noCommit.actual.startMode, 'Disabled'); assert.equal(JSON.parse(await readFile(noCommit.file, 'utf8')).phase, 'intent');
  const status = await noCommit.manager.inspect(); assert.equal(status.code, 'CLAUDE_STARTUP_UNCONFIRMED'); assert.equal(status.canRestore, false);
  await assert.rejects(noCommit.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
  const invalidAfter = await fixture(t, {}, { native: async (request, actual) => request.operation === 'disable'
    ? { ok: true, observation: { ...actual, startMode: 'Disabled', signatureStatus: 'HashMismatch' } } : null });
  await assert.rejects(invalidAfter.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_UNCONFIRMED');
  assert.equal(JSON.parse(await readFile(invalidAfter.file, 'utf8')).phase, 'intent');
});

test('malformed recovery records and overlapping actions remain fail-closed, mock changes never call the OS or filesystem', async t => {
  const f = await fixture(t); await f.manager.disableStartup(); await writeFile(f.file, '{private malformed}');
  await assert.rejects(f.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_RECORD_FAILED');
  assert.equal(f.requests.some(request => request.operation === 'restore'), false);
  let release; const pending = await fixture(t, {}, { native: async () => new Promise(resolve => { release = resolve; }) });
  const check = pending.manager.inspect(); await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(pending.manager.disableStartup(), cause => cause.code === 'CLAUDE_BACKGROUND_BUSY');
  release({ ok: true, observation }); await check;
  const mock = createClaudeBackgroundManager({ userData: path.resolve('.cache/not-created-claude-mock'), mock: true,
    executeFile: () => assert.fail('no native command'), createDirectory: () => assert.fail('no directory') });
  assert.equal((await mock.disableStartup()).mock, true); assert.equal((await mock.inspect()).canRestore, true);
  assert.equal((await mock.restoreStartup()).startMode, 'automatic');
});

test('SCM restoration rejects delayed-auto external changes, including missing versus explicit zero', async t => {
    for (const patch of [{ registryDelayedPresent: true, registryDelayedValue: 0 }, { registryDelayedPresent: true, registryDelayedValue: 1, delayedAuto: true }]) {
      const f = await fixture(t); await f.manager.disableStartup(); f.actual = { ...f.actual, ...patch };
      assert.equal((await f.manager.inspect()).code, 'CLAUDE_STARTUP_CONFLICT');
      await assert.rejects(f.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
      assert.equal(f.requests.some(request => request.operation.startsWith('restore')), false);
    }
});

test('registry read denial, invalid types and incomplete snapshots reject SCM changes before saving intent or changing startup', async t => {
    for (const patch of [{ readStatus: 'denied' }, { readStatus: 'invalid' }, { readStatus: 'unknown' }, { registryDelayedPresent: 'false' }, { registryDelayedValue: 2 }, { registryStart: 1 }]) {
      const f = await fixture(t, patch); await assert.rejects(f.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_REGISTRY_UNREADABLE');
      assert.equal(f.requests.some(request => request.operation !== 'inspect'), false);
      await assert.rejects(readFile(f.file), cause => cause.code === 'ENOENT');
    }
});

test('legacy applied records cannot restore without delayed metadata, legacy restored history permits a fresh verified SCM change', async t => {
  const f = await fixture(t); await f.manager.disableStartup();
  const incomplete = JSON.parse(await readFile(f.file, 'utf8')); delete incomplete.appliedDelayedAuto;
  await writeFile(f.file, JSON.stringify(incomplete));
  await assert.rejects(f.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_RECORD_FAILED');
  assert.equal(f.requests.some(request => request.operation === 'restore'), false);
  incomplete.phase = 'restored'; delete incomplete.method; delete incomplete.originalRegistryStart; delete incomplete.originalDelayedAuto; delete incomplete.appliedRegistryStart;
  await writeFile(f.file, JSON.stringify(incomplete)); f.actual = { ...observation };
  const result = await f.manager.disableStartup(); assert.equal(result.code, 'CLAUDE_STARTUP_DISABLED');
  assert.equal(JSON.parse(await readFile(f.file, 'utf8')).method, 'scm');
});

test('unreleased active registry-method records cannot authorize restoration or native mutation', async t => {
  const f = await fixture(t); await f.manager.disableStartup();
  const record = JSON.parse(await readFile(f.file, 'utf8')); record.method = 'registry';
  await writeFile(f.file, JSON.stringify(record));
  const status = await f.manager.inspect(); assert.equal(status.canRestore, false); assert.equal(status.code, 'CLAUDE_STARTUP_CONFLICT');
  await assert.rejects(f.manager.restoreStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
  await assert.rejects(f.manager.disableStartup(), cause => cause.code === 'CLAUDE_STARTUP_CONFLICT');
  assert.equal(f.requests.filter(request => request.operation !== 'inspect').length, 1);
  assert.equal(Object.hasOwn(f.manager, 'disableStartupCompat'), false);
});

test('service management opens only the fixed Windows console and never opens it in mock or unsupported mode', async () => {
  const targets = [];
  assert.deepEqual(await openClaudeServices({ platform: 'win32', systemRoot: 'C:\\Windows', openPath: async target => { targets.push(target); return ''; } }), { opened: true, mock: false });
  assert.deepEqual(targets, ['C:\\Windows\\System32\\services.msc']);
  const never = () => assert.fail('must not open an OS management window');
  assert.deepEqual(await openClaudeServices({ mock: true, openPath: never }), { opened: false, mock: true });
  await assert.rejects(openClaudeServices({ platform: 'darwin', openPath: never }), error => error.code === 'CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
  for (const openPath of [async () => 'secret path failed', async () => { throw new Error('private Windows exception'); }]) {
    await assert.rejects(openClaudeServices({ platform: 'win32', openPath }), error => error.code === 'CLAUDE_SERVICES_OPEN_FAILED' && !error.message);
  }
  await assert.rejects(openClaudeServices({ platform: 'win32', systemRoot: 'C:\\Windows\\..\\evil', openPath: never }), error => error.code === 'CLAUDE_SERVICES_OPEN_FAILED');
});

test('fixed native startup script parses in Windows PowerShell 5.1 and rechecks the admin token and identity before sc config', { skip: process.platform !== 'win32' }, async () => {
  let script;
  await getClaudeBackground({ platform: 'win32', executeFile: async (_file, args) => { script = args[3]; return { stdout: JSON.stringify({ ok: true, observation }) }; } });
  assert.match(script, /Microsoft\.PowerShell\.Security\\Microsoft\.PowerShell\.Security\.psd1/);
  assert.ok(script.indexOf('if (-not $before.elevated)') < script.indexOf('& $sc'));
  assert.ok(script.indexOf('Service identity or configuration changed') < script.indexOf('& $sc'));
  assert.match(script, /\$LASTEXITCODE -eq 5/); assert.match(script, /Service signature changed after configuration/);
  assert.doesNotMatch(script, /Stop-Service|Stop-Process|Start-Service|taskkill|icacls|takeown|Remove-ItemProperty|Set-ItemProperty|New-ItemProperty|disable-compat|restore-compat/);
  assert.match(script, /@\('inspect','disable','restore'\)/);
  const parse = "$source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:MC_PROXY_CLAUDE_PARSE)); $tokens = $null; $errors = $null; [void][Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors); [Console]::WriteLine($errors.Count)";
  const result = await promisify(execFile)(path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoProfile', '-NonInteractive', '-Command', parse], { windowsHide: true, timeout: 10_000, env: { ...process.env, MC_PROXY_CLAUDE_PARSE: Buffer.from(script).toString('base64') } });
  assert.equal(result.stdout.trim(), '0');
});
