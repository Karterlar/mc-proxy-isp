import test from 'node:test';
import assert from 'node:assert/strict';
import { createWindowsNetworkLockAdapter, sanitizeNetworkLockDiagnostic } from '../src/windows-network-lock.mjs';

test('large firewall inventories disable sequentially in bounded data-only requests', async () => {
  const calls = []; let running = 0;
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_file, args, options, callback) => {
    running++; assert.equal(running, 1);
    const encoded = options.env.PROXYPILOT_NETWORK_LOCK_REQUEST;
    assert.ok(encoded.length < 16384);
    calls.push(JSON.parse(Buffer.from(encoded, 'base64')));
    assert.ok(!Buffer.from(args.at(-1), 'base64').toString('utf16le').includes('untrusted-name-$('));
    setImmediate(() => { running--; callback(null, '{"ok":true,"value":true}'); });
  } });
  const names = Array.from({ length: 750 }, (_, index) => `untrusted-name-$(literal)-${index}-${'中文'.repeat(20)}`);
  await adapter.disableRules(names);
  assert.ok(calls.length > 5);
  assert.deepEqual(calls.flatMap(call => call.names), names);
  assert.ok(calls.every(call => call.operation === 'disable'));
  assert.ok(calls.every(call => call.names.length <= 16));
});

test('short firewall names still have a per-command work limit and a failed batch prevents later mutations', async () => {
  const calls = [];
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_file, _args, options, callback) => {
    calls.push(JSON.parse(Buffer.from(options.env.PROXYPILOT_NETWORK_LOCK_REQUEST, 'base64')));
    callback(null, calls.length === 2 ? '{"ok":false,"code":"NETWORK_LOCK_WINDOWS_FAILED"}' : '{"ok":true,"value":true}');
  } });
  const names = Array.from({ length: 50 }, (_, index) => `rule-${index}`);
  await assert.rejects(adapter.disableRules(names), { code: 'NETWORK_LOCK_WINDOWS_FAILED' });
  assert.equal(calls.length, 2); assert.ok(calls.every(call => call.names.length === 16));
  assert.deepEqual(calls.flatMap(call => call.names), names.slice(0, 32));
});

test('empty disable lists invoke no command and malformed names fail before mutation', async () => {
  let calls = 0;
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: () => { calls++; } });
  await adapter.disableRules([]);
  await assert.rejects(adapter.disableRules([null]), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  await assert.rejects(adapter.disableRules([...Array.from({ length: 500 }, (_, i) => `rule-${i}`), null]), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  assert.equal(calls, 0);
});

test('adapter captures descriptive settings and avoids PowerShell reserved function keywords', async () => {
  let source;
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_file, args, _options, callback) => { source = Buffer.from(args.at(-1), 'base64').toString('utf16le'); callback(null, '{"ok":true,"value":{}}'); } });
  await adapter.inspect();
  assert.match(source, /function Read-Configuration\(/);
  assert.doesNotMatch(source, /function Configuration\(/);
  assert.doesNotMatch(source.split('\n').find(line => line.includes('$_.Name -notin $skip')), /Description|ElementName/);
  assert.match(source, /'Rule','MainModeRule','Phase1AuthSet','Phase2AuthSet','MainModeCryptoSet','QuickModeCryptoSet'/);
  assert.match(source, /Get-NetIPsecMainModeRule -PolicyStore ActiveStore/);
  assert.match(source, /policyDigest -cne \$request.expectedPolicyDigest/);
});

test('restore guard transmits only the native policy digest and requires it before import', async () => {
  const calls = [];
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_f, _a, options, callback) => { calls.push(JSON.parse(Buffer.from(options.env.PROXYPILOT_NETWORK_LOCK_REQUEST, 'base64'))); callback(null, '{"ok":true,"value":true}'); } });
  await assert.rejects(async () => adapter.importPolicy('C:\\private\\snapshot.wfw', {}), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  assert.equal(calls.length, 0);
  await adapter.importPolicy('C:\\private\\snapshot.wfw', { policyDigest: 'a'.repeat(64), rules: Array.from({ length: 10000 }, () => ({ description: 'not transmitted' })) });
  assert.deepEqual(calls[0], { operation: 'import', path: 'C:\\private\\snapshot.wfw', expectedPolicyDigest: 'a'.repeat(64) });
});

test('idle orphan check is an explicit read-only operation and native failures are never treated as no rules', async () => {
  let request; let source; let fail = false;
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_f, args, options, callback) => {
    request = JSON.parse(Buffer.from(options.env.PROXYPILOT_NETWORK_LOCK_REQUEST, 'base64'));
    source = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    callback(null, fail ? '{"ok":false,"code":"NETWORK_LOCK_WINDOWS_FAILED"}' : '{"ok":true,"value":{"names":[]}}');
  } });
  assert.deepEqual(await adapter.inspectOrphans(), { names: [] }); assert.deepEqual(request, { operation: 'inspect-orphans' });
  const branch = source.split("'inspect-orphans' {")[1].split("'export' {")[0];
  assert.match(branch, /Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop/);
  assert.doesNotMatch(branch, /Set-Net|New-Net|Remove-Net|= Inspect|FilterMap/);
  fail = true; await assert.rejects(adapter.inspectOrphans(), { code: 'NETWORK_LOCK_WINDOWS_FAILED' });
});

test('native restore errors distinguish permissions, policy conflicts, import failure, timeout and unreadable output', async () => {
  let error = null; let output = '';
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_f, _a, _o, callback) => callback(error, output) });
  for (const code of ['ADMIN_REQUIRED', 'NETWORK_LOCK_CONFLICT', 'NETWORK_LOCK_IMPORT_FAILED', 'NETWORK_LOCK_EXPORT_FAILED']) {
    output = JSON.stringify({ ok: false, code });
    await assert.rejects(adapter.inspect(), { code });
  }
  output = JSON.stringify({ ok: false, code: 'PRIVATE_PATH_AND_PASSWORD' });
  await assert.rejects(adapter.inspect(), { code: 'NETWORK_LOCK_WINDOWS_FAILED' });
  output = 'unreadable PRIVATE_SECRET';
  await assert.rejects(adapter.inspect(), { code: 'NETWORK_LOCK_RESPONSE_INVALID' });
  error = Object.assign(new Error('PRIVATE_SECRET'), { killed: true });
  await assert.rejects(adapter.inspect(), { code: 'NETWORK_LOCK_TIMEOUT' });
});

test('native failure identifies the precise add command and rule kind without leaking native messages or rule data', async () => {
  let source;
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_f, args, _o, callback) => {
    source = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    callback(null, JSON.stringify({ ok: false, code: 'NETWORK_LOCK_WINDOWS_FAILED', diagnostic: {
      command: 'New-NetFirewallRule', category: 'InvalidArgument', nativeCode: 87, hResult: -2147024809, rule: 'loopback',
      operation: 'import', message: 'PRIVATE_SECRET', target: 'C:\\PRIVATE_SECRET', errorId: 'PRIVATE_SECRET',
    } }));
  } });
  await assert.rejects(adapter.addRules([]), cause => {
    assert.deepEqual(cause.diagnostic, { operation: 'add', command: 'New-NetFirewallRule', category: 'InvalidArgument', nativeCode: 87, hResult: -2147024809, rule: 'loopback' });
    assert.ok(!JSON.stringify(cause).includes('PRIVATE_SECRET'));
    return true;
  });
  assert.match(source, /\$diagnosticRule = \$Matches\[1\]/);
  assert.match(source, /nativeCode=\$_\.Exception\.NativeErrorCode/);
});

test('diagnostic metadata admits only known fields and bounds numeric values', async () => {
  assert.deepEqual(sanitizeNetworkLockDiagnostic({ operation: 'add', command: 'PRIVATE_SECRET', category: 'PRIVATE_SECRET', rule: 'PRIVATE_SECRET', nativeCode: Infinity, hResult: 2147483648, message: 'PRIVATE_SECRET' }), { operation: 'add' });
  assert.equal(sanitizeNetworkLockDiagnostic({ operation: 'PRIVATE_SECRET' }), undefined);
  assert.deepEqual(sanitizeNetworkLockDiagnostic({ operation: 'disable', rule: 'isp', nativeCode: 4294967295, hResult: -2147483648 }), { operation: 'disable', nativeCode: 4294967295, hResult: -2147483648 });
  const adapter = createWindowsNetworkLockAdapter({ platform: 'win32', execFile: (_f, _a, _o, callback) => callback(Object.assign(new Error('PRIVATE_SECRET'), { killed: true }), '') });
  await assert.rejects(adapter.inspect(), cause => {
    assert.deepEqual(cause.diagnostic, { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout' });
    assert.ok(!JSON.stringify(cause).includes('PRIVATE_SECRET'));
    return true;
  });
});
