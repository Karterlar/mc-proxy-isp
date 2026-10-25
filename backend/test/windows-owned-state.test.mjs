import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import net from 'node:net';
import { createWindowsProcessTools, sameProcess } from '../src/windows-process.mjs';
import { TUN_NETWORK } from '../src/config.mjs';

const identity = { pid: 123, parentPid: 12, createdAt: '2026-10-06T01:02:03.0000000Z', executable: 'D:\\Private App\\sing-box.exe', commandLine: '"D:\\Private App\\sing-box.exe" run -c "D:\\Private App\\owned-config.json"' };
const snapshot = () => ({ identity: { ...identity }, owner: { ...identity, listenAddresses: ['127.0.0.1'] }, tun: { exists: true, ready: true } });

test('native port-filtered listener reads only this fixture and keeps a closed listener absent', { skip: process.platform !== 'win32', timeout: 45000 }, async t => {
  const server = net.createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { if (server.listening) await new Promise(resolve => server.close(resolve)); });
  const port = server.address().port, tools = createWindowsProcessTools();
  const owner = await tools.listenerOwner(port);
  assert.equal(owner?.pid === process.pid, true, 'only the fixture process can own its loopback listener');
  assert.equal(owner.listenAddresses.includes('127.0.0.1'), true);
  const state = await tools.inspectOwnedState({ pid: process.pid, port, tun: false });
  assert.equal(sameProcess(owner, state.identity), true, 'full process identity is retained without printing it');
  assert.equal(sameProcess(owner, state.owner), true); assert.equal(state.tun, null);
  await new Promise(resolve => server.close(resolve));
  assert.equal(await tools.listenerOwner(port), null, 'the standard port-filter no-match result is absence');
});

test('owned state combines identity, listener and exact TUN checks in one bounded hidden call', async () => {
  const calls = [];
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    calls.push({ file, args, options }); callback(null, '\uFEFF' + JSON.stringify({ ok: true, value: snapshot() }));
  } });
  const result = await tools.inspectOwnedState({ pid: 123, port: 17890, tun: true });
  assert.deepEqual(result, snapshot()); assert.equal(calls.length, 1);
  const call = calls[0];
  assert.equal(call.file, 'powershell.exe'); assert.equal(call.options.windowsHide, true); assert.equal(call.options.timeout, 15000);
  const input = JSON.parse(Buffer.from(call.options.env.PROXYPILOT_PROCESS_INPUT, 'base64').toString('utf8'));
  assert.deepEqual(input, { operation: 'owned-state', pid: 123, port: 17890, tun: true, tunNetwork: TUN_NETWORK });
  const script = Buffer.from(call.args.at(-1), 'base64').toString('utf16le');
  assert.match(script, /Get-NetTCPConnection -LocalPort \$port -State Listen -ErrorAction Stop/);
  assert.match(script, /Select-Object -ExpandProperty OwningProcess -Unique/);
  assert.match(script, /Select-Object -ExpandProperty LocalAddress -Unique/);
  assert.match(script, /\$_.Name -ceq \$expected.interfaceName/);
  assert.match(script, /\$missingRoutes.Count -eq 0 -and \$missingDns.Count -eq 0/);
  const operation = script.split("'owned-state' {")[1].split("'stop' {")[0];
  assert.match(operation, /Read-Identity/); assert.match(operation, /Read-ListenerOwner/); assert.match(operation, /Read-TunState/);
  assert.doesNotMatch(operation, /Set-|New-|Remove-|Start-|Stop-|Clear-|\.Kill/);
});

test('owned-state timeouts retain bounded elapsed and fixed category without any native identity or command text', async () => {
  for (const nativeError of [Object.assign(new Error('PRIVATE_SECRET'), { killed: true, signal: 'SIGTERM', cmd: identity.commandLine, pid: identity.pid }), Object.assign(new Error('PRIVATE_SECRET'), { code: 'ETIMEDOUT' })]) {
    let clock = 100;
    const tools = createWindowsProcessTools({ platform: 'win32', now: () => clock, execFile: (_file, _args, options, callback) => {
      assert.equal(options.timeout, 15000); clock = 15221; callback(nativeError, 'PRIVATE_STDOUT');
    } });
    await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890 }), cause => {
      assert.equal(cause.code, 'PROCESS_QUERY_FAILED');
      assert.deepEqual(cause.diagnostic, { operation: 'owned-state', category: 'timeout', elapsedMs: 15121 });
      assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|sing-box|17890|\b123\b|cmd|pid/); return true;
    });
  }
  for (const nativeError of [new Error('PRIVATE_SECRET'), Object.assign(new Error('PRIVATE_SECRET'), { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true, signal: 'SIGTERM' })]) {
    let clock = 0;
    const tools = createWindowsProcessTools({ platform: 'win32', now: () => clock, execFile: (_file, _args, _options, callback) => { clock = 20000; callback(nativeError); } });
    await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890 }), cause => cause.code === 'PROCESS_QUERY_FAILED' && cause.diagnostic.category === 'query-failed' && !JSON.stringify(cause).includes('PRIVATE_SECRET'));
  }
});

test('HTTP inspection skips TUN and null identities stay unverified instead of inventing ownership', async () => {
  let payload;
  const value = { identity: null, owner: null, tun: null };
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, options, callback) => {
    payload = JSON.parse(Buffer.from(options.env.PROXYPILOT_PROCESS_INPUT, 'base64')); callback(null, JSON.stringify({ ok: true, value }));
  } });
  assert.deepEqual(await tools.inspectOwnedState({ pid: 123, port: 17890 }), value);
  assert.deepEqual(payload, { operation: 'owned-state', pid: 123, port: 17890, tun: false });
  assert.equal(sameProcess(identity, value.identity), false);
});

test('invalid inputs and malformed or failed snapshots reject with fixed private-safe errors', async () => {
  let calls = 0; let response;
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => { calls++; callback(null, response); } });
  for (const input of [{ pid: -1, port: 17890 }, { pid: 123, port: 0 }, { pid: 123, port: 65536 }, { pid: 123, port: 17890, tun: 'true' }]) await assert.rejects(tools.inspectOwnedState(input), { code: 'PROCESS_INVALID' });
  assert.equal(calls, 0);
  for (const value of [null, {}, { ...snapshot(), identity: {} }, { ...snapshot(), owner: { ...identity, listenAddresses: '127.0.0.1' } }, { ...snapshot(), identity: { ...identity, createdAt: 'PRIVATE_SECRET' } }, { ...snapshot(), owner: { ...snapshot().owner, unreadable: true } }]) {
    response = JSON.stringify({ ok: true, value });
    await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890, tun: true }), cause => cause.code === 'PROCESS_QUERY_FAILED' && !cause.message.includes('PRIVATE_SECRET'));
  }
  for (const tun of [null, {}, { exists: false, ready: true }, { exists: true, ready: 'true' }]) {
    response = JSON.stringify({ ok: true, value: { ...snapshot(), tun } });
    await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890, tun: true }), { code: 'TUN_STATE_UNAVAILABLE' });
  }
  for (const code of ['PROCESS_UNREADABLE', 'LISTENER_AMBIGUOUS', 'LISTENER_UNREADABLE', 'TUN_STATE_UNAVAILABLE', 'PRIVATE_SECRET']) {
    response = JSON.stringify({ ok: false, code });
    await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890, tun: true }), cause => cause.code === (code === 'PRIVATE_SECRET' ? 'PROCESS_QUERY_FAILED' : code) && !cause.message.includes('PRIVATE_SECRET'));
  }
  for (const syncThrow of [false, true]) {
    const failed = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => {
      if (syncThrow) throw new Error('PRIVATE_SECRET');
      callback(new Error('PRIVATE_SECRET'), 'PRIVATE_SECRET');
    } });
    await assert.rejects(failed.inspectOwnedState({ pid: 123, port: 17890 }), cause => cause.code === 'PROCESS_QUERY_FAILED' && !cause.message.includes('PRIVATE_SECRET'));
  }
  await assert.rejects(createWindowsProcessTools({ platform: 'linux', execFile: () => assert.fail('unsupported platform') }).inspectOwnedState({ pid: 123, port: 17890 }), { code: 'PLATFORM_UNSUPPORTED' });
});

test('native combined snapshot preserves full identities, unique listener and exact dual-stack TUN guards', { skip: process.platform !== 'win32', timeout: 60000 }, async t => {
  // Every native query is replaced by a fixed synthetic function. No real
  // process, adapter, route, DNS or firewall inspection/control occurs here.
  const stub = String.raw`
function Get-CimInstance {
  param($ClassName, $Filter)
  if ($env:PROXYPILOT_OWNED_CASE -eq 'missing-process') { return }
  $command = '"D:\Private App\sing-box.exe" run -c "D:\Private App\owned-config.json"'
  if ($env:PROXYPILOT_OWNED_CASE -eq 'unreadable') { $command = $null }
  [pscustomobject]@{ProcessId=123;ParentProcessId=12;CreationDate=[datetime]'2026-10-06T01:02:03Z';ExecutablePath='D:\Private App\sing-box.exe';CommandLine=$command}
}
function Get-NetTCPConnection {
  param($LocalPort, $State, $ErrorAction)
  if ($LocalPort -ne 17890 -or $State -ne 'Listen') { throw 'PRIVATE_SECRET' }
  if ($env:PROXYPILOT_OWNED_CASE -eq 'no-listener') { return }
  if ($env:PROXYPILOT_OWNED_CASE -eq 'not-found') {
    throw [Management.Automation.ErrorRecord]::new([Exception]::new('PRIVATE_SECRET'), 'CmdletizationQuery_NotFound,Get-NetTCPConnection', [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
  }
  if ($env:PROXYPILOT_OWNED_CASE -eq 'unknown-query-failure') { throw 'PRIVATE_SECRET' }
  [pscustomobject]@{LocalPort=17890;OwningProcess=123;LocalAddress='127.0.0.1'}
  if ($env:PROXYPILOT_OWNED_CASE -eq 'wildcard') { [pscustomobject]@{LocalPort=17890;OwningProcess=123;LocalAddress='0.0.0.0'}; [pscustomobject]@{LocalPort=17890;OwningProcess=123;LocalAddress='::'} }
  if ($env:PROXYPILOT_OWNED_CASE -eq 'ambiguous-listener') { [pscustomobject]@{LocalPort=17890;OwningProcess=999;LocalAddress='::1'} }
}
function Get-NetAdapter {
  param([switch]$IncludeHidden)
  $name = 'ProxyPilot'; $status = 'Up'
  if ($env:PROXYPILOT_OWNED_CASE -eq 'other-adapter') { $name = 'ProxyPilot-other' }
  if ($env:PROXYPILOT_OWNED_CASE -eq 'down') { $status = 'Disconnected' }
  [pscustomobject]@{Name=$name;ifIndex=88;Status=$status}
  if ($env:PROXYPILOT_OWNED_CASE -eq 'ambiguous-tun') { [pscustomobject]@{Name='ProxyPilot';ifIndex=89;Status='Up'} }
}
function Get-NetRoute {
  param($InterfaceIndex, $ErrorAction)
  if ($InterfaceIndex -ne 88) { throw 'PRIVATE_SECRET' }
  @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') | ForEach-Object {
    if ($env:PROXYPILOT_OWNED_CASE -ne 'missing-ipv6-route' -or $_ -ne '8000::/1') { [pscustomobject]@{DestinationPrefix=$_} }
  }
}
function Get-DnsClientServerAddress {
  param($InterfaceIndex, $ErrorAction)
  if ($InterfaceIndex -ne 88) { throw 'PRIVATE_SECRET' }
  $addresses = @('172.30.255.2','fdfe:dcba:9876::2')
  if ($env:PROXYPILOT_OWNED_CASE -eq 'missing-ipv6-dns') { $addresses = @('172.30.255.2') }
  [pscustomobject]@{ServerAddresses=$addresses}
}
`;
  for (const scenario of ['healthy', 'wildcard', 'other-adapter', 'down', 'missing-ipv6-route', 'missing-ipv6-dns', 'no-listener', 'not-found', 'unknown-query-failure', 'missing-process', 'ambiguous-listener', 'ambiguous-tun', 'unreadable']) await t.test(scenario, async () => {
    let calls = 0;
    const tools = createWindowsProcessTools({ platform: 'win32', execFile: (file, args, options, callback) => {
      calls++;
      const script = stub + Buffer.from(args.at(-1), 'base64').toString('utf16le');
      execFile(file, [...args.slice(0, -1), Buffer.from(script, 'utf16le').toString('base64')], { ...options, env: { ...options.env, PROXYPILOT_OWNED_CASE: scenario } }, callback);
    } });
    if (['ambiguous-listener', 'ambiguous-tun', 'unreadable', 'missing-process', 'unknown-query-failure'].includes(scenario)) {
      const code = ({ 'ambiguous-listener': 'LISTENER_AMBIGUOUS', 'ambiguous-tun': 'TUN_STATE_UNAVAILABLE', unreadable: 'PROCESS_UNREADABLE', 'missing-process': 'LISTENER_UNREADABLE', 'unknown-query-failure': 'PROCESS_QUERY_FAILED' })[scenario];
      await assert.rejects(tools.inspectOwnedState({ pid: 123, port: 17890, tun: true }), { code });
    } else {
      const result = await tools.inspectOwnedState({ pid: 123, port: 17890, tun: true });
      assert.deepEqual(result.identity, identity);
      assert.equal(result.tun.exists, scenario !== 'other-adapter');
      assert.equal(result.tun.ready, ['healthy', 'wildcard', 'no-listener', 'not-found'].includes(scenario));
      if (['no-listener', 'not-found'].includes(scenario)) assert.equal(result.owner, null);
      else { assert.equal(sameProcess(identity, result.owner), true); assert.deepEqual(result.owner.listenAddresses, scenario === 'wildcard' ? ['127.0.0.1', '0.0.0.0', '::'] : ['127.0.0.1']); }
    }
    assert.equal(calls, 1);
  });
});
