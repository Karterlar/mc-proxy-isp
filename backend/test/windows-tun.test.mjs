import test from 'node:test';
import assert from 'node:assert/strict';
import { createWindowsTunTools, classifyExternalVpnAdapters } from '../src/windows-tun.mjs';

test('TUN inspection uses read-only commands, encoded input and hidden bounded PowerShell', async () => {
  const calls = [];
  const tools = createWindowsTunTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    calls.push({ file, args, options, script });
    callback(null, script.includes('IsInRole') ? 'true' : '{"exists":true,"ready":true}');
  } });
  assert.equal(await tools.isElevated(), true);
  assert.deepEqual(await tools.inspectTun(), { exists: true, ready: true });
  for (const call of calls) {
    assert.equal(call.file, 'powershell.exe'); assert.equal(call.options.windowsHide, true);
    assert.equal(call.options.timeout, 15000);
    assert.doesNotMatch(call.script, /Set-Net|New-Net|Remove-Net|Set-Dns|Start-Process/);
  }
  const expected = JSON.parse(Buffer.from(calls[1].options.env.PROXYPILOT_TUN_CHECK, 'base64').toString('utf8'));
  assert.deepEqual(expected.routes, ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1']);
  assert.match(calls[1].script, /Get-DnsClientServerAddress/);
});

test('unsupported platform and unparseable Windows output fail closed', async () => {
  await assert.rejects(createWindowsTunTools({ platform: 'linux' }).isElevated(), { code: 'PLATFORM_UNSUPPORTED' });
  const tools = createWindowsTunTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, 'untrusted output') });
  await assert.rejects(tools.isElevated(), { code: 'ADMIN_CHECK_FAILED' });
  await assert.rejects(tools.inspectTun(), { code: 'TUN_STATE_UNAVAILABLE' });
  await assert.rejects(tools.inspectExternalVpnTun(), { code: 'VPN_INTERFACE_STATE_UNAVAILABLE' });
});

test('external VPN inspection recognizes active TUN/TAP/VPN without generic virtual adapter false positives', () => {
  const adapter = (name, description, status = 'Up') => ({ name, description, status });
  assert.deepEqual(classifyExternalVpnAdapters([
    adapter('ProxyPilot', 'Wintun Userspace Tunnel'), adapter('Ethernet', 'Intel Ethernet'),
    adapter('vEthernet (VPN Lab)', 'Hyper-V Virtual Ethernet Adapter'), adapter('Teredo', 'Microsoft Teredo Tunneling Adapter'),
    adapter('ISATAP', 'Microsoft ISATAP Adapter'), adapter('VPN Miniport', 'WAN Miniport (IKEv2)'),
    adapter('XVPN', 'Wintun Userspace Tunnel', 'Disconnected'),
  ]), { active: false, count: 0 });
  for (const item of [adapter('XVPN', 'Wintun Userspace Tunnel'), adapter('WireGuard Tunnel', 'WireGuard Tunnel'), adapter('Ethernet 2', 'TAP-Windows Adapter V9'), adapter('sing-tun', 'Virtual Adapter'), adapter('VPN Client', 'VPN Client Adapter')]) {
    assert.deepEqual(classifyExternalVpnAdapters([item]), { active: true, count: 1 });
  }
  for (const value of [null, {}, [{}], [{ name: 'XVPN', description: 'Wintun', status: true }]]) {
    assert.throws(() => classifyExternalVpnAdapters(value), { code: 'VPN_INTERFACE_STATE_UNAVAILABLE' });
  }
});

test('external VPN adapter read is bounded, hidden, read-only and returns no interface names', async () => {
  const tools = createWindowsTunTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    assert.equal(file, 'powershell.exe'); assert.equal(options.windowsHide, true); assert.equal(options.timeout, 15000);
    assert.match(script, /Get-NetAdapter -IncludeHidden/);
    assert.doesNotMatch(script, /Set-|New-Net|Remove-|Start-Process|Stop-Process|Get-NetRoute|Get-Dns/);
    callback(null, '[{"name":"PRIVATE VPN","description":"Wintun Userspace Tunnel","status":"Up"}]');
  } });
  assert.deepEqual(await tools.inspectExternalVpnTun(), { active: true, count: 1 });
});

test('explicit startup DNS cache hook uses one fixed hidden bounded command and confirms its result', async () => {
  const calls = [];
  const tools = createWindowsTunTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    calls.push({ file, args, options, script }); callback(null, '\uFEFF{"cleared":true}');
  } });
  assert.deepEqual(await tools.clearDnsCache(), { cleared: true });
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.equal(call.file, 'powershell.exe'); assert.equal(call.options.windowsHide, true);
  assert.equal(call.options.timeout, 15000); assert.equal(call.options.maxBuffer, 65536);
  assert.deepEqual(call.args.slice(0, 3), ['-NoProfile', '-NonInteractive', '-EncodedCommand']);
  assert.equal((call.script.match(/Clear-DnsClientCache/g) || []).length, 1);
  assert.match(call.script, /Clear-DnsClientCache -ErrorAction Stop/);
  assert.doesNotMatch(call.script, /Set-|New-Net|Remove-Net|Start-Process|Stop-Process|Get-Net|Get-Dns|Resolve-Dns/);
});

test('DNS cache hook rejects missing confirmation and native errors without exposing their output', async () => {
  for (const output of ['{}', '{"cleared":false}', '{"cleared":"true"}', 'null', 'PRIVATE_DNS_OUTPUT']) {
    const tools = createWindowsTunTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, output) });
    await assert.rejects(tools.clearDnsCache(), cause => cause.code === 'DNS_CACHE_CLEAR_FAILED' && !cause.message.includes('PRIVATE_DNS'));
  }
  for (const synchronous of [false, true]) {
    const tools = createWindowsTunTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => {
      const cause = new Error('PRIVATE_DNS_NATIVE_ERROR');
      if (synchronous) throw cause;
      callback(cause, 'PRIVATE_DNS_OUTPUT');
    } });
    await assert.rejects(tools.clearDnsCache(), cause => cause.code === 'DNS_CACHE_CLEAR_FAILED' && !cause.message.includes('PRIVATE_DNS'));
  }
  await assert.rejects(createWindowsTunTools({ platform: 'linux', execFile: () => assert.fail('unsupported platforms must not execute a command') }).clearDnsCache(), { code: 'PLATFORM_UNSUPPORTED' });
});
