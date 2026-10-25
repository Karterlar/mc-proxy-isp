import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createWindowsProcessTools, sameProcess, parseWindowsCommandLine } from '../src/windows-process.mjs';

const identity = { pid: 123, createdAt: '2026-09-30T12:00:00.0000000Z', executable: 'C:\\Program Files\\Chrome\\chrome.exe', commandLine: '"C:\\Program Files\\Chrome\\chrome.exe" --user-data-dir="C:\\private test"' };

test('Windows process requests keep all variable values outside PowerShell source', async () => {
  const calls = [];
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    calls.push({ file, args, options });
    callback(null, JSON.stringify({ ok: true, value: { stopped: true } }));
  } });
  const unusual = { ...identity, commandLine: `${identity.commandLine} --literal="$env:SECRET;$(whoami)"` };
  await tools.stopProcess(unusual, { graceful: true, timeoutMs: 2345 });
  assert.equal(calls[0].file, 'powershell.exe');
  assert.equal(calls[0].options.windowsHide, true);
  const script = Buffer.from(calls[0].args.at(-1), 'base64').toString('utf16le');
  assert.equal(script.includes(unusual.commandLine), false);
  const payload = JSON.parse(Buffer.from(calls[0].options.env.PROXYPILOT_PROCESS_INPUT, 'base64'));
  assert.deepEqual(payload, { operation: 'stop', identity: unusual, graceful: true, timeoutMs: 2345 });
  assert.match(script, /Same-Identity/);
  assert.match(script, /\$native\.Handle/);
  assert.match(script, /if \(\$request\.graceful\)[\s\S]*ProxyPilotWindowCloser/);
  assert.doesNotMatch(script, /Stop-Process\s+-Name|taskkill/i);
});

test('process identity comparison rejects reused PID or changed arguments', () => {
  assert.equal(sameProcess(identity, { ...identity, executable: identity.executable.toUpperCase() }), true);
  for (const changed of [{ pid: 124 }, { createdAt: '2026-09-30T12:00:00.0000010Z' }, { commandLine: `${identity.commandLine}x` }, { executable: 'C:\\other.exe' }]) {
    assert.equal(sameProcess(identity, { ...identity, ...changed }), false);
  }
});

test('process failures expose controlled messages and never command output', async () => {
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(new Error('secret-user:secret-password'), 'secret output') });
  await assert.rejects(tools.inspectProcess(123), error => error.code === 'PROCESS_QUERY_FAILED' && !error.message.includes('secret'));
  const denied = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, JSON.stringify({ ok: false, code: 'PROCESS_IDENTITY_MISMATCH' })) });
  await assert.rejects(denied.stopProcess(identity), { code: 'PROCESS_IDENTITY_MISMATCH' });
  const timeout = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, JSON.stringify({ ok: false, code: 'BROWSER_CLOSE_TIMEOUT' })) });
  await assert.rejects(timeout.stopProcess(identity, { graceful: true }), { code: 'BROWSER_CLOSE_TIMEOUT' });
});

test('Windows argument splitting preserves paths with spaces and exact config tokens', () => {
  assert.deepEqual(parseWindowsCommandLine('"C:\\Program Files\\sing-box.exe" run -c "D:\\Proxy Pilot\\session\\sing-box.json"'), ['C:\\Program Files\\sing-box.exe', 'run', '-c', 'D:\\Proxy Pilot\\session\\sing-box.json']);
  assert.deepEqual(parseWindowsCommandLine('chrome.exe --user-data-dir="D:\\Profile One" ""'), ['chrome.exe', '--user-data-dir=D:\\Profile One', '']);
  assert.throws(() => parseWindowsCommandLine('chrome.exe "unclosed'), { code: 'PROCESS_COMMAND_INVALID' });
});

test('invalid process inputs fail before invoking Windows', async () => {
  let calls = 0;
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: () => { calls++; } });
  await assert.rejects(tools.inspectProcess(-1), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.listProcesses("chrome.exe'; Stop-Process *"), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.listProcessCandidates("chrome.exe'; Stop-Process *"), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.stopProcess({ pid: 123 }), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.stopProcess({ ...identity, unreadable: true }), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.stopBackgroundBrowser({ ...identity, unreadable: true }), { code: 'PROCESS_INVALID' });
  await assert.rejects(tools.stopBackgroundBrowser(identity, { timeoutMs: 0 }), { code: 'PROCESS_INVALID' });
  assert.equal(calls, 0);
});

test('browser background stop is identity-bound and checks visible windows before terminating', async () => {
  let request; let source;
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (_file,args,options,callback) => {
    request = JSON.parse(Buffer.from(options.env.PROXYPILOT_PROCESS_INPUT,'base64'));
    source = Buffer.from(args.at(-1),'base64').toString('utf16le');
    callback(null,JSON.stringify({ok:true,value:{stopped:true}}));
  } });
  await tools.stopBackgroundBrowser(identity,{timeoutMs:2000});
  assert.deepEqual(request,{operation:'stop',identity,graceful:false,backgroundOnly:true,timeoutMs:2000});
  assert.match(source,/if \(\$request\.backgroundOnly -and \[ProxyPilotWindowCloser\]::HasVisibleWindow/);
  assert.match(source,/Same-Identity/);
  assert.match(source,/bool completed = EnumWindows/);
  assert.match(source,/if \(!completed\) throw new InvalidOperationException\("WINDOW_ENUMERATION_FAILED"\)/);
});

test('native close accepts exited races but refuses visible/recycled background identities', { skip:process.platform !== 'win32' }, async () => {
  // Production PowerShell control code runs against inert process/window stubs.
  // The fake Kill throws unless the windowless identity is the allowed case.
  for (const scenario of ['get-process-exited','handle-exited','recheck-exited','visible','enumeration-failed','recycled','windowless']) {
    const stub = String.raw`
$script:reads = 0
function Get-CimInstance {
  param($ClassName,$Filter)
  $script:reads++
  if (('${scenario}' -eq 'get-process-exited' -or '${scenario}' -eq 'handle-exited' -or '${scenario}' -eq 'recheck-exited') -and $script:reads -gt 1) { return $null }
  $item = [pscustomobject]@{ProcessId=123;ParentProcessId=1;CreationDate=[datetime]'2026-09-30T12:00:00Z';ExecutablePath='C:\Program Files\Chrome\chrome.exe';CommandLine='"C:\Program Files\Chrome\chrome.exe" --user-data-dir="C:\private test"'}
  if ('${scenario}' -eq 'recycled' -and $script:reads -gt 1) {$item.CreationDate = [datetime]'2026-09-30T12:00:01Z'}
  return $item
}
function Get-Process {
  param($Id,$ErrorAction)
  if ('${scenario}' -eq 'get-process-exited') {throw 'Already exited'}
  $fake = [pscustomobject]@{Handle=1;HasExited=$false}
  if ('${scenario}' -eq 'handle-exited') { $fake | Add-Member ScriptProperty Handle {throw 'Exited before handle capture'} -Force }
  $fake | Add-Member ScriptMethod Kill {if ('${scenario}' -ne 'windowless') {throw 'Unexpected kill'}}
  $fake | Add-Member ScriptMethod WaitForExit {param($Timeout);return $true}
  $fake | Add-Member ScriptMethod Dispose {}
  return $fake
}
function Add-Type {
  param($TypeDefinition)
  Microsoft.PowerShell.Utility\Add-Type -TypeDefinition 'public static class ProxyPilotWindowCloser { public static void Close(uint p) {} public static bool HasVisibleWindow(uint p) { ${scenario === 'enumeration-failed' ? 'throw new System.InvalidOperationException("WINDOW_ENUMERATION_FAILED");' : `return ${scenario === 'visible' ? 'true' : 'false'};`} } }'
}
`;
    const tools = createWindowsProcessTools({ platform:'win32', execFile:(file,args,options,callback) => {
      const script = stub + Buffer.from(args.at(-1),'base64').toString('utf16le');
      execFile(file,[...args.slice(0,-1),Buffer.from(script,'utf16le').toString('base64')],options,callback);
    } });
    if (scenario === 'visible') await assert.rejects(tools.stopBackgroundBrowser(identity),{code:'BROWSER_CLOSE_TIMEOUT'});
    else if (scenario === 'enumeration-failed') await assert.rejects(tools.stopBackgroundBrowser(identity),{code:'PROCESS_QUERY_FAILED'});
    else if (scenario === 'recycled') await assert.rejects(tools.stopBackgroundBrowser(identity),{code:'PROCESS_IDENTITY_MISMATCH'});
    else assert.equal((await tools.stopBackgroundBrowser(identity)).stopped,true);
  }
});

test('browser candidate enumeration preserves partial identities while default process listing stays strict', { skip: process.platform !== 'win32' }, async () => {
  // Native PowerShell executes production conversion with a fixed CIM stub.
  // No real process enumeration or control occurs in this regression.
  const stub = String.raw`
function Get-CimInstance {
  [pscustomobject]@{Name='chrome.exe';ProcessId=10;ParentProcessId=1;CreationDate=[datetime]'2026-10-05T12:00:00Z';ExecutablePath='C:\Chrome\chrome.exe';CommandLine='chrome.exe'}
  [pscustomobject]@{Name='chrome.exe';ProcessId=11;ParentProcessId=10;CreationDate=[datetime]'2026-10-05T12:00:01Z';ExecutablePath=$null;CommandLine=$null}
}
`;
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (file, args, options, callback) => {
    const script = stub + Buffer.from(args.at(-1), 'base64').toString('utf16le');
    execFile(file, [...args.slice(0, -1), Buffer.from(script, 'utf16le').toString('base64')], options, callback);
  } });
  await assert.rejects(tools.listProcesses('chrome.exe'), { code: 'PROCESS_UNREADABLE' });
  const candidates = await tools.listProcessCandidates('chrome.exe');
  assert.equal(candidates.length, 2); assert.equal(candidates[0].unreadable, undefined);
  assert.deepEqual(candidates[1], { pid: 11, parentPid: 10, createdAt: '2026-10-05T12:00:01.0000000Z', executable: '', commandLine: '', unreadable: true });
  assert.equal(sameProcess({ ...identity, pid: 11 }, candidates[1]), false);
  await assert.rejects(tools.stopProcess(candidates[1]), { code: 'PROCESS_INVALID' });
});

test('malformed candidate responses fail closed without exposing native output', async () => {
  let response;
  const tools = createWindowsProcessTools({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, JSON.stringify({ ok: true, value: response })) });
  for (const bad of [{ pid: 1, parentPid: -1 }, { pid: 1, parentPid: 0, createdAt: 'PRIVATE_SECRET', executable: '', commandLine: '', unreadable: true }]) {
    response = [bad];
    await assert.rejects(tools.listProcessCandidates('chrome.exe'), cause => cause.code === 'PROCESS_QUERY_FAILED' && !cause.message.includes('PRIVATE_SECRET'));
  }
});
