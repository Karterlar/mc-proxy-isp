import { execFile as nodeExecFile } from 'node:child_process';
import path from 'node:path';
import { UserError, TUN_NETWORK } from './config.mjs';
import { TUN_STATE_FUNCTION } from './windows-tun.mjs';

const INPUT_ENV = 'PROXYPILOT_PROCESS_INPUT';
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROXYPILOT_PROCESS_INPUT)) | ConvertFrom-Json
${TUN_STATE_FUNCTION}
function Convert-Identity($item) {
  if ($null -eq $item) { return $null }
  if (-not $item.ExecutablePath -or -not $item.CommandLine -or -not $item.CreationDate) { throw 'PROCESS_UNREADABLE' }
  return [pscustomobject]@{ pid=[int]$item.ProcessId; parentPid=[int]$item.ParentProcessId; createdAt=$item.CreationDate.ToUniversalTime().ToString('o'); executable=[string]$item.ExecutablePath; commandLine=[string]$item.CommandLine }
}
function Convert-Candidate($item) {
  # Only browser discovery may carry an unreadable candidate. It is never a
  # stop identity; the caller must exclude it or retain unresolved recovery.
  if ($item.ExecutablePath -and $item.CommandLine -and $item.CreationDate) { return Convert-Identity $item }
  $createdAt = $null
  if ($item.CreationDate) { $createdAt = $item.CreationDate.ToUniversalTime().ToString('o') }
  return [pscustomobject]@{ pid=[int]$item.ProcessId; parentPid=[int]$item.ParentProcessId; createdAt=$createdAt; executable=[string]$item.ExecutablePath; commandLine=[string]$item.CommandLine; unreadable=$true }
}
function Read-Identity([int]$processId) {
  return Convert-Identity (Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $processId))
}
function Read-ListenerOwner([int]$port) {
  try { $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction Stop) }
  catch {
    # This cmdlet reports a missing matching listener as ObjectNotFound. Only
    # that documented query result is absence; failed/denied reads stay unknown.
    if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*' -and $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { $listeners = @() }
    else { throw }
  }
  if ($listeners.Count -eq 0) { return $null }
  $owners = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
  if ($owners.Count -ne 1) { throw 'LISTENER_AMBIGUOUS' }
  $owner = Read-Identity ([int]$owners[0])
  if ($null -eq $owner) { throw 'LISTENER_UNREADABLE' }
  $owner | Add-Member -NotePropertyName listenAddresses -NotePropertyValue @($listeners | Select-Object -ExpandProperty LocalAddress -Unique)
  return $owner
}
function Same-Identity($expected, $actual) {
  return ($null -ne $actual -and $expected.pid -eq $actual.pid -and $expected.createdAt -ceq $actual.createdAt -and $expected.executable -ieq $actual.executable -and $expected.commandLine -ceq $actual.commandLine)
}
try {
  $result = $null
  switch ($request.operation) {
    'inspect' { $result = Read-Identity ([int]$request.pid) }
    'list' {
      $items = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq $request.name })
      # Convert this snapshot directly: querying CIM once per Chrome renderer is expensive.
      $result = @($items | ForEach-Object { Convert-Identity $_ })
    }
    'list-candidates' {
      $items = @(Get-CimInstance Win32_Process -Filter ("Name='" + $request.name + "'"))
      $result = @($items | ForEach-Object { Convert-Candidate $_ })
    }
    'listener' { $result = Read-ListenerOwner ([int]$request.port) }
    'owned-state' {
      $identity = Read-Identity ([int]$request.pid)
      $owner = Read-ListenerOwner ([int]$request.port)
      $tun = $null
      if ($request.tun) {
        try { $tun = Read-TunState $request.tunNetwork }
        catch { throw 'TUN_STATE_UNAVAILABLE' }
      }
      $result = @{ identity=$identity; owner=$owner; tun=$tun }
    }
    'stop' {
      $expected = $request.identity
      $current = Read-Identity ([int]$expected.pid)
      if ($null -eq $current) { $result = @{ stopped=$true; alreadyExited=$true }; break }
      if (-not (Same-Identity $expected $current)) { throw 'PROCESS_IDENTITY_MISMATCH' }
      try { $native = Get-Process -Id ([int]$expected.pid) -ErrorAction Stop }
      catch {
        # A browser can exit normally between CIM and opening its handle.
        if ($null -eq (Read-Identity ([int]$expected.pid))) { $result = @{ stopped=$true; alreadyExited=$true }; break }
        throw
      }
      try {
        # Hold the process handle while rechecking identity so a recycled PID cannot be killed.
        try { [void]$native.Handle }
        catch {
          if ($null -eq (Read-Identity ([int]$expected.pid))) { $result = @{ stopped=$true; alreadyExited=$true }; break }
          throw
        }
        $current = Read-Identity ([int]$expected.pid)
        if ($null -eq $current) { $result = @{ stopped=$true; alreadyExited=$true }; break }
        if (-not (Same-Identity $expected $current)) { throw 'PROCESS_IDENTITY_MISMATCH' }
        if ($request.graceful -or $request.backgroundOnly) {
          Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ProxyPilotWindowCloser {
  public delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr value);
  [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr value);
  [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
  [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
  [DllImport("user32.dll", SetLastError=true)] private static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);
  public static void Close(uint processId) {
    EnumWindows(delegate(IntPtr hwnd, IntPtr value) {
      uint owner; GetWindowThreadProcessId(hwnd, out owner);
      if (owner == processId) PostMessage(hwnd, 0x0010, IntPtr.Zero, IntPtr.Zero);
      return true;
    }, IntPtr.Zero);
  }
  public static bool HasVisibleWindow(uint processId) {
    bool found = false;
    bool completed = EnumWindows(delegate(IntPtr hwnd, IntPtr value) {
      uint owner; GetWindowThreadProcessId(hwnd, out owner);
      if (owner == processId && IsWindowVisible(hwnd)) found = true;
      return true;
    }, IntPtr.Zero);
    if (!completed) throw new InvalidOperationException("WINDOW_ENUMERATION_FAILED");
    return found;
  }
}
'@
        }
        if ($request.graceful) {
          [ProxyPilotWindowCloser]::Close([uint32]$expected.pid)
        } else {
          if ($request.backgroundOnly -and [ProxyPilotWindowCloser]::HasVisibleWindow([uint32]$expected.pid)) { throw 'BROWSER_CLOSE_TIMEOUT' }
          if ($native.HasExited) { $result = @{ stopped=$true; alreadyExited=$true }; break }
          try { $native.Kill() }
          catch {
            if ($native.HasExited) { $result = @{ stopped=$true; alreadyExited=$true }; break }
            throw
          }
        }
        if (-not $native.WaitForExit([int]$request.timeoutMs)) {
          if ($request.graceful) { throw 'BROWSER_CLOSE_TIMEOUT' }
          throw 'PROCESS_STOP_TIMEOUT'
        }
        $result = @{ stopped=$true; alreadyExited=$false }
      } finally { $native.Dispose() }
    }
    default { throw 'PROCESS_OPERATION_INVALID' }
  }
  ConvertTo-Json -InputObject @{ ok=$true; value=$result } -Depth 8 -Compress
} catch {
  $allowed = @('PROCESS_UNREADABLE','LISTENER_AMBIGUOUS','LISTENER_UNREADABLE','PROCESS_IDENTITY_MISMATCH','BROWSER_CLOSE_TIMEOUT','PROCESS_STOP_TIMEOUT','PROCESS_OPERATION_INVALID','TUN_STATE_UNAVAILABLE')
  $code = [string]$_.Exception.Message
  if ($allowed -cnotcontains $code) { $code = 'PROCESS_QUERY_FAILED' }
  ConvertTo-Json -InputObject @{ ok=$false; code=$code } -Compress
}
`;

const errorMessages = {
  PROCESS_UNREADABLE: 'Cannot safely inspect the Windows process identity',
  LISTENER_AMBIGUOUS: 'The proxy port has more than one listener owner',
  LISTENER_UNREADABLE: 'Cannot safely inspect the proxy listener owner',
  PROCESS_IDENTITY_MISMATCH: 'The process identity changed; no process was stopped',
  BROWSER_CLOSE_TIMEOUT: 'The browser has not closed; finish any browser prompts and retry',
  PROCESS_STOP_TIMEOUT: 'The owned process has not stopped; retry after checking its status',
  PROCESS_QUERY_FAILED: 'Windows process inspection or control failed',
  TUN_STATE_UNAVAILABLE: 'Windows TUN inspection returned an invalid or unavailable result',
};

function validPid(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 0xffffffff) throw new UserError('PROCESS_INVALID', 'A valid process ID is required');
}

function validIdentity(identity) {
  validPid(identity?.pid);
  if (identity.unreadable === true) throw new UserError('PROCESS_INVALID', 'A complete process identity is required');
  for (const field of ['createdAt', 'executable', 'commandLine']) {
    if (typeof identity[field] !== 'string' || !identity[field] || identity[field].includes('\0')) throw new UserError('PROCESS_INVALID', 'A complete process identity is required');
  }
}

export function sameProcess(expected, actual) {
  return Boolean(expected && actual && expected.unreadable !== true && actual.unreadable !== true && Number.isSafeInteger(expected.pid) && expected.pid > 0 && expected.pid === actual.pid
    && typeof expected.createdAt === 'string' && expected.createdAt && expected.createdAt === actual.createdAt
    && typeof expected.executable === 'string' && typeof actual.executable === 'string'
    && path.win32.normalize(expected.executable).toLowerCase() === path.win32.normalize(actual.executable).toLowerCase()
    && typeof expected.commandLine === 'string' && expected.commandLine === actual.commandLine);
}

// Windows CRT argument splitting: quoted spaces and backslashes before quotes are significant.
export function parseWindowsCommandLine(commandLine) {
  if (typeof commandLine !== 'string') throw new UserError('PROCESS_COMMAND_INVALID', 'The process command line is not safely parseable');
  const args = [];
  let index = 0;
  while (index < commandLine.length) {
    while (/\s/.test(commandLine[index] || '') && index < commandLine.length) index++;
    if (index >= commandLine.length) break;
    let token = ''; let quoted = false;
    while (index < commandLine.length && (quoted || !/\s/.test(commandLine[index]))) {
      let slashes = 0;
      while (commandLine[index] === '\\') { slashes++; index++; }
      if (commandLine[index] === '"') {
        token += '\\'.repeat(Math.floor(slashes / 2));
        if (slashes % 2) { token += '"'; index++; }
        else if (quoted && commandLine[index + 1] === '"') { token += '"'; index += 2; }
        else { quoted = !quoted; index++; }
      } else {
        token += '\\'.repeat(slashes);
        if (index < commandLine.length && (quoted || !/\s/.test(commandLine[index]))) token += commandLine[index++];
      }
    }
    if (quoted) throw new UserError('PROCESS_COMMAND_INVALID', 'The process command line is not safely parseable');
    args.push(token);
  }
  return args;
}

export function createWindowsProcessTools({ execFile = nodeExecFile, platform = process.platform, now = () => performance.now() } = {}) {
  async function invoke(request) {
    if (platform !== 'win32') throw new UserError('PLATFORM_UNSUPPORTED', 'Managed process control requires Windows');
    const encoded = Buffer.from(JSON.stringify(request), 'utf8').toString('base64');
    const started = now();
    const timeoutMs = Math.max(15000, (request.timeoutMs || 0) + 10000);
    const raw = await new Promise((resolve, reject) => {
      execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(SCRIPT, 'utf16le').toString('base64')], {
        env: { ...process.env, [INPUT_ENV]: encoded }, encoding: 'utf8', windowsHide: true,
        timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024,
      }, (error, stdout) => {
        if (error) return reject(error);
        resolve(stdout);
      });
    }).catch(cause => {
      const safe = new UserError('PROCESS_QUERY_FAILED', errorMessages.PROCESS_QUERY_FAILED);
      if (request.operation === 'owned-state') {
        const elapsed = now() - started;
        const timedOut = cause?.code === 'ETIMEDOUT' || cause?.code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' && cause?.killed === true
          && ['SIGTERM', 'SIGKILL'].includes(cause?.signal) && elapsed >= timeoutMs;
        safe.diagnostic = { operation: 'owned-state', category: timedOut ? 'timeout' : 'query-failed', elapsedMs: Number.isFinite(elapsed) ? Math.min(600000, Math.max(0, Math.round(elapsed))) : 0 };
      }
      throw safe;
    });
    let result;
    try { result = JSON.parse(raw.replace(/^\uFEFF/, '').trim()); } catch { throw new UserError('PROCESS_QUERY_FAILED', errorMessages.PROCESS_QUERY_FAILED); }
    if (!result?.ok) {
      const code = Object.hasOwn(errorMessages, result?.code) ? result.code : 'PROCESS_QUERY_FAILED';
      throw new UserError(code, errorMessages[code]);
    }
    return result.value;
  }

  return {
    async listProcesses(executableName) {
      if (typeof executableName !== 'string' || !/^[a-zA-Z0-9_. -]+\.exe$/i.test(executableName)) throw new UserError('PROCESS_INVALID', 'A Windows executable filename is required');
      const result = await invoke({ operation: 'list', name: executableName });
      return result === null ? [] : Array.isArray(result) ? result : [result];
    },
    async listProcessCandidates(executableName) {
      if (typeof executableName !== 'string' || !/^[a-zA-Z0-9_. -]+\.exe$/i.test(executableName)) throw new UserError('PROCESS_INVALID', 'A Windows executable filename is required');
      const result = await invoke({ operation: 'list-candidates', name: executableName });
      const candidates = result === null ? [] : Array.isArray(result) ? result : [result];
      for (const item of candidates) {
        if (!Number.isSafeInteger(item?.pid) || item.pid <= 0 || item.pid > 0xffffffff || !Number.isSafeInteger(item.parentPid) || item.parentPid < 0 || item.parentPid > 0xffffffff
          || (item.createdAt !== null && (typeof item.createdAt !== 'string' || !item.createdAt || !Number.isFinite(Date.parse(item.createdAt))))
          || ['executable', 'commandLine'].some(field => typeof item[field] !== 'string' || item[field].includes('\0'))
          || (item.unreadable !== true && (!item.createdAt || !item.executable || !item.commandLine))) throw new UserError('PROCESS_QUERY_FAILED', errorMessages.PROCESS_QUERY_FAILED);
      }
      return candidates;
    },
    async inspectProcess(pid) { validPid(pid); return invoke({ operation: 'inspect', pid }); },
    async listenerOwner(port) {
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('PROCESS_INVALID', 'A valid listener port is required');
      return invoke({ operation: 'listener', port });
    },
    async inspectOwnedState({ pid, port, tun = false } = {}) {
      validPid(pid);
      if (!Number.isInteger(port) || port < 1 || port > 65535 || typeof tun !== 'boolean') throw new UserError('PROCESS_INVALID', 'A valid listener port and TUN selection are required');
      const state = await invoke({ operation: 'owned-state', pid, port, tun, ...(tun ? { tunNetwork: TUN_NETWORK } : {}) });
      try {
        if (!state || typeof state !== 'object' || !Object.hasOwn(state, 'identity') || !Object.hasOwn(state, 'owner')) throw new Error();
        for (const identity of [state.identity, state.owner]) {
          if (identity === null) continue;
          validIdentity(identity);
          if (!Number.isSafeInteger(identity.parentPid) || identity.parentPid < 0 || identity.parentPid > 0xffffffff || !Number.isFinite(Date.parse(identity.createdAt))) throw new Error();
        }
        if (state.owner && (!Array.isArray(state.owner.listenAddresses) || state.owner.listenAddresses.length > 256 || state.owner.listenAddresses.some(value => typeof value !== 'string' || value.includes('\0')))) throw new Error();
      } catch { throw new UserError('PROCESS_QUERY_FAILED', errorMessages.PROCESS_QUERY_FAILED); }
      if (tun ? typeof state.tun?.exists !== 'boolean' || typeof state.tun?.ready !== 'boolean' || state.tun.ready && !state.tun.exists : state.tun !== null) throw new UserError('TUN_STATE_UNAVAILABLE', errorMessages.TUN_STATE_UNAVAILABLE);
      return state;
    },
    async stopProcess(identity, { graceful = false, timeoutMs = 5000 } = {}) {
      validIdentity(identity);
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new UserError('PROCESS_INVALID', 'A bounded process stop timeout is required');
      return invoke({ operation: 'stop', identity, graceful: Boolean(graceful), timeoutMs });
    },
    async stopBackgroundBrowser(identity, { timeoutMs = 5000 } = {}) {
      validIdentity(identity);
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new UserError('PROCESS_INVALID', 'A bounded process stop timeout is required');
      // A complete captured identity and no visible window are both required.
      // The browser manager calls this only after its root has safely exited.
      return invoke({ operation: 'stop', identity, graceful: false, backgroundOnly: true, timeoutMs });
    },
  };
}

const defaultTools = createWindowsProcessTools();
export const listProcesses = (...args) => defaultTools.listProcesses(...args);
export const inspectProcess = (...args) => defaultTools.inspectProcess(...args);
export const listenerOwner = (...args) => defaultTools.listenerOwner(...args);
export const inspectWindowsOwnedState = (...args) => defaultTools.inspectOwnedState(...args);
export const stopProcess = (...args) => defaultTools.stopProcess(...args);
export const closeBrowser = (identity, { timeoutMs = 10000 } = {}) => stopProcess(identity, { graceful: true, timeoutMs });
