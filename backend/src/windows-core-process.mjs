import { spawn as nodeSpawn, execFile as nodeExecFile } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { UserError } from './config.mjs';

const INPUT = 'MC_PROXY_CORE_CONSOLE_INPUT';
const fail = code => new UserError(code, 'The owned core could not complete its private console lifecycle');
const native = String.raw`
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class MCPrivateCore {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct STARTUPINFO { public int cb; public string reserved; public string desktop; public string title; public int x,y,xsize,ysize,xchars,ychars,fill; public int flags; public short show,reserved2; public IntPtr reserved3,input,output,error; }
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr process,thread; public uint pid,tid; }
  [StructLayout(LayoutKind.Sequential)] public struct SECURITY_ATTRIBUTES { public int length; public IntPtr descriptor; [MarshalAs(UnmanagedType.Bool)] public bool inherit; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string directory, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder name, ref uint size);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out long created, out long exited, out long kernel, out long user);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll")] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES attributes, uint size);
  [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES attributes, uint mode, uint flags, IntPtr template);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle, uint ms);
  [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll")] static extern bool FreeConsole();
  [DllImport("kernel32.dll")] static extern uint GetConsoleProcessList([Out] uint[] processes, uint count);
  [DllImport("kernel32.dll")] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GenerateConsoleCtrlEvent(uint type, uint group);
  static string Quote(string value) { return "\"" + value.Replace("\\", "\\").Replace("\"", "\\\"") + "\""; }
  public sealed class LaunchResult { public uint Pid; public IntPtr ErrorRead; public IntPtr Process; public string CreatedAt; }
  public static LaunchResult Launch(string executable, string config) {
    SECURITY_ATTRIBUTES attributes=new SECURITY_ATTRIBUTES(); attributes.length=Marshal.SizeOf(attributes); attributes.inherit=true;
    IntPtr read,write;
    if(!CreatePipe(out read,out write,ref attributes,4096)) throw new Exception("CORE_CONSOLE_START_FAILED");
    SetHandleInformation(read,1,0);
    IntPtr nullHandle=CreateFileW("NUL",0xC0000000,3,ref attributes,3,0,IntPtr.Zero);
    STARTUPINFO startup = new STARTUPINFO(); startup.cb=Marshal.SizeOf(startup); startup.flags=0x101; startup.show=0;
    startup.input=nullHandle; startup.output=nullHandle; startup.error=write; PROCESS_INFORMATION info=new PROCESS_INFORMATION();
    try {
      if (!CreateProcessW(executable, new StringBuilder(Quote(executable)+" run -c "+Quote(config)), IntPtr.Zero, IntPtr.Zero, true, 0x10|0x200, IntPtr.Zero, null, ref startup, out info)) throw new Exception("CORE_CONSOLE_START_FAILED");
      long created,exited,kernel,user;
      if(!GetProcessTimes(info.process,out created,out exited,out kernel,out user)) throw new Exception("CORE_CONSOLE_START_FAILED");
      CloseHandle(info.thread); info.thread=IntPtr.Zero; return new LaunchResult {Pid=info.pid,ErrorRead=read,Process=info.process,CreatedAt=DateTime.FromFileTimeUtc(created).ToString("o")};
    } catch { CloseHandle(read); if(info.thread!=IntPtr.Zero) CloseHandle(info.thread); if(info.process!=IntPtr.Zero) CloseHandle(info.process); throw; } finally { CloseHandle(write); CloseHandle(nullHandle); }
  }
  public static uint Finish(LaunchResult result) {
    try {
      if(WaitForSingleObject(result.Process,5000)!=0) throw new Exception("CORE_CONSOLE_CLOSE_TIMEOUT");
      uint code; if(!GetExitCodeProcess(result.Process,out code)) throw new Exception("CORE_CONSOLE_CLOSE_FAILED"); return code;
    } finally { Release(result); }
  }
  public static void Release(LaunchResult result) { if(result!=null && result.Process!=IntPtr.Zero) { CloseHandle(result.Process); result.Process=IntPtr.Zero; } }
  public static uint Close(uint pid, string executable, long ticks, uint timeout) {
    IntPtr handle=OpenProcess(0x100000|0x1000, false, pid);
    if (handle==IntPtr.Zero) throw new Exception("CORE_CONSOLE_IDENTITY_FAILED");
    bool attached=false;
    try {
      StringBuilder image=new StringBuilder(32768); uint size=32768; long created,exited,kernel,user;
      if (!QueryFullProcessImageNameW(handle,0,image,ref size) || !GetProcessTimes(handle,out created,out exited,out kernel,out user)
        || !String.Equals(System.IO.Path.GetFullPath(image.ToString()),System.IO.Path.GetFullPath(executable),StringComparison.OrdinalIgnoreCase)
        || Math.Abs(DateTime.FromFileTimeUtc(created).Ticks-ticks)>10) throw new Exception("CORE_CONSOLE_IDENTITY_FAILED");
      // WMI creation times round to microseconds; compare at that precision while
      // holding the native handle so PID reuse cannot change the signalled target.
      if (WaitForSingleObject(handle,0)==0) throw new Exception("CORE_CONSOLE_CLOSE_FAILED");
      FreeConsole();
      if (!AttachConsole(pid)) throw new Exception("CORE_CONSOLE_UNAVAILABLE"); attached=true;
      uint[] processes=new uint[4]; uint count=GetConsoleProcessList(processes,4);
      uint self=(uint)System.Diagnostics.Process.GetCurrentProcess().Id; bool found=false;
      if(count<1 || count>2) throw new Exception("CORE_CONSOLE_NOT_PRIVATE");
      for(int i=0;i<count;i++) { if(processes[i]==pid) found=true; else if(processes[i]!=self) throw new Exception("CORE_CONSOLE_NOT_PRIVATE"); }
      // CREATE_NEW_PROCESS_GROUP disables Ctrl+C for that group. Ctrl+Break is
      // delivered only to this private group and Go exposes it as os.Interrupt.
      if(!found || !SetConsoleCtrlHandler(IntPtr.Zero,true) || !GenerateConsoleCtrlEvent(1,pid)) throw new Exception("CORE_CONSOLE_CLOSE_FAILED");
      if(WaitForSingleObject(handle,timeout)!=0) throw new Exception("CORE_CONSOLE_CLOSE_TIMEOUT");
      uint code; if(!GetExitCodeProcess(handle,out code)) throw new Exception("CORE_CONSOLE_CLOSE_FAILED"); return code;
    } finally { if(attached) FreeConsole(); CloseHandle(handle); }
  }
}
`;
const prelude = `$ErrorActionPreference='Stop'\n$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:${INPUT})) | ConvertFrom-Json\nAdd-Type -TypeDefinition @'\n${native}\n'@\n`;
const launchScript = `${prelude}
try { $stage='prepare'
  [Console]::Out.WriteLine('MC_CORE:READY'); [Console]::Out.Flush()
  if ([Console]::In.ReadLine() -ne 'start') { exit 12 }
  $stage='create'; $launch=[MCPrivateCore]::Launch($request.executable,$request.config); $corePid=$launch.Pid
  [Console]::Out.WriteLine(('MC_CORE:CREATED:'+ $launch.CreatedAt)); [Console]::Out.Flush()
  [Console]::Out.WriteLine(('MC_CORE:PID:'+ $corePid)); [Console]::Out.Flush()
  $stage='stream'; $handle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($launch.ErrorRead,$true)
  $stream=New-Object IO.FileStream($handle,[IO.FileAccess]::Read)
  $bytes=New-Object byte[] 4096
  while(($read=$stream.Read($bytes,0,4096)) -gt 0) { [Console]::Out.WriteLine(('MC_CORE:STDERR:'+ [Convert]::ToBase64String($bytes,0,$read))); [Console]::Out.Flush() }
  $stream.Dispose()
  $stage='wait'; $exitCode=[MCPrivateCore]::Finish($launch)
  [Console]::Out.WriteLine(('MC_CORE:EXIT:'+ $exitCode)); [Console]::Out.Flush()
} catch { [Console]::Out.WriteLine(('MC_CORE:ERROR:'+ $stage +':'+ $_.Exception.HResult)); [Console]::Out.Flush(); exit 13 }
finally { [MCPrivateCore]::Release($launch) }
`;
const closeScript = `${prelude}
try { $ticks=[DateTime]::Parse($request.createdAt).ToUniversalTime().Ticks
  $exitCode=[MCPrivateCore]::Close($request.pid,$request.executable,$ticks,$request.timeoutMs)
  @{closed=$true;exitCode=$exitCode} | ConvertTo-Json -Compress
} catch { $code='CORE_CONSOLE_CLOSE_FAILED'; foreach($known in @('CORE_CONSOLE_IDENTITY_FAILED','CORE_CONSOLE_UNAVAILABLE','CORE_CONSOLE_NOT_PRIVATE','CORE_CONSOLE_CLOSE_TIMEOUT')) { if($_.Exception.ToString().Contains($known)){$code=$known;break} }; @{closed=$false;code=$code}|ConvertTo-Json -Compress; exit 1 }
`;
const args = script => ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
const env = payload => ({ ...process.env, [INPUT]: Buffer.from(JSON.stringify(payload)).toString('base64') });

export async function launchWindowsCore(executable, config, { prepare, spawn = nodeSpawn } = {}) {
  const helper = spawn('powershell.exe', args(launchScript), { windowsHide: true, stdio: ['pipe', 'pipe', 'ignore'], env: env({ executable, config }) });
  const core = new EventEmitter(); core.pid = null; core.exitCode = null; core.signalCode = null;
  core.on('error', () => {});
  core.stderr = new PassThrough(); core.unref = () => { helper.unref?.(); helper.stdout.unref?.(); core.stderr.unref?.(); };
  let buffer = '', settled = false, prepared = false, closed = false, startRequested = false, cancelled = false;
  const launchFailure = () => Object.assign(fail('CORE_CONSOLE_START_FAILED'), { mayHaveStarted: startRequested });
  return new Promise((resolve, reject) => {
    const abort = cause => { cancelled = true; clearTimeout(timer); helper.stdin.destroy(); reject(cause); };
    const timer = setTimeout(() => abort(launchFailure()), 20000);
    helper.stdin.on('error', () => { if(!settled) abort(launchFailure()); else core.emit('error', fail('CORE_CONSOLE_CLOSE_FAILED')); });
    helper.once('error', () => { clearTimeout(timer); if (!settled) abort(launchFailure()); else core.emit('error', fail('CORE_CONSOLE_CLOSE_FAILED')); });
    helper.stdout.on('data', chunk => {
      if(cancelled) return;
      buffer += String(chunk);
      let newline;
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, newline).trim(); buffer = buffer.slice(newline + 1);
        if (line.length > 65536) { buffer = ''; if(!settled) abort(launchFailure()); else { cancelled=true; helper.stdout.destroy(); core.emit('error', fail('CORE_CONSOLE_CLOSE_FAILED')); } return; }
        if (line === 'MC_CORE:READY' && !prepared && !cancelled) {
          prepared = true;
          Promise.resolve().then(() => prepare(helper.pid)).then(() => { if(!cancelled && !helper.stdin.destroyed) { startRequested = true; helper.stdin.end('start\n'); } }, () => abort(launchFailure()));
        } else if (/^MC_CORE:PID:\d+$/.test(line) && !settled && !cancelled) {
          core.pid = Number(line.slice(12)); settled = true; clearTimeout(timer); resolve(core); setImmediate(() => core.emit('spawn'));
        } else if (line.startsWith('MC_CORE:CREATED:') && !settled) core.createdAt = line.slice(16);
        else if (/^MC_CORE:EXIT:-?\d+$/.test(line) && settled) {
          closed = true; core.exitCode = Number(line.slice(13)); core.stderr.end(); core.emit('exit', core.exitCode, null);
        } else if (line.startsWith('MC_CORE:STDERR:') && settled && !core.stderr.write(Buffer.from(line.slice(15), 'base64'))) { helper.stdout.pause(); core.stderr.once('drain', () => helper.stdout.resume()); }
        else if (line.startsWith('MC_CORE:ERROR:')) { clearTimeout(timer);
          const diagnostic = line.split(':'); const cause = settled ? fail('CORE_CONSOLE_CLOSE_FAILED') : launchFailure();
          cause.diagnostic = { operation: ['prepare','create','stream','wait'].includes(diagnostic[2]) ? diagnostic[2] : 'launch', nativeCode: Number(diagnostic[3]) };
          if(!settled) abort(cause); else core.emit('error', cause);
        }
      }
      if(buffer.length>65536) { buffer=''; if(!settled) abort(launchFailure()); else { cancelled=true; helper.stdout.destroy(); core.emit('error', fail('CORE_CONSOLE_CLOSE_FAILED')); } }
    });
    helper.once('close', () => { clearTimeout(timer); if(!settled) abort(launchFailure()); else if(!closed) { core.stderr.end(); core.emit('error', fail('CORE_CONSOLE_CLOSE_FAILED')); } });
  });
}

export async function closeWindowsCore(identity, { execFile = nodeExecFile, timeoutMs = 5000 } = {}) {
  const output = await new Promise((resolve, reject) => execFile('powershell.exe', args(closeScript), { windowsHide: true, encoding: 'utf8',
    timeout: timeoutMs + 15000, maxBuffer: 32768, env: env({ pid: identity.pid, executable: identity.executable, createdAt: identity.createdAt, timeoutMs }) },
  (cause, stdout) => { if (stdout) resolve(stdout); else if(cause) reject(fail('CORE_CONSOLE_CLOSE_FAILED')); else reject(fail('CORE_CONSOLE_CLOSE_FAILED')); }));
  let response; try { response = JSON.parse(output); } catch { throw fail('CORE_CONSOLE_CLOSE_FAILED'); }
  if (response.closed !== true || response.exitCode !== 0) throw fail(['CORE_CONSOLE_IDENTITY_FAILED', 'CORE_CONSOLE_UNAVAILABLE', 'CORE_CONSOLE_NOT_PRIVATE', 'CORE_CONSOLE_CLOSE_TIMEOUT'].includes(response.code) ? response.code : 'CORE_CONSOLE_CLOSE_FAILED');
  return { closed: true, exitCode: 0 };
}
