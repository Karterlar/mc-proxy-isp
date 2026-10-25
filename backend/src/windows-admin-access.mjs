import path from 'node:path';
import { execFile as nodeExecFile } from 'node:child_process';

// Read the application's token, not just a helper's account. Requesting a SCM
// handle tests its access rights without creating, changing or starting services.
const SCRIPT = String.raw`
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$WarningPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class MCStartupAccess {
  [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr Sid; public UInt32 Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct GroupHeader { public UInt32 Count; public SidAttributes First; }
  public sealed class TokenState { public bool Elevated; public bool AdminMember; public int IntegrityRid; public string UserSid; }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(UInt32 access, bool inherit, UInt32 pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, UInt32 access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr data, int bytes, out int required);
  [DllImport("advapi32.dll")] static extern bool IsWellKnownSid(IntPtr sid, int kind);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
  [DllImport("advapi32.dll")] static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 index);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr OpenSCManagerW(string machine, string database, UInt32 access);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool CloseServiceHandle(IntPtr handle);
  static IntPtr Information(IntPtr token, int kind) {
    int bytes;
    GetTokenInformation(token, kind, IntPtr.Zero, 0, out bytes);
    if(bytes < 1 || bytes > 1024 * 1024) throw new Win32Exception(Marshal.GetLastWin32Error());
    IntPtr data=Marshal.AllocHGlobal(bytes);
    if(!GetTokenInformation(token, kind, data, bytes, out bytes)) {
      int error=Marshal.GetLastWin32Error(); Marshal.FreeHGlobal(data); throw new Win32Exception(error);
    }
    return data;
  }
  public static TokenState Read(UInt32 pid) {
    IntPtr process=OpenProcess(0x1000, false, pid), token=IntPtr.Zero;
    if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
    try {
      if(!OpenProcessToken(process, 0x8, out token)) throw new Win32Exception(Marshal.GetLastWin32Error());
      TokenState state=new TokenState();
      IntPtr data=Information(token,20);
      try { state.Elevated=Marshal.ReadInt32(data)!=0; } finally { Marshal.FreeHGlobal(data); }
      data=Information(token,25);
      try {
        IntPtr sid=Marshal.ReadIntPtr(data); int count=Marshal.ReadByte(GetSidSubAuthorityCount(sid));
        if(count < 1) throw new InvalidOperationException();
        state.IntegrityRid=Marshal.ReadInt32(GetSidSubAuthority(sid,(UInt32)(count-1)));
      } finally { Marshal.FreeHGlobal(data); }
      data=Information(token,1);
      try { state.UserSid=new SecurityIdentifier(Marshal.ReadIntPtr(data)).Value; } finally { Marshal.FreeHGlobal(data); }
      data=Information(token,2);
      try {
        int count=Marshal.ReadInt32(data), offset=(int)Marshal.OffsetOf(typeof(GroupHeader),"First"), size=Marshal.SizeOf(typeof(SidAttributes));
        if(count < 0 || count > 4096) throw new InvalidOperationException();
        for(int index=0;index<count;index++) {
          SidAttributes group=(SidAttributes)Marshal.PtrToStructure(IntPtr.Add(data,offset+index*size),typeof(SidAttributes));
          if(IsWellKnownSid(group.Sid,26) && (group.Attributes & 0x4)!=0 && (group.Attributes & 0x10)==0) state.AdminMember=true;
        }
      } finally { Marshal.FreeHGlobal(data); }
      return state;
    } finally { if(token!=IntPtr.Zero) CloseHandle(token); CloseHandle(process); }
  }
  public static int ServiceManagerAccess() {
    IntPtr manager=OpenSCManagerW(null,null,0x2);
    if(manager==IntPtr.Zero) return Marshal.GetLastWin32Error();
    if(!CloseServiceHandle(manager)) throw new Win32Exception(Marshal.GetLastWin32Error());
    return 0;
  }
}
'@
$application=[MCStartupAccess]::Read([uint32]$env:MC_PROXY_PERMISSION_PID)
$helper=[MCStartupAccess]::Read([uint32]$PID)
$same=$application.UserSid -ceq $helper.UserSid -and $application.Elevated -eq $helper.Elevated -and $application.AdminMember -eq $helper.AdminMember -and $application.IntegrityRid -eq $helper.IntegrityRid
$capability=[MCStartupAccess]::ServiceManagerAccess()
@{version=1;processId=[int]$env:MC_PROXY_PERMISSION_PID;elevated=$application.Elevated;adminMember=$application.AdminMember;integrityRid=$application.IntegrityRid;tokenMatched=[bool]$same;capabilityError=$capability} | ConvertTo-Json -Compress
`;

const failed = () => Object.assign(new Error('Unable to verify Windows administrator access'), { code: 'ADMIN_CHECK_FAILED' });
export function classifyAdminAccess(value, processId) {
  const keys=['version','processId','elevated','adminMember','integrityRid','tokenMatched','capabilityError'];
  if(!value || typeof value!=='object' || Array.isArray(value) || Object.keys(value).sort().join(',')!==keys.sort().join(',')
    || value.version!==1 || value.processId!==processId || !['elevated','adminMember','tokenMatched'].every(key=>typeof value[key]==='boolean')
    || !Number.isInteger(value.integrityRid) || value.integrityRid<0 || value.integrityRid>0xffff
    || !Number.isInteger(value.capabilityError) || value.capabilityError<0 || value.capabilityError>0xffff) throw failed();
  const integrity=value.integrityRid>=0x4000?'system':value.integrityRid>=0x3000?'high':value.integrityRid>=0x2000?'medium':'low';
  const errorCode=!value.tokenMatched?'ADMIN_CHECK_FAILED':!value.elevated||!value.adminMember||value.integrityRid<0x3000?'ADMIN_REQUIRED'
    :value.capabilityError===0?null:value.capabilityError===5?'ADMIN_CAPABILITY_DENIED':'ADMIN_CHECK_FAILED';
  return {checked:true,elevated:value.elevated,adminMember:value.adminMember,integrity,tokenMatched:value.tokenMatched,
    capabilityVerified:value.capabilityError===0,capabilityError:value.capabilityError,errorCode};
}

export function createWindowsAdminInspector({execFile=nodeExecFile,platform=process.platform,processId=process.pid,systemRoot=process.env.SystemRoot||'C:\\Windows'}={}) {
  return async()=>{
    if(platform!=='win32'||!Number.isInteger(processId)||processId<1||processId>0x7fffffff
      ||!path.win32.isAbsolute(systemRoot)||/^[\\/]{2}|[\x00-\x1f\x7f]/.test(systemRoot)) throw failed();
    const stdout=await new Promise((resolve,reject)=>execFile(path.win32.join(systemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe'),
      ['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(SCRIPT,'utf16le').toString('base64')],
      {windowsHide:true,encoding:'utf8',timeout:15000,maxBuffer:16384,env:{...process.env,MC_PROXY_PERMISSION_PID:String(processId)}},
      (error,output)=>error?reject(failed()):resolve(output)));
    try {return classifyAdminAccess(JSON.parse(stdout.replace(/^\uFEFF/,'').trim()),processId);} catch {throw failed();}
  };
}
export const inspectWindowsAdminAccess=createWindowsAdminInspector();
