import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyAdminAccess, createWindowsAdminInspector } from '../src/windows-admin-access.mjs';
import { startupAccess } from '../../desktop/admin-startup.mjs';

const ordinary={version:1,processId:12000,elevated:false,adminMember:false,integrityRid:0x2000,tokenMatched:true,capabilityError:5};
const elevated={...ordinary,elevated:true,adminMember:true,integrityRid:0x3000,capabilityError:0};
const inspect=(value,processId=12000)=>classifyAdminAccess(value,processId);

test('effective application token and access capability must both pass, including an unlinked elevated administrator token',()=>{
  assert.equal(inspect(ordinary).errorCode,'ADMIN_REQUIRED');
  assert.equal(inspect({...ordinary,capabilityError:0}).errorCode,'ADMIN_REQUIRED','a delegated SCM ACL is not an administrator token');
  assert.equal(inspect({...elevated,adminMember:false}).errorCode,'ADMIN_REQUIRED','deny-only or absent administrator SID cannot authorize');
  assert.equal(inspect({...elevated,integrityRid:0x2000}).errorCode,'ADMIN_REQUIRED');
  const result=inspect(elevated);
  assert.equal(result.errorCode,null); assert.equal(result.integrity,'high'); assert.equal(result.capabilityVerified,true);
  assert.equal(inspect({...elevated,integrityRid:0x4000}).integrity,'system');
  assert.deepEqual(Object.keys(result).sort(),['adminMember','capabilityError','capabilityVerified','checked','elevated','errorCode','integrity','tokenMatched']);
});

test('helper mismatch, administrator capability denial and unknown native failures stay distinct and locked',async()=>{
  for(const [patch,code] of [[{tokenMatched:false},'ADMIN_CHECK_FAILED'],[{capabilityError:5},'ADMIN_CAPABILITY_DENIED'],[{capabilityError:1722},'ADMIN_CHECK_FAILED']]) {
    const verification=inspect({...elevated,...patch});
    const access=await startupAccess({platform:'win32',inspectAdminAccess:async()=>verification});
    assert.equal(access.allowed,false); assert.equal(access.reason,code); assert.deepEqual(access.verification,verification);
  }
  const access=await startupAccess({platform:'win32',inspectAdminAccess:async()=>inspect(elevated)});
  assert.equal(access.allowed,true); assert.equal(access.verification.checked,true);
  for(const value of [null,{}, {checked:false,errorCode:null}, {checked:true,errorCode:'arbitrary'}]) {
    assert.equal((await startupAccess({platform:'win32',inspectAdminAccess:async()=>value})).reason,'ADMIN_CHECK_FAILED');
  }
});

test('native response cannot authorize another PID, missing facts, strings, extra data or out of bounds values',()=>{
  for(const value of [null,true,[],{}, {...elevated,processId:12001},{...elevated,elevated:'true'}, {...elevated,tokenMatched:null},
    {...elevated,integrityRid:-1},{...elevated,capabilityError:-1},{...elevated,capabilityError:65536},{...elevated,userSid:'private'},
    Object.fromEntries(Object.entries(elevated).filter(([key])=>key!=='capabilityError'))]) assert.throws(()=>inspect(value),{code:'ADMIN_CHECK_FAILED'});
});

test('fixed system PowerShell queries the supplied main PID and closes a requested SCM handle without system writes',async()=>{
  let observed;
  const adapter=createWindowsAdminInspector({platform:'win32',processId:12000,systemRoot:'C:\\Windows',execFile:(file,args,options,callback)=>{
    observed={file,args,options}; callback(null,JSON.stringify(elevated));
  }});
  assert.equal((await adapter()).errorCode,null);
  assert.equal(observed.file,'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(observed.args.slice(0,3),['-NoProfile','-NonInteractive','-EncodedCommand']);
  assert.equal(observed.options.env.MC_PROXY_PERMISSION_PID,'12000');
  assert.equal(observed.options.windowsHide,true); assert.equal(observed.options.timeout,15000);
  const script=Buffer.from(observed.args[3],'base64').toString('utf16le');
  assert.match(script,/Read\(\[uint32\]\$env:MC_PROXY_PERMISSION_PID\)/);
  assert.match(script,/OpenSCManagerW\(null,null,0x2\)/); assert.match(script,/CloseServiceHandle\(manager\)/);
  assert.doesNotMatch(script,/CreateService|ChangeService|StartService|Stop-Service|Set-Item|Remove-Item|Set-Net|RunAs|sc\.exe|netsh/i);
});

test('execution errors, corrupt output and unsafe inputs cannot fall back to administrator success',async()=>{
  for(const reply of ['true','false','{"errorCode":null}','private non-JSON output']) {
    const adapter=createWindowsAdminInspector({platform:'win32',processId:12000,execFile:(_file,_args,_options,callback)=>callback(null,reply)});
    await assert.rejects(adapter(),{code:'ADMIN_CHECK_FAILED'});
  }
  const adapter=createWindowsAdminInspector({platform:'win32',processId:12000,execFile:(_file,_args,_options,callback)=>callback(new Error('private path or error'))});
  await assert.rejects(adapter(),error=>error.code==='ADMIN_CHECK_FAILED'&&!error.message.includes('private'));
  for(const options of [{platform:'darwin'}, {processId:0}, {systemRoot:'powershell.exe'}, {systemRoot:'\\\\remote\\Windows'}]) {
    await assert.rejects(createWindowsAdminInspector({platform:'win32',execFile:()=>assert.fail('invalid inputs must not invoke'),...options})(),{code:'ADMIN_CHECK_FAILED'});
  }
});
