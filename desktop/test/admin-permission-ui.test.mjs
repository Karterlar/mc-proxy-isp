import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const appSource=await readFile(new URL('../../frontend/app.js',import.meta.url),'utf8');
const from=appSource.indexOf('function adminAccessStatusText('),to=appSource.indexOf('async function refreshClientLogState(',from);
assert.ok(from>=0&&to>from);
const adminAccessStatusText=vm.runInNewContext(appSource.slice(from,to)+';adminAccessStatusText');
const verified={checked:true,elevated:true,adminMember:true,integrity:'high',tokenMatched:true,capabilityVerified:true,errorCode:null};

test('administrator status requires complete native verification and never exposes native identifiers',()=>{
  assert.equal(adminAccessStatusText(verified),'管理员权限与能力已验证。');
  assert.equal(adminAccessStatusText({...verified,integrity:'system'}),'管理员权限与能力已验证。');
  assert.match(adminAccessStatusText({mock:true,checked:false}),/演示模式未检查/);
  assert.match(adminAccessStatusText({...verified,elevated:false,errorCode:'ADMIN_REQUIRED'}),/尚未提权.*保持锁定/);
  assert.match(adminAccessStatusText({...verified,capabilityVerified:false,errorCode:'ADMIN_CAPABILITY_DENIED'}),/已提权.*系统未允许/);
  for(const access of [undefined,{}, {...verified,checked:false}, {...verified,tokenMatched:false}, {...verified,integrity:'medium'}, {...verified,capabilityVerified:false}, {...verified,adminMember:false}, {...verified,errorCode:'ADMIN_CHECK_FAILED'}, {...verified,errorCode:'unexpected'}]){
    assert.match(adminAccessStatusText(access),/暂时无法确认/);
  }
  assert.doesNotMatch(adminAccessStatusText({...verified,errorCode:'ADMIN_CHECK_FAILED',sid:'private-sid',pid:123,path:'private-path'}),/private|123/);
});

const gateSource=await readFile(new URL('../../frontend/admin-required.js',import.meta.url),'utf8');
async function gate(info){
  const elements=new Map(),calls=[];
  const element=selector=>{
    if(!elements.has(selector))elements.set(selector,{textContent:'',hidden:true,disabled:true,events:new Map(),attributes:new Map(),addEventListener(name,callback){this.events.set(name,callback);},setAttribute(name,value){this.attributes.set(name,value);},focus(){this.focused=true;}});
    return elements.get(selector);
  };
  vm.runInNewContext(gateSource,{document:{querySelector:element},window:{mcAdminGate:{info:async()=>info,restart:async()=>{calls.push('restart');return {canceled:true,started:false};},close:async()=>calls.push('close'),minimize:async()=>calls.push('minimize')}}});
  await new Promise(resolve=>setImmediate(resolve));
  return {element,calls};
}

test('capability-denied gate explains policy limits while retaining safe restart and exit controls',async()=>{
  const h=await gate({reason:'capability-denied',adminAccess:{...verified,capabilityVerified:false,errorCode:'ADMIN_CAPABILITY_DENIED'}});
  assert.match(h.element('#gateTitle').textContent,/管理员能力验证未通过/);
  assert.match(h.element('#gateDescription').textContent,/已具备管理员权限.*未允许.*保持锁定/);
  assert.match(h.element('#gateHelp').textContent,/系统策略.*再次提权不一定能解决/);
  assert.equal(h.element('#restartButton').disabled,false);
  assert.equal(h.element('#restartLabel').textContent,'重新启动并核验权限');
  assert.deepEqual(h.calls,[]);
  await h.element('#restartButton').events.get('click')();
  assert.deepEqual(h.calls,['restart']);
  assert.equal(h.element('#restartButton').disabled,false);
  assert.match(h.element('#gateError').textContent,/已取消权限确认.*保持锁定/);
  assert.equal(h.element('#restartLabel').textContent,'重新启动并核验权限');
  await h.element('#exitButton').events.get('click')();
  assert.deepEqual(h.calls,['restart','close']);
});

test('unknown verification and changed Windows account remain locked without claiming elevated status',async()=>{
  const unknown=await gate({reason:'check-failed',adminAccess:{checked:false}});
  assert.match(unknown.element('#gateStatus').textContent,/权限检查未完成.*保持锁定/);
  assert.match(unknown.element('#gateError').textContent,/无法确认当前管理员权限/);
  const changed=await gate({reason:'account-changed',adminAccess:verified});
  assert.match(changed.element('#gateTitle').textContent,/原来的 Windows 账户/);
  assert.equal(changed.element('#restartButton').disabled,true);
  assert.deepEqual(changed.calls,[]);
});
