import test from 'node:test';
import assert from 'node:assert/strict';
import { createFingerprintSecurityCheck, FINGERPRINT_SECURITY_BASELINE } from '../src/fingerprint-browser-security.mjs';
const now=()=>Date.parse('2026-10-18T12:00:00Z');
const response=(version='155.0.8059.85',extra={})=>new Response(JSON.stringify([{version,platform:'Windows',channel:'Stable',time:now()-1000,...extra}]));
test('offline status distinguishes known old engine, fresh baseline and unknown coverage without fetching',()=>{
  const noFetch=()=>{throw Error('unexpected network');};
  assert.equal(createFingerprintSecurityCheck({version:'150.0.7871.186',now,fetchRelease:noFetch}).snapshot().status,'outdated');
  assert.equal(createFingerprintSecurityCheck({version:FINGERPRINT_SECURITY_BASELINE.version,now,fetchRelease:noFetch}).snapshot().status,'meets-baseline');
  assert.equal(createFingerprintSecurityCheck({version:'bad',now,fetchRelease:noFetch}).snapshot().status,'unverified');
  const stale=()=>now()+15*86400000;
  assert.equal(createFingerprintSecurityCheck({version:FINGERPRINT_SECURITY_BASELINE.version,now:stale}).snapshot().status,'unverified');
  assert.equal(createFingerprintSecurityCheck({version:'150.0.7871.186',now:stale}).snapshot().status,'outdated');
});
test('explicit checks accept only official bounded stable metadata, deduplicate requests and never authorize code',async()=>{
  let count=0,finish;
  const checker=createFingerprintSecurityCheck({version:'150.0.7871.186',now,fetchRelease:async(url,options)=>{count++;assert.equal(url,FINGERPRINT_SECURITY_BASELINE.source);assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');return new Promise(resolve=>finish=()=>resolve(response()));}});
  const a=checker.check(),b=checker.check();await Promise.resolve();assert.equal(count,1);assert.equal(checker.snapshot().checking,true);finish();
  for(const value of await Promise.all([a,b])){assert.equal(value.status,'outdated');assert.equal(value.checkError,null);assert.equal(value.automaticDownload,false);assert.equal(value.checking,false);}
  await checker.check();assert.equal(count,1);
});
test('network failure, downgrade, wrong channel, oversized response and future release never erase known outdated status',async()=>{
  for(const fetchRelease of [()=>{throw Error('sync failure');},async()=>{throw Error('offline');},async()=>response('149.0.1.1'),async()=>response('156.0.1.1',{channel:'Dev'}),async()=>new Response('x'.repeat(65537)),async()=>response('156.0.1.1',{time:now()+2*86400000})]){
    const checker=createFingerprintSecurityCheck({version:'150.0.7871.186',now,fetchRelease}),result=await checker.check();assert.equal(result.status,'outdated');assert.equal(result.baselineVersion,FINGERPRINT_SECURITY_BASELINE.version);assert.equal(result.checkError,'FINGERPRINT_SECURITY_CHECK_FAILED');assert.equal(result.checkedAt,null);assert.equal(checker.snapshot().checking,false);
  }
});
test('newer valid metadata is advisory and mock never contacts the network',async()=>{
  const checker=createFingerprintSecurityCheck({version:'155.0.8059.85',now,fetchRelease:async()=>response('156.0.1.2')});
  assert.equal((await checker.check()).status,'outdated');assert.equal(checker.snapshot().baselineVersion,'156.0.1.2');
  assert.equal((await createFingerprintSecurityCheck({version:'150.0.7871.186',mock:true,now,fetchRelease:()=>assert.fail('network')}).check()).status,'mocked');
});
