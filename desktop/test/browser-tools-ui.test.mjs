import test from 'node:test';
import assert from 'node:assert/strict';
import { browserSelection, browserObservationView, localObservationUrl, applicationDiagnosisView, fingerprintRegionSummary } from '../../frontend/browser-tools.js';
import { sessionPreferencePayload, sessionPreferenceDefaults, createPreferenceWriter } from '../../frontend/workspace-view.js';

test('fingerprint region distinguishes manual and auto sources per field and never labels a fallback as exit-matched', () => {
  const settings={language:'auto',timezone:'Asia/Tokyo',resolvedLanguage:'zh-CN',resolvedTimezone:'Asia/Tokyo',languageSource:'local-environment',timezoneSource:'manual',alignmentSource:'verified-exit'};
  const fallback=fingerprintRegionSummary(settings);
  assert.match(fallback,/zh-CN（本机环境 · 未匹配出口）/);
  assert.match(fallback,/Asia\/Tokyo（手动设置）/);
  assert.doesNotMatch(fallback,/已核验出口/);
  assert.match(fingerprintRegionSummary({...settings,alignmentCode:'GEO_UNVERIFIED'}),/本次出口地区未能核验/);
  assert.match(fingerprintRegionSummary({...settings,resolvedLanguage:'ja-JP',languageSource:'verified-exit'}),/ja-JP（已核验出口）/);
  const bound={...settings,resolvedLanguage:'ja-JP',languageSource:'verified-exit',alignmentRevision:3,alignmentExitIp:'203.0.113.8'};
  for (const state of [{ready:false},{ready:true,revision:4},{ready:true,exitIp:'203.0.113.9'}]) {
    assert.match(fingerprintRegionSummary(bound,state),/上一轮匹配不能沿用/);
    assert.doesNotMatch(fingerprintRegionSummary(bound,state),/ja-JP|已核验出口/);
  }
  assert.match(fingerprintRegionSummary({...bound,language:'ja-JP',languageSource:'manual'},{ready:false}),/ja-JP（手动设置）/);
  assert.match(fingerprintRegionSummary({...bound,alignmentExpiresAt:'2020-01-01T00:00:00Z'}),/上一轮匹配不能沿用/);
});

test('Chrome defaults to retained data and preserves the separate optional fingerprint preference', async () => {
  assert.equal(sessionPreferenceDefaults.browser,'chrome');
  assert.equal(sessionPreferenceDefaults.fingerprintFresh,false);
  assert.equal(sessionPreferenceDefaults.fresh,false);
  const requests=[],writer=createPreferenceWriter({request:async payload=>{requests.push(sessionPreferencePayload(payload));return {};}});
  assert.equal(writer.hydrate({browser:'chrome',fresh:false,fingerprintFresh:false,fingerprintLanguage:'en-US',fingerprintTimezone:'auto',fingerprintNativeGraphics:true}).browser,'chrome');
  await writer.write({browser:'fingerprint',fingerprintFresh:true});
  assert.equal(requests[0].fresh,false);
  assert.equal(requests[0].fingerprintFresh,true);
  for (const key of ['fingerprintLanguage','fingerprintTimezone','fingerprintNativeGraphics']) assert.equal(Object.hasOwn(requests[0],key),false);
});

test('selecting an unavailable fingerprint engine never silently opens Chrome', () => {
  const choices = [{id:'chrome',available:true},{id:'edge',available:false},{id:'fingerprint',available:false}];
  const result = browserSelection(choices,'fingerprint','fingerprint');
  assert.equal(result.selected,'fingerprint');
  assert.equal(result.autoFallback,false);
  assert.match(result.notice,/准备引擎/);
  assert.equal(browserSelection(choices,'edge','edge').selected,'chrome');
  assert.equal(browserSelection([...choices.slice(0,2),{id:'fingerprint',available:true}],'fingerprint','fingerprint').selected,'fingerprint');
  const onlyFingerprint = browserSelection([{id:'chrome',available:false},{id:'edge',available:false},{id:'fingerprint',available:true}],'chrome','chrome');
  assert.equal(onlyFingerprint.selected,'chrome');
  assert.equal(onlyFingerprint.autoFallback,false);
  assert.match(onlyFingerprint.notice,/安装官方浏览器.*指定程序路径/);
});

test('browser self-report retains pending items and never converts configuration into measurements', () => {
  const observation = {status:'completed',report:{source:{kind:'browser-self-report'},summary:{status:'partial'},checks:[
    {id:'https-exit',label:'HTTPS 出口',status:'verified',value:'203.0.113.8',detail:'当前页面实测'},
    {id:'dns',label:'DNS',status:'configured',detail:'尚未独立检测'},
    {id:'webrtc',label:'WebRTC',status:'unverified',detail:'未完成'},
    {id:'unknown',label:'未来检测项',status:'green-all-safe'},
  ]}};
  const view = browserObservationView(observation);
  assert.equal(view.state,'completed');
  assert.deepEqual(view.checks.map(item=>item.status),['verified','configured','unverified','unverified']);
  assert.match(view.summary,/这不证明其他窗口/);
  assert.ok(!view.summary.includes('全部通过'));
  assert.equal(browserObservationView(observation,{mock:true}).checks[0].status,'mocked');
  assert.equal(browserObservationView({...observation,status:'unverified'}).checks[0].status,'stale');
  assert.equal(browserObservationView(observation,{connected:false}).checks[0].status,'stale');
  assert.equal(browserObservationView({...observation,expiresAt:'2020-01-01T00:00:00Z'}).checks[0].status,'stale');
});

test('only loopback observation links may be copied and stale links disappear', () => {
  const url = 'http://127.0.0.1:17889/browser-observation#token=ephemeral';
  assert.equal(localObservationUrl(url),url);
  for (const value of ['https://remote.example/observe','javascript:alert(1)','http://127.0.0.1.evil/','http://user:pass@127.0.0.1/']) assert.equal(localObservationUrl(value),'');
  assert.equal(browserObservationView({status:'waiting',url,expiresAt:'2020-01-01T00:00:00Z'}).link,'');
  assert.equal(browserObservationView({status:'waiting',url,expiresAt:'2099-01-01T00:00:00Z'}).link,url);
});

test('layered diagnosis presents evidence and bounded codes without guessing from a timeout', () => {
  const result = applicationDiagnosisView({summary:'需要分层核验',layers:[
    {id:'entry',label:'VPN 入口',status:'unverified',detail:'未独立检测'},
    {id:'isp',label:'ISP',status:'unverified',code:'PROBE_TIMEOUT'},
    {id:'target',label:'目标服务',status:'restricted',code:'bad code private data'},
  ]});
  assert.equal(result.layers[0].status,'unverified');
  assert.equal(result.layers[1].status,'unverified');
  assert.equal(result.layers[1].code,'PROBE_TIMEOUT');
  assert.equal(result.layers[2].code,'');
  assert.deepEqual(applicationDiagnosisView(null),{summary:'',layers:[]});
});
