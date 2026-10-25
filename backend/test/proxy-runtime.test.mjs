import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { readFileSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createProxyRuntime } from '../src/proxy-runtime.mjs';
import { createNetworkLockManager, networkLockBinding } from '../src/network-lock.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';
import { vpnOutbound } from './vpn-fixture.mjs';
import { createHash } from 'node:crypto';
const compatConfig = () => ({ ...structuredClone(config), connectionMode: 'vpn-compat', upstream: { ...config.upstream, host: 'provider.invalid' } });

const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '192.0.2.1', port: 8080, auth: 'password' }, probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };

async function fixture(t, overrides = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'proxypilot runtime test '));
  t.after(() => rm(root, { recursive: true, force: true }));
  const corePath = path.join(root, 'Core With Spaces', 'sing-box.exe');
  const now = Date.parse('2026-09-30T12:00:00Z');
  const parent = { pid: process.pid, createdAt: '2026-09-30T11:00:00.0000000Z', executable: process.execPath, commandLine: `"${process.execPath}" test-controller.mjs` };
  const state = { process: null, owner: null, controller: parent, clock: now, stopCalls: [], spawns: [], execs: [], readSecrets: 0, dnsClears: 0, trafficGate: [] };
  const dependencies = {
    loadConfig: async () => structuredClone(config),
    loadSecrets: async () => { state.readSecrets++; return { ISP_USERNAME: 'test-user', ISP_PASSWORD: 'test-secret' }; },
    createPrivateDirectory: directory => mkdir(directory, { mode: 0o700 }),
    writePrivate: (file, contents) => writeFile(file, contents, { mode: 0o600, flag: 'wx' }),
    execFile: (file, args, options, callback) => {
      state.execs.push({ file, args, options });
      callback(null, args[0] === 'version' ? 'sing-box version 1.14.2\n' : '');
    },
    spawn: (file, args, options) => {
      state.spawns.push({ file, args, options });
      const child = new EventEmitter();
      child.pid = 1234; child.exitCode = null; child.signalCode = null; child.unref = () => {};
      state.process = { pid: child.pid, parentPid: process.pid, createdAt: new Date(state.clock).toISOString(), executable: file, commandLine: `"${file}" run -c "${args[2]}"` };
      state.owner = { ...state.process, listenAddresses: ['127.0.0.1'] };
      state.child = child;
      queueMicrotask(() => child.emit('spawn'));
      return child;
    },
    inspectProcess: async pid => pid === process.pid ? { ...state.controller } : state.process?.pid === pid ? { ...state.process } : null,
    listProcesses: async () => state.process ? [{ ...state.process }] : [],
    isElevated: async () => true,
    inspectTun: async () => ({ exists: Boolean(state.process), ready: Boolean(state.process) }),
    inspectExternalVpnTun: async () => ({ active: false, count: 0 }),
    clearDnsCache: async () => { state.dnsClears++; return { cleared: true }; },
    allocateCoreApiPort: async () => 17991,
    setCoreTrafficBlocked: async (api, blocked) => { state.trafficGate.push({ port: api.port, blocked }); return { blocked, confirmed: true }; },
    closeCore: async (identity, { stopProcess }) => { await stopProcess(identity); return { closed: true, exitCode: 0 }; },
    resolveUpstream: async () => '192.0.2.2',
    listenerOwner: async () => state.owner ? { ...state.owner } : null,
    stopProcess: async identity => { state.stopCalls.push(identity); state.process = null; state.owner = null; return { stopped: true }; },
    delay: async () => {},
    now: () => state.clock,
    ...overrides,
  };
  const options = { runtimeRoot: root, corePath, dependencies, networkLock: createNetworkLockManager({ mock: true }), ownedStateCacheMs: 0 };
  return { root, corePath, state, dependencies, options, runtime: createProxyRuntime(options) };
}

function simulateControllerRestart(state) {
  state.clock += 1000;
  // Reuse the test runner PID with a newer creation identity, as Windows may
  // after the original controller exits. Its detached child identity stays fixed.
  state.controller = { ...state.controller, createdAt: new Date(state.clock).toISOString() };
}

test('completed owned evidence is reused only briefly with the same held child and is invalidated on native change', async t => {
  const f=await fixture(t);let nativeReads=0,tunReady=true;
  const runtime=createProxyRuntime({...f.options,ownedStateCacheMs:2000,dependencies:{...f.dependencies,inspectWindowsOwnedState:async()=>{
    nativeReads++;return {identity:{...f.state.process},owner:{...f.state.owner},tun:{exists:true,ready:tunReady}};
  }}});
  await runtime.start(config);nativeReads=0;
  for(let i=0;i<20;i++)assert.equal((await runtime.inspectOwnedState()).tunReady,true);
  assert.equal(nativeReads,1,'a connection burst does not repeat PowerShell after completion');
  f.state.clock+=2000;await runtime.inspectOwnedState();assert.equal(nativeReads,2);
  tunReady=false;runtime.invalidateOwnedState();assert.equal((await runtime.inspectOwnedState()).tunReady,false);
  assert.equal(nativeReads,3);assert.equal((await runtime.inspectOwnedState()).tunReady,false);assert.equal(nativeReads,4,'negative readiness is never cached');
  tunReady=true;await runtime.inspectOwnedState();f.state.child.emit('error',new Error('monitor lost'));
  await runtime.inspectOwnedState();await runtime.inspectOwnedState();assert.equal(nativeReads,7,'a failed held monitor cannot support cached identity');
  await runtime.stop();assert.equal((await runtime.inspectOwnedState()).running,false);
});

test('native invalidation supersedes an unfinished owned read and cannot seed later cached authorization', async t => {
  const f=await fixture(t);let resolve,entered;
  const waiting=new Promise(done=>{entered=done;}),held=new Promise(done=>{resolve=done;});
  const runtime=createProxyRuntime({...f.options,ownedStateCacheMs:2000,dependencies:{...f.dependencies,inspectWindowsOwnedState:async()=>{
    entered();await held;return {identity:{...f.state.process},owner:{...f.state.owner},tun:{exists:true,ready:true}};
  }}});
  await runtime.start(config);const reading=runtime.inspectOwnedState();await waiting;runtime.invalidateOwnedState();resolve();
  assert.equal((await reading).inspectionSuperseded,true);await runtime.stop();
});

test('traffic gate start resets persisted blocked mode, hold journals before RPC and keeps the same TUN, resume is explicit', async t => {
  const f=await fixture(t);let runtime, held=false;
  runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,setCoreTrafficBlocked:async(api,blocked)=>{
    if(blocked){const saved=JSON.parse(await readFile(path.join(f.root,'.proxy-manager','active.json'),'utf8'));assert.equal(saved.trafficBlocked,true);assert.equal(saved.trafficBlockConfirmed,false);}
    held=blocked;f.state.trafficGate.push({blocked});return {blocked,confirmed:true};
  }}});
  const first=await runtime.start(config);assert.equal(held,false);assert.equal(first.trafficBlocked,false);
  const blocked=await runtime.holdTraffic({reason:'license-expired'});
  assert.equal(blocked.running,true);assert.equal(blocked.tunReady,true);assert.equal(blocked.trafficBlocked,true);assert.equal(blocked.trafficBlockConfirmed,true);
  assert.equal(blocked.sessionId,first.sessionId);assert.equal(f.state.stopCalls.length,0);assert.equal(f.state.spawns.length,1);
  const resumed=await runtime.resumeTraffic();assert.equal(resumed.trafficBlocked,false);assert.equal(resumed.sessionId,first.sessionId);
  assert.deepEqual(f.state.trafficGate.map(item=>item.blocked),[false,true,false]);await runtime.stop();
});

test('a failed traffic hold preserves durable intent and the TUN without claiming confirmed blocking', async t => {
  const f=await fixture(t);let fail=false;
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,setCoreTrafficBlocked:async(api,blocked)=>{
    if(fail)throw new Error('synthetic RPC failure');return {blocked,confirmed:true};
  }}});
  await runtime.start(config);fail=true;
  await assert.rejects(runtime.holdTraffic({reason:'license-expired'}),{code:'CORE_TRAFFIC_GATE_FAILED'});
  const status=await runtime.status();assert.equal(status.running,true);assert.equal(status.trafficBlocked,true);assert.equal(status.trafficBlockConfirmed,false);assert.equal(f.state.stopCalls.length,0);
  const saved=JSON.parse(await readFile(path.join(f.root,'.proxy-manager','active.json'),'utf8'));assert.equal(saved.trafficBlocked,true);assert.equal(saved.trafficBlockConfirmed,false);
  await runtime.stop();
});

test('resume failure retains blocked intent, stays unconfirmed and never stops the owned TUN', async t => {
  const f=await fixture(t);let failResume=false;
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,setCoreTrafficBlocked:async(api,blocked)=>{
    if(failResume&&!blocked)throw new Error('controlled resume failure');return {blocked,confirmed:true};
  }}});
  await runtime.start(config);await runtime.holdTraffic();failResume=true;
  await assert.rejects(runtime.resumeTraffic(),{code:'CORE_TRAFFIC_GATE_FAILED'});
  const status=await runtime.status();assert.equal(status.running,true);assert.equal(status.trafficBlocked,true);assert.equal(status.trafficBlockConfirmed,false);assert.equal(f.state.stopCalls.length,0);
  await runtime.stop();
});

test('a hold queued during resume inspects the resulting session and cannot be lost as mutation-pending',async t=>{
  const f=await fixture(t);let delayResume=false,entered,release;
  const waiting=new Promise(done=>{entered=done;}),held=new Promise(done=>{release=done;});
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,setCoreTrafficBlocked:async(api,blocked)=>{
    if(delayResume&&!blocked){entered();await held;}f.state.trafficGate.push({blocked});return {blocked,confirmed:true};
  }}});
  await runtime.start(config);await runtime.holdTraffic();delayResume=true;
  const resume=runtime.resumeTraffic();await waiting;const block=runtime.holdTraffic({reason:'license-expired'});release();
  await resume;const blocked=await block;assert.equal(blocked.trafficBlocked,true);assert.equal(blocked.trafficBlockConfirmed,true);assert.equal(f.state.stopCalls.length,0);await runtime.stop();
});

test('lost TUN routes or a reused owner identity cannot resume a retained block',async t=>{
  const f=await fixture(t);let ready=true;
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,inspectTun:async()=>({exists:Boolean(f.state.process),ready:Boolean(f.state.process)&&ready})}});
  await runtime.start(config);await runtime.holdTraffic();ready=false;
  await assert.rejects(runtime.resumeTraffic(),{code:'TUN_NOT_READY'});assert.equal((await runtime.status()).trafficBlocked,true);
  ready=true;f.state.owner.createdAt='2025-01-01T00:00:00.000Z';
  await assert.rejects(runtime.resumeTraffic(),{code:'CORE_OWNERSHIP_UNVERIFIED'});assert.equal(f.state.stopCalls.length,0);
  f.state.owner={...f.state.process,listenAddresses:['127.0.0.1']};await runtime.stop();
});

test('recovery reapplies durable blocking with the private API and rejects a missing DNS gate', async t => {
  const f=await fixture(t);await f.runtime.start(config);await f.runtime.holdTraffic();await f.runtime.dispose();simulateControllerRestart(f.state);
  const before=f.state.trafficGate.length,recovered=createProxyRuntime(f.options),status=await recovered.status();
  assert.equal(status.trafficBlocked,true);assert.equal(status.trafficBlockConfirmed,true);assert.equal(f.state.trafficGate[before].blocked,true);await recovered.dispose();
  const manifestPath=path.join(f.root,'.proxy-manager','active.json'),saved=JSON.parse(await readFile(manifestPath,'utf8'));
  const renderedPath=f.state.spawns[0].args[2],rendered=JSON.parse(await readFile(renderedPath,'utf8'));rendered.dns.rules.shift();
  const contents=JSON.stringify(rendered);saved.renderedHash=createHash('sha256').update(contents).digest('hex');await writeFile(renderedPath,contents);await writeFile(manifestPath,JSON.stringify(saved));
  simulateControllerRestart(f.state);await assert.rejects(createProxyRuntime(f.options).status(),{code:'PROXY_STATE_INVALID'});assert.equal(f.state.stopCalls.length,0);
});

test('canceling a hanging readonly preflight returns promptly without native core or secret reads', async t => {
  const f=await fixture(t),signal=new AbortController();let entered;
  const waiting=new Promise(done=>{entered=done;});
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,inspectExternalVpnTun:async()=>{entered();return new Promise(()=>{});}}});
  const starting=runtime.start({config,mode:'tun',signal:signal.signal});await waiting;signal.abort();
  await assert.rejects(starting,{code:'CONNECTION_CANCELED'});assert.equal(f.state.spawns.length,0);assert.equal(f.state.readSecrets,0);
  assert.equal((await runtime.stop()).running,false);
});

test('canceling after creation records exact ownership, closes only that core and preserves a clean mapping for retry', async t => {
  const f=await fixture(t),signal=new AbortController();let cancel=true;
  const runtime=createProxyRuntime({...f.options,dependencies:{...f.dependencies,inspectProcess:async pid=>{
    const identity=await f.dependencies.inspectProcess(pid);if(pid===1234&&cancel){cancel=false;signal.abort();}return identity;
  }}});
  await assert.rejects(runtime.start({config,mode:'tun',signal:signal.signal}),{code:'CONNECTION_CANCELED'});
  assert.equal(f.state.stopCalls.length,1);assert.equal(f.state.process,null);
  const mapping=JSON.parse(await readFile(path.join(f.root,'.proxy-manager','fakeip-cache-v1','identity.json'),'utf8'));assert.equal(mapping.clean,true);
  await runtime.start({config,mode:'tun'});await runtime.stop();
});

test('batched ownership adapter retains identity, loopback and TUN guards with one call per inspection', async t => {
  let calls = 0, resultOverride = {};
  const f = await fixture(t, { inspectWindowsOwnedState: async input => {
    calls++; assert.equal(input.pid, f.state.process.pid); assert.equal(input.port, config.listen.port); assert.equal(input.tun, true);
    return { identity: { ...f.state.process }, owner: { ...f.state.owner }, tun: { exists: true, ready: true }, ...resultOverride };
  } });
  const started = await f.runtime.start(config);
  const owned = await f.runtime.inspectOwnedState();
  assert.equal(owned.tunReady, true); assert.equal(calls, 1);
  assert.equal(owned.sessionId, started.sessionId); assert.equal(owned.configHash, started.configHash); assert.equal(owned.vpnNodeHash, null);
  assert.equal(owned.protections.systemRouting, true); assert.equal(owned.protections.ipv6Captured, true);
  assert.deepEqual(owned.ownedInspection, { status: 'verified', reason: 'verified' });
  resultOverride = { owner: { ...f.state.owner, createdAt: '2025-01-01T00:00:00.000Z' } };
  const changed = await f.runtime.inspectOwnedState(); assert.equal(changed.running, false); assert.equal(calls, 2);
  assert.deepEqual(changed.ownedInspection, { status: 'not-ready', reason: 'listener-identity-mismatch' });
  resultOverride = { owner: { ...f.state.owner, listenAddresses: ['0.0.0.0'] } };
  const wildcard = await f.runtime.inspectOwnedState(); assert.equal(wildcard.running, false); assert.equal(calls, 3);
  assert.equal(wildcard.ownedInspection.reason, 'listener-not-loopback');
  resultOverride = { tun: { exists: true, ready: false } };
  const lost = await f.runtime.inspectOwnedState(); assert.equal(lost.running, true); assert.equal(lost.tunReady, false); assert.equal(calls, 4);
  assert.equal(lost.protections.systemRouting, false); assert.equal(lost.protections.ipv6Captured, false);
  assert.deepEqual(lost.ownedInspection, { status: 'not-ready', reason: 'tun-not-ready' });
  assert.deepEqual(Object.keys(lost.ownedInspection), ['status', 'reason'], 'inspection diagnostics expose no process or destination data');
});

test('batched TUN observations reject missing, truthy and contradictory readiness without stopping an owned core', async t => {
  let tun = { exists: true, ready: true };
  const f = await fixture(t, { inspectWindowsOwnedState: async () => ({ identity: { ...f.state.process }, owner: { ...f.state.owner }, tun }) });
  await f.runtime.start(config);
  for (const invalid of [undefined, {}, { exists: true }, { exists: true, ready: 'false' }, { exists: 'true', ready: true }, { exists: false, ready: true }]) {
    tun = invalid;
    await assert.rejects(f.runtime.inspectOwnedState(), { code: 'TUN_STATE_UNAVAILABLE' });
    assert.equal(f.state.stopCalls.length, 0);
  }
  tun = { exists: false, ready: false };
  const absent = await f.runtime.inspectOwnedState();
  assert.equal(absent.running, true); assert.equal(absent.tunReady, false); assert.equal(absent.protections.systemRouting, false);
  assert.deepEqual(absent.ownedInspection, { status: 'not-ready', reason: 'tun-absent' });
  tun = { exists: true, ready: true };
  assert.equal((await f.runtime.inspectOwnedState()).tunReady, true, 'a completed failed inspection is not cached');
  await f.runtime.stop();
});

test('individual TUN reads use the same strict contract in status, owned inspection and network lock admission', async t => {
  let invalid = false;
  const f = await fixture(t, { inspectTun: async () => invalid ? { exists: true, ready: 'true' } : ({ exists: Boolean(f.state.process), ready: Boolean(f.state.process) }) });
  await f.runtime.start(config); invalid = true;
  await assert.rejects(f.runtime.status({ force: true }), { code: 'TUN_STATE_UNAVAILABLE' });
  await assert.rejects(f.runtime.inspectOwnedState(), { code: 'TUN_STATE_UNAVAILABLE' });
  await assert.rejects(f.runtime.armNetworkLock(), { code: 'TUN_STATE_UNAVAILABLE' });
  assert.equal(f.state.stopCalls.length, 0); assert.equal(f.options.networkLock.snapshot().state, 'unlocked');
  invalid = false; await f.runtime.stop();
});

test('an invalid pre-start TUN observation is refused before credentials or a native core launch', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: false, ready: true }) });
  await assert.rejects(f.runtime.start(config), { code: 'TUN_STATE_UNAVAILABLE' });
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.spawns.length, 0);
});

test('owned adapter errors retain their original fixed code instead of becoming a false TUN-loss result', async t => {
  let broken = false;
  const original = Object.assign(new Error('synthetic read failure'), { code: 'PROCESS_QUERY_FAILED', diagnostic: { operation: 'owned-state', category: 'OperationTimeout' } });
  const f = await fixture(t, { inspectWindowsOwnedState: async () => {
    if (broken) throw original;
    return { identity: { ...f.state.process }, owner: { ...f.state.owner }, tun: { exists: true, ready: true } };
  } });
  await f.runtime.start(config); broken = true;
  await assert.rejects(f.runtime.inspectOwnedState(), cause => cause === original);
  assert.equal(f.state.stopCalls.length, 0); broken = false;
  assert.equal((await f.runtime.inspectOwnedState()).tunReady, true);
  await f.runtime.stop();
});

test('managed proxy lifecycle generates only the ISP route, verifies ownership, then removes private bundle', async t => {
  const { runtime, state, root, corePath } = await fixture(t);
  assert.equal((await runtime.status()).running, false);
  const loaded = await runtime.readConfig();
  assert.equal(JSON.stringify(loaded).includes('test-secret'), false);
  const started = await runtime.start(loaded);
  assert.equal(started.running, true); assert.equal(started.managed, true); assert.equal(started.mock, false);
  assert.equal(started.mode, 'tun'); assert.equal(started.tunReady, true);
  assert.equal(started.networkLock.state, 'unlocked');
  assert.equal(started.protections.killSwitch, false);
  assert.equal(started.configHash.length, 64);
  assert.equal(state.spawns.length, 1);
  assert.equal(state.spawns[0].file, corePath);
  assert.equal(state.spawns[0].args.length, 3);
  assert.match(state.spawns[0].args[2], /runtime test /);
  const rendered = JSON.parse(await readFile(state.spawns[0].args[2], 'utf8'));
  assert.deepEqual(rendered.outbounds.map(item => item.tag), ['isp-upstream', 'private-direct']);
  assert.equal(rendered.route.final, 'isp-upstream');
  assert.equal(rendered.inbounds[0].listen, '127.0.0.1');
  assert.equal(rendered.inbounds[1].type, 'tun');
  const manifestText = await readFile(path.join(root, '.proxy-manager', 'active.json'), 'utf8');
  assert.equal(manifestText.includes('test-secret'), false);
  assert.equal((await runtime.start(loaded)).running, true);
  assert.equal(state.spawns.length, 1, 'idempotent start never adopts or spawns a second process');
  assert.equal((await runtime.armNetworkLock()).networkLock.locked, true);
  assert.equal((await runtime.stop()).running, false);
  assert.equal((await runtime.networkLock.status()).locked, true, 'Stopping the proxy retains the persistent lock');
  assert.equal(state.stopCalls.length, 1);
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
  assert.deepEqual(await readdir(path.join(root, '.proxy-manager')), ['fakeip-cache-v1']);
});

test('an occupied port is rejected before credentials are read or any process is started', async t => {
  const { runtime, state } = await fixture(t);
  state.owner = { pid: 9999, createdAt: 'external', executable: 'C:\\external.exe', commandLine: 'external.exe', listenAddresses: ['127.0.0.1'] };
  await assert.rejects(runtime.start(config), { code: 'PROXY_PORT_IN_USE' });
  assert.equal(state.readSecrets, 0); assert.equal(state.spawns.length, 0); assert.equal(state.stopCalls.length, 0);
});

test('a new controller recovers only the exact recorded core identity and can stop it', async t => {
  const { runtime, state, options } = await fixture(t);
  await runtime.start(config); await runtime.dispose();
  simulateControllerRestart(state);
  const restarted = createProxyRuntime(options);
  assert.equal((await restarted.status()).running, true);
  assert.equal((await restarted.stop()).running, false);
  assert.equal(state.spawns.length, 1); assert.equal(state.stopCalls.length, 1);
});

test('legacy HTTP manifest recovery does not claim system TUN after the new default changes', async t => {
  const { runtime, options, root, state } = await fixture(t);
  await runtime.start({ mode: 'http', config }); await runtime.dispose();
  simulateControllerRestart(state);
  const manifestPath = path.join(root, '.proxy-manager', 'active.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.version = 1; delete manifest.transportMode;
  await writeFile(manifestPath, JSON.stringify(manifest));
  const restarted = createProxyRuntime(options);
  const status = await restarted.status();
  assert.equal(status.running, true); assert.equal(status.mode, 'http'); assert.equal(status.tunReady, false);
  await assert.rejects(restarted.start(config), { code: 'PROXY_ALREADY_MANAGED' });
  await restarted.stop();
});

test('version 2 manifests from an earlier release remain recoverable after the launch-intent upgrade', async t => {
  const { runtime, state, options, root } = await fixture(t);
  await runtime.start(config); await runtime.armNetworkLock(); await runtime.dispose();
  simulateControllerRestart(state);
  const manifestPath = path.join(root, '.proxy-manager', 'active.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.version = 2; delete manifest.phase; delete manifest.launch; delete manifest.networkLockRequired;
  await writeFile(manifestPath, JSON.stringify(manifest));
  const restarted = createProxyRuntime(options);
  assert.equal((await restarted.status()).running, true);
  await restarted.stop();
  assert.equal(state.stopCalls.length, 1);
  assert.equal((await restarted.networkLock.status()).locked, true);
});

test('recovered TUN with missing routes retains ownership so the controller can stop it', async t => {
  const { runtime, options, dependencies, state } = await fixture(t);
  await runtime.start({ mode: 'tun', config }); await runtime.dispose();
  simulateControllerRestart(state);
  const restarted = createProxyRuntime({ ...options, dependencies: { ...dependencies, inspectTun: async () => ({ exists: true, ready: false }) } });
  const status = await restarted.status();
  assert.equal(status.running, true); assert.equal(status.managed, true); assert.equal(status.tunReady, false);
  assert.equal((await restarted.stop()).running, false);
  assert.equal(state.stopCalls.length, 1);
});

test('recycled PID cannot be adopted or stopped and its runtime evidence is retained', async t => {
  const { runtime, state, root, options } = await fixture(t);
  await runtime.start(config); await runtime.dispose();
  simulateControllerRestart(state);
  state.process.createdAt = '2026-09-30T12:01:00.0000000Z';
  const restarted = createProxyRuntime(options);
  await assert.rejects(restarted.status(), { code: 'PROCESS_IDENTITY_MISMATCH' });
  await assert.rejects(restarted.stop(), { code: 'PROCESS_IDENTITY_MISMATCH' });
  assert.equal(state.stopCalls.length, 0);
  assert.ok((await readdir(root)).some(name => name.startsWith('.proxy-session-')));
});

test('asynchronous spawn errors are handled and scrubbed without killing another process', async t => {
  const { runtime, state, root } = await fixture(t, { spawn: () => {
    const child = new EventEmitter();
    queueMicrotask(() => child.emit('error', new Error('credentials test-secret')));
    return child;
  } });
  await assert.rejects(runtime.start(config), error => error.code === 'CORE_START_FAILED' && !error.message.includes('test-secret'));
  assert.equal(state.stopCalls.length, 0);
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
});

test('loopback ownership mismatch fails startup and stops only the newly owned core', async t => {
  let listenerCalls = 0;
  const f = await fixture(t, { listenerOwner: async port => port !== config.listen.port || ++listenerCalls === 1 ? null : { pid: 4321, executable: 'external.exe', createdAt: 'external', commandLine: 'external.exe', listenAddresses: ['127.0.0.1'] } });
  await assert.rejects(f.runtime.start(config), { code: 'PROXY_PORT_IN_USE' });
  assert.equal(f.state.stopCalls.length, 1);
  assert.equal(f.state.stopCalls[0].pid, 1234);
});

test('a failed start retains ownership and its bundle when the stop request returns before the core exits', async t => {
  const f = await fixture(t); let stopEffective = false;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listenerOwner: async () => null,
    stopProcess: async identity => { f.state.stopCalls.push(identity); if (stopEffective) { f.state.process = null; f.state.owner = null; } },
  } });
  await assert.rejects(runtime.start({ config, mode: 'http' }), { code: 'PROCESS_STOP_TIMEOUT' });
  assert.ok(f.state.process);
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.identity.pid, f.state.process.pid);
  assert.ok(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.equal((await runtime.status()).managed, true);
  stopEffective = true; await runtime.stop();
  assert.deepEqual(await readdir(f.root), ['.proxy-manager']);
});

test('mock lifecycle never calls process, network, elevation, file, config or credential dependencies', async () => {
  const forbidden = () => { throw new Error('mock must not perform I/O'); };
  const runtime = createProxyRuntime({ mock: true, networkLock: Object.fromEntries(['snapshot', 'status', 'arm', 'attachTun', 'unlock'].map(name => [name, forbidden])), dependencies: Object.fromEntries(['loadConfig', 'loadSecrets', 'readFile', 'lstat', 'createPrivateDirectory', 'writePrivate', 'spawn', 'inspectProcess', 'listenerOwner', 'stopProcess', 'isElevated', 'inspectTun', 'resolveUpstream', 'clearDnsCache'].map(name => [name, forbidden])) });
  assert.equal((await runtime.status()).running, false);
  const config = await runtime.readConfig();
  assert.deepEqual(config.probe.expectedExitIps, ['203.0.113.8']);
  config.upstream.host = 'gateway.provider.test';
  assert.equal((await runtime.start({ mode: 'tun', config })).mock, true);
  assert.equal((await runtime.status()).running, true);
  assert.equal((await runtime.status()).tunReady, true);
  assert.equal((await runtime.status()).protections.systemRouting, false);
  assert.equal((await runtime.armNetworkLock()).networkLock.locked, true);
  assert.equal((await runtime.stop()).running, false);
});

test('TUN requires elevation before credentials or processes are touched', async t => {
  const { runtime, state } = await fixture(t, { isElevated: async () => false });
  await assert.rejects(runtime.start({ mode: 'tun' }), { code: 'ADMIN_REQUIRED' });
  assert.equal(state.spawns.length, 0); assert.equal(state.readSecrets, 0);
});

test('TUN refuses to reuse an existing network interface', async t => {
  const { runtime, state } = await fixture(t, { inspectTun: async () => ({ exists: true, ready: false }) });
  await assert.rejects(runtime.start({ mode: 'tun' }), { code: 'TUN_INTERFACE_IN_USE' });
  assert.equal(state.spawns.length, 0); assert.equal(state.stopCalls.length, 0);
});

test('a loopback listener alone never counts as ready system TUN', async t => {
  const { runtime, state, root } = await fixture(t, { inspectTun: async () => ({ exists: false, ready: false }) });
  await assert.rejects(runtime.start({ mode: 'tun' }), { code: 'TUN_NOT_READY' });
  assert.equal(state.stopCalls.length, 1);
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
});

test('provider hostname resolves before TUN and never becomes an active local DNS fallback', async t => {
  let resolved = false;
  const { runtime, state } = await fixture(t, { resolveUpstream: async host => {
    assert.equal(host, 'gateway.provider.test'); resolved = true; return '192.0.2.44';
  } });
  const selected = structuredClone(config);
  selected.upstream.host = 'gateway.provider.test';
  selected.upstream.tls = { enabled: true, serverName: 'gateway.provider.test' };
  await runtime.start({ mode: 'tun', config: selected });
  assert.equal(resolved, true);
  const rendered = JSON.parse(await readFile(state.spawns[0].args[2], 'utf8'));
  assert.equal(rendered.outbounds[0].server, '192.0.2.44');
  assert.equal(rendered.outbounds[0].tls.server_name, 'gateway.provider.test');
  assert.ok(rendered.dns.servers.filter(server => !['fakeip', 'hosts'].includes(server.type)).every(server => server.detour === 'isp-upstream'));
  assert.deepEqual(rendered.dns.rules, [{ clash_mode: 'mc-blocked', action: 'reject' }, { domain: ['localhost'], action: 'route', server: 'callback-hosts' }, { query_type: ['A', 'AAAA'], action: 'route', server: 'isp-fakeip' }]);
});

test('failed provider resolution blocks TUN without exposing errors or reading credentials', async t => {
  const { runtime, state } = await fixture(t, { resolveUpstream: async () => { throw new Error('private resolver data'); } });
  const selected = { ...config, upstream: { ...config.upstream, host: 'gateway.provider.test' } };
  await assert.rejects(runtime.start({ config: selected, mode: 'tun' }), error => error.code === 'UPSTREAM_RESOLVE_FAILED' && !error.message.includes('private resolver'));
  assert.equal(state.readSecrets, 0); assert.equal(state.spawns.length, 0);
});

test('relay TUN only opens the physical relay endpoint and never resolves the ISP locally, including reconnect', async t => {
  const { runtime, state } = await fixture(t, {
    resolveUpstream: async () => { throw new Error('local ISP DNS must never occur'); },
    loadSecrets: async () => ({ ISP_USERNAME: 'test-user', ISP_PASSWORD: 'test-secret', ...relaySecrets }),
  });
  const selected = { ...config, upstream: { ...config.upstream, host: 'isp-at-relay.invalid' }, relay: relayFixture() };
  await runtime.start({ mode: 'tun', config: selected });
  await runtime.armNetworkLock();
  const rendered = JSON.parse(await readFile(state.spawns[0].args[2], 'utf8'));
  assert.equal(rendered.outbounds[0].server, 'isp-at-relay.invalid');
  assert.equal(rendered.outbounds[0].detour, 'relay-entry');
  const lock = await runtime.networkLock.status({ force: true });
  assert.deepEqual(lock.allowedEndpoint, { host: selected.relay.host, ip: selected.relay.host, port: 443 });
  assert.ok(rendered.dns.servers.filter(server => !['fakeip', 'hosts'].includes(server.type)).every(server => server.detour === 'isp-upstream'));
  assert.deepEqual(rendered.dns.rules, [{ clash_mode: 'mc-blocked', action: 'reject' }, { domain: ['localhost'], action: 'route', server: 'callback-hosts' }, { query_type: ['A', 'AAAA'], action: 'route', server: 'isp-fakeip' }]);
  await runtime.stop();
  await runtime.start({ mode: 'tun', config: selected });
  await runtime.stop();
  await assert.rejects(runtime.start({ mode: 'tun', config: { ...selected, relay: { ...selected.relay, host: '192.0.2.51' } } }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
});

test('reconnecting a locked provider hostname reuses its persisted IP without direct DNS', async t => {
  let resolves = 0;
  const { runtime } = await fixture(t, { resolveUpstream: async () => { resolves++; if (resolves > 1) throw new Error('direct DNS while locked'); return '192.0.2.44'; } });
  const selected = { ...config, upstream: { ...config.upstream, host: 'gateway.provider.test' } };
  await runtime.start({ mode: 'tun', config: selected });
  await runtime.armNetworkLock();
  await runtime.stop();
  assert.equal((await runtime.networkLock.status()).locked, true);
  await runtime.start({ mode: 'tun', config: selected });
  assert.equal(resolves, 1);
  await runtime.stop();
});

test('a missing persistent lock invalidates the readiness of a running TUN', async t => {
  const { runtime } = await fixture(t);
  await runtime.start({ mode: 'tun', config });
  await runtime.armNetworkLock();
  await runtime.networkLock.unlock({ confirm: true });
  const status = await runtime.status();
  assert.equal(status.running, true); assert.equal(status.tunReady, false);
  assert.equal(status.protections.systemRouting, false);
  await runtime.stop();
});

test('HTTP-only override does not require administrator, and switching mode requires stop', async t => {
  const { runtime, state } = await fixture(t, { isElevated: async () => { throw new Error('must not inspect elevation'); }, inspectTun: async () => { throw new Error('must not inspect TUN'); } });
  const started = await runtime.start({ mode: 'http', config });
  assert.equal(started.mode, 'http'); assert.equal(started.tunReady, false);
  assert.equal(started.protections.systemRouting, false);
  assert.equal(JSON.parse(await readFile(state.spawns[0].args[2], 'utf8')).inbounds.length, 1);
  await assert.rejects(runtime.start({ mode: 'tun', config }), { code: 'PROXY_ALREADY_MANAGED' });
});

test('VPN compatibility uses HTTP ISP hostname bootstrap without elevation, TUN activation, local DNS lookup or firewall mutation', async t => {
  const forbidden = () => assert.fail('compatibility must preserve external VPN networking');
  const f = await fixture(t, { isElevated: forbidden, inspectTun: async () => ({ exists: false, ready: false }), resolveUpstream: forbidden });
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...f.options.networkLock, arm: forbidden, attachTun: forbidden, unlock: forbidden } });
  const selected = compatConfig();
  const started = await runtime.start({ config: selected, mode: 'http' });
  assert.deepEqual(started.compatibility, { strategy: 'system' });
  assert.equal(started.tunReady, false); assert.equal(started.protections.systemRouting, false);
  const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.deepEqual(rendered.inbounds.map(item => item.type), ['http']);
  assert.equal(rendered.outbounds[0].server, 'provider.invalid');
  assert.equal(rendered.outbounds[0].domain_resolver, 'bootstrap');
  assert.deepEqual(rendered.dns.servers, [{ type: 'local', tag: 'bootstrap' }]);
  await runtime.stop();
});

test('VPN compatibility rejects only a remaining owned ProxyPilot TUN before secrets or core startup', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: true, ready: false }) });
  await assert.rejects(f.runtime.assertCompatibilityReady(), { code: 'TUN_INTERFACE_IN_USE' });
  await assert.rejects(f.runtime.start({ config: compatConfig(), mode: 'http' }), { code: 'TUN_INTERFACE_IN_USE' });
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.execs.length, 0); assert.equal(f.state.spawns.length, 0);
});

test('VPN compatibility rejects TUN, invalid local entries and every unresolved existing lock before secrets or core startup', async t => {
  const selected = compatConfig();
  const f = await fixture(t);
  await assert.rejects(f.runtime.start({ config: selected, mode: 'tun' }), { code: 'VPN_COMPAT_HTTP_ONLY' });
  for (const vpnProxy of [null, { type: 'http', host: '192.0.2.2', port: 8080 }, { type: 'http', host: '127.0.0.1', port: 17890 }]) {
    await assert.rejects(f.runtime.start({ config: selected, mode: 'http', vpnProxy }), { code: 'VPN_PROXY_INVALID' });
  }
  for (const lockState of ['locked', 'conflict', 'unknown', 'recovery-required']) {
    const runtime = createProxyRuntime({ ...f.options, networkLock: { snapshot: () => ({ state: lockState }), status: async () => ({ state: lockState, locked: lockState === 'locked' }), unlock: () => assert.fail('must not unlock') } });
    await assert.rejects(runtime.start({ config: selected, mode: 'http' }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  }
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.spawns.length, 0); assert.equal(f.state.execs.length, 0);
});

test('VPN entry survives managed recovery with the same rendered route and a new route requires explicit stop', async t => {
  for (const type of ['http', 'socks']) {
    const f = await fixture(t, { inspectTun: async () => ({ exists: false, ready: false }) });
    const selected = compatConfig();
    const vpnProxy = { type, host: '127.0.0.1', port: 17891 };
    const started = await f.runtime.start({ config: selected, mode: 'http', vpnProxy });
    assert.deepEqual(started.compatibility, { strategy: `${type}-proxy`, proxy: vpnProxy });
    const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
    assert.equal(rendered.outbounds[0].detour, 'vpn-entry'); assert.equal(rendered.dns, undefined);
    const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
    assert.deepEqual(manifest.vpnProxy, vpnProxy); assert.equal(manifest.config.vpnProxy, undefined);
    await f.runtime.dispose(); simulateControllerRestart(f.state);
    const recovered = createProxyRuntime(f.options);
    assert.deepEqual((await recovered.status()).compatibility, started.compatibility);
    await assert.rejects(recovered.start({ config: selected, mode: 'http', vpnProxy: { ...vpnProxy, port: 17892 } }), { code: 'PROXY_ALREADY_MANAGED' });
    assert.equal(f.state.spawns.length, 1); await recovered.stop();
  }
});

test('an older compatibility system-route manifest without VPN entry remains recoverable without credentials', async t => {
  const f = await fixture(t, { loadSecrets: async () => ({}) });
  const selected = compatConfig(); selected.upstream.auth = 'none';
  await f.runtime.start({ config: selected, mode: 'http' }); await f.runtime.dispose(); simulateControllerRestart(f.state);
  const recovered = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, loadSecrets: () => assert.fail('recovery cannot read current credentials') } });
  assert.deepEqual((await recovered.status()).compatibility, { strategy: 'system' });
  await recovered.stop();
});

test('tampering a saved VPN entry cannot redirect managed recovery even if generated bundle hash is intact', async t => {
  const f = await fixture(t);
  await f.runtime.start({ config: compatConfig(), mode: 'http', vpnProxy: { type: 'http', host: '127.0.0.1', port: 17891 } });
  await f.runtime.dispose(); simulateControllerRestart(f.state);
  const file = path.join(f.root, '.proxy-manager', 'active.json');
  const manifest = JSON.parse(await readFile(file, 'utf8')); manifest.vpnProxy.port = 17892;
  await writeFile(file, JSON.stringify(manifest));
  await assert.rejects(createProxyRuntime(f.options).status(), { code: 'PROXY_STATE_INVALID' });
  assert.equal(f.state.stopCalls.length, 0);
});

test('mock VPN compatibility reports its selected route without any native networking', async () => {
  const forbidden = () => assert.fail('mock must remain offline');
  const runtime = createProxyRuntime({ mock: true, dependencies: Object.fromEntries(['loadSecrets', 'isElevated', 'inspectTun', 'resolveUpstream', 'spawn'].map(key => [key, forbidden])) });
  const vpnProxy = { type: 'socks', host: '::1', port: 17891 };
  assert.deepEqual((await runtime.start({ config: compatConfig(), mode: 'http', vpnProxy })).compatibility, { strategy: 'socks-proxy', proxy: vpnProxy });
  assert.deepEqual((await runtime.status()).compatibility, { strategy: 'socks-proxy', proxy: vpnProxy });
});

test('imported Reality VPN resolves only its own server, keeps ISP detoured, binds its original hash and recovers without secrets or DNS', async t => {
  const resolutions = [];
  const f = await fixture(t, { inspectTun: async () => ({ exists: false }), isElevated: () => assert.fail('HTTP import must not request elevation'),
    resolveUpstream: async host => { resolutions.push(host); return '192.0.2.70'; } });
  const foreignCore = { pid: 9876, parentPid: 9875, executable: 'C:\\XVPN\\sing-box.exe', commandLine: 'synthetic unrelated external VPN', createdAt: '2026-09-30T11:00:00.0000000Z' };
  const preserveNetwork = () => assert.fail('import must never change firewall protection or external VPN networking');
  f.options.networkLock = { ...f.options.networkLock, arm: preserveNetwork, attachTun: preserveNetwork, unlock: preserveNetwork };
  f.options.dependencies.listProcesses = async () => [foreignCore, ...(f.state.process ? [{ ...f.state.process }] : [])];
  f.runtime = createProxyRuntime(f.options);
  const selected = { ...compatConfig(), connectionMode: 'vpn-import' }; const vpnNode = vpnOutbound();
  const started = await f.runtime.start({ config: selected, mode: 'http', vpnNode });
  assert.deepEqual(resolutions, ['vpn.private.invalid']); assert.deepEqual(started.compatibility, { strategy: 'imported-node' });
  assert.match(started.vpnNodeHash, /^[a-f0-9]{64}$/); assert.equal(started.tunReady, false); assert.equal(started.networkLock.state, 'unlocked');
  assert.doesNotMatch(JSON.stringify(started), /private\.invalid|11111111|public_key|test-secret/);
  const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.deepEqual(rendered.inbounds.map(inbound => inbound.type), ['http']);
  assert.deepEqual(rendered.outbounds.map(node => node.tag), ['isp-upstream', 'vpn-entry']);
  assert.equal(rendered.outbounds[0].server, 'provider.invalid'); assert.equal(rendered.outbounds[0].detour, 'vpn-entry'); assert.equal(rendered.dns, undefined);
  assert.equal(rendered.outbounds[1].server, '192.0.2.70'); assert.equal(rendered.outbounds[1].tls.server_name, 'localhost');
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.deepEqual(manifest.vpnNode, vpnNode); assert.equal(manifest.vpnNodeIp, '192.0.2.70'); assert.equal(manifest.vpnNodeHash, started.vpnNodeHash);
  assert.equal(manifest.networkLockRequired, false); assert.equal(manifest.vpnProxy, undefined);
  assert.equal((await f.runtime.start({ config: selected, mode: 'http', vpnNode })).vpnNodeHash, started.vpnNodeHash);
  assert.deepEqual(resolutions, ['vpn.private.invalid']); assert.equal(f.state.spawns.length, 1);
  await assert.rejects(f.runtime.start({ config: selected, mode: 'http', vpnNode: { ...vpnNode, server_port: 8443 } }), { code: 'PROXY_ALREADY_MANAGED' });
  await f.runtime.dispose(); simulateControllerRestart(f.state);
  const forbidden = () => assert.fail('recovery must use only saved validated imported node and process identity');
  const recovered = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, loadSecrets: forbidden, loadConfig: forbidden, resolveUpstream: forbidden } });
  const status = await recovered.status(); assert.equal(status.running, true); assert.equal(status.vpnNodeHash, started.vpnNodeHash);
  assert.deepEqual(status.compatibility, { strategy: 'imported-node' });
  await recovered.stop(); assert.equal(f.state.stopCalls.length, 1);
  assert.ok(f.state.stopCalls.every(identity => identity.pid !== foreignCore.pid), 'only the owned child may be stopped');
  assert.ok(f.state.execs.every(call => call.file === f.corePath && ['version', 'check'].includes(call.args[0])), 'no system proxy or network command is executed');
});

test('imported VPN rejects missing nodes, mixed local entries and unresolved lock before reading credentials or starting', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: false }) });
  const selected = { ...compatConfig(), connectionMode: 'vpn-import' }; const vpnNode = vpnOutbound();
  await assert.rejects(f.runtime.start({ config: selected, mode: 'http' }), { code: 'VPN_NODE_REQUIRED' });
  await assert.rejects(f.runtime.start({ config: selected, mode: 'http', vpnNode, vpnProxy: { type: 'http', host: '127.0.0.1', port: 1088 } }), { code: 'VPN_PROXY_INVALID' });
  await assert.rejects(f.runtime.start({ config: compatConfig(), mode: 'http', vpnNode }), { code: 'VPN_NODE_INVALID' });
  const locked = createProxyRuntime({ ...f.options, networkLock: { snapshot: () => ({ state: 'locked', locked: true }), status: async () => ({ state: 'locked', locked: true }) } });
  await assert.rejects(locked.start({ config: selected, mode: 'http', vpnNode }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  await assert.rejects(locked.start({ config: selected, mode: 'tun', vpnNode }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.spawns.length, 0); assert.equal(f.state.execs.length, 0);
});

test('imported VPN defaults to application HTTP routing even when the runtime default is TUN', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: false }),
    inspectExternalVpnTun: () => assert.fail('application import must permit external VPN'),
    isElevated: () => assert.fail('application import must not request elevation') });
  const selected = { ...compatConfig(), connectionMode: 'vpn-import' };
  const started = await f.runtime.start({ config: selected, vpnNode: vpnOutbound() });
  assert.equal(started.mode, 'http'); assert.equal(started.tunReady, false); assert.equal(started.protections.systemRouting, false);
  const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.deepEqual(rendered.inbounds.map(inbound => inbound.type), ['http']);
  await f.runtime.stop();
});

test('imported explicit global TUN pins only the VPN physical server, never arms a lock and recovers its exact route', async t => {
  const resolutions = []; let checks = 0;
  const f = await fixture(t, { resolveUpstream: async host => { resolutions.push(host); return '192.0.2.70'; },
    inspectExternalVpnTun: async () => { checks++; return { active: false, count: 0 }; } });
  const preserve = () => assert.fail('imported global must not mutate the firewall');
  f.options.networkLock = { ...f.options.networkLock, arm: preserve, attachTun: preserve, unlock: preserve };
  const runtime = createProxyRuntime(f.options);
  const selected = { ...compatConfig(), connectionMode: 'vpn-import' }; const vpnNode = vpnOutbound();
  const started = await runtime.start({ config: selected, mode: 'tun', vpnNode });
  assert.equal(started.mode, 'tun'); assert.equal(started.tunReady, true); assert.equal(started.protections.systemRouting, true);
  assert.equal(started.networkLock.state, 'unlocked'); assert.equal(started.protections.killSwitch, false);
  assert.equal(started.protections.persistentKillSwitch, true);
  assert.deepEqual(resolutions, ['vpn.private.invalid']); assert.equal(checks, 2);
  const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.equal(rendered.route.auto_detect_interface, true); assert.equal(rendered.outbounds[0].server, 'provider.invalid');
  assert.equal(rendered.outbounds[0].detour, 'vpn-entry'); assert.equal(rendered.outbounds[1].server, '192.0.2.70');
  assert.equal(rendered.outbounds[1].tls.server_name, 'localhost');
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.transportMode, 'tun'); assert.equal(manifest.networkLockRequired, false);
  assert.equal(manifest.vpnNodeHash, started.vpnNodeHash); assert.deepEqual(manifest.vpnNode, vpnNode);
  await runtime.dispose(); simulateControllerRestart(f.state);
  const recovered = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    loadSecrets: () => assert.fail('recovery cannot read current credentials'), resolveUpstream: () => assert.fail('recovery cannot repeat DNS') } });
  const status = await recovered.status(); assert.equal(status.running, true); assert.equal(status.mode, 'tun');
  assert.equal(status.tunReady, true); assert.equal(status.vpnNodeHash, started.vpnNodeHash);
  await recovered.stop(); assert.equal(f.state.stopCalls.length, 1);
});

test('global routing refuses active external VPN or unreadable state before credentials, DNS, spawn or cleanup', async t => {
  for (const connectionMode of ['relay', 'vpn-import']) {
    const f = await fixture(t, { inspectExternalVpnTun: async () => ({ active: true, count: 1 }),
      resolveUpstream: () => assert.fail('conflict must precede network resolution') });
    const selected = connectionMode === 'relay' ? config : { ...compatConfig(), connectionMode };
    await assert.rejects(f.runtime.assertGlobalReady(), { code: 'GLOBAL_VPN_CONFLICT' });
    await assert.rejects(f.runtime.start({ config: selected, mode: 'tun', ...(connectionMode === 'vpn-import' ? { vpnNode: vpnOutbound() } : {}) }), { code: 'GLOBAL_VPN_CONFLICT' });
    assert.equal(f.state.readSecrets, 0); assert.equal(f.state.execs.length, 0); assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
  }
  const f = await fixture(t, { inspectExternalVpnTun: async () => ({ active: false, count: 1 }) });
  await assert.rejects(f.runtime.start({ mode: 'tun', config }), { code: 'VPN_INTERFACE_STATE_UNAVAILABLE' });
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.spawns.length, 0);
});

test('external VPN appearing during core validation aborts global startup without spawning or stopping any process', async t => {
  let checks = 0;
  const f = await fixture(t, { inspectExternalVpnTun: async () => (++checks === 1 ? { active: false, count: 0 } : { active: true, count: 1 }) });
  await assert.rejects(f.runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'tun', vpnNode: vpnOutbound() }), { code: 'GLOBAL_VPN_CONFLICT' });
  assert.equal(checks, 2); assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
  assert.deepEqual(await readdir(f.root), ['.proxy-manager']);
  assert.deepEqual(await readdir(path.join(f.root, '.proxy-manager')), ['fakeip-cache-v1']);
});

test('imported global recovery rejects HTTP lock requirements or changed VPN node, address, SNI and routing mode', async t => {
  for (const mutate of [manifest => { manifest.transportMode = 'http'; manifest.networkLockRequired = true; }, manifest => { manifest.vpnNode.server_port = 8443; },
    manifest => { manifest.vpnNodeIp = '192.0.2.80'; }, manifest => { manifest.vpnNode.tls.server_name = 'other.invalid'; },
    manifest => { manifest.transportMode = 'http'; }]) {
    const f = await fixture(t);
    await f.runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'tun', vpnNode: vpnOutbound() });
    await f.runtime.dispose(); simulateControllerRestart(f.state);
    const file = path.join(f.root, '.proxy-manager', 'active.json'); const manifest = JSON.parse(await readFile(file, 'utf8'));
    mutate(manifest); await writeFile(file, JSON.stringify(manifest));
    await assert.rejects(createProxyRuntime(f.options).status(), { code: 'PROXY_STATE_INVALID' });
    assert.equal(f.state.stopCalls.length, 0);
  }
});

test('mock imported global lock remains explicitly simulated without native network access', async () => {
  const forbidden = () => assert.fail('mock global must remain offline');
  const runtime = createProxyRuntime({ mock: true, dependencies: Object.fromEntries(['loadSecrets', 'isElevated', 'inspectTun', 'inspectExternalVpnTun', 'resolveUpstream', 'spawn'].map(key => [key, forbidden])) });
  const result = await runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'tun', vpnNode: vpnOutbound() });
  assert.equal(result.mode, 'tun'); assert.equal(result.mock, true); assert.equal(result.protections.systemRouting, false);
  const locked = await runtime.armNetworkLock(); assert.equal(locked.networkLock.locked, true); assert.equal(locked.networkLock.mock, true);
  assert.equal(locked.protections.killSwitch, false);
});

test('imported TUN manually locks only its pinned physical node, preserves the requirement through recovery and reuses DNS pin', async t => {
  for (const protocol of ['TCP', 'UDP']) {
    const resolutions = [];
    const f = await fixture(t, { resolveUpstream: async host => { resolutions.push(host); return '192.0.2.70'; } });
    const selected = { ...compatConfig(), connectionMode: 'vpn-import' };
    const vpnNode = protocol === 'TCP' ? vpnOutbound() : { type: 'hysteria2', tag: 'vpn-entry', server: 'quic.private.invalid', server_port: 443,
      password: 'PRIVATE_PASSWORD', network: 'tcp', tls: { enabled: true, server_name: 'quic.private.invalid', insecure: false } };
    await f.runtime.start({ config: selected, mode: 'tun', vpnNode }); assert.equal((await f.runtime.networkLock.status()).locked, false);
    const armed = await f.runtime.armNetworkLock();
    assert.equal(armed.networkLock.locked, true); assert.equal(armed.tunReady, true);
    assert.deepEqual(armed.networkLock.allowedEndpoint, { host: vpnNode.server, ip: '192.0.2.70', port: vpnNode.server_port, protocol });
    assert.equal(armed.networkLock.binding, networkLockBinding({ upstream: selected.upstream, corePath: f.corePath, proxyPort: selected.listen.port,
      vpnNodeHash: armed.vpnNodeHash, physical: { host: vpnNode.server, port: vpnNode.server_port, protocol } }));
    assert.deepEqual(await f.runtime.resumeImportedNode({ config: selected, nodes: [{ index: 1, outbound: { ...vpnNode, server_port: 8443 } }, { index: 2, outbound: vpnNode }] }), vpnNode);
    await assert.rejects(f.runtime.resumeImportedNode({ config: selected, nodes: [{ outbound: { ...vpnNode, server_port: 8443 } }] }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
    const file = path.join(f.root, '.proxy-manager', 'active.json'); assert.equal(JSON.parse(await readFile(file, 'utf8')).networkLockRequired, true);
    await f.runtime.dispose(); simulateControllerRestart(f.state);
    const options = { ...f.options, dependencies: { ...f.dependencies, resolveUpstream: () => assert.fail('locked reconnect must reuse its pin') } };
    const recovered = createProxyRuntime(options); assert.equal((await recovered.status()).tunReady, true);
    await recovered.stop(); assert.equal((await recovered.networkLock.status()).locked, true);
    await recovered.start({ config: selected, mode: 'tun', vpnNode }); assert.equal(resolutions.length, 1);
    await recovered.stop();
    await assert.rejects(recovered.start({ config: selected, mode: 'http', vpnNode }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
    await assert.rejects(recovered.start({ config: selected, mode: 'tun', vpnNode: { ...vpnNode, server_port: 8443 } }), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
    assert.equal(f.state.spawns.length, 2); assert.equal((await recovered.networkLock.status()).locked, true);
  }
});

test('an imported required lock removed after controller restart retains core ownership but cannot claim ready', async t => {
  const f = await fixture(t); const selected = { ...compatConfig(), connectionMode: 'vpn-import' };
  await f.runtime.start({ config: selected, mode: 'tun', vpnNode: vpnOutbound() }); await f.runtime.armNetworkLock(); await f.runtime.dispose(); simulateControllerRestart(f.state);
  const recovered = createProxyRuntime({ ...f.options, networkLock: createNetworkLockManager({ mock: true }) });
  const status = await recovered.status(); assert.equal(status.running, true); assert.equal(status.managed, true); assert.equal(status.tunReady, false);
  await recovered.stop(); assert.equal(f.state.stopCalls.length, 1);
});

test('imported QUIC nodes use managed HTTP ownership without a TCP preflight and preserve TLS identity through restart', async t => {
  for (const type of ['hysteria2', 'tuic']) {
    const requests = [];
    const f = await fixture(t, {
      inspectTun: async () => ({ exists: false }),
      isElevated: () => assert.fail('HTTP-only import must not request elevation'),
      resolveUpstream: async host => { requests.push(host); return '192.0.2.70'; },
    });
    const vpnNode = { type, tag: 'vpn-entry', server: 'quic.private.invalid', server_port: 443,
      password: 'PRIVATE_VPN_PASSWORD', network: 'tcp', tls: { enabled: true, server_name: 'quic.private.invalid', insecure: false },
      ...(type === 'tuic' ? { uuid: '11111111-2222-4333-8444-555555555555', congestion_control: 'bbr' } : {}),
    };
    const selected = { ...compatConfig(), connectionMode: 'vpn-import' };
    const result = await f.runtime.start({ config: selected, mode: 'http', vpnNode });
    const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
    assert.deepEqual(requests, ['quic.private.invalid']);
    assert.deepEqual(rendered.outbounds.map(item => item.tag), ['isp-upstream', 'vpn-entry']);
    assert.equal(rendered.outbounds[0].server, 'provider.invalid');
    assert.equal(rendered.outbounds[0].detour, 'vpn-entry');
    assert.equal(rendered.outbounds[1].server, '192.0.2.70');
    assert.equal(rendered.outbounds[1].tls.server_name, 'quic.private.invalid');
    assert.equal(rendered.inbounds.length, 1); assert.equal(rendered.dns, undefined);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_VPN_PASSWORD|quic\.private\.invalid|11111111/);
    await f.runtime.dispose(); simulateControllerRestart(f.state);
    const recovered = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
      loadSecrets: () => assert.fail('recovery must use the saved bundle'),
      resolveUpstream: () => assert.fail('recovery must reuse the pinned node address'),
    } });
    assert.equal((await recovered.status()).vpnNodeHash, result.vpnNodeHash);
    await recovered.stop(); assert.equal(f.state.stopCalls.length, 1);
  }
});

test('failed imported-node DNS stays redacted and cannot fall back directly to the ISP', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: false }), resolveUpstream: async () => { throw new Error('PRIVATE_DNS_OR_SERVER'); } });
  await assert.rejects(f.runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'http', vpnNode: vpnOutbound() }), cause => cause.code === 'VPN_NODE_RESOLVE_FAILED' && !cause.message.includes('PRIVATE_DNS_OR_SERVER'));
  assert.equal(f.state.readSecrets, 0); assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
});

test('tampering imported raw node, resolved address or node hash prevents managed recovery before process adoption', async t => {
  for (const mutate of [manifest => { manifest.vpnNode.server_port = 8443; }, manifest => { manifest.vpnNodeIp = '192.0.2.88'; }, manifest => { manifest.vpnNodeHash = '0'.repeat(64); }, manifest => { delete manifest.vpnNode; }]) {
    const f = await fixture(t, { inspectTun: async () => ({ exists: false }) });
    await f.runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'http', vpnNode: vpnOutbound() });
    await f.runtime.dispose(); simulateControllerRestart(f.state);
    const file = path.join(f.root, '.proxy-manager', 'active.json'); const manifest = JSON.parse(await readFile(file, 'utf8')); mutate(manifest);
    await writeFile(file, JSON.stringify(manifest));
    await assert.rejects(createProxyRuntime(f.options).status(), { code: 'PROXY_STATE_INVALID' }); assert.equal(f.state.stopCalls.length, 0);
  }
});

test('mock imported VPN exposes only its strategy and node hash without DNS or native access', async () => {
  const forbidden = () => assert.fail('mock import must remain offline');
  const runtime = createProxyRuntime({ mock: true, dependencies: Object.fromEntries(['loadSecrets', 'isElevated', 'inspectTun', 'resolveUpstream', 'spawn'].map(key => [key, forbidden])) });
  const result = await runtime.start({ config: { ...compatConfig(), connectionMode: 'vpn-import' }, mode: 'http', vpnNode: vpnOutbound() });
  assert.deepEqual(result.compatibility, { strategy: 'imported-node' }); assert.match(result.vpnNodeHash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(result), /private\.invalid|11111111|public_key/);
});

test('loss of observed TUN routes marks running protection unavailable', async t => {
  const f = await fixture(t);
  let healthy = true;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, inspectTun: async () => ({ exists: Boolean(f.state.process), ready: Boolean(f.state.process) && healthy }) } });
  await runtime.start({ mode: 'tun' });
  healthy = false;
  const status = await runtime.status();
  assert.equal(status.running, true); assert.equal(status.managed, true); assert.equal(status.tunReady, false); assert.equal(status.protections.systemRouting, false);
  await assert.rejects(runtime.start({ mode: 'tun' }), { code: 'TUN_NOT_READY' });
  assert.equal(f.state.stopCalls.length, 0, 'status is read-only');
  await runtime.stop();
});

test('empty expected exit blocks managed browser proxy startup', async t => {
  const { runtime, state } = await fixture(t);
  await assert.rejects(runtime.start({ ...config, probe: { ...config.probe, expectedExitIps: [] } }), { code: 'EXPECTED_EXIT_REQUIRED' });
  assert.equal(state.spawns.length, 0);
});

test('internal discovery accepts an unpinned config only for HTTP and bypasses native firewall dependencies', async t => {
  const f = await fixture(t, { isElevated: () => { throw new Error('unexpected elevation'); }, inspectTun: () => { throw new Error('unexpected TUN inspection'); } });
  const forbidden = () => { throw new Error('setup must not access persistent firewall'); };
  const runtime = createProxyRuntime({ ...f.options, setupDiscovery: true, networkLock: Object.fromEntries(['snapshot', 'status', 'arm', 'attachTun'].map(name => [name, forbidden])) });
  const selected = { ...config, probe: { ...config.probe, expectedExitIps: [] } };
  await assert.rejects(runtime.start({ mode: 'tun', config: selected }), { code: 'PROXY_SETUP_HTTP_ONLY' });
  const result = await runtime.start({ mode: 'http', config: selected });
  assert.equal(result.mode, 'http'); assert.equal(result.running, true);
  const rendered = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  assert.deepEqual(rendered.inbounds.map(inbound => inbound.type), ['http']);
  await runtime.stop();
  assert.throws(() => createProxyRuntime({ ...f.options, setupDiscovery: true, transportMode: 'tun' }), { code: 'PROXY_SETUP_HTTP_ONLY' });
});

test('unlock refuses an orphan TUN with no manifest or credentials read', async t => {
  const f = await fixture(t, { inspectTun: async () => ({ exists: true, ready: false }), loadConfig: () => { throw new Error('unexpected configuration read'); }, loadSecrets: () => { throw new Error('unexpected credentials read'); } });
  await assert.rejects(f.runtime.assertSafeToUnlock(), { code: 'TUN_INTERFACE_IN_USE' });
  assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
});

test('unlock requires owned core stop and mock unlock performs no native inspection', async t => {
  const f = await fixture(t);
  await f.runtime.start(config);
  await assert.rejects(f.runtime.assertSafeToUnlock(), { code: 'PROXY_STILL_RUNNING' });
  await f.runtime.stop();
  assert.deepEqual(await f.runtime.assertSafeToUnlock(), { safe: true });
  const mock = createProxyRuntime({ mock: true, dependencies: { inspectTun: () => { throw new Error('mock network inspection'); } } });
  assert.deepEqual(await mock.assertSafeToUnlock(), { safe: true });
  await mock.start();
  await assert.rejects(mock.assertSafeToUnlock(), { code: 'PROXY_STILL_RUNNING' });
});

test('a queued status superseded by stop performs no extra native read and cannot claim the old core is running', async t => {
  const { runtime, state } = await fixture(t);
  const started = runtime.start(config);
  const during = runtime.status();
  const stopped = runtime.stop();
  assert.equal((await started).running, true);
  const superseded = await during;
  assert.equal(superseded.running, false); assert.equal(superseded.inspectionSuperseded, true);
  assert.deepEqual(superseded.ownedInspection, { status: 'superseded', reason: 'session-changed' });
  assert.equal((await stopped).running, false);
  assert.equal(state.stopCalls.length, 1);
});

test('parallel status reads share only their current native inspection and a forced read never borrows an ordinary one', async t => {
  const f = await fixture(t); const base = f.options.networkLock;
  let inspections = 0; let release; let entered;
  const waiting = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  let hold = false;
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...base, status: async options => {
    inspections++; if (hold) { entered(); await gate; } return base.status(options);
  } } });
  await runtime.start(config); const before = inspections; hold = true;
  const reads = Array.from({ length: 8 }, () => runtime.status());
  assert.ok(reads.every(read => read === reads[0])); await waiting;
  const forced = runtime.status({ force: true }); assert.notEqual(forced, reads[0]);
  release(); await Promise.all([...reads, forced]);
  assert.equal(inspections, before + 2);
  await runtime.status(); assert.equal(inspections, before + 3, 'completed identity results are never cached');
  await runtime.stop();
});

test('slow firewall inspection does not block owned gateway identity checks or safe stop and cannot revive a stopped session', async t => {
  const f = await fixture(t); const base = f.options.networkLock;
  let release; let entered; let hold = false; let lockReads = 0; let identities = 0; let listeners = 0; let tuns = 0;
  const waiting = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...base, status: async options => {
    lockReads++; if (hold) { entered(); await gate; } return base.status(options);
  } }, dependencies: { ...f.dependencies,
    inspectProcess: async pid => { identities++; return f.dependencies.inspectProcess(pid); },
    listenerOwner: async port => { listeners++; return f.dependencies.listenerOwner(port); },
    inspectTun: async () => { tuns++; return f.dependencies.inspectTun(); },
  } });
  await runtime.start(config); hold = true; identities = listeners = tuns = 0;
  const inspection = runtime.status({ force: true }); await waiting;
  try {
    const checks = Array.from({ length: 8 }, () => runtime.inspectOwnedState());
    assert.ok(checks.every(check => check === checks[0])); assert.ok((await Promise.all(checks)).every(item => item.running && item.tunReady));
    assert.deepEqual([identities, listeners, tuns], [1, 1, 1]);
    const before = lockReads;
    const stopped = await runtime.stop(); assert.equal(stopped.running, false); assert.equal(lockReads, before);
    assert.equal(f.state.stopCalls.length, 1); assert.equal(f.state.process, null);
  } finally { release(); }
  const late = await inspection; assert.equal(late.running, false); assert.equal(late.inspectionSuperseded, true);
});

test('firewall inspection failure preserves its safe cause instead of reporting a lost TUN and never prevents owned stop', async t => {
  const f = await fixture(t); const base = f.options.networkLock; let broken = false; let reads = 0;
  const failedLock = { ...base.snapshot(), state: 'recovery-required', locked: false, inspectionFailed: true,
    errorCode: 'NETWORK_LOCK_TIMEOUT', diagnostic: { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout', secret: 'PRIVATE_UPSTREAM' } };
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...base,
    snapshot: () => broken ? failedLock : base.snapshot(),
    status: async options => { reads++; return broken ? failedLock : base.status(options); },
  } });
  await runtime.start(config); broken = true;
  await assert.rejects(runtime.status({ force: true }), cause => {
    assert.equal(cause.code, 'NETWORK_LOCK_TIMEOUT'); assert.equal(cause.diagnostic.operation, 'inspect');
    assert.doesNotMatch(JSON.stringify(cause.diagnostic), /PRIVATE_UPSTREAM|secret/); return true;
  });
  assert.equal((await runtime.inspectOwnedState()).running, false);
  const before = reads; const stopped = await runtime.stop();
  assert.equal(reads, before); assert.equal(stopped.networkLock.errorCode, 'NETWORK_LOCK_TIMEOUT');
  assert.equal(f.state.stopCalls.length, 1); assert.equal(stopped.networkLock.state, 'recovery-required');
});

test('an in-flight owned identity read is revoked as soon as a core mutation is queued', async t => {
  const f = await fixture(t); let hold = false; let release; let entered;
  const waiting = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, inspectProcess: async pid => {
    if (hold && pid !== process.pid) { entered(); await gate; } return f.dependencies.inspectProcess(pid);
  } } });
  await runtime.start(config); hold = true;
  const pending = runtime.inspectOwnedState(); await waiting; const stopped = runtime.stop();
  const during = await runtime.inspectOwnedState();
  assert.equal(during.running, false); assert.equal(during.inspectionSuperseded, true);
  assert.deepEqual(during.ownedInspection, { status: 'superseded', reason: 'mutation-pending' });
  release(); const late = await pending;
  assert.equal(late.running, false); assert.equal(late.inspectionSuperseded, true);
  assert.deepEqual(late.ownedInspection, { status: 'superseded', reason: 'session-changed' }); await stopped;
  assert.equal(f.state.stopCalls.length, 1);
});

test('a late firewall timeout after safe stop retains the original failure instead of reviving or relabelling the session', async t => {
  const f = await fixture(t); const base = f.options.networkLock; let hold = false; let failed = false; let entered; let release;
  const waiting = new Promise(resolve => { entered = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  const observedFailure = { ...base.snapshot(), state: 'recovery-required', locked: false, inspectionFailed: true, errorCode: 'NETWORK_LOCK_TIMEOUT',
    diagnostic: { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout' } };
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...base, snapshot: () => failed ? observedFailure : base.snapshot(), status: async options => {
    if (!hold) return base.status(options); entered(); await gate; failed = true; return observedFailure;
  } } });
  await runtime.start(config); hold = true;
  const pending = runtime.status({ force: true }); const outcome = pending.catch(cause => cause); await waiting;
  try { assert.equal((await runtime.stop()).running, false); } finally { release(); }
  const cause = await outcome; assert.equal(cause.code, 'NETWORK_LOCK_TIMEOUT'); assert.equal(cause.diagnostic.operation, 'inspect');
  assert.equal((await runtime.inspectOwnedState()).running, false); assert.equal(f.state.stopCalls.length, 1);
  assert.equal(failed, true, 'the failed policy observation remains available for explicit recovery');
});

test('configuration changes require stopping the old owned core', async t => {
  const { runtime, state } = await fixture(t);
  await runtime.start(config);
  const changed = { ...config, listen: { host: '127.0.0.1', port: 17891 } };
  await assert.rejects(runtime.start(changed), { code: 'PROXY_ALREADY_MANAGED' });
  assert.equal((await runtime.status()).port, 17890);
  assert.equal(state.spawns.length, 1); assert.equal(state.stopCalls.length, 0);
  await runtime.stop();
});

test('pinned core validation errors do not expose its captured stderr or secrets', async t => {
  const { runtime, state, root } = await fixture(t, { execFile: (_file, args, _options, callback) => {
    if (args[0] === 'version') callback(null, 'sing-box version 1.14.2\n');
    else callback(new Error('test-secret from sing-box stderr'), '', 'test-secret');
  } });
  await assert.rejects(runtime.start(config), error => error.code === 'CORE_CHECK_FAILED' && !error.message.includes('test-secret'));
  assert.equal(state.spawns.length, 0); assert.equal(state.stopCalls.length, 0);
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
});

test('an unpinned version is rejected before credentials are read', async t => {
  const { runtime, state } = await fixture(t, { execFile: (_file, _args, _options, callback) => callback(null, 'sing-box version 1.14.3\n') });
  await assert.rejects(runtime.start(config), { code: 'CORE_VERSION_INVALID' });
  assert.equal(state.readSecrets, 0); assert.equal(state.spawns.length, 0);
});

test('a missing core yields a setup-actionable error before credentials or processes are touched', async t => {
  const { runtime, state } = await fixture(t, { execFile: (_file, _args, _options, callback) => callback(Object.assign(new Error('private path'), { code: 'ENOENT' })) });
  await assert.rejects(runtime.start({ mode: 'http' }), error => error.code === 'CORE_NOT_FOUND' && !error.message.includes('private path'));
  assert.equal(state.readSecrets, 0); assert.equal(state.spawns.length, 0);
});

test('unexpected owned core exit clears stale persisted state and reports failure', async t => {
  const { state, root, options } = await fixture(t);
  const failures = [];
  const runtime = createProxyRuntime({ ...options, onFailure: error => failures.push(error.code) });
  await runtime.start(config);
  state.process = null; state.owner = null;
  assert.equal((await runtime.status()).running, false);
  assert.ok(failures.includes('PROXY_EXITED'));
  assert.equal(state.stopCalls.length, 0);
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
});

test('tampered manifest paths are never followed or used to stop any process', async t => {
  const { runtime, state, options, root } = await fixture(t);
  await runtime.start(config); await runtime.dispose();
  const manifestPath = path.join(root, '.proxy-manager', 'active.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.sessionId = '..\\..\\outside';
  await writeFile(manifestPath, JSON.stringify(manifest));
  await assert.rejects(createProxyRuntime(options).stop(), { code: 'PROXY_STATE_INVALID' });
  assert.equal(state.stopCalls.length, 0);
  assert.ok((await readdir(root)).some(name => name.startsWith('.proxy-session-')));
});

test('PID reuse after the owned process stops cannot cause a second kill or retain stale ownership', async t => {
  const { state, root, options, dependencies } = await fixture(t);
  const runtime = createProxyRuntime({ ...options, dependencies: { ...dependencies, stopProcess: async identity => {
    state.stopCalls.push(identity);
    state.process = { ...identity, createdAt: '2026-09-30T12:01:00.0000000Z', commandLine: 'external replacement' };
    state.owner = null;
    return { stopped: true };
  } } });
  await runtime.start(config);
  assert.equal((await runtime.stop()).running, false);
  assert.equal(state.stopCalls.length, 1);
  assert.equal(state.process.commandLine, 'external replacement');
  assert.deepEqual(await readdir(root), ['.proxy-manager']);
});

test('TUN clears DNS only once per fresh startup after owned listener and interface readiness', async t => {
  const f = await fixture(t); const stages = [];
  const runtime = createProxyRuntime({ ...f.options, onProgress: operation => stages.push(operation.stage), dependencies: { ...f.dependencies,
    clearDnsCache: async () => {
      assert.ok(f.state.process); assert.equal(f.state.owner.pid, f.state.process.pid);
      assert.equal((await f.dependencies.inspectTun()).ready, true);
      const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
      assert.equal(manifest.phase, 'active'); assert.equal(manifest.dnsCacheCleared, false);
      f.state.dnsClears++; return { cleared: true };
    },
  } });
  assert.equal((await runtime.start({ config, mode: 'tun' })).tunReady, true);
  assert.equal(JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8')).dnsCacheCleared, true);
  assert.ok(stages.indexOf('verifying-tun') < stages.indexOf('clearing-dns-cache'));
  await runtime.start({ config, mode: 'tun' }); await runtime.status({ force: true }); await runtime.inspectOwnedState();
  assert.equal(f.state.dnsClears, 1, 'status, gateway identity reads and idempotent starts never flush again');
  await runtime.dispose(); simulateControllerRestart(f.state);
  const restarted = createProxyRuntime(f.options);
  assert.equal((await restarted.status()).tunReady, true); assert.equal(f.state.dnsClears, 1, 'recovery never changes DNS');
  await restarted.stop(); assert.equal((await restarted.start({ config, mode: 'tun' })).tunReady, true);
  assert.equal(f.state.dnsClears, 2); await restarted.stop();
});

test('HTTP starts omit DNS startup state and never invoke the cache command', async t => {
  const f = await fixture(t, { clearDnsCache: async () => assert.fail('HTTP must not clear system DNS') });
  await f.runtime.start({ config, mode: 'http' });
  assert.equal(JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8')).dnsCacheCleared, undefined);
  await f.runtime.status(); await f.runtime.stop();
});

test('TUN startup without a ready owned listener or interface never clears DNS', async t => {
  for (const missing of ['listener', 'interface']) await t.test(missing, async t => {
    const f = await fixture(t, missing === 'listener' ? { listenerOwner: async () => null } : { inspectTun: async () => ({ exists: false, ready: false }) });
    await assert.rejects(f.runtime.start({ config, mode: 'tun' }), { code: 'TUN_NOT_READY' });
    assert.equal(f.state.dnsClears, 0); assert.equal(f.state.stopCalls.length, 1);
  });
});

test('DNS hook failure stops only the owned core, retains the persistent lock and emits a safe cause', async t => {
  for (const confirmation of [undefined, { cleared: false }, 'native-error']) await t.test(String(confirmation?.cleared ?? confirmation), async t => {
    const f = await fixture(t); const diagnostics = [];
    await f.options.networkLock.arm({ binding: networkLockBinding({ upstream: config.upstream, corePath: f.corePath, proxyPort: config.listen.port }),
      endpoint: { host: config.upstream.host, ip: config.upstream.host, port: config.upstream.port }, corePath: f.corePath });
    const runtime = createProxyRuntime({ ...f.options, onDiagnostic: event => diagnostics.push(event), dependencies: { ...f.dependencies,
      clearDnsCache: async () => { f.state.dnsClears++; if (confirmation === 'native-error') throw new Error('PRIVATE_DNS_FAILURE'); return confirmation; },
    } });
    await assert.rejects(runtime.start({ config, mode: 'tun' }), cause => cause.code === 'DNS_CACHE_CLEAR_FAILED' && !cause.message.includes('PRIVATE_DNS'));
    assert.equal(f.state.dnsClears, 1); assert.equal(f.state.stopCalls.length, 1); assert.equal(f.state.stopCalls[0].pid, 1234);
    assert.equal(runtime.networkLock.snapshot().locked, true); assert.equal((await runtime.status()).running, false);
    assert.ok(diagnostics.some(event => event.code === 'DNS_CACHE_CLEAR_FAILED' && event.operation === 'clearing-dns-cache'));
    assert.doesNotMatch(JSON.stringify(diagnostics), /PRIVATE_DNS|test-secret/);
    assert.deepEqual(await readdir(path.join(f.root, '.proxy-manager')), ['fakeip-cache-v1']);
  });
});

test('failed DNS startup with an incomplete stop remains unready after recovery and cannot arm a new lock', async t => {
  const f = await fixture(t); const diagnostics = [];
  const runtime = createProxyRuntime({ ...f.options, onDiagnostic: event => diagnostics.push(event), dependencies: { ...f.dependencies,
    clearDnsCache: async () => { f.state.dnsClears++; throw new Error('PRIVATE_DNS_FAILURE'); },
    stopProcess: async identity => { f.state.stopCalls.push(identity); },
  } });
  await assert.rejects(runtime.start({ config, mode: 'tun' }), { code: 'PROCESS_STOP_TIMEOUT' });
  assert.equal(diagnostics.some(event => event.code === 'DNS_CACHE_CLEAR_FAILED'), true);
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.dnsCacheCleared, false); assert.equal(manifest.identity.pid, 1234);
  await runtime.dispose(); simulateControllerRestart(f.state);
  const restarted = createProxyRuntime(f.options);
  const status = await restarted.status({ force: true });
  assert.equal(status.running, true); assert.equal(status.managed, true); assert.equal(status.tunReady, false);
  assert.equal(status.protections.systemRouting, false); assert.equal((await restarted.inspectOwnedState()).tunReady, false);
  await assert.rejects(restarted.armNetworkLock(), { code: 'DNS_CACHE_CLEAR_FAILED' });
  assert.equal(restarted.networkLock.snapshot().locked, false); assert.equal(f.state.dnsClears, 1);
  await restarted.stop(); assert.equal(f.state.stopCalls.at(-1).pid, 1234);
});

test('legacy TUN manifests without DNS startup metadata remain readable without clearing DNS', async t => {
  const f = await fixture(t); await f.runtime.start({ config, mode: 'tun' }); await f.runtime.dispose();
  const file = path.join(f.root, '.proxy-manager', 'active.json'); const manifest = JSON.parse(await readFile(file, 'utf8'));
  delete manifest.dnsCacheCleared; await writeFile(file, JSON.stringify(manifest)); simulateControllerRestart(f.state);
  const restarted = createProxyRuntime(f.options);
  assert.equal((await restarted.status()).tunReady, true); assert.equal(f.state.dnsClears, 1); await restarted.stop();
});

test('failed DNS completion commit and incomplete stop cannot promote in-memory or recovered TUN readiness', async t => {
  const f = await fixture(t);
  await f.options.networkLock.arm({ binding: networkLockBinding({ upstream: config.upstream, corePath: f.corePath, proxyPort: config.listen.port }),
    endpoint: { host: config.upstream.host, ip: config.upstream.host, port: config.upstream.port }, corePath: f.corePath });
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    writePrivate: async (file, contents) => {
      if (path.basename(file).startsWith('active-') && JSON.parse(contents).dnsCacheCleared === true) throw new Error('PRIVATE_COMMIT_ERROR');
      return f.dependencies.writePrivate(file, contents);
    },
    stopProcess: async identity => { f.state.stopCalls.push(identity); },
  } });
  await assert.rejects(runtime.start({ config, mode: 'tun' }), { code: 'PROCESS_STOP_TIMEOUT' });
  assert.equal(f.state.dnsClears, 1);
  assert.equal(JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8')).dnsCacheCleared, false);
  assert.equal((await runtime.status()).tunReady, false); assert.equal((await runtime.inspectOwnedState()).protections.systemRouting, false);
  assert.equal(runtime.networkLock.snapshot().locked, true);
  await runtime.dispose(); simulateControllerRestart(f.state);
  const restarted = createProxyRuntime(f.options);
  assert.equal((await restarted.status()).tunReady, false); assert.equal(f.state.dnsClears, 1);
  await restarted.stop(); assert.equal(restarted.networkLock.snapshot().locked, true);
});

test('a core exit during lock attachment prevents the startup DNS command', async t => {
  const f = await fixture(t);
  await f.options.networkLock.arm({ binding: networkLockBinding({ upstream: config.upstream, corePath: f.corePath, proxyPort: config.listen.port }),
    endpoint: { host: config.upstream.host, ip: config.upstream.host, port: config.upstream.port }, corePath: f.corePath });
  const attachTun = f.options.networkLock.attachTun;
  f.options.networkLock.attachTun = async () => {
    const lock = await attachTun(); f.state.process = null; f.state.owner = null; f.state.child.emit('exit', 1, null); return lock;
  };
  await assert.rejects(f.runtime.start({ config, mode: 'tun' }), { code: 'CORE_START_FAILED' });
  assert.equal(f.state.dnsClears, 0); assert.equal(f.runtime.networkLock.snapshot().locked, true);
});

test('invalid DNS startup metadata is refused before adopting or stopping a saved process', async t => {
  for (const [mode, flag] of [['tun', 'true'], ['tun', null], ['http', true]]) await t.test(`${mode}:${flag}`, async t => {
    const f = await fixture(t); await f.runtime.start({ config, mode }); await f.runtime.dispose();
    const file = path.join(f.root, '.proxy-manager', 'active.json'); const manifest = JSON.parse(await readFile(file, 'utf8'));
    manifest.dnsCacheCleared = flag; await writeFile(file, JSON.stringify(manifest)); simulateControllerRestart(f.state);
    await assert.rejects(createProxyRuntime(f.options).status(), { code: 'PROXY_STATE_INVALID' });
    assert.equal(f.state.stopCalls.length, 0);
  });
});

test('default DNS startup implementation uses the runtime injected execFile instead of a host command', async t => {
  const f = await fixture(t); const dependencies = { ...f.dependencies }; delete dependencies.clearDnsCache;
  let calls = 0;
  dependencies.execFile = (file, args, options, callback) => {
    if (file !== 'powershell.exe') return f.dependencies.execFile(file, args, options, callback);
    calls++; const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    assert.match(script, /Clear-DnsClientCache -ErrorAction Stop/); assert.equal(options.windowsHide, true);
    callback(null, '{"cleared":true}');
  };
  const runtime = createProxyRuntime({ ...f.options, dependencies });
  assert.equal((await runtime.start({ config, mode: 'tun' })).tunReady, true);
  await runtime.status({ force: true }); await runtime.stop(); assert.equal(calls, 1);
});

test('a core exit while DNS startup is pending cannot return TUN readiness', async t => {
  const f = await fixture(t);
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, clearDnsCache: async () => {
    f.state.process = null; f.state.owner = null; f.state.child.emit('exit', 1, null); return { cleared: true };
  } } });
  await assert.rejects(runtime.start({ config, mode: 'tun' }), { code: 'CORE_START_FAILED' });
  assert.equal((await runtime.status()).tunReady, false); assert.equal(f.state.stopCalls.length, 0);
});

async function interruptedLaunch(t) {
  const f = await fixture(t);
  await f.options.networkLock.arm({ binding: networkLockBinding({ upstream: config.upstream, corePath: f.corePath, proxyPort: config.listen.port }),
    endpoint: { host: config.upstream.host, ip: config.upstream.host, port: config.upstream.port }, corePath: f.corePath });
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    inspectProcess: async pid => {
      if (pid !== process.pid) throw new Error('simulated loss of identity query before child PID persistence');
      return f.dependencies.inspectProcess(pid);
    },
  } });
  await assert.rejects(runtime.start(config), { code: 'CORE_OWNERSHIP_UNVERIFIED' });
  const manifestPath = path.join(f.root, '.proxy-manager', 'active.json');
  const text = await readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(text);
  assert.equal(manifest.version, 3); assert.equal(manifest.phase, 'starting'); assert.equal(manifest.identity, null);
  assert.equal(text.includes('test-secret'), false);
  assert.equal(f.state.spawns.length, 1); assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await runtime.networkLock.status()).locked, true);
  await runtime.dispose();
  simulateControllerRestart(f.state);
  return { ...f, manifestPath, manifest };
}

test('the complete private launch intent is on disk before a detached core can exist', async t => {
  const f = await fixture(t);
  let intent;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    spawn: (...args) => {
      intent = JSON.parse(readFileSync(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
      assert.equal(intent.phase, 'starting'); assert.equal(intent.identity, null);
      assert.equal(intent.launch.parent.pid, process.pid);
      assert.equal(intent.launch.notAfter - intent.launch.notBefore, 60000);
      assert.equal(intent.renderedHash.length, 64);
      return f.dependencies.spawn(...args);
    },
  } });
  await runtime.start(config);
  const active = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(active.phase, 'active'); assert.deepEqual(active.launch, intent.launch);
  await runtime.stop();
});

test('restarting after the spawn-to-PID crash window recovers only that core and retains the lock', async t => {
  const f = await interruptedLaunch(t);
  const restarted = createProxyRuntime(f.options);
  const status = await restarted.status();
  assert.equal(status.running, true); assert.equal(status.managed, true);
  assert.equal(status.tunReady, false, 'uncompleted startup never claims that the TUN firewall binding was attached');
  assert.equal(f.state.spawns.length, 1, 'recovery never creates a replacement core');
  const saved = JSON.parse(await readFile(f.manifestPath, 'utf8'));
  assert.equal(saved.phase, 'active'); assert.equal(saved.identity.pid, f.state.process.pid);
  await assert.rejects(restarted.assertSafeToUnlock(), { code: 'PROXY_STILL_RUNNING' });
  assert.equal((await restarted.stop()).running, false);
  assert.equal(f.state.stopCalls.length, 1);
  assert.equal((await restarted.networkLock.status()).locked, true);
  assert.deepEqual(await restarted.assertSafeToUnlock(), { safe: true });
  assert.deepEqual(await readdir(f.root), ['.proxy-manager']);
});

test('interrupted launch recovery can stop its core before any listener or TUN is ready', async t => {
  const f = await interruptedLaunch(t);
  f.state.owner = null;
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    inspectTun: async () => ({ exists: false, ready: false }),
  } });
  const status = await restarted.status();
  assert.equal(status.running, false); assert.equal(status.managed, true);
  await restarted.stop();
  assert.equal(f.state.stopCalls.length, 1);
  assert.equal((await restarted.networkLock.status()).locked, true);
});

test('an intent with no surviving child is cleaned up without releasing the persistent lock', async t => {
  const f = await interruptedLaunch(t);
  f.state.process = null; f.state.owner = null;
  const restarted = createProxyRuntime(f.options);
  assert.equal((await restarted.status()).running, false);
  assert.equal((await restarted.networkLock.status()).locked, true);
  assert.equal(f.state.stopCalls.length, 0);
  assert.deepEqual(await readdir(f.root), ['.proxy-manager']);
});

test('same-name cores with another executable or config are never adopted or stopped', async t => {
  const f = await interruptedLaunch(t);
  const original = { ...f.state.process };
  const otherConfig = { ...original, pid: 5678, commandLine: original.commandLine.replace('sing-box.json', 'other.json') };
  const otherExecutable = { ...original, pid: 5679, executable: path.join(f.root, 'other', 'sing-box.exe') };
  f.state.process = null; f.state.owner = null;
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listProcesses: async () => [otherConfig, otherExecutable],
  } });
  assert.equal((await restarted.stop()).running, false);
  assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await restarted.networkLock.status()).locked, true);
});

test('an ambiguous interrupted launch preserves evidence and never guesses which core to stop', async t => {
  const f = await interruptedLaunch(t);
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listProcesses: async () => [{ ...f.state.process }, { ...f.state.process, pid: 5678 }],
  } });
  await assert.rejects(restarted.stop(), { code: 'CORE_OWNERSHIP_UNVERIFIED' });
  await assert.rejects(restarted.assertSafeToUnlock(), { code: 'CORE_OWNERSHIP_UNVERIFIED' });
  assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await restarted.networkLock.status()).locked, true);
  assert.equal(JSON.parse(await readFile(f.manifestPath, 'utf8')).phase, 'starting');
});

test('wrong parents and out-of-window creations cannot impersonate an interrupted launch', async t => {
  for (const changed of [{ parentPid: 987654 }, { createdAt: '2026-09-30T11:59:59.999Z' }, { createdAt: '2026-09-30T12:01:00.001Z' }]) {
    await t.test(JSON.stringify(changed), async t => {
      const f = await interruptedLaunch(t);
      Object.assign(f.state.process, changed);
      const restarted = createProxyRuntime(f.options);
      await assert.rejects(restarted.stop(), { code: 'PROCESS_IDENTITY_MISMATCH' });
      assert.equal(f.state.stopCalls.length, 0);
      assert.equal((await restarted.networkLock.status()).locked, true);
      assert.equal(JSON.parse(await readFile(f.manifestPath, 'utf8')).phase, 'starting');
    });
  }
});

test('PID reuse between candidate enumeration and identity recheck cannot cause adoption or a kill', async t => {
  const f = await interruptedLaunch(t);
  const candidate = { ...f.state.process };
  f.state.process.createdAt = '2026-09-30T12:00:01.0000000Z';
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listProcesses: async () => [candidate],
  } });
  await assert.rejects(restarted.stop(), { code: 'PROCESS_IDENTITY_MISMATCH' });
  assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await restarted.networkLock.status()).locked, true);
});

test('a reused parent PID created before the candidate is not accepted as the recorded controller', async t => {
  const f = await interruptedLaunch(t);
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    inspectProcess: async pid => {
      const identity = await f.dependencies.inspectProcess(pid);
      return pid === process.pid ? { ...identity, createdAt: '2026-09-30T11:59:59.9000000Z' } : identity;
    },
  } });
  await assert.rejects(restarted.stop(), { code: 'PROCESS_IDENTITY_MISMATCH' });
  assert.equal(f.state.stopCalls.length, 0);
});

test('changed rendered configuration blocks interrupted-launch recovery before process discovery', async t => {
  const f = await interruptedLaunch(t);
  await writeFile(f.state.spawns[0].args[2], '{}');
  let discovery = 0;
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listProcesses: async () => { discovery++; return [{ ...f.state.process }]; },
  } });
  await assert.rejects(restarted.stop(), { code: 'PROXY_STATE_INVALID' });
  assert.equal(discovery, 0); assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await restarted.networkLock.status()).locked, true);
});

test('failed process enumeration retains the launch intent and blocks ordinary network unlock', async t => {
  const f = await interruptedLaunch(t);
  const restarted = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listProcesses: async () => { throw Object.assign(new Error('Windows query unavailable'), { code: 'PROCESS_QUERY_FAILED' }); },
  } });
  await assert.rejects(restarted.assertSafeToUnlock(), { code: 'PROCESS_QUERY_FAILED' });
  assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await restarted.networkLock.status()).locked, true);
  assert.equal(JSON.parse(await readFile(f.manifestPath, 'utf8')).phase, 'starting');
});

test('a failed initial launch-intent commit prevents spawn and any new firewall policy', async t => {
  const f = await fixture(t, { writePrivate: async (file, contents) => {
    if (path.basename(file) === 'active.json') throw new Error('simulated disk failure');
    return writeFile(file, contents, { mode: 0o600, flag: 'wx' });
  } });
  await assert.rejects(f.runtime.start(config), { code: 'CORE_START_FAILED' });
  assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
  assert.equal((await f.runtime.networkLock.status()).locked, false);
});

test('a second controller cannot delete a live launch intent before the first controller spawns', async t => {
  const f = await fixture(t);
  let release, entered;
  const held = new Promise(resolve => { release = resolve; });
  const written = new Promise(resolve => { entered = resolve; });
  const first = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    writePrivate: async (file, contents) => {
      await f.dependencies.writePrivate(file, contents);
      if (path.basename(file) === 'active.json') { entered(); await held; }
    },
  } });
  const starting = first.start({ mode: 'http', config });
  await written;
  const second = createProxyRuntime(f.options);
  try {
    for (const action of [() => second.status(), () => second.stop(), () => second.assertSafeToUnlock()]) await assert.rejects(action(), { code: 'PROXY_CONTROLLER_ACTIVE' });
    const intent = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
    assert.equal(intent.phase, 'starting');
    assert.equal(f.state.spawns.length, 0); assert.equal(f.state.stopCalls.length, 0);
    assert.ok(await readFile(path.join(f.root, `.proxy-session-${intent.sessionId}`, 'sing-box.json'), 'utf8'));
  } finally { release(); }
  assert.equal((await starting).running, true);
  await first.stop();
});

test('a registered core awaiting readiness remains owned by its live starting controller', async t => {
  const f = await fixture(t);
  let release, entered;
  const held = new Promise(resolve => { release = resolve; });
  const registered = new Promise(resolve => { entered = resolve; });
  const first = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    listenerOwner: async port => { if (f.state.process) { entered(); await held; } return f.dependencies.listenerOwner(port); },
  } });
  const starting = first.start({ mode: 'http', config });
  await registered;
  const second = createProxyRuntime(f.options);
  try {
    assert.equal(JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8')).phase, 'active');
    await assert.rejects(second.status(), { code: 'PROXY_CONTROLLER_ACTIVE' });
    await assert.rejects(second.stop(), { code: 'PROXY_CONTROLLER_ACTIVE' });
    assert.equal(f.state.stopCalls.length, 0);
  } finally { release(); }
  assert.equal((await starting).running, true);
  await first.stop();
});

test('the recovering controller records its ownership so a third live controller cannot steal it', async t => {
  const f = await fixture(t);
  await f.runtime.start({ mode: 'http', config });
  await f.runtime.dispose();
  simulateControllerRestart(f.state);
  const second = createProxyRuntime(f.options);
  assert.equal((await second.status()).running, true);
  const third = createProxyRuntime(f.options);
  await assert.rejects(third.stop(), { code: 'PROXY_CONTROLLER_ACTIVE' });
  assert.equal(f.state.stopCalls.length, 0);
  await second.stop();
  assert.equal(f.state.stopCalls.length, 1);
});

test('concurrent TUN starts claim one manifest without arming policy and only its owner can manually arm', async t => {
  const f = await fixture(t);
  await f.runtime.status();
  const checks = [];
  let arms = 0;
  const options = { ...f.options, networkLock: { ...f.options.networkLock, arm: async input => { arms++; return f.options.networkLock.arm(input); } }, dependencies: { ...f.dependencies,
    execFile: (file, args, opts, callback) => {
      if (args[0] !== 'check') return f.dependencies.execFile(file, args, opts, callback);
      checks.push(callback);
      if (checks.length === 2) for (const checked of checks) checked(null, '');
    },
  } };
  const first = createProxyRuntime(options), second = createProxyRuntime(options);
  const results = await Promise.allSettled([first.start({ mode: 'tun', config }), second.start({ mode: 'tun', config })]);
  const winnerIndex = results.findIndex(result => result.status === 'fulfilled');
  assert.notEqual(winnerIndex, -1, JSON.stringify(results.map(result => ({ status: result.status, code: result.reason?.code }))));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results[1 - winnerIndex].reason.code, 'PROXY_CONTROLLER_ACTIVE');
  assert.equal(arms, 0, 'establishing a connection never arms firewall policy');
  await assert.rejects([first, second][1 - winnerIndex].armNetworkLock(), { code: 'PROXY_CONTROLLER_ACTIVE' });
  assert.equal((await [first, second][winnerIndex].armNetworkLock()).networkLock.locked, true);
  assert.equal(arms, 1, 'only the exclusive controller may manually arm firewall policy');
  assert.equal(f.state.spawns.length, 1); assert.equal(f.state.stopCalls.length, 0);
  const saved = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(saved.phase, 'active');
  assert.ok(await readFile(path.join(f.root, `.proxy-session-${saved.sessionId}`, 'sing-box.json'), 'utf8'));
  await [first, second][winnerIndex].stop();
});

test('slow manual firewall activation leaves the already running core launch window unchanged', async t => {
  const f = await fixture(t);
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...f.options.networkLock,
    arm: async input => { f.state.clock += 90000; return f.options.networkLock.arm(input); },
  } });
  assert.equal((await runtime.start(config)).running, true);
  const saved = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(saved.launch.notBefore, f.state.clock);
  assert.equal(saved.launch.notAfter - saved.launch.notBefore, 60000);
  assert.equal((await runtime.armNetworkLock()).networkLock.locked, true);
  const armed = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.deepEqual(armed.launch, saved.launch);
  await runtime.stop();
});

test('a transient identity query failure can recover the pending core in the same controller', async t => {
  const f = await fixture(t);
  let unavailable = true;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies,
    inspectProcess: async pid => {
      if (unavailable && pid !== process.pid) throw new Error('temporary query failure');
      return f.dependencies.inspectProcess(pid);
    },
  } });
  await assert.rejects(runtime.start(config), { code: 'CORE_OWNERSHIP_UNVERIFIED' });
  unavailable = false;
  await runtime.stop();
  assert.equal(f.state.spawns.length, 1); assert.equal(f.state.stopCalls.length, 1);
  assert.equal((await runtime.networkLock.status()).locked, false, 'fresh failed connections do not arm a lock');
  assert.deepEqual(await readdir(f.root), ['.proxy-manager']);
});

test('fresh TUN is ready with observed routes while firewall mutations wait for manual arm', async t => {
  const f = await fixture(t);
  const forbidden = () => { throw new Error('connection startup must not mutate firewall policy'); };
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...f.options.networkLock, arm: forbidden, attachTun: forbidden } });
  const started = await runtime.start({ mode: 'tun', config });
  assert.equal(started.networkLock.state, 'unlocked'); assert.equal(started.tunReady, true);
  assert.equal((await runtime.status()).protections.systemRouting, true);
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.networkLockRequired, false);
  await runtime.stop();
  assert.equal((await runtime.networkLock.status()).state, 'unlocked');
});

test('manual arm requires an owned TUN with live loopback listener and observed routes before mutation', async t => {
  const f = await fixture(t);
  await assert.rejects(f.runtime.armNetworkLock(), { code: 'PROXY_NOT_RUNNING' });
  await f.runtime.start({ mode: 'http', config });
  await assert.rejects(f.runtime.armNetworkLock(), { code: 'NETWORK_LOCK_TUN_REQUIRED' });
  await f.runtime.stop();
  let healthy = true;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, inspectTun: async () => ({ exists: Boolean(f.state.process), ready: healthy && Boolean(f.state.process) }) } });
  await runtime.start(config);
  healthy = false;
  await assert.rejects(runtime.armNetworkLock(), { code: 'TUN_NOT_READY' });
  healthy = true; f.state.owner = null;
  await assert.rejects(runtime.armNetworkLock(), { code: 'PROXY_NOT_RUNNING' });
  assert.equal((await runtime.networkLock.status()).state, 'unlocked');
  await runtime.stop();
  const external = createProxyRuntime({ ...f.options, mode: 'external' });
  await assert.rejects(external.armNetworkLock(), { code: 'NETWORK_LOCK_TUN_REQUIRED' });
});

test('manual arm pins the running core endpoint without rereading changed settings, credentials or DNS', async t => {
  let resolves = 0; let connected = false;
  const f = await fixture(t, {
    loadConfig: async () => { if (connected) throw new Error('changed current configuration must not be read'); return structuredClone(config); },
    resolveUpstream: async () => { if (connected) throw new Error('must reuse the running core IP'); resolves++; return '192.0.2.44'; },
  });
  const selected = { ...config, upstream: { ...config.upstream, host: 'provider.test' } };
  await f.runtime.start({ mode: 'tun', config: selected });
  connected = true;
  const armed = await f.runtime.armNetworkLock();
  assert.equal(armed.tunReady, true); assert.equal(armed.networkLock.tunAllowed, true);
  assert.deepEqual(armed.networkLock.allowedEndpoint, { host: 'provider.test', ip: '192.0.2.44', port: 8080 });
  assert.equal(resolves, 1); assert.equal(f.state.readSecrets, 1);
  assert.equal((await f.runtime.armNetworkLock()).networkLock.locked, true, 'manual arm is idempotent');
  await f.runtime.stop();
  assert.equal((await f.runtime.networkLock.status()).locked, true, 'stopping retains a manually enabled lock');
});

test('manual arm refuses changed generated core configuration before any firewall mutation', async t => {
  const f = await fixture(t);
  await f.runtime.start(config);
  await writeFile(f.state.spawns[0].args[2], '{}');
  await assert.rejects(f.runtime.armNetworkLock(), { code: 'PROXY_STATE_INVALID' });
  assert.equal((await f.runtime.networkLock.status()).state, 'unlocked');
  await f.runtime.stop();
});

test('manual arm saves the persistent protection requirement before mutation and keeps partial lock for explicit recovery', async t => {
  const f = await fixture(t);
  const runtime = createProxyRuntime({ ...f.options, networkLock: { ...f.options.networkLock,
    attachTun: async () => { throw Object.assign(new Error('simulated attachment failure'), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' }); },
  } });
  await runtime.start(config);
  await assert.rejects(runtime.armNetworkLock(), { code: 'NETWORK_LOCK_RECOVERY_REQUIRED' });
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.networkLockRequired, true);
  const status = await runtime.status();
  assert.equal(status.running, true); assert.equal(status.tunReady, false);
  assert.equal(status.networkLock.locked, true); assert.equal(status.networkLock.tunAllowed, false);
  await runtime.dispose(); simulateControllerRestart(f.state);
  const recovered = createProxyRuntime(f.options);
  assert.equal((await recovered.status()).tunReady, false);
  await recovered.stop();
  assert.equal((await recovered.networkLock.status()).locked, true);
});

test('a failed manual-arm manifest commit prevents firewall mutation', async t => {
  const f = await fixture(t, { writePrivate: async (file, contents) => {
    if (path.basename(file).startsWith('active-') && JSON.parse(contents).networkLockRequired) throw new Error('disk full');
    return writeFile(file, contents, { mode: 0o600, flag: 'wx' });
  } });
  await f.runtime.start(config);
  await assert.rejects(f.runtime.armNetworkLock(), /disk full/);
  assert.equal((await f.runtime.networkLock.status()).state, 'unlocked');
  assert.equal((await f.runtime.status()).tunReady, true);
  await f.runtime.stop();
});

test('paused lock cannot alter the owned manifest or stop the running TUN', async t => {
  const f = await fixture(t);
  const snapshot = () => ({ state: 'unlocked', locked: false, canArm: false });
  const runtime = createProxyRuntime({ ...f.options, networkLock: {
    canArm: false, snapshot, status: async () => snapshot(),
    arm: () => assert.fail('disabled lock must never mutate policy'),
    attachTun: () => assert.fail('disabled lock must never attach'), detachTun: async () => {},
  } });
  await runtime.start(config);
  const file = path.join(f.root, '.proxy-manager', 'active.json');
  const before = await readFile(file, 'utf8');
  await assert.rejects(runtime.armNetworkLock(), { code: 'NETWORK_LOCK_DISABLED' });
  assert.equal(await readFile(file, 'utf8'), before);
  const manifest = JSON.parse(await readFile(path.join(f.root, '.proxy-manager', 'active.json'), 'utf8'));
  assert.equal(manifest.networkLockRequired, false);
  const status = await runtime.status();
  assert.equal(status.running, true); assert.equal(status.tunReady, true);
  assert.equal(f.state.stopCalls.length, 0);
  await runtime.stop();
});

test('stderr and process exit yield fixed diagnostics without emitting provider, endpoint or credentials', async t => {
  const f = await fixture(t);
  const diagnostics = [];
  const runtime = createProxyRuntime({ ...f.options, onDiagnostic: event => diagnostics.push(event), dependencies: { ...f.dependencies,
    spawn: (...args) => {
      const child = f.dependencies.spawn(...args);
      child.stderr = new PassThrough();
      queueMicrotask(() => child.stderr.write('FATAL create tun: access denied user=test-user password=test-secret at 192.0.2.1'));
      return child;
    },
  } });
  await runtime.start(config);
  assert.equal(diagnostics[0].code, 'CORE_TUN_PERMISSION_DENIED');
  assert.equal(diagnostics[0].operation, 'core-start');
  f.state.child.stderr.write('\nTLS handshake failed with certificate error private=test-secret');
  assert.equal(diagnostics.at(-1).code, 'CORE_UPSTREAM_TLS_FAILED');
  assert.equal(diagnostics.at(-1).operation, 'core-runtime');
  const beforeEof = diagnostics.length;
  f.state.child.stderr.write('\nstream ended: EOF endpoint=private-host.invalid credential=test-secret');
  assert.equal(diagnostics.length, beforeEof);
  f.state.child.stderr.write('\nwsarecv: An existing connection was forcibly closed by the remote host endpoint=private-host.invalid credential=test-secret');
  assert.deepEqual(diagnostics.at(-1), { code: 'CORE_CONNECTION_RESET', operation: 'core-runtime', diagnostic: {} });
  const afterReset = diagnostics.length;
  f.state.child.stderr.write('\nread tcp private-host.invalid:443: connection reset by peer credential=test-secret');
  assert.equal(diagnostics.length, afterReset);
  f.state.child.emit('exit', 1, 'unexpected private signal');
  assert.deepEqual(diagnostics.at(-1), { code: 'CORE_PROCESS_EXITED', operation: 'core-exit', diagnostic: { exitCode: 1, signal: null } });
  assert.doesNotMatch(JSON.stringify(diagnostics), /test-user|test-secret|192\.0\.2\.1|private-host\.invalid|unexpected private signal/);
  await runtime.stop();
});

test('an explicit stop labels a late Windows child exit as stopped without a false failure', async t => {
  const f = await fixture(t); const diagnostics = []; const failures = []; let stopped = false;
  const runtime = createProxyRuntime({ ...f.options, onDiagnostic: event => diagnostics.push(event), onFailure: cause => failures.push(cause.code), dependencies: { ...f.dependencies,
    stopProcess: async identity => { const result = await f.dependencies.stopProcess(identity); stopped = true; return result; },
    inspectProcess: async pid => {
      if (stopped && pid === f.state.child.pid) {
        stopped = false;
        // The stop command returned already; the old transient stopping flag
        // is false when Windows delivers this delayed notification.
        f.state.child.emit('exit', 4294967295, null);
      }
      return f.dependencies.inspectProcess(pid);
    },
  } });
  await runtime.start({ config, mode: 'http' });
  assert.equal((await runtime.stop()).running, false);
  assert.deepEqual(diagnostics, [{ code: 'CORE_PROCESS_STOPPED', operation: 'core-stop', diagnostic: { exitCode: 4294967295, signal: null } }]);
  assert.deepEqual(failures, []);
});

test('a rejected stop withdraws intent and a later unexpected exit keeps its failure classification', async t => {
  const f = await fixture(t); const diagnostics = []; const failures = [];
  const runtime = createProxyRuntime({ ...f.options, onDiagnostic: event => diagnostics.push(event), onFailure: cause => failures.push(cause.code), dependencies: { ...f.dependencies,
    stopProcess: async () => { throw Object.assign(new Error('synthetic stop rejected'), { code: 'PROCESS_STOP_TIMEOUT' }); },
  } });
  await runtime.start({ config, mode: 'http' });
  await assert.rejects(runtime.stop(), { code: 'PROCESS_STOP_TIMEOUT' });
  f.state.child.emit('exit', 2, null); f.state.process = null; f.state.owner = null;
  assert.deepEqual(diagnostics, [{ code: 'CORE_PROCESS_EXITED', operation: 'core-exit', diagnostic: { exitCode: 2, signal: null } }]);
  assert.deepEqual(failures, ['PROXY_EXITED']);
  await runtime.stop();
});

test('a setup child exiting before readiness remains a startup failure and unexpected exit diagnostic', async t => {
  const f = await fixture(t); const diagnostics = []; const failures = [];
  const runtime = createProxyRuntime({ ...f.options, setupDiscovery: true, onDiagnostic: event => diagnostics.push(event), onFailure: cause => failures.push(cause.code), dependencies: { ...f.dependencies,
    spawn: (...args) => {
      const child = f.dependencies.spawn(...args);
      queueMicrotask(() => { child.exitCode = 1; f.state.process = null; f.state.owner = null; child.emit('exit', 1, null); });
      return child;
    },
  } });
  await assert.rejects(runtime.start({ config, mode: 'http' }), { code: 'CORE_START_FAILED' });
  assert.deepEqual(diagnostics, [{ code: 'CORE_PROCESS_EXITED', operation: 'core-exit', diagnostic: { exitCode: 1, signal: null } }]);
  assert.deepEqual(failures, ['PROXY_EXITED']);
});

test('persistent Fake-IP mapping survives stop, changed entry credentials and routing mode without a new namespace', async t => {
  const f = await fixture(t), selected = { ...compatConfig(), connectionMode: 'vpn-import' };
  const node = vpnOutbound();
  await f.runtime.start({ config: selected, mode: 'tun', vpnNode: node });
  const first = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  await writeFile(first.experimental.cache_file.path, 'fixture-existing-mapping');
  const firstSecret = first.experimental.clash_api.secret;
  await f.runtime.stop();
  await f.runtime.start({ config: { ...selected, listen: { ...selected.listen, port: 17891 } }, mode: 'tun', routingMode: 'global', vpnNode: { ...node, uuid: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' } });
  const second = JSON.parse(await readFile(f.state.spawns[1].args[2], 'utf8'));
  assert.deepEqual(second.experimental.cache_file, first.experimental.cache_file);
  assert.equal(await readFile(second.experimental.cache_file.path, 'utf8'), 'fixture-existing-mapping');
  assert.notEqual(second.experimental.clash_api.secret, firstSecret);
  assert.equal((await f.runtime.status()).routingMode, 'global');
  assert.equal(second.route.rules.some(rule => rule.type === 'logical'), false);
});

test('missing existing Fake-IP mapping is not silently recreated and unsafe cache paths prevent startup', async t => {
  const f = await fixture(t); await f.runtime.start(config);
  const generated = JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8'));
  await f.runtime.stop(); await rm(generated.experimental.cache_file.path);
  await assert.rejects(f.runtime.start(config), { code: 'FAKE_IP_CACHE_UNAVAILABLE' });
  assert.equal(f.state.spawns.length, 1);
  assert.equal(await readFile(path.join(f.root, '.proxy-manager', 'fakeip-cache-v1', 'identity.json'), 'utf8').then(JSON.parse).then(record => record.id), generated.experimental.cache_file.cache_id);
});

test('private cache identity cannot escape its runtime, and an independent runtime starts in its own private directory', async t => {
  const first = await fixture(t), second = await fixture(t); await first.runtime.start(config); await second.runtime.start(config);
  const firstRendered = JSON.parse(await readFile(first.state.spawns[0].args[2], 'utf8'));
  const secondRendered = JSON.parse(await readFile(second.state.spawns[0].args[2], 'utf8'));
  assert.notEqual(firstRendered.experimental.cache_file.path, secondRendered.experimental.cache_file.path);
  await first.runtime.dispose(); simulateControllerRestart(first.state);
  const file = path.join(first.root, '.proxy-manager', 'active.json'), saved = JSON.parse(await readFile(file, 'utf8'));
  saved.fakeIpCacheId = '../../other'; await writeFile(file, JSON.stringify(saved));
  await assert.rejects(createProxyRuntime(first.options).status(), { code: 'PROXY_STATE_INVALID' });
  assert.equal(first.state.stopCalls.length, 0);
});

test('older TUN records without API, cache or routing fields retain their exact previous renderer and recover as global', async t => {
  const f = await fixture(t), selected = { ...compatConfig(), connectionMode: 'vpn-import' };
  await f.runtime.start({ config: selected, mode: 'tun', vpnNode: vpnOutbound() }); await f.runtime.dispose();
  const file = path.join(f.root, '.proxy-manager', 'active.json'), saved = JSON.parse(await readFile(file, 'utf8'));
  const generatedPath = f.state.spawns[0].args[2], rendered = JSON.parse(await readFile(generatedPath, 'utf8'));
  delete rendered.experimental; rendered.route.rules = rendered.route.rules.filter(rule=>!rule.clash_mode).slice(0, 2);
  rendered.dns.rules = rendered.dns.rules.filter(rule => !rule.clash_mode&&rule.server !== 'callback-hosts');
  rendered.dns.servers = rendered.dns.servers.filter(server => server.tag !== 'callback-hosts');
  rendered.outbounds = rendered.outbounds.filter(outbound => outbound.tag !== 'private-direct');
  const contents = JSON.stringify(rendered); saved.renderedHash = createHash('sha256').update(contents).digest('hex');
  for (const key of ['coreApi', 'fakeIpCacheId', 'routingPolicyVersion', 'routingMode', 'routingApplicationPaths', 'consoleManaged', 'trafficGateVersion', 'trafficBlocked', 'trafficBlockConfirmed']) delete saved[key];
  await writeFile(generatedPath, contents); await writeFile(file, JSON.stringify(saved)); simulateControllerRestart(f.state);
  const restarted = createProxyRuntime(f.options), status = await restarted.status();
  assert.equal(status.running, true); assert.equal(status.routingMode, 'global'); assert.equal(status.coreObservation.available, false);
  assert.equal(status.dnsCompatibility.persistentFakeIp, false); assert.equal(f.state.dnsClears, 1);
  assert.equal((await restarted.connections()).status, 'unavailable');
});

test('observations authenticate owned core, share request reads and revoke results when stop changes the session', async t => {
  const f = await fixture(t); let calls = 0, finish;
  const held = new Promise(resolve => { finish = resolve; });
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, requestCoreConnections: async api => {
    assert.match(api.secret, /^[a-f0-9]{64}$/); calls++; await held;
    return { connections: [{ id: 'connection-1', chains: ['isp-upstream'], metadata: { type: 'tun/system-tun', host: 'api.anthropic.com', network: 'tcp' } }] };
  } } });
  const started = await runtime.start(config); assert.equal(started.coreObservation.available, true);
  assert.doesNotMatch(JSON.stringify(started), /secret|17991|external_controller/);
  const one = runtime.connections(), two = runtime.connections();
  await new Promise(resolve => setImmediate(resolve)); await runtime.stop(); finish();
  await assert.rejects(one, { code: 'SESSION_CHANGED' }); await assert.rejects(two, { code: 'SESSION_CHANGED' });
  assert.equal(calls, 1); assert.equal((await runtime.status()).coreObservation.observed, 0);
});

test('HTTP discovery and mocked connection observations perform no native API calls or fake-IP writes', async t => {
  const f = await fixture(t);
  const discovery = createProxyRuntime({ ...f.options, setupDiscovery: true, dependencies: { ...f.dependencies,
    allocateCoreApiPort: () => { throw new Error('unexpected allocation'); }, requestCoreConnections: () => { throw new Error('unexpected observation'); } } });
  await discovery.start({ config, mode: 'http' });
  assert.equal(JSON.parse(await readFile(f.state.spawns[0].args[2], 'utf8')).experimental, undefined);
  assert.equal((await discovery.connections()).status, 'unavailable');
  const mocked = createProxyRuntime({ mock: true, dependencies: { requestCoreConnections: () => { throw new Error('unexpected observation'); } } });
  assert.equal((await mocked.connections()).status, 'mocked');
});

test('routing modes and application path manifests are bound to recovery and cannot change a live route', async t => {
  const f = await fixture(t), selected = { ...compatConfig(), connectionMode: 'vpn-import' };
  await f.runtime.start({ config: selected, mode: 'tun', vpnNode: vpnOutbound(), applicationPaths: ['C:\\Trusted\\Claude.exe'] });
  assert.equal((await f.runtime.status()).routingMode, 'safe-rules');
  await assert.rejects(f.runtime.start({ config: selected, mode: 'tun', routingMode: 'global', vpnNode: vpnOutbound(), applicationPaths: ['C:\\Trusted\\Claude.exe'] }), { code: 'PROXY_ALREADY_MANAGED' });
  await f.runtime.dispose(); simulateControllerRestart(f.state);
  const file = path.join(f.root, '.proxy-manager', 'active.json'), saved = JSON.parse(await readFile(file, 'utf8'));
  saved.routingMode = 'global'; await writeFile(file, JSON.stringify(saved));
  await assert.rejects(createProxyRuntime(f.options).status(), { code: 'PROXY_STATE_INVALID' });
});

test('a failed normal Close stops only the owned core but retains dirty mapping until explicit recovery', async t => {
  const f = await fixture(t, { closeCore: async () => { throw new Error('synthetic normal close failed'); } });
  await f.runtime.start(config); await f.runtime.armNetworkLock();
  const cache = path.join(f.root, '.proxy-manager', 'fakeip-cache-v1');
  await writeFile(path.join(cache, 'mapping.db'), 'preserved-old-mapping');
  await f.runtime.stop();
  assert.equal(JSON.parse(await readFile(path.join(cache, 'identity.json'), 'utf8')).clean, false);
  await assert.rejects(f.runtime.start(config), { code: 'FAKEIP_CACHE_RECOVERY_REQUIRED' });
  assert.equal((await f.runtime.networkLock.status()).locked, true);
  assert.equal(f.state.spawns.length, 1);
  await assert.rejects(f.runtime.recoverFakeIpCache({ confirm: true }), { code: 'FAKEIP_CACHE_CONFIRM_REQUIRED' });
  const before = f.state.dnsClears;
  const result = await f.runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
  assert.deepEqual(result, { status: 'recovered', recovered: true, archived: true, mock: false, requiresReconnect: true });
  const record = JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8'));
  assert.equal(record.phase, 'complete'); assert.equal(f.state.dnsClears, before + 1);
  assert.equal(await readFile(path.join(cache, `archive-${record.archiveId}`, 'mapping.db'), 'utf8'), 'preserved-old-mapping');
  assert.equal(JSON.parse(await readFile(path.join(cache, `archive-${record.archiveId}`, 'identity.json'), 'utf8')).clean, false);
  assert.equal((await f.runtime.networkLock.status()).locked, true, 'cache recovery never unlocks the firewall');
  await f.runtime.start(config); assert.equal(f.state.spawns.length, 2);
  assert.equal(await readFile(path.join(cache, 'mapping.db'), 'utf8'), '');
});

test('DNS failure retains both originals and a pending cache journal, and retry is explicit', async t => {
  const f = await fixture(t); await f.runtime.start(config); await f.runtime.stop(); let succeeds = false;
  const cache = path.join(f.root, '.proxy-manager', 'fakeip-cache-v1');
  await writeFile(path.join(cache, 'mapping.db'), 'old-records');
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, clearDnsCache: async () => {
    f.state.dnsClears++; if (!succeeds) throw new Error('private error should never escape'); return { cleared: true };
  } } });
  await assert.rejects(runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'DNS_CACHE_CLEAR_FAILED' });
  assert.equal(await readFile(path.join(cache, 'mapping.db'), 'utf8'), 'old-records');
  assert.equal(JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8')).phase, 'prepared');
  await assert.rejects(runtime.start(config), { code: 'FAKEIP_CACHE_RECOVERY_REQUIRED' });
  succeeds = true; await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
  assert.equal(JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8')).phase, 'complete');
});

test('partial archive and final journal failures resume without overwriting originals or clearing DNS twice', async t => {
  for (const failure of ['identity-move', 'journal-commit']) {
    const f = await fixture(t); await f.runtime.start(config); await f.runtime.stop();
    const cache = path.join(f.root, '.proxy-manager', 'fakeip-cache-v1');
    await writeFile(path.join(cache, 'mapping.db'), 'important-old-map');
    let fails = true;
    const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, rename: async (source, target) => {
      if (fails && ((failure === 'identity-move' && path.basename(source) === 'identity.json') || (failure === 'journal-commit' && path.basename(target) === 'recovery.json' && JSON.parse(await readFile(source, 'utf8')).phase === 'complete'))) throw new Error('synthetic disk error');
      return f.dependencies.rename ? f.dependencies.rename(source, target) : (await import('node:fs/promises')).rename(source, target);
    } } });
    const before = f.state.dnsClears;
    await assert.rejects(runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'FAKEIP_CACHE_RECOVERY_FAILED' });
    const record = JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8'));
    assert.equal(record.phase, 'dns-cleared');
    assert.equal(await readFile(path.join(cache, `archive-${record.archiveId}`, 'mapping.db'), 'utf8'), 'important-old-map');
    await assert.rejects(runtime.start(config), { code: 'FAKEIP_CACHE_RECOVERY_REQUIRED' });
    fails = false; await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
    assert.equal(f.state.dnsClears, before + 1);
    assert.equal(JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8')).phase, 'complete');
    await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
    assert.equal(f.state.dnsClears, before + 1, 'already completed retry does not flush DNS again');
  }
});

test('cache recovery refuses active cores, foreign listeners, orphaned TUN and unsafe archives before DNS mutation', async t => {
  const f = await fixture(t); await f.runtime.start(config); const before = f.state.dnsClears;
  await assert.rejects(f.runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'PROXY_STILL_RUNNING' });
  assert.equal(f.state.dnsClears, before); await f.runtime.stop();
  f.state.owner = { pid: 9999, listenAddresses: ['127.0.0.1'] };
  await assert.rejects(f.runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'PROXY_PORT_IN_USE' });
  f.state.owner = null;
  const orphan = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, inspectTun: async () => ({ exists: true, ready: false }) } });
  await assert.rejects(orphan.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'TUN_INTERFACE_IN_USE' });
  const unsafe = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, lstat: async file => path.basename(file) === 'identity.json' ? { isFile: () => true, isSymbolicLink: () => true } : (await import('node:fs/promises')).lstat(file) } });
  await assert.rejects(unsafe.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'FAKE_IP_CACHE_UNAVAILABLE' });
  assert.equal(f.state.dnsClears, before);
});

test('mocked cache recovery requires attestations and performs no native or file operation', async () => {
  const forbidden = () => { throw new Error('unexpected native recovery'); };
  const runtime = createProxyRuntime({ mock: true, dependencies: Object.fromEntries(['inspectProcess','inspectTun','listProcesses','listenerOwner','clearDnsCache','loadConfig','lstat','readFile','writePrivate','rename'].map(key => [key, forbidden])) });
  await assert.rejects(runtime.recoverFakeIpCache({}), { code: 'FAKEIP_CACHE_CONFIRM_REQUIRED' });
  assert.deepEqual(await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { status: 'mocked', recovered: true, archived: false, mock: true, requiresReconnect: true });
});

test('normal stop helper errors are diagnostic only, while unexpected helper errors revoke the session', async t => {
  const f = await fixture(t), failures = [], diagnostics = [];
  const runtime = createProxyRuntime({ ...f.options, onFailure: cause => failures.push(cause.code), onDiagnostic: event => diagnostics.push(event), dependencies: { ...f.dependencies, closeCore: async (identity, { stopProcess }) => {
    f.state.child.emit('error', new Error('synthetic monitor ended')); await stopProcess(identity); return { closed: true, exitCode: 0 };
  } } });
  await runtime.start(config); await runtime.stop();
  assert.deepEqual(failures, []); assert.equal(diagnostics.at(-1).code, 'CORE_CONSOLE_CLOSE_FAILED');
  await runtime.start(config); f.state.child.emit('error', new Error('synthetic monitor failure'));
  assert.deepEqual(failures, ['CORE_CONSOLE_CLOSE_FAILED']);
});

test('clean mapping checksum refuses modified DB before native startup and explicit recovery preserves the damaged original', async t => {
  const f = await fixture(t); await f.runtime.start(config); await f.runtime.stop();
  const cache = path.join(f.root, '.proxy-manager', 'fakeip-cache-v1');
  const identity = JSON.parse(await readFile(path.join(cache, 'identity.json'), 'utf8'));
  assert.equal(identity.clean, true); assert.match(identity.dbHash, /^[a-f0-9]{64}$/);
  await writeFile(path.join(cache, 'mapping.db'), 'synthetic-corrupt-db');
  await assert.rejects(f.runtime.start(config), { code: 'FAKE_IP_CACHE_UNAVAILABLE' });
  assert.equal(f.state.spawns.length, 1);
  await f.runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
  const journal = JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8'));
  assert.equal(await readFile(path.join(cache, `archive-${journal.archiveId}`, 'mapping.db'), 'utf8'), 'synthetic-corrupt-db');
  await f.runtime.start(config); await f.runtime.stop();
});

test('new generation claim survives journal write failure, blocks startup and permits explicitly confirmed retry', async t => {
  const f = await fixture(t); await f.runtime.start(config); await f.runtime.stop();
  await f.runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
  await f.runtime.start(config); await f.runtime.stop();
  const cache = path.join(f.root, '.proxy-manager', 'fakeip-cache-v1');
  const old = JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8'));
  let fails = true;
  const runtime = createProxyRuntime({ ...f.options, dependencies: { ...f.dependencies, rename: async (source, target) => {
    if (fails && path.basename(target) === 'recovery.json') throw new Error('synthetic journal replacement failure');
    return (await import('node:fs/promises')).rename(source, target);
  } } });
  await assert.rejects(runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true }), { code: 'FAKEIP_CACHE_RECOVERY_FAILED' });
  assert.equal(JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8')).archiveId, old.archiveId);
  await assert.rejects(runtime.start(config), { code: 'FAKEIP_CACHE_RECOVERY_REQUIRED' });
  fails = false; const recovered = await runtime.recoverFakeIpCache({ confirm: true, applicationsClosed: true });
  assert.equal(recovered.archived, true);
  const current = JSON.parse(await readFile(path.join(cache, 'recovery.json'), 'utf8'));
  assert.notEqual(current.archiveId, old.archiveId); assert.notEqual(current.generation, old.generation);
  await runtime.start(config); await runtime.stop();
});
