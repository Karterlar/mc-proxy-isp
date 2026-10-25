import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createNetworkLifecycle } from '../network-lifecycle.mjs';

const adapter = address => ({ Ethernet: [{ family: 'IPv4', address, cidr: `${address}/24`, mac: '00:11:22:33:44:55', internal: false }] });
function timers() {
  let id = 0; const tasks = new Map();
  return { setTimeout: (action, ms) => { tasks.set(++id, { action, ms, interval: false }); return id; }, clearTimeout: key => tasks.delete(key),
    setInterval: (action, ms) => { tasks.set(++id, { action, ms, interval: true }); return id; }, clearInterval: key => tasks.delete(key),
    run: ms => { for (const [key, item] of [...tasks]) if (item.ms === ms) { if (!item.interval) tasks.delete(key); item.action(); } },
    count: () => tasks.size };
}
const settle = async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); };
const stable = () => ({ networkLifecycle: { state: 'stable' } });

test('mock mode reads no host interfaces, power events or timers', () => {
  const forbidden = () => assert.fail('mock must not query the host');
  const monitor = createNetworkLifecycle({ mock: true, networkInterfaces: forbidden, powerMonitor: { on: forbidden }, setInterval: forbidden,
    controller: { suspendNetwork: forbidden, networkChanged: forbidden } });
  assert.deepEqual(monitor.status(), { enabled: false, phase: 'mock', errorCode: null }); monitor.stop();
});

test('suspend immediately revokes leases, repeated resume is debounced and stop removes all owned watchers', async () => {
  const clock = timers(), power = new EventEmitter(), events = [];
  const monitor = createNetworkLifecycle({ ...clock, powerMonitor: power, networkInterfaces: () => adapter('192.0.2.1'),
    controller: { suspendNetwork: () => events.push('invalidate'), networkChanged: async reason => { events.push(reason); return stable(); } } });
  power.emit('suspend'); assert.deepEqual(events, ['invalidate']); assert.equal(monitor.status().phase, 'suspended');
  power.emit('resume'); power.emit('resume'); assert.equal(events.filter(value => value === 'resume').length, 0);
  clock.run(2000); await settle(); assert.equal(events.filter(value => value === 'resume').length, 1);
  monitor.stop(); assert.equal(clock.count(), 0); assert.equal(power.listenerCount('resume'), 0); assert.equal(power.listenerCount('suspend'), 0);
  const before = events.length; power.emit('resume'); clock.run(15000); assert.equal(events.length, before);
});

test('adapter signature ignores loopback, owned TUN and enumeration order but detects a physical address change without exposing metadata', async () => {
  const clock = timers(), power = new EventEmitter(), events = []; let snapshot = adapter('192.0.2.1');
  const monitor = createNetworkLifecycle({ ...clock, powerMonitor: power, networkInterfaces: () => snapshot,
    controller: { suspendNetwork: () => events.push('invalidate'), networkChanged: async reason => { events.push(reason); return stable(); } } });
  snapshot = { ProxyPilot: [{ address: '172.19.0.1', internal: false }], Loopback: [{ address: '127.0.0.1', internal: false }], ...snapshot };
  clock.run(15000); clock.run(2000); await settle(); assert.deepEqual(events, []);
  snapshot = { ...snapshot, Ethernet: adapter('192.0.2.2').Ethernet }; clock.run(15000);
  assert.deepEqual(events, ['invalidate']); clock.run(2000); await settle(); assert.deepEqual(events, ['invalidate', 'adapter-change']);
  assert.doesNotMatch(JSON.stringify(monitor.status()), /192\.|172\.|00:11|address|signature/); monitor.stop();
});

test('network changes coalesce during pending verification and failures have no automatic retry', async () => {
  const clock = timers(), power = new EventEmitter(), reasons = [], errors = []; let release, snapshot = adapter('192.0.2.1');
  const first = new Promise(resolve => { release = resolve; });
  const monitor = createNetworkLifecycle({ ...clock, powerMonitor: power, networkInterfaces: () => snapshot, onFailure: event => errors.push(event),
    controller: { suspendNetwork: () => {}, networkChanged: async reason => { reasons.push(reason); if (reasons.length === 1) { await first; return stable(); } else throw new Error('PRIVATE_SYSTEM_DETAILS'); } } });
  power.emit('resume'); clock.run(2000); await settle(); assert.deepEqual(reasons, ['resume']);
  snapshot = adapter('192.0.2.2'); clock.run(15000); power.emit('resume'); clock.run(2000); await settle(); assert.deepEqual(reasons, ['resume']);
  release(); await settle(); assert.deepEqual(reasons, ['resume', 'resume']); await settle();
  assert.equal(monitor.status().errorCode, 'NETWORK_RECHECK_FAILED');
  clock.run(15000); clock.run(2000); await settle(); assert.equal(reasons.length, 2);
  assert.doesNotMatch(JSON.stringify(errors), /PRIVATE_|192\./); monitor.stop();
});

test('interface observation failure revokes once, stays explicit and recovering observation triggers one fresh check', async () => {
  const clock = timers(), events = []; let failed = true;
  const monitor = createNetworkLifecycle({ ...clock, powerMonitor: new EventEmitter(), networkInterfaces: () => { if (failed) throw new Error('PRIVATE_IP'); return adapter('192.0.2.1'); },
    controller: { suspendNetwork: () => events.push('invalidate'), networkChanged: async reason => { events.push(reason); return stable(); } } });
  assert.equal(monitor.status().errorCode, 'NETWORK_OBSERVATION_FAILED'); assert.deepEqual(events, ['invalidate']);
  clock.run(15000); assert.deepEqual(events, ['invalidate']);
  failed = false; clock.run(15000); clock.run(2000); await settle(); assert.deepEqual(events, ['invalidate', 'invalidate', 'adapter-change']); monitor.stop();
});

test('resolved unverified or unknown controller checks remain visibly failed without retrying or exposing values', async () => {
  for (const result of [{ networkLifecycle: { state: 'unverified' }, lastError: { code: 'SYSTEM_NETWORK_TIMEOUT', message: 'PRIVATE_IP' } }, undefined]) {
    const clock = timers(), power = new EventEmitter(), errors = []; let calls = 0;
    const monitor = createNetworkLifecycle({ ...clock, powerMonitor: power, networkInterfaces: () => adapter('192.0.2.1'), onFailure: event => errors.push(event),
      controller: { suspendNetwork: () => {}, networkChanged: async () => { calls++; return result; } } });
    power.emit('resume'); clock.run(2000); await settle();
    assert.deepEqual(monitor.status(), { enabled: true, phase: 'failed', errorCode: 'NETWORK_RECHECK_FAILED' });
    assert.deepEqual(errors, [{ code: 'NETWORK_RECHECK_FAILED', operation: 'network-lifecycle' }]);
    assert.doesNotMatch(JSON.stringify([monitor.status(), errors]), /PRIVATE_|192\./);
    clock.run(15000); clock.run(2000); await settle(); assert.equal(calls, 1); monitor.stop();
  }
});

test('a pending old check cannot overwrite an actual suspend or failed interface observation', async () => {
  for (const reason of ['suspend', 'observation-failure']) {
    const clock = timers(), power = new EventEmitter(); let release, unreadable = false;
    const held = new Promise(resolve => { release = resolve; });
    const monitor = createNetworkLifecycle({ ...clock, powerMonitor: power, networkInterfaces: () => { if (unreadable) throw new Error('PRIVATE_IP'); return adapter('192.0.2.1'); },
      controller: { suspendNetwork: () => {}, networkChanged: async () => { await held; return stable(); } } });
    power.emit('resume'); clock.run(2000); await settle(); assert.equal(monitor.status().phase, 'checking');
    if (reason === 'suspend') power.emit('suspend');
    else { unreadable = true; clock.run(15000); }
    release(); await settle();
    assert.equal(monitor.status().phase, reason === 'suspend' ? 'suspended' : 'failed');
    assert.equal(monitor.status().errorCode, reason === 'suspend' ? null : 'NETWORK_OBSERVATION_FAILED'); monitor.stop();
  }
});
