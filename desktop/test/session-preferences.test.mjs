import test from 'node:test';
import assert from 'node:assert/strict';
import { createPreferenceWriter, preferredTakeoverMode, sessionPreferenceDefaults, connectionView } from '../../frontend/workspace-view.js';

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const tick = () => new Promise(resolve => setImmediate(resolve));

test('rapid changes persist complete snapshots strictly in user order', async () => {
  const first = deferred(), second = deferred(), calls = [], states = [];
  const writer = createPreferenceWriter({ request: payload => { calls.push(payload); return calls.length === 1 ? first.promise : second.promise; }, onState: state => states.push(state) });
  writer.hydrate({ ...sessionPreferenceDefaults, takeoverMode: 'smart' });
  const savingFirst = writer.write({ takeoverMode: 'application' });
  const savingSecond = writer.write({ takeoverMode: 'global', browser: 'edge' });
  await tick();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].takeoverMode, 'application');
  assert.equal(writer.dirty(), true);
  first.resolve({}); await savingFirst; await tick();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].takeoverMode, 'global');
  assert.equal(calls[1].browser, 'edge');
  assert.equal(calls[1].relayRoutingMode, 'global');
  assert.equal(states.includes('saved'), false);
  second.resolve({}); await writer.flush(); await savingSecond;
  assert.equal(writer.dirty(), false);
  assert.equal(states.at(-1), 'saved');
});

test('a failed save retains drafts, blocks flush, and a later edit retries every preference', async () => {
  const calls = [], failure = new Error('local service unavailable');
  const writer = createPreferenceWriter({ request: payload => { calls.push(payload); return calls.length === 1 ? Promise.reject(failure) : Promise.resolve({}); } });
  writer.hydrate({ ...sessionPreferenceDefaults, relayRoutingMode: 'smart' });
  await assert.rejects(writer.write({ takeoverMode: 'application', externalReport: true }), /unavailable/);
  await assert.rejects(writer.flush(), /unavailable/);
  writer.hydrate({ ...sessionPreferenceDefaults, takeoverMode: 'global' });
  assert.equal(writer.values().takeoverMode, 'application');
  assert.equal(writer.dirty(), true);
  await writer.write({ browser: 'edge' });
  assert.equal(calls[1].takeoverMode, 'application');
  assert.equal(calls[1].relayRoutingMode, 'smart');
  assert.equal(calls[1].externalReport, true);
  assert.equal(writer.dirty(), false);
});

test('delayed refresh responses cannot overwrite new preferences, even after the write succeeds', async () => {
  const pending = deferred();
  const writer = createPreferenceWriter({ request: () => pending.promise });
  writer.hydrate({ ...sessionPreferenceDefaults, browser: 'chrome' });
  const saving = writer.write({ browser: 'edge', autoOptimize: false });
  assert.equal(writer.hydrate({ ...sessionPreferenceDefaults }).browser, 'edge');
  pending.resolve({}); await saving;
  assert.equal(writer.hydrate({ ...sessionPreferenceDefaults }).autoOptimize, false);
  const reopened = createPreferenceWriter({ request: async () => ({}) });
  assert.equal(reopened.hydrate(writer.values()).browser, 'edge');
});

test('completion is explicit, reports stay opt-in, and confirmation fields are not part of session defaults', async () => {
  const calls = [], writer = createPreferenceWriter({ request: async payload => { calls.push(payload); return {}; } });
  await writer.write({ fresh: false });
  await writer.write({}, { completed: true });
  assert.equal(calls[0].externalReport, false);
  assert.equal(Object.hasOwn(calls[0], 'completed'), false);
  assert.equal(calls[1].completed, true);
  for (const key of ['vpnConfirmed', 'applicationsClosed', 'cleanupConfirmed']) assert.equal(Object.hasOwn(calls[1], key), false);
});

test('import and VPS remember separate choices, external VPN always selects HTTP', () => {
  const prefs = { takeoverMode: 'application', relayRoutingMode: 'smart' };
  assert.equal(preferredTakeoverMode('vpn-import', prefs), 'application');
  assert.equal(preferredTakeoverMode('relay', prefs), 'smart');
  assert.equal(preferredTakeoverMode('vpn-compat', prefs), 'application');
  assert.deepEqual(prefs, { takeoverMode: 'application', relayRoutingMode: 'smart' });
  assert.equal(preferredTakeoverMode('relay', { relayRoutingMode: 'application' }), 'global');
  assert.equal(preferredTakeoverMode('vpn-import', {}), 'global');
});

test('workspace planned scope uses saved mode but running scope uses the actual core', () => {
  const input = { status: { proxy: { running: false, routingMode: 'global' } }, configuration: { connectionMode: 'relay' }, targetMode: 'tun', targetRoutingMode: 'safe-rules' };
  assert.equal(connectionView(input).scope, '智能规则 TUN');
  assert.equal(connectionView({ ...input, configuration: { connectionMode: 'vpn-import' } }).scope, '智能规则 TUN');
  assert.equal(connectionView({ ...input, configuration: { connectionMode: 'vpn-compat' } }).scope, '显式 HTTP 代理');
  assert.equal(connectionView({ ...input, targetMode: 'http', configuration: { connectionMode: 'vpn-import' } }).scope, '显式 HTTP 代理');
  assert.equal(connectionView({ ...input, status: { proxy: { running: true, mode: 'tun', connectionMode: 'relay', routingMode: 'global' } } }).scope, '全局 TUN');
});
