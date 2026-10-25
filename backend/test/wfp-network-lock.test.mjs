import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, readFile, writeFile, readdir } from 'node:fs/promises';
import { createWfpNetworkLockManager } from '../src/wfp-network-lock.mjs';
import { UserError } from '../src/config.mjs';

const input = { binding: 'a'.repeat(64), endpoint: { host: 'ignored-node.example', ip: '192.0.2.9', port: 443, protocol: 'TCP' },
  corePath: path.resolve('test-only/sing-box.exe') };
const empty = () => ({ present: false, verified: true, serviceReady: false, bootProtected: false, tunCurrent: false, ownedFilterCount: 0 });
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function fixture(t, extra = {}) {
  const temporaryRoot = fileURLToPath(new URL('../../.cache/', import.meta.url));
  await mkdir(temporaryRoot, { recursive: true });
  const root = await mkdtemp(path.join(temporaryRoot, 'wfp-lock-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = path.join(root, 'lock'), calls = [];
  let state = empty(), time = 100000, luid = '123456', behavior = null, inspections = 0;
  const foreignPolicy = { profiles: ['Domain', 'Public'], foreignAllow: true, foreignBlock: true };
  const adapter = {
    inspect: async () => { inspections++; if (behavior === 'inspect-fails') throw new Error('private native failure'); return { ...structuredClone(state), tunCurrent: state.present && state.tunLuid === luid }; },
    apply: async request => {
      const journal = JSON.parse(await readFile(path.join(stateDir, 'journal.json'), 'utf8'));
      assert.equal(journal.version, 2); assert.equal(journal.engine, 'wfp');
      assert.equal(journal.id, request.id); assert.ok(['arming', 'attaching'].includes(journal.phase));
      calls.push({ operation: 'apply', request: structuredClone(request) });
      if (behavior === 'apply-before-commit') throw new UserError('NETWORK_LOCK_TIMEOUT', 'not committed');
      if (state.present && state.fingerprint !== request.expectedFingerprint) throw new UserError('NETWORK_LOCK_CONFLICT', 'CAS failed');
      const policy = { id: request.id, binding: request.binding, corePath: request.corePath, endpoint: request.endpoint, tunLuid: request.includeTun ? luid : null };
      state = { ...policy, present: true, verified: true, serviceReady: true, bootProtected: false, tunCurrent: true, ownedFilterCount: 12, fingerprint: digest(policy) };
      if (behavior === 'apply-after-commit') throw new UserError('NETWORK_LOCK_TIMEOUT', 'response lost');
      return structuredClone(state);
    },
    clear: async request => {
      const journal = JSON.parse(await readFile(path.join(stateDir, 'journal.json'), 'utf8'));
      assert.equal(journal.version, 2); assert.equal(journal.phase, 'unlocking'); assert.equal(journal.id, request.id);
      calls.push({ operation: 'clear', request: structuredClone(request) });
      assert.equal(request.id, state.id); assert.equal(request.expectedFingerprint, state.fingerprint);
      if (behavior === 'clear-before-commit') throw new UserError('NETWORK_LOCK_TIMEOUT', 'not committed');
      state = empty();
      if (behavior === 'clear-after-commit') throw new UserError('NETWORK_LOCK_TIMEOUT', 'response lost');
      return structuredClone(state);
    },
  };
  const options = { stateDir, adapter, now: () => time, dependencies: { createPrivateDirectory: value => mkdir(value), ...extra.dependencies } };
  return { options, root, stateDir, calls, foreignPolicy, manager: createWfpNetworkLockManager(options),
    get state() { return state; }, set state(value) { state = value; }, get inspections() { return inspections; },
    advance: ms => { time += ms; }, behavior: value => { behavior = value; }, setLuid: value => { luid = value; } };
}

test('manual activation journals before one complete WFP transaction and leaves foreign firewall policy alone', async t => {
  const f = await fixture(t);
  const original = structuredClone(f.foreignPolicy);
  const armed = await f.manager.arm(input);
  assert.equal(armed.locked, true); assert.equal(armed.tunAllowed, true); assert.equal(armed.engine, 'wfp');
  assert.equal(armed.bootProtected, false); assert.equal(armed.serviceReady, true);
  assert.equal(armed.allowedEndpoint.host, input.endpoint.host, 'runtime reconnect retains the validated pinned hostname');
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].request.includeTun, true);
  assert.equal(f.calls[0].request.tunAlias, 'ProxyPilot'); assert.equal(f.calls[0].request.expectedFingerprint, undefined);
  assert.deepEqual(f.calls[0].request.endpoint, { host: input.endpoint.host, ip: input.endpoint.ip, port: 443, protocol: 'TCP' });
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.equal(journal.phase, 'active'); assert.equal(journal.fingerprint, f.state.fingerprint);
  assert.ok(!('before' in journal)); assert.ok(!('rules' in journal));
  await assert.rejects(f.manager.unlock(), { code: 'CONFIRMATION_REQUIRED' });
  assert.equal(f.calls.length, 1, 'neither process exit nor missing confirmation implicitly removes the lock');
  assert.equal((await f.manager.unlock({ confirm: true })).state, 'unlocked');
  assert.equal(f.calls.length, 2); assert.equal(f.calls[1].operation, 'clear');
  assert.deepEqual(f.foreignPolicy, original);
});

test('status uses bounded cached observations and restart only reads owned rules', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const before = f.inspections;
  await f.manager.status(); await f.manager.status(); assert.equal(f.inspections, before);
  f.advance(3000); assert.equal((await f.manager.status()).locked, true); assert.equal(f.inspections, before + 1);
  f.advance(15001); assert.equal(f.manager.snapshot().locked, false);
  assert.equal(f.manager.snapshot().errorCode, 'NETWORK_LOCK_RECHECK_REQUIRED');
  const restarted = createWfpNetworkLockManager(f.options);
  assert.equal((await restarted.status()).locked, true); assert.equal(f.calls.length, 1);
  assert.equal((await restarted.reload()).locked, true); assert.equal(f.calls.length, 1);
});

test('lost apply and clear responses reconcile actual committed WFP state without duplicate writes', async t => {
  const f = await fixture(t); f.behavior('apply-after-commit');
  assert.equal((await f.manager.arm(input)).locked, true); assert.equal(f.calls.length, 1);
  f.behavior('clear-after-commit');
  assert.equal((await f.manager.unlock({ confirm: true })).state, 'unlocked'); assert.equal(f.calls.length, 2);
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.equal(journal.phase, 'unlocked'); assert.equal(journal.fingerprint, null);
});

test('failed initial activation rolls back only its journal after proven absence and never clears native rules', async t => {
  const f = await fixture(t); f.behavior('apply-before-commit');
  await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_TIMEOUT' });
  assert.equal(f.manager.snapshot().state, 'unlocked');
  assert.equal(f.manager.snapshot().absenceVerified, true); assert.equal(f.manager.snapshot().policyPresent, false);
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.equal(journal.phase, 'unlocked'); assert.equal(journal.fingerprint, null); assert.equal(journal.includeTun, false);
  f.behavior(null);
  assert.equal((await f.manager.unlock({ confirm: true })).state, 'unlocked');
  assert.equal(f.calls.length, 1, 'an empty namespace needs no native mutation');
});

test('an ambiguous initial apply timeout cannot roll back the journal without a readable empty namespace', async t => {
  const f = await fixture(t);
  const apply = f.options.adapter.apply;
  f.options.adapter.apply = async request => {
    f.behavior('apply-before-commit');
    try { return await apply(request); } finally { f.behavior('inspect-fails'); }
  };
  await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_TIMEOUT' });
  const journal = JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8'));
  assert.equal(journal.phase, 'arming'); assert.equal(f.manager.snapshot().absenceVerified, false);
  assert.equal(f.manager.snapshot().state, 'recovery-required'); assert.equal(f.calls.length, 1);
});

test('failed unlock retains lock and recovery record; retry uses a fresh fingerprint', async t => {
  const f = await fixture(t); await f.manager.arm(input); f.behavior('clear-before-commit');
  await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_TIMEOUT' });
  assert.equal(f.state.present, true); assert.equal(f.manager.snapshot().state, 'recovery-required');
  assert.equal(JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8')).phase, 'unlocking');
  f.behavior(null); assert.equal((await f.manager.unlock({ confirm: true })).state, 'unlocked');
});

test('owned orphan policy is recovered from native identity and journals explicit removal before clearing', async t => {
  for (const verified of [true, false]) {
    const f = await fixture(t); await f.manager.arm(input);
    await rm(path.join(f.stateDir, 'journal.json')); f.state = { ...f.state, verified };
    const restarted = createWfpNetworkLockManager(f.options);
    const current = await restarted.status({ force: true });
    assert.equal(current.locked, false); assert.equal(current.canUnlock, true);
    assert.equal((await restarted.unlock({ confirm: true })).state, 'unlocked');
    assert.equal(f.calls.length, 2); assert.equal(f.calls[1].operation, 'clear');
    assert.equal(JSON.parse(await readFile(path.join(f.stateDir, 'journal.json'), 'utf8')).phase, 'unlocked');
  }
});

test('owned metadata, changed endpoint, malformed or unreadable observations never create a false unlocked state', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  await assert.rejects(f.manager.arm({ ...input, endpoint: { ...input.endpoint, port: 8443 } }), { code: 'NETWORK_LOCK_ENDPOINT_CHANGED' });
  assert.equal(f.calls.length, 1);
  const original = structuredClone(f.state);
  f.state = { ...original, fingerprint: 'b'.repeat(64) };
  assert.equal((await f.manager.status({ force: true })).state, 'conflict');
  await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_CONFLICT' });
  assert.equal(f.calls.length, 1);
  f.state = { ...original, verified: false };
  assert.equal((await f.manager.status({ force: true })).state, 'recovery-required');
  assert.equal(f.manager.snapshot().locked, false);
  f.state = original; f.behavior('inspect-fails');
  const unreadable = await f.manager.status({ force: true });
  assert.equal(unreadable.state, 'recovery-required'); assert.equal(unreadable.locked, false);
  assert.equal(unreadable.observedAt, null); assert.equal(unreadable.verifiedAt, null);
  assert.equal(unreadable.absenceVerified, false); assert.equal(unreadable.policyPresent, false);
  assert.ok(!JSON.stringify(unreadable).includes('private native failure'));
  await assert.rejects(f.manager.unlock({ confirm: true }), { code: 'NETWORK_LOCK_INSPECTION_FAILED' });
  assert.equal(f.calls.length, 1);
});

test('TUN updates carry CAS ownership and one failure does not discard the existing policy', async t => {
  const f = await fixture(t); await f.manager.arm(input);
  const fingerprint = f.state.fingerprint;
  f.setLuid('654321'); await f.manager.attachTun();
  assert.equal(f.calls[1].request.expectedFingerprint, fingerprint); assert.equal(f.state.tunLuid, '654321');
  f.behavior('apply-before-commit');
  // Existing complete protection remains usable even if a redundant attachment
  // times out before commit. The helper readback is authoritative.
  assert.equal((await f.manager.attachTun()).locked, true);
  assert.equal(f.state.tunLuid, '654321'); assert.ok(f.calls.every(call => call.operation !== 'clear'));
  f.setLuid('777777');
  await assert.rejects(f.manager.attachTun(), { code: 'NETWORK_LOCK_TIMEOUT' });
  assert.equal(f.manager.snapshot().locked, true, 'old catch-all protection remains active');
  assert.equal(f.manager.snapshot().tunAllowed, false, 'a stale interface exception cannot authorize the new TUN');
});

test('legacy active journals require old recovery; restored v1 journals are archived before WFP replacement', async t => {
  const f = await fixture(t); await mkdir(f.stateDir);
  await writeFile(path.join(f.stateDir, 'journal.json'), JSON.stringify({ version: 1, phase: 'armed' }));
  await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_LEGACY_RECOVERY_REQUIRED' });
  assert.equal(f.inspections, 0); assert.deepEqual(f.calls, []);
  const restored = { version: 1, phase: 'unlocked', originalPolicy: 'retained legacy fixture' };
  await writeFile(path.join(f.stateDir, 'journal.json'), JSON.stringify(restored));
  await createWfpNetworkLockManager(f.options).arm(input);
  const archives = (await readdir(f.stateDir)).filter(name => /^legacy-v1-.*\.json$/.test(name));
  assert.equal(archives.length, 1);
  assert.deepEqual(JSON.parse(await readFile(path.join(f.stateDir, archives[0]), 'utf8')), restored);
});

test('invalid journals and failed journal writes are rejected before native mutations', async t => {
  for (const value of [null, false, [], { version: 2, engine: 'wfp', phase: 'active' }]) {
    const f = await fixture(t); await mkdir(f.stateDir);
    await writeFile(path.join(f.stateDir, 'journal.json'), JSON.stringify(value));
    await assert.rejects(f.manager.arm(input), { code: 'NETWORK_LOCK_STATE_INVALID' });
    assert.equal(f.inspections, 0); assert.deepEqual(f.calls, []);
  }
  const f = await fixture(t, { dependencies: { writePrivate: async () => { throw new Error('private write failed'); } } });
  await assert.rejects(f.manager.arm(input)); assert.deepEqual(f.calls, []); assert.equal(f.state.present, false);
});
