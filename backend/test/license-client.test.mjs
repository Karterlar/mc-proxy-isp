import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import tls from 'node:tls';
import https from 'node:https';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { createLicenseClient, requestLicense } from '../src/license-client.mjs';
import { signLicense, verifyDeviceRequest } from '../src/license-format.mjs';

const DAY = 24 * 60 * 60 * 1000;
const signing = generateKeyPairSync('ed25519');
const signingPem = signing.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = signing.publicKey.export({ type: 'spki', format: 'pem' });
const config = { version: 1, mode: 'required', serviceUrl: 'https://license.example.test', publicKeys: { test: publicPem } };
const start = Date.UTC(2026, 9, 6, 12, 0);
const HOUR = DAY / 24;
async function waitFor(predicate) {
  const deadline = Date.now() + 3000;
  while (!predicate()) {
    if (Date.now() > deadline) assert.fail('background job did not finish');
    await new Promise(resolve => setTimeout(resolve, 1));
  }
}

async function fixture(t, extra = {}) {
  const directory = await mkdtemp(path.join(import.meta.dirname, '.license-test-'));
  const clock = { value: start, monotonic: 0 };
  let identityReads = 0, ioReads = 0, requests = 0, scheduled;
  const options = { stateDir: path.join(directory, '.license'), config, now: () => clock.value,
    getDeviceIdentity: async () => { identityReads++; return 'windows-machine-1'; },
    request: async () => { requests++; throw new Error('network must be explicit'); },
    dependencies: { monotonic: () => clock.monotonic,
      createPrivateDirectory: target => mkdir(target, { mode: 0o700 }),
      readFile: (...args) => { ioReads++; return readFile(...args); },
      setTimeout: (callback, delay) => { scheduled = { callback, delay, cleared: false }; return scheduled; },
      clearTimeout: item => { item.cleared = true; },
    }, ...extra };
  if (extra.dependencies) options.dependencies = { monotonic: () => clock.monotonic,
    createPrivateDirectory: target => mkdir(target, { mode: 0o700 }),
    readFile: (...args) => { ioReads++; return readFile(...args); },
    setTimeout: (callback, delay) => { scheduled = { callback, delay, cleared: false }; return scheduled; },
    clearTimeout: item => { item.cleared = true; }, ...extra.dependencies };
  const client = createLicenseClient(options);
  t.after(async () => { await client.close(); await rm(directory, { recursive: true, force: true }); });
  await client.initialize();
  const claims = overrides => ({ version: 1, licenseId: randomUUID(), deviceId: client.status().deviceId,
    deviceKeyHash: client.status().deviceKeyHash, generation: 1, plan: 'isp-30d-single', status: 'active', issuedAt: clock.value,
    expiresAt: clock.value + 30 * DAY, offlineUntil: clock.value + 3 * DAY, ispExpiresAt: clock.value + 30 * DAY, vpsExpiresAt: null, ...overrides });
  const envelope = overrides => signLicense(claims(overrides), { privateKey: signingPem, keyId: 'test' });
  return { directory, client, clock, options, claims, envelope,
    counters: () => ({ identityReads, ioReads, requests }), timer: () => scheduled };
}

test('absent trusted config preserves development behavior without filesystem, device or networking', async () => {
  let calls = 0;
  const client = createLicenseClient({ getDeviceIdentity: () => { calls++; }, request: () => { calls++; } });
  assert.equal(client.assertAllowed().status, 'development');
  assert.equal((await client.initialize()).allowed, true);
  assert.equal(calls, 0); await client.close();
});

test('invalid required config fails closed; production HTTP cannot activate', async () => {
  for (const settings of [{ version: 1, mode: 'required' }, { ...config, serviceUrl: 'http://127.0.0.1:8080' }, { ...config, mode: 'renderer-selected' }]) {
    const client = createLicenseClient({ config: settings });
    assert.equal((await client.initialize()).status, 'error');
    assert.throws(() => client.assertAllowed(), { code: 'LICENSE_CONFIG_INVALID' });
    await client.close();
  }
});

test('required offline-only release imports signed licenses and never schedules or sends online requests', async t => {
  const f = await fixture(t, { config: { version: 1, mode: 'required', publicKeys: config.publicKeys } });
  assert.equal(f.client.status().onlineAvailable, false); assert.equal(f.timer(), undefined);
  assert.equal(verifyDeviceRequest(JSON.parse(f.client.deviceApplication())).request.action, 'offline');
  await f.client.importLicense(f.envelope()); assert.equal(f.client.assertAllowed().allowed, true);
  const before = f.counters();
  await assert.rejects(f.client.activate('activation_card_12345'), { code: 'LICENSE_ONLINE_UNAVAILABLE', status: 409 });
  await assert.rejects(f.client.refresh(), { code: 'LICENSE_ONLINE_UNAVAILABLE', status: 409 });
  assert.equal(f.client.refreshIfDue(), false); assert.equal(f.timer(), undefined);
  assert.deepEqual(f.counters(), before, 'disabled online operations cannot perform network or refresh journal IO');
  await f.client.close(); f.clock.value += 3 * DAY;
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.equal(restarted.status().status, 'offline-expired'); assert.equal(restarted.status().onlineAvailable, false);
  assert.equal(restarted.refreshIfDue(), false); assert.equal(f.timer(), undefined); assert.equal(f.counters().requests, 0);
});

test('offline device application is signed and activation needs no online request', async t => {
  const f = await fixture(t);
  assert.equal(f.client.status().status, 'unactivated');
  const application = verifyDeviceRequest(JSON.parse(f.client.deviceApplication({ card: 'never_put_card_in_offline_application' })));
  assert.equal(application.request.action, 'offline');
  assert.equal(application.request.deviceId, f.client.status().deviceId);
  assert.equal(application.deviceKeyHash, f.client.status().deviceKeyHash);
  assert.equal(Object.hasOwn(application.request, 'card'), false);
  const license = f.envelope();
  assert.equal((await f.client.importLicense(JSON.stringify(license))).allowed, true);
  const before = f.counters();
  for (let i = 0; i < 50; i++) { assert.equal(f.client.assertAllowed().allowed, true); f.client.status(); }
  assert.deepEqual(f.counters(), before, 'status and assertAllowed must never perform IO or requests');
  assert.equal(f.timer().delay, DAY);
  await f.client.close(); assert.equal(f.timer().cleared, true);
});

test('forged signature, unknown issuer and copied wrong-device license cannot replace a valid token', async t => {
  const f = await fixture(t); const license = f.envelope(); await f.client.importLicense(license);
  const wrong = f.envelope({ deviceId: 'b'.repeat(64), deviceKeyHash: 'c'.repeat(64) });
  for (const invalid of [{ ...license, signature: 'A'.repeat(86) }, { ...license, keyId: 'unknown' }]) {
    await assert.rejects(f.client.importLicense(invalid), { code: 'LICENSE_INVALID' });
  }
  await assert.rejects(f.client.importLicense(wrong), { code: 'LICENSE_DEVICE_MISMATCH' });
  assert.equal(f.client.assertAllowed().licenseId, license.payload.licenseId);
});

test('renewal advances generations, and replay cannot undo observed revocation or rebind across restart', async t => {
  const f = await fixture(t); const first = f.envelope(); await f.client.importLicense(first);
  const renewed = f.envelope({ licenseId: first.payload.licenseId, generation: 2 });
  await f.client.importLicense(renewed); assert.equal(f.client.status().generation, 2);
  await assert.rejects(f.client.importLicense(first), { code: 'LICENSE_REPLAY' });
  const revoked = f.envelope({ licenseId: first.payload.licenseId, generation: 3, status: 'revoked' });
  await f.client.importLicense(revoked); assert.equal(f.client.status().status, 'revoked');
  await assert.rejects(f.client.importLicense(renewed), { code: 'LICENSE_REPLAY' });
  await f.client.close();
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.equal(restarted.status().status, 'revoked');
  await assert.rejects(restarted.importLicense(renewed), { code: 'LICENSE_REPLAY' });
  const rebind = f.envelope({ licenseId: first.payload.licenseId, generation: 4, deviceId: 'd'.repeat(64), deviceKeyHash: 'e'.repeat(64) });
  await restarted.importLicense(rebind);
  assert.throws(() => restarted.assertAllowed(), { code: 'LICENSE_DEVICE_MISMATCH' });
  await assert.rejects(restarted.importLicense(renewed), { code: 'LICENSE_REPLAY' });
});

test('lease expiry, ISP expiry and VPS expiry have no grace; expired cache loads authenticated and blocked', async t => {
  const f = await fixture(t); const token = f.envelope(); await f.client.importLicense(token);
  f.clock.value += 3 * DAY;
  assert.equal(f.client.status().status, 'offline-expired');
  assert.throws(() => f.client.assertAllowed(), { code: 'LICENSE_REFRESH_REQUIRED', status: 409 });
  await f.client.close();
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.equal(restarted.status().status, 'offline-expired');
  const paidExpired = f.envelope({ expiresAt: f.clock.value, offlineUntil: f.clock.value });
  await restarted.importLicense(paidExpired); assert.equal(restarted.status().status, 'expired');
  const ispExpired = f.envelope({ ispExpiresAt: f.clock.value, offlineUntil: f.clock.value });
  await restarted.importLicense(ispExpired); assert.equal(restarted.status().status, 'expired');
  const vpsExpired = f.envelope({ vpsExpiresAt: f.clock.value, offlineUntil: f.clock.value });
  await restarted.importLicense(vpsExpired); assert.equal(restarted.status().status, 'expired');
});

test('v2 customer ISP grants survive restart without resource dates and end at software expiry', async t => {
  const f = await fixture(t, { config: { version: 1, mode: 'required', publicKeys: config.publicKeys } });
  const token = f.envelope({ version: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null, offlineUntil: start + 30 * DAY });
  await f.client.importLicense(token);
  const current = f.client.assertAllowed();
  assert.equal(current.licenseVersion, 2); assert.equal(current.resourcesMode, 'customer');
  assert.equal(current.ispExpiresAt, null); assert.equal(current.vpsExpiresAt, null);
  await f.client.close(); f.clock.value += 20 * DAY;
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.equal(restarted.assertAllowed().allowed, true);
  f.clock.value = start + 30 * DAY;
  assert.throws(() => restarted.assertAllowed(), { code: 'LICENSE_EXPIRED' });
  assert.doesNotMatch(restarted.status().message, /ISP/);
});

test('v2 included expired resource reminders do not block imports, restart or the full software term', async t => {
  const f = await fixture(t, { config: { version: 1, mode: 'required', publicKeys: config.publicKeys } });
  const token = f.envelope({ version: 2, resourcesMode: 'included', ispExpiresAt: start - 1, vpsExpiresAt: start - 1, offlineUntil: start + 30 * DAY });
  assert.equal((await f.client.importLicense(token)).allowed, true);
  assert.equal(f.client.status().resourcesMode, 'included');
  await f.client.close(); f.clock.value += 29 * DAY;
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.equal(restarted.assertAllowed().allowed, true);
  assert.equal(restarted.status().ispExpiresAt, start - 1); assert.equal(restarted.status().vpsExpiresAt, start - 1);
  f.clock.value = start + 30 * DAY;
  assert.throws(() => restarted.assertAllowed(), { code: 'LICENSE_EXPIRED' });
});

test('only a newer signed v2 grant can relax v1 resource expiry and replay remains blocked', async t => {
  const f = await fixture(t);
  const legacy = f.envelope({ ispExpiresAt: start + DAY, offlineUntil: start + DAY });
  await f.client.importLicense(legacy); f.clock.value += DAY;
  assert.throws(() => f.client.assertAllowed(), { code: 'LICENSE_EXPIRED' });
  assert.equal(f.client.status().licenseVersion, 1); assert.equal(f.client.status().resourcesMode, 'included');
  const upgraded = f.envelope({ version: 2, resourcesMode: 'customer', licenseId: legacy.payload.licenseId, generation: 2,
    ispExpiresAt: null, vpsExpiresAt: null, offlineUntil: start + 30 * DAY });
  assert.equal((await f.client.importLicense(upgraded)).allowed, true);
  await assert.rejects(f.client.importLicense(legacy), { code: 'LICENSE_REPLAY' });
  const revoked = f.envelope({ ...upgraded.payload, generation: 3, status: 'revoked' });
  await f.client.importLicense(revoked); assert.throws(() => f.client.assertAllowed(), { code: 'LICENSE_REVOKED' });
  await assert.rejects(f.client.importLicense(upgraded), { code: 'LICENSE_REPLAY' });
});

test('v2 software grants retain persisted UTC rollback checks and offline lease enforcement', async t => {
  const f = await fixture(t, { config: { version: 1, mode: 'required', publicKeys: config.publicKeys } });
  await f.client.importLicense(f.envelope({ version: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null }));
  f.clock.value += 2 * DAY; assert.equal(f.client.assertAllowed().allowed, true);
  await f.client.close(); f.clock.value -= DAY;
  const rollback = createLicenseClient(f.options); t.after(() => rollback.close()); await rollback.initialize();
  assert.throws(() => rollback.assertAllowed(), { code: 'LICENSE_CLOCK_ROLLBACK' });
  await rollback.close(); f.clock.value = start + 3 * DAY;
  const expiredLease = createLicenseClient(f.options); t.after(() => expiredLease.close()); await expiredLease.initialize();
  assert.throws(() => expiredLease.assertAllowed(), { code: 'LICENSE_REFRESH_REQUIRED' });
});

test('invalid v2 claims preserve the current signed license', async t => {
  const f = await fixture(t); const valid = f.envelope(); await f.client.importLicense(valid);
  const v2 = f.envelope({ version: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null });
  for (const payload of [{ ...v2.payload, status: 'pending-resource' }, { ...v2.payload, resourcesMode: 'unknown' },
    { ...v2.payload, resourcesMode: undefined }, { ...v2.payload, ispExpiresAt: start + DAY }, { ...v2.payload, resourceStatus: 'expired' }]) {
    await assert.rejects(f.client.importLicense({ ...v2, payload }), { code: 'LICENSE_INVALID' });
    assert.equal(f.client.assertAllowed().licenseId, valid.payload.licenseId);
  }
});

test('signed issuance anchor survives restart, rollback is blocked, UTC timezone changes do not matter', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope());
  const originalZone = process.env.TZ;
  try {
    for (const zone of ['Asia/Taipei', 'America/Los_Angeles', 'UTC']) { process.env.TZ = zone; assert.equal(f.client.assertAllowed().allowed, true); }
  } finally { if (originalZone === undefined) delete process.env.TZ; else process.env.TZ = originalZone; }
  f.clock.value -= 10 * 60 * 1000;
  assert.throws(() => f.client.assertAllowed(), { code: 'LICENSE_CLOCK_ROLLBACK' });
  await f.client.close();
  const restarted = createLicenseClient(f.options); t.after(() => restarted.close()); await restarted.initialize();
  assert.throws(() => restarted.assertAllowed(), { code: 'LICENSE_CLOCK_ROLLBACK' });
});

test('monotonic lease prevents a frozen wall clock extending use or identical imports resetting elapsed time', async t => {
  const f = await fixture(t); const token = f.envelope(); await f.client.importLicense(token);
  f.clock.monotonic += 3 * DAY;
  assert.equal(f.client.status().status, 'offline-expired');
  await f.client.importLicense(token);
  assert.equal(f.client.status().status, 'offline-expired');
});

test('observed UTC high-water persists across restart and rejects rollback after expiry', async t => {
  const f = await fixture(t, { config: { version: 1, mode: 'required', publicKeys: config.publicKeys } });
  const token = f.envelope(); await f.client.importLicense(token);
  f.clock.value += 3 * DAY;
  assert.equal(f.client.status().status, 'offline-expired');
  await f.client.close();
  const state = JSON.parse(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8'));
  assert.equal(state.record.lastObservedTime, f.clock.value);
  assert.equal(state.record.license.signature, token.signature, 'checkpoint must not change the issuer-signed license');
  f.clock.value = start + DAY;
  const client = createLicenseClient(f.options); t.after(() => client.close());
  assert.equal((await client.initialize()).reason, 'LICENSE_CLOCK_ROLLBACK');
  assert.throws(() => client.assertAllowed(), { code: 'LICENSE_CLOCK_ROLLBACK' });
  assert.equal(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8'), `${JSON.stringify(state)}\n`);
});

test('monotonic high-water survives restart even if UTC remained frozen', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope());
  f.clock.monotonic += 3 * DAY;
  assert.equal(f.client.status().status, 'offline-expired');
  await f.client.close();
  f.clock.monotonic = 0;
  const client = createLicenseClient(f.options); t.after(() => client.close());
  assert.equal((await client.initialize()).reason, 'LICENSE_CLOCK_ROLLBACK');
});

test('forward UTC restarts remain authorized and startup records progress before returning', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope()); await f.client.close();
  for (const hour of [1, 2, 3]) {
    f.clock.value = start + hour * HOUR;
    const client = createLicenseClient(f.options); t.after(() => client.close());
    assert.equal((await client.initialize()).allowed, true);
    const saved = JSON.parse(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8'));
    assert.equal(saved.record.lastObservedTime, f.clock.value);
    await client.close();
  }
});

test('clock checks coalesce into one bounded checkpoint and close flushes sub-interval progress', async t => {
  let writes = 0;
  const f = await fixture(t, { dependencies: { renamePrivate: async (source, target) => {
    writes++; const { rename } = await import('node:fs/promises'); return rename(source, target);
  } } });
  await f.client.importLicense(f.envelope()); assert.equal(writes, 1);
  f.clock.value += 4 * 60 * 1000;
  for (let i = 0; i < 50; i++) f.client.assertAllowed();
  await new Promise(resolve => setImmediate(resolve)); assert.equal(writes, 1);
  f.clock.value += 60 * 1000;
  for (let i = 0; i < 50; i++) f.client.assertAllowed();
  await waitFor(() => writes === 2);
  f.clock.value += 60 * 1000;
  const closing = f.client.close(); assert.equal(closing, f.client.close());
  assert.equal(f.client.status().allowed, false, 'close must block immediately, before filesystem work finishes');
  await closing;
  assert.equal(writes, 3);
  assert.equal(JSON.parse(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8')).record.lastObservedTime, f.clock.value);
});

test('clock checkpoint write or read failure blocks use and preserves the original license journal', async t => {
  for (const operation of ['write', 'read']) {
    let deny = false;
    const f = await fixture(t, { dependencies: {
      readFile: async (...args) => {
        if (deny && operation === 'read' && path.basename(args[0]) === 'state.json') throw Object.assign(new Error('read denied'), { code: 'EACCES' });
        return readFile(...args);
      },
      renamePrivate: async (source, target) => {
        if (deny && operation === 'write') throw Object.assign(new Error('write denied'), { code: 'EACCES' });
        const { rename } = await import('node:fs/promises'); return rename(source, target);
      },
    } });
    await f.client.importLicense(f.envelope());
    const file = path.join(f.options.stateDir, 'state.json'), before = await readFile(file, 'utf8');
    deny = true; f.clock.value += 5 * 60 * 1000; f.client.status();
    await waitFor(() => f.client.status().lastError === 'LICENSE_STATE_INVALID');
    assert.throws(() => f.client.assertAllowed(), { code: 'LICENSE_STATE_INVALID' });
    assert.equal(await readFile(file, 'utf8'), before);
    deny = false;
  }
});

test('shutdown checkpoint failure is reported, blocks immediately and leaves the previous signed journal intact', async t => {
  let deny = false;
  const f = await fixture(t, { dependencies: { renamePrivate: async (source, target) => {
    if (deny) throw Object.assign(new Error('write denied at shutdown'), { code: 'EACCES' });
    const { rename } = await import('node:fs/promises'); return rename(source, target);
  } } });
  await f.client.importLicense(f.envelope());
  const file = path.join(f.options.stateDir, 'state.json'), before = await readFile(file, 'utf8');
  f.clock.value += 60 * 1000; deny = true;
  const result = await f.client.close();
  assert.equal(result.allowed, false); assert.equal(result.lastError, 'LICENSE_STATE_INVALID');
  assert.equal(await readFile(file, 'utf8'), before);
});

test('startup checkpoint failure cannot authorize a valid cached license or replace its journal', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope()); await f.client.close();
  const file = path.join(f.options.stateDir, 'state.json'), before = await readFile(file, 'utf8');
  f.clock.value += HOUR;
  const client = createLicenseClient({ ...f.options, dependencies: { ...f.options.dependencies,
    renamePrivate: async () => { throw Object.assign(new Error('startup write denied'), { code: 'EACCES' }); },
  } }); t.after(() => client.close());
  assert.equal((await client.initialize()).reason, 'LICENSE_STATE_INVALID');
  assert.throws(() => client.assertAllowed(), { code: 'LICENSE_STATE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), before);
});

test('stale clock checkpoint fails closed instead of overwriting another instance revocation', async t => {
  const f = await fixture(t); const first = f.envelope(); await f.client.importLicense(first);
  const stale = createLicenseClient(f.options); t.after(() => stale.close()); await stale.initialize();
  await f.client.importLicense(f.envelope({ licenseId: first.payload.licenseId, generation: 2, status: 'revoked' }));
  const file = path.join(f.options.stateDir, 'state.json'), before = await readFile(file, 'utf8');
  f.clock.value += 5 * 60 * 1000; stale.status();
  await waitFor(() => stale.status().reason === 'LICENSE_STATE_CONFLICT');
  assert.throws(() => stale.assertAllowed(), { code: 'LICENSE_STATE_CONFLICT' });
  assert.equal(await readFile(file, 'utf8'), before);
});

test('queued clock checkpoint and concurrent imports retain the newest license generation', async t => {
  let release, notify, delay = false;
  const entered = new Promise(resolve => { notify = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  const f = await fixture(t, { dependencies: { renamePrivate: async (source, target) => {
    if (delay) { delay = false; notify(); await gate; }
    const { rename } = await import('node:fs/promises'); return rename(source, target);
  } } });
  const first = f.envelope(); await f.client.importLicense(first);
  delay = true;
  const renewed = f.client.importLicense(f.envelope({ licenseId: first.payload.licenseId, generation: 2 }));
  await entered;
  f.clock.value += 6 * 60 * 1000;
  for (let i = 0; i < 50; i++) f.client.status();
  const revoked = f.client.importLicense(f.envelope({ licenseId: first.payload.licenseId, generation: 3, status: 'revoked' }));
  release(); await Promise.all([renewed, revoked]); await f.client.close();
  const saved = JSON.parse(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8'));
  assert.equal(saved.record.license.payload.generation, 3); assert.equal(saved.record.license.payload.status, 'revoked');
  assert.equal(saved.record.history[first.payload.licenseId].generation, 3);
  assert.equal(saved.record.lastObservedTime, f.clock.value);
  const client = createLicenseClient(f.options); t.after(() => client.close());
  assert.equal((await client.initialize()).status, 'revoked');
  await assert.rejects(client.importLicense(first), { code: 'LICENSE_REPLAY' });
});

test('corrupt private device and signed state fail closed and are preserved', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope()); await f.client.close();
  const state = path.join(f.options.stateDir, 'state.json');
  const saved = await readFile(state, 'utf8');
  const changed = JSON.parse(saved); changed.record.license.payload.status = 'active'; changed.record.lastTrustedServerTime = 0;
  await writeFile(state, JSON.stringify(changed));
  const corrupted = createLicenseClient(f.options); t.after(() => corrupted.close()); await corrupted.initialize();
  assert.throws(() => corrupted.assertAllowed(), { code: 'LICENSE_STATE_INVALID' });
  assert.equal(await readFile(state, 'utf8'), JSON.stringify(changed));
  await writeFile(state, saved); await writeFile(path.join(f.options.stateDir, 'device.json'), '{');
  const badDevice = createLicenseClient(f.options); t.after(() => badDevice.close()); await badDevice.initialize();
  assert.equal(badDevice.status().allowed, false); assert.equal(badDevice.status().reason, 'LICENSE_STATE_INVALID');
});

test('copied license directory fails device binding after machine identity changes', async t => {
  const f = await fixture(t); await f.client.importLicense(f.envelope()); await f.client.close();
  const copied = createLicenseClient({ ...f.options, getDeviceIdentity: async () => 'windows-machine-2' }); t.after(() => copied.close());
  assert.equal((await copied.initialize()).allowed, false);
  assert.throws(() => copied.assertAllowed(), { code: 'LICENSE_STATE_INVALID' });
});

test('refresh timeout preserves valid cached authorization and observes only latest verified local proxy', async t => {
  let currentProxy = { proxyPort: 17890, verified: true }, optionsSeen, calls = 0, started;
  const requestStarted = new Promise(resolve => { started = resolve; });
  const f = await fixture(t, { getProxy: () => currentProxy, dependencies: { timeoutMs: 15 },
    request: (_url, options) => { calls++; optionsSeen = options; started(); return new Promise(() => {}); } });
  await f.client.importLicense(f.envelope());
  const refreshing = f.client.refresh(); await requestStarted;
  assert.equal(f.client.status().refreshing, true);
  await assert.rejects(refreshing, { code: 'LICENSE_TIMEOUT', status: 503 });
  assert.equal(optionsSeen.proxyPort, 17890); assert.equal(optionsSeen.signal.aborted, true);
  assert.equal(f.client.assertAllowed().allowed, true); assert.equal(f.client.status().lastError, 'LICENSE_TIMEOUT');
  currentProxy = { unavailable: true };
  await assert.rejects(f.client.refresh(), { code: 'LICENSE_PROXY_UNVERIFIED', status: 503 }); assert.equal(calls, 1);
  currentProxy = null;
  await assert.rejects(f.client.refresh(), { code: 'LICENSE_TIMEOUT' }); assert.equal(optionsSeen.proxyPort, null);
});

test('online activation signs card request, refresh is separate from local assertions and authenticates service response', async t => {
  let f, calls = 0, latest;
  f = await fixture(t, { request: async (url, options) => {
    calls++; latest = verifyDeviceRequest(options.body).request;
    assert.equal(options.timeoutMs, 8000); assert.equal(url.pathname, latest.action === 'redeem' ? '/v1/redeem' : '/v1/refresh');
    return { ok: true, data: { license: f.envelope({ licenseId: f.client.status().licenseId || randomUUID(), generation: calls }) } };
  } });
  assert.equal((await f.client.activate('activation_card_12345')).refreshing, false);
  assert.equal(latest.card, 'activation_card_12345'); assert.equal(f.client.assertAllowed().allowed, true);
  await f.client.refresh(); assert.equal(latest.action, 'refresh'); assert.equal(calls, 2);
  assert.equal(f.counters().identityReads, 1);
});

test('stale client cannot overwrite a newer revocation journal', async t => {
  const f = await fixture(t); const first = f.envelope(); await f.client.importLicense(first);
  const stale = createLicenseClient(f.options); t.after(() => stale.close()); await stale.initialize();
  await f.client.importLicense(f.envelope({ licenseId: first.payload.licenseId, generation: 2, status: 'revoked' }));
  const state = path.join(f.options.stateDir, 'state.json'), before = await readFile(state, 'utf8');
  await assert.rejects(stale.importLicense(f.envelope({ licenseId: first.payload.licenseId, generation: 3 })), { code: 'LICENSE_STATE_CONFLICT' });
  assert.equal(stale.status().allowed, false); assert.equal(await readFile(state, 'utf8'), before);
});

test('authenticated withdrawal blocks immediately even if journal replacement fails', async t => {
  let denyWrites = false;
  const f = await fixture(t, { dependencies: { renamePrivate: async (source, target) => {
    if (denyWrites) throw Object.assign(new Error('locked journal'), { code: 'EACCES' });
    const { rename } = await import('node:fs/promises'); return rename(source, target);
  } } });
  const first = f.envelope(); await f.client.importLicense(first); denyWrites = true;
  const revoked = f.envelope({ licenseId: first.payload.licenseId, generation: 2, status: 'revoked' });
  await assert.rejects(f.client.importLicense(revoked));
  assert.equal(f.client.status().status, 'revoked');
  await assert.rejects(f.client.importLicense(first), { code: 'LICENSE_REPLAY' });
});

test('pending-resource and oversized imported file cannot authorize', async t => {
  const f = await fixture(t);
  await f.client.importLicense(f.envelope({ status: 'pending-resource' }));
  assert.equal(f.client.status().status, 'pending-resource');
  await assert.rejects(f.client.importLicense(' '.repeat(128 * 1024 + 1)), { code: 'LICENSE_RESPONSE_INVALID' });
  assert.equal(f.client.status().allowed, false);
});

test('linked runtime directory is rejected before storing any device key', async t => {
  const f = await fixture(t); await f.client.close();
  const linked = path.join(f.directory, 'linked');
  await symlink(f.options.stateDir, linked, process.platform === 'win32' ? 'junction' : 'dir');
  const client = createLicenseClient({ ...f.options, stateDir: linked }); t.after(() => client.close());
  assert.equal((await client.initialize()).reason, 'LICENSE_PATH_INVALID');
});

test('first install safely creates missing runtime parents and private license directory', async t => {
  const f = await fixture(t); await f.client.close();
  const stateDir = path.join(f.directory, 'new-runtime', 'nested', '.license');
  const created = [];
  const client = createLicenseClient({ ...f.options, stateDir, dependencies: { ...f.options.dependencies,
    createPrivateDirectory: async directory => { created.push(directory); await mkdir(directory, { mode: 0o700 }); },
  } }); t.after(() => client.close());
  assert.equal((await client.initialize()).status, 'unactivated');
  assert.deepEqual(created, [path.join(f.directory, 'new-runtime'), path.join(f.directory, 'new-runtime', 'nested'), stateDir]);
  assert.ok(JSON.parse(await readFile(path.join(stateDir, 'device.json'), 'utf8')).privateKey);
  assert.equal(created.includes(f.directory), false, 'existing directories must never have ACL changed');
});

test('existing directory without established private device storage cannot receive a plaintext key', async t => {
  const f = await fixture(t); await f.client.close();
  const stateDir = path.join(f.directory, 'pre-existing'); await mkdir(stateDir);
  const client = createLicenseClient({ ...f.options, stateDir }); t.after(() => client.close());
  assert.equal((await client.initialize()).reason, 'LICENSE_STATE_INVALID');
  await assert.rejects(readFile(path.join(stateDir, 'device.json')), { code: 'ENOENT' });
});

test('short sessions across restarts keep the signed daily deadline and overdue startup never awaits cloud', async t => {
  let f, calls = 0, id;
  f = await fixture(t, { request: async () => { calls++; return { ok: true, data: { license: f.envelope({ licenseId: id, generation: calls + 1 }) } }; } });
  const first = f.envelope(); id = first.payload.licenseId; await f.client.importLicense(first); await f.client.close();
  for (const hour of [4, 8, 12, 20]) {
    f.clock.value = start + hour * HOUR;
    const client = createLicenseClient(f.options); t.after(() => client.close()); await client.initialize();
    assert.equal(f.timer().delay, (24 - hour) * HOUR);
    assert.equal(calls, 0); assert.equal(client.assertAllowed().allowed, true); await client.close();
  }
  f.clock.value = start + 25 * HOUR;
  const overdue = createLicenseClient(f.options); t.after(() => overdue.close());
  assert.equal((await overdue.initialize()).allowed, true);
  assert.equal(calls, 0, 'initialize must not await or start the cloud request inline');
  assert.equal(f.timer().delay, 0, 'an overdue cache must not wait a new 24 hours');
  f.timer().callback(); assert.equal(overdue.refreshIfDue(), false, 'only one background job may be pending');
  await waitFor(() => overdue.status().generation === 2 && f.timer().delay === DAY);
  assert.equal(calls, 1); assert.equal(overdue.assertAllowed().allowed, true);
});

test('near-expiry and expired offline leases refresh immediately after reading cache', async t => {
  let f, calls = 0, id;
  f = await fixture(t, { request: async () => { calls++; return { ok: true, data: { license: f.envelope({ licenseId: id, generation: calls + 1,
    expiresAt: start + 30 * DAY, ispExpiresAt: start + 30 * DAY }) } }; } });
  const first = f.envelope(); id = first.payload.licenseId; await f.client.importLicense(first); await f.client.close();
  for (const [hour, expected] of [[71, 'active'], [144, 'offline-expired']]) {
    f.clock.value = start + hour * HOUR;
    const client = createLicenseClient(f.options); t.after(() => client.close()); await client.initialize();
    assert.equal(client.status().status, expected); assert.equal(f.timer().delay, 0);
    const generation = calls + 2;
    f.timer().callback();
    await waitFor(() => client.status().generation === generation && f.timer().delay === DAY);
    assert.equal(client.assertAllowed().allowed, true); await client.close();
  }
  assert.equal(calls, 2);
});

test('automatic refresh failures persist hourly exponential backoff across restart without polling IO', async t => {
  let calls = 0;
  const f = await fixture(t, { request: async () => { calls++; throw new Error('offline'); } });
  await f.client.importLicense(f.envelope()); f.clock.value += DAY + 1;
  f.timer().callback();
  await waitFor(() => calls === 1 && f.timer().delay === HOUR);
  assert.equal(f.client.assertAllowed().allowed, true); await f.client.close();
  f.clock.value += 10 * 60 * 1000;
  const client = createLicenseClient(f.options); t.after(() => client.close()); await client.initialize();
  assert.equal(f.timer().delay, HOUR - 10 * 60 * 1000); assert.equal(calls, 1);
  const counters = f.counters();
  for (let i = 0; i < 50; i++) { assert.equal(client.refreshIfDue(), false); client.status(); client.assertAllowed(); }
  assert.deepEqual(f.counters(), counters, 'not-due refresh and authorization checks must remain local');
  for (const [advance, expectedDelay, expectedCalls] of [[HOUR - 10 * 60 * 1000, 2 * HOUR, 2], [2 * HOUR, 4 * HOUR, 3], [4 * HOUR, 6 * HOUR, 4]]) {
    f.clock.value += advance; f.timer().callback();
    await waitFor(() => calls === expectedCalls && f.timer().delay === expectedDelay);
    assert.equal(client.assertAllowed().allowed, true);
  }
  const saved = JSON.parse(await readFile(path.join(f.options.stateDir, 'state.json'), 'utf8'));
  assert.equal(saved.record.refresh.failures, 4);
});

test('verified-route retry skips only a previous unavailable proxy and starts one independent job', async t => {
  let f, proxy = { unavailable: true }, calls = 0, id;
  f = await fixture(t, { getProxy: () => proxy, request: async (_url, options) => {
    calls++; assert.equal(options.proxyPort, 17890);
    return { ok: true, data: { license: f.envelope({ licenseId: id, generation: 2 }) } };
  } });
  const first = f.envelope(); id = first.payload.licenseId; await f.client.importLicense(first); f.clock.value += DAY + 1;
  assert.equal(f.client.refreshIfDue(), true);
  await waitFor(() => f.client.status().lastError === 'LICENSE_PROXY_UNVERIFIED' && f.timer().delay === HOUR);
  assert.equal(calls, 0); assert.equal(f.client.refreshIfDue(), false); assert.equal(f.client.assertAllowed().allowed, true);
  proxy = { proxyPort: 17890, verified: true };
  assert.equal(f.client.refreshIfDue(), true); assert.equal(f.client.refreshIfDue(), false);
  await waitFor(() => f.client.status().generation === 2 && f.timer().delay === DAY);
  assert.equal(calls, 1); assert.equal(f.client.refreshIfDue(), false);
});

test('refresh metadata save failure cannot block a still-valid cached license', async t => {
  let denyWrites = false, calls = 0;
  const f = await fixture(t, { request: async () => { calls++; throw new Error('offline'); }, dependencies: {
    renamePrivate: async (source, target) => {
      if (denyWrites) throw Object.assign(new Error('locked metadata'), { code: 'EACCES' });
      const { rename } = await import('node:fs/promises'); return rename(source, target);
    },
  } });
  await f.client.importLicense(f.envelope()); denyWrites = true;
  await assert.rejects(f.client.refresh(), { code: 'LICENSE_NETWORK_FAILED' });
  assert.equal(calls, 1);
  assert.equal(f.client.assertAllowed().allowed, true); assert.equal(f.client.status().lastError, 'LICENSE_NETWORK_FAILED');
});

test('frozen wall clock cannot turn monotonic daily refresh failures into immediate retry loops', async t => {
  let calls = 0;
  const f = await fixture(t, { request: async () => { calls++; throw new Error('offline'); } });
  await f.client.importLicense(f.envelope()); f.clock.monotonic = DAY;
  assert.equal(f.client.refreshIfDue(), true);
  await waitFor(() => calls === 1 && f.timer().delay === HOUR);
  assert.equal(f.client.refreshIfDue(), false); assert.equal(f.client.assertAllowed().allowed, true);
});

test('a service response with exhausted paid expiry cannot cause a zero-delay refresh loop', async t => {
  let f, id, calls = 0;
  f = await fixture(t, { request: async () => { calls++; return { ok: true, data: { license: f.envelope({ licenseId: id, generation: 2,
    expiresAt: start + DAY, offlineUntil: start + DAY }) } }; } });
  const first = f.envelope({ expiresAt: start + DAY, offlineUntil: start + DAY }); id = first.payload.licenseId;
  await f.client.importLicense(first); f.clock.value += 2 * DAY;
  f.timer().callback();
  await waitFor(() => f.client.status().generation === 2 && f.timer().delay === DAY);
  assert.equal(calls, 1); assert.equal(f.client.status().status, 'expired'); assert.equal(f.client.refreshIfDue(), false);
});

test('HTTPS transport uses only selected loopback CONNECT, validates TLS and never falls back or redirects', async t => {
  const original = { connect: net.connect, tlsConnect: tls.connect, request: https.request };
  t.after(() => { net.connect = original.connect; tls.connect = original.tlsConnect; https.request = original.request; });
  let proxyFails = false, socketTarget, tlsOptions, httpsCalls = 0, responseStatus = 200;
  const socket = () => {
    const value = new EventEmitter(); value.destroyed = false;
    value.destroy = () => { value.destroyed = true; };
    value.pause = value.resume = value.unshift = () => {};
    value.write = data => { assert.match(data, /^CONNECT license\.example\.test:443 HTTP\/1\.1/); queueMicrotask(() => value.emit('data', Buffer.from('HTTP/1.1 200 Connection established\r\n\r\n'))); };
    return value;
  };
  net.connect = options => { socketTarget = options; const value = socket(); queueMicrotask(() => value.emit(proxyFails ? 'error' : 'connect', proxyFails ? new Error('connection refused') : undefined)); return value; };
  tls.connect = options => { tlsOptions = options; const secure = socket(); queueMicrotask(() => secure.emit('secureConnect')); return secure; };
  https.request = (_url, options, callback) => {
    httpsCalls++; assert.equal(options.method, 'POST'); options.agent?.createConnection();
    const outbound = socket(); outbound.end = body => {
      assert.equal(JSON.parse(body.toString()).requestId, 'fake-id');
      const response = socket(); response.statusCode = responseStatus; response.resume = () => {};
      queueMicrotask(() => { callback(response); response.emit('data', Buffer.from('{"ok":true,"data":{}}')); response.emit('end'); });
    }; return outbound;
  };
  const args = { body: { requestId: 'fake-id' }, proxyPort: 17890, timeoutMs: 100 };
  assert.equal((await requestLicense('https://license.example.test/v1/refresh', args)).ok, true);
  assert.deepEqual(socketTarget, { host: '127.0.0.1', port: 17890 });
  assert.equal(tlsOptions.rejectUnauthorized, true); assert.equal(tlsOptions.servername, 'license.example.test'); assert.equal(tlsOptions.minVersion, 'TLSv1.2');
  proxyFails = true;
  await assert.rejects(requestLicense('https://license.example.test/v1/refresh', args), { code: 'LICENSE_NETWORK_FAILED' });
  assert.equal(httpsCalls, 1, 'failed tunnel must never open a direct HTTPS request');
  proxyFails = false; responseStatus = 302;
  await assert.rejects(requestLicense('https://license.example.test/v1/refresh', args), { code: 'LICENSE_SERVICE_REJECTED' });
  assert.equal(httpsCalls, 2, 'redirect must not be followed');
});
