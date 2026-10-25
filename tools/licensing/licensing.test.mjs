import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, link, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { Worker } from 'node:worker_threads';
import { createPrivateDirectory } from '../../backend/src/private-files.mjs';
import { LICENSE_TERM_MS, LICENSE_LEASE_MS, publicKeyHash, signLicense, signDeviceRequest, verifyLicense, verifyDeviceRequest, validateLicenseConfig } from '../../backend/src/license-format.mjs';
import { LicenseStore, AMOUNT_FEN, ISP_COST_FEN } from './store.mjs';
import { createLicensingServer, startLicensingService } from './service.mjs';
import { runAdmin } from './admin.mjs';
import { readSafeText, checkNewOutput } from './safe-files.mjs';
import { openStore } from './runtime.mjs';

const DAY = 86400000;
function device(id = 'a'.repeat(64)) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { id, privateKey, publicKey: publicKey.export({ type: 'spki', format: 'pem' }) };
}
function request(d, action, fields = {}, requestId = randomUUID()) {
  return signDeviceRequest({ version: 1, action, requestId, deviceId: d.id, devicePublicKey: d.publicKey, ...fields }, d.privateKey);
}
async function fixture(action) {
  const parent = await mkdtemp(join(tmpdir(), 'proxypilot-licensing-'));
  const directory = join(parent, 'private');
  await createPrivateDirectory(directory);
  try { return await action(directory); }
  finally {
    const root = resolve(parent);
    assert.ok(root.startsWith(resolve(tmpdir()) + sep) && root.split(sep).at(-1).startsWith('proxypilot-licensing-'));
    await rm(root, { recursive: true, force: true });
  }
}
function keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, keyId: 'test-1', publicKeys: { 'test-1': publicKey.export({ type: 'spki', format: 'pem' }) } };
}
function verify(token, signing, d, now, options = {}) { return verifyLicense(token, { publicKeys: signing.publicKeys, deviceId: d.id, deviceKeyHash: publicKeyHash(d.publicKey), now, ...options }); }

test('customer resources need no supplier dates; pricing, order ownership and software terms remain correct across trials, cards and renewals', async () => fixture(async directory => {
  const signing = keys(), d = device(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'ownership.sqlite'), { ...signing, now: () => now });
  try {
    const trial = store.trialOffline(request(d, 'offline'), { resourcesMode: 'customer' });
    assert.equal(trial.payload.version, 2); assert.equal(trial.payload.resourcesMode, 'customer');
    assert.equal(trial.payload.ispExpiresAt, null); assert.equal(trial.payload.vpsExpiresAt, null);
    assert.equal(trial.payload.offlineUntil, start + DAY); assert.equal(store.list().orders.length, 0);
    const id = trial.payload.licenseId;
    now += DAY / 2;
    const paid = store.renew(id, { orderId: 'self-first', paid: true });
    assert.equal(paid.payload.expiresAt, now + LICENSE_TERM_MS); assert.equal(paid.payload.offlineUntil, paid.payload.expiresAt);
    assert.equal(store.list().orders[0].amount_fen, 10000); assert.equal(store.list().orders[0].isp_cost_fen, 0);
    assert.equal(store.list().orders[0].resources_mode, 'customer'); assert.equal(store.list().licenses[0].isp_expires_at, null);
    assert.deepEqual(store.renew(id, { orderId: 'self-first', resourcesMode: 'included' }), paid);
    const switched = store.renew(id, { orderId: 'bundled-next', paid: true, resourcesMode: 'included', resourcesReady: true, ispExpiresAt: start + 100 * DAY });
    assert.equal(switched.payload.resourcesMode, 'included'); assert.equal(store.list().orders.find(row => row.id === 'self-first').isp_cost_fen, 0);
    assert.equal(store.list().orders.find(row => row.id === 'bundled-next').isp_cost_fen, 3500);
    const reminder = store.resources(id, { resourcesReady: true, ispExpiresAt: start - DAY });
    assert.equal(reminder.payload.status, 'active'); assert.equal(reminder.payload.expiresAt, switched.payload.expiresAt);
    assert.equal(store.refreshOfflineById(id).payload.offlineUntil, now + LICENSE_TERM_MS);
    const self = store.resources(id, { resourcesMode: 'customer' });
    assert.equal(self.payload.ispExpiresAt, null); assert.equal(self.payload.vpsExpiresAt, null);
    assert.equal(store.list().orders.find(row => row.id === 'bundled-next').isp_cost_fen, 3500);
    const other = device('c'.repeat(64)), card = store.issueCard({ orderId: 'self-card', paid: true, resourcesMode: 'customer' });
    assert.equal(card.ispCostFen, 0);
    assert.throws(() => store.cardResources('self-card', { resourcesMode: 'included', resourcesReady: true, ispExpiresAt: start + 100 * DAY }), { code: 'CARD_RESOURCE_MODE_FIXED' });
    assert.equal(store.list().orders.find(row => row.id === 'self-card').isp_cost_fen, 0);
    now += 5 * DAY;
    const redeemed = store.redeem(request(other, 'redeem', { card: card.card }));
    assert.equal(redeemed.payload.resourcesMode, 'customer'); assert.equal(redeemed.payload.expiresAt, now + LICENSE_TERM_MS);
    const before = store.list();
    assert.throws(() => store.activateOffline(request(device('d'.repeat(64)), 'offline'), { orderId: 'bad-mode', paid: true, resourcesMode: 'anything' }), { code: 'INVALID_RESOURCE_MODE' });
    assert.deepEqual(store.list(), before);
  } finally { store.close(); }
}));

test('unredeemed cards retain both original supply modes and ledger costs while legitimate resource updates remain usable', async () => fixture(async directory => {
  const signing = keys(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'card-mode-fixed.sqlite'), { ...signing, now: () => now });
  try {
    const included = store.issueCard({ orderId: 'bundled-card', paid: true, resourcesReady: true, ispExpiresAt: start + 40 * DAY });
    const customer = store.issueCard({ orderId: 'own-card', paid: true, resourcesMode: 'customer' });
    const before = store.list();
    for (const [orderId, resourcesMode] of [['bundled-card', 'customer'], ['own-card', 'included']]) {
      assert.throws(() => store.cardResources(orderId, { resourcesMode, resourcesReady: true, ispExpiresAt: start + 100 * DAY }), { code: 'CARD_RESOURCE_MODE_FIXED' });
      assert.deepEqual(store.list(), before, 'a rejected mode change cannot alter card, payment or event records');
    }
    now += 5 * DAY;
    const updated = store.cardResources('bundled-card', { resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: start - DAY });
    assert.equal(updated.resourcesMode, 'included'); assert.equal(updated.vpsExpiresAt, start - DAY);
    const inherited = store.cardResources('own-card', {});
    assert.equal(inherited.resourcesMode, 'customer'); assert.equal(inherited.ispExpiresAt, null);
    assert.equal(store.list().orders.length, 2);
    assert.equal(store.list().orders.find(row => row.id === 'bundled-card').isp_cost_fen, 3500);
    assert.equal(store.list().orders.find(row => row.id === 'own-card').isp_cost_fen, 0);
    for (const [card, d, mode] of [[included, device('e'.repeat(64)), 'included'], [customer, device('f'.repeat(64)), 'customer']]) {
      const issued = store.redeem(request(d, 'redeem', { card: card.card }));
      assert.equal(issued.payload.resourcesMode, mode); assert.equal(issued.payload.expiresAt, now + LICENSE_TERM_MS);
    }
    assert.equal(store.list().orders.length, 2, 'resource updates and redemption do not repeat payment');
  } finally { store.close(); }
}));

test('strict Ed25519 protocol rejects tamper, unknown fields, mismatched keys, unbounded leases and invalid config', () => {
  const d = device(), signing = keys(), now = Date.now();
  const proof = request(d, 'offline');
  assert.equal(verifyDeviceRequest(proof).deviceKeyHash, publicKeyHash(d.publicKey));
  assert.throws(() => verifyDeviceRequest({ ...proof, request: { ...proof.request, deviceId: 'b'.repeat(64) } }), { code: 'INVALID_SIGNATURE' });
  assert.throws(() => verifyDeviceRequest({ ...proof, debug: true }), { code: 'INVALID_REQUEST' });
  assert.throws(() => signDeviceRequest(proof.request, device().privateKey), { code: 'INVALID_KEY' });
  const payload = { version: 1, licenseId: randomUUID(), deviceId: d.id, deviceKeyHash: publicKeyHash(d.publicKey), generation: 1,
    plan: 'isp-30d-single', status: 'active', issuedAt: now, expiresAt: now + LICENSE_TERM_MS, offlineUntil: now + LICENSE_LEASE_MS,
    ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null };
  const token = signLicense(payload, signing);
  assert.deepEqual(verify(token, signing, d, now), payload);
  assert.throws(() => verify({ ...token, payload: { ...payload, expiresAt: now + 60 * DAY } }, signing, d, now), { code: 'INVALID_SIGNATURE' });
  assert.throws(() => signLicense({ ...payload, offlineUntil: now + LICENSE_TERM_MS + 1 }, signing), { code: 'INVALID_LICENSE' });
  assert.throws(() => signLicense({ ...payload, wallet: 100 }, signing), { code: 'INVALID_LICENSE' });
  assert.throws(() => verify(token, signing, device(), now), { code: 'DEVICE_MISMATCH' });
  assert.throws(() => verify(token, signing, d, now + LICENSE_LEASE_MS), { code: 'LICENSE_EXPIRED' });
  assert.equal(verify(token, signing, d, now + LICENSE_LEASE_MS, { allowExpired: true }).licenseId, payload.licenseId);
  assert.throws(() => verify(token, signing, d, now - 60001), { code: 'CLOCK_INVALID' });
  assert.equal(validateLicenseConfig({ version: 1, mode: 'development' }).mode, 'development');
  assert.equal(validateLicenseConfig({ version: 1, mode: 'required', publicKeys: signing.publicKeys }).serviceUrl, '');
  assert.throws(() => validateLicenseConfig({ version: 1, mode: 'required' }), { code: 'INVALID_LICENSE_CONFIG' });
  assert.throws(() => validateLicenseConfig({ version: 1, mode: 'required', publicKeys: signing.publicKeys, serviceUrl: 'http://127.0.0.1:8787' }), { code: 'INVALID_LICENSE_CONFIG' });
  assert.equal(validateLicenseConfig({ version: 1, mode: 'required', publicKeys: signing.publicKeys, serviceUrl: 'http://127.0.0.1:8787' }, { allowLoopback: true }).serviceUrl, 'http://127.0.0.1:8787');
  for (const url of ['https://u:p@example.com', 'https://example.com/path', 'https://example.com/?a=1', 'https://example.com/#x']) assert.throws(() => validateLicenseConfig({ version: 1, mode: 'required', publicKeys: signing.publicKeys, serviceUrl: url }), { code: 'INVALID_LICENSE_CONFIG' });
});

test('atomic card retry, paid renewals, independent ISP/VPS expiries, pending resources, rebind and revocation', async () => fixture(async directory => {
  const signing = keys(), d = device(), replacement = device('b'.repeat(64));
  let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    const purchase = { orderId: 'paid-1', paid: true, resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: start + 35 * DAY };
    assert.throws(() => store.issueCard({ ...purchase, paid: false }), { code: 'PAYMENT_NOT_CONFIRMED' });
    assert.throws(() => store.issueCard({ ...purchase, resourcesReady: false }), { code: 'RESOURCE_NOT_READY' });
    const issued = store.issueCard(purchase);
    assert.equal(issued.amountFen, AMOUNT_FEN); assert.equal(issued.ispCostFen, ISP_COST_FEN);
    assert.throws(() => store.issueCard(purchase), { code: 'ORDER_EXISTS' });
    const redemption = request(d, 'redeem', { card: issued.card });
    const first = store.redeem(redemption), id = first.payload.licenseId;
    assert.equal(first.payload.expiresAt, start + LICENSE_TERM_MS);
    assert.equal(first.payload.ispExpiresAt, purchase.ispExpiresAt); assert.equal(first.payload.vpsExpiresAt, purchase.vpsExpiresAt);
    now += 1000;
    assert.deepEqual(store.redeem(redemption), first);
    const retried = store.redeem(request(d, 'redeem', { card: issued.card }));
    assert.equal(retried.payload.expiresAt, first.payload.expiresAt); assert.ok(retried.payload.generation > first.payload.generation);
    assert.throws(() => store.redeem(request(replacement, 'redeem', { card: issued.card })), { code: 'CARD_ALREADY_USED' });
    const refreshRequest = request(d, 'refresh', { licenseId: id });
    now = start + 19 * DAY;
    const refreshed = store.refresh(refreshRequest);
    assert.equal(refreshed.payload.offlineUntil, now + LICENSE_LEASE_MS);
    assert.ok(refreshed.payload.generation > retried.payload.generation);
    assert.deepEqual(store.refresh(refreshRequest), refreshed);
    const renewed = store.renew(id, { ...purchase, orderId: 'paid-2', ispExpiresAt: start + 90 * DAY, vpsExpiresAt: start + 70 * DAY });
    assert.equal(renewed.payload.expiresAt, start + 2 * LICENSE_TERM_MS);
    assert.deepEqual(store.renew(id, { ...purchase, orderId: 'paid-2', ispExpiresAt: start + 90 * DAY, vpsExpiresAt: start + 70 * DAY }), renewed);
    assert.equal(store.list().orders.length, 2);
    const pending = store.resources(id, { resourcesReady: false });
    assert.equal(verify(pending, signing, d, now).status, 'active');
    assert.ok(pending.payload.offlineUntil > now);
    assert.equal(store.row(id).resources_ready, 0);
    assert.equal(store.resources(id, { resourcesReady: true, ispExpiresAt: start + 21 * DAY, vpsExpiresAt: start + 80 * DAY }).payload.expiresAt, renewed.payload.expiresAt);
    store.resources(id, { resourcesReady: true, ispExpiresAt: start + 90 * DAY, vpsExpiresAt: start + 80 * DAY });
    // Resource expiration is a reminder and cannot cancel v2 software rights.
    store.db.prepare('UPDATE licenses SET isp_expires_at=? WHERE id=?').run(start + 21 * DAY, id);
    now = start + 22 * DAY;
    const exhausted = store.refresh(request(d, 'refresh', { licenseId: id }));
    assert.equal(exhausted.payload.status, 'active');
    assert.equal(exhausted.payload.offlineUntil, now + LICENSE_LEASE_MS);
    assert.equal(exhausted.payload.vpsExpiresAt, start + 80 * DAY);
    assert.equal(exhausted.payload.ispExpiresAt, start + 21 * DAY);
    store.resources(id, { resourcesReady: true, ispExpiresAt: start + 90 * DAY, vpsExpiresAt: start + 80 * DAY });
    now = start + 65 * DAY;
    const expiredRenewal = store.renew(id, { ...purchase, orderId: 'paid-after-expiry', ispExpiresAt: start + 150 * DAY, vpsExpiresAt: start + 120 * DAY });
    assert.equal(expiredRenewal.payload.expiresAt, now + LICENSE_TERM_MS);
    const rebound = store.rebind(id, request(replacement, 'offline', { licenseId: id }));
    assert.equal(verify(rebound, signing, replacement, now).deviceId, replacement.id);
    assert.throws(() => verify(rebound, signing, d, now), { code: 'DEVICE_MISMATCH' });
    const oldDeviceResult = store.refresh(request(d, 'refresh', { licenseId: id }));
    assert.equal(oldDeviceResult.payload.deviceId, replacement.id);
    assert.throws(() => store.activateOffline(request(d, 'offline', { licenseId: id }), { ...purchase, orderId: 'old-device-renew', ispExpiresAt: start + 90 * DAY, vpsExpiresAt: null }), { code: 'DEVICE_MISMATCH' });
    assert.equal(store.list().orders.length, 3);
    const revoked = store.revoke(id);
    assert.equal(verify(revoked, signing, replacement, now).status, 'revoked');
    assert.deepEqual(store.revoke(id), revoked);
    assert.throws(() => store.renew(id, { ...purchase, orderId: 'revoked-renew', ispExpiresAt: start + 90 * DAY, vpsExpiresAt: null }), { code: 'LICENSE_REVOKED' });
    const bytes = await readFile(join(directory, 'licenses.sqlite'));
    assert.equal(bytes.includes(Buffer.from(issued.card)), false);
    assert.equal(JSON.stringify(store.list()).includes(issued.card), false);
  } finally { store.close(); }
}));

test('offline lease refresh changes generation/lease, preserves software rights after resource expiry, and rejects expired paid time', async () => fixture(async directory => {
  const signing = keys(), d = device(), replacement = device('b'.repeat(64)); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    const initial = store.activateOffline(request(d, 'offline'), { orderId: 'offline-paid', paid: true, resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: null, offlineDays: 3 });
    const licenseId = initial.payload.licenseId;
    // Model a legacy short resource record; new paid issuance can no longer create it.
    store.db.prepare('UPDATE licenses SET isp_expires_at=? WHERE id=?').run(start + 20 * DAY, licenseId);
    now += DAY;
    const app = request(d, 'offline', { licenseId }), refreshed = store.refreshOffline(app);
    assert.ok(refreshed.payload.generation > initial.payload.generation); assert.equal(refreshed.payload.offlineUntil, now + LICENSE_LEASE_MS);
    assert.equal(refreshed.payload.expiresAt, initial.payload.expiresAt); assert.equal(store.list().orders.length, 1);
    assert.deepEqual(store.refreshOffline(app), refreshed);
    assert.throws(() => store.refreshOffline(request(d, 'offline')), { code: 'INVALID_REQUEST' });
    store.rebind(licenseId, request(replacement, 'offline', { licenseId }));
    assert.equal(store.refreshOffline(request(d, 'offline', { licenseId })).payload.deviceId, replacement.id);
    now = start + 21 * DAY;
    assert.equal(store.refreshOffline(request(replacement, 'offline', { licenseId })).payload.offlineUntil, now + LICENSE_LEASE_MS);
    store.resources(licenseId, { resourcesReady: true, ispExpiresAt: start + 60 * DAY, vpsExpiresAt: null });
    now = start + 31 * DAY;
    assert.throws(() => store.refreshOffline(request(replacement, 'offline', { licenseId })), { code: 'LICENSE_EXPIRED' });
    assert.equal(store.list().orders.length, 1);
  } finally { store.close(); }
}));

test('offline application contains no card; manual order and separately supplied issued card are retry safe', async () => fixture(async directory => {
  const signing = keys(), d = device(), now = Date.now();
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    const app = request(d, 'offline');
    assert.equal(Object.hasOwn(app.request, 'card'), false);
    const purchase = { orderId: 'offline-1', paid: true, resourcesReady: true, ispExpiresAt: now + 60 * DAY, vpsExpiresAt: null };
    const token = store.activateOffline(app, purchase);
    assert.deepEqual(store.activateOffline(app, purchase), token);
    const card = store.issueCard({ ...purchase, orderId: 'offline-card' });
    const cardApp = request(d, 'offline');
    const extended = store.activateOffline(cardApp, { card: card.card });
    assert.equal(extended.payload.licenseId, token.payload.licenseId);
    assert.equal(extended.payload.expiresAt, now + 2 * LICENSE_TERM_MS);
    assert.deepEqual(store.activateOffline(cardApp, { card: card.card }), extended);
  } finally { store.close(); }
}));

test('expired unredeemed resources do not consume the card or start paid time; one order can restore resources or revoke card', async () => fixture(async directory => {
  const signing = keys(), d = device(); let now = Date.now();
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    const card = store.issueCard({ orderId: 'expired-card', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
    now += 41 * DAY;
    const redemption = request(d, 'redeem', { card: card.card });
    assert.throws(() => store.redeem(redemption), { code: 'RESOURCE_NOT_READY' });
    assert.equal(store.list().licenses.length, 0); assert.equal(store.list().cards[0].redeemed_at, null);
    store.cardResources('expired-card', { resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: now + 35 * DAY });
    const token = store.redeem(redemption);
    assert.equal(token.payload.expiresAt, now + LICENSE_TERM_MS); assert.equal(store.list().orders.length, 1);
    const toRevoke = store.issueCard({ orderId: 'unused-revoke', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
    assert.deepEqual(store.cardRevoke('unused-revoke'), { orderId: 'unused-revoke', status: 'revoked' });
    assert.throws(() => store.redeem(request(d, 'redeem', { card: toRevoke.card })), { code: 'CARD_INVALID' });
    const count = store.list().orders.length;
    assert.throws(() => store.issueCard({ orderId: 'delivery-failure', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null }, { deliver: () => { throw new Error('disk unavailable'); } }), /disk unavailable/);
    assert.equal(store.list().orders.length, count);
    now -= 1;
    assert.throws(() => store.refresh(request(d, 'refresh', { licenseId: token.payload.licenseId })), { code: 'SERVER_CLOCK_INVALID' });
  } finally { store.close(); }
}));

test('separate SQLite connections redeem one card concurrently without adding time twice', async () => fixture(async directory => {
  const signing = keys(), d = device(), now = Date.now(), path = join(directory, 'licenses.sqlite');
  const store = new LicenseStore(path, { ...signing, now: () => now });
  const card = store.issueCard({ orderId: 'concurrent-1', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
  store.close();
  const payload = { path, privateKey: signing.privateKey.export({ type: 'pkcs8', format: 'pem' }), keyId: signing.keyId, now, envelope: request(d, 'redeem', { card: card.card }), module: new URL('./store.mjs', import.meta.url).href };
  const run = () => new Promise((resolve, reject) => {
    const worker = new Worker(`const {parentPort,workerData}=require('node:worker_threads'); import(workerData.module).then(({LicenseStore})=>{const s=new LicenseStore(workerData.path,{privateKey:workerData.privateKey,keyId:workerData.keyId,now:()=>workerData.now});try{parentPort.postMessage(s.redeem(workerData.envelope));}finally{s.close();}}).catch(error=>{throw error});`, { eval: true, workerData: payload });
    worker.once('message', resolve); worker.once('error', reject);
  });
  const results = await Promise.all([run(), run(), run(), run()]);
  for (const result of results) assert.deepEqual(result, results[0]);
  const check = new LicenseStore(path, { ...signing, now: () => now });
  try { assert.equal(check.list().licenses.length, 1); assert.equal(check.list().orders.length, 1); assert.equal(results[0].payload.expiresAt, now + LICENSE_TERM_MS); }
  finally { check.close(); }
}));

test('public loopback endpoints have bounded input, signed responses and sanitized stable errors', async () => fixture(async directory => {
  const signing = keys(), d = device(), now = Date.now();
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  const server = createLicensingServer(store);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const post = (path, data, type = 'application/json') => fetch(base + path, { method: 'POST', headers: { 'content-type': type }, body: typeof data === 'string' ? data : JSON.stringify(data) });
  try {
    const card = store.issueCard({ orderId: 'http-1', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
    const response = await post('/v1/redeem', request(d, 'redeem', { card: card.card }));
    assert.equal(response.status, 200);
    const body = await response.json(); assert.equal(body.ok, true); verify(body.data.license, signing, d, now);
    const insufficientRenewal = store.issueCard({ orderId: 'http-too-short', paid: true, resourcesReady: true, ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
    const shortResponse = await post('/v1/redeem', request(d, 'redeem', { card: insufficientRenewal.card }));
    assert.equal(shortResponse.status, 400); assert.equal((await shortResponse.json()).error.code, 'RESOURCE_TERM_TOO_SHORT');
    assert.equal(store.list().cards.find(card => card.order_id === 'http-too-short').redeemed_at, null);
    const malformed = await post('/v1/redeem', '{'); assert.equal((await malformed.json()).error.code, 'INVALID_REQUEST');
    const raw = await post('/v1/redeem', 'x'.repeat(9000)); assert.equal(raw.status, 413); assert.equal((await raw.json()).error.code, 'REQUEST_TOO_LARGE');
    const media = await post('/v1/redeem', '{}', 'text/plain'); assert.equal(media.status, 415);
    const admin = await post('/admin/revoke', {}); assert.equal(admin.status, 404);
    const bad = await post('/v1/refresh', { request: { secret: 'private-key-example' }, signature: 'bad' });
    const message = JSON.stringify(await bad.json()); assert.equal(message.includes('private-key-example'), false);
    await assert.rejects(startLicensingService('unused.json', { host: '0.0.0.0' }), { code: 'INVALID_SERVER_CONFIG' });
  } finally { await new Promise(resolve => server.close(resolve)); store.close(); }
}));

test('paid issuance and conversion reject partial resources without changing the ledger; completed orders remain retry safe', async () => fixture(async directory => {
  const signing = keys(), d = device(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'coverage.sqlite'), { ...signing, now: () => now });
  try {
    const full = { orderId: 'full-first', paid: true, resourcesReady: true, ispExpiresAt: start + 90 * DAY, vpsExpiresAt: start + 90 * DAY };
    const unchanged = action => { const before = store.list(); assert.throws(action, { code: 'RESOURCE_TERM_TOO_SHORT' }); assert.deepEqual(store.list(), before); };
    for (const offlineDays of [1, 30]) {
      unchanged(() => store.activateOffline(request(d, 'offline'), { ...full, ispExpiresAt: start + DAY / 2, offlineDays }));
      unchanged(() => store.issueCard({ ...full, ispExpiresAt: start + 29 * DAY }));
    }
    const trial = store.trialOffline(request(d, 'offline'), { resourcesReady: true, ispExpiresAt: start + DAY, vpsExpiresAt: start + DAY });
    const id = trial.payload.licenseId;
    now = start + DAY / 2;
    unchanged(() => store.renew(id, { ...full, orderId: 'convert-too-short', ispExpiresAt: start + DAY, offlineDays: 1 }));
    unchanged(() => store.activateOffline(request(d, 'offline', { licenseId: id }), { ...full, orderId: 'activate-too-short', ispExpiresAt: start + DAY }));
    const converted = store.renew(id, { ...full, orderId: 'paid-conversion', ispExpiresAt: now + LICENSE_TERM_MS, vpsExpiresAt: now + LICENSE_TERM_MS });
    assert.equal(converted.payload.expiresAt, now + LICENSE_TERM_MS); assert.equal(converted.payload.offlineUntil, converted.payload.expiresAt);
    assert.equal(store.list().orders.length, 1);
    // An unexpired paid term carries forward, so another 30 days must cover the combined end.
    unchanged(() => store.renew(id, { ...full, orderId: 'early-renewal', ispExpiresAt: now + 31 * DAY }));
    const reminder = store.resources(id, { resourcesReady: true, ispExpiresAt: now + DAY, vpsExpiresAt: start + 90 * DAY });
    assert.equal(reminder.payload.expiresAt, converted.payload.expiresAt);
    assert.equal(store.list().orders.length, 1);
    const renewed = store.renew(id, { ...full, orderId: 'early-renewal', ispExpiresAt: converted.payload.expiresAt + LICENSE_TERM_MS, vpsExpiresAt: converted.payload.expiresAt + LICENSE_TERM_MS });
    assert.equal(renewed.payload.expiresAt, converted.payload.expiresAt + LICENSE_TERM_MS);
    now += 100 * DAY;
    assert.deepEqual(store.renew(id, { orderId: 'early-renewal', paid: false, resourcesReady: false, ispExpiresAt: 0 }), renewed);
    assert.equal(store.list().orders.length, 2);
    const other = device('c'.repeat(64));
    const activated = store.activateOffline(request(other, 'offline'), { ...full, orderId: 'new-after-expiry', ispExpiresAt: now + 40 * DAY, vpsExpiresAt: null });
    assert.deepEqual(store.activateOffline(request(other, 'offline'), { orderId: 'new-after-expiry', paid: false, resourcesReady: false, ispExpiresAt: 0 }), activated);
    assert.throws(() => store.activateOffline(request(d, 'offline'), { orderId: 'new-after-expiry' }), { code: 'ORDER_CONFLICT' });
    assert.equal(store.list().orders.length, 3);
  } finally { store.close(); }
}));

test('delayed card redemption requires the full new term and retains unused cards until resources are corrected', async () => fixture(async directory => {
  const signing = keys(), d = device(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'card-coverage.sqlite'), { ...signing, now: () => now });
  try {
    const purchase = { orderId: 'delayed-card', paid: true, resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: start + 40 * DAY };
    const card = store.issueCard(purchase), redemption = request(d, 'redeem', { card: card.card });
    now += 15 * DAY;
    const before = store.list();
    assert.throws(() => store.redeem(redemption), { code: 'RESOURCE_TERM_TOO_SHORT' }); assert.deepEqual(store.list(), before);
    for (const vpsExpiresAt of [null, now + 29 * DAY]) {
      assert.throws(() => store.cardResources(purchase.orderId, { resourcesReady: true, ispExpiresAt: now + 29 * DAY, vpsExpiresAt }), { code: 'RESOURCE_TERM_TOO_SHORT' });
      assert.deepEqual(store.list(), before);
    }
    store.cardResources(purchase.orderId, { resourcesReady: true, ispExpiresAt: now + 30 * DAY, vpsExpiresAt: now + 30 * DAY });
    const activated = store.redeem(redemption);
    assert.equal(activated.payload.expiresAt, now + 30 * DAY); assert.equal(store.list().orders.length, 1);
    now += 50 * DAY;
    assert.deepEqual(store.redeem(redemption), activated); assert.equal(store.list().orders.length, 1);
  } finally { store.close(); }
}));

test('admin CLI initializes private generated state and gates issue, exports only public client configuration', async () => fixture(async directory => {
  const state = join(directory, 'server-state');
  const initialized = await runAdmin(['init', '--dir', state, '--service-url', 'https://licenses.example.com']);
  const client = JSON.parse(await readFile(initialized.clientConfigTemplate, 'utf8'));
  assert.equal(client.mode, 'required'); assert.equal(JSON.stringify(client).includes('PRIVATE KEY'), false);
  const config = initialized.serverConfig;
  await assert.rejects(runAdmin(['issue-card', '--config', config, '--order-id', 'cli-1', '--resources-ready', '--isp-expires', String(Date.now() + 40 * DAY)]), { code: 'PAYMENT_NOT_CONFIRMED' });
  const issued = await runAdmin(['issue-card', '--config', config, '--order-id', 'cli-1', '--paid', '--resources-ready', '--isp-expires', String(Date.now() + 40 * DAY)]);
  assert.match(issued.card, /^PP1_/);
  const ledger = await runAdmin(['list', '--config', config]); assert.equal(ledger.orders[0].amount_fen, 10000); assert.equal(ledger.orders[0].isp_cost_fen, 3500);
  assert.equal(JSON.stringify(ledger).includes(issued.card), false);
  const existing = join(state, 'existing.json'); await writeFile(existing, 'existing');
  await assert.rejects(runAdmin(['issue-card', '--config', config, '--order-id', 'blocked-output', '--paid', '--resources-ready', '--isp-expires', String(Date.now() + 40 * DAY), '--out', existing]), { code: 'OUTPUT_EXISTS' });
  assert.equal((await runAdmin(['list', '--config', config])).orders.length, 1);
  const durableOutput = join(state, 'card-once.json');
  assert.deepEqual(await runAdmin(['issue-card', '--config', config, '--order-id', 'durable-card', '--paid', '--resources-ready', '--isp-expires', String(Date.now() + 40 * DAY), '--out', durableOutput]), { output: resolve(durableOutput) });
  assert.match(JSON.parse(await readFile(durableOutput, 'utf8')).card, /^PP1_/);
}));

test('private state and source/output files reject hard links, directory junctions and oversized input', async () => fixture(async directory => {
  const source = join(directory, 'source.json'), linked = join(directory, 'linked.json');
  await writeFile(source, '{}'); await link(source, linked);
  await assert.rejects(readSafeText(source, 8192), { code: 'UNSAFE_FILE' });
  await assert.rejects(readSafeText(linked, 8192), { code: 'UNSAFE_FILE' });
  await rm(linked);
  const large = join(directory, 'large.json'); await writeFile(large, 'x'.repeat(8193));
  await assert.rejects(readSafeText(large, 8192), { code: 'UNSAFE_FILE' });
  const junction = join(directory, 'junction');
  await symlink(directory, junction, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(checkNewOutput(join(junction, 'unsafe-output.json')), { code: 'UNSAFE_FILE' });
  const state = join(directory, 'server-state');
  const initialized = await runAdmin(['init', '--dir', state, '--service-url', 'https://licenses.example.com']);
  const keyLink = join(directory, 'key-copy.pem'); await link(join(state, 'signing-private.pem'), keyLink);
  await assert.rejects(openStore(initialized.serverConfig), { code: 'SIGNING_KEY_UNAVAILABLE' });
}));

test('offline CLI init emits public keys without a service URL and excludes mixed launch configuration', async () => fixture(async directory => {
  const state = join(directory, 'offline-state');
  const initialized = await runAdmin(['init', '--dir', state, '--offline']);
  const config = JSON.parse(await readFile(initialized.clientConfigTemplate, 'utf8'));
  assert.equal(config.mode, 'required'); assert.equal(Object.hasOwn(config, 'serviceUrl'), false); assert.equal(Object.keys(config.publicKeys).length, 1);
  assert.equal(JSON.stringify(config).includes('PRIVATE KEY'), false);
  await assert.rejects(runAdmin(['init', '--dir', join(directory, 'mixed'), '--offline', '--service-url', 'https://example.com']), { code: 'INVALID_ARGUMENT' });
  const d = device(), app = join(directory, 'new-device.json'), output = join(state, 'initial-license.json');
  await writeFile(app, JSON.stringify(request(d, 'offline')));
  await runAdmin(['activate-offline', '--config', initialized.serverConfig, '--application', app, '--order-id', 'offline-cli-paid', '--paid', '--resources-ready', '--isp-expires', String(Date.now() + 40 * DAY), '--out', output]);
  const initial = JSON.parse(await readFile(output, 'utf8')), refreshApp = join(directory, 'refresh-device.json'), refreshOutput = join(state, 'refreshed-license.json');
  await writeFile(refreshApp, JSON.stringify(request(d, 'offline', { licenseId: initial.payload.licenseId })));
  await runAdmin(['refresh-offline', '--config', initialized.serverConfig, '--application', refreshApp, '--out', refreshOutput]);
  const refreshed = JSON.parse(await readFile(refreshOutput, 'utf8'));
  assert.equal(refreshed.payload.expiresAt, initial.payload.expiresAt); assert.ok(refreshed.payload.generation > initial.payload.generation);
  assert.equal((await runAdmin(['list', '--config', initialized.serverConfig])).orders.length, 1);
}));
