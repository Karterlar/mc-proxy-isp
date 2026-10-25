import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, readFile, rm, writeFile, access } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';
import { createPrivateDirectory } from '../../backend/src/private-files.mjs';
import { LICENSE_PLAN, LICENSE_TRIAL_PLAN, LICENSE_LEASE_MS, LICENSE_TERM_MS, publicKeyHash, signDeviceRequest, signLicense, verifyLicense } from '../../backend/src/license-format.mjs';
import { LicenseStore } from './store.mjs';
import { runAdmin } from './admin.mjs';
import { runLicensingAction } from './ui.mjs';

const DAY = 86400000;
function keys() { const pair = generateKeyPairSync('ed25519'); return { ...pair, keyId: 'windows-test', publicKeys: { 'windows-test': pair.publicKey.export({ type: 'spki', format: 'pem' }) } }; }
function device(id = 'a'.repeat(64)) { const pair = keys(); return { ...pair, id, publicPem: pair.publicKeys[pair.keyId] }; }
function application(d, action = 'offline', fields = {}) { return signDeviceRequest({ version: 1, action, requestId: randomUUID(), deviceId: d.id, devicePublicKey: d.publicPem, ...fields }, d.privateKey); }
function verified(token, signing, d, now, allowExpired = false) { return verifyLicense(token, { publicKeys: signing.publicKeys, deviceId: d.id, deviceKeyHash: publicKeyHash(d.publicPem), now, allowExpired }); }
async function fixture(action) {
  const parent = await mkdtemp(join(tmpdir(), 'proxypilot-offline-window-')), directory = join(parent, 'private'); await createPrivateDirectory(directory);
  try { return await action(directory); }
  finally { assert(resolve(parent).startsWith(resolve(tmpdir()) + sep) && resolve(parent).split(sep).at(-1).startsWith('proxypilot-offline-window-')); await rm(parent, { recursive: true, force: true }); }
}

test('paid offline windows are selectable and bounded by software expiry; resource reminders stay independent and online refresh remains 72h', async () => fixture(async directory => {
  const signing = keys(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    for (const days of [1, 3, 7, 15, 30]) {
      const d = device(String(days).padStart(2, '0').repeat(32));
      const token = store.activateOffline(application(d), { orderId: `days-${days}`, paid: true, resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: start + 35 * DAY, offlineDays: days });
      assert.equal(verified(token, signing, d, now).offlineUntil, start + days * DAY);
      assert.equal(store.row(token.payload.licenseId).offline_window_ms, days * DAY);
      if (days === 30) {
        now += DAY;
        const online = store.refresh(application(d, 'refresh', { licenseId: token.payload.licenseId }));
        assert.equal(online.payload.offlineUntil, now + LICENSE_LEASE_MS);
        assert.equal(store.row(token.payload.licenseId).offline_window_ms, 30 * DAY);
        const backOffline = store.refreshOfflineById(token.payload.licenseId);
        assert.equal(backOffline.payload.offlineUntil, start + LICENSE_TERM_MS);
        store.resources(token.payload.licenseId, { resourcesReady: true, ispExpiresAt: now + 12 * DAY, vpsExpiresAt: now + 9 * DAY, offlineDays: 15 });
        const capped = store.refreshOfflineById(token.payload.licenseId, { offlineDays: 15 });
        assert.equal(capped.payload.offlineUntil, now + 15 * DAY);
        assert.equal(capped.payload.expiresAt, token.payload.expiresAt);
        for (const invalid of [0, 2, 31, '30']) assert.throws(() => store.refreshOfflineById(token.payload.licenseId, { offlineDays: invalid }), { code: 'INVALID_OFFLINE_WINDOW' });
      }
    }
    assert.equal(store.list().orders.length, 5);
  } finally { store.close(); }
}));

test('trial is one day with no fake revenue, same-device retry cannot extend, paid conversion keeps ID and starts now', async () => fixture(async directory => {
  const signing = keys(), d = device(); let now = Date.now(); const start = now;
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { ...signing, now: () => now });
  try {
    const resources = { resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: null };
    const trial = store.trialOffline(application(d), resources), id = trial.payload.licenseId;
    assert.equal(trial.payload.plan, LICENSE_TRIAL_PLAN); assert.equal(trial.payload.expiresAt, start + DAY); assert.equal(trial.payload.offlineUntil, start + DAY);
    assert.equal(store.list().orders.length, 0);
    now += DAY / 2;
    assert.deepEqual(store.trialOffline(application(d), resources), trial);
    assert.equal(store.refreshOfflineById(id).payload.expiresAt, trial.payload.expiresAt);
    assert.throws(() => store.refreshOfflineById(id, { offlineDays: 30 }), { code: 'TRIAL_WINDOW_FIXED' });
    const paid = store.renew(id, { ...resources, paid: true, orderId: 'trial-conversion' });
    assert.equal(paid.payload.licenseId, id); assert.equal(paid.payload.plan, LICENSE_PLAN); assert.equal(paid.payload.expiresAt, now + LICENSE_TERM_MS);
    assert.equal(paid.payload.offlineUntil, paid.payload.expiresAt);
    assert.equal(store.list().orders.length, 1); assert.equal(store.list().orders[0].amount_fen, 10000);
    assert.deepEqual(store.renew(id, { ...resources, paid: true, orderId: 'trial-conversion' }), paid);
    assert.throws(() => store.trialOffline(application(d), resources), { code: 'TRIAL_UNAVAILABLE' });
    const renewal = store.renew(id, { ...resources, paid: true, orderId: 'next-paid', ispExpiresAt: now + 100 * DAY });
    assert.equal(renewal.payload.expiresAt, paid.payload.expiresAt + LICENSE_TERM_MS);
    const copied = device(d.id);
    assert.throws(() => store.trialOffline(application(copied), resources), { code: 'TRIAL_UNAVAILABLE' });
    const other = device('b'.repeat(64));
    const short = store.trialOffline(application(other), { ...resources, ispExpiresAt: now + DAY / 4 });
    assert.equal(short.payload.offlineUntil, now + DAY);
    now += 2 * DAY;
    assert.equal(store.trialOffline(application(other), resources).payload.expiresAt, short.payload.expiresAt);
    assert.throws(() => verified(short, signing, other, now), { code: 'LICENSE_EXPIRED' });
  } finally { store.close(); }
}));

test('legacy database migration preserves signed 72h payload and offline default until explicitly changed', async () => fixture(async directory => {
  const signing = keys(), d = device(), now = Date.now(), id = randomUUID(), file = join(directory, 'old.sqlite');
  const db = new DatabaseSync(file);
  db.exec('CREATE TABLE licenses(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,device_key_hash TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL,expires_at INTEGER NOT NULL,isp_expires_at INTEGER NOT NULL,vps_expires_at INTEGER,resources_ready INTEGER NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)');
  db.prepare('INSERT INTO licenses VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id, d.id, publicKeyHash(d.publicPem), 4, 'active', now + LICENSE_TERM_MS, now + 90 * DAY, null, 1, now, now); db.close();
  const old = signLicense({ version: 1, licenseId: id, deviceId: d.id, deviceKeyHash: publicKeyHash(d.publicPem), generation: 4, plan: LICENSE_PLAN, status: 'active', issuedAt: now, expiresAt: now + LICENSE_TERM_MS, offlineUntil: now + LICENSE_LEASE_MS, ispExpiresAt: now + 90 * DAY, vpsExpiresAt: null }, signing);
  const store = new LicenseStore(file, { ...signing, now: () => now + DAY });
  try {
    assert.deepEqual(store.status(id), old);
    assert.equal(store.row(id).plan, LICENSE_PLAN); assert.equal(store.row(id).offline_window_ms, LICENSE_LEASE_MS);
    assert.equal(store.refreshOfflineById(id).payload.offlineUntil, now + 4 * DAY);
    const long = store.refreshOfflineById(id, { offlineDays: 30 }); assert.equal(long.payload.offlineUntil, now + LICENSE_TERM_MS);
    assert.equal(verified(long, signing, d, now + DAY).version, 2);
    assert.equal(long.payload.resourcesMode, 'included');
    assert.ok(long.payload.generation > old.payload.generation);
  } finally { store.close(); }
}));

test('CLI and native generator issue customer ISP licenses without supplier inputs and reports never charge a fake ISP cost', async () => fixture(async directory => {
  const initialized = await runAdmin(['init', '--dir', join(directory, 'customer-state'), '--offline']);
  const d = device(), requestPath = join(directory, 'customer-request.json');
  await writeFile(requestPath, JSON.stringify(application(d)));
  const common = ['--config', initialized.serverConfig];
  const trial = await runAdmin(['trial-offline', ...common, '--application', requestPath, '--resources-mode', 'customer']);
  assert.equal(trial.payload.resourcesMode, 'customer'); assert.equal(trial.payload.ispExpiresAt, null);
  const paid = await runAdmin(['renew', ...common, '--license-id', trial.payload.licenseId, '--order-id', 'self-cli', '--paid']);
  assert.equal(paid.payload.resourcesMode, 'customer'); assert.equal(paid.payload.offlineUntil, paid.payload.expiresAt);
  const list = await runLicensingAction({ action: 'customers', configPath: initialized.serverConfig });
  assert.equal(list.summary.totalReceivedFen, 10000); assert.equal(list.summary.totalIspCostFen, 0);
  assert.equal(list.orders[0].ispCostFen, 0); assert.equal(list.orders[0].resourcesMode, 'customer');
  assert.equal(list.customers[0].resourceStatus, 'customer'); assert.equal(list.customers[0].status, 'active');
  const update = await runLicensingAction({ action: 'resources', configPath: initialized.serverConfig, licenseId: trial.payload.licenseId, resourcesMode: 'included', resourcesReady: true, ispExpiresAt: Date.now() - DAY, vpsExpiresAt: Date.now() - DAY, outputPath: join(directory, 'expired-resources.json') });
  assert.equal(update.license.status, 'active'); assert.equal(update.license.expiresAt, paid.payload.expiresAt);
  assert.equal(update.customers[0].resourceStatus, 'expired'); assert.equal(update.summary.totalIspCostFen, 0);
  const renewed = await runLicensingAction({ action: 'renew', configPath: initialized.serverConfig, licenseId: trial.payload.licenseId, orderId: 'included-cli-next', paid: true, resourcesMode: 'included', resourcesReady: true, ispExpiresAt: Date.now() + 100 * DAY, vpsExpiresAt: Date.now() - DAY, outputPath: join(directory, 'optional-expired-vps.json') });
  assert.equal(renewed.license.status, 'active'); assert.equal(renewed.summary.totalIspCostFen, 3500);
  const cleared = await runLicensingAction({ action: 'renew', configPath: initialized.serverConfig, licenseId: trial.payload.licenseId, orderId: 'clear-optional-vps', paid: true, resourcesReady: true, ispExpiresAt: Date.now() + 100 * DAY, vpsExpiresAt: null, outputPath: join(directory, 'no-vps.json') });
  assert.equal(cleared.license.vpsExpiresAt, null); assert.equal(cleared.summary.totalReceivedFen, 30000);
}));

test('UI generator writes only signed customer outputs, safe summaries and rolls back delivery failure', async () => fixture(async directory => {
  const initialized = await runAdmin(['init', '--dir', join(directory, 'state'), '--offline']), d = device(), start = Date.now();
  const configPath = initialized.serverConfig, applicationEnvelope = application(d), resources = { resourcesReady: true, ispExpiresAt: start + 100 * DAY, vpsExpiresAt: null };
  const trialOutput = join(directory, 'trial.json');
  const trial = await runLicensingAction({ action: 'trial', configPath, applicationEnvelope, ...resources, outputPath: trialOutput });
  assert.equal(trial.license.plan, LICENSE_TRIAL_PLAN); assert.equal(trial.summary.totalReceivedFen, 0); assert.equal(trial.orders.length, 0);
  assert.equal(trial.customers[0].deviceId, d.id); assert.equal(trial.customers[0].offlineDays, 1); assert.match(trial.publicKeyFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(Object.hasOwn(trial, 'signature'), false); assert.equal(JSON.stringify(trial).includes('PRIVATE KEY'), false);
  assert.equal(JSON.parse(await readFile(trialOutput, 'utf8')).payload.plan, LICENSE_TRIAL_PLAN);
  const paid = await runLicensingAction({ action: 'renew', configPath, licenseId: trial.license.licenseId, orderId: 'gui-paid', paid: true, ...resources, outputPath: join(directory, 'paid.json') });
  assert.equal(paid.license.plan, LICENSE_PLAN); assert.equal(paid.customers[0].offlineDays, 30); assert.equal(paid.summary.revenueFen, 10000); assert.equal(paid.summary.totalIspCostFen, 3500);
  const refreshed = await runLicensingAction({ action: 'refresh', configPath, licenseId: paid.license.licenseId, offlineDays: 7, outputPath: join(directory, 'refresh.json') });
  assert.equal(refreshed.license.expiresAt, paid.license.expiresAt); assert.equal(refreshed.orders.length, 1); assert.equal(refreshed.customers[0].offlineDays, 7);
  const list = await runLicensingAction({ action: 'customers', configPath }); assert.equal(list.keyId, 'license-1'); assert.equal(list.orders[0].orderId, 'gui-paid');
  assert.equal(Object.hasOwn(list, 'outputPath'), false); assert.equal(JSON.stringify(list).includes('signature'), false);
  const signing = keys(), failStore = new LicenseStore(join(directory, 'fail.sqlite'), { ...signing, deliver: () => { throw new Error('delivery failed'); } });
  try {
    assert.throws(() => failStore.trialOffline(application(device('c'.repeat(64))), resources), /delivery failed/); assert.equal(failStore.list().licenses.length, 0);
    assert.throws(() => failStore.activateOffline(application(device('d'.repeat(64))), { ...resources, paid: true, orderId: 'not-delivered' }), /delivery failed/); assert.equal(failStore.list().orders.length, 0);
  } finally { failStore.close(); }
}));

test('CLI trial and configurable offline refresh do not record payment until explicit conversion', async () => fixture(async directory => {
  const initialized = await runAdmin(['init', '--dir', join(directory, 'state'), '--offline']), d = device(), appFile = join(directory, 'application.json');
  await writeFile(appFile, JSON.stringify(application(d)));
  const trial = await runAdmin(['trial-offline', '--config', initialized.serverConfig, '--application', appFile, '--resources-ready', '--isp-expires', String(Date.now() + 90 * DAY)]);
  assert.equal(trial.payload.plan, LICENSE_TRIAL_PLAN);
  const paid = await runAdmin(['renew', '--config', initialized.serverConfig, '--license-id', trial.payload.licenseId, '--order-id', 'cli-paid', '--paid', '--resources-ready', '--isp-expires', String(Date.now() + 90 * DAY), '--offline-days', '15']);
  assert.equal(paid.payload.plan, LICENSE_PLAN); assert.equal(paid.payload.offlineUntil, paid.payload.issuedAt + 15 * DAY);
  assert.deepEqual(await runAdmin(['renew', '--config', initialized.serverConfig, '--license-id', trial.payload.licenseId, '--order-id', 'cli-paid']), paid);
  const fresh = await runAdmin(['refresh-offline', '--config', initialized.serverConfig, '--license-id', paid.payload.licenseId, '--offline-days', '30']);
  assert.equal(fresh.payload.expiresAt, paid.payload.expiresAt); assert.equal((await runAdmin(['list', '--config', initialized.serverConfig])).orders.length, 1);
}));
test('post-commit summary failure returns saved success and keeps the paid output and ledger', async () => fixture(async directory => {
  const initialized = await runAdmin(['init', '--dir', join(directory, 'state'), '--offline']), d = device(), start = Date.now(), originalNow = Date.now;
  const outputPath = join(directory, 'saved-paid.json'), applicationEnvelope = application(d); let calls = 0, result;
  try {
    Date.now = () => ++calls === 1 ? start : start - 1;
    result = await runLicensingAction({ action: 'activate', configPath: initialized.serverConfig, applicationEnvelope, outputPath,
      paid: true, orderId: 'saved-before-summary-error', resourcesReady: true, ispExpiresAt: start + 40 * DAY, vpsExpiresAt: null });
  } finally { Date.now = originalNow; }
  assert.equal(result.summaryError, 'SUMMARY_UNAVAILABLE'); assert.equal(result.summaryUnavailable, true);
  assert.equal(result.outputPath, resolve(outputPath)); assert.equal(result.license.plan, LICENSE_PLAN);
  const saved = JSON.parse(await readFile(outputPath, 'utf8'));
  assert.equal(saved.payload.licenseId, result.license.licenseId);
  const ledger = await runAdmin(['list', '--config', initialized.serverConfig]);
  assert.equal(ledger.orders.length, 1); assert.equal(ledger.orders[0].amount_fen, 10000); assert.equal(ledger.licenses.length, 1);
}));

test('GUI and CLI reject a short paid delivery without leaving an output or charging/converting the customer', async () => fixture(async directory => {
  const initialized = await runAdmin(['init', '--dir', join(directory, 'state'), '--offline']), d = device(), start = Date.now();
  const applicationEnvelope = application(d), appFile = join(directory, 'application.json');
  await writeFile(appFile, JSON.stringify(applicationEnvelope));
  const trial = await runLicensingAction({ action: 'trial', configPath: initialized.serverConfig, applicationEnvelope, outputPath: join(directory, 'trial.json'), resourcesReady: true, ispExpiresAt: start + DAY });
  const original = await runAdmin(['list', '--config', initialized.serverConfig]);
  for (const path of ['gui-short.json', 'cli-short.json']) {
    const outputPath = join(directory, path);
    if (path.startsWith('gui')) await assert.rejects(runLicensingAction({ action: 'renew', configPath: initialized.serverConfig, licenseId: trial.license.licenseId, orderId: 'short-gui', paid: true, resourcesReady: true, ispExpiresAt: start + DAY, offlineDays: 1, outputPath }), { code: 'RESOURCE_TERM_TOO_SHORT' });
    else await assert.rejects(runAdmin(['renew', '--config', initialized.serverConfig, '--license-id', trial.license.licenseId, '--order-id', 'short-cli', '--paid', '--resources-ready', '--isp-expires', String(start + DAY), '--offline-days', '1', '--out', outputPath]), { code: 'RESOURCE_TERM_TOO_SHORT' });
    await assert.rejects(access(outputPath), { code: 'ENOENT' });
    assert.deepEqual(await runAdmin(['list', '--config', initialized.serverConfig]), original);
  }
}));
