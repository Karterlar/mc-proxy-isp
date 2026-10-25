import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { createLicenseClient } from '../../backend/src/license-client.mjs';
import { createLicenseAdmin } from '../licensing-admin.mjs';
import { initializeLicensing } from '../../tools/licensing/admin.mjs';
import { parseCustomerDelivery } from '../../backend/src/customer-delivery.mjs';
import { vpnYamlNode } from '../../backend/test/vpn-fixture.mjs';

const DAY = 86400000;
test('actual isolated signing bridge issues a free trial, upgrades it, refreshes without charging and handles rebind/revoke', async t => {
  const base = path.resolve('.cache'); await mkdir(base, { recursive: true });
  const root = await mkdtemp(path.join(base, 'admin-client-integration-'));
  const directory = path.join(root, 'private'), customers = []; let stamp = Date.now(), counter = 0, deliveryLicensePath;
  t.after(async () => { customers.forEach(client => client.close()); assert(path.relative(base, root).startsWith('admin-client-integration-')); await rm(root, { recursive: true, force: true }); });
  await initializeLicensing({ dir: directory, offline: true });
  const config = JSON.parse(await readFile(path.join(directory, 'client-config.template.json'), 'utf8'));
  const admin = createLicenseAdmin({ enabled: true, settingsPath: path.join(root, 'selected.json'),
    chooseStore: async () => directory, chooseLicenseInput: async () => deliveryLicensePath,
    chooseOutput: async suggested => path.join(root, suggested.endsWith('.mcproxy.json') ? suggested : `license-${++counter}.json`) });
  assert.equal((await admin.selectStore()).configured, true);
  async function client(name) {
    const current = createLicenseClient({ config, stateDir: path.join(root, name), now: () => stamp,
      getDeviceIdentity: async () => `synthetic-${name}`, request: () => assert.fail('offline issuer must not contact any network'),
      dependencies: { monotonic: () => 0, createPrivateDirectory: target => mkdir(target, { mode: 0o700 }) } });
    customers.push(current); await current.initialize(); return current;
  }
  const first = await client('first'), ispExpiresAt = stamp + 90 * DAY;
  const trial = await admin.generate({ action: 'trial', applicationText: first.deviceApplication(), resourcesReady: true, ispExpiresAt, offlineDays: 1 });
  assert.equal(trial.saved, true);
  assert.equal((await first.importLicense(await readFile(trial.filePath, 'utf8'))).allowed, true);
  assert.equal(first.status().plan, 'isp-1d-trial'); assert.equal(first.status().priceCny, 0);
  let listing = await admin.status(); assert.equal(listing.customers.length, 1); assert.equal(listing.orders.length, 0);
  const id = first.status().licenseId;
  const beforePaid = listing;
  await assert.rejects(admin.generate({ action: 'renew', licenseId: id, orderId: 'unconfirmed' }), { code: 'PAYMENT_NOT_CONFIRMED' });
  await assert.rejects(admin.generate({ action: 'renew', licenseId: id, orderId: 'missing-resource', paidConfirmed: true }), { code: 'RESOURCE_NOT_READY' });
  await assert.rejects(admin.generate({ action: 'renew', licenseId: id, orderId: 'short-resource', paidConfirmed: true, resourcesReady: true, ispExpiresAt: stamp + DAY, offlineDays: 1 }), { code: 'RESOURCE_TERM_TOO_SHORT' });
  assert.deepEqual(await admin.status(), beforePaid);
  for (let failed = 2; failed <= counter; failed++) await assert.rejects(readFile(path.join(root, `license-${failed}.json`)), { code: 'ENOENT' });
  const paid = await admin.generate({ action: 'renew', licenseId: id, orderId: 'synthetic-paid-0001', paidConfirmed: true,
    resourcesReady: true, ispExpiresAt, offlineDays: 30 });
  await first.importLicense(await readFile(paid.filePath, 'utf8'));
  assert.equal(first.status().licenseId, id); assert.equal(first.status().plan, 'isp-30d-single');
  assert.equal(first.status().expiresAt - first.status().issuedAt, 30 * DAY);
  assert.equal(first.status().offlineUntil, first.status().expiresAt);
  listing = await admin.status(); assert.equal(listing.customers.length, 1); assert.equal(listing.orders.length, 1);
  assert.equal(listing.orders[0].amountFen, 10000);
  const retried = await admin.generate({ action: 'renew', licenseId: id, orderId: 'synthetic-paid-0001' });
  assert.equal(retried.saved, true); assert.deepEqual(JSON.parse(await readFile(retried.filePath, 'utf8')), JSON.parse(await readFile(paid.filePath, 'utf8')));
  assert.equal((await admin.status()).orders.length, 1);
  const refreshed = await admin.generate({ action: 'refresh', licenseId: id, offlineDays: 30 });
  await first.importLicense(await readFile(refreshed.filePath, 'utf8'));
  assert.equal((await admin.status()).orders.length, 1);
  const deliveryInput = { connectionMode: 'vpn-import', takeoverMode: 'global', vpnText: JSON.stringify({ proxies: [vpnYamlNode()] }),
    isp: { type: 'socks', host: '192.0.2.55', port: 1080, username: 'test-user', password: 'test-secret', expectedExitIps: ['203.0.113.8'] } };
  deliveryLicensePath = trial.filePath;
  await assert.rejects(admin.exportDelivery(deliveryInput), { code: 'DELIVERY_LICENSE_STALE' });
  deliveryLicensePath = refreshed.filePath;
  const beforeExport = await admin.status();
  const delivery = await admin.exportDelivery(deliveryInput);
  assert.equal(delivery.saved, true);
  assert.equal(parseCustomerDelivery(await readFile(delivery.filePath, 'utf8')).licenseText, await readFile(refreshed.filePath, 'utf8'));
  assert.deepEqual(await admin.status(), beforeExport, 'delivery composition cannot sign, charge or change the current customer generation');
  assert.doesNotMatch(JSON.stringify(delivery), /test-secret|test-user|192\.0\.2\.55|BEGIN PRIVATE KEY/);
  stamp += 2 * DAY;
  assert.equal(first.assertAllowed().allowed, true, 'a full-period offline customer should not need a 72-hour refresh');
  // A second device owns a different key. Rebinding preserves the original paid
  // expiry and fails closed if the old device observes the replacement token.
  const replacement = await client('replacement');
  const rebound = await admin.generate({ action: 'rebind', licenseId: id, applicationText: replacement.deviceApplication(), offlineDays: 30 });
  const reboundText = await readFile(rebound.filePath, 'utf8');
  assert.equal((await replacement.importLicense(reboundText)).licenseId, id);
  await first.importLicense(reboundText);
  assert.equal(first.status().allowed, false);
  const revoked = await admin.generate({ action: 'revoke', licenseId: id });
  await replacement.importLicense(await readFile(revoked.filePath, 'utf8'));
  assert.equal(replacement.status().status, 'revoked'); assert.equal(replacement.status().allowed, false);
  assert.equal((await admin.status()).orders.length, 1);
});
