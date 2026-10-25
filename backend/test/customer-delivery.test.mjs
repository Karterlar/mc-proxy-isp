import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, writeFile, rm, rename, link, symlink } from 'node:fs/promises';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createCustomerDelivery, parseCustomerDelivery, customerDeliveryPreview, customerDeliveryConfiguration,
  verifyCustomerDeliveryLicense, createCustomerDeliveryTransaction, CUSTOMER_DELIVERY_MAX_BYTES } from '../src/customer-delivery.mjs';
import { signLicense, signDeviceRequest, publicKeyHash } from '../src/license-format.mjs';
import { vpnYamlNode } from './vpn-fixture.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';

const pair = generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
const now = Date.now(), deviceId = 'a'.repeat(64), deviceKeyHash = 'b'.repeat(64);
function grant(changes = {}) {
  return signLicense({ version: 2, licenseId: randomUUID(), deviceId, deviceKeyHash, generation: 1, plan: 'isp-30d-single', status: 'active',
    issuedAt: now, expiresAt: now + 30 * 86400000, offlineUntil: now + 86400000, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null, ...changes }, { keyId: 'test', privateKey: pair.privateKey });
}
function input(changes = {}) {
  return { licenseText: `\uFEFF${JSON.stringify(grant(), null, 2)}\n`, connectionMode: 'vpn-import', takeoverMode: 'global',
    vpnText: JSON.stringify({ proxies: [vpnYamlNode()] }),
    isp: { type: 'socks', host: '192.0.2.55', port: 35959, username: 'synthetic-user', password: 'synthetic-password', expectedExitIps: ['203.0.113.8'] }, ...changes };
}
const context = { publicKeys: { test: publicKey }, deviceId, deviceKeyHash, now };

test('container preserves the exact existing license and supports the original VPN parser without leaking credentials in preview', () => {
  const original = input(), serialized = createCustomerDelivery(original), parsed = parseCustomerDelivery(serialized);
  assert.equal(parsed.licenseText, original.licenseText); assert.equal(parsed.vpnText, original.vpnText);
  assert.equal(verifyCustomerDeliveryLicense(parsed, context).deviceId, deviceId);
  const preview = customerDeliveryPreview(serialized);
  assert.equal(preview.vpn.supported, 1); assert.equal(preview.license.verified, false); assert.equal(preview.isp.pinnedExits, 1);
  for (const secret of [original.isp.host, original.isp.username, original.isp.password, deviceId, deviceKeyHash, 'vpn.private.invalid', '11111111-2222-4333-8444-555555555555']) assert(!JSON.stringify(preview).includes(secret));
  const prepared = customerDeliveryConfiguration(parsed);
  assert.equal(prepared.config.connectionMode, 'vpn-import'); assert.equal(prepared.secrets.ISP_PASSWORD, original.isp.password);
  assert.equal(prepared.config.relay, undefined);
});

test('new wrapper accepts signed legacy grants without changing their original resource boundary', () => {
  const envelope = grant(); delete envelope.payload.resourcesMode;
  const old = signLicense({ ...envelope.payload, version: 1, ispExpiresAt: now + 86400000 }, { keyId: 'test', privateKey: pair.privateKey });
  const text = `${JSON.stringify(old)}\r\n`, delivery = createCustomerDelivery(input({ licenseText: text }));
  assert.equal(parseCustomerDelivery(delivery).licenseText, text);
  assert.equal(verifyCustomerDeliveryLicense(delivery, context).version, 1);
  assert.throws(() => verifyCustomerDeliveryLicense(delivery, { ...context, now: now + 86400001 }), { code: 'LICENSE_EXPIRED' });
});

test('foreign, expired, revoked and tampered licenses cannot pass import preflight', () => {
  const delivery = createCustomerDelivery(input());
  assert.throws(() => verifyCustomerDeliveryLicense(delivery, { ...context, deviceId: 'c'.repeat(64) }), { code: 'DEVICE_MISMATCH' });
  assert.throws(() => verifyCustomerDeliveryLicense(delivery, { ...context, now: now + 86400001 }), { code: 'LICENSE_EXPIRED' });
  assert.throws(() => verifyCustomerDeliveryLicense(createCustomerDelivery(input({ licenseText: JSON.stringify(grant({ status: 'revoked' })) })), context), { code: 'DELIVERY_LICENSE_INACTIVE' });
  const altered = grant(); altered.payload.expiresAt++;
  assert.throws(() => verifyCustomerDeliveryLicense(createCustomerDelivery(input({ licenseText: JSON.stringify(altered) })), context), { code: 'INVALID_SIGNATURE' });
});

test('signed local device applications can supply identity for the unchanged license verifier', () => {
  const device = generateKeyPairSync('ed25519'), devicePublicKey = device.publicKey.export({ type: 'spki', format: 'pem' });
  const application = signDeviceRequest({ version: 1, action: 'offline', requestId: randomUUID(), deviceId, devicePublicKey }, device.privateKey);
  const license = grant({ deviceKeyHash: publicKeyHash(devicePublicKey) });
  assert.equal(verifyCustomerDeliveryLicense(createCustomerDelivery(input({ licenseText: JSON.stringify(license) })), { publicKeys: { test: publicKey }, deviceApplication: JSON.stringify(application), now }).deviceId, deviceId);
});

test('container trust boundary rejects unknown fields, credentials in URLs, oversize input, unsupported modes and incomplete ISP data', () => {
  const examples = [input({ privateKey: 'secret' }), input({ device: { privateKey: 'secret' } }), input({ profiles: [] }), input({ filePath: '../../other' }),
    input({ connectionMode: 'direct' }), input({ takeoverMode: 'auto' }), input({ vpnText: 'nothing supported' }),
    input({ isp: { ...input().isp, host: 'http://user:pass@host/' } }), input({ isp: { ...input().isp, username: '' } }),
    input({ isp: { ...input().isp, port: 65536 } }), input({ isp: { ...input().isp, expectedExitIps: ['not-an-ip'] } }),
    input({ reminders: { vpnExpiresAt: -1 } }), input({ reminders: { licenseExpiresAt: now } })];
  for (const value of examples) assert.throws(() => createCustomerDelivery(value));
  assert.throws(() => parseCustomerDelivery('x'.repeat(CUSTOMER_DELIVERY_MAX_BYTES + 1)), { code: 'DELIVERY_SIZE_INVALID' });
  assert.throws(() => parseCustomerDelivery('{'), { code: 'DELIVERY_INVALID' });
});

test('relay capability is explicit and cannot accidentally invent a VPN to VPS chain', () => {
  const plain = input({ connectionMode: 'relay' }); delete plain.vpnText;
  assert.equal(customerDeliveryPreview(createCustomerDelivery(plain)).relay.enrollmentRequired, true);
  const relay = { config: relayFixture(), secrets: relaySecrets };
  const composed = parseCustomerDelivery(createCustomerDelivery({ ...plain, relay }));
  assert.deepEqual(customerDeliveryConfiguration(composed).config.relay, relayFixture());
  assert.equal(customerDeliveryPreview(composed).relay.included, true);
  assert.throws(() => createCustomerDelivery(input({ relay })), { code: 'DELIVERY_MODE_INVALID' });
  assert.throws(() => createCustomerDelivery({ ...plain, vpnText: input().vpnText }), { code: 'DELIVERY_MODE_INVALID' });
});

async function fixture(t, dependencies = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.delivery-test-'));
  t.after(async () => { assert(path.basename(root).startsWith('.delivery-test-')); await rm(root, { recursive: true, force: true }); });
  const fs = { createPrivateDirectory: target => mkdir(target, { mode: 0o700 }), ...dependencies };
  return { root, options: { runtimeRoot: root, dependencies: fs }, manager: createCustomerDeliveryTransaction({ runtimeRoot: root, dependencies: fs }),
    journal: path.join(root, '.customer-delivery', 'pending.json') };
}

test('transaction commits all prepared files, invokes licensing last and never touches identity or browser profiles', async t => {
  const f = await fixture(t), marker = path.join(f.root, '.license', 'device.json');
  await mkdir(path.dirname(marker)); await writeFile(marker, 'untouched synthetic identity');
  await writeFile(path.join(f.root, 'config.json'), 'old config');
  const files = { config: 'new config', secrets: 'new secrets', vpn: 'new nodes', preferences: 'new preferences' };
  const result = await f.manager.commit({ files, finalize: async () => {
    assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), files.config);
    assert.equal(await readFile(path.join(f.root, '.vpn-config', 'nodes.json'), 'utf8'), files.vpn);
    return { allowed: true };
  } });
  assert.equal(result.allowed, true); assert.equal(await readFile(marker, 'utf8'), 'untouched synthetic identity');
  await assert.rejects(readFile(f.journal), { code: 'ENOENT' });
});

test('failed verification/final license import restores every previous byte and removes new configuration files', async t => {
  const f = await fixture(t), original = '{"old":"配置"}\r\n';
  await writeFile(path.join(f.root, 'config.json'), original);
  await assert.rejects(f.manager.commit({ files: { config: 'next', secrets: 'new' }, licenseText: input().licenseText,
    finalize: async () => { throw Object.assign(new Error('LICENSE_REPLAY'), { code: 'LICENSE_REPLAY' }); } }), { code: 'LICENSE_REPLAY' });
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), original);
  await assert.rejects(readFile(path.join(f.root, 'upstream.secrets.env')), { code: 'ENOENT' });
  await assert.rejects(readFile(f.journal), { code: 'ENOENT' });
});

test('partial writes roll back before returning a failure', async t => {
  let once = true;
  const f = await fixture(t, { rename: async (from, to) => {
    if (to.endsWith('upstream.secrets.env') && once) { once = false; throw Object.assign(new Error('simulated disk failure'), { code: 'ENOSPC' }); }
    return rename(from, to);
  } });
  await writeFile(path.join(f.root, 'config.json'), 'original');
  await assert.rejects(f.manager.commit({ files: { config: 'next', secrets: 'new' }, finalize: () => assert.fail('license must not import on partial write') }), { code: 'ENOSPC' });
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'original');
});

test('startup resolves crash after final grant save as committed, and crash before final save as rollback', async t => {
  for (const saved of [false, true]) {
    const f = await fixture(t), licenseText = input().licenseText;
    await writeFile(path.join(f.root, 'config.json'), 'original');
    let journal;
    await f.manager.commit({ files: { config: 'next' }, licenseText, finalize: async () => {
      journal = await readFile(f.journal, 'utf8');
      if (saved) { await mkdir(path.join(f.root, '.license')); await writeFile(path.join(f.root, '.license', 'state.json'), JSON.stringify({ record: { license: JSON.parse(licenseText.replace(/^\uFEFF/, '')) } })); }
    } });
    await writeFile(f.journal, journal);
    const result = await createCustomerDeliveryTransaction(f.options).recover();
    assert.equal(result.committed, saved);
    assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), saved ? 'next' : 'original');
  }
});

test('a final signed grant remains a reported commit when writing the delivery receipt fails', async t => {
  const licenseText = input().licenseText; let receiptWrites = 0;
  const f = await fixture(t, { rename: async (from, to) => {
    if (to.endsWith(path.join('.customer-delivery', 'pending.json')) && ++receiptWrites === 3) throw Object.assign(new Error('receipt write unavailable'), { code: 'EACCES' });
    return rename(from, to);
  } });
  await writeFile(path.join(f.root, 'config.json'), 'old');
  const result = await f.manager.commit({ files: { config: 'new' }, licenseText, finalize: async () => {
    await mkdir(path.join(f.root, '.license'));
    await writeFile(path.join(f.root, '.license', 'state.json'), JSON.stringify({ record: { license: JSON.parse(licenseText.replace(/^\uFEFF/, '')) } }));
    return { allowed: true };
  } });
  assert.equal(result.deliveryCommitted, true); assert.equal(result.cleanupPending, true); assert.equal(result.allowed, true);
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'new');
  assert.equal(JSON.parse(await readFile(f.journal, 'utf8')).phase, 'finalizing');
  assert.equal((await createCustomerDeliveryTransaction(f.options).recover()).committed, true);
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'new');
});

test('reimporting an identical grant then canceling finalization rolls configuration back without rewriting license state', async t => {
  const f = await fixture(t), licenseText = input().licenseText;
  await mkdir(path.join(f.root, '.license'));
  const licenseFile = path.join(f.root, '.license', 'state.json'), licenseBytes = JSON.stringify({ record: { license: JSON.parse(licenseText.replace(/^\uFEFF/, '')) } });
  await writeFile(licenseFile, licenseBytes); await writeFile(path.join(f.root, 'config.json'), 'old');
  await assert.rejects(f.manager.commit({ files: { config: 'new' }, licenseText, finalize: async () => { throw Object.assign(new Error('canceled before no-op grant save'), { code: 'CONNECTION_CANCELED' }); } }), { code: 'CONNECTION_CANCELED' });
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'old');
  assert.equal(await readFile(licenseFile, 'utf8'), licenseBytes);
});

test('identical grant crash before a committed receipt rolls back, while its normal successful reimport commits', async t => {
  const f = await fixture(t), licenseText = input().licenseText;
  await mkdir(path.join(f.root, '.license'));
  const licenseFile = path.join(f.root, '.license', 'state.json'), licenseBytes = JSON.stringify({ record: { license: JSON.parse(licenseText.replace(/^\uFEFF/, '')) } });
  await writeFile(licenseFile, licenseBytes); await writeFile(path.join(f.root, 'config.json'), 'old');
  let pending;
  assert.equal((await f.manager.commit({ files: { config: 'new' }, licenseText, finalize: async () => { pending = await readFile(f.journal, 'utf8'); } })).deliveryCommitted, true);
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'new');
  await writeFile(f.journal, pending);
  assert.equal((await createCustomerDeliveryTransaction(f.options).recover()).committed, false);
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'old');
  assert.equal(await readFile(licenseFile, 'utf8'), licenseBytes);
});

test('a license-free import safely restores old files if its commit receipt cannot persist', async t => {
  let receiptWrites = 0;
  const f = await fixture(t, { rename: async (from, to) => {
    if (to.endsWith(path.join('.customer-delivery', 'pending.json')) && ++receiptWrites === 3) throw Object.assign(new Error('receipt write unavailable'), { code: 'EACCES' });
    return rename(from, to);
  } });
  await writeFile(path.join(f.root, 'config.json'), 'old');
  await assert.rejects(f.manager.commit({ files: { config: 'new' }, finalize: async () => {} }), { code: 'EACCES' });
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'old');
});

test('recovery preserves external edits and blocks untrusted journal paths or a pending onboarding transaction', async t => {
  const f = await fixture(t); let journal;
  await writeFile(path.join(f.root, 'config.json'), 'old');
  await f.manager.commit({ files: { config: 'new' }, finalize: async () => { journal = JSON.parse(await readFile(f.journal, 'utf8')); } });
  await writeFile(f.journal, JSON.stringify(journal)); await writeFile(path.join(f.root, 'config.json'), 'external');
  await assert.rejects(f.manager.recover(), { code: 'DELIVERY_CONFLICT' });
  assert.equal(await readFile(path.join(f.root, 'config.json'), 'utf8'), 'external');
  journal.files.device = journal.files.config; delete journal.files.config;
  await writeFile(f.journal, JSON.stringify(journal));
  await assert.rejects(f.manager.recover(), { code: 'DELIVERY_RECOVERY_REQUIRED' });
  await rm(f.journal); await mkdir(path.join(f.root, '.onboarding')); await writeFile(path.join(f.root, '.onboarding', 'pending.json'), '{}');
  await assert.rejects(f.manager.commit({ files: { config: 'new' }, finalize: () => {} }), { code: 'DELIVERY_RECOVERY_REQUIRED' });
});

test('transaction rejects device/private-store targets and linked files', async t => {
  const f = await fixture(t);
  for (const file of [path.resolve(f.root, '..', 'elsewhere'), path.join(f.root, '.license', 'state.json'), path.join(f.root, '.license', 'device.json')])
    assert.throws(() => createCustomerDeliveryTransaction({ ...f.options, configPath: file }), { code: 'DELIVERY_PATH_INVALID' });
  await assert.rejects(f.manager.commit({ files: { device: '{}' }, finalize: () => {} }), { code: 'DELIVERY_INVALID' });
  const config = path.join(f.root, 'config.json'); await writeFile(config, 'old'); await link(config, path.join(f.root, 'hardlink.json'));
  await assert.rejects(f.manager.commit({ files: { config: 'new' }, finalize: () => {} }), { code: 'DELIVERY_STATE_INVALID' });
  await rm(path.join(f.root, 'hardlink.json')); await rm(config);
  await mkdir(path.join(f.root, 'linked')); await symlink(path.join(f.root, 'linked'), path.join(f.root, '.vpn-config'), 'junction');
  await assert.rejects(f.manager.commit({ files: { vpn: 'new' }, finalize: () => {} }), { code: 'DELIVERY_PATH_INVALID' });
});
