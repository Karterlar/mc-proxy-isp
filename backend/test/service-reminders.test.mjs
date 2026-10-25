import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, readdir, rm, symlink } from 'node:fs/promises';
import { createServiceReminderManager } from '../src/service-reminders.mjs';

const NOW = Date.parse('2026-10-13T00:00:00.000Z'), DAY = 86_400_000;
const bindings = { vpn: 'a'.repeat(64), isp: 'b'.repeat(64) };
const find = (status, kind) => status.items.find(item => item.kind === kind);
async function fixture(t, options = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.reminders-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, manager: createServiceReminderManager({ runtimeRoot: root, now: () => NOW, ...options }) };
}

test('read-only status separates software and offline license dates, leaves unknown VPN/ISP unknown, and never creates storage', async t => {
  const f = await fixture(t);
  const license = Object.freeze({ required: true, allowed: true, expiresAt: NOW + 30 * DAY, offlineUntil: NOW + DAY,
    ispExpiresAt: NOW - DAY, vpsExpiresAt: NOW - DAY, licenseId: 'PRIVATE_LICENSE', deviceId: 'PRIVATE_DEVICE' });
  const status = await f.manager.status({ license, bindings, lastError: { code: 'ISP_TIMEOUT' } });
  assert.equal(find(status, 'license').daysRemaining, 30); assert.equal(find(status, 'license').state, 'active');
  assert.equal(find(status, 'license-offline').daysRemaining, 1); assert.equal(find(status, 'license-offline').state, 'due-soon');
  assert.equal(find(status, 'vpn').state, 'unknown'); assert.equal(find(status, 'isp').source, 'unknown');
  assert.equal(status.noticeCount, 1); assert.equal(license.allowed, true);
  assert.doesNotMatch(JSON.stringify(status), /PRIVATE|deviceId|licenseId|vpsExpiresAt|ispExpiresAt/);
  assert.deepEqual(await readdir(f.root), []);
  const developer = await f.manager.status({ license: { required: false }, bindings });
  assert.equal(find(developer, 'license').state, 'not-required'); assert.equal(find(developer, 'license-offline').state, 'not-required');
});

test('manual records survive restart, bind to the current service, clear explicitly, and never edit existing configurations or license', async t => {
  const f = await fixture(t), sentinel = path.join(f.root, 'existing-customer-data.json');
  await writeFile(sentinel, 'PRIVATE_CONFIG_AND_LICENSE');
  assert.deepEqual(await f.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: '2026-10-15', expectedRevision: 0 }), { saved: true, revision: 1 });
  await f.manager.save({ kind: 'vpn', binding: bindings.vpn, expiresOn: '2026-10-12', expectedRevision: 1 });
  const reopened = createServiceReminderManager({ runtimeRoot: f.root, now: () => NOW });
  const status = await reopened.status({ bindings });
  assert.equal(find(status, 'isp').source, 'manual'); assert.equal(find(status, 'isp').expiresOn, '2026-10-15');
  assert.equal(find(status, 'vpn').state, 'expired'); assert.equal(find(status, 'vpn').reminderOnly, true);
  assert.doesNotMatch(JSON.stringify(status), /a{64}|b{64}|binding/);
  const replacement = await reopened.status({ bindings: { vpn: 'c'.repeat(64), isp: 'd'.repeat(64) } });
  assert.equal(find(replacement, 'vpn').state, 'unknown'); assert.equal(find(replacement, 'isp').state, 'unknown');
  await reopened.save({ kind: 'isp', binding: bindings.isp, expiresOn: null });
  assert.equal(find(await reopened.status({ bindings }), 'isp').state, 'unknown');
  assert.equal(await readFile(sentinel, 'utf8'), 'PRIVATE_CONFIG_AND_LICENSE');
});

test('provider values take precedence with timestamp and counters, missing provider expiry permits a clearly manual reminder', async () => {
  const manager = createServiceReminderManager({ mock: true, now: () => NOW });
  await manager.save({ kind: 'vpn', binding: bindings.vpn, expiresOn: '2026-12-01' });
  const provider = await manager.status({ bindings, subscription: { configured: true, lastUpdatedAt: '2026-10-13T00:00:00.000Z',
    url: 'https://PRIVATE_TOKEN/', usage: { expire: (NOW - 1000) / 1000, upload: 30, download: 80, total: 100, token: 'PRIVATE_TOKEN' } } });
  assert.equal(find(provider, 'vpn').source, 'provider'); assert.equal(find(provider, 'vpn').state, 'expired');
  assert.equal(find(provider, 'vpn').observedAt, '2026-10-13T00:00:00.000Z');
  assert.deepEqual(find(provider, 'vpn').usage, { upload: 30, download: 80, total: 100, remaining: 0, exhausted: true });
  assert.doesNotMatch(JSON.stringify(provider), /PRIVATE|:\/\//);
  const noExpiry = await manager.status({ bindings, subscription: { configured: true, usage: { expire: 0, upload: 1, total: 0 } } });
  assert.equal(find(noExpiry, 'vpn').source, 'manual'); assert.equal(find(noExpiry, 'vpn').usage.exhausted, undefined);
  const newConfig = await manager.status({ bindings: { ...bindings, vpn: 'c'.repeat(64) }, subscription: { configured: false, usage: { expire: (NOW - 1000) / 1000 } } });
  assert.equal(find(newConfig, 'vpn').source, 'unknown'); assert.equal(find(newConfig, 'vpn').usage, undefined);
});

test('invalid manual input and stale revisions reject without overwriting, corruption cannot silently reset', async t => {
  const f = await fixture(t); await f.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: '2026-10-15' });
  const file = path.join(f.root, '.service-reminders', 'reminders.json'), before = await readFile(file);
  for (const input of [{ kind: 'license', binding: bindings.isp, expiresOn: '2026-10-15' }, { kind: 'isp', binding: 'PRIVATE', expiresOn: '2026-10-15' },
    ...['2026-02-30', '2026-99-99', '2026-13-01', '', 'PRIVATE', '2026-10-13T00:00:00Z'].map(expiresOn => ({ kind: 'isp', binding: bindings.isp, expiresOn })),
    { kind: 'isp', binding: bindings.isp, expiresOn: '2026-10-15', message: 'PRIVATE' }]) {
    await assert.rejects(f.manager.save(input), cause => cause.code === 'REMINDERS_INPUT_INVALID' && !cause.message.includes('PRIVATE'));
  }
  await assert.rejects(f.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: null, expectedRevision: 0 }), { code: 'REMINDERS_CONFLICT' });
  assert.deepEqual(await readFile(file), before);
  await writeFile(file, 'invalid'); await assert.rejects(f.manager.status(), { code: 'REMINDERS_STATE_INVALID' });
  await assert.rejects(f.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: null }), { code: 'REMINDERS_STATE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), 'invalid');
});

test('linked reminder directory is refused and injected failed publish leaves prior records intact', async t => {
  const f = await fixture(t), external = await mkdtemp(path.resolve(import.meta.dirname, '.reminders-target-'));
  t.after(() => rm(external, { recursive: true, force: true }));
  await symlink(external, path.join(f.root, '.service-reminders'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: '2026-10-15' }), { code: 'REMINDERS_PATH_INVALID' });
  assert.deepEqual(await readdir(external), []);
  const g = await fixture(t); await g.manager.save({ kind: 'isp', binding: bindings.isp, expiresOn: '2026-10-15' });
  const broken = createServiceReminderManager({ runtimeRoot: g.root, dependencies: { renamePrivate: async () => { throw new Error('PRIVATE_RAW_PATH'); } } });
  await assert.rejects(broken.save({ kind: 'isp', binding: bindings.isp, expiresOn: null }), { code: 'REMINDERS_WRITE_FAILED' });
  assert.equal(find(await g.manager.status({ bindings }), 'isp').expiresOn, '2026-10-15');
  assert.equal((await readdir(path.join(g.root, '.service-reminders'))).filter(name => name.endsWith('.tmp')).length, 0);
});
