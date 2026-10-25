import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { LICENSE_TERM_MS, LICENSE_TRIAL_MS, signLicense, verifyLicense } from '../src/license-format.mjs';

const signing = generateKeyPairSync('ed25519');
const signer = { privateKey: signing.privateKey, keyId: 'ephemeral-test' };
const now = Date.UTC(2026, 9, 7);
const payload = overrides => ({ version: 1, licenseId: randomUUID(), deviceId: 'a'.repeat(64), deviceKeyHash: 'b'.repeat(64),
  generation: 1, plan: 'isp-30d-single', status: 'active', issuedAt: now, expiresAt: now + LICENSE_TERM_MS,
  offlineUntil: now + LICENSE_TERM_MS, ispExpiresAt: now + LICENSE_TERM_MS, vpsExpiresAt: null, ...overrides });
const signed = overrides => signLicense(payload(overrides), signer);
const verify = (token, time = now, options = {}) => verifyLicense(token, {
  publicKeys: { 'ephemeral-test': signing.publicKey.export({ type: 'spki', format: 'pem' }) },
  deviceId: 'a'.repeat(64), deviceKeyHash: 'b'.repeat(64), now: time, ...options,
});

test('v1 preserves exact signed claims, resource expiry and pending-resource semantics', () => {
  const boundary = now + 1000;
  for (const dates of [{ ispExpiresAt: boundary }, { vpsExpiresAt: boundary }]) {
    const token = signed({ ...dates, offlineUntil: boundary });
    assert.equal(token.version, 1); assert.equal(token.payload.version, 1);
    assert.equal(verify(token, boundary - 1).status, 'active');
    assert.throws(() => verify(token, boundary), { code: 'LICENSE_EXPIRED' });
    assert.throws(() => signed({ ...dates, offlineUntil: boundary + 1 }), { code: 'INVALID_LICENSE' });
  }
  const pending = signed({ status: 'pending-resource', ispExpiresAt: now, offlineUntil: now });
  assert.equal(verify(pending).status, 'pending-resource');
  assert.throws(() => signed({ ispExpiresAt: null }), { code: 'INVALID_LICENSE' });
  assert.throws(() => signed({ resourcesMode: 'included' }), { code: 'INVALID_LICENSE' });
});

test('v2 included resource reminders do not truncate software or offline authorization', () => {
  for (const dates of [{ ispExpiresAt: now - 1, vpsExpiresAt: now - 1 }, { ispExpiresAt: null, vpsExpiresAt: null }]) {
    const token = signed({ version: 2, resourcesMode: 'included', ...dates });
    assert.equal(token.version, 1, 'the envelope and signing domain stay compatible');
    assert.equal(verify(token, now + LICENSE_TERM_MS - 1).offlineUntil, now + LICENSE_TERM_MS);
    assert.throws(() => verify(token, now + LICENSE_TERM_MS), { code: 'LICENSE_EXPIRED' });
  }
});

test('v2 customer resources need no provider dates and still enforce lease and software expiry', () => {
  const customer = { version: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null };
  const token = signed(customer);
  assert.equal(verify(token, now + LICENSE_TERM_MS - 1).resourcesMode, 'customer');
  const short = signed({ ...customer, offlineUntil: now + 1000 });
  assert.throws(() => verify(short, now + 1000), { code: 'LICENSE_EXPIRED' });
  assert.throws(() => signed({ ...customer, expiresAt: now + 1000 }), { code: 'INVALID_LICENSE' });
  assert.throws(() => signed({ ...customer, expiresAt: now + LICENSE_TERM_MS + 1, offlineUntil: now + LICENSE_TERM_MS + 1 }), { code: 'INVALID_LICENSE' });
  const trial = signed({ ...customer, plan: 'isp-1d-trial', expiresAt: now + LICENSE_TRIAL_MS, offlineUntil: now + LICENSE_TRIAL_MS });
  assert.equal(verify(trial, now + LICENSE_TRIAL_MS - 1).status, 'active');
  assert.throws(() => verify(trial, now + LICENSE_TRIAL_MS), { code: 'LICENSE_EXPIRED' });
  assert.throws(() => signed({ ...customer, plan: 'isp-1d-trial', expiresAt: now + LICENSE_TRIAL_MS + 1, offlineUntil: now + LICENSE_TRIAL_MS }), { code: 'INVALID_LICENSE' });
});

test('v2 rejects missing, unknown and ambiguous fields and statuses even when expiry checks are disabled', () => {
  const base = payload({ version: 2, resourcesMode: 'included' });
  const noMode = { ...base }; delete noMode.resourcesMode;
  const noIsp = { ...base }; delete noIsp.ispExpiresAt;
  const noVps = { ...base }; delete noVps.vpsExpiresAt;
  for (const invalid of [noMode, noIsp, noVps,
    ...['pending-resource', 'expired', '', null].map(status => ({ ...base, status })),
    ...['external', '', null, 1].map(resourcesMode => ({ ...base, resourcesMode })),
    ...[-1, '2026-10-07', Infinity, Number.MAX_SAFE_INTEGER + 1].map(ispExpiresAt => ({ ...base, ispExpiresAt })),
    { ...base, resourceStatus: 'pending-resource' }, { ...base, version: 3 }, { ...base, version: '2' },
    { ...base, resourcesMode: 'customer' },
    { ...base, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: now },
  ]) {
    assert.throws(() => signLicense(invalid, signer), { code: 'INVALID_LICENSE' });
    assert.throws(() => verify({ ...signed({ version: 2, resourcesMode: 'included' }), payload: invalid }, now, { allowExpired: true }), { code: 'INVALID_LICENSE' });
  }
  assert.equal(verify(signed({ version: 2, resourcesMode: 'included', status: 'revoked' })).status, 'revoked');
});

test('resource mode and claim version are signed and cannot silently relax a legacy token', () => {
  const legacy = signed();
  assert.throws(() => verify({ ...legacy, payload: { ...legacy.payload, version: 2, resourcesMode: 'included' } }), { code: 'INVALID_SIGNATURE' });
  const customer = signed({ version: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null });
  assert.throws(() => verify({ ...customer, payload: { ...customer.payload, resourcesMode: 'included' } }), { code: 'INVALID_SIGNATURE' });
  assert.throws(() => verify({ ...customer, version: 2 }), { code: 'INVALID_LICENSE' });
});
