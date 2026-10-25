import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

export const LICENSE_PLAN = 'isp-30d-single';
export const LICENSE_TRIAL_PLAN = 'isp-1d-trial';
export const LICENSE_TRIAL_MS = 24 * 60 * 60 * 1000;
export const LICENSE_TERM_MS = 30 * 24 * 60 * 60 * 1000;
export const LICENSE_LEASE_MS = 72 * 60 * 60 * 1000;
export const LICENSE_MAX_OFFLINE_MS = LICENSE_TERM_MS;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9_.-]{1,40}$/;
const CARD = /^[A-Za-z0-9_-]{16,128}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const CLAIM_KEYS = ['version', 'licenseId', 'deviceId', 'deviceKeyHash', 'generation', 'plan', 'status', 'issuedAt', 'expiresAt', 'offlineUntil', 'ispExpiresAt', 'vpsExpiresAt'];

export class LicenseError extends Error {
  constructor(code, message) { super(message); this.name = 'LicenseError'; this.code = code; }
}
function fail(code = 'INVALID_LICENSE', message = 'Invalid license') { throw new LicenseError(code, message); }
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function exact(value, keys, code) {
  if (!object(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
}
function time(value) { return Number.isSafeInteger(value) && value >= 0; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function signingBytes(domain, value) { return Buffer.from(`ProxyPilot:${domain}:v1\n${canonical(value)}`, 'utf8'); }
function edKey(value, privateKey = false) {
  try {
    const key = value?.type === (privateKey ? 'private' : 'public') && value?.asymmetricKeyType ? value : privateKey ? createPrivateKey(value) : createPublicKey(value);
    if (key.asymmetricKeyType !== 'ed25519') fail('INVALID_KEY', 'An Ed25519 key is required');
    return key;
  } catch (error) {
    if (error instanceof LicenseError) throw error;
    fail('INVALID_KEY', 'Invalid Ed25519 key');
  }
}
function publicPem(value) {
  if (typeof value !== 'string' || value.length > 1024 || !/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----\n?$/.test(value)) fail('INVALID_KEY', 'Invalid Ed25519 public key');
  return edKey(value);
}
export function publicKeyHash(publicKey) {
  const key = typeof publicKey === 'string' ? publicPem(publicKey) : edKey(publicKey);
  return createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}
function claims(value) {
  const independent = value?.version === 2;
  exact(value, independent ? [...CLAIM_KEYS, 'resourcesMode'] : CLAIM_KEYS, 'INVALID_LICENSE');
  if (![1, 2].includes(value.version) || !UUID.test(value.licenseId) || !HASH.test(value.deviceId) || !HASH.test(value.deviceKeyHash) || !Number.isSafeInteger(value.generation) || value.generation < 1 || ![LICENSE_PLAN, LICENSE_TRIAL_PLAN].includes(value.plan) || !(independent ? ['active', 'revoked'] : ['active', 'revoked', 'pending-resource']).includes(value.status)) fail();
  for (const key of ['issuedAt', 'expiresAt', 'offlineUntil']) if (!time(value[key])) fail();
  if (!(independent && value.ispExpiresAt === null) && !time(value.ispExpiresAt)) fail();
  if (value.vpsExpiresAt !== null && !time(value.vpsExpiresAt)) fail();
  if (independent && (!['included', 'customer'].includes(value.resourcesMode) || value.resourcesMode === 'customer' && (value.ispExpiresAt !== null || value.vpsExpiresAt !== null))) fail();
  const maxWindow = value.plan === LICENSE_TRIAL_PLAN ? LICENSE_TRIAL_MS : LICENSE_MAX_OFFLINE_MS;
  const ceiling = Math.min(value.issuedAt + maxWindow, licenseExpiresAt(value));
  if (!Number.isSafeInteger(value.issuedAt + maxWindow) || value.offlineUntil > ceiling || (value.plan === LICENSE_TRIAL_PLAN && value.expiresAt > value.issuedAt + LICENSE_TRIAL_MS)) fail();
  return value;
}
// Only an explicitly signed v2 grant separates software access from resource
// reminders; old grants retain their original ISP/VPS authorization boundary.
export function licenseExpiresAt(payload) {
  return payload.version === 2 ? payload.expiresAt : Math.min(payload.expiresAt, payload.ispExpiresAt, payload.vpsExpiresAt ?? Infinity);
}
export function signLicense(payload, { privateKey, keyId }) {
  claims(payload);
  if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) fail('INVALID_KEY', 'Invalid signing key identifier');
  const content = { version: 1, keyId, payload: { ...payload } };
  return { ...content, signature: sign(null, signingBytes('license', content), edKey(privateKey, true)).toString('base64url') };
}
export function verifyLicense(envelope, { publicKeys, deviceId, deviceKeyHash, now = Date.now(), allowExpired = false }) {
  exact(envelope, ['version', 'keyId', 'payload', 'signature'], 'INVALID_LICENSE');
  if (envelope.version !== 1 || typeof envelope.keyId !== 'string' || !KEY_ID.test(envelope.keyId) || typeof envelope.signature !== 'string' || !SIGNATURE.test(envelope.signature)) fail();
  const payload = claims(envelope.payload);
  if (!object(publicKeys) || !Object.hasOwn(publicKeys, envelope.keyId)) fail('UNKNOWN_SIGNING_KEY', 'Unknown license signing key');
  const bytes = Buffer.from(envelope.signature, 'base64url');
  if (bytes.toString('base64url') !== envelope.signature || !verify(null, signingBytes('license', { version: 1, keyId: envelope.keyId, payload }), publicPem(publicKeys[envelope.keyId]), bytes)) fail('INVALID_SIGNATURE', 'Invalid license signature');
  if (!HASH.test(deviceId) || !HASH.test(deviceKeyHash) || payload.deviceId !== deviceId || payload.deviceKeyHash !== deviceKeyHash) fail('DEVICE_MISMATCH', 'License belongs to another device');
  if (!time(now) || payload.issuedAt > now + 60000) fail('CLOCK_INVALID', 'Device clock is behind the license time');
  if (!allowExpired && payload.status === 'active' && now >= Math.min(payload.offlineUntil, licenseExpiresAt(payload))) fail('LICENSE_EXPIRED', 'License or offline lease has expired');
  return { ...payload };
}
function deviceRequest(request) {
  if (!object(request)) fail('INVALID_REQUEST', 'Invalid activation request');
  const keys = ['version', 'action', 'requestId', 'deviceId', 'devicePublicKey'];
  if (Object.hasOwn(request, 'card')) keys.push('card');
  if (Object.hasOwn(request, 'licenseId')) keys.push('licenseId');
  exact(request, keys, 'INVALID_REQUEST');
  if (request.version !== 1 || !['redeem', 'refresh', 'offline'].includes(request.action) || !UUID.test(request.requestId) || !HASH.test(request.deviceId)) fail('INVALID_REQUEST', 'Invalid activation request');
  if (Object.hasOwn(request, 'card') && (typeof request.card !== 'string' || !CARD.test(request.card))) fail('INVALID_REQUEST', 'Invalid activation card');
  if (Object.hasOwn(request, 'licenseId') && !UUID.test(request.licenseId)) fail('INVALID_REQUEST', 'Invalid license identifier');
  if ((request.action === 'redeem' && (!request.card || request.licenseId)) || (request.action === 'refresh' && (!request.licenseId || request.card)) || (request.action === 'offline' && request.card) || (request.card && request.licenseId)) fail('INVALID_REQUEST', 'Invalid activation request');
  return publicPem(request.devicePublicKey);
}
export function signDeviceRequest(request, privateKey) {
  const publicKey = deviceRequest(request);
  const key = edKey(privateKey, true);
  if (publicKeyHash(publicKey) !== publicKeyHash(createPublicKey(key))) fail('INVALID_KEY', 'Device keys do not match');
  return { request: { ...request }, signature: sign(null, signingBytes('device-request', request), key).toString('base64url') };
}
export function verifyDeviceRequest(envelope) {
  exact(envelope, ['request', 'signature'], 'INVALID_REQUEST');
  const key = deviceRequest(envelope.request);
  if (typeof envelope.signature !== 'string' || !SIGNATURE.test(envelope.signature)) fail('INVALID_REQUEST', 'Invalid device signature');
  const signature = Buffer.from(envelope.signature, 'base64url');
  if (signature.toString('base64url') !== envelope.signature || !verify(null, signingBytes('device-request', envelope.request), key, signature)) fail('INVALID_SIGNATURE', 'Invalid device signature');
  return { request: { ...envelope.request }, deviceKeyHash: publicKeyHash(key) };
}
export function validateLicenseConfig(config, { allowLoopback = false } = {}) {
  if (!object(config)) fail('INVALID_LICENSE_CONFIG', 'Invalid license configuration');
  const keys = ['version', 'mode'];
  if (Object.hasOwn(config, 'serviceUrl')) keys.push('serviceUrl');
  if (Object.hasOwn(config, 'publicKeys')) keys.push('publicKeys');
  exact(config, keys, 'INVALID_LICENSE_CONFIG');
  if (config.version !== 1 || !['development', 'required'].includes(config.mode)) fail('INVALID_LICENSE_CONFIG', 'Invalid license configuration');
  const publicKeys = config.publicKeys ?? {};
  if (!object(publicKeys) || Object.keys(publicKeys).length > 8) fail('INVALID_LICENSE_CONFIG', 'Invalid license public keys');
  for (const [keyId, key] of Object.entries(publicKeys)) {
    if (typeof keyId !== 'string' || !KEY_ID.test(keyId)) fail('INVALID_LICENSE_CONFIG', 'Invalid license signing key identifier');
    try { publicPem(key); } catch { fail('INVALID_LICENSE_CONFIG', 'Invalid license public key'); }
  }
  let serviceUrl = config.serviceUrl ?? '';
  if (serviceUrl !== '') {
    try {
      const url = new URL(serviceUrl);
      const localHttp = allowLoopback && url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
      if (typeof serviceUrl !== 'string' || serviceUrl.length > 2048 || (url.protocol !== 'https:' && !localHttp) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
      serviceUrl = url.origin;
    } catch { fail('INVALID_LICENSE_CONFIG', 'License service must be an HTTPS origin'); }
  }
  if (config.mode === 'required' && Object.keys(publicKeys).length === 0) fail('INVALID_LICENSE_CONFIG', 'Required licensing needs public keys');
  return { version: 1, mode: config.mode, serviceUrl, publicKeys: { ...publicKeys } };
}
