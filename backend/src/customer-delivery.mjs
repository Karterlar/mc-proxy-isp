import path from 'node:path';
import { lstat, readFile, realpath, rename, rm, open } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { validateConfig, validateSecrets, UserError } from './config.mjs';
import { parseVpnConfig } from './vpn-yaml.mjs';
import { verifyLicense, publicKeyHash, verifyDeviceRequest } from './license-format.mjs';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';

export const CUSTOMER_DELIVERY_MAX_BYTES = 1536 * 1024;
const MAX_FILE = 1024 * 1024;
const fail = code => { throw new UserError(code, 'Customer delivery could not be safely validated or imported'); };
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const shape = (value, allowed, required = allowed) => plain(value) && Object.keys(value).every(key => allowed.includes(key)) && required.every(key => Object.hasOwn(value, key));
const stamp = value => Number.isSafeInteger(value) && value >= 0;
const text = (value, max) => typeof value === 'string' && Buffer.byteLength(value, 'utf8') <= max;
const hash = value => value === null ? null : createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : plain(value) ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const licenseDigest = envelope => hash(JSON.stringify(canonical(envelope)));
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const within = (root, file) => { const relative = path.relative(root, file); return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); };

function licenseEnvelope(licenseText) {
  if (!text(licenseText, 8192)) fail('DELIVERY_LICENSE_INVALID');
  let envelope;
  try { envelope = JSON.parse(licenseText.replace(/^\uFEFF/, '')); } catch { fail('DELIVERY_LICENSE_INVALID'); }
  if (!shape(envelope, ['version', 'keyId', 'payload', 'signature']) || envelope.version !== 1
    || typeof envelope.keyId !== 'string' || !/^[A-Za-z0-9_.-]{1,40}$/.test(envelope.keyId)
    || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) fail('DELIVERY_LICENSE_INVALID');
  const claims = ['version', 'licenseId', 'deviceId', 'deviceKeyHash', 'generation', 'plan', 'status', 'issuedAt', 'expiresAt', 'offlineUntil', 'ispExpiresAt', 'vpsExpiresAt'];
  if (envelope.payload?.version === 2) claims.push('resourcesMode');
  if (!shape(envelope.payload, claims) || ![1, 2].includes(envelope.payload.version)
    || !['isp-1d-trial', 'isp-30d-single'].includes(envelope.payload.plan)
    || !['active', 'revoked', 'pending-resource'].includes(envelope.payload.status)
    || !['issuedAt', 'expiresAt', 'offlineUntil'].every(key => stamp(envelope.payload[key]))
    || !['ispExpiresAt', 'vpsExpiresAt'].every(key => envelope.payload[key] === null || stamp(envelope.payload[key]))) fail('DELIVERY_LICENSE_INVALID');
  return envelope;
}

function validate(value) {
  if (!shape(value, ['format', 'version', 'licenseText', 'isp', 'connectionMode', 'takeoverMode', 'vpnText', 'relay', 'reminders'],
    ['format', 'version', 'licenseText', 'isp', 'connectionMode', 'takeoverMode']) || value.format !== 'mc-proxy-customer-delivery' || value.version !== 1) fail('DELIVERY_INVALID');
  licenseEnvelope(value.licenseText);
  if (!['vpn-import', 'vpn-compat', 'relay'].includes(value.connectionMode) || !['global', 'smart', 'application'].includes(value.takeoverMode)) fail('DELIVERY_MODE_INVALID');
  if (!shape(value.isp, ['type', 'host', 'port', 'username', 'password', 'expectedExitIps', 'tls'], ['type', 'host', 'port', 'username', 'password', 'expectedExitIps'])) fail('DELIVERY_ISP_INVALID');
  if (![value.isp.username, value.isp.password].every(value => text(value, 8192))
    || !Array.isArray(value.isp.expectedExitIps) || value.isp.expectedExitIps.length > 32) fail('DELIVERY_ISP_INVALID');
  if (value.connectionMode === 'vpn-import') {
    if (!text(value.vpnText, 1024 * 1024) || !value.vpnText.trim()) fail('DELIVERY_VPN_INVALID');
    let parsed; try { parsed = parseVpnConfig(value.vpnText); } catch { fail('DELIVERY_VPN_INVALID'); }
    if (!parsed.nodes.length) fail('DELIVERY_VPN_INVALID');
  } else if (value.vpnText !== undefined) fail('DELIVERY_MODE_INVALID');
  if (value.relay !== undefined && (value.connectionMode !== 'relay' || !shape(value.relay, ['config', 'secrets'])
    || !shape(value.relay.secrets, ['RELAY_USERNAME', 'RELAY_PASSWORD']) || !Object.values(value.relay.secrets).every(value => text(value, 8192)))) fail('DELIVERY_MODE_INVALID');
  if (value.reminders !== undefined && (!shape(value.reminders, ['vpnExpiresAt', 'ispExpiresAt', 'vpsExpiresAt'], [])
    || Object.values(value.reminders).some(value => value !== null && !stamp(value)))) fail('DELIVERY_REMINDERS_INVALID');
  try { const input = customerDeliveryConfiguration(value); validateConfig(input.config); validateSecrets(input.config, input.secrets); }
  catch { fail('DELIVERY_ISP_INVALID'); }
  return value;
}

// This returns private credentials. Callers must only retain it for the current
// preview/confirm operation; never attach it to controller state or diagnostics.
export function parseCustomerDelivery(input) {
  if (!text(input, CUSTOMER_DELIVERY_MAX_BYTES)) fail('DELIVERY_SIZE_INVALID');
  let value; try { value = JSON.parse(input.replace(/^\uFEFF/, '')); } catch { fail('DELIVERY_INVALID'); }
  return validate(value);
}
export function createCustomerDelivery(input) {
  if (!plain(input)) fail('DELIVERY_INVALID');
  const value = validate({ ...input, format: 'mc-proxy-customer-delivery', version: 1 });
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (!text(serialized, CUSTOMER_DELIVERY_MAX_BYTES)) fail('DELIVERY_SIZE_INVALID');
  return serialized;
}
export function customerDeliveryConfiguration(delivery) {
  const { type, host, port, username, password, expectedExitIps, tls } = delivery.isp;
  return {
    config: { version: 1, listen: { host: '127.0.0.1', port: 17890 }, connectionMode: delivery.connectionMode,
      upstream: { type, host, port, auth: username || password ? 'password' : 'none', ...(tls ? { tls: structuredClone(tls) } : {}) },
      probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: [...expectedExitIps], timeoutMs: 10000 },
      ...(delivery.relay ? { relay: structuredClone(delivery.relay.config) } : {}) },
    secrets: { ...(username || password ? { ISP_USERNAME: username, ISP_PASSWORD: password } : {}), ...(delivery.relay ? delivery.relay.secrets : {}) },
  };
}
export function customerDeliveryPreview(input) {
  const value = typeof input === 'string' ? parseCustomerDelivery(input) : validate(input);
  const { payload } = licenseEnvelope(value.licenseText);
  const vpn = value.vpnText ? parseVpnConfig(value.vpnText) : null;
  return { version: 1, connectionMode: value.connectionMode, takeoverMode: value.takeoverMode,
    isp: { type: value.isp.type, authenticated: Boolean(value.isp.username), pinnedExits: value.isp.expectedExitIps.length, tls: Boolean(value.isp.tls) },
    vpn: { included: Boolean(vpn), supported: vpn?.nodes.length || 0, unsupported: vpn?.unsupported.length || 0, format: vpn?.format || null },
    relay: { included: Boolean(value.relay), enrollmentRequired: value.connectionMode === 'relay' && !value.relay },
    license: { plan: payload.plan, expiresAt: payload.expiresAt, offlineUntil: payload.offlineUntil, verified: false },
    reminders: { ...value.reminders }, containsCredentials: true };
}
export function verifyCustomerDeliveryLicense(delivery, { publicKeys, deviceApplication, deviceId, deviceKeyHash, now = Date.now() } = {}) {
  const value = typeof delivery === 'string' ? parseCustomerDelivery(delivery) : validate(delivery);
  const envelope = licenseEnvelope(value.licenseText);
  if (deviceApplication !== undefined) {
    let signed; try { signed = typeof deviceApplication === 'string' ? JSON.parse(deviceApplication) : deviceApplication; } catch { fail('DELIVERY_DEVICE_INVALID'); }
    const { request } = verifyDeviceRequest(signed);
    if (request.action !== 'offline') fail('DELIVERY_DEVICE_INVALID');
    deviceId = request.deviceId; deviceKeyHash = publicKeyHash(request.devicePublicKey);
  }
  const claims = verifyLicense(envelope, { publicKeys, deviceId, deviceKeyHash, now });
  if (claims.status !== 'active') fail('DELIVERY_LICENSE_INACTIVE');
  return claims;
}

// Files are prepared with the existing importers in an isolated staging runtime.
// This journal commits only their public configuration/private credentials and
// preferences. It cannot replace license history, device keys or browser data.
export function createCustomerDeliveryTransaction({ runtimeRoot, configPath, secretsPath, dependencies = {} } = {}) {
  if (typeof runtimeRoot !== 'string' || !path.isAbsolute(runtimeRoot)) fail('DELIVERY_PATH_INVALID');
  const root = path.resolve(runtimeRoot), directory = path.join(root, '.customer-delivery'), journalPath = path.join(directory, 'pending.json');
  const targets = { config: path.resolve(configPath || path.join(root, 'config.json')), secrets: path.resolve(secretsPath || path.join(root, 'upstream.secrets.env')),
    vpn: path.join(root, '.vpn-config', 'nodes.json'), preferences: path.join(root, '.onboarding', 'preferences.json'),
    browserMigration: path.join(root, '.onboarding', 'fingerprint-default-1.6.2.json') };
  const protectedRoots = ['.license', '.customer-delivery', '.browser', 'browser-profiles', '.relay', '.firewall', '.environment'];
  if (Object.values(targets).some(file => !within(root, file) || protectedRoots.some(name => within(path.join(root, name), file)))
    || new Set(Object.values(targets).map(normalize)).size !== Object.keys(targets).length) fail('DELIVERY_PATH_INVALID');
  const binding = hash(JSON.stringify(Object.fromEntries(Object.entries(targets).map(([key, file]) => [key, normalize(file)]))));
  const fs = { lstat, readFile, realpath, rename, rm, open, createPrivateDirectory, writePrivate, ...dependencies };
  let serial = Promise.resolve();
  const locked = operation => { const task = serial.then(operation, operation); serial = task.catch(() => {}); return task; };
  async function safe(file) {
    if (!within(root, file)) fail('DELIVERY_PATH_INVALID');
    let cursor = path.parse(file).root;
    for (const part of file.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try {
        const stat = await fs.lstat(cursor);
        if (stat.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('DELIVERY_PATH_INVALID');
      } catch (error) { if (error.code === 'ENOENT') break; throw error; }
    }
  }
  async function ensureDirectory(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('DELIVERY_PATH_INVALID'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (target !== root) await ensureDirectory(path.dirname(target));
      await fs.createPrivateDirectory(target);
    }
  }
  async function read(file, max = MAX_FILE) {
    await safe(file);
    try {
      const info = await fs.lstat(file);
      if (!info.isFile() || info.nlink !== 1 || info.size > max) fail('DELIVERY_STATE_INVALID');
      const value = await fs.readFile(file, 'utf8');
      if (!text(value, max)) fail('DELIVERY_STATE_INVALID');
      return value;
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function replace(file, content) {
    await ensureDirectory(path.dirname(file));
    const temporary = path.join(path.dirname(file), `.delivery-${randomUUID()}.tmp`);
    try {
      await safe(file); await fs.writePrivate(temporary, content);
      const handle = await fs.open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
      await safe(file); await fs.rename(temporary, file);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  const journalLimit = MAX_FILE * 12;
  function validateJournal(record) {
    if (!shape(record, ['version', 'binding', 'phase', 'licenseDigest', 'beforeLicenseDigest', 'files']) || record.version !== 1 || record.binding !== binding
      || record.licenseDigest !== null && !/^[a-f0-9]{64}$/.test(record.licenseDigest)
      || record.beforeLicenseDigest !== null && !/^[a-f0-9]{64}$/.test(record.beforeLicenseDigest)
      || !['prepared', 'finalizing', 'committed'].includes(record.phase) || !plain(record.files) || !Object.keys(record.files).length) fail('DELIVERY_RECOVERY_REQUIRED');
    for (const [key, entry] of Object.entries(record.files)) {
      if (!Object.hasOwn(targets, key) || !shape(entry, ['before', 'after', 'beforeHash', 'afterHash'])
        || entry.before !== null && !text(entry.before, MAX_FILE) || !text(entry.after, MAX_FILE)
        || hash(entry.before) !== entry.beforeHash || hash(entry.after) !== entry.afterHash) fail('DELIVERY_RECOVERY_REQUIRED');
    }
    return record;
  }
  async function savedLicenseDigest() {
    const raw = await read(path.join(root, '.license', 'state.json'));
    if (raw === null) return null;
    let state; try { state = JSON.parse(raw); } catch { fail('DELIVERY_RECOVERY_REQUIRED'); }
    if (!plain(state?.record?.license)) fail('DELIVERY_RECOVERY_REQUIRED');
    return licenseDigest(state.record.license);
  }
  async function recover() {
    const raw = await read(journalPath, journalLimit); if (raw === null) return { recovered: false };
    let record; try { record = validateJournal(JSON.parse(raw)); } catch { fail('DELIVERY_RECOVERY_REQUIRED'); }
    // The original license client must initialize/authenticate its own state
    // before this recovery runs. Only the signed grant is read here; never the
    // device identity/private key. A completed final license write is the commit
    // decision even if power was lost before the delivery receipt was updated.
    let committed = record.phase === 'committed';
    if (record.phase === 'finalizing' && record.licenseDigest && record.licenseDigest !== record.beforeLicenseDigest) {
      committed = await savedLicenseDigest() === record.licenseDigest;
    }
    // Preflight every target before restoring any, to avoid a partial rollback
    // overwriting concurrent edits made outside the controller's setup lock.
    for (const [key, entry] of Object.entries(record.files)) {
      const digest = hash(await read(targets[key]));
      if (!(committed ? [entry.afterHash] : [entry.beforeHash, entry.afterHash]).includes(digest)) fail('DELIVERY_CONFLICT');
    }
    if (!committed) for (const [key, entry] of Object.entries(record.files)) {
      const file = targets[key], digest = hash(await read(file));
      if (digest === entry.beforeHash) continue;
      if (digest !== entry.afterHash) fail('DELIVERY_CONFLICT');
      if (entry.before === null) { await safe(file); await fs.rm(file, { force: true }); }
      else await replace(file, entry.before);
    }
    await safe(journalPath); await fs.rm(journalPath);
    return { recovered: !committed, committed };
  }
  return {
    recover: () => locked(recover),
    commit: ({ files, licenseText, expected, finalize } = {}) => locked(async () => {
      if (!plain(files) || !Object.keys(files).length || Object.keys(files).some(key => !Object.hasOwn(targets, key))
        || Object.values(files).some(value => !text(value, MAX_FILE)) || typeof finalize !== 'function') fail('DELIVERY_INVALID');
      if (expected !== undefined && (!plain(expected) || Object.keys(expected).some(key => !Object.hasOwn(files, key))
        || Object.values(expected).some(value => value !== null && !/^[a-f0-9]{64}$/.test(value)))) fail('DELIVERY_INVALID');
      await recover();
      // An interrupted onboarding transaction must be recovered by its owner
      // before a separate delivery transaction can touch the same files.
      if (await read(path.join(root, '.onboarding', 'pending.json'), 16384) !== null) fail('DELIVERY_RECOVERY_REQUIRED');
      const record = { version: 1, binding, phase: 'prepared', licenseDigest: licenseText === undefined ? null : licenseDigest(licenseEnvelope(licenseText)),
        beforeLicenseDigest: licenseText === undefined ? null : await savedLicenseDigest(), files: {} };
      for (const [key, after] of Object.entries(files)) {
        const before = await read(targets[key]); record.files[key] = { before, after, beforeHash: hash(before), afterHash: hash(after) };
        if (expected && Object.hasOwn(expected, key) && hash(before) !== expected[key]) fail('DELIVERY_CONFLICT');
      }
      if (!text(JSON.stringify(record), journalLimit)) fail('DELIVERY_SIZE_INVALID');
      await replace(journalPath, JSON.stringify(record));
      let finalized = false, result;
      try {
        for (const [key, entry] of Object.entries(record.files)) {
          if (hash(await read(targets[key])) !== entry.beforeHash) fail('DELIVERY_CONFLICT');
          await replace(targets[key], entry.after);
        }
        record.phase = 'finalizing'; await replace(journalPath, JSON.stringify(record));
        // The original license client is the final authority for replay/generation
        // and writes only its own journal. Never roll that journal back here.
        result = await finalize(); finalized = true;
        record.phase = 'committed'; await replace(journalPath, JSON.stringify(record));
        let cleanupPending = false; await fs.rm(journalPath).catch(() => { cleanupPending = true; });
        return { ...result, deliveryCommitted: true, cleanupPending };
      } catch (error) {
        // Once a real license client has saved the signed grant the transaction
        // is committed, even if writing/removing our receipt fails. Report that
        // actual outcome; restart resolves the durable finalizing receipt by the
        // exact signed grant. For a license-free import, rollback remains safe.
        if (finalized && record.licenseDigest && record.licenseDigest !== record.beforeLicenseDigest) return { ...result, deliveryCommitted: true, cleanupPending: true };
        try { const recovery = await recover(); if (recovery.committed) return { ...result, deliveryCommitted: true, cleanupPending: false }; }
        catch { fail('DELIVERY_RECOVERY_REQUIRED'); }
        throw error;
      }
    }),
  };
}
