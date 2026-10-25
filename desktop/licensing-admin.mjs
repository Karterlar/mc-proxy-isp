import path from 'node:path';
import { lstat, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { publicKeyHash, verifyDeviceRequest } from '../backend/src/license-format.mjs';
import { createCustomerDelivery, customerDeliveryPreview, verifyCustomerDeliveryLicense } from '../backend/src/customer-delivery.mjs';

const ACTIONS = new Set(['trial', 'activate', 'refresh', 'renew', 'rebind', 'revoke', 'resources']);
const FIELDS = new Set(['action', 'applicationText', 'licenseId', 'orderId', 'paidConfirmed', 'resourcesReady', 'resourcesMode', 'ispExpiresAt', 'vpsExpiresAt', 'offlineDays']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = code => { throw Object.assign(new Error(code), { code }); };

export function validateAdminRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Object.keys(input).some(key => !FIELDS.has(key)) || !ACTIONS.has(input.action)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
  const value = { action: input.action };
  if (input.resourcesMode !== undefined) {
    if (!['included', 'customer'].includes(input.resourcesMode)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value.resourcesMode = input.resourcesMode;
  }
  if (input.licenseId !== undefined && input.licenseId !== '') {
    if (typeof input.licenseId !== 'string' || !UUID.test(input.licenseId)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value.licenseId = input.licenseId;
  }
  if (input.orderId !== undefined && input.orderId !== '') {
    if (typeof input.orderId !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(input.orderId)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value.orderId = input.orderId;
  }
  for (const key of ['paidConfirmed', 'resourcesReady']) {
    if (input[key] !== undefined && typeof input[key] !== 'boolean') fail('LICENSE_ADMIN_ARGUMENT_INVALID');
  }
  value.paid = input.paidConfirmed === true;
  value.resourcesReady = input.resourcesReady === true;
  for (const key of ['ispExpiresAt', 'vpsExpiresAt']) {
    if (input[key] === undefined || input[key] === null || input[key] === '') continue;
    const stamp = typeof input[key] === 'number' ? input[key] : typeof input[key] === 'string' && input[key].length < 80 ? Date.parse(input[key]) : NaN;
    if (!Number.isSafeInteger(stamp) || stamp < 0) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value[key] = stamp;
  }
  if (input.offlineDays !== undefined) {
    if (![1, 3, 7, 15, 30].includes(input.offlineDays)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value.offlineDays = input.offlineDays;
  }
  if (input.applicationText !== undefined && input.applicationText !== '') {
    if (typeof input.applicationText !== 'string' || Buffer.byteLength(input.applicationText, 'utf8') > 8192) fail('LICENSE_ADMIN_APPLICATION_INVALID');
    try {
      value.applicationEnvelope = JSON.parse(input.applicationText.replace(/^\uFEFF/, ''));
      if (verifyDeviceRequest(value.applicationEnvelope).request.action !== 'offline') throw new Error();
    } catch { fail('LICENSE_ADMIN_APPLICATION_INVALID'); }
  }
  if (['trial', 'activate', 'rebind'].includes(value.action) && !value.applicationEnvelope) fail('LICENSE_ADMIN_APPLICATION_INVALID');
  if (['refresh', 'renew', 'rebind', 'revoke', 'resources'].includes(value.action) && !value.licenseId) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
  // The issuer checks payment/resources after detecting a completed order. Keep
  // this bridge limited to shape/proof validation so an idempotent save can retry.
  if (['activate', 'renew'].includes(value.action) && !value.orderId) fail('PAYMENT_NOT_CONFIRMED');
  if (value.action === 'trial' && value.resourcesMode !== 'customer' && (!value.resourcesReady || value.ispExpiresAt === undefined)) fail('RESOURCE_NOT_READY');
  if (value.action === 'trial') {
    if (value.orderId || value.paid || (value.offlineDays !== undefined && value.offlineDays !== 1)) fail('LICENSE_ADMIN_ARGUMENT_INVALID');
    value.offlineDays = 1;
  }
  return value;
}

async function plainDirectory(directory) {
  let current = path.parse(path.resolve(directory)).root;
  for (const segment of path.resolve(directory).slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment); const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) fail('LICENSE_ADMIN_SETTINGS_INVALID');
  }
}
async function plainFile(file) {
  await plainDirectory(path.dirname(file));
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 8192) fail('LICENSE_ADMIN_SETTINGS_INVALID');
}
const defaultTools = async () => {
  const [ui, admin, runtime, files] = await Promise.all([
    import('../tools/licensing/ui.mjs'), import('../tools/licensing/admin.mjs'), import('../tools/licensing/runtime.mjs'), import('../tools/licensing/safe-files.mjs'),
  ]);
  return { ...ui, initializeLicensing: admin.initializeLicensing, openStore: runtime.openStore, ...files };
};

// Only this main-process bridge receives native file-dialog paths. Neither the
// renderer nor the local HTTP controller can select a key or output path.
export function createLicenseAdmin({ enabled = false, mock = false, settingsPath, chooseStore, chooseNewStore, chooseOutput, chooseLicenseInput,
  loadTools = defaultTools } = {}) {
  let selected = null, loaded = false, busy = false, toolPromise;
  const guard = () => { if (!enabled) fail('LICENSE_ADMIN_UNAVAILABLE'); if (mock) fail('LICENSE_ADMIN_MOCK_UNAVAILABLE'); };
  const tools = () => toolPromise ??= loadTools();
  async function readSelection() {
    if (loaded) return;
    if (!settingsPath) { loaded = true; return; }
    try {
      await plainFile(settingsPath);
      const data = JSON.parse(await readFile(settingsPath, 'utf8'));
      if (!data || Object.keys(data).sort().join(',') !== 'directory,fingerprint,version' || data.version !== 1
        || typeof data.directory !== 'string' || data.directory.length > 4096 || !path.isAbsolute(data.directory)
        || !/^[a-f0-9]{64}$/.test(data.fingerprint)) fail('LICENSE_ADMIN_SETTINGS_INVALID');
      selected = data; loaded = true;
    } catch (error) {
      if (error.code === 'ENOENT') { loaded = true; return; }
      fail('LICENSE_ADMIN_SETTINGS_INVALID');
    }
  }
  async function metadata(directory) {
    const opened = await (await tools()).openStore(path.join(directory, 'server-config.json'));
    try { return { keyId: opened.keyId, fingerprint: publicKeyHash(opened.publicKey), publicKey: opened.publicKey }; }
    finally { opened.store.close(); }
  }
  async function saveSelection(directory, fingerprint) {
    const next = { version: 1, directory, fingerprint };
    if (settingsPath) {
      await plainDirectory(path.dirname(settingsPath));
      try { await plainFile(settingsPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      const temporary = `${settingsPath}.${randomUUID()}.tmp`;
      try {
        await writeFile(temporary, `${JSON.stringify(next)}\n`, { flag: 'wx', mode: 0o600 });
        await rename(temporary, settingsPath);
      } finally { await unlink(temporary).catch(() => {}); }
    }
    selected = next; loaded = true;
  }
  async function current() {
    await readSelection();
    if (!selected) fail('LICENSE_ADMIN_STORE_REQUIRED');
    const info = await metadata(selected.directory);
    if (info.fingerprint !== selected.fingerprint) fail('LICENSE_ADMIN_STORE_CHANGED');
    return { ...selected, ...info };
  }
  async function exclusive(operation) {
    guard(); if (busy) fail('LICENSE_ADMIN_BUSY'); busy = true;
    try { return await operation(); } finally { busy = false; }
  }
  async function status() {
    if (!enabled || mock) return { enabled: enabled && !mock, configured: false, mock, customers: [], orders: [], summary: {} };
    guard(); await readSelection();
    if (!selected) return { enabled: true, configured: false, customers: [], orders: [], summary: {} };
    const info = await current();
    const data = await (await tools()).runLicensingAction({ action: 'customers', configPath: path.join(info.directory, 'server-config.json') });
    return { ...data, enabled: true, configured: true, directory: info.directory, keyId: info.keyId, publicKeyFingerprint: info.fingerprint };
  }
  return {
    status,
    isBusy: () => busy,
    selectStore: () => exclusive(async () => {
      const directory = await chooseStore(); if (!directory) return { canceled: true };
      const absolute = path.resolve(directory), info = await metadata(absolute);
      await saveSelection(absolute, info.fingerprint); return status();
    }),
    createStore: () => exclusive(async () => {
      const directory = await chooseNewStore(); if (!directory) return { canceled: true };
      const absolute = path.resolve(directory);
      await (await tools()).initializeLicensing({ dir: absolute, offline: true });
      const info = await metadata(absolute); await saveSelection(absolute, info.fingerprint);
      return { ...await status(), newTrustRoot: true };
    }),
    generate: input => exclusive(async () => {
      const request = validateAdminRequest(input), info = await current();
      const label = request.orderId || request.licenseId?.slice(0, 8) || 'trial';
      const outputPath = await chooseOutput(`MC-Proxy-${request.action}-${label}-${randomUUID().slice(0, 8)}.json`);
      if (!outputPath) return { canceled: true };
      if (typeof outputPath !== 'string' || !/\.json$/i.test(outputPath) || outputPath.length > 4096) fail('LICENSE_ADMIN_OUTPUT_INVALID');
      // Recheck the selected signing identity after the native dialog returns.
      await current();
      const result = await (await tools()).runLicensingAction({ ...request, configPath: path.join(info.directory, 'server-config.json'), outputPath });
      return { ...result, saved: true, filePath: outputPath, licenseId: result.license?.licenseId, plan: result.license?.plan };
    }),
    exportDelivery: input => exclusive(async () => {
      if (!input || typeof input !== 'object' || Array.isArray(input)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
        || Object.keys(input).some(key => !['isp', 'vpnText', 'connectionMode', 'takeoverMode', 'relay', 'reminders'].includes(key))) fail('DELIVERY_INVALID');
      const info = await current();
      if (typeof chooseLicenseInput !== 'function') fail('DELIVERY_LICENSE_INPUT_REQUIRED');
      const licensePath = await chooseLicenseInput(); if (!licensePath) return { canceled: true };
      if (typeof licensePath !== 'string' || licensePath.length > 4096 || !path.isAbsolute(licensePath)) fail('DELIVERY_LICENSE_INVALID');
      const licenseText = await (await tools()).readSafeText(licensePath, 8192);
      const content = createCustomerDelivery({ ...input, licenseText });
      const verifyCurrentGrant = async () => {
        const latest = await current();
        if (latest.fingerprint !== info.fingerprint) fail('LICENSE_ADMIN_STORE_CHANGED');
        let envelope; try { envelope = JSON.parse(licenseText.replace(/^\uFEFF/, '')); } catch { fail('DELIVERY_LICENSE_INVALID'); }
        const claims = verifyCustomerDeliveryLicense(content, { publicKeys: { [latest.keyId]: latest.publicKey },
          deviceId: envelope.payload.deviceId, deviceKeyHash: envelope.payload.deviceKeyHash });
        const listing = await (await tools()).runLicensingAction({ action: 'customers', configPath: path.join(latest.directory, 'server-config.json') });
        const customer = listing.customers?.find(item => item.licenseId === claims.licenseId);
        if (!customer || customer.status !== 'active' || customer.generation !== claims.generation || customer.deviceId !== claims.deviceId) fail('DELIVERY_LICENSE_STALE');
        return claims;
      };
      const grant = await verifyCurrentGrant();
      const outputPath = await chooseOutput(`MC-Proxy-Customer-${grant.licenseId.slice(0, 8)}-${randomUUID().slice(0, 8)}.mcproxy.json`);
      if (!outputPath) return { canceled: true };
      if (typeof outputPath !== 'string' || outputPath.length > 4096 || !path.isAbsolute(outputPath) || !/\.mcproxy\.json$/i.test(outputPath)) fail('LICENSE_ADMIN_OUTPUT_INVALID');
      await verifyCurrentGrant();
      const output = await (await tools()).reserveSafeOutput(outputPath);
      try { output.write(content); output.close(); }
      catch (error) { output.cancel(); throw error; }
      // Export composes the already-issued grant byte-for-byte. It cannot issue,
      // extend, rebind or charge a customer; old standalone grants remain valid.
      return { saved: true, filePath: outputPath, preview: customerDeliveryPreview(content) };
    }),
  };
}
