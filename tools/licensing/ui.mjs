import { resolve } from 'node:path';
import { LicenseError, publicKeyHash } from '../../backend/src/license-format.mjs';
import { openStore } from './runtime.mjs';
import { reserveSafeOutput } from './safe-files.mjs';

const ACTIONS = ['trial', 'activate', 'renew', 'refresh', 'rebind', 'revoke', 'resources', 'customers'];
function fail(message) { throw new LicenseError('INVALID_ARGUMENT', message); }
function application(value) {
  try { if (!value || Buffer.byteLength(JSON.stringify(value)) > 8192) fail('A bounded signed device application is required'); }
  catch { fail('A bounded signed device application is required'); }
  return value;
}
function effectiveStatus(row, now) {
  if (row.status === 'revoked') return 'revoked';
  if (row.expires_at <= now) return 'expired';
  if (row.license_version !== 2 && (row.resources_ready !== 1 || row.isp_expires_at <= now || (row.vps_expires_at !== null && row.vps_expires_at <= now))) return 'pending-resource';
  return 'active';
}
function resourceStatus(row, now) {
  if (row.resources_mode === 'customer') return 'customer';
  if (row.resources_ready !== 1) return 'pending';
  if (row.isp_expires_at <= now || row.vps_expires_at !== null && row.vps_expires_at <= now) return 'expired';
  return 'active';
}
function customers(store, keyId, publicKey) {
  const ledger = store.list(), now = store.serverTime();
  const orders = ledger.orders.map(order => ({ orderId: order.id, licenseId: order.license_id, kind: order.kind, amountFen: order.amount_fen, ispCostFen: order.isp_cost_fen, paidAt: order.paid_at, resourcesMode: order.resources_mode }));
  const list = ledger.licenses.map(row => ({ licenseId: row.id, deviceId: row.device_id, plan: row.plan, status: effectiveStatus(row, now), generation: row.generation,
    version: row.license_version, resourcesMode: row.resources_mode, resourceStatus: resourceStatus(row, now),
    expiresAt: row.expires_at, offlineUntil: store.envelope(row).payload.offlineUntil, ispExpiresAt: row.isp_expires_at, vpsExpiresAt: row.vps_expires_at,
    offlineDays: row.offline_window_ms / 86400000, amountFenPaid: orders.filter(order => order.licenseId === row.id).reduce((sum, order) => sum + order.amountFen, 0) }));
  const trialCount = list.filter(row => row.plan === 'isp-1d-trial').length, activeCount = list.filter(row => row.status === 'active').length;
  const totalReceivedFen = orders.reduce((sum, order) => sum + order.amountFen, 0), totalIspCostFen = orders.reduce((sum, order) => sum + order.ispCostFen, 0);
  return { keyId, publicKeyFingerprint: publicKeyHash(publicKey), customers: list, orders,
    summary: { licenseCount: list.length, customers: list.length, trialCount, trial: trialCount, paidLicenseCount: list.length - trialCount,
      activeCount, active: activeCount, revokedCount: list.filter(row => row.status === 'revoked').length, pendingResourceCount: list.filter(row => ['pending', 'expired'].includes(row.resourceStatus)).length,
      paidOrders: orders.length, totalReceivedFen, revenueFen: totalReceivedFen, totalIspCostFen } };
}
export async function runLicensingAction(options) {
  if (!options || !ACTIONS.includes(options.action) || typeof options.configPath !== 'string') fail('Invalid licensing action');
  const { action, configPath, outputPath } = options;
  if (action !== 'customers' && (typeof outputPath !== 'string' || !outputPath)) fail('Choose a new output file before issuing a license');
  const output = action === 'customers' ? null : await reserveSafeOutput(outputPath);
  let store, committed = false;
  try {
    const opened = await openStore(resolve(configPath), { deliver: output ? value => output.write(`${JSON.stringify(value, null, 2)}\n`) : undefined });
    store = opened.store;
    if (action === 'customers') return { action, ...customers(store, opened.keyId, opened.publicKey) };
    let envelope;
    switch (action) {
      case 'trial': envelope = store.trialOffline(application(options.applicationEnvelope), options); break;
      case 'activate': envelope = store.activateOffline(application(options.applicationEnvelope), options); break;
      case 'renew': envelope = store.renew(options.licenseId, options); break;
      case 'refresh': envelope = options.applicationEnvelope ? store.refreshOffline(application(options.applicationEnvelope), options) : store.refreshOfflineById(options.licenseId, options); break;
      case 'rebind': envelope = store.rebind(options.licenseId, application(options.applicationEnvelope), options); break;
      case 'revoke': envelope = store.revoke(options.licenseId); break;
      case 'resources': envelope = store.resources(options.licenseId, options); break;
    }
    committed = true;
    output.close();
    const { version, resourcesMode, licenseId, plan, status, generation, issuedAt, expiresAt, offlineUntil, ispExpiresAt, vpsExpiresAt } = envelope.payload;
    const result = { action, outputPath: resolve(outputPath), license: { version, resourcesMode, licenseId, plan, status, generation, issuedAt, expiresAt, offlineUntil, ispExpiresAt, vpsExpiresAt } };
    try { return { ...result, ...customers(store, opened.keyId, opened.publicKey) }; }
    catch { return { ...result, keyId: opened.keyId, publicKeyFingerprint: publicKeyHash(opened.publicKey), summaryUnavailable: true, summaryError: 'SUMMARY_UNAVAILABLE' }; }
  } catch (error) { if (!committed) output?.cancel(); else output?.close(); throw error; }
  finally { store?.close(); }
}
