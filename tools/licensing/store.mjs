import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { LICENSE_PLAN, LICENSE_TRIAL_PLAN, LICENSE_TRIAL_MS, LICENSE_TERM_MS, LICENSE_LEASE_MS, LicenseError, signLicense, verifyDeviceRequest } from '../../backend/src/license-format.mjs';

export const AMOUNT_FEN = 10000;
export const ISP_COST_FEN = 3500;
export const OFFLINE_DAYS = Object.freeze([1, 3, 7, 15, 30]);
const DAY = 86400000;
const hash = value => createHash('sha256').update(value).digest('hex');
const error = (code, message) => { throw new LicenseError(code, message); };
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(value)) error('INVALID_ORDER', 'Order identifier must contain 1–100 letters, digits, underscores or hyphens');
}
function resourceDates(ispExpiresAt, vpsExpiresAt, now) {
  if (!Number.isSafeInteger(ispExpiresAt) || ispExpiresAt <= now || (vpsExpiresAt !== null && (!Number.isSafeInteger(vpsExpiresAt) || vpsExpiresAt < 0))) error('RESOURCE_NOT_READY', 'Confirmed ISP expiry must be in the future; optional free VPS dates are reminders');
}
function resourcesMode(value, fallback = 'included') {
  const mode = value ?? fallback;
  if (!['included', 'customer'].includes(mode)) error('INVALID_RESOURCE_MODE', 'Choose included ISP delivery or customer-provided resources');
  return mode;
}
function resourceCoverage(ispExpiresAt, expiresAt) {
  if (!Number.isSafeInteger(expiresAt)) error('INVALID_EXPIRY', 'Invalid license expiry');
  if (!Number.isSafeInteger(ispExpiresAt) || ispExpiresAt < expiresAt) {
    error('RESOURCE_TERM_TOO_SHORT', `Included ISP must cover the complete software term through ${new Date(expiresAt).toISOString()}; no new payment record, term extension or license was committed`);
  }
}
function paidReady(options, now, mode = resourcesMode(options.resourcesMode)) {
  if (options.paid !== true) error('PAYMENT_NOT_CONFIRMED', 'Manual payment confirmation is required');
  if (mode === 'included') {
    if (options.resourcesReady !== true) error('RESOURCE_NOT_READY', 'Manual resource readiness confirmation is required');
    resourceDates(options.ispExpiresAt, options.vpsExpiresAt ?? null, now);
  }
  identifier(options.orderId);
}
function offlineWindow(days, fallback = LICENSE_TERM_MS) {
  if (days === undefined) return fallback;
  if (!OFFLINE_DAYS.includes(days)) error('INVALID_OFFLINE_WINDOW', 'Offline days must be 1, 3, 7, 15 or 30');
  return days * DAY;
}
function rowWindow(row, days) {
  const window = offlineWindow(days, row.offline_window_ms);
  if (row.plan === LICENSE_TRIAL_PLAN && window !== LICENSE_TRIAL_MS) error('TRIAL_WINDOW_FIXED', 'Trial offline window is fixed at one day');
  return window;
}

export class LicenseStore {
  constructor(path, { privateKey, keyId, now = Date.now, deliver } = {}) {
    this.signer = { privateKey, keyId };
    this.now = now;
    this.deliver = deliver;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS licenses (
        id TEXT PRIMARY KEY, device_id TEXT NOT NULL, device_key_hash TEXT NOT NULL, generation INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active','revoked','pending-resource')), expires_at INTEGER NOT NULL,
        isp_expires_at INTEGER NOT NULL, vps_expires_at INTEGER, resources_ready INTEGER NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL, license_id TEXT REFERENCES licenses(id), amount_fen INTEGER NOT NULL CHECK(amount_fen=10000),
        isp_cost_fen INTEGER NOT NULL CHECK(isp_cost_fen=3500), paid_at INTEGER NOT NULL, expires_at INTEGER);
      CREATE TABLE IF NOT EXISTS cards (
        card_hash TEXT PRIMARY KEY, order_id TEXT UNIQUE NOT NULL REFERENCES orders(id), license_id TEXT REFERENCES licenses(id),
        isp_expires_at INTEGER NOT NULL, vps_expires_at INTEGER, redeemed_at INTEGER, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')));
      CREATE TABLE IF NOT EXISTS bindings (
        license_id TEXT NOT NULL REFERENCES licenses(id), device_id TEXT NOT NULL, device_key_hash TEXT NOT NULL,
        PRIMARY KEY(license_id,device_id,device_key_hash));
      CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, license_id TEXT NOT NULL REFERENCES licenses(id), result TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, license_id TEXT, order_id TEXT, occurred_at INTEGER NOT NULL);`);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const columns = new Set(this.db.prepare('PRAGMA table_info(licenses)').all().map(column => column.name));
      for (const [name, definition] of [['plan', `TEXT NOT NULL DEFAULT '${LICENSE_PLAN}'`], ['offline_window_ms', `INTEGER NOT NULL DEFAULT ${LICENSE_LEASE_MS}`], ['lease_window_ms', `INTEGER NOT NULL DEFAULT ${LICENSE_LEASE_MS}`], ['resources_mode', "TEXT NOT NULL DEFAULT 'included'"], ['license_version', 'INTEGER NOT NULL DEFAULT 1']]) {
        if (!columns.has(name)) this.db.exec(`ALTER TABLE licenses ADD COLUMN ${name} ${definition}`);
      }
      for (const table of ['cards', 'orders']) {
        if (!this.db.prepare(`PRAGMA table_info(${table})`).all().some(column => column.name === 'resources_mode')) this.db.exec(`ALTER TABLE ${table} ADD COLUMN resources_mode TEXT NOT NULL DEFAULT 'included'`);
      }
      this.db.exec('COMMIT');
    } catch (cause) { this.db.exec('ROLLBACK'); this.db.close(); throw cause; }
  }
  close() { this.db.close(); }
  serverTime() {
    const now = this.now(), latest = this.db.prepare('SELECT MAX(stamp) AS latest FROM (SELECT MAX(updated_at) AS stamp FROM licenses UNION ALL SELECT MAX(occurred_at) AS stamp FROM events)').get().latest ?? 0;
    if (!Number.isSafeInteger(now) || now < latest || now < 0) error('SERVER_CLOCK_INVALID', 'Server clock moved backward; correct the server clock before issuing licenses');
    return now;
  }
  transaction(action) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = action(); this.deliver?.(result); this.db.exec('COMMIT'); return result; }
    catch (cause) { this.db.exec('ROLLBACK'); throw cause; }
  }
  event(type, licenseId, orderId, now) { this.db.prepare('INSERT INTO events(type,license_id,order_id,occurred_at) VALUES(?,?,?,?)').run(type, licenseId ?? null, orderId ?? null, now); }
  row(id) {
    const row = this.db.prepare('SELECT * FROM licenses WHERE id=?').get(id);
    if (!row) error('LICENSE_NOT_FOUND', 'License not found');
    return row;
  }
  envelope(row) {
    const issuedAt = row.updated_at;
    const ready = row.resources_ready === 1 && row.isp_expires_at > issuedAt && (row.vps_expires_at === null || row.vps_expires_at > issuedAt);
    const version = row.license_version ?? 1, mode = resourcesMode(row.resources_mode);
    const status = row.status === 'revoked' ? 'revoked' : version === 2 || ready ? 'active' : 'pending-resource';
    return signLicense({ version, ...(version === 2 ? { resourcesMode: mode } : {}), licenseId: row.id, deviceId: row.device_id, deviceKeyHash: row.device_key_hash,
      generation: row.generation, plan: row.plan, status, issuedAt, expiresAt: row.expires_at,
      offlineUntil: Math.min(issuedAt + (status === 'active' ? row.lease_window_ms : 0), row.expires_at, ...(version === 1 ? [row.isp_expires_at, row.vps_expires_at ?? Infinity] : [])),
      ispExpiresAt: mode === 'customer' ? null : row.isp_expires_at, vpsExpiresAt: mode === 'customer' ? null : row.vps_expires_at }, this.signer);
  }
  issueCard(options, { deliver } = {}) {
    return this.transaction(() => {
      const now = this.serverTime(), mode = resourcesMode(options.resourcesMode); paidReady(options, now, mode);
      if (this.db.prepare('SELECT id FROM orders WHERE id=?').get(options.orderId)) error('ORDER_EXISTS', 'Order already recorded; card secrets cannot be retrieved');
      if (mode === 'included') resourceCoverage(options.ispExpiresAt, now + LICENSE_TERM_MS);
      const card = `PP1_${randomBytes(32).toString('base64url')}`;
      this.db.prepare('INSERT INTO orders(id,kind,amount_fen,isp_cost_fen,paid_at,resources_mode) VALUES(?,?,?,?,?,?)').run(options.orderId, 'card', AMOUNT_FEN, ISP_COST_FEN, now, mode);
      this.db.prepare('INSERT INTO cards(card_hash,order_id,isp_expires_at,vps_expires_at,resources_mode) VALUES(?,?,?,?,?)').run(hash(card), options.orderId, mode === 'customer' ? 0 : options.ispExpiresAt, mode === 'customer' ? null : options.vpsExpiresAt ?? null, mode);
      this.event('card-issued', null, options.orderId, now);
      const result = { card, orderId: options.orderId, amountFen: AMOUNT_FEN, ispCostFen: mode === 'customer' ? 0 : ISP_COST_FEN, plan: LICENSE_PLAN, resourcesMode: mode };
      deliver?.(result);
      return result;
    });
  }
  cardResources(orderId, { resourcesReady, ispExpiresAt, vpsExpiresAt = null, resourcesMode: selectedMode }) {
    identifier(orderId);
    return this.transaction(() => {
      const now = this.serverTime();
      const card = this.db.prepare('SELECT * FROM cards WHERE order_id=?').get(orderId);
      if (!card || card.status !== 'active') error('CARD_INVALID', 'Activation card is invalid');
      if (card.license_id) error('CARD_ALREADY_USED', 'Use license resources for a redeemed card');
      const mode = resourcesMode(selectedMode, card.resources_mode);
      if (mode !== card.resources_mode) error('CARD_RESOURCE_MODE_FIXED', 'An unredeemed card must retain the original payment order ISP supply mode; update its resources using that mode');
      if (mode === 'included') {
        if (resourcesReady !== true) error('RESOURCE_NOT_READY', 'Manual resource readiness confirmation is required');
        resourceDates(ispExpiresAt, vpsExpiresAt, now);
        resourceCoverage(ispExpiresAt, now + LICENSE_TERM_MS);
      } else { ispExpiresAt = 0; vpsExpiresAt = null; }
      this.db.prepare('UPDATE cards SET isp_expires_at=?,vps_expires_at=?,resources_mode=? WHERE order_id=?').run(ispExpiresAt, vpsExpiresAt, mode, orderId);
      this.event('card-resources-confirmed', null, orderId, now);
      return { orderId, status: 'active', resourcesMode: mode, ispExpiresAt: mode === 'customer' ? null : ispExpiresAt, vpsExpiresAt };
    });
  }
  cardRevoke(orderId) {
    identifier(orderId);
    return this.transaction(() => {
      const now = this.serverTime();
      const card = this.db.prepare('SELECT * FROM cards WHERE order_id=?').get(orderId);
      if (!card) error('CARD_INVALID', 'Activation card is invalid');
      if (card.license_id) error('CARD_ALREADY_USED', 'Use license revoke for a redeemed card');
      if (card.status !== 'revoked') {
        this.db.prepare("UPDATE cards SET status='revoked' WHERE order_id=?").run(orderId);
        this.event('card-revoked', null, orderId, now);
      }
      return { orderId, status: 'revoked' };
    });
  }
  newLicense(request, keyHash, options, now) {
    const id = randomUUID();
    const plan = options.plan ?? LICENSE_PLAN, term = plan === LICENSE_TRIAL_PLAN ? LICENSE_TRIAL_MS : LICENSE_TERM_MS;
    const window = plan === LICENSE_TRIAL_PLAN ? LICENSE_TRIAL_MS : offlineWindow(options.offlineDays);
    const mode = resourcesMode(options.resourcesMode);
    if (mode === 'included' && plan !== LICENSE_TRIAL_PLAN) resourceCoverage(options.ispExpiresAt, now + term);
    // Zero is an internal sentinel only for the legacy NOT NULL resource column.
    // Customer-provided resources are exposed and signed as null in schema v2.
    this.db.prepare('INSERT INTO licenses(id,device_id,device_key_hash,generation,status,expires_at,isp_expires_at,vps_expires_at,resources_ready,created_at,updated_at,plan,offline_window_ms,lease_window_ms,resources_mode,license_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id, request.deviceId, keyHash, 1, 'active', now + term, mode === 'customer' ? 0 : options.ispExpiresAt, mode === 'customer' ? null : options.vpsExpiresAt ?? null, 1, now, now, plan, window, options.online ? LICENSE_LEASE_MS : window, mode, 2);
    this.db.prepare('INSERT INTO bindings VALUES(?,?,?)').run(id, request.deviceId, keyHash);
    return this.row(id);
  }
  addTerm(row, ispExpiresAt, vpsExpiresAt, now, { offlineDays, online = false, resourcesMode: selectedMode } = {}) {
    if (row.status === 'revoked') error('LICENSE_REVOKED', 'Revoked licenses cannot be renewed');
    const expiresAt = (row.plan === LICENSE_TRIAL_PLAN ? now : Math.max(now, row.expires_at)) + LICENSE_TERM_MS;
    const window = offlineWindow(offlineDays);
    if (!Number.isSafeInteger(expiresAt)) error('INVALID_EXPIRY', 'Invalid license expiry');
    const mode = resourcesMode(selectedMode, row.resources_mode);
    if (mode === 'included') resourceCoverage(ispExpiresAt, expiresAt);
    else { ispExpiresAt = 0; vpsExpiresAt = null; }
    this.db.prepare("UPDATE licenses SET generation=generation+1,status='active',plan=?,expires_at=?,isp_expires_at=?,vps_expires_at=?,resources_ready=1,updated_at=?,offline_window_ms=?,lease_window_ms=?,resources_mode=?,license_version=2 WHERE id=?").run(LICENSE_PLAN, expiresAt, ispExpiresAt, vpsExpiresAt, now, window, online ? LICENSE_LEASE_MS : window, mode, row.id);
    return this.row(row.id);
  }
  processRequest(envelope, expectedAction, { card: adminCard, requireLive = false, offlineDays } = {}) {
    const proof = verifyDeviceRequest(envelope);
    const { deviceKeyHash } = proof;
    const request = adminCard ? { ...proof.request, card: adminCard } : proof.request;
    if (request.action !== expectedAction) error('INVALID_REQUEST', 'Request action does not match endpoint');
    if (offlineDays !== undefined) offlineWindow(offlineDays);
    const fingerprintFields = [request.action, request.deviceId, deviceKeyHash, request.card ? hash(request.card) : null, request.licenseId ?? null];
    if (offlineDays !== undefined) fingerprintFields.push(offlineDays);
    const fingerprint = hash(JSON.stringify(fingerprintFields)), online = expectedAction !== 'offline';
    return this.transaction(() => {
      const now = this.serverTime();
      if (requireLive) {
        const current = this.row(request.licenseId);
        if (current.status !== 'revoked') {
          if (current.expires_at <= now) error('LICENSE_EXPIRED', 'Paid license has expired; a confirmed renewal is required');
        }
      }
      const previous = this.db.prepare('SELECT * FROM requests WHERE id=?').get(request.requestId);
      if (previous) {
        if (previous.fingerprint !== fingerprint) error('REQUEST_CONFLICT', 'Request identifier was already used');
        const saved = JSON.parse(previous.result), current = this.row(previous.license_id);
        if (saved.payload.generation === current.generation) return saved;
        const result = this.envelope(current, now);
        this.db.prepare('UPDATE requests SET result=? WHERE id=?').run(JSON.stringify(result), request.requestId);
        return result;
      }
      let row, refreshIssuance = false;
      if (expectedAction === 'redeem' || adminCard) {
        const card = this.db.prepare('SELECT * FROM cards WHERE card_hash=?').get(hash(request.card));
        if (!card || card.status !== 'active') error('CARD_INVALID', 'Activation card is invalid');
        if (card.license_id) {
          row = this.row(card.license_id);
          if (!this.db.prepare('SELECT 1 FROM bindings WHERE license_id=? AND device_id=? AND device_key_hash=?').get(row.id, request.deviceId, deviceKeyHash)) error('CARD_ALREADY_USED', 'Activation card was already used');
          refreshIssuance = true;
        } else {
          if (card.resources_mode === 'included') resourceDates(card.isp_expires_at, card.vps_expires_at, now);
          row = this.db.prepare("SELECT * FROM licenses WHERE device_id=? AND device_key_hash=? AND status!='revoked' ORDER BY created_at DESC LIMIT 1").get(request.deviceId, deviceKeyHash);
          const resourceOptions = { resourcesMode: card.resources_mode, offlineDays, online };
          row = row ? this.addTerm(row, card.isp_expires_at, card.vps_expires_at, now, resourceOptions) : this.newLicense(request, deviceKeyHash, { ispExpiresAt: card.isp_expires_at, vpsExpiresAt: card.vps_expires_at, ...resourceOptions }, now);
          this.db.prepare('UPDATE cards SET license_id=?,redeemed_at=? WHERE card_hash=?').run(row.id, now, card.card_hash);
          this.db.prepare('UPDATE orders SET license_id=?,expires_at=? WHERE id=?').run(row.id, row.expires_at, card.order_id);
          this.event('card-redeemed', row.id, card.order_id, now);
        }
      } else {
        row = this.row(request.licenseId);
        if (!this.db.prepare('SELECT 1 FROM bindings WHERE license_id=? AND device_id=? AND device_key_hash=?').get(row.id, request.deviceId, deviceKeyHash)) error('DEVICE_MISMATCH', 'License belongs to another device');
        refreshIssuance = true;
      }
      if (refreshIssuance) {
        const window = online ? LICENSE_LEASE_MS : rowWindow(row, offlineDays);
        this.db.prepare('UPDATE licenses SET generation=generation+1,updated_at=?,offline_window_ms=?,lease_window_ms=?,license_version=2 WHERE id=?').run(now, online ? row.offline_window_ms : window, window, row.id);
        row = this.row(row.id);
      }
      const result = this.envelope(row, now);
      this.db.prepare('INSERT INTO requests VALUES(?,?,?,?)').run(request.requestId, fingerprint, row.id, JSON.stringify(result));
      return result;
    });
  }
  redeem(envelope) { return this.processRequest(envelope, 'redeem'); }
  refresh(envelope) { return this.processRequest(envelope, 'refresh'); }
  refreshOffline(envelope, { offlineDays } = {}) {
    const { request } = verifyDeviceRequest(envelope);
    if (request.action !== 'offline' || !request.licenseId || request.card) error('INVALID_REQUEST', 'An offline application with the existing license identifier is required');
    return this.processRequest(envelope, 'offline', { requireLive: true, offlineDays });
  }
  refreshOfflineById(licenseId, { offlineDays } = {}) {
    return this.transaction(() => {
      const now = this.serverTime(), row = this.row(licenseId);
      if (row.status !== 'revoked') {
        if (row.expires_at <= now) error('LICENSE_EXPIRED', 'License has expired; a confirmed renewal is required');
      }
      const window = rowWindow(row, offlineDays);
      this.db.prepare('UPDATE licenses SET generation=generation+1,updated_at=?,offline_window_ms=?,lease_window_ms=?,license_version=2 WHERE id=?').run(now, window, window, licenseId);
      this.event('offline-refreshed', licenseId, null, now);
      return this.envelope(this.row(licenseId));
    });
  }
  trialOffline(envelope, options) {
    const { request, deviceKeyHash } = verifyDeviceRequest(envelope);
    if (request.action !== 'offline' || request.card) error('INVALID_REQUEST', 'An offline device application is required');
    if (options.paid || options.orderId) error('INVALID_TRIAL', 'Trial does not accept a payment or order');
    if (options.offlineDays !== undefined && options.offlineDays !== 1) error('TRIAL_WINDOW_FIXED', 'Trial is fixed at one day');
    return this.transaction(() => {
      const now = this.serverTime();
      const paid = this.db.prepare('SELECT l.id FROM licenses l JOIN bindings b ON b.license_id=l.id WHERE l.plan=? AND b.device_id=? LIMIT 1').get(LICENSE_PLAN, request.deviceId);
      if (paid) error('TRIAL_UNAVAILABLE', 'A paid device cannot be downgraded to a trial');
      const previous = this.db.prepare('SELECT l.* FROM licenses l JOIN bindings b ON b.license_id=l.id WHERE l.plan=? AND b.device_id=? ORDER BY l.created_at LIMIT 1').get(LICENSE_TRIAL_PLAN, request.deviceId);
      if (previous) {
        if (request.licenseId && request.licenseId !== previous.id) error('DEVICE_MISMATCH', 'Application belongs to another license');
        return this.envelope(previous);
      }
      if (request.licenseId) error('LICENSE_NOT_FOUND', 'Existing trial was not found');
      if (resourcesMode(options.resourcesMode) === 'included') {
        if (options.resourcesReady !== true) error('RESOURCE_NOT_READY', 'Manual resource readiness confirmation is required');
        resourceDates(options.ispExpiresAt, options.vpsExpiresAt ?? null, now);
      }
      const row = this.newLicense(request, deviceKeyHash, { ...options, plan: LICENSE_TRIAL_PLAN }, now);
      this.event('trial-issued', row.id, null, now);
      return this.envelope(row);
    });
  }
  activateOffline(envelope, options) {
    const { request, deviceKeyHash } = verifyDeviceRequest(envelope);
    if (request.action !== 'offline') error('INVALID_REQUEST', 'An offline device application is required');
    if (request.card) error('INVALID_REQUEST', 'Offline applications must not contain an activation card');
    if (options.card) {
      if (request.licenseId || typeof options.card !== 'string' || !/^PP1_[A-Za-z0-9_-]{43}$/.test(options.card)) error('INVALID_REQUEST', 'Invalid offline activation card');
      return this.processRequest(envelope, 'offline', { card: options.card, offlineDays: options.offlineDays });
    }
    return this.transaction(() => {
      const now = this.serverTime(); identifier(options.orderId);
      const oldOrder = this.db.prepare('SELECT * FROM orders WHERE id=?').get(options.orderId);
      if (oldOrder) {
        if (oldOrder.kind !== 'offline' || !oldOrder.license_id) error('ORDER_CONFLICT', 'Order belongs to another operation');
        const row = this.row(oldOrder.license_id);
        if (row.device_id !== request.deviceId || row.device_key_hash !== deviceKeyHash) error('ORDER_CONFLICT', 'Order belongs to another device');
        return this.envelope(row, now);
      }
      let row;
      if (request.licenseId) {
        row = this.row(request.licenseId);
        if (row.device_id !== request.deviceId || row.device_key_hash !== deviceKeyHash) error('DEVICE_MISMATCH', 'License belongs to another device');
      } else {
        row = this.db.prepare("SELECT * FROM licenses WHERE device_id=? AND device_key_hash=? AND status!='revoked' ORDER BY created_at DESC LIMIT 1").get(request.deviceId, deviceKeyHash);
      }
      const mode = resourcesMode(options.resourcesMode, row?.resources_mode ?? 'included'), issueOptions = { ...options, resourcesMode: mode };
      paidReady(issueOptions, now, mode);
      row = row ? this.addTerm(row, options.ispExpiresAt, options.vpsExpiresAt ?? null, now, issueOptions) : this.newLicense(request, deviceKeyHash, issueOptions, now);
      this.db.prepare('INSERT INTO orders(id,kind,license_id,amount_fen,isp_cost_fen,paid_at,expires_at,resources_mode) VALUES(?,?,?,?,?,?,?,?)').run(options.orderId, 'offline', row.id, AMOUNT_FEN, ISP_COST_FEN, now, row.expires_at, mode);
      this.event('offline-activated', row.id, options.orderId, now);
      return this.envelope(row, now);
    });
  }
  renew(licenseId, options) {
    return this.transaction(() => {
      const now = this.serverTime(); identifier(options.orderId);
      const oldOrder = this.db.prepare('SELECT * FROM orders WHERE id=?').get(options.orderId);
      if (oldOrder) {
        if (oldOrder.kind !== 'renew' || oldOrder.license_id !== licenseId) error('ORDER_CONFLICT', 'Order belongs to another operation');
        return this.envelope(this.row(licenseId), now);
      }
      const current = this.row(licenseId), mode = resourcesMode(options.resourcesMode, current.resources_mode), issueOptions = { ...options, resourcesMode: mode };
      paidReady(issueOptions, now, mode);
      const row = this.addTerm(current, options.ispExpiresAt, options.vpsExpiresAt ?? null, now, issueOptions);
      this.db.prepare('INSERT INTO orders(id,kind,license_id,amount_fen,isp_cost_fen,paid_at,expires_at,resources_mode) VALUES(?,?,?,?,?,?,?,?)').run(options.orderId, 'renew', licenseId, AMOUNT_FEN, ISP_COST_FEN, now, row.expires_at, mode);
      this.event('renewed', licenseId, options.orderId, now);
      return this.envelope(row, now);
    });
  }
  resources(licenseId, { resourcesReady, ispExpiresAt, vpsExpiresAt = null, offlineDays, resourcesMode: selectedMode }) {
    return this.transaction(() => {
      const now = this.serverTime();
      const row = this.row(licenseId);
      if (row.status === 'revoked') error('LICENSE_REVOKED', 'License was revoked');
      const mode = resourcesMode(selectedMode, row.resources_mode);
      if (mode === 'customer') { resourcesReady = true; ispExpiresAt = 0; vpsExpiresAt = null; }
      else {
        if (typeof resourcesReady !== 'boolean') error('RESOURCE_NOT_READY', 'Resource readiness must be explicitly confirmed or marked pending');
        if (resourcesReady) {
          // Resource reminders may truthfully record an expired supplier term.
          // Only a new bundled payment promises and checks full delivery coverage.
          if (!Number.isSafeInteger(ispExpiresAt) || ispExpiresAt < 0 || vpsExpiresAt !== null && (!Number.isSafeInteger(vpsExpiresAt) || vpsExpiresAt < 0)) error('INVALID_EXPIRY', 'Resource reminder dates must be valid timestamps');
        } else { ispExpiresAt = row.isp_expires_at; vpsExpiresAt = row.vps_expires_at; }
      }
      const window = rowWindow(row, offlineDays);
      this.db.prepare("UPDATE licenses SET generation=generation+1,status='active',isp_expires_at=?,vps_expires_at=?,resources_ready=?,updated_at=?,offline_window_ms=?,lease_window_ms=?,resources_mode=?,license_version=2 WHERE id=?").run(ispExpiresAt, vpsExpiresAt, resourcesReady ? 1 : 0, now, window, window, mode, licenseId);
      this.event(resourcesReady ? 'resources-confirmed' : 'resources-pending', licenseId, null, now);
      return this.envelope(this.row(licenseId), now);
    });
  }
  rebind(licenseId, envelope, { offlineDays } = {}) {
    const { request, deviceKeyHash } = verifyDeviceRequest(envelope);
    if (request.action !== 'offline' || request.card || (request.licenseId && request.licenseId !== licenseId)) error('INVALID_REQUEST', 'An offline application from the replacement device is required');
    return this.transaction(() => {
      const now = this.serverTime();
      const row = this.row(licenseId);
      if (row.status === 'revoked') error('LICENSE_REVOKED', 'License was revoked');
      const window = rowWindow(row, offlineDays);
      if (row.device_id !== request.deviceId || row.device_key_hash !== deviceKeyHash || window !== row.offline_window_ms || row.license_version !== 2) {
        this.db.prepare('UPDATE licenses SET generation=generation+1,device_id=?,device_key_hash=?,updated_at=?,offline_window_ms=?,lease_window_ms=?,license_version=2 WHERE id=?').run(request.deviceId, deviceKeyHash, now, window, window, licenseId);
        this.db.prepare('INSERT OR IGNORE INTO bindings VALUES(?,?,?)').run(licenseId, request.deviceId, deviceKeyHash);
        this.event('rebound', licenseId, null, now);
      }
      return this.envelope(this.row(licenseId), now);
    });
  }
  revoke(licenseId) {
    return this.transaction(() => {
      const now = this.serverTime();
      const row = this.row(licenseId);
      if (row.status !== 'revoked') {
        this.db.prepare("UPDATE licenses SET generation=generation+1,status='revoked',updated_at=?,license_version=2 WHERE id=?").run(now, licenseId);
        this.event('revoked', licenseId, null, now);
      }
      return this.envelope(this.row(licenseId), now);
    });
  }
  list() {
    const publicResource = row => row.resources_mode === 'customer' ? { ...row, isp_expires_at: null, vps_expires_at: null } : row;
    // The legacy SQL cost column has a fixed-3500 CHECK. Ownership is persisted
    // per order; every public ledger/report exposes actual customer ISP cost 0.
    const orders = this.db.prepare('SELECT * FROM orders ORDER BY paid_at,id').all().map(row => ({ ...row, isp_cost_fen: row.resources_mode === 'customer' ? 0 : row.isp_cost_fen }));
    return { licenses: this.db.prepare('SELECT * FROM licenses ORDER BY created_at,id').all().map(publicResource), orders,
      cards: this.db.prepare('SELECT order_id,license_id,isp_expires_at,vps_expires_at,redeemed_at,status,resources_mode FROM cards ORDER BY order_id').all().map(publicResource), events: this.db.prepare('SELECT * FROM events ORDER BY id').all() };
  }
  status(licenseId) { return this.envelope(this.row(licenseId)); }
}
