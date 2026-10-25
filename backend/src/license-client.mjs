import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { performance } from 'node:perf_hooks';
import { lstat, realpath, readFile, open, rm } from 'node:fs/promises';
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { connectTunnel } from './probe.mjs';
import { LicenseError, licenseExpiresAt, publicKeyHash, signDeviceRequest, validateLicenseConfig, verifyLicense } from './license-format.mjs';

const MAX_JSON = 128 * 1024;
const DAY = 24 * 60 * 60 * 1000;
const HOUR = DAY / 24;
const CLOCK_ALLOWANCE = 5 * 60 * 1000;
const CLOCK_CHECKPOINT_INTERVAL = 5 * 60 * 1000;
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const cacheBytes = record => Buffer.from(`ProxyPilot:license-cache:v1\n${canonical(record)}`);
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const errors = Object.freeze({
  LICENSE_CONFIG_INVALID: '授权配置无效，请联系软件提供方。',
  LICENSE_STATE_INVALID: '本机授权记录无效，请检查保留的授权文件。',
  LICENSE_PATH_INVALID: '授权存储路径异常，未读取或覆盖授权文件。',
  LICENSE_STATE_CONFLICT: '授权记录已被其他操作修改，请重新启动软件。',
  LICENSE_DEVICE_UNAVAILABLE: '无法确认本机设备身份，请检查系统权限。',
  LICENSE_REQUIRED: '请先激活本机授权。',
  LICENSE_EXPIRED: '授权已到期，请续费或导入新的授权文件。',
  LICENSE_REFRESH_REQUIRED: '离线授权已到期，请刷新授权或导入新的签名授权文件。',
  LICENSE_REVOKED: '本机授权已撤销，请联系软件提供方。',
  LICENSE_RESOURCE_PENDING: '授权资源尚未配置完成，请联系软件提供方。',
  LICENSE_DEVICE_MISMATCH: '授权属于另一台设备，请申请本机授权。',
  LICENSE_CLOCK_ROLLBACK: '系统 UTC 时间早于已验证授权时间，请校准系统时间。',
  LICENSE_INVALID: '签名授权文件无效，原有授权已保留。',
  LICENSE_REPLAY: '授权文件早于本机已验证的授权记录，未覆盖现有授权。',
  LICENSE_NETWORK_FAILED: '无法连接授权服务，仍按已保存授权的有效期判断。',
  LICENSE_TIMEOUT: '授权服务响应超时，仍按已保存授权的有效期判断。',
  LICENSE_RESPONSE_INVALID: '授权服务响应无效，原有授权已保留。',
  LICENSE_SERVICE_REJECTED: '授权服务拒绝请求，请检查卡密或联系软件提供方。',
  LICENSE_PROXY_UNVERIFIED: '当前代理未经验证，未发送授权请求。',
  LICENSE_ONLINE_UNAVAILABLE: '当前版本仅支持离线授权，请导入签名授权文件。',
  LICENSE_CARD_INVALID: '卡密格式无效，请检查输入。',
  LICENSE_CLOSED: '授权管理已停止。',
});
export const LICENSE_ERROR_MESSAGES = errors;
const unavailable = new Set(['LICENSE_TIMEOUT', 'LICENSE_NETWORK_FAILED', 'LICENSE_RESPONSE_INVALID', 'LICENSE_PROXY_UNVERIFIED']);
const error = code => Object.assign(new LicenseError(code, errors[code] || errors.LICENSE_INVALID), { status: unavailable.has(code) ? 503 : code === 'LICENSE_CARD_INVALID' ? 400 : 409 });
const fail = code => { throw error(code); };
const time = value => Number.isSafeInteger(value) && value >= 0;
const boundedJson = value => {
  let text;
  try { text = typeof value === 'string' ? value : JSON.stringify(value); }
  catch { fail('LICENSE_RESPONSE_INVALID'); }
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_JSON) fail('LICENSE_RESPONSE_INVALID');
  try { return JSON.parse(text.replace(/^\uFEFF/, '')); } catch { fail('LICENSE_RESPONSE_INVALID'); }
};

// Read one stable machine identity at startup; locale, timezone and network
// adapters are deliberately absent from the device binding.
async function windowsIdentity() {
  if (process.platform !== 'win32') fail('LICENSE_DEVICE_UNAVAILABLE');
  const result = await promisify(execFile)('reg.exe', ['query', 'HKLM\\SOFTWARE\\Microsoft\\Cryptography', '/v', 'MachineGuid'], {
    encoding: 'utf8', windowsHide: true, timeout: 5000, maxBuffer: 16384,
  });
  const identity = /MachineGuid\s+REG_SZ\s+([a-f0-9-]{36})/i.exec(result.stdout)?.[1];
  if (!identity) fail('LICENSE_DEVICE_UNAVAILABLE');
  return identity.toLowerCase();
}

// This transport never reads ambient proxy settings or follows redirects. A
// chosen verified loopback proxy cannot silently fall back to a direct socket.
export async function requestLicense(url, { body, proxyPort = null, timeoutMs = 8000, signal, allowLoopback = false } = {}) {
  try { url = url instanceof URL ? url : new URL(url); } catch { fail('LICENSE_CONFIG_INVALID'); }
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(allowLoopback && loopback && url.protocol === 'http:')) || url.username || url.password
    || !['/v1/redeem', '/v1/refresh'].includes(url.pathname) || url.search || url.hash
    || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 8000
    || (proxyPort !== null && (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535))
    || (proxyPort !== null && url.protocol !== 'https:')) fail('LICENSE_CONFIG_INVALID');
  let payload;
  try { payload = Buffer.from(JSON.stringify(body)); } catch { fail('LICENSE_RESPONSE_INVALID'); }
  if (payload.length > MAX_JSON) fail('LICENSE_RESPONSE_INVALID');
  let tunnel, secure, request, agent, settled = false;
  const started = performance.now();
  try {
    if (signal?.aborted) fail('LICENSE_TIMEOUT');
    if (proxyPort !== null) {
      tunnel = await connectTunnel({ host: url.hostname.replace(/^\[|\]$/g, ''), port: Number(url.port || 443), proxyPort, timeoutMs,
        onSocket(socket) { tunnel = socket; signal?.addEventListener('abort', () => socket.destroy(), { once: true }); },
      });
    }
    if (signal?.aborted) fail('LICENSE_TIMEOUT');
    return await new Promise((resolve, reject) => {
      const finish = (cause, result) => {
        if (settled) return;
        settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
        agent?.destroy(); secure?.destroy(); tunnel?.destroy();
        cause ? reject(cause) : resolve(result);
      };
      const abort = () => { finish(error('LICENSE_TIMEOUT')); request?.destroy(); };
      const timer = setTimeout(abort, Math.max(1, timeoutMs - (performance.now() - started)));
      signal?.addEventListener('abort', abort, { once: true });
      if (tunnel) {
        const host = url.hostname.replace(/^\[|\]$/g, '');
        agent = new https.Agent({ keepAlive: false });
        agent.createConnection = () => {
          secure = tls.connect({ socket: tunnel, host, servername: isIP(host) ? undefined : host, rejectUnauthorized: true, minVersion: 'TLSv1.2' });
          secure.once('error', () => finish(error('LICENSE_NETWORK_FAILED')));
          return secure;
        };
      }
      const protocol = url.protocol === 'https:' ? https : http;
      request = protocol.request(url, { method: 'POST', agent: agent || false, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        headers: { accept: 'application/json', 'content-type': 'application/json', 'content-length': payload.length, connection: 'close' },
      }, response => {
        if (response.statusCode !== 200) { response.resume(); finish(error('LICENSE_SERVICE_REJECTED')); request.destroy(); return; }
        const chunks = []; let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > MAX_JSON) { finish(error('LICENSE_RESPONSE_INVALID')); response.destroy(); request.destroy(); }
          else chunks.push(chunk);
        });
        response.once('error', () => finish(error('LICENSE_NETWORK_FAILED')));
        response.once('end', () => {
          if (settled) return;
          try { finish(null, boundedJson(Buffer.concat(chunks).toString('utf8'))); }
          catch { finish(error('LICENSE_RESPONSE_INVALID')); }
        });
      });
      request.once('error', () => finish(error(signal?.aborted ? 'LICENSE_TIMEOUT' : 'LICENSE_NETWORK_FAILED')));
      request.end(payload);
    });
  } catch (cause) {
    tunnel?.destroy();
    if (cause instanceof LicenseError) throw cause;
    throw error(signal?.aborted || cause?.code === 'PROXY_TIMEOUT' ? 'LICENSE_TIMEOUT' : 'LICENSE_NETWORK_FAILED');
  }
}

export function createLicenseClient({ stateDir, config, mock = false, now = Date.now, request = requestLicense,
  getProxy = () => null, getDeviceIdentity = windowsIdentity, dependencies = {} } = {}) {
  let settings, configError = false;
  try { settings = config === undefined || config === null ? { version: 1, mode: 'development', serviceUrl: '', publicKeys: {} }
    : validateLicenseConfig(config, { allowLoopback: dependencies.allowLoopback === true }); }
  catch { settings = { version: 1, mode: 'required', serviceUrl: '', publicKeys: {} }; configError = true; }
  const required = settings.mode === 'required';
  const root = stateDir && path.resolve(stateDir);
  const fs = { lstat, realpath, readFile, open, rm, createPrivateDirectory, writePrivate, renamePrivate, ...dependencies };
  const timeoutMs = Math.min(8000, Math.max(1, dependencies.timeoutMs || 8000));
  const monotonic = dependencies.monotonic || (() => performance.now());
  const schedule = dependencies.setTimeout || setTimeout;
  const unschedule = dependencies.clearTimeout || clearTimeout;
  let initialized = false, initPromise, closed = false, timer, identity, deviceId, deviceKeyHash, device, record = null, recordRaw = null;
  let blocked = configError ? 'LICENSE_CONFIG_INVALID' : null, lastError = null, lastRefreshAt = null, lastCheckedAt = null, refreshing = false;
  let trustedAnchor = 0, monotonicAnchor = monotonic(), wallHighWater = 0, clockHighWater = 0;
  let backgroundPending = false, checkpointPending = false, closePromise;
  const freshRefresh = () => ({ lastAttemptAt: null, retryAt: 0, failures: 0, proxyBlocked: false });
  let refreshState = freshRefresh();
  let serial = Promise.resolve();
  const requests = new Set();
  const locked = action => { const work = serial.then(action, action); serial = work.catch(() => {}); return work; };
  const clock = () => {
    const wall = now();
    if (!time(wall)) return { invalid: true, effective: Infinity };
    const rollback = wall + CLOCK_ALLOWANCE < Math.max(record?.lastTrustedServerTime || 0, wallHighWater);
    const elapsed = monotonic();
    const effective = Math.max(wall, clockHighWater, trustedAnchor + Math.max(0, elapsed - monotonicAnchor));
    if (!time(Math.floor(effective))) return { invalid: true, effective: Infinity };
    trustedAnchor = effective; monotonicAnchor = elapsed;
    wallHighWater = Math.max(wallHighWater, wall); clockHighWater = Math.max(clockHighWater, Math.floor(effective));
    queueCheckpoint();
    return { invalid: rollback, effective };
  };
  // Reuse the authenticated journal and its serialization queue. Frequent
  // authorization reads coalesce into at most one write per five minutes;
  // the online refresh timer and retry deadlines remain independent.
  function queueCheckpoint() {
    if (!initialized || !required || !record || blocked || closed || checkpointPending
      || clockHighWater < record.lastObservedTime + CLOCK_CHECKPOINT_INTERVAL) return;
    checkpointPending = true;
    locked(async () => { if (!closed && !blocked) await checkpoint(); })
      .finally(() => { checkpointPending = false; });
  }
  async function checkpoint() {
    if (!record || blocked) return;
    clock();
    if (clockHighWater <= record.lastObservedTime) return;
    try { await save({ ...record, lastObservedTime: clockHighWater }); }
    catch (cause) {
      blocked = ['LICENSE_PATH_INVALID', 'LICENSE_STATE_CONFLICT'].includes(cause?.code) ? cause.code : 'LICENSE_STATE_INVALID';
      lastError = blocked;
      if (timer !== undefined) { unschedule(timer); timer = undefined; }
    }
  }
  function dueAt() {
    const claims = record?.license?.payload;
    if (!claims) return Infinity;
    return claims.status === 'active' ? Math.min(claims.issuedAt + DAY, claims.offlineUntil) : claims.issuedAt + DAY;
  }
  function scheduleRefresh() {
    if (timer !== undefined) { unschedule(timer); timer = undefined; }
    if (!initialized || !required || !settings.serviceUrl || blocked || closed || !record || backgroundPending || refreshing || !time(now())) return;
    const deadline = Math.max(dueAt(), refreshState.retryAt);
    const delay = Math.min(DAY, Math.max(0, Math.ceil(deadline - clock().effective)));
    timer = schedule(() => { timer = undefined; if (!refreshIfDue()) scheduleRefresh(); }, delay);
    timer?.unref?.();
  }
  // Called after a verified route becomes available. Only local cached time and
  // the supplied synchronous lease callback are inspected before queuing work.
  function backgroundDue() {
    if (!record || !time(now())) return false;
    const current = clock().effective;
    if (current < dueAt()) return false;
    if (current < refreshState.retryAt) {
      if (!refreshState.proxyBlocked) return false;
      let proxy;
      try { proxy = getProxy(); } catch { return false; }
      const port = proxy?.proxyPort ?? proxy?.port;
      if (!proxy || proxy.then || proxy.unavailable || proxy.verified === false || proxy.host && proxy.host !== '127.0.0.1'
        || !Number.isInteger(port) || port < 1 || port > 65535) return false;
    }
    return true;
  }
  function refreshIfDue() {
    if (!initialized || !required || !settings.serviceUrl || blocked || closed || backgroundPending || refreshing || !backgroundDue()) return false;
    if (timer !== undefined) { unschedule(timer); timer = undefined; }
    backgroundPending = true;
    locked(async () => {
      // Activation/import may have refreshed the token while this job queued.
      if (closed || blocked || !backgroundDue()) return;
      await runRefresh();
    }).catch(() => {}).finally(() => { backgroundPending = false; scheduleRefresh(); });
    return true;
  }
  function status() {
    const claims = record?.license?.payload;
    let reason = null, state = 'development', allowed = true;
    if (required) {
      allowed = false;
      reason = closed ? 'LICENSE_CLOSED' : blocked || (!initialized ? 'LICENSE_REQUIRED' : null);
      state = !initialized ? 'initializing' : 'unlicensed';
      if (!reason && !claims) reason = 'LICENSE_REQUIRED';
      if (!reason && (claims.deviceId !== deviceId || claims.deviceKeyHash !== deviceKeyHash)) reason = 'LICENSE_DEVICE_MISMATCH';
      if (!reason && claims.status === 'revoked') reason = 'LICENSE_REVOKED';
      if (!reason && claims.version === 1 && claims.status === 'pending-resource') reason = 'LICENSE_RESOURCE_PENDING';
      if (!reason && claims) {
        const observed = clock();
        if (observed.invalid) reason = 'LICENSE_CLOCK_ROLLBACK';
        else if (observed.effective >= licenseExpiresAt(claims)) reason = 'LICENSE_EXPIRED';
        else if (observed.effective >= claims.offlineUntil) reason = 'LICENSE_REFRESH_REQUIRED';
        else { state = 'active'; allowed = true; }
      }
      if (reason) state = ({ LICENSE_CONFIG_INVALID: 'error', LICENSE_STATE_INVALID: 'error', LICENSE_PATH_INVALID: 'error',
        LICENSE_STATE_CONFLICT: 'error', LICENSE_DEVICE_UNAVAILABLE: 'error', LICENSE_REQUIRED: 'unactivated',
        LICENSE_REVOKED: 'revoked', LICENSE_RESOURCE_PENDING: 'pending-resource', LICENSE_DEVICE_MISMATCH: 'device-mismatch',
        LICENSE_CLOCK_ROLLBACK: 'error', LICENSE_EXPIRED: 'expired', LICENSE_REFRESH_REQUIRED: 'offline-expired', LICENSE_CLOSED: 'error' })[reason] || 'error';
      if (state === 'device-mismatch') state = 'error';
    }
    return { version: 1, mode: settings.mode, required, enabled: required, onlineAvailable: Boolean(settings.serviceUrl), allowed, state, status: state, reason,
      message: reason ? errors[reason] : null, deviceId: deviceId || null, deviceKeyHash: deviceKeyHash || null,
      licenseId: claims?.licenseId || null, licenseVersion: claims?.version ?? null, resourcesMode: claims ? claims.version === 2 ? claims.resourcesMode : 'included' : null,
      plan: claims?.plan || null, generation: claims?.generation || null,
      issuedAt: claims?.issuedAt ?? null, expiresAt: claims?.expiresAt ?? null, offlineUntil: claims?.offlineUntil ?? null,
      ispExpiresAt: claims?.ispExpiresAt ?? null, vpsExpiresAt: claims?.vpsExpiresAt ?? null, priceCny: claims?.plan === 'isp-1d-trial' ? 0 : 100, refreshing, lastCheckedAt, lastRefreshAt, lastError };
  }
  // Authorization is synchronous and only inspects authenticated cached data.
  function assertAllowed() { const current = status(); if (!current.allowed) throw error(current.reason); return current; }
  async function safe(file) {
    if (!root || !path.isAbsolute(stateDir) || path.relative(root, file).startsWith('..') || path.isAbsolute(path.relative(root, file))) fail('LICENSE_PATH_INVALID');
    let cursor = path.parse(file).root;
    const parts = file.slice(cursor.length).split(path.sep).filter(Boolean);
    if (parts.length > 64) fail('LICENSE_PATH_INVALID');
    for (const part of parts) {
      cursor = path.join(cursor, part);
      let info;
      try { info = await fs.lstat(cursor); } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
      if (info.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('LICENSE_PATH_INVALID');
    }
  }
  async function readOptional(file) {
    await safe(file);
    try {
      const info = await fs.lstat(file);
      if (!info.isFile() || info.nlink > 1 || info.size > MAX_JSON) fail('LICENSE_STATE_INVALID');
      const bytes = await fs.readFile(file, 'utf8');
      if (Buffer.byteLength(bytes) > MAX_JSON) fail('LICENSE_STATE_INVALID');
      return bytes;
    } catch (cause) { if (cause.code === 'ENOENT') return null; throw cause; }
  }
  async function ensureRoot() {
    await safe(root);
    const missing = [];
    let cursor = root;
    for (let depth = 0; ; depth++) {
      if (depth > 64) fail('LICENSE_PATH_INVALID');
      try { if (!(await fs.lstat(cursor)).isDirectory()) fail('LICENSE_PATH_INVALID'); break; }
      catch (cause) {
        if (cause.code !== 'ENOENT') throw cause;
        missing.push(cursor);
        const parent = path.dirname(cursor);
        if (parent === cursor) fail('LICENSE_PATH_INVALID');
        cursor = parent;
      }
    }
    for (const directory of missing.reverse()) {
      await safe(root);
      await fs.createPrivateDirectory(directory);
    }
    return missing.includes(root);
  }
  async function durable(file, bytes) {
    await safe(file); await fs.writePrivate(file, bytes);
    const handle = await fs.open(file, 'r+');
    try { await handle.sync(); } finally { await handle.close(); }
  }
  function authenticate(envelope) {
    try {
      // Bind to the signed claims while authenticating, then compare locally.
      // A newer signed rebind must replace the old locally authorized token.
      return verifyLicense(envelope, { publicKeys: settings.publicKeys, deviceId: envelope?.payload?.deviceId,
        deviceKeyHash: envelope?.payload?.deviceKeyHash, now: Math.max(time(now()) ? now() : 0, envelope?.payload?.issuedAt || 0), allowExpired: true });
    } catch { fail('LICENSE_INVALID'); }
  }
  async function save(next, { metadataOnly = false } = {}) {
    if (mock) { record = structuredClone(next); return; }
    const file = path.join(root, 'state.json');
    const signed = { record: next, signature: sign(null, cacheBytes(next), device.privateKey).toString('base64url') };
    const bytes = `${JSON.stringify(signed)}\n`;
    if (Buffer.byteLength(bytes) > MAX_JSON) fail('LICENSE_STATE_INVALID');
    const temp = path.join(root, `.license-${randomUUID()}.tmp`);
    try {
      await durable(temp, bytes);
      if (await readOptional(file) !== recordRaw) { if (!metadataOnly) blocked = 'LICENSE_STATE_CONFLICT'; fail('LICENSE_STATE_CONFLICT'); }
      await safe(file); await fs.renamePrivate(temp, file);
      recordRaw = bytes; record = structuredClone(next);
    } finally { await fs.rm(temp, { force: true }).catch(() => {}); }
  }
  async function loadDevice() {
    const deviceFile = root && path.join(root, 'device.json');
    const createdRoot = mock || await ensureRoot();
    const existing = mock ? null : await readOptional(deviceFile);
    const cache = mock ? null : await readOptional(path.join(root, 'state.json'));
    if (cache !== null && existing === null) fail('LICENSE_STATE_INVALID');
    if (existing === null) {
      // Never place a new plaintext private key in a pre-existing directory
      // whose ACL this client did not establish. Preserve it for inspection.
      if (!createdRoot) fail('LICENSE_STATE_INVALID');
      const pair = generateKeyPairSync('ed25519');
      device = { privateKey: pair.privateKey, publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }) };
      if (!mock) await durable(deviceFile, `${JSON.stringify({ version: 1, privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKey: device.publicKey })}\n`);
    } else {
      const saved = boundedJson(existing);
      if (saved?.version !== 1 || Object.keys(saved).length !== 3 || typeof saved.privateKey !== 'string' || typeof saved.publicKey !== 'string') fail('LICENSE_STATE_INVALID');
      const key = createPrivateKey(saved.privateKey);
      if (key.asymmetricKeyType !== 'ed25519' || publicKeyHash(createPublicKey(key).export({ type: 'spki', format: 'pem' })) !== publicKeyHash(saved.publicKey)) fail('LICENSE_STATE_INVALID');
      device = { privateKey: key, publicKey: saved.publicKey };
    }
    try { identity = mock && getDeviceIdentity === windowsIdentity ? 'mock-license-device' : await getDeviceIdentity(); }
    catch { fail('LICENSE_DEVICE_UNAVAILABLE'); }
    if (typeof identity !== 'string' || !identity || Buffer.byteLength(identity) > 4096) fail('LICENSE_DEVICE_UNAVAILABLE');
    deviceKeyHash = publicKeyHash(device.publicKey);
    deviceId = hash(`ProxyPilot:device:v1\n${identity}\n${deviceKeyHash}`);
    identity = null;
    if (cache !== null) {
      const saved = boundedJson(cache), value = saved?.record;
      if (!value || value.version !== 1 || value.deviceId !== deviceId || value.deviceKeyHash !== deviceKeyHash || !time(value.lastTrustedServerTime)
        || !time(value.lastObservedTime) || typeof saved.signature !== 'string' || Object.keys(saved).length !== 2
        || !verify(null, cacheBytes(value), device.publicKey, Buffer.from(saved.signature, 'base64url'))) fail('LICENSE_STATE_INVALID');
      const claims = authenticate(value.license);
      const history = value.history;
      if (!history || typeof history !== 'object' || Array.isArray(history) || Object.keys(history).length > 128
        || history[claims.licenseId]?.generation !== claims.generation || history[claims.licenseId]?.digest !== hash(canonical(value.license))) fail('LICENSE_STATE_INVALID');
      record = value; recordRaw = cache;
      if (value.refresh !== undefined) {
        const item = value.refresh;
        if (!item || (item.lastAttemptAt !== null && !time(item.lastAttemptAt)) || !time(item.retryAt)
          || !Number.isInteger(item.failures) || item.failures < 0 || item.failures > 4 || typeof item.proxyBlocked !== 'boolean') fail('LICENSE_STATE_INVALID');
        refreshState = { ...item };
      }
      trustedAnchor = Math.max(value.lastTrustedServerTime, value.lastObservedTime); wallHighWater = clockHighWater = value.lastObservedTime;
      monotonicAnchor = monotonic();
    }
  }
  function initialize() {
    if (initPromise) return initPromise;
    initPromise = (async () => {
      if (closed) return status();
      if (!required || configError) { initialized = true; lastCheckedAt = now(); return status(); }
      try {
        await loadDevice();
        // Check rollback before accepting a restart and persist forward UTC
        // progress before exposing authorization. A bad clock never lowers
        // the existing signed high-water mark.
        const observed = clock();
        if (!observed.invalid) await checkpoint();
        else lastError = 'LICENSE_CLOCK_ROLLBACK';
        initialized = true;
        scheduleRefresh();
      } catch (cause) {
        blocked = ['LICENSE_DEVICE_UNAVAILABLE', 'LICENSE_PATH_INVALID'].includes(cause?.code) ? cause.code : 'LICENSE_STATE_INVALID';
        lastError = blocked; initialized = true;
      }
      lastCheckedAt = now(); return status();
    })();
    return initPromise;
  }
  async function ready() {
    await initialize();
    if (closed) fail('LICENSE_CLOSED');
    if (blocked) throw error(blocked);
    if (!required || !device) fail('LICENSE_CONFIG_INVALID');
  }
  function deviceApplication() {
    if (closed) fail('LICENSE_CLOSED');
    if (blocked) throw error(blocked);
    if (!initialized || !device) fail('LICENSE_REQUIRED');
    const application = { version: 1, action: 'offline', requestId: randomUUID(), deviceId, devicePublicKey: device.publicKey,
      ...(record ? { licenseId: record.license.payload.licenseId } : {}) };
    return JSON.stringify(signDeviceRequest(application, device.privateKey), null, 2);
  }
  async function accept(envelope, { fromService = false } = {}) {
    const claims = authenticate(envelope);
    const digest = hash(canonical(envelope));
    const previous = record?.history?.[claims.licenseId];
    if (previous && (claims.generation < previous.generation || claims.generation === previous.generation && digest !== previous.digest
      || claims.issuedAt < previous.issuedAt)) fail('LICENSE_REPLAY');
    if (previous?.digest === digest && record?.license?.payload?.licenseId === claims.licenseId) {
      scheduleRefresh(); return status();
    }
    const mismatch = claims.deviceId !== deviceId || claims.deviceKeyHash !== deviceKeyHash;
    // A foreign token cannot establish the first local license. Authenticated
    // rebinds of the current license are persisted so older tokens cannot undo it.
    if (mismatch && (!record || claims.licenseId !== record.license.payload.licenseId)) fail('LICENSE_DEVICE_MISMATCH');
    const history = { ...(record?.history || {}), [claims.licenseId]: { generation: claims.generation, issuedAt: claims.issuedAt, digest } };
    // ponytail: retain 128 observed licenses without pruning revocation history;
    // an explicit journal migration is needed if one installation exceeds it.
    if (Object.keys(history).length > 128) fail('LICENSE_STATE_INVALID');
    const wall = now();
    if (!time(wall)) fail('LICENSE_CLOCK_ROLLBACK');
    const trusted = Math.max(record?.lastTrustedServerTime || 0, claims.issuedAt);
    const refreshTime = Math.floor(Math.max(wall, claims.issuedAt, clock().effective));
    const nextRefresh = { ...freshRefresh(), lastAttemptAt: fromService ? refreshTime : null,
      retryAt: fromService && (mismatch || claims.status !== 'active' || refreshTime >= claims.offlineUntil) ? refreshTime + DAY : 0 };
    const next = { version: 1, deviceId, deviceKeyHash, license: envelope, history, lastTrustedServerTime: trusted,
      lastObservedTime: Math.max(record?.lastObservedTime || 0, clockHighWater, trusted, wall), refresh: nextRefresh };
    // An authenticated withdrawal remains binding even when Windows cannot
    // replace the journal. Keep its generation in memory so a retry/replay
    // cannot restore the previous active token during this process.
    if (mismatch || claims.status !== 'active' || wall >= Math.min(claims.offlineUntil, licenseExpiresAt(claims))) record = structuredClone(next);
    await save(next);
    refreshState = nextRefresh;
    trustedAnchor = Math.max(trusted, clockHighWater); monotonicAnchor = monotonic(); wallHighWater = Math.max(wallHighWater, wall);
    lastRefreshAt = wall; lastCheckedAt = wall; lastError = null;
    scheduleRefresh(); return status();
  }
  async function online(action, details) {
    await ready();
    if (!settings.serviceUrl) fail('LICENSE_ONLINE_UNAVAILABLE');
    let selected;
    try { selected = getProxy(); }
    catch { fail('LICENSE_PROXY_UNVERIFIED'); }
    if (selected?.then) fail('LICENSE_PROXY_UNVERIFIED');
    let proxyPort = null;
    if (selected !== null && selected !== undefined) {
      proxyPort = selected.proxyPort ?? selected.port;
      if (selected.unavailable || selected.verified === false || selected.host && selected.host !== '127.0.0.1' || !Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) fail('LICENSE_PROXY_UNVERIFIED');
    }
    const body = signDeviceRequest({ version: 1, action, requestId: randomUUID(), deviceId, devicePublicKey: device.publicKey, ...details }, device.privateKey);
    const abort = new AbortController(); requests.add(abort); refreshing = true;
    let limit;
    try {
      const result = await Promise.race([
        request(new URL(action === 'redeem' ? '/v1/redeem' : '/v1/refresh', settings.serviceUrl), { body, proxyPort, timeoutMs, signal: abort.signal, allowLoopback: dependencies.allowLoopback === true }),
        new Promise((_resolve, reject) => { limit = setTimeout(() => { abort.abort(); reject(error('LICENSE_TIMEOUT')); }, timeoutMs); }),
      ]);
      if (closed) fail('LICENSE_CLOSED');
      const value = boundedJson(result);
      if (value?.ok !== true || !value.data?.license) fail(value?.ok === false ? 'LICENSE_SERVICE_REJECTED' : 'LICENSE_RESPONSE_INVALID');
      await accept(value.data.license, { fromService: true }); refreshing = false; return status();
    } catch (cause) {
      const code = Object.hasOwn(errors, cause?.code) ? cause.code : 'LICENSE_NETWORK_FAILED';
      lastError = code; throw error(code);
    } finally { clearTimeout(limit); requests.delete(abort); refreshing = false; lastCheckedAt = now(); scheduleRefresh(); }
  }
  const activate = card => locked(async () => {
    if (typeof card !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(card.trim())) fail('LICENSE_CARD_INVALID');
    return online('redeem', { card: card.trim() });
  });
  const importLicense = text => locked(async () => { await ready();
    try { return await accept(boundedJson(text)); }
    catch (cause) { const code = Object.hasOwn(errors, cause?.code) ? cause.code : 'LICENSE_INVALID'; lastError = code; throw error(code); }
  });
  async function rememberRefresh(next) {
    refreshState = next;
    // Refresh bookkeeping cannot invalidate an otherwise valid cached license
    // if its optional journal update fails. The authorization token is unchanged.
    if (!record || closed) return;
    try { await save({ ...record, refresh: next }, { metadataOnly: true }); } catch { /* retain local backoff and cached authorization */ }
  }
  async function runRefresh() {
    await ready(); if (!settings.serviceUrl) fail('LICENSE_ONLINE_UNAVAILABLE'); if (!record) fail('LICENSE_REQUIRED');
    if (!time(now())) fail('LICENSE_CLOCK_ROLLBACK');
    const attemptedAt = Math.floor(clock().effective);
    const failures = Math.min(4, refreshState.failures + 1);
    await rememberRefresh({ lastAttemptAt: attemptedAt, retryAt: attemptedAt + HOUR * Math.min(6, 2 ** (failures - 1)), failures, proxyBlocked: false });
    try { return await online('refresh', { licenseId: record.license.payload.licenseId }); }
    catch (cause) {
      lastError = Object.hasOwn(errors, cause?.code) ? cause.code : 'LICENSE_NETWORK_FAILED';
      await rememberRefresh({ ...refreshState, proxyBlocked: cause?.code === 'LICENSE_PROXY_UNVERIFIED' });
      throw cause;
    } finally { scheduleRefresh(); }
  }
  const refresh = () => locked(runRefresh);
  function close() {
    if (closePromise) return closePromise;
    if (initialized && required && record && !blocked) clock();
    closed = true;
    if (timer !== undefined) { unschedule(timer); timer = undefined; }
    for (const pending of requests) pending.abort();
    closePromise = locked(async () => {
      await initPromise;
      await checkpoint();
      return status();
    });
    return closePromise;
  }
  return { initialize, status, assertAllowed, deviceApplication, activate, importLicense, refresh, refreshIfDue, close, stop: close };
}
