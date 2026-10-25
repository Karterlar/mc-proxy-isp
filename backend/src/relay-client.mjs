import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { lstat, realpath, readFile, rename, rm, open, chmod } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID, X509Certificate } from 'node:crypto';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { UserError, validateConfig, validHost } from './config.mjs';

const execute = promisify(execFile);
const clone = value => structuredClone(value);
const fail = (code, message) => { throw new UserError(code, message); };
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const sha256 = value => createHash('sha256').update(value).digest('hex').toUpperCase();
const boundedString = (value, max) => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= max && !/[\x00-\x1f\x7f]/.test(value);
const revisionValid = revision => Number.isSafeInteger(revision) && revision >= 0;
const sameEndpoint = (a, b) => a?.host === b?.host && a?.port === b?.port;
const errorMessages = Object.freeze({
  RELAY_TIMEOUT: '中转服务器响应超时，请检查直连网络后重试。',
  RELAY_TLS_FAILED: '中转服务器证书验证失败，未发送账号或连接信息。',
  RELAY_UNREACHABLE: '无法直连中转服务器，请检查网络和入口服务器状态。',
  RELAY_RESPONSE_INVALID: '中转服务器响应不符合协议，未继续连接。',
  RELAY_AUTH_FAILED: '账号认证失败或已停用，请联系管理员核验。',
  RELAY_DISABLED: '中转账号已停用或无权执行此操作。',
  RELAY_IN_USE: '中转仍有活动连接，请先停止连接再修改 ISP。',
  RELAY_BINDING_CONFLICT: '中转绑定已被其他操作修改，未覆盖现有设置。',
});
const requestError = code => new UserError(code, errorMessages[code]);
const safeRequestError = cause => requestError(cause instanceof UserError && Object.hasOwn(errorMessages, cause.code || '') ? cause.code : 'RELAY_UNREACHABLE');

function relayConfig(enrollment) {
  return { type: 'http', host: enrollment.host, port: enrollment.port, auth: 'password',
    tls: { enabled: true, serverName: enrollment.tlsServerName, certificate: enrollment.certificate } };
}

export function validateRelayEnrollment(input) {
  const allowed = ['version', 'type', 'host', 'port', 'tlsServerName', 'certificate', 'certificateSha256', 'username', 'password', 'label'];
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !allowed.includes(key))
    || input.version !== 1 || input.type !== 'mc-proxy-relay' || typeof input.host !== 'string' || !isIP(input.host)
    || !boundedString(input.username, 256) || input.username.includes(':') || !boundedString(input.password, 4096)
    || (input.label !== undefined && !boundedString(input.label, 80))) fail('RELAY_ENROLLMENT_INVALID', '中转注册文件格式或账号信息无效。');
  const enrollment = clone(input);
  try {
    validateConfig({ version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '127.0.0.1', port: 1080, auth: 'none' },
      relay: relayConfig(enrollment), probe: { exitUrl: 'https://api.ipify.org', expectedExitIps: [], timeoutMs: 10000 } });
    const certificate = new X509Certificate(enrollment.certificate);
    const supplied = typeof enrollment.certificateSha256 === 'string' ? enrollment.certificateSha256.replaceAll(':', '').toUpperCase() : '';
    if (!/^[0-9A-F]{64}$/.test(supplied) || supplied !== sha256(certificate.raw)) throw new Error();
    const matches = isIP(enrollment.tlsServerName) ? certificate.checkIP(enrollment.tlsServerName) : certificate.checkHost(enrollment.tlsServerName);
    if (!matches) throw new Error();
    enrollment.certificateSha256 = supplied;
  } catch { fail('RELAY_ENROLLMENT_INVALID', '中转注册文件的固定地址、TLS 证书、身份或指纹无效。'); }
  return enrollment;
}

function validateEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint) || Object.keys(endpoint).some(key => !['host', 'port'].includes(key))
    || !validHost(endpoint.host) || !Number.isInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 65535) fail('RELAY_UPSTREAM_INVALID', 'ISP 地址和端口无效。');
  return { host: endpoint.host.toLowerCase(), port: endpoint.port };
}

function validateResponse(body, status = false) {
  if (!body || body.ok !== true || !revisionValid(body.bindingRevision) || !Object.hasOwn(body, 'upstream')) fail('RELAY_RESPONSE_INVALID', errorMessages.RELAY_RESPONSE_INVALID);
  let upstream = null;
  try { if (body.upstream !== null) upstream = validateEndpoint(body.upstream); }
  catch { fail('RELAY_RESPONSE_INVALID', errorMessages.RELAY_RESPONSE_INVALID); }
  const result = { ok: true, upstream, bindingRevision: body.bindingRevision };
  if (status) {
    if (!Number.isSafeInteger(body.activeTunnels) || body.activeTunnels < 0 || !Number.isSafeInteger(body.maxTunnels) || body.maxTunnels < 1
      || (body.enabled !== undefined && body.enabled !== true)) fail('RELAY_RESPONSE_INVALID', errorMessages.RELAY_RESPONSE_INVALID);
    Object.assign(result, { activeTunnels: body.activeTunnels, maxTunnels: body.maxTunnels });
  }
  return result;
}

// Built-in HTTPS with a fresh direct socket deliberately ignores HTTP(S)_PROXY
// and never follows redirects. TLS trust, hostname and leaf fingerprint all
// succeed before HTTP Basic credentials can be transmitted.
export function requestRelay(enrollment, { method = 'GET', pathname = '/v1/status', body, timeoutMs = 10000 } = {}) {
  const selected = validateRelayEnrollment(enrollment);
  if (!['GET', 'POST', 'DELETE'].includes(method) || !['/v1/status', '/v1/upstream'].includes(pathname)
    || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000) fail('RELAY_REQUEST_INVALID', '中转请求参数无效。');
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  if (payload && payload.length > 8192) fail('RELAY_REQUEST_INVALID', '中转请求内容过大。');
  return new Promise((resolve, reject) => {
    let settled = false; let timer; let request;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(value); };
    try {
      request = https.request({ hostname: selected.host, port: selected.port, servername: selected.tlsServerName,
        method, path: pathname, agent: false, ca: selected.certificate, rejectUnauthorized: true, minVersion: 'TLSv1.2',
        // Enrollment explicitly trusts this certificate. Electron's BoringSSL
        // needs partial-chain trust for a pinned CA:false self-signed leaf.
        // Trust/validity, hostname and the exact leaf fingerprint remain required.
        allowPartialTrustChain: true,
        checkServerIdentity: (_host, certificate) => tls.checkServerIdentity(selected.tlsServerName, certificate)
          || (!certificate.raw || sha256(certificate.raw) !== selected.certificateSha256 ? requestError('RELAY_TLS_FAILED') : undefined),
        headers: { Authorization: `Basic ${Buffer.from(`${selected.username}:${selected.password}`).toString('base64')}`, Accept: 'application/json',
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}) },
      }, response => {
        if ([401, 403].includes(response.statusCode)) {
          response.resume(); finish(requestError(response.statusCode === 401 ? 'RELAY_AUTH_FAILED' : 'RELAY_DISABLED')); request.destroy(); return;
        }
        let size = 0; const chunks = [];
        response.on('error', () => finish(requestError('RELAY_UNREACHABLE')));
        response.on('data', chunk => {
          size += chunk.length;
          if (size > 32768) { finish(requestError('RELAY_RESPONSE_INVALID')); response.destroy(); request.destroy(); }
          else chunks.push(chunk);
        });
        response.on('end', () => {
          if (settled) return;
          let result;
          try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
          catch { finish(requestError('RELAY_RESPONSE_INVALID')); return; }
          if (response.statusCode === 409) finish(result.error === 'upstream_in_use'
            ? new UserError('RELAY_IN_USE', '中转仍有活动连接，请先停止连接再修改 ISP。')
            : new UserError('RELAY_BINDING_CONFLICT', '中转绑定已被其他操作修改，未覆盖现有设置。'));
          else if (response.statusCode !== 200) finish(requestError('RELAY_RESPONSE_INVALID'));
          else finish(null, result);
        });
      });
      timer = setTimeout(() => { finish(requestError('RELAY_TIMEOUT')); request.destroy(); }, timeoutMs);
      request.on('error', error => {
        const code = String(error.code || '');
        finish(requestError(code === 'RELAY_TLS_FAILED' || /CERT|TLS|SSL|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code) ? 'RELAY_TLS_FAILED' : 'RELAY_UNREACHABLE'));
      });
      if (payload) request.write(payload);
      request.end();
    } catch { request?.destroy(); finish(requestError('RELAY_UNREACHABLE')); }
  });
}

async function restrictDirectory(directory) {
  if (process.platform !== 'win32') { await chmod(directory, 0o700); return; }
  try {
    const options = { encoding: 'utf8', windowsHide: true, timeout: 10000, maxBuffer: 16384 };
    const identity = await execute('whoami.exe', ['/user', '/fo', 'csv', '/nh'], options);
    const sid = identity.stdout.match(/S-1-5-(?:\d+-)*\d+/)?.[0];
    if (!sid) throw new Error();
    await execute('icacls.exe', [directory, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'], options);
  } catch { fail('RELAY_STORAGE_FAILED', '无法限制中转凭据目录权限，未写入账号信息。'); }
}

export function createRelayManager({ runtimeRoot, mock = false, dependencies = {} } = {}) {
  if (!mock && (!runtimeRoot || !path.isAbsolute(runtimeRoot))) fail('RELAY_PATH_INVALID', '中转运行目录必须为绝对路径。');
  const root = path.resolve(runtimeRoot || '.mock-relay'); const directory = path.join(root, '.relay'); const filename = path.join(directory, 'enrollment.json');
  const deps = { lstat, realpath, readFile, rename, rm, open, createPrivateDirectory, writePrivate, restrictDirectory, request: requestRelay, now: Date.now, ...dependencies };
  let memory = null; let mockUpstream = null; let mockRevision = 0; let checked = null; let checkedEnrollment = null; let serial = Promise.resolve();
  const locked = action => { const task = serial.then(action, action); serial = task.catch(() => {}); return task; };
  const enrollmentIdentity = enrollment => sha256(JSON.stringify(enrollment));
  const checkedTime = () => { try { return new Date(deps.now()).toISOString(); } catch { return null; } };
  async function safe(file) {
    const relative = path.relative(root, file);
    if (relative.startsWith('..') || path.isAbsolute(relative)) fail('RELAY_PATH_INVALID', '中转凭据文件超出运行目录。');
    let cursor = path.parse(file).root;
    for (const component of file.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, component);
      let info;
      try { info = await deps.lstat(cursor); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (info.isSymbolicLink() || normalize(await deps.realpath(cursor)) !== normalize(cursor)) fail('RELAY_PATH_INVALID', '中转凭据文件或父目录包含链接，操作已拒绝。');
    }
  }
  async function ensureDirectory(target) {
    await safe(target);
    try { if (!(await deps.lstat(target)).isDirectory()) fail('RELAY_PATH_INVALID', '中转凭据存储位置不是目录。'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (normalize(target) !== normalize(root)) await ensureDirectory(path.dirname(target));
      await deps.createPrivateDirectory(target);
    }
  }
  async function readEnrollment() {
    if (mock) return clone(memory);
    try {
      await safe(filename);
      const info = await deps.lstat(filename);
      if (!info.isFile() || info.size > 32768) fail('RELAY_ENROLLMENT_INVALID', '中转注册文件类型或大小无效。');
      let parsed;
      try { parsed = JSON.parse((await deps.readFile(filename, 'utf8')).replace(/^\uFEFF/, '')); }
      catch { fail('RELAY_ENROLLMENT_INVALID', '中转注册文件无法解析，请重新导入。'); }
      return validateRelayEnrollment(parsed);
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      if (error instanceof UserError) throw error;
      fail('RELAY_STORAGE_FAILED', '无法读取私有中转注册文件。');
    }
  }
  async function required() { const enrollment = await readEnrollment(); if (!enrollment) fail('RELAY_NOT_CONFIGURED', '尚未配置中转入口，请先导入中转注册文件。'); return enrollment; }
  const publicStatus = enrollment => {
    if (!enrollment) return { configured: false, mock };
    const match = checkedEnrollment === enrollmentIdentity(enrollment);
    return { configured: true, mock, host: enrollment.host, port: enrollment.port, serverName: enrollment.tlsServerName,
      accountHint: enrollment.username.length > 4 ? `${enrollment.username.slice(0, 2)}•••${enrollment.username.slice(-2)}` : '••••',
      ...(enrollment.label ? { label: enrollment.label } : {}),
      checkStatus: match && checked ? checked.checkStatus : 'unchecked', checkedAt: match && checked ? checked.checkedAt : null,
      errorCode: match && checked ? checked.errorCode : null };
  };
  async function invoke(enrollment, request) {
    try { return await deps.request(enrollment, request); }
    catch (cause) { throw safeRequestError(cause); }
  }
  return {
    status: () => locked(async () => publicStatus(await readEnrollment())),
    credentials: () => locked(async () => {
      const enrollment = await required();
      return { relay: relayConfig(enrollment), secrets: { RELAY_USERNAME: enrollment.username, RELAY_PASSWORD: enrollment.password } };
    }),
    importEnrollment: input => locked(async () => {
      const enrollment = validateRelayEnrollment(input);
      if (mock) memory = clone(enrollment);
      else {
        const temporary = path.join(directory, `.enrollment-${randomUUID()}.tmp`);
        try {
          await ensureDirectory(directory); await deps.restrictDirectory(directory); await safe(filename); await safe(temporary);
          await deps.writePrivate(temporary, `${JSON.stringify(enrollment, null, 2)}\n`);
          const handle = await deps.open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
          await safe(filename); await deps.rename(temporary, filename);
        } catch (error) {
          if (error instanceof UserError) throw error;
          fail('RELAY_STORAGE_FAILED', '中转注册文件未能安全保存，原有注册信息保持不变。');
        } finally {
          // Never clean up through a directory that has become a link.
          await safe(temporary).then(() => deps.rm(temporary, { force: true })).catch(() => {});
        }
      }
      checked = null; checkedEnrollment = null;
      return publicStatus(enrollment);
    }),
    check: () => locked(async () => {
      const enrollment = await required();
      try {
        const response = mock ? { ok: true, upstream: clone(mockUpstream), bindingRevision: mockRevision, activeTunnels: 0, maxTunnels: 64 }
          : await invoke(enrollment, { method: 'GET', pathname: '/v1/status' });
        checked = { ...validateResponse(response, true), checkStatus: 'ready', errorCode: null, checkedAt: checkedTime() };
        checkedEnrollment = enrollmentIdentity(enrollment);
        return { ...publicStatus(enrollment), ...clone(checked) };
      } catch (cause) {
        const failure = safeRequestError(cause);
        checked = { checkStatus: failure.code === 'RELAY_AUTH_FAILED' ? 'auth-failed' : failure.code === 'RELAY_DISABLED' ? 'disabled' : 'unavailable',
          errorCode: failure.code, checkedAt: checkedTime() };
        checkedEnrollment = enrollmentIdentity(enrollment);
        throw failure;
      }
    }),
    bind: (input, expectedRevision) => locked(async () => {
      const endpoint = validateEndpoint(input);
      if (!revisionValid(expectedRevision)) fail('RELAY_REVISION_REQUIRED', '修改 ISP 绑定前必须先检查中转状态。');
      const enrollment = await required(); let response;
      if (mock) {
        if (expectedRevision !== mockRevision) fail('RELAY_BINDING_CONFLICT', '中转绑定已被其他操作修改，未覆盖现有设置。');
        if (!sameEndpoint(endpoint, mockUpstream)) { mockUpstream = endpoint; mockRevision++; }
        response = { ok: true, upstream: clone(mockUpstream), bindingRevision: mockRevision };
      } else response = await invoke(enrollment, { method: 'POST', pathname: '/v1/upstream', body: { ...endpoint, expectedRevision } });
      const result = validateResponse(response);
      if (!sameEndpoint(result.upstream, endpoint) || result.bindingRevision < expectedRevision) fail('RELAY_RESPONSE_INVALID', errorMessages.RELAY_RESPONSE_INVALID);
      checked = null; return result;
    }),
    clear: expectedRevision => locked(async () => {
      if (!revisionValid(expectedRevision)) fail('RELAY_REVISION_REQUIRED', '清除 ISP 绑定前必须先检查中转状态。');
      const enrollment = await required(); let response;
      if (mock) {
        if (expectedRevision !== mockRevision) fail('RELAY_BINDING_CONFLICT', '中转绑定已被其他操作修改，未覆盖现有设置。');
        if (mockUpstream !== null) { mockUpstream = null; mockRevision++; }
        response = { ok: true, upstream: null, bindingRevision: mockRevision };
      } else response = await invoke(enrollment, { method: 'DELETE', pathname: '/v1/upstream', body: { expectedRevision } });
      const result = validateResponse(response);
      if (result.upstream !== null || result.bindingRevision < expectedRevision) fail('RELAY_RESPONSE_INVALID', errorMessages.RELAY_RESPONSE_INVALID);
      checked = null; return result;
    }),
  };
}
