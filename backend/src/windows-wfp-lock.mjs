import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile as nodeExecFile } from 'node:child_process';
import { isIP } from 'node:net';
import { UserError, TUN_NETWORK } from './config.mjs';

const HEX = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const operations = new Set(['inspect', 'apply', 'clear']);
const nativeCodes = new Set(['ADMIN_REQUIRED', 'NETWORK_LOCK_CONFLICT', 'NETWORK_LOCK_INPUT_INVALID',
  'NETWORK_LOCK_VERIFY_FAILED', 'NETWORK_LOCK_RECOVERY_REQUIRED', 'NETWORK_LOCK_SERVICE_UNAVAILABLE',
  'NETWORK_LOCK_SERVICE_CONFLICT', 'NETWORK_LOCK_TUN_UNAVAILABLE', 'NETWORK_LOCK_WFP_FAILED']);
const fail = (code, message) => { throw new UserError(code, message); };

export function normalizeWfpLockInput(input) {
  if (!input || !HEX.test(input.binding || '') || !isIP(input.endpoint?.ip || '')
    || !Number.isInteger(input.endpoint.port) || input.endpoint.port < 1 || input.endpoint.port > 65535
    || (input.endpoint.host !== undefined && (typeof input.endpoint.host !== 'string'
      || !input.endpoint.host || input.endpoint.host.length > 253 || /[\s\0]/.test(input.endpoint.host)))
    || (input.endpoint.protocol !== undefined && !['TCP', 'UDP'].includes(input.endpoint.protocol))
    || typeof input.corePath !== 'string' || !path.isAbsolute(input.corePath) || /[\0\r\n]/.test(input.corePath)
    || input.corePath.length > 1024 || path.extname(input.corePath).toLowerCase() !== '.exe') {
    fail('NETWORK_LOCK_INPUT_INVALID', 'A fixed outer proxy IP, port, protocol and absolute core executable are required');
  }
  return { binding: input.binding, corePath: path.resolve(input.corePath),
    endpoint: { ...(input.endpoint.host === undefined ? {} : { host: input.endpoint.host }),
      ip: input.endpoint.ip, port: input.endpoint.port, protocol: input.endpoint.protocol || 'TCP' } };
}

export function sanitizeWfpLockDiagnostic(value, operation = value?.operation) {
  if (!operations.has(operation)) return undefined;
  const output = { operation, command: 'MCProxy.NetworkLock.exe' };
  if (['OperationTimeout', 'OperationStopped', 'PermissionDenied', 'ServiceUnavailable', 'InvalidData', 'WfpFailure', 'Conflict'].includes(value?.category)) output.category = value.category;
  if (Number.isInteger(value?.nativeCode) && value.nativeCode >= -2147483648 && value.nativeCode <= 4294967295) output.nativeCode = value.nativeCode;
  return output;
}

function failure(code, operation, diagnostic) {
  const cause = new UserError(code, 'The MC Proxy WFP operation could not be verified; recovery state is retained');
  cause.diagnostic = sanitizeWfpLockDiagnostic(diagnostic, operation);
  return cause;
}

export function validateWfpInspection(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || typeof value.present !== 'boolean'
    || typeof value.verified !== 'boolean' || typeof value.serviceReady !== 'boolean'
    || typeof value.bootProtected !== 'boolean' || typeof value.tunCurrent !== 'boolean' || !Number.isInteger(value.ownedFilterCount)
    || value.ownedFilterCount < 0 || value.ownedFilterCount > 512) {
    fail('NETWORK_LOCK_RESPONSE_INVALID', 'The WFP helper returned an invalid rule observation');
  }
  const output = { present: value.present, verified: value.verified, serviceReady: value.serviceReady,
    bootProtected: value.bootProtected, tunCurrent: value.tunCurrent, ownedFilterCount: value.ownedFilterCount };
  if (!value.present) {
    if (value.ownedFilterCount !== 0) fail('NETWORK_LOCK_RESPONSE_INVALID', 'The WFP helper returned inconsistent ownership information');
    return { ...output, id: null, binding: null, corePath: null, endpoint: null, tunLuid: null, fingerprint: null };
  }
  // A partial or disabled policy is still present and must remain recoverable.
  // Never turn incomplete metadata into an "unlocked" observation.
  if (!value.verified) {
    const partial = { ...output, id: UUID.test(value.id || '') ? value.id : null,
      fingerprint: HEX.test(value.fingerprint || '') ? value.fingerprint : null };
    try { Object.assign(partial, normalizeWfpLockInput(value)); } catch {}
    return partial;
  }
  if (!UUID.test(value.id || '') || !HEX.test(value.fingerprint || '') || value.ownedFilterCount === 0
    || !value.serviceReady || (value.tunLuid !== null && (typeof value.tunLuid !== 'string'
      || !/^[1-9][0-9]{0,19}$/.test(value.tunLuid) || BigInt(value.tunLuid) > 18446744073709551615n))) {
    fail('NETWORK_LOCK_RESPONSE_INVALID', 'The WFP helper returned invalid verified policy metadata');
  }
  return { ...output, id: value.id, ...normalizeWfpLockInput(value), fingerprint: value.fingerprint, tunLuid: value.tunLuid };
}

// The executable owns one provider/sublayer. Requests are data on stdin; no
// shell, PowerShell interpolation, system firewall inventory or policy import.
export function createWindowsWfpLockAdapter({ platform = process.platform, execFile = nodeExecFile,
  helperPath = process.resourcesPath
    ? path.join(process.resourcesPath, 'network-lock', 'MCProxy.NetworkLock.exe')
    : fileURLToPath(new URL('../.cache/network-lock/MCProxy.NetworkLock.exe', import.meta.url)), timeoutMs = 10000 } = {}) {
  if (!path.isAbsolute(helperPath) || path.extname(helperPath).toLowerCase() !== '.exe' || /[\0\r\n]/.test(helperPath)) fail('NETWORK_LOCK_PATH_INVALID', 'The WFP helper requires an absolute executable path');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) fail('NETWORK_LOCK_INPUT_INVALID', 'The WFP helper timeout must be bounded');
  async function call(request) {
    if (platform !== 'win32') fail('PLATFORM_UNSUPPORTED', 'The WFP network lock requires Windows');
    const input = JSON.stringify(request);
    if (Buffer.byteLength(input) > 16384) fail('NETWORK_LOCK_INPUT_INVALID', 'The WFP request exceeds its fixed policy limit');
    const completed = await new Promise((resolve, reject) => {
      const child = execFile(helperPath, [], { windowsHide: true, shell: false, encoding: 'utf8',
        timeout: timeoutMs, maxBuffer: 128 * 1024 }, (error, stdout) => {
        if (error?.killed || (error && !stdout?.trim())) reject(failure(error.killed ? 'NETWORK_LOCK_TIMEOUT' : error.code === 'ENOENT'
          ? 'NETWORK_LOCK_HELPER_UNAVAILABLE' : 'NETWORK_LOCK_WFP_FAILED', request.operation,
        { category: error.killed ? 'OperationTimeout' : 'OperationStopped' }));
        else resolve({ output: stdout, processError: error });
      });
      if (!child?.stdin?.end) { reject(failure('NETWORK_LOCK_HELPER_UNAVAILABLE', request.operation)); return; }
      child.stdin.on('error', () => reject(failure('NETWORK_LOCK_WFP_FAILED', request.operation, { category: 'OperationStopped' })));
      child.stdin.end(input);
    });
    let result;
    try { result = JSON.parse(completed.output.replace(/^\uFEFF/, '').trim()); } catch {}
    if (!result || typeof result !== 'object' || typeof result.ok !== 'boolean') throw failure('NETWORK_LOCK_RESPONSE_INVALID', request.operation);
    if (!result.ok) throw failure(nativeCodes.has(result.code) ? result.code : 'NETWORK_LOCK_WFP_FAILED', request.operation, result.diagnostic);
    if (completed.processError) throw failure('NETWORK_LOCK_WFP_FAILED', request.operation, { category: 'OperationStopped' });
    try { return validateWfpInspection(result.value); }
    catch { throw failure('NETWORK_LOCK_RESPONSE_INVALID', request.operation); }
  }
  function applyRequest(input) {
    const normalized = normalizeWfpLockInput(input);
    if (!UUID.test(input.id || '') || (input.includeTun !== undefined && typeof input.includeTun !== 'boolean')
      || (input.expectedFingerprint !== undefined && !HEX.test(input.expectedFingerprint))
      || (input.tunAlias !== undefined && input.tunAlias !== TUN_NETWORK.interfaceName)) fail('NETWORK_LOCK_INPUT_INVALID', 'The WFP policy identity or expected observation is invalid');
    const { ip, port, protocol } = normalized.endpoint;
    return { operation: 'apply', id: input.id, ...normalized, endpoint: { ip, port, protocol }, includeTun: input.includeTun === true,
      ...(input.includeTun === true ? { tunAlias: TUN_NETWORK.interfaceName } : {}),
      ...(input.expectedFingerprint ? { expectedFingerprint: input.expectedFingerprint } : {}) };
  }
  return {
    inspect: () => call({ operation: 'inspect' }),
    apply: input => call(applyRequest(input)),
    clear: input => {
      if (!UUID.test(input?.id || '') || !HEX.test(input?.expectedFingerprint || '')) fail('NETWORK_LOCK_INPUT_INVALID', 'Explicit unlock requires the current owned policy identity and fingerprint');
      return call({ operation: 'clear', id: input.id, expectedFingerprint: input.expectedFingerprint });
    },
  };
}
