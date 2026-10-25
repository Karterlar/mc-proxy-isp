import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, realpath, mkdir, open, rename } from 'node:fs/promises';
import { sanitizeNetworkLockDiagnostic } from '../backend/src/windows-network-lock.mjs';
import { sanitizeEnvironmentDiagnostic } from '../backend/src/windows-environment.mjs';
import { sanitizeProbeFailure } from '../backend/src/probe.mjs';
import { sanitizeSetupDiagnostic } from '../backend/src/setup-diagnostic.mjs';

const events = new Set(['network repair launch failed', 'desktop quit request failed', 'desktop shutdown complete', 'safe shutdown incomplete',
  'network repair helper ready', 'network repair state reload incomplete', 'network repair complete', 'network repair incomplete',
  'managed website open incomplete', 'report link failed', 'report navigation failed', 'desktop action incomplete', 'link failed',
  'navigation failed', 'renderer stopped', 'desktop ready', 'desktop startup or acceptance failed', 'controller diagnostic', 'network lifecycle incomplete', 'desktop admin handoff incomplete', 'desktop permission verified']);
const additionalCodes = ['OPERATION_FAILED', 'CONNECTION_PROGRESS', 'CORE_PROCESS_STOPPED', 'CORE_PROCESS_EXITED', 'CORE_FAKE_IP_RECORD_MISSING',
  'CORE_TUN_PERMISSION_DENIED', 'CORE_TUN_CREATE_FAILED', 'CORE_TUN_ROUTE_FAILED', 'CORE_LISTEN_FAILED', 'CORE_UPSTREAM_AUTH_FAILED',
  'CORE_UPSTREAM_TLS_FAILED', 'CORE_CONNECTION_RESET', 'CORE_UPSTREAM_CONNECT_FAILED', 'CORE_RUNTIME_FAILED', 'SYSTEM_NETWORK_CHECK', 'SYSTEM_NETWORK_VERIFIED',
  'VPN_COMPAT_NETWORK_CHECK', 'VPN_COMPAT_NETWORK_VERIFIED', 'VPN_IMPORT_VERIFIED', 'DESKTOP_RENDERER_STOPPED', 'DESKTOP_LOG_UNSAFE', 'DESKTOP_LOG_WRITE_FAILED',
  'DESKTOP_BUSY', 'DESKTOP_IPC_UNTRUSTED', 'DESKTOP_IPC_INVALID', 'DESKTOP_LOG_UNAVAILABLE', 'NETWORK_OBSERVATION_FAILED', 'NETWORK_RECHECK_FAILED',
  'APPLICATION_TARGET_INVALID', 'APPLICATION_UNAVAILABLE', 'APPLICATION_PROCESS_UNKNOWN', 'APPLICATION_ALREADY_RUNNING', 'APPLICATION_GATEWAY_CHANGED',
  'APPLICATION_LAUNCH_FAILED', 'APPLICATION_SYSTEM_PROTECTION_REQUIRED', 'APPLICATION_SYSTEM_NETWORK_REQUIRED', 'APPLICATION_SYSTEM_UNVERIFIED',
  'APPLICATION_TARGET_UNREACHABLE', 'APPLICATION_CLOSE_MANUALLY', 'APPLICATION_CLOSE_FAILED', 'APPLICATION_CLOSE_TIMEOUT', 'NETWORK_REPAIR_FAILED',
  'LOCAL_FIREWALL_RESTORED', 'LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES', 'UNSAFE_PATH', 'RECOVERY_FILE_MISSING', 'FIREWALL_FILTER_MISSING',
  'AMBIGUOUS_FIREWALL_RULE', 'AMBIGUOUS_FIREWALL_FILTER', 'INVALID_RECOVERY_JOURNAL', 'PROFILE_CHANGED_OUTSIDE_MC_PROXY', 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY',
  'MANAGED_RULE_CHANGED_OR_OTHER_LOCK_EXISTS', 'MANAGED_RULE_FINGERPRINT_MISMATCH', 'FIREWALL_INSPECTION_FAILED', 'MULTIPLE_RECOVERY_ROOTS_USE_RUNTIME_ROOT',
  'RECOVERY_ROOT_NOT_FOUND_USE_RUNTIME_ROOT', 'MANAGED_CORE_STILL_RUNNING_CLOSE_MC_PROXY', 'CORE_PROCESS_IDENTITY_UNAVAILABLE',
  'PROXYPILOT_TUN_STILL_EXISTS_CLOSE_MC_PROXY_OR_REBOOT', 'INVALID_DESKTOP_REQUEST', 'DESKTOP_REPAIR_CANCELED', 'DESKTOP_SESSION_STOP_TIMEOUT',
  'REPAIR_VERIFICATION_FAILED', 'USER_CANCELED', 'INVALID_WAIT_PROCESS', 'DESKTOP_STILL_RUNNING', 'ADMIN_ELEVATION_FAILED', 'UAC_CANCELED_OR_ELEVATION_FAILED',
  'ADMIN_STARTUP_INVALID', 'ADMIN_STARTUP_INCOMPLETE', 'ADMIN_STARTUP_IDENTITY_CHANGED', 'ADMIN_VERIFIED',
  'RECOVERY_BACKUP_HASH_MISMATCH', 'MANAGED_FIREWALL_POLICY_PRESENT', 'WINDOWS_REPAIR_OPERATION_FAILED', 'DESKTOP_LOG_OVERLOADED',
  'CLAUDE_BACKGROUND_CHECK_FAILED', 'CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED', 'CLAUDE_SERVICES_OPEN_FAILED', 'CLAUDE_BACKGROUND_BUSY',
  'CLAUDE_STARTUP_ADMIN_REQUIRED', 'CLAUDE_STARTUP_IDENTITY_UNVERIFIED', 'CLAUDE_STARTUP_ACCESS_DENIED', 'CLAUDE_STARTUP_CONFLICT',
  'CLAUDE_STARTUP_UNCONFIRMED', 'CLAUDE_STARTUP_RECORD_FAILED', 'CLAUDE_STARTUP_REGISTRY_UNREADABLE'];
const environmentFields = ['timeZoneId', 'daylightSavingDisabled', 'culture', 'uiLanguageOverride', 'languages', 'defaultInputMethod', 'cultureFromLanguageListOptOut', 'homeGeoId'];

export function createClientLog({ directory, maxBytes = 1024 * 1024, copies = 3, knownCodes = [], now = Date.now, dependencies = {} } = {}) {
  if (!path.isAbsolute(directory || '')) throw Object.assign(new Error('Client log directory is invalid'), { code: 'DESKTOP_LOG_UNSAFE' });
  maxBytes = Math.max(256, Math.min(1024 * 1024, Number.isInteger(maxBytes) ? maxBytes : 1024 * 1024));
  copies = Math.max(1, Math.min(3, Number.isInteger(copies) ? copies : 3));
  const root = path.resolve(directory), file = path.join(root, 'desktop.log');
  const files = Array.from({ length: copies }, (_, index) => index ? `${file}.${index}` : file);
  const fs = { lstat, realpath, mkdir, open, rename, ...dependencies }, codes = new Set([...knownCodes, ...additionalCodes]);
  let serial = Promise.resolve(), queued = 0, state = { ok: true, errorCode: null, lastFailureAt: null, lastFailureCode: null };
  const unsafe = () => { throw Object.assign(new Error('Client log path identity is unsafe'), { code: 'DESKTOP_LOG_UNSAFE' }); };
  const equal = (a, b) => process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
  async function safeDirectory() {
    let cursor = path.parse(root).root;
    for (const part of root.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try { const stat = await fs.lstat(cursor); if (!stat.isDirectory() || stat.isSymbolicLink() || !equal(await fs.realpath(cursor), cursor)) unsafe(); }
      catch (cause) { if (cause.code === 'ENOENT') return false; throw cause; }
    }
    return true;
  }
  async function safeFile(target) {
    try { const stat = await fs.lstat(target); if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1 || !equal(await fs.realpath(target), target)) unsafe(); return stat; }
    catch (cause) { if (cause.code === 'ENOENT') return null; throw cause; }
  }
  async function verifiedOpen(target) {
    const handle = await fs.open(target, constants.O_RDWR | constants.O_CREAT | (constants.O_NOFOLLOW || 0), 0o600);
    try {
      const stat = await handle.stat(), current = await safeFile(target);
      if (!stat.isFile() || stat.nlink > 1 || !current || stat.dev !== current.dev || stat.ino !== current.ino || !await safeDirectory()) unsafe();
      return handle;
    } catch (cause) { await handle.close(); throw cause; }
  }
  async function writeAll(handle, bytes, position) {
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, position + offset);
      if (!Number.isInteger(bytesWritten) || bytesWritten < 1) throw new Error('Client log write made no progress');
      offset += bytesWritten;
    }
  }
  async function compact(target, exists) {
    if (!exists || exists.size <= maxBytes) return exists?.size || 0;
    const handle = await verifiedOpen(target);
    try {
      const stat = await handle.stat(), tail = Buffer.alloc(maxBytes);
      const { bytesRead } = await handle.read(tail, 0, maxBytes, Math.max(0, stat.size - maxBytes));
      const firstLine = tail.subarray(0, bytesRead).indexOf(10), content = tail.subarray(firstLine < 0 ? bytesRead : firstLine + 1, bytesRead);
      await writeAll(handle, content, 0); await handle.truncate(content.length); await handle.sync(); return content.length;
    } finally { await handle.close(); }
  }
  function record(event, cause) {
    const entry = { at: new Date(now()).toISOString(), event: events.has(event) ? event : 'desktop event' };
    if (cause) entry.code = codes.has(cause.code) ? cause.code : 'OPERATION_FAILED';
    if (/^[a-z][a-z-]{0,79}$/.test(cause?.operation || '')) entry.stage = cause.operation;
    const value = cause?.diagnostic;
    const detail = { ...(sanitizeNetworkLockDiagnostic(value) || {}), ...(sanitizeEnvironmentDiagnostic(value) || {}), ...sanitizeProbeFailure(cause)?.diagnostic, ...sanitizeSetupDiagnostic(value) };
    if (entry.event === 'desktop permission verified' && cause?.code === 'ADMIN_VERIFIED') {
      for (const key of ['checked', 'elevated', 'adminMember', 'tokenMatched', 'capabilityVerified']) if (typeof value?.[key] === 'boolean') detail[key] = value[key];
      if (['low', 'medium', 'high', 'system', 'unknown'].includes(value?.integrity)) detail.integrity = value.integrity;
    }
    if (cause?.code === 'SETUP_CHECK_FAILED' && Array.isArray(value?.checks)) {
      const checks = value.checks.slice(0, 2).flatMap(check => {
        const safe = sanitizeProbeFailure({ code: check?.code, diagnostic: check });
        return safe && ['ipify', 'cloudflare'].includes(check.source) ? [{ source: check.source, code: safe.code, ...safe.diagnostic }] : [];
      });
      if (checks.length) detail.checks = checks;
    }
    for (const key of ['environmentFields', 'rollbackEnvironmentFields']) if (Array.isArray(value?.[key])) {
      const filtered = [...new Set(value[key].filter(field => environmentFields.includes(field)))]; if (filtered.length) detail[key] = filtered;
    }
    if (Number.isSafeInteger(value?.exitCode)) detail.exitCode = value.exitCode;
    if (Number.isInteger(value?.httpStatus) && value.httpStatus >= 100 && value.httpStatus <= 599) detail.httpStatus = value.httpStatus;
    if (Number.isInteger(value?.skippedAllowRules) && value.skippedAllowRules >= 0 && value.skippedAllowRules <= 65535) detail.skippedAllowRules = value.skippedAllowRules;
    if (['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGSEGV', 'SIGBREAK'].includes(value?.signal)) detail.signal = value.signal;
    if (Object.keys(detail).length) entry.diagnostic = detail;
    let bytes = Buffer.from(`${JSON.stringify(entry)}\n`);
    if (bytes.length > maxBytes) bytes = Buffer.from(`${JSON.stringify({ at: entry.at, event: 'desktop event', code: entry.code || 'OPERATION_FAILED' })}\n`);
    return bytes;
  }
  return {
    path: file,
    status: () => ({ ...state }),
    flush: () => serial,
    write: (event, cause) => {
      if (queued >= 256) {
        state = { ok: false, errorCode: 'DESKTOP_LOG_OVERLOADED', lastFailureCode: 'DESKTOP_LOG_OVERLOADED', lastFailureAt: new Date(now()).toISOString() };
        return Promise.resolve(false);
      }
      const bytes = record(event, cause);
      queued++;
      const action = async () => {
        try {
          if (!await safeDirectory()) { await fs.mkdir(root, { recursive: true }); if (!await safeDirectory()) unsafe(); }
          const stats = await Promise.all(files.map(safeFile));
          const sizes = [];
          for (let index = 0; index < files.length; index++) sizes[index] = await compact(files[index], stats[index]);
          if (sizes[0] + bytes.length > maxBytes) {
            for (let index = files.length - 2; index >= 0; index--) if (await safeFile(files[index])) {
              await safeFile(files[index + 1]); if (!await safeDirectory()) unsafe(); await fs.rename(files[index], files[index + 1]);
            }
          }
          const handle = await verifiedOpen(file);
          try {
            const size = (await handle.stat()).size;
            // With one retained copy, discard only this owned log before appending.
            if (size + bytes.length > maxBytes) await handle.truncate(0);
            await writeAll(handle, bytes, size + bytes.length > maxBytes ? 0 : size); await handle.sync();
          } finally { await handle.close(); }
          state = { ...state, ok: true, errorCode: null }; return true;
        } catch (cause) {
          const code = cause.code === 'DESKTOP_LOG_UNSAFE' ? cause.code : 'DESKTOP_LOG_WRITE_FAILED';
          state = { ok: false, errorCode: code, lastFailureCode: code, lastFailureAt: new Date(now()).toISOString() };
          return false;
        } finally { queued--; }
      };
      const task = serial.then(action, action); serial = task.then(() => {}); return task;
    },
  };
}
