import path from 'node:path';
import { lstat, realpath, open, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { createDiagnosticShareSummary } from './diagnostic-summary.mjs';
import { buildLayeredDiagnosis } from './layered-diagnostics.mjs';
import { UserError } from './config.mjs';

const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const allowed = (value, choices, fallback) => choices.includes(value) ? value : fallback;
const fail = () => { throw new UserError('SUPPORT_REPORT_WRITE_FAILED', '故障报告未能写入所选目录，请选择可写的本地目录。'); };
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);

// Build from fixed fields, never from logs or a raw JSON dump. No input text is
// copied into the report, including errors, URLs, IPs, paths, ICE or identities.
export function createSupportReport({ version, status: value = {}, targetCheck, now = Date.now } = {}) {
  const status = object(value), summary = createDiagnosticShareSummary({ version, status });
  const proxy = object(status.proxy), sourceChecks = Array.isArray(targetCheck?.checks) ? targetCheck.checks.slice(0, 32) : [];
  const target = targetCheck && sourceChecks.length ? { status: allowed(targetCheck.status, ['mocked', 'reachable', 'failed'], 'failed'), checks: sourceChecks.map(raw => {
    const row = object(raw), http = row.targetHttpStatus || row.httpStatus;
    return { transportReachable: row.transportReachable === true, targetHttpStatus: Number.isInteger(http) && http >= 100 && http <= 599 ? http : null };
  }) } : null;
  const diagnostic = buildLayeredDiagnosis({ service: { mock: summary.simulation }, proxy: { connectionMode: summary.connectionMode, mode: summary.transportMode,
    running: proxy.running === true, managed: proxy.managed === true, requestedStop: proxy.requestedStop === true, exitStatus: summary.exitStatus, systemNetwork: { status: summary.systemNetwork } },
    browserObservation: { status: summary.browser.observation, report: { checks: Object.entries(summary.browser.checks).map(([id, state]) => ({ id, status: state })) } },
    lastError: summary.code ? { code: summary.code } : null }, target);
  const at = typeof now === 'function' ? now() : now;
  const license = object(status.license), workspaces = object(status.workspaces);
  return {
    schemaVersion: 1, product: 'MC Proxy', createdAt: new Date(Number.isSafeInteger(at) && at >= 0 && at <= 253_402_300_799_999 ? at : Date.now()).toISOString(),
    privacy: { redacted: true, includesRawLogs: false, includesCredentials: false, uploaded: false },
    scope: 'current-observations-only', summary, diagnosis: diagnostic,
    license: { required: license.required === true, allowed: license.allowed === true,
      state: allowed(license.state, ['development', 'initializing', 'active', 'unactivated', 'unlicensed', 'revoked', 'pending-resource', 'expired', 'offline-expired', 'error'], 'unknown') },
    workspace: { count: Number.isSafeInteger(workspaces.count) && workspaces.count >= 0 ? Math.min(workspaces.count, 100) : Array.isArray(workspaces.items) ? Math.min(workspaces.items.length, 100) : 0,
      phase: allowed(workspaces.phase, ['idle', 'connecting', 'verifying', 'opening', 'ready', 'failed', 'cancelled'], 'unknown') },
    untested: [
      ...diagnostic.layers.filter(row => ['unverified', 'configured', 'mocked'].includes(row.status)).map(row => row.id),
      ...Object.entries(summary.browser.checks).filter(([, state]) => !['verified', 'failed', 'mismatch'].includes(state)).map(([id]) => `browser:${id}`),
      'account-login', 'provider-account-status', 'continuous-connection-stability',
    ],
  };
}

export async function writeSupportReport({ directory, ...options } = {}) {
  if (typeof directory !== 'string' || !path.isAbsolute(directory)) fail();
  const root = path.resolve(directory), report = createSupportReport(options);
  const fileName = `MC-Proxy-support-${report.createdAt.replace(/[-:.]/g, '')}-${randomUUID().slice(0, 8)}.json`, file = path.join(root, fileName);
  async function safe(target) {
    let cursor = path.parse(target).root;
    for (const part of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try { const info = await lstat(cursor); if (info.isSymbolicLink() || normalize(await realpath(cursor)) !== normalize(cursor)) fail(); }
      catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
    }
  }
  let created = false;
  try {
    await safe(root);
    try { if (!(await lstat(root)).isDirectory()) fail(); }
    catch (cause) { if (cause.code !== 'ENOENT') throw cause; await createPrivateDirectory(root); }
    await safe(file); await writePrivate(file, `${JSON.stringify(report, null, 2)}\n`); created = true;
    const handle = await open(file, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
    return { fileName, path: file, report };
  } catch { if (created) await rm(file, { force: true }).catch(() => {}); fail(); }
}
