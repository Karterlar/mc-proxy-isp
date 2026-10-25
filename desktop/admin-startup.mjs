import path from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, realpath, readFile, writeFile, mkdir, rm, rmdir } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { createPrivateDirectory } from '../backend/src/private-files.mjs';
import { inspectWindowsAdminAccess } from '../backend/src/windows-admin-access.mjs';

const executeFile = promisify(execFile);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SID = /^S-1-5-(?:\d+-)*\d+$/;
const SHORT_NAME = /^[A-Za-z0-9_!#$%&'()@^`{}-]{1,6}~[1-9][0-9]{0,5}(?:\.[A-Za-z0-9_!#$%&'()@^`{}-]{1,3})?$/;
const PREFIX = 'MC-Proxy-admin-startup-';
const failure = code => Object.assign(new Error(code), { code });
const canonical = value => path.resolve(value).replace(/[\\/]+$/, '').toLowerCase();
const same = (left, right) => canonical(left) === canonical(right);
const localPath = value => typeof value === 'string' && value.length <= 32768 && path.isAbsolute(value)
  && !/^[\\/]{2}|[\x00-\x1f\x7f]/.test(value);
const powershell = systemRoot => path.join(systemRoot || process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const encoded = script => ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];

export async function startupAccess({ mock = false, platform = process.platform, isElevated, inspectAdminAccess = inspectWindowsAdminAccess } = {}) {
  if (mock === true) return { allowed: true, reason: null, ...(isElevated ? {} : { verification: { mock: true, checked: false } }) };
  if (platform !== 'win32') return { allowed: false, reason: 'PLATFORM_UNSUPPORTED' };
  try {
    // Retain the existing inert boolean dependency for handoff unit fixtures.
    // Production always checks the main process token and a real access right.
    if (!isElevated) {
      const verification = await inspectAdminAccess();
      if (verification?.checked !== true || ![null, 'ADMIN_REQUIRED', 'ADMIN_CAPABILITY_DENIED', 'ADMIN_CHECK_FAILED'].includes(verification.errorCode)) throw failure('ADMIN_CHECK_FAILED');
      return { allowed: verification.errorCode === null, reason: verification.errorCode, verification };
    }
    const value = await isElevated();
    if (value === true) return { allowed: true, reason: null };
    return { allowed: false, reason: value === false ? 'ADMIN_REQUIRED' : 'ADMIN_CHECK_FAILED' };
  } catch { return { allowed: false, reason: 'ADMIN_CHECK_FAILED', ...(isElevated ? {} : { verification: { checked: false, errorCode: 'ADMIN_CHECK_FAILED' } }) }; }
}

async function identity({ dependencies, systemRoot }) {
  try {
    if (dependencies.getIdentity) return await dependencies.getIdentity();
    const result = await (dependencies.executeFile || executeFile)(path.join(systemRoot || process.env.SystemRoot || 'C:\\Windows', 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh'], {
      encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 16384,
    });
    const sid = SID.exec(result.stdout?.match(/S-1-5-(?:\d+-)*\d+/)?.[0] || '')?.[0];
    return { sid, userProfile: process.env.USERPROFILE };
  } catch { throw failure('ADMIN_CHECK_FAILED'); }
}

function validIdentity(value) { return value && SID.test(value.sid || '') && localPath(value.userProfile); }
function filesystem(dependencies) { return { lstat, realpath, readFile, writeFile, mkdir, rm, rmdir, ...dependencies.fs }; }

async function ordinary(fs, file, directory = false) {
  const stat = await fs.lstat(file);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1)
    || !same(await fs.realpath(file), file)) throw failure('ADMIN_HANDOFF_INVALID');
  return stat;
}
async function unlinkedAncestors(fs, target) {
  let cursor = path.parse(target).root;
  for (const part of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
    const candidate = path.join(cursor, part), stat = await fs.lstat(candidate), actual = path.resolve(await fs.realpath(candidate));
    // Windows TEMP and portable launches can legitimately contain ADMINI~1.
    // Expand only an actual short-name component in the same verified parent.
    if (!stat.isDirectory() || stat.isSymbolicLink() || !same(actual, candidate)
      && (!SHORT_NAME.test(part) || !same(path.dirname(actual), cursor))) throw failure('ADMIN_HANDOFF_INVALID');
    cursor = actual;
  }
  return cursor;
}
function handoffPaths(requestPath, temporaryRoot) {
  if (!localPath(requestPath) || !localPath(temporaryRoot)) throw failure('ADMIN_HANDOFF_INVALID');
  const request = path.resolve(requestPath), directory = path.dirname(request), name = path.basename(directory);
  if (path.basename(request) !== 'request.json' || !same(path.dirname(directory), temporaryRoot)
    || !name.startsWith(PREFIX) || !UUID.test(name.slice(PREFIX.length))) throw failure('ADMIN_HANDOFF_INVALID');
  return { directory, requestPath: request, readyPath: path.join(directory, 'ready.json'), nonce: name.slice(PREFIX.length) };
}
async function readJson(fs, file) {
  const stat = await ordinary(fs, file);
  if (stat.size > 4096) throw failure('ADMIN_HANDOFF_INVALID');
  const text = await fs.readFile(file, 'utf8');
  if (Buffer.byteLength(text) > 4096) throw failure('ADMIN_HANDOFF_INVALID');
  try { return JSON.parse(text); } catch { throw failure('ADMIN_HANDOFF_INVALID'); }
}

// This verification precedes any licensing, component preparation or session
// initialization. A different account supplied to UAC cannot create a new
// device identity while pretending to continue the original user's session.
export async function verifyAdminStartupHandoff(requestPath, { userData, temporaryRoot = tmpdir(), now = Date.now,
  platform = process.platform, isElevated, dependencies = {}, systemRoot } = {}) {
  const access = await startupAccess({ platform, isElevated });
  if (!access.allowed) throw failure(access.reason);
  const fs = filesystem(dependencies), temporaryBase = await unlinkedAncestors(fs, path.resolve(temporaryRoot));
  const paths = handoffPaths(requestPath, temporaryBase);
  await unlinkedAncestors(fs, paths.directory);
  const request = await readJson(fs, paths.requestPath);
  if (!request || Object.keys(request).sort().join(',') !== 'expiresAt,issuedAt,nonce,userData,userProfile,userSid,version'
    || request.version !== 1 || request.nonce !== paths.nonce || !SID.test(request.userSid || '')
    || !localPath(request.userProfile) || !localPath(request.userData) || !localPath(userData)
    || !same(request.userData, userData) || !Number.isSafeInteger(request.issuedAt) || !Number.isSafeInteger(request.expiresAt)
    || request.expiresAt <= request.issuedAt || request.expiresAt - request.issuedAt > 600000) throw failure('ADMIN_HANDOFF_INVALID');
  if (now() < request.issuedAt - 5000 || now() > request.expiresAt) throw failure('ADMIN_HANDOFF_EXPIRED');
  const current = await identity({ dependencies, systemRoot });
  if (!validIdentity(current)) throw failure('ADMIN_CHECK_FAILED');
  if (current.sid !== request.userSid || !same(current.userProfile, request.userProfile)) throw failure('ADMIN_ACCOUNT_CHANGED');
  return { ...paths, request };
}

// Call only after the administrator window is actually visible, or after an
// existing administrator instance has been shown. RunAs success alone is not
// enough to let the ordinary permissions window close.
export async function completeAdminStartupHandoff(requestPath, options = {}) {
  const verified = await verifyAdminStartupHandoff(requestPath, options), fs = filesystem(options.dependencies || {});
  const ready = { version: 1, nonce: verified.nonce, ready: true };
  try { await fs.writeFile(verified.readyPath, JSON.stringify(ready) + '\n', { flag: 'wx', mode: 0o600 }); }
  catch (cause) {
    if (cause.code !== 'EEXIST') throw failure('ADMIN_HANDOFF_WRITE_FAILED');
    const existing = await readJson(fs, verified.readyPath);
    if (existing.version !== 1 || existing.nonce !== verified.nonce || existing.ready !== true
      || Object.keys(existing).sort().join(',') !== 'nonce,ready,version') throw failure('ADMIN_HANDOFF_INVALID');
  }
  return { ready: true };
}

export function quoteWindowsArgument(value) {
  if (typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value)) throw failure('ADMIN_RESTART_INVALID');
  return '"' + value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1') + '"';
}

function launchArguments(argv, userData, requestPath) {
  if (!Array.isArray(argv) || argv.length > 32 || argv.some(value => typeof value !== 'string' || value.length > 32768 || /[\x00-\x1f\x7f]/.test(value))) throw failure('ADMIN_RESTART_INVALID');
  const allowed = new Set(['--runtime-root', '--config-path', '--secrets-path', '--core-path', '--control-port']);
  const result = [];
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index];
    if (index === 0 && localPath(value)) { result.push(value); continue; } // Source Electron's app directory.
    if (value === '--mock') { result.push(value); continue; }
    if (!allowed.has(value) || !argv[index + 1] || argv[index + 1].startsWith('--')) throw failure('ADMIN_RESTART_INVALID');
    const argument = argv[++index];
    if (value === '--control-port' ? !/^\d{1,5}$/.test(argument) || Number(argument) > 65535 : !localPath(argument)) throw failure('ADMIN_RESTART_INVALID');
    result.push(value, argument);
  }
  return [...result, `--user-data-dir=${path.resolve(userData)}`, `--admin-startup-handoff=${requestPath}`];
}

const ELEVATE_SCRIPT = String.raw`
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$payload=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:MC_PROXY_ADMIN_STARTUP_PAYLOAD)) | ConvertFrom-Json
function Quote-Argument([string]$value) {
  $value=[regex]::Replace($value,'(\\*)"','$1$1\"')
  $value=[regex]::Replace($value,'(\\+)$','$1$1')
  return '"'+$value+'"'
}
try {
  $arguments=(@($payload.argv | ForEach-Object { Quote-Argument ([string]$_) }) -join ' ')
  $child=Start-Process -FilePath ([string]$payload.executable) -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru -ErrorAction Stop
  if(-not $child){throw 'ADMIN_RESTART_FAILED'}
  @{launched=$true} | ConvertTo-Json -Compress
} catch {
  $exception=$_.Exception
  while($exception -and -not ($exception -is [ComponentModel.Win32Exception])){$exception=$exception.InnerException}
  if($exception -and $exception.NativeErrorCode -eq 1223){@{launched=$false;code='ADMIN_RESTART_CANCELED'} | ConvertTo-Json -Compress;exit 0}
  @{launched=$false;code='ADMIN_RESTART_FAILED'} | ConvertTo-Json -Compress
  exit 0
}
`;

// No Electron dependency, persistent environment change, shell interpolation,
// real customer runtime access or renderer-selected executable is required.
export async function restartElevated({ executable, argv = [], userData, temporaryRoot = tmpdir(), timeoutMs = 180000,
  pollMs = 200, now = Date.now, dependencies = {}, systemRoot, signal } = {}) {
  if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
  if (!localPath(executable) || !localPath(userData) || !localPath(temporaryRoot) || !Number.isInteger(timeoutMs)
    || timeoutMs < 1000 || timeoutMs > 600000 || !Number.isInteger(pollMs) || pollMs < 1 || pollMs > 1000) throw failure('ADMIN_RESTART_INVALID');
  const fs = filesystem(dependencies), current = await identity({ dependencies, systemRoot });
  if (!validIdentity(current)) throw failure('ADMIN_CHECK_FAILED');
  const executableDirectory = await unlinkedAncestors(fs, path.dirname(path.resolve(executable)));
  const executableCandidate = path.join(executableDirectory, path.basename(executable)), executableActual = path.resolve(await fs.realpath(executableCandidate));
  if (!same(executableActual, executableCandidate) && (!SHORT_NAME.test(path.basename(executableCandidate))
    || !same(path.dirname(executableActual), executableDirectory))) throw failure('ADMIN_RESTART_INVALID');
  await ordinary(fs, executableActual);
  const temporaryBase = await unlinkedAncestors(fs, path.resolve(temporaryRoot));
  const nonce = (dependencies.randomUUID || randomUUID)(), directory = path.join(temporaryBase, PREFIX + nonce);
  const paths = handoffPaths(path.join(directory, 'request.json'), temporaryBase);
  const args = launchArguments(argv, userData, paths.requestPath);
  const issuedAt = now(), request = { version: 1, nonce, issuedAt, expiresAt: issuedAt + timeoutMs,
    userSid: current.sid, userProfile: path.resolve(current.userProfile), userData: path.resolve(userData) };
  let ownsDirectory = false;
  async function cleanup() {
    // Remove only our known files; unexpected files keep the directory for
    // inspection rather than broadening deletion to arbitrary contents.
    if (!ownsDirectory) return;
    try {
      await unlinkedAncestors(fs, directory);
      for (const file of [paths.readyPath, paths.requestPath]) {
        try { await ordinary(fs, file); await fs.rm(file); } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
      }
      const ignore = path.join(directory, '.gitignore');
      try {
        const stat = await ordinary(fs, ignore);
        if (stat.size !== 2 || await fs.readFile(ignore, 'utf8') !== '*\n') throw failure('ADMIN_HANDOFF_INVALID');
        await fs.rm(ignore);
      } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
      await fs.rmdir(directory);
    } catch { /* Preserve a changed path or an unexpected file. */ }
  }
  try {
    if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
    await (dependencies.createPrivateDirectory || createPrivateDirectory)(directory);
    ownsDirectory = true;
    if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
    await fs.writeFile(paths.requestPath, JSON.stringify(request) + '\n', { flag: 'wx', mode: 0o600 });
    if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
    const env = { ...process.env, MC_PROXY_ADMIN_STARTUP_PAYLOAD: Buffer.from(JSON.stringify({ executable: executableActual, argv: args })).toString('base64') };
    const launch = await (dependencies.executeFile || executeFile)(powershell(systemRoot), encoded(ELEVATE_SCRIPT), {
      windowsHide: true, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 16384, env, ...(signal ? { signal } : {}),
    });
    if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
    let result;
    try { result = JSON.parse(launch.stdout.replace(/^\uFEFF/, '').trim()); } catch { throw failure('ADMIN_RESTART_FAILED'); }
    if (result.launched !== true) return { ready: false, code: result.code === 'ADMIN_RESTART_CANCELED' ? result.code : 'ADMIN_RESTART_FAILED' };
    while (now() <= request.expiresAt) {
      if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
      try {
        const ready = await readJson(fs, paths.readyPath);
        if (ready.version !== 1 || ready.nonce !== nonce || ready.ready !== true || Object.keys(ready).sort().join(',') !== 'nonce,ready,version') throw failure('ADMIN_HANDOFF_INVALID');
        if (signal?.aborted) return { ready: false, code: 'ADMIN_RESTART_CANCELED' };
        return { ready: true, code: null };
      } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
      await (dependencies.delay || delay)(pollMs);
    }
    return { ready: false, code: 'ADMIN_RESTART_TIMEOUT' };
  } catch (cause) {
    return { ready: false, code: signal?.aborted || cause.code === 'ADMIN_RESTART_CANCELED' ? 'ADMIN_RESTART_CANCELED'
      : cause.code === 'ADMIN_HANDOFF_INVALID' ? 'ADMIN_HANDOFF_INVALID' : 'ADMIN_RESTART_FAILED' };
  } finally { await cleanup(); }
}
