import path from 'node:path';
import { access, lstat, mkdir, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { spawn, execFile as nodeExecFile } from 'node:child_process';
import { randomInt, randomUUID } from 'node:crypto';
import os from 'node:os';
import { createWindowsProcessTools, sameProcess, closeBrowser, parseWindowsCommandLine } from './windows-process.mjs';
import { inspectFingerprintRuntime } from './fingerprint-browser-runtime.mjs';
import { validBrowserWorkspaceId, validateWorkspaceServices } from './browser-workspaces.mjs';
import { resolveWindowsPlatformVersion } from './browser-identity.mjs';
import { createBrowserProfileArchives } from './browser-profile-archives.mjs';

const URLS = Object.freeze({ exit: 'https://api.ipify.org/', google: 'https://www.google.com/', wikipedia: 'https://www.wikipedia.org/', github: 'https://github.com/', youtube: 'https://www.youtube.com/', chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/', tiktok: 'https://www.tiktok.com/', ping0: 'https://ping0.cc/', cleanip: 'https://cleanip.io/claude', ippure: 'https://ippure.com/claude' });
const LABELS = Object.freeze({ chrome: 'Google Chrome', edge: 'Microsoft Edge' });
const CACHE_PATHS = ['Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'Service Worker/CacheStorage', 'Service Worker/ScriptCache'];
const COOKIE_PATHS = ['Cookies', 'Cookies-journal', 'Cookies-wal', 'Cookies-shm', 'Network/Cookies', 'Network/Cookies-journal', 'Network/Cookies-wal', 'Network/Cookies-shm'];
const LANGUAGE_KEYS = ['accept_languages', 'selected_languages'];
const WEBRTC_KEYS = ['ip_handling_policy'];
const WEBRTC_POLICY = 'disable_non_proxied_udp';
const GEO_PATHS = [ ['profile', 'default_content_setting_values', 'geolocation'], ['profile', 'default_content_setting_values', 'geolocation_with_options'], ['profile', 'content_settings', 'exceptions', 'geolocation'], ['profile', 'content_settings', 'exceptions', 'geolocation_with_options'] ];
const GEO_PARENTS = [ ['profile'], ['profile', 'default_content_setting_values'], ['profile', 'content_settings'], ['profile', 'content_settings', 'exceptions'] ];
const keyFor = parts => parts.join('/');
const atPath = (value, parts) => parts.reduce((at, key) => at?.[key], value);
function setPreference(value, parts, field) {
  let cursor = value;
  for (const key of parts.slice(0, -1)) {
    if (cursor[key] !== undefined && (!cursor[key] || Array.isArray(cursor[key]) || typeof cursor[key] !== 'object')) throw error('BROWSER_STATE_INVALID', '定位首选项格式异常');
    cursor = cursor[key] ||= {};
  }
  if (field.present) cursor[parts.at(-1)] = field.value; else delete cursor[parts.at(-1)];
}
const error = (code, message, status = 409) => Object.assign(new Error(message), { code, status });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const exists = async file => { try { await access(file); return true; } catch (e) { if (e.code === 'ENOENT') return false; throw e; } };
const normalize = value => path.resolve(value).replace(/[\\/]+$/, '').toLowerCase();

// A substring match can confuse sibling profiles and must never establish ownership.
export const splitWindowsCommandLine = parseWindowsCommandLine;

export function commandUsesProfile(commandLine, profile) {
  const args = splitWindowsCommandLine(String(commandLine || ''));
  const values = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--user-data-dir') values.push(args[++i]);
    else if (args[i].startsWith('--user-data-dir=')) values.push(args[i].slice('--user-data-dir='.length));
  }
  return values.length === 1 && typeof values[0] === 'string' && normalize(values[0]) === normalize(profile);
}

function defaultCandidates() {
  const local = process.env.LOCALAPPDATA;
  const programFiles = [...new Set([process.env.ProgramW6432, process.env.ProgramFiles, process.env['ProgramFiles(x86)'], 'C:\\Program Files', 'C:\\Program Files (x86)'].filter(Boolean))];
  return [
    ...programFiles.map(folder => ({ id: 'chrome', executable: path.join(folder, 'Google', 'Chrome', 'Application', 'chrome.exe') })),
    ...(local ? [{ id: 'chrome', executable: path.join(local, 'Google', 'Chrome', 'Application', 'chrome.exe') }] : []),
    ...(local ? [{ id: 'chrome', executable: path.join(local, 'Google', 'Chrome', 'Bin', 'chrome.exe') }] : []),
    ...programFiles.map(folder => ({ id: 'edge', executable: path.join(folder, 'Microsoft', 'Edge', 'Application', 'msedge.exe') })),
    ...(local ? [{ id: 'edge', executable: path.join(local, 'Microsoft', 'Edge', 'Application', 'msedge.exe') }] : []),
  ];
}

// Read installation registrations and executable paths only. Browser profiles,
// command lines, cookies and account data are outside discovery's scope.
const BROWSER_DISCOVERY_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$found = @()
function Add-BrowserCandidate($id, $executable) {
    if (-not $executable) { return }
    $executable = [Environment]::ExpandEnvironmentVariables([string]$executable).Trim().Trim('"')
    # Reject remote/device/argument paths before any filesystem metadata query.
    if ($executable.Length -gt 1024 -or $executable -notmatch '^[A-Za-z]:[\\/]' -or $executable -match '["\x00-\x1f\x7f]' -or $executable.Substring(2).Contains(':')) { return }
    $alias = $false
    if ($id -eq 'chrome' -and [IO.Path]::GetFileName($executable) -ieq 'Google Chrome.exe') {
        $canonical = Join-Path ([IO.Path]::GetDirectoryName($executable)) 'chrome.exe'
        if (Test-Path -LiteralPath $canonical -PathType Leaf) { $executable = $canonical }
        else {
            try {
                $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($executable)
                if ($version.ProductName -cne 'Google Chrome' -or $version.OriginalFilename -ine 'chrome.exe' -or $version.CompanyName -cne 'Google LLC') { return }
                $alias = $true
            } catch { return }
        }
    }
    $script:found += [pscustomobject]@{id=$id;executable=$executable;verifiedAlias=$alias}
}
foreach ($hive in @([Microsoft.Win32.RegistryHive]::CurrentUser,[Microsoft.Win32.RegistryHive]::LocalMachine)) {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,$view)
            foreach ($browser in @(@{id='chrome';name='chrome.exe'},@{id='chrome';name='Google Chrome.exe'},@{id='edge';name='msedge.exe'})) {
                $key = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\' + $browser.name)
                if ($key) { try { Add-BrowserCandidate $browser.id $key.GetValue('') } finally { $key.Dispose() } }
            }
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                try {
                    foreach ($name in @($uninstall.GetSubKeyNames() | Select-Object -First 512)) {
                        $product = $uninstall.OpenSubKey($name)
                        if ($product) {
                            try {
                                $display = [string]$product.GetValue('DisplayName')
                                $location = [string]$product.GetValue('InstallLocation')
                                if ($location -and $display -ceq 'Google Chrome') {
                                    Add-BrowserCandidate 'chrome' (Join-Path $location 'chrome.exe')
                                    Add-BrowserCandidate 'chrome' (Join-Path $location 'Google Chrome.exe')
                                } elseif ($location -and $display -ceq 'Microsoft Edge') { Add-BrowserCandidate 'edge' (Join-Path $location 'msedge.exe') }
                            } finally { $product.Dispose() }
                        }
                    }
                } finally { $uninstall.Dispose() }
            }
        } catch {} finally { if ($base) { $base.Dispose() } }
    }
}
try {
    foreach ($item in @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='Google Chrome.exe' OR Name='msedge.exe'" -ErrorAction Stop)) {
        if ($item.ExecutablePath) { Add-BrowserCandidate $(if ($item.Name -ieq 'msedge.exe') {'edge'} else {'chrome'}) $item.ExecutablePath }
    }
} catch {}
ConvertTo-Json -InputObject @($found | Select-Object id,executable,verifiedAlias -Unique) -Compress
`;

export async function discoverWindowsBrowserCandidates({ execFile = nodeExecFile, platform = process.platform } = {}) {
  if (platform !== 'win32') return [];
  try {
    const raw = await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(BROWSER_DISCOVERY_SCRIPT, 'utf16le').toString('base64')],
      { windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 65536 }, (cause, output) => cause ? reject(cause) : resolve(output)));
    const found = JSON.parse(String(raw).replace(/^\uFEFF/, '').trim());
    if (!Array.isArray(found) || found.length > 64) return [];
    const seen = new Set();
    return found.flatMap(item => {
      const executable = typeof item?.executable === 'string' ? item.executable.trim().replace(/^"([^"]+)"$/, '$1') : '';
      const filename = path.win32.basename(executable).toLowerCase();
      if (!Object.hasOwn(LABELS, item?.id) || !/^[A-Za-z]:[\\/]/.test(executable) || /["\x00-\x1f\x7f]/.test(executable) || executable.slice(2).includes(':')
        || (filename !== (item.id === 'chrome' ? 'chrome.exe' : 'msedge.exe') && !(item.id === 'chrome' && filename === 'google chrome.exe' && item.verifiedAlias === true))) return [];
      const key = `${item.id}:${path.win32.normalize(executable).toLowerCase()}`;
      if (seen.has(key)) return []; seen.add(key);
      return [{ id: item.id, executable }];
    });
  } catch { return []; }
}

export function createBrowserManager({ runtimeRoot, fingerprintRoot, readFingerprintRuntime = inspectFingerprintRuntime, readPlatformVersion = resolveWindowsPlatformVersion, readHardwareConcurrency = () => os.availableParallelism(), mock = false, processApi, candidates, discoverCandidates = discoverWindowsBrowserCandidates, spawnProcess = spawn, wait = delay, launchTimeoutMs = 5000, closeTimeoutMs = 10000, onFailure = () => {} } = {}) {
  if (!runtimeRoot || !path.isAbsolute(runtimeRoot)) throw error('RUNTIME_INVALID', '浏览器运行目录必须是绝对路径', 400);
  const root = path.resolve(runtimeRoot);
  const profileRoot = path.join(root, 'browser-profiles');
  const manifestPath = path.join(root, 'browser-session.json');
  const labels = { ...LABELS, ...(fingerprintRoot ? { fingerprint: '指纹浏览器' } : {}) };
  const pendingSeeds = new Map();
  let platformVersionPromise;
  const platformVersion = () => mock ? { version: '19.0.0', source: 'mocked' } : platformVersionPromise ||= Promise.resolve().then(readPlatformVersion).catch(cause => { platformVersionPromise = null; throw cause; });
  const fingerprintState = async full => mock ? { state: 'ready', version: 'mocked', architecture: 'x64', verified: false, mode: 'mocked' } : readFingerprintRuntime(fingerprintRoot, { full });
  const processes = processApi || { ...createWindowsProcessTools(), sameProcess, closeBrowser };
  const standardCandidates = candidates || (mock ? [] : defaultCandidates());
  let discovery = null;
  const selectedExecutables = new Map();
  async function browserCandidates() {
    if (mock || candidates) return [...selectedExecutables.values(), ...standardCandidates];
    // Ordinary status reads reuse discovery; explicit rescan refreshes it.
    discovery ||= Promise.resolve().then(discoverCandidates).catch(() => []);
    return [...selectedExecutables.values(), ...await discovery, ...standardCandidates];
  }
  async function executableAvailable(candidate) {
    if (!candidate || !Object.hasOwn(LABELS, candidate.id) || !path.isAbsolute(candidate.executable || '')) return false;
    try {
      if (!(await lstat(candidate.executable)).isFile()) return false;
      return selectedExecutables.get(candidate.id) !== candidate || normalize(await realpath(candidate.executable)) === normalize(candidate.executable);
    }
    catch (cause) { if (['ENOENT', 'ENOTDIR', 'EACCES', 'EPERM'].includes(cause.code)) return false; throw cause; }
  }
  let loaded = false; let session = null; let serial = Promise.resolve(); let activeFreshId = null; let activeWorkspaceId = null;
  const locked = action => { const next = serial.then(action, action); serial = next.catch(() => {}); return next; };
  const validFreshId = value => typeof value === 'string' && /^[a-f0-9-]{36}$/.test(value);
  const profilePath = (browser, freshId, workspaceId) => workspaceId ? path.join(profileRoot, 'workspaces', workspaceId, browser) : freshId ? path.join(profileRoot, 'fresh', browser, freshId) : path.join(profileRoot, browser);
  const profileFor = browser => profilePath(browser, activeFreshId, activeWorkspaceId);
  const snapshotFor = browser => path.join(profileFor(browser), '.proxypilot-language.json');
  const validateBrowser = browser => { if (!Object.hasOwn(labels, browser)) throw error('BROWSER_INVALID', '请选择受支持的受管浏览器', 400); };

  async function safePath(target, { tree = false } = {}) {
    const absolute = path.resolve(target);
    const relative = path.relative(root, absolute);
    if (relative.startsWith('..') || path.isAbsolute(relative)) throw error('BROWSER_PATH_UNSAFE', '浏览器路径超出独立运行目录');
    const parsed = path.parse(absolute);
    let cursor = parsed.root;
    for (const segment of absolute.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      let stat; try { stat = await lstat(cursor); } catch (e) { if (e.code === 'ENOENT') break; throw e; }
      if (stat.isSymbolicLink()) throw error('BROWSER_PATH_UNSAFE', '浏览器路径含符号链接或目录联接，操作已拒绝');
      if (normalize(await realpath(cursor)) !== normalize(cursor)) throw error('BROWSER_PATH_UNSAFE', '浏览器路径解析到非预期位置，操作已拒绝');
    }
    if (tree && await exists(absolute)) {
      const visit = async directory => {
        const stat = await lstat(directory);
        if (stat.isSymbolicLink()) throw error('BROWSER_PATH_UNSAFE', '缓存目录内部含链接，操作已拒绝');
        if (stat.isDirectory()) for (const child of await readdir(directory)) await visit(path.join(directory, child));
      };
      await visit(absolute);
    }
    return absolute;
  }

  async function readJson(file, missing = null) {
    await safePath(file);
    try { return JSON.parse(await readFile(file, 'utf8')); }
    catch (e) { if (e.code === 'ENOENT') return missing; if (e instanceof SyntaxError) throw error('BROWSER_STATE_INVALID', '独立浏览器状态文件无法解析；请保留文件后人工检查'); throw e; }
  }

  async function writeJson(file, value) {
    await safePath(file);
    await mkdir(path.dirname(file), { recursive: true });
    await safePath(file);
    const temporary = `${file}.${randomUUID()}.tmp`;
    try { await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); await safePath(file); await rename(temporary, file); }
    finally { await rm(temporary, { force: true }).catch(() => {}); }
  }

  async function profileDirectories(browser, { create = false, profile = profileFor(browser) } = {}) {
    const directory = profile;
    await safePath(directory);
    if (!(await exists(directory))) { if (!create) return ['Default']; await mkdir(directory, { recursive: true }); }
    const names = (await readdir(directory, { withFileTypes: true })).filter(entry => entry.name === 'Default' || /^Profile (?:0|[1-9]\d*)$/.test(entry.name));
    for (const entry of names) { await safePath(path.join(directory, entry.name)); if (!entry.isDirectory()) throw error('BROWSER_PATH_UNSAFE', '浏览器 profile 目录类型异常'); }
    if (!names.some(entry => entry.name === 'Default')) names.unshift({ name: 'Default' });
    return names.map(entry => entry.name);
  }

  const processSnapshot = async browser => {
    const read = name => (processes.listProcessCandidates || processes.listProcesses).call(processes, name);
    const lists = await Promise.all((browser === 'edge' ? ['msedge.exe'] : ['chrome.exe', 'Google Chrome.exe']).map(read));
    const list = lists.flat().filter((item, index, all) => all.findIndex(other => processes.sameProcess(item, other)) === index);
    if (new Set(list.map(item => item.pid)).size !== list.length) throw error('PROCESS_UNREADABLE', '浏览器进程快照发生身份冲突，恢复记录已保留；请等待浏览器状态稳定后重试');
    if (!list.some(item => item.unreadable === true)) return list;
    const scope = item => {
      if (!item.commandLine) return {};
      try {
        const args = splitWindowsCommandLine(item.commandLine); const profiles = [];
        for (let i = 0; i < args.length; i++) {
          if (args[i] === '--user-data-dir') profiles.push(args[++i]);
          else if (args[i].startsWith('--user-data-dir=')) profiles.push(args[i].slice(16));
        }
        const owned = profiles.some(value => typeof value === 'string' && (normalize(value) === normalize(profileRoot) || normalize(value).startsWith(normalize(profileRoot) + path.sep)));
        // A renderer without its profile argument cannot establish a foreign
        // root. Its parent chain must lead to a readable external root instead.
        const child = args.some(arg => arg === '--type' || arg.startsWith('--type='));
        const explicitForeignRoot = !owned && !child && profiles.length === 1 && typeof profiles[0] === 'string' && path.isAbsolute(profiles[0]);
        return { owned, explicitForeignRoot, foreignRoot: explicitForeignRoot || !owned && !child && profiles.length === 0 };
      } catch { return {}; }
    };
    const scopes = new Map(list.map(item => [item.pid, scope(item)]));
    const possiblyOwned = new Set(session?.browser === browser ? (session.ownedProcesses || []).map(item => item.pid) : []);
    if (session?.browser === browser && session.identity?.pid) possiblyOwned.add(session.identity.pid);
    for (const item of list) if (scopes.get(item.pid).owned) possiblyOwned.add(item.pid);
    // Keep unreadable descendants unresolved, even if their own arguments do
    // not expose the profile. Never put these partial records in the manifest.
    for (let changed = true; changed;) {
      changed = false;
      for (const item of list) if (possiblyOwned.has(item.parentPid) && !possiblyOwned.has(item.pid)) { possiblyOwned.add(item.pid); changed = true; }
    }
    const byPid = new Map(list.map(item => [item.pid, item]));
    for (const item of list.filter(item => item.unreadable === true)) {
      if (possiblyOwned.has(item.pid)) throw error('PROCESS_UNREADABLE', '受管浏览器进程身份暂时不可读，恢复记录已保留；请正常关闭独立浏览器后重试');
      let current = item; const seen = new Set(); let excluded = Boolean(scopes.get(item.pid).explicitForeignRoot);
      while (!excluded && current && !seen.has(current.pid)) {
        seen.add(current.pid);
        const parent = byPid.get(current.parentPid);
        // An exited/recycled parent PID is not evidence of foreign ownership.
        if (!parent || !Number.isFinite(Date.parse(current.createdAt)) || !Number.isFinite(Date.parse(parent.createdAt)) || Date.parse(parent.createdAt) >= Date.parse(current.createdAt)) break;
        if (parent.unreadable !== true && scopes.get(parent.pid).foreignRoot) excluded = true;
        current = parent;
      }
      if (!excluded) throw error('PROCESS_UNREADABLE', '无法排除不可读浏览器进程属于独立会话，恢复记录已保留；请正常关闭相关浏览器后重试');
    }
    return list.filter(item => item.unreadable !== true);
  };
  const identityPresent = (identity, list) => list.some(item => processes.sameProcess(identity, item));
  function creationOrder(first, second) {
    const a = Date.parse(first), b = Date.parse(second);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
    if (a !== b) return a > b ? 1 : -1;
    // CIM UTC timestamps carry seven fractional digits. Date.parse retains
    // only milliseconds; compare the remaining digits before claiming order.
    const fraction = value => (String(value).match(/\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/)?.[1] || '').padEnd(7, '0').slice(3, 7);
    const extraA = fraction(first), extraB = fraction(second);
    return extraA === extraB ? 0 : extraA > extraB ? 1 : -1;
  }
  const possibleChildOf = (child, parent) => child.parentPid === parent.pid && normalize(child.executable) === normalize(parent.executable)
    && creationOrder(child.createdAt, parent.createdAt) !== null && creationOrder(child.createdAt, parent.createdAt) >= 0;
  const childOf = (child, parent) => possibleChildOf(child, parent) && creationOrder(child.createdAt, parent.createdAt) > 0;
  function childScope(item, profile) {
    const args = splitWindowsCommandLine(item.commandLine); const explicitProfile = args.some(arg => arg === '--user-data-dir' || arg.startsWith('--user-data-dir='));
    return { allowedProfile: !explicitProfile || commandUsesProfile(item.commandLine, profile), subprocess: args.some(arg => arg === '--type' || arg.startsWith('--type=')) };
  }

  function validateRecordedProcesses(data) {
    const valid = item => item && item.unreadable !== true && Number.isSafeInteger(item.pid) && item.pid > 0 && item.pid <= 0xffffffff
      && Number.isSafeInteger(item.parentPid) && item.parentPid >= 0 && item.parentPid <= 0xffffffff
      && typeof item.createdAt === 'string' && Number.isFinite(Date.parse(item.createdAt))
      && typeof item.executable === 'string' && path.isAbsolute(item.executable) && !item.executable.includes('\0')
      && typeof item.commandLine === 'string' && item.commandLine && !item.commandLine.includes('\0');
    if (!data.identity) {
      if ([data.ownedProcesses, data.unconfirmedProcesses].some(list => list !== undefined && (!Array.isArray(list) || list.length))) throw error('BROWSER_STATE_INVALID', '浏览器恢复记录缺少可验证根身份，未关闭任何进程');
      return;
    }
    const executables = data.browser === 'edge' ? ['msedge.exe'] : data.browser === 'chrome' ? ['chrome.exe', 'google chrome.exe'] : ['chrome.exe'];
    if (!valid(data.identity) || !executables.includes(path.basename(data.identity.executable).toLowerCase())
      || !commandUsesProfile(data.identity.commandLine, data.profile)) throw error('BROWSER_STATE_INVALID', '浏览器根身份与独立资料目录不一致，未关闭任何进程');
    const groups = [data.ownedProcesses || [], data.unconfirmedProcesses || []];
    if (groups.some(list => !Array.isArray(list) || list.length > 4096 || list.some(item => !valid(item)))) throw error('BROWSER_STATE_INVALID', '浏览器子进程恢复记录无效，未关闭任何进程');
    for (let group = 0; group < groups.length; group++) for (const item of groups[group]) if (!processes.sameProcess(item, data.identity)) {
      const scope = childScope(item, data.profile);
      if (!scope.allowedProfile || group === 0 && !scope.subprocess) throw error('BROWSER_STATE_INVALID', '浏览器子进程指向其他资料目录或窗口，未关闭任何进程');
    }
    const records = [data.identity];
    for (const item of groups.flat()) {
      const previous = records.find(other => other.pid === item.pid);
      if (previous && !processes.sameProcess(previous, item)) throw error('BROWSER_STATE_INVALID', '浏览器恢复记录出现复用的进程编号，未关闭任何进程');
      if (!previous) records.push(item);
    }
    const byPid = new Map(records.map(item => [item.pid, item]));
    const confirmedPids = new Set([data.identity, ...groups[0]].map(item => item.pid));
    for (const item of records.slice(1)) {
      let current = item; const seen = new Set();
      while (!processes.sameProcess(current, data.identity)) {
        if (seen.has(current.pid)) throw error('BROWSER_STATE_INVALID', '浏览器子进程父链异常，未关闭任何进程');
        seen.add(current.pid);
        const parent = byPid.get(current.parentPid);
        const confirmed = confirmedPids.has(current.pid);
        if (!parent || confirmed && (!confirmedPids.has(parent.pid) || !childOf(current, parent))
          || !confirmed && !possibleChildOf(current, parent)) throw error('BROWSER_STATE_INVALID', '浏览器子进程归属无法验证，未关闭任何进程');
        current = parent;
      }
    }
  }

  async function unconfirmedChildren(snapshot) {
    if (!session?.identity) return false;
    const owned = [session.identity, ...(session.ownedProcesses || [])];
    const uncertain = [...(session.unconfirmedProcesses || [])];
    const anchors = [...owned, ...uncertain];
    for (let index = 0; index < anchors.length; index++) for (const item of snapshot) {
      if (possibleChildOf(item, anchors[index]) && childScope(item, session.profile).allowedProfile && !identityPresent(item, owned) && !identityPresent(item, uncertain)) {
        // A child first observed after its parent exits is only possibly ours.
        // Retain its exact identity/ancestry to block restoration, never stop it.
        uncertain.push(item); anchors.push(item);
      }
    }
    if (JSON.stringify(uncertain) !== JSON.stringify(session.unconfirmedProcesses || [])) {
      session.unconfirmedProcesses = uncertain; await writeJson(manifestPath, session);
    }
    return uncertain.some(identity => identityPresent(identity, snapshot));
  }

  async function launchedIdentity(snapshot) {
    const launch = session?.launch;
    if (!launch || launch.baselineEmpty !== true || !launch.pid) return null;
    const earliest = Date.parse(launch.startedAt);
    const matches = [];
    for (const item of snapshot) {
      const created = Date.parse(item.createdAt);
      if (!Number.isFinite(created) || created < earliest || created > earliest + 30000 || !commandUsesProfile(item.commandLine, session.profile)) continue;
      const args = splitWindowsCommandLine(item.commandLine);
      if (JSON.stringify(args.slice(1)) !== JSON.stringify(launch.args)) continue;
      try { if (normalize(await realpath(item.executable)) !== normalize(launch.executable)) continue; }
      catch { continue; }
      matches.push(item);
    }
    if (matches.length > 1) throw error('BROWSER_SESSION_UNTRACKED', '本次启动出现多个相同浏览器身份，未接管其他进程');
    return matches[0] || null;
  }

  async function profileProcesses(browser, snapshot) {
    const list = snapshot || await processSnapshot(browser);
    return list.filter(item => commandUsesProfile(item.commandLine, profileFor(browser)));
  }

  async function ownedProcessTree(identity, browser, snapshot) {
    const list = snapshot || await processSnapshot(browser);
    if (!identityPresent(identity, list)) throw error('BROWSER_SESSION_UNTRACKED', '浏览器进程身份已改变，请手动关闭窗口后重试');
    const selected = [identity];
    for (const previous of session?.ownedProcesses || []) {
      if (identityPresent(previous, list) && !selected.some(item => item.pid === previous.pid)) selected.push(previous);
    }
    const previous = new Map((session?.ownedProcesses || []).map(item => [item.pid, item]));
    for (let index = 0; index < selected.length; index++) {
      const parent = previous.get(selected[index].parentPid);
      if (parent && childOf(selected[index], parent) && !selected.some(item => item.pid === parent.pid)) selected.push(parent);
    }
    for (let index = 0; index < selected.length; index += 1) {
      const parent = selected[index];
      if (!identityPresent(parent, list)) continue;
      for (const item of list) {
        const scope = childScope(item, session.profile);
        if (childOf(item, parent) && scope.allowedProfile && scope.subprocess && !selected.some(known => known.pid === item.pid)) selected.push(item);
      }
    }
    return selected;
  }

  async function assertClosed(browser) {
    const snapshot = await processSnapshot(browser);
    if ((await profileProcesses(browser, snapshot)).length) throw error('BROWSER_ALREADY_RUNNING', '此独立浏览器仍在运行，请先安全结束会话');
    await loadSession();
    if (session?.browser === browser) {
      if ((session.ownedProcesses || []).some(identity => identityPresent(identity, snapshot))) throw error('BROWSER_ALREADY_RUNNING', '此独立浏览器的子进程仍在运行，请等待安全结束');
      if (await unconfirmedChildren(snapshot)) throw error('BROWSER_ALREADY_RUNNING', '此独立浏览器可能仍有子进程，恢复记录保留，请等待退出');
    }
  }

  async function loadSession() {
    if (loaded || mock) return;
    const data = await readJson(manifestPath);
    if (data) {
      if (data.version !== 1 || !Object.hasOwn(labels, data.browser) || (data.freshId && !validFreshId(data.freshId)) || (data.workspaceId !== undefined && (!validBrowserWorkspaceId(data.workspaceId) || data.freshId)) || normalize(data.profile || '.') !== normalize(profilePath(data.browser, data.freshId, data.workspaceId)) || !Number.isInteger(data.port)) throw error('BROWSER_STATE_INVALID', '浏览器会话记录无效，已拒绝恢复');
      if (data.launch && (data.launch.version !== 1 || data.launch.baselineEmpty !== true || !Number.isFinite(Date.parse(data.launch.startedAt))
        || typeof data.launch.executable !== 'string' || !path.isAbsolute(data.launch.executable) || data.launch.executable.includes('\0')
        || !Array.isArray(data.launch.args) || data.launch.args.length > 256 || data.launch.args.some(value => typeof value !== 'string' || value.length > 8192 || value.includes('\0'))
        || data.launch.pid !== null && (!Number.isSafeInteger(data.launch.pid) || data.launch.pid <= 0 || data.launch.pid > 0xffffffff))) throw error('BROWSER_STATE_INVALID', '浏览器启动恢复记录无效，已拒绝接管');
      if (data.observationPort !== undefined && (!validPort(data.observationPort) || data.observationPort === data.port)
        || data.browserArgs !== undefined && (!Array.isArray(data.browserArgs) || data.browserArgs.length > 256 || data.browserArgs.some(value => typeof value !== 'string' || value.length > 8192 || value.includes('\0')))
        || data.fingerprint !== undefined && (data.browser !== 'fingerprint' || !validSeed(data.fingerprint?.seed) || !validCores(data.fingerprint?.cores) || !/^\d{1,5}\.\d{1,5}\.0$/.test(data.fingerprint?.platformVersion || '') || typeof data.fingerprint.timezone !== 'string' || typeof data.fingerprint.nativeGraphics !== 'boolean' || typeof data.fingerprint.engineVersion !== 'string')) throw error('BROWSER_STATE_INVALID', '浏览器身份或本机检测恢复记录无效，未接管其他进程');
      validateRecordedProcesses(data);
      activeFreshId = data.freshId || null;
      activeWorkspaceId = data.workspaceId || null;
      session = data;
    }
    loaded = true;
  }

  async function restorePreferences(browser) {
    await assertClosed(browser);
    const snapshot = await readJson(snapshotFor(browser));
    if (!snapshot) return;
    if (![1, 2, 3].includes(snapshot.version) || !Array.isArray(snapshot.preferences)) throw error('BROWSER_STATE_INVALID', '浏览器首选项恢复记录无效');
    for (const entry of snapshot.preferences) {
      if (!/^(Default|Profile (?:0|[1-9]\d*))$/.test(entry.directory) || !entry.fields || typeof entry.fields !== 'object') throw error('BROWSER_STATE_INVALID', '语言恢复路径无效');
      const file = path.join(profileFor(browser), entry.directory, 'Preferences');
      const prefs = await readJson(file, {});
      if (!prefs || Array.isArray(prefs) || typeof prefs !== 'object') throw error('BROWSER_STATE_INVALID', '浏览器首选项格式异常');
      const intl = prefs.intl && typeof prefs.intl === 'object' && !Array.isArray(prefs.intl) ? prefs.intl : {};
      for (const key of LANGUAGE_KEYS) {
        const field = entry.fields[key];
        if (!field || typeof field.present !== 'boolean') throw error('BROWSER_STATE_INVALID', '语言恢复字段无效');
        if (field.present) intl[key] = field.value; else delete intl[key];
      }
      if (Object.keys(intl).length || entry.hadIntl) prefs.intl = intl; else delete prefs.intl;
      if (snapshot.version >= 2) {
        if (typeof entry.hadWebrtc !== 'boolean' || !entry.webrtcFields || typeof entry.webrtcFields !== 'object') throw error('BROWSER_STATE_INVALID', 'WebRTC 恢复记录无效');
        if (prefs.webrtc && (typeof prefs.webrtc !== 'object' || Array.isArray(prefs.webrtc))) throw error('BROWSER_STATE_INVALID', 'WebRTC 首选项格式异常');
        const webrtc = prefs.webrtc || {};
        for (const key of WEBRTC_KEYS) {
          const field = entry.webrtcFields[key];
          if (!field || typeof field.present !== 'boolean') throw error('BROWSER_STATE_INVALID', 'WebRTC 恢复字段无效');
          if (field.present) webrtc[key] = field.value; else delete webrtc[key];
        }
        if (Object.keys(webrtc).length || entry.hadWebrtc) prefs.webrtc = webrtc; else delete prefs.webrtc;
      }
      if (snapshot.version === 3) {
        if (browser !== 'fingerprint' || !entry.geolocationFields || !entry.geolocationParents) throw error('BROWSER_STATE_INVALID', '定位恢复记录无效');
        for (const parts of GEO_PATHS) {
          const field = entry.geolocationFields[keyFor(parts)];
          if (!field || typeof field.present !== 'boolean') throw error('BROWSER_STATE_INVALID', '定位恢复字段无效');
          setPreference(prefs, parts, field);
        }
        for (const parts of [...GEO_PARENTS].reverse()) {
          if (typeof entry.geolocationParents[keyFor(parts)] !== 'boolean') throw error('BROWSER_STATE_INVALID', '定位恢复父字段无效');
          const parent = atPath(prefs, parts.slice(0, -1)), value = parent?.[parts.at(-1)];
          if (!entry.geolocationParents[keyFor(parts)] && value && !Object.keys(value).length) delete parent[parts.at(-1)];
        }
      }
      await writeJson(file, prefs);
    }
    await safePath(snapshotFor(browser));
    await rm(snapshotFor(browser), { force: true });
  }

  async function preparePreferences(browser, language = 'en-US') {
    await restorePreferences(browser);
    const preferences = [];
    for (const directory of await profileDirectories(browser, { create: true })) {
      const file = path.join(profileFor(browser), directory, 'Preferences');
      const prefs = await readJson(file, {});
      if (!prefs || Array.isArray(prefs) || typeof prefs !== 'object' || (prefs.intl && (typeof prefs.intl !== 'object' || Array.isArray(prefs.intl)))) throw error('BROWSER_STATE_INVALID', '浏览器首选项格式异常');
      if (prefs.webrtc && (typeof prefs.webrtc !== 'object' || Array.isArray(prefs.webrtc))) throw error('BROWSER_STATE_INVALID', 'WebRTC 首选项格式异常');
      preferences.push({ directory, hadIntl: Object.hasOwn(prefs, 'intl'), fields: Object.fromEntries(LANGUAGE_KEYS.map(key => [key, { present: Object.hasOwn(prefs.intl || {}, key), ...(Object.hasOwn(prefs.intl || {}, key) ? { value: prefs.intl[key] } : {}) }])), hadWebrtc: Object.hasOwn(prefs, 'webrtc'), webrtcFields: Object.fromEntries(WEBRTC_KEYS.map(key => [key, { present: Object.hasOwn(prefs.webrtc || {}, key), ...(Object.hasOwn(prefs.webrtc || {}, key) ? { value: prefs.webrtc[key] } : {}) }])) });
      if (browser === 'fingerprint') {
        for (const parts of GEO_PARENTS) { const value = atPath(prefs, parts); if (value !== undefined && (!value || Array.isArray(value) || typeof value !== 'object')) throw error('BROWSER_STATE_INVALID', '定位首选项格式异常'); }
        Object.assign(preferences.at(-1), {
          geolocationParents: Object.fromEntries(GEO_PARENTS.map(parts => [keyFor(parts), atPath(prefs, parts) !== undefined])),
          geolocationFields: Object.fromEntries(GEO_PATHS.map(parts => [keyFor(parts), { present: atPath(prefs, parts) !== undefined, ...(atPath(prefs, parts) !== undefined ? { value: atPath(prefs, parts) } : {}) }])),
        });
      }
    }
    // Save the narrow rollback record before changing any preferences.
    await writeJson(snapshotFor(browser), { version: browser === 'fingerprint' ? 3 : 2, preferences });
    try {
      for (const entry of preferences) {
        const file = path.join(profileFor(browser), entry.directory, 'Preferences');
        const prefs = await readJson(file, {});
        const languages = [...new Set([language, language.split('-')[0]])].join(',');
        prefs.intl = { ...prefs.intl, accept_languages: languages, selected_languages: languages };
        // Chromium reads this registered profile preference for renderer WebRTC.
        // A launch argument alone is not proof that the effective policy is set.
        prefs.webrtc = { ...prefs.webrtc, ip_handling_policy: WEBRTC_POLICY };
        if (browser === 'fingerprint') {
          for (const [index, parts] of GEO_PATHS.entries()) setPreference(prefs, parts, { present: true, value: index === 0 ? 2 : index === 1 ? { approximate: 2, precise: 2 } : {} });
        }
        await writeJson(file, prefs);
      }
    } catch (e) { await restorePreferences(browser); throw e; }
  }

  async function clearFinishedSession() {
    if (!session) return;
    await restorePreferences(session.browser);
    await safePath(manifestPath);
    await rm(manifestPath, { force: true });
    session = null;
    activeFreshId = null;
    activeWorkspaceId = null;
  }

  async function statusInternal({ inspectMissingProfiles = false } = {}) {
    if (mock) return { running: false, browser: null, language: null, mode: 'mocked', restorePending: false };
    await profileArchivesStore.recover();
    await loadSession();
    if (session) {
      const snapshot = await processSnapshot(session.browser);
      if (!session.identity && session.launch) {
        const identity = await launchedIdentity(snapshot);
        if (identity) { session.identity = identity; await writeJson(manifestPath, session); }
      }
      const active = await profileProcesses(session.browser, snapshot);
      const managed = !!session.identity && active.some(item => processes.sameProcess(session.identity, item));
      if (managed) {
        const owned = await ownedProcessTree(session.identity, session.browser, snapshot);
        if (JSON.stringify(owned) !== JSON.stringify(session.ownedProcesses)) { session.ownedProcesses = owned; await writeJson(manifestPath, session); }
      }
      const tracked = (session.ownedProcesses || []).some(identity => identityPresent(identity, snapshot));
      const uncertain = await unconfirmedChildren(snapshot);
      if (active.length || tracked || uncertain) return { running: true, browser: session.browser, language: session.language, port: session.port, startedAt: session.startedAt, managed, restorePending: true, ...(session.freshId ? { fresh: true } : {}), ...(session.workspaceId ? { workspaceId: session.workspaceId } : {}), ...(session.fingerprint ? { fingerprint: { ...session.fingerprint } } : {}), ...(session.observationPort ? { observationPort: session.observationPort } : {}), webrtc: { policy: WEBRTC_POLICY, configured: session.settingsVersion === 2, verification: 'unverified', restartRequired: session.settingsVersion !== 2 } };
      await clearFinishedSession();
    }
    for (const browser of Object.keys(labels)) {
      // The manager creates its profile before launching any browser. A fresh
      // installation with no profile or recovery snapshot has nothing to adopt;
      // avoid enumerating unrelated Chrome/Edge processes on each UI poll.
      await safePath(profileFor(browser));
      if (!inspectMissingProfiles && !await exists(profileFor(browser))) continue;
      if ((await profileProcesses(browser)).length) return { running: true, browser, language: null, managed: false, restorePending: await exists(snapshotFor(browser)) };
      if (await exists(snapshotFor(browser))) await restorePreferences(browser);
    }
    // A missing manifest cannot prove that our fresh windows have closed. Find
    // only exact managed UUID profiles; never adopt or terminate these roots.
    const snapshots = new Map();
    for (const browser of Object.keys(labels)) {
      const freshRoot = path.join(profileRoot, 'fresh', browser);
      await safePath(freshRoot);
      if (!await exists(freshRoot)) continue;
      for (const entry of await readdir(freshRoot, { withFileTypes: true })) {
        if (!validBrowserWorkspaceId(entry.name) || !entry.isDirectory()) throw error('BROWSER_PATH_UNSAFE', '纯净浏览器目录包含非预期项目');
        const profile = profilePath(browser, entry.name);
        await safePath(profile);
        if (!snapshots.has(browser)) snapshots.set(browser, await processSnapshot(browser));
        if (snapshots.get(browser).some(item => commandUsesProfile(item.commandLine, profile))) return { running: true, browser, fresh: true, language: null, managed: false, restorePending: await exists(path.join(profile, '.proxypilot-language.json')) };
      }
    }
    // A missing manifest must not allow a second workspace beside an orphaned
    // managed profile. Read only our UUID directory names, never other browsers.
    const workspacesRoot = path.join(profileRoot, 'workspaces');
    await safePath(workspacesRoot);
    if (await exists(workspacesRoot)) {
      const directories = await readdir(workspacesRoot, { withFileTypes: true });
      for (const entry of directories) {
        if (!validBrowserWorkspaceId(entry.name) || !entry.isDirectory()) throw error('BROWSER_PATH_UNSAFE', '工作区浏览器目录包含非预期项目');
        for (const browser of Object.keys(labels)) {
          const profile = profilePath(browser, null, entry.name);
          await safePath(profile);
          if (!await exists(profile)) continue;
          if (!snapshots.has(browser)) snapshots.set(browser, await processSnapshot(browser));
          if (snapshots.get(browser).some(item => commandUsesProfile(item.commandLine, profile))) return { running: true, browser, workspaceId: entry.name, language: null, managed: false, restorePending: await exists(path.join(profile, '.proxypilot-language.json')) };
        }
      }
    }
    return { running: false, browser: null, language: null, restorePending: false };
  }

  async function listBrowsers() {
    if (mock) return Object.entries(labels).map(([id, label]) => ({ id, label, available: true, mode: 'mocked' }));
    const available = new Set();
    for (const candidate of await browserCandidates()) if (await executableAvailable(candidate)) available.add(candidate.id);
    const list = Object.entries(LABELS).map(([id, label]) => ({ id, label, available: available.has(id) }));
    if (fingerprintRoot) {
      const { executable: _executable, ...runtime } = await fingerprintState(false);
      list.push({ id: 'fingerprint', label: labels.fingerprint, available: runtime.state === 'ready', runtime });
    }
    return list;
  }

  async function rescan() { discovery = null; return listBrowsers(); }

  async function setExecutable({ browser = 'chrome', executable } = {}) {
    validateBrowser(browser);
    if (browser === 'fingerprint') throw error('BROWSER_FINGERPRINT_PATH_MANAGED', '指纹浏览器必须使用经过固定摘要校验的专用组件', 400);
    if (executable !== null && (typeof executable !== 'string' || executable.length > 1024 || !path.isAbsolute(executable) || process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(executable) || /^[\\/]{2}/.test(executable) || /["\x00-\x1f\x7f]/.test(executable) || executable.slice(2).includes(':'))) throw error('BROWSER_EXECUTABLE_INVALID', '请指定本机浏览器的完整可执行文件路径', 400);
    if (!mock && (await statusInternal()).running) throw error('BROWSER_ALREADY_RUNNING', '请先结束独立浏览器会话再修改安装路径');
    if (executable === null) selectedExecutables.delete(browser);
    else {
      let filename = path.basename(executable).toLowerCase();
      if (browser === 'chrome' && filename === 'google chrome.exe') { executable = path.join(path.dirname(executable), 'chrome.exe'); filename = 'chrome.exe'; }
      if (filename !== (browser === 'chrome' ? 'chrome.exe' : 'msedge.exe')) throw error('BROWSER_EXECUTABLE_INVALID', '安装路径必须指向 Chrome 或 Edge 浏览器程序', 400);
      if (!mock) {
        try {
          if (!(await lstat(executable)).isFile() || normalize(await realpath(executable)) !== normalize(executable)) throw new Error();
        } catch { throw error('BROWSER_EXECUTABLE_INVALID', '浏览器路径不存在、不可访问或包含链接，请重新选择', 400); }
      }
      selectedExecutables.set(browser, { id: browser, executable });
    }
    return listBrowsers();
  }

  const validSeed = value => Number.isInteger(value) && value >= 1 && value <= 4294967295;
  const validCores = value => Number.isInteger(value) && value >= 1 && value <= 65535;
  async function profileIdentity(profile, requested) {
    if (requested !== undefined && !validSeed(requested)) throw error('BROWSER_FINGERPRINT_SEED_INVALID', '指纹种子必须是 1-4294967295 的整数', 400);
    const saved = mock ? null : await readJson(path.join(profile, '.mc-fingerprint.json'));
    if (saved && (![1, 2].includes(saved.version) || !validSeed(saved.seed) || (saved.version === 2 || Object.hasOwn(saved, 'cores')) && !validCores(saved.cores))) throw error('BROWSER_FINGERPRINT_STATE_INVALID', '指纹身份记录损坏，未覆盖原记录');
    let identity = saved && validCores(saved.cores) ? { seed: saved.seed, cores: saved.cores } : pendingSeeds.get(profile);
    if (saved?.version === 1 && identity?.seed !== saved.seed) identity = null;
    if (!identity) {
      const cores = readHardwareConcurrency();
      if (!validCores(cores)) throw error('BROWSER_FINGERPRINT_HARDWARE_UNAVAILABLE', '无法读取本机处理器线程数，未生成虚假硬件参数');
      identity = { seed: saved?.seed || requested || randomInt(1, 4294967296), cores };
      if (pendingSeeds.size >= 128) pendingSeeds.delete(pendingSeeds.keys().next().value);
      pendingSeeds.set(profile, identity);
    }
    if (requested !== undefined && requested !== identity.seed) throw error('BROWSER_FINGERPRINT_SEED_CHANGED', '现有空间的种子已改变，请使用明确的换种子操作后重新生成计划');
    return identity;
  }

  const validPort = value => Number.isInteger(value) && value >= 1024 && value <= 65535;
  function validateObservationUrl(observationUrl) {
    let observed;
    try { observed = new URL(observationUrl); } catch { throw error('SERVICE_INVALID', '本机检测页面地址无效', 400); }
    const observationPort = Number(observed.port);
    if (observed.protocol !== 'http:' || observed.hostname !== '127.0.0.1' || !validPort(observationPort) || observed.username || observed.password || observed.search || observed.hash || !/^\/s\/[A-Za-z0-9_-]{32}\/$/.test(observed.pathname) || observed.href !== observationUrl) throw error('SERVICE_INVALID', '只允许当前本机检测服务的受限地址', 400);
    return observationPort;
  }

  async function plan({ browser = 'chrome', service = 'exit', services, workspaceId, port, language = 'en-US', fresh = false, freshId, observationUrl, observationPort, timezone = Intl.DateTimeFormat().resolvedOptions().timeZone, nativeGraphics = false, seed } = {}) {
    validateBrowser(browser);
    await profileArchivesStore.recover();
    if (workspaceId !== undefined && (!validBrowserWorkspaceId(workspaceId) || fresh || freshId !== undefined)) throw error('BROWSER_WORKSPACE_INVALID', '命名工作区必须使用固定的独立保留资料，不能同时开启纯净空间', 400);
    if (services !== undefined) {
      if (!workspaceId || service !== 'exit' && service !== services?.[0]) throw error('BROWSER_PLAN_INVALID', '多个网站只能用于已选工作区', 400);
      services = validateWorkspaceServices(services); service = services[0];
    }
    let url = URLS[service];
    if (observationPort !== undefined && (!validPort(observationPort) || observationPort === port)) throw error('SERVICE_INVALID', '本机检测端口无效或与代理端口冲突', 400);
    if (service === 'observation') {
      const observedPort = validateObservationUrl(observationUrl);
      if (observationPort !== undefined && observationPort !== observedPort || observedPort === port) throw error('SERVICE_INVALID', '检测页面与已绑定的本机端口不一致', 400);
      observationPort = observedPort;
      url = observationUrl;
    } else if (!Object.hasOwn(URLS, service) || observationUrl !== undefined) throw error('SERVICE_INVALID', '只允许已配置的官方网站', 400);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw error('PROXY_PORT_INVALID', '代理端口必须是 1024-65535 的整数', 400);
    try { if (typeof language !== 'string' || !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(language) || Intl.getCanonicalLocales(language)[0] !== language) throw new Error(); }
    catch { throw error('BROWSER_LANGUAGE_INVALID', '浏览器语言必须是有效的标准语言标记', 400); }
    let candidate = null;
    let runtime;
    if (browser === 'fingerprint') {
      runtime = await fingerprintState(false);
      if (!mock && runtime.state !== 'ready') throw error(runtime.errorCode || 'BROWSER_FINGERPRINT_NOT_INSTALLED', '指纹浏览器未安装或完整性校验失败，请先准备组件', 400);
      candidate = { id: browser, executable: runtime.executable || null };
    } else if (!mock) for (const item of await browserCandidates()) if (item.id === browser && await executableAvailable(item)) { candidate = item; break; }
    if (!mock && !candidate) throw error('BROWSER_UNAVAILABLE', '未找到受支持的浏览器', 400);
    if (freshId !== undefined && !validFreshId(freshId)) throw error('BROWSER_PLAN_INVALID', '纯净会话标识无效', 400);
    const id = fresh ? (freshId || randomUUID()) : null;
    const profile = profilePath(browser, id, workspaceId);
    if (!mock) await safePath(profile);
    const args = [
      `--user-data-dir=${profile}`, '--profile-directory=Default', '--no-first-run', '--no-default-browser-check', '--disable-background-mode',
      '--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp', '--webrtc-ip-handling-policy=disable_non_proxied_udp', `--lang=${language}`,
      `--proxy-server=http://127.0.0.1:${port}`, `--proxy-bypass-list=<-loopback>${observationPort ? `;127.0.0.1:${observationPort}` : ''}`,
    ];
    let fingerprint;
    if (browser === 'fingerprint') {
      try { if (typeof timezone !== 'string' || timezone.length > 100 || !/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+){0,2}$/.test(timezone)) throw new Error(); new Intl.DateTimeFormat('en-US', { timeZone: timezone }); }
      catch { throw error('BROWSER_FINGERPRINT_TIMEZONE_INVALID', '请选择有效的 IANA 时区', 400); }
      if (typeof nativeGraphics !== 'boolean') throw error('BROWSER_FINGERPRINT_GRAPHICS_INVALID', '图形设置必须是明确的开关', 400);
      const identity = await profileIdentity(profile, seed), resolvedPlatform = await platformVersion();
      if (!resolvedPlatform || !/^\d{1,5}\.\d{1,5}\.0$/.test(resolvedPlatform.version)) throw error('BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE', 'Windows UA-CH 平台版本不可用，未使用内核构建号替代');
      fingerprint = { seed: identity.seed, timezone, nativeGraphics, platform: 'windows', platformVersion: resolvedPlatform.version, platformVersionSource: resolvedPlatform.source, cores: identity.cores, engineVersion: runtime.version };
      args.push(`--fingerprint=${fingerprint.seed}`, '--fingerprint-platform=windows', `--fingerprint-platform-version=${fingerprint.platformVersion}`, '--fingerprint-brand=Chrome', `--fingerprint-brand-version=${runtime.version}`, `--fingerprint-hardware-concurrency=${fingerprint.cores}`, `--accept-lang=${[...new Set([language, language.split('-')[0]])].join(',')}`, `--timezone=${timezone}`, '--disable-non-proxied-udp', `--log-file=${path.join(profile, 'engine.log')}`, `--disable-spoofing=${nativeGraphics ? 'font,audio,gpu,canvas,clientrects' : 'font,audio,gpu'}`);
      // Retain the existing scoped rendering policy. The fixed component's
      // neighbour-row correction, not this switch, repairs the native readback
      // crash. Renderer sandboxing and native WebGL/GPU remain enabled.
      if (!nativeGraphics) args.push('--disable-accelerated-2d-canvas');
    }
    const urls = services ? services.map(service => URLS[service]) : [url];
    args.push(...urls);
    return { browserId: browser, label: labels[browser], executable: candidate?.executable || null, profile, args, url, language, port, service, webrtcPolicy: WEBRTC_POLICY, ...(workspaceId ? { workspaceId } : {}), ...(services ? { services, urls } : {}), ...(fresh ? { fresh: true, freshId: id } : {}), ...(observationPort ? { observationPort } : {}), ...(service === 'observation' ? { observationUrl } : {}), ...(fingerprint ? { fingerprint } : {}) };
  }

  async function spawnPlanned(input) {
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (/^(https?_proxy|all_proxy|no_proxy)$/i.test(key)) delete env[key];
    const child = spawnProcess(input.executable, input.args, { detached: true, windowsHide: false, stdio: 'ignore', env });
    try {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(error('BROWSER_LAUNCH_TIMEOUT', '浏览器启动未及时确认')), launchTimeoutMs);
        child.once('spawn', () => { clearTimeout(timer); resolve(); });
        child.once('error', () => { clearTimeout(timer); reject(error('BROWSER_LAUNCH_FAILED', '浏览器无法启动，请检查安装和运行权限')); });
      });
    } catch (cause) { child.unref(); throw cause; }
    return child;
  }

  async function launchInternal(input) {
    if (!input || typeof input !== 'object') throw error('BROWSER_PLAN_INVALID', '浏览器启动计划无效', 400);
    const canonical = await plan({ browser: input.browserId, service: input.service, services: input.services, workspaceId: input.workspaceId, port: input.port, language: input.language, fresh: input.fresh, freshId: input.freshId, observationUrl: input.observationUrl, observationPort: input.observationPort, timezone: input.fingerprint?.timezone, nativeGraphics: input.fingerprint?.nativeGraphics, seed: input.fingerprint?.seed });
    if (JSON.stringify(canonical) !== JSON.stringify(input)) throw error('BROWSER_PLAN_INVALID', '浏览器启动计划已改变，请重新生成', 400);
    if (mock) {
      if (!input.freshId && !input.workspaceId) profileArchivesStore.markMockCurrent(input.browserId);
      return { mode: 'mocked', launched: false, browser: input.browserId, url: input.url, ...(input.workspaceId ? { workspaceId: input.workspaceId, urls: input.urls || [input.url] } : {}) };
    }
    if (input.browserId === 'fingerprint') {
      const runtime = await fingerprintState(true);
      if (runtime.state !== 'ready' || normalize(runtime.executable || '') !== normalize(input.executable)) throw error(runtime.errorCode || 'BROWSER_FINGERPRINT_BINARY_CHANGED', '指纹浏览器组件已改变，请重新准备或生成计划');
    }
    await loadSession();
    const current = await statusInternal();
    if (current.running) {
      if (!input.workspaceId || session?.workspaceId !== input.workspaceId) throw error('BROWSER_ALREADY_RUNNING', '已有独立浏览器会话运行，请先安全结束');
      if (!current.managed || session.closing || !session.identity) throw error('BROWSER_SESSION_UNTRACKED', '工作区会话身份无法确认，请正常关闭窗口后重试');
      const args = input.args.slice(0, -(input.urls?.length || 1));
      if (JSON.stringify(session.workspaceArgs) !== JSON.stringify(args)) throw error('BROWSER_WORKSPACE_SESSION_CHANGED', '工作区的代理或浏览器环境已改变，请先正常结束再重新开始');
      const previous = session.identity, child = await spawnPlanned(input);
      child.unref();
      const live = await processes.inspectProcess(previous.pid);
      if (!live || !processes.sameProcess(previous, live)) throw error('BROWSER_SESSION_UNTRACKED', '追加网站时工作区会话已退出，请重新开始工作');
      return { mode: 'launched', launched: true, reused: true, browser: input.browserId, workspaceId: input.workspaceId, url: input.url, urls: input.urls || [input.url], language: input.language, port: input.port };
    }
    activeFreshId = input.freshId || null;
    activeWorkspaceId = input.workspaceId || null;
    try {
      await assertClosed(input.browserId);
      if (input.fresh && await exists(input.profile)) throw error('BROWSER_PLAN_INVALID', '纯净会话目录已存在，请重新生成计划', 400);
      if (input.fingerprint) {
        // Version 1's reader intentionally ignores additional fields. Keep that
        // rollback contract while preserving the per-profile CPU identity.
        await writeJson(path.join(input.profile, '.mc-fingerprint.json'), { version: 1, seed: input.fingerprint.seed, cores: input.fingerprint.cores });
        pendingSeeds.delete(input.profile);
      }
      await preparePreferences(input.browserId, input.language);
    }
    catch (cause) { activeFreshId = null; activeWorkspaceId = null; throw cause; }
    session = { version: 1, settingsVersion: 2, browser: input.browserId, profile: input.profile, language: input.language, port: input.port, startedAt: new Date().toISOString(), identity: null, browserArgs: input.args.slice(0, -(input.urls?.length || 1)), ...(input.workspaceId ? { workspaceId: input.workspaceId, workspaceArgs: input.args.slice(0, -(input.urls?.length || 1)) } : {}), ...(input.fingerprint ? { fingerprint: { ...input.fingerprint } } : {}), ...(input.observationPort ? { observationPort: input.observationPort } : {}), ...(input.fresh ? { freshId: input.freshId } : {}) };
    let child;
    try {
      session.launch = { version: 1, baselineEmpty: true, startedAt: new Date().toISOString(), executable: await realpath(input.executable), args: input.args, pid: null };
      await writeJson(manifestPath, session);
      child = await spawnPlanned(input);
      session.launch.pid = child.pid;
      await writeJson(manifestPath, session);
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const identity = await processes.inspectProcess(child.pid);
        session.identity = await launchedIdentity(identity ? [identity] : []);
        // Chromium can transfer a launch to a new root PID. Only the exact
        // executable, full planned command and this launch's empty baseline /
        // creation window can establish ownership; old unverified sessions do not.
        session.identity ||= await launchedIdentity(await processSnapshot(input.browserId));
        if (session.identity) break;
        await wait(100);
      }
      if (!session.identity) throw error('BROWSER_IDENTITY_UNVERIFIED', '无法确认独立浏览器进程身份，请保留代理并手动关闭窗口');
      await writeJson(manifestPath, session);
      child.unref();
      return { mode: 'launched', launched: true, browser: input.browserId, url: input.url, language: input.language, port: input.port, ...(input.workspaceId ? { workspaceId: input.workspaceId, urls: input.urls || [input.url] } : {}) };
    } catch (e) {
      child?.unref();
      // A started but unverified browser may still need its proxy. Never claim
      // it is closed or restore Preferences while a matching process exists.
      if (!(await profileProcesses(input.browserId)).length) await clearFinishedSession();
      await onFailure({ code: e.code?.startsWith('BROWSER_') ? e.code : 'BROWSER_LAUNCH_FAILED', browser: input.browserId });
      if (e.code?.startsWith('BROWSER_')) throw e;
      throw error('BROWSER_LAUNCH_FAILED', '浏览器启动失败，未启动其他浏览器');
    }
  }

  async function closeInternal() {
    if (mock) return { closed: false, running: false, mode: 'mocked', languageRestored: false };
    await loadSession();
    const settledRead = async read => {
      for (let attempt = 0; ; attempt++) {
        try { return await read(); }
        catch (cause) { if (cause.code !== 'PROCESS_UNREADABLE' || attempt === 3) throw cause; await wait(100); }
      }
    };
    // CIM may return a partial identity during normal Chromium teardown. A
    // short re-read avoids a false failure; persistently unknown stays blocked.
    const current = await settledRead(statusInternal);
    if (!current.running) return { closed: true, running: false, languageRestored: true };
    if (!session?.identity) throw error('BROWSER_SESSION_UNTRACKED', '此独立浏览器不属于可确认的受管会话，请在窗口内正常退出后重试');
    const snapshot = await settledRead(() => processSnapshot(session.browser));
    const rootRunning = identityPresent(session.identity, snapshot);
    if (rootRunning && (!current.managed || !commandUsesProfile(session.identity.commandLine, session.profile))) throw error('BROWSER_SESSION_UNTRACKED', '浏览器根身份归属无法确认，未关闭任何进程');
    if (!rootRunning && (await profileProcesses(session.browser, snapshot)).length) throw error('BROWSER_SESSION_UNTRACKED', '浏览器根进程身份已改变，未关闭其他进程');
    const owned = rootRunning ? await ownedProcessTree(session.identity, session.browser, snapshot)
      : session.ownedProcesses || [];
    session.ownedProcesses = owned; session.closing = true;
    await writeJson(manifestPath, session);
    try { if (rootRunning) await processes.closeBrowser(session.identity, { timeoutMs: closeTimeoutMs }); }
    catch (cause) {
      const code = ['PROCESS_UNREADABLE', 'PROCESS_IDENTITY_MISMATCH', 'PROCESS_QUERY_FAILED'].includes(cause?.code) ? cause.code : 'BROWSER_CLOSE_TIMEOUT';
      await onFailure({ code, browser: session.browser });
      throw error(code, '浏览器尚未确认安全退出；请正常关闭窗口后重试，恢复记录和代理保持运行');
    }
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const snapshot = await settledRead(() => processSnapshot(session.browser));
      const stillOwned = owned.some(identity => identityPresent(identity, snapshot));
      const uncertain = await unconfirmedChildren(snapshot);
      if (!stillOwned && !uncertain && !(await profileProcesses(session.browser, snapshot)).length) { await clearFinishedSession(); return { closed: true, running: false, languageRestored: true }; }
      await wait(100);
    }
    // A closed Chromium root may leave a windowless utility/crash process.
    // Retry can finish these exact recorded identities, never a name/PID tree.
    if (processes.stopBackgroundBrowser) {
      const snapshot = await settledRead(() => processSnapshot(session.browser));
      if (!identityPresent(session.identity, snapshot) && !(await profileProcesses(session.browser, snapshot)).length) {
        for (const identity of [...owned].reverse()) if (identityPresent(identity, snapshot)) {
          try { await processes.stopBackgroundBrowser(identity, { timeoutMs: Math.min(closeTimeoutMs, 5000) }); }
          catch (cause) {
            const code = ['PROCESS_UNREADABLE', 'PROCESS_IDENTITY_MISMATCH', 'PROCESS_QUERY_FAILED'].includes(cause?.code) ? cause.code : 'BROWSER_CLOSE_TIMEOUT';
            await onFailure({ code, browser: session.browser });
            throw error(code, '浏览器仍有窗口或进程身份无法确认；恢复记录和代理保持运行');
          }
        }
        const finished = await settledRead(() => processSnapshot(session.browser));
        if (!owned.some(identity => identityPresent(identity, finished)) && !await unconfirmedChildren(finished) && !(await profileProcesses(session.browser, finished)).length) {
          await clearFinishedSession(); return { closed: true, running: false, languageRestored: true };
        }
      }
    }
    throw error('BROWSER_CLOSE_TIMEOUT', '浏览器子进程尚未退出，代理保持运行');
  }

  async function cleanupPreview({ browser = 'chrome', items } = {}) {
    validateBrowser(browser);
    if (!Array.isArray(items) || !items.length || items.some(item => !['browserCache', 'browserCookies'].includes(item))) throw error('CLEANUP_SCOPE_INVALID', '仅支持独立浏览器缓存和 Cookie 清理', 400);
    const requested = [...new Set(items)];
    if (!mock) await assertClosed(browser);
    const profiles = [{ path: profilePath(browser, null), label: `独立 ${labels[browser]}` }];
    if (!mock) {
      const freshRoot = path.join(profileRoot, 'fresh', browser);
      await safePath(freshRoot);
      if (await exists(freshRoot)) for (const entry of await readdir(freshRoot, { withFileTypes: true })) {
        if (!validFreshId(entry.name)) throw error('BROWSER_PATH_UNSAFE', '纯净浏览器目录含非预期项目');
        const freshPath = path.join(freshRoot, entry.name);
        await safePath(freshPath);
        profiles.push({ path: freshPath, label: `纯净 ${labels[browser]}/${entry.name}` });
      }
      const running = await processSnapshot(browser);
      if (profiles.some(profile => running.some(item => commandUsesProfile(item.commandLine, profile.path)))) throw error('BROWSER_ALREADY_RUNNING', '清理范围内有浏览器运行，请先关闭');
    }
    const targets = [];
    for (const profile of profiles) {
    const directories = mock ? ['Default'] : await profileDirectories(browser, { profile: profile.path });
    for (const directory of directories) for (const item of requested) for (const relative of item === 'browserCache' ? CACHE_PATHS : COOKIE_PATHS) {
      const target = path.join(profile.path, directory, ...relative.split('/'));
      let stat = null;
      if (!mock) { await safePath(target); try { stat = await lstat(target); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
      const type = item === 'browserCache' ? 'directory' : 'file';
      if (stat && (type === 'directory' ? !stat.isDirectory() : !stat.isFile())) throw error('BROWSER_PATH_UNSAFE', '缓存或 Cookie 路径类型异常');
      targets.push({ path: target, displayPath: `${profile.label}/${directory}/${relative}`, item, type, exists: !!stat });
    }
    }
    return { browser, requested, targets, mode: mock ? 'mocked' : 'preview', preserves: ['书签', '密码', '本地存储', '主浏览器数据'] };
  }

  async function cleanupApplyInternal(input) {
    if (!input || typeof input !== 'object') throw error('CLEANUP_PLAN_INVALID', '清理计划无效', 400);
    const fresh = await cleanupPreview({ browser: input.browser, items: input.requested });
    const requestedTargets = input.targets;
    if (!Array.isArray(requestedTargets) || requestedTargets.length !== fresh.targets.length || requestedTargets.some((target, i) => target.path !== fresh.targets[i].path || target.item !== fresh.targets[i].item || target.type !== fresh.targets[i].type)) throw error('CLEANUP_PLAN_INVALID', '清理范围已改变，请重新预览', 400);
    if (mock) return { mode: 'mocked', deleted: 0, browser: input.browser };
    // Validate every target before touching the first one, including descendants.
    for (const target of fresh.targets) await safePath(target.path, { tree: target.type === 'directory' });
    await assertClosed(input.browser);
    // Check every past fresh profile again after the potentially slow tree scan.
    await cleanupPreview({ browser: input.browser, items: input.requested });
    let deleted = 0;
    for (const target of fresh.targets) {
      await safePath(target.path, { tree: target.type === 'directory' });
      await rm(target.path, { recursive: target.type === 'directory', force: true });
      if (target.exists) deleted += 1;
    }
    return { mode: 'applied', deleted, browser: input.browser, preservedProfile: true };
  }

  async function openObservation({ observationUrl, workspaceId, port } = {}) {
    const observedPort = validateObservationUrl(observationUrl);
    if (!validPort(port)) throw error('PROXY_PORT_INVALID', '代理端口必须是 1024-65535 的整数', 400);
    if (workspaceId !== undefined && !validBrowserWorkspaceId(workspaceId)) throw error('BROWSER_WORKSPACE_INVALID', '请选择有效的用户环境', 400);
    const current = await statusInternal();
    if (!current.running) throw error('BROWSER_OBSERVATION_NOT_RUNNING', '请先打开要检测的用户环境');
    if (!current.managed || !session?.identity || session.closing) throw error('BROWSER_SESSION_UNTRACKED', '当前浏览器归属无法确认，未在其他浏览器中检测');
    if ((session.workspaceId || undefined) !== workspaceId || session.port !== port) throw error('BROWSER_OBSERVATION_SESSION_CHANGED', '当前用户环境或代理线路已改变，请重新选择检测目标');
    if (session.observationPort !== observedPort || !Array.isArray(session.browserArgs)) throw error('BROWSER_OBSERVATION_RESTART_REQUIRED', '当前窗口尚未启用本机检测入口，请先正常关闭并重新打开此用户环境');
    const planned = await plan({ browser: session.browser, service: 'observation', workspaceId, port, language: session.language, fresh: Boolean(session.freshId), freshId: session.freshId, observationUrl, observationPort: observedPort, timezone: session.fingerprint?.timezone, nativeGraphics: session.fingerprint?.nativeGraphics, seed: session.fingerprint?.seed });
    if (normalize(planned.profile) !== normalize(session.profile) || normalize(planned.executable) !== normalize(session.identity.executable)
      || JSON.stringify(planned.args.slice(0, -1)) !== JSON.stringify(session.browserArgs)) throw error('BROWSER_OBSERVATION_SESSION_CHANGED', '当前浏览器身份设置已改变，请先正常结束再重新打开');
    if (session.browser === 'fingerprint') {
      const runtime = await fingerprintState(true);
      if (runtime.state !== 'ready' || normalize(runtime.executable || '') !== normalize(planned.executable)) throw error(runtime.errorCode || 'BROWSER_FINGERPRINT_BINARY_CHANGED', '当前指纹内核完整性无法确认，未追加检测页面');
    }
    const previous = session.identity;
    const before = await processes.inspectProcess(previous.pid);
    if (!before || !processes.sameProcess(previous, before)) throw error('BROWSER_SESSION_UNTRACKED', '打开检测页面前受管浏览器已退出，请重新打开');
    const child = await spawnPlanned(planned); child.unref();
    const after = await processes.inspectProcess(previous.pid);
    if (!after || !processes.sameProcess(previous, after)) throw error('BROWSER_SESSION_UNTRACKED', '打开检测页面时受管浏览器已退出，请重新打开');
    return { mode: 'appended', launched: true, reused: true, browser: session.browser, ...(workspaceId ? { workspaceId } : {}), port, observationPort: observedPort, observationUrl, language: session.language, ...(session.fingerprint ? { fingerprint: { ...session.fingerprint } } : {}) };
  }

  async function rotateFingerprint({ confirm, workspaceId } = {}) {
    if (confirm !== true) throw error('CONFIRMATION_REQUIRED', '换种子需要明确确认', 400);
    validateBrowser('fingerprint');
    if (workspaceId !== undefined && !validBrowserWorkspaceId(workspaceId)) throw error('BROWSER_WORKSPACE_INVALID', '请选择有效的用户环境', 400);
    const current = await statusInternal();
    if (current.running && current.browser !== 'fingerprint') throw error('BROWSER_ALREADY_RUNNING', '请先安全结束当前独立浏览器，再调整指纹空间');
    if (current.running && workspaceId !== undefined && workspaceId !== activeWorkspaceId) throw error('BROWSER_ALREADY_RUNNING', '其他用户环境仍在运行，请先正常结束，未轮换任何身份');
    if (current.running && activeFreshId) throw error('BROWSER_FINGERPRINT_FRESH_ROTATION_UNSUPPORTED', '纯净空间本身使用新身份；轮换种子请切换到保留资料模式，当前窗口保持运行', 400);
    const freshId = activeFreshId;
    const targetWorkspaceId = workspaceId || activeWorkspaceId;
    const profile = profilePath('fingerprint', freshId, targetWorkspaceId);
    if (current.running) await closeInternal();
    if (!mock) {
      await safePath(profile);
      const snapshot = await processSnapshot('fingerprint');
      if (snapshot.some(item => commandUsesProfile(item.commandLine, profile))) throw error('BROWSER_ALREADY_RUNNING', '目标用户环境仍有未接管的浏览器进程，请先正常关闭');
      await assertClosed('fingerprint');
    }
    const old = await profileIdentity(profile);
    let seed; do { seed = randomInt(1, 4294967296); } while (seed === old.seed);
    if (!mock) await writeJson(path.join(profile, '.mc-fingerprint.json'), { version: 1, seed, cores: old.cores });
    pendingSeeds.set(profile, { seed, cores: old.cores });
    return { changed: !mock, seed, freshId: freshId || null, profile, ...(targetWorkspaceId ? { workspaceId: targetWorkspaceId } : {}), preserves: ['Cookie', '登录状态', '代理线路', '授权设备'], mode: mock ? 'mocked' : 'applied' };
  }
  async function assertProfileOperationsClosed() {
    if (mock) return;
    await loadSession();
    for (const browser of Object.keys(labels)) {
      const snapshot = await processSnapshot(browser);
      const inManagedRoot = snapshot.some(item => {
        const args = splitWindowsCommandLine(item.commandLine);
        const directories = [];
        for (let index = 0; index < args.length; index++) {
          if (args[index] === '--user-data-dir') directories.push(args[++index]);
          else if (args[index].startsWith('--user-data-dir=')) directories.push(args[index].slice('--user-data-dir='.length));
        }
        return directories.some(directory => typeof directory === 'string' && (normalize(directory) === normalize(profileRoot) || normalize(directory).startsWith(normalize(profileRoot) + path.sep)));
      });
      if (inManagedRoot || session?.browser === browser && ((session.ownedProcesses || []).some(identity => identityPresent(identity, snapshot)) || await unconfirmedChildren(snapshot))) throw error('BROWSER_ALREADY_RUNNING', '受管浏览器仍在运行，请先正常关闭所有独立浏览器窗口，原资料未移动');
    }
  }

  const profileArchivesStore = createBrowserProfileArchives({ profileRoot, browsers: Object.keys(labels), safePath, readJson, writeJson,
    assertClosed: assertProfileOperationsClosed, beforeChange: prepareProfileChange, mock, onChanged: browser => { pendingSeeds.delete(profilePath(browser, null)); },
  });
  async function prepareProfileChange() {
    const current = await statusInternal({ inspectMissingProfiles: true });
    if (current.running) throw error('BROWSER_ALREADY_RUNNING', '请先正常关闭受管浏览器，原资料未移动');
    await assertProfileOperationsClosed();
  }
  return { listBrowsers, fingerprintStatus: async () => { const { executable: _executable, ...runtime } = await fingerprintState(false); return runtime; }, openObservation: value => locked(() => openObservation(value)), rotateFingerprint: value => locked(() => rotateFingerprint(value)), rescan: () => locked(rescan), setExecutable: value => locked(() => setExecutable(value)), plan: value => locked(() => plan(value)), launch: value => locked(() => launchInternal(value)), status: () => locked(statusInternal), close: () => locked(closeInternal), cleanupPreview: value => locked(() => cleanupPreview(value)), cleanupApply: value => locked(() => cleanupApplyInternal(value)),
    profileArchives: value => locked(() => profileArchivesStore.list(value)),
    refreshProfile: value => locked(() => profileArchivesStore.refresh(value)),
    restoreProfile: value => locked(() => profileArchivesStore.restore(value)),
  };
}
