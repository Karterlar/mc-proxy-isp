import path from 'node:path';
import { lstat, realpath, readdir } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { createWindowsProcessTools, sameProcess } from '../backend/src/windows-process.mjs';
import { CONTROL_ERROR_CODES } from '../backend/src/local-controller.mjs';

const runFile = promisify(execFile);
const targets = Object.freeze({ 'claude-desktop': 'Claude Desktop', 'claude-code': 'Claude Code', 'codex-desktop': 'Codex Desktop', 'codex-cli': 'Codex CLI', terminal: '代理终端' });
const fail = (code, message) => Object.assign(new Error(message), { code });
const controllerErrors = new Set(CONTROL_ERROR_CODES);
const quote = value => `'${String(value).replaceAll("'", "''")}'`;
const systemVerified = proxy => proxy?.exitStatus === 'verified' && proxy.coverage?.mode === 'tun' && proxy.coverage.systemExitVerified === true;
const leaseIdentity = proxy => typeof proxy?.binding === 'string' && /^[a-f0-9]{64}$/.test(proxy.binding)
  && Number.isSafeInteger(proxy.revision) && proxy.revision >= 0 && Number.isInteger(proxy.corePort) && proxy.corePort >= 1024 && proxy.corePort <= 65535
  ? { binding: proxy.binding, revision: proxy.revision, corePort: proxy.corePort, url: proxy.url } : null;

export function proxyEnvironment(environment, url) {
  const match = typeof url === 'string' ? /^http:\/\/127\.0\.0\.1:([1-9]\d{0,4})$/.exec(url) : null;
  const port = Number(match?.[1]);
  if (!match || port < 1024 || port > 65535) throw fail('APPLICATION_PROXY_INVALID', '本地代理地址无效。');
  const result = { ...environment };
  for (const key of Object.keys(result)) if (/^(https?_proxy|all_proxy|no_proxy|node_options|node_use_env_proxy|electron_run_as_node)$/i.test(key)) delete result[key];
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) result[key] = url;
  // SDKs disagree on wildcard/CIDR NO_PROXY. Private-network routing is enforced
  // by the managed HTTP proxy; only standard local names bypass it here.
  result.NO_PROXY = result.no_proxy = 'localhost,127.0.0.1,::1,.localhost,.local,.lan';
  result.NODE_USE_ENV_PROXY = '1';
  return result;
}

export function createApplicationManager({ applicationProxy, mock = false, environment = process.env, platform = process.platform, run = runFile, launch = spawn, stat = lstat, canonical = realpath, list = readdir, processTools = createWindowsProcessTools({ platform }), launchTimeoutMs = 5000 } = {}) {
  if (!Number.isInteger(launchTimeoutMs) || launchTimeoutMs <= 0 || launchTimeoutMs > 60_000) throw fail('APPLICATION_TARGET_INVALID', '应用启动超时设置无效。');
  const windows = path.win32;
  const ps = windows.join(environment.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  let binaries = new Map(), desktopProcesses = new Map();
  let serial = Promise.resolve();
  const locked = action => { const next = serial.then(action, action); serial = next.catch(() => {}); return next; };
  async function binary(candidate) {
    try {
      if (!windows.isAbsolute(candidate) || candidate.startsWith('\\\\') || !/\.(exe|cmd)$/i.test(candidate)) return null;
      const info = await stat(candidate);
      if (!info.isFile() || info.isSymbolicLink()) return null;
      const resolved = await canonical(candidate);
      return { path: resolved, size: info.size, mtimeMs: info.mtimeMs };
    } catch { return null; }
  }
  async function versioned(directory, name) {
    try { return (await list(directory, { withFileTypes: true })).filter(entry => entry.isDirectory() && !entry.isSymbolicLink()).sort((a, b) => b.name.localeCompare(a.name, undefined, { numeric: true })).slice(0, 16).map(entry => windows.join(directory, entry.name, name)); }
    catch { return []; }
  }
  const samePath = (left, right) => typeof left === 'string' && typeof right === 'string' && windows.normalize(left).toLowerCase() === windows.normalize(right).toLowerCase();
  const isCli = (entry, family) => samePath(entry.Path, binaries.get(family === 'claude' ? 'claude-code' : 'codex-cli')?.path) || typeof entry.Path === 'string' && (/claude-code[\\/]|[\\/]\.local[\\/]bin[\\/]claude\.exe$|[\\/]npm[\\/]/i.test(entry.Path) && family === 'claude' || /[\\/]Codex[\\/]bin[\\/]|[\\/]npm[\\/]/i.test(entry.Path) && family === 'codex');
  const isDesktop = (entry, family) => {
    if (isCli(entry, family)) return false;
    if (family === 'claude') return entry.ProcessName.toLowerCase().includes('claude');
    const name = entry.ProcessName.toLowerCase();
    if (name === 'codex') return true;
    return name === 'chatgpt' && typeof entry.Path === 'string' && (/\\WindowsApps\\OpenAI\.Codex_/i.test(entry.Path) || samePath(entry.Path, binaries.get('codex-desktop')?.path));
  };
  async function processSnapshot() {
    try {
      // Missing names are a successful empty snapshot, not a native query error.
      const command = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); $items=@(Get-Process -ErrorAction Stop | Where-Object {$_.ProcessName -match 'claude|codex|^ChatGPT$'}); $entries=@($items | ForEach-Object { $location=$null; try { $location=$_.Path } catch {}; [pscustomobject]@{ProcessName=[string]$_.ProcessName;Id=[int]$_.Id;Path=$location} }); ConvertTo-Json -InputObject $entries -Compress";
      const { stdout } = await run(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command], { timeout: 4000, maxBuffer: 65536, windowsHide: true });
      const data = JSON.parse(stdout.replace(/^\uFEFF/, '').trim()), entries = Array.isArray(data) ? data : [data];
      if (entries.length > 256 || entries.some(entry => !entry || typeof entry.ProcessName !== 'string' || !Number.isSafeInteger(entry.Id) || entry.Id <= 0 || entry.Id > 0xffffffff)) throw new Error('Invalid process metadata');
      return { processes: entries, processStatus: 'observed' };
    } catch { return { processes: [], processStatus: 'unknown' }; }
  }
  async function assertDesktopStillIdle(id) {
    const { processes, processStatus } = await processSnapshot(), family = id.startsWith('claude') ? 'claude' : 'codex';
    if (processStatus !== 'observed' || family === 'codex' && processes.some(entry => entry.ProcessName.toLowerCase() === 'chatgpt' && typeof entry.Path !== 'string')) throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法确认桌面应用是否仍在运行。请自行检查并完整退出后刷新列表；未启动新进程。');
    if (processes.some(entry => isDesktop(entry, family))) throw fail('APPLICATION_RESTART_REQUIRED', '桌面应用正在运行。请自行完整退出后再从这里启动；已有进程不能继承新代理设置。也可使用已核验的全局 TUN。');
  }
  async function discover() {
    if (mock) return { mock: true, processStatus: 'simulated', applications: Object.entries(targets).map(([id, label]) => ({ id, label, kind: id.endsWith('-desktop') ? 'desktop' : id === 'terminal' ? 'terminal' : 'cli', installed: true, launchable: true, running: id === 'codex-cli' ? 1 : 0, blockedReason: null, stoppable: false, stopBlockedReason: id.endsWith('-desktop') ? 'not-running' : 'close-manually' })) };
    if (platform !== 'win32') return { mock: false, processStatus: 'unknown', applications: Object.entries(targets).map(([id, label]) => ({ id, label, kind: id.endsWith('-desktop') ? 'desktop' : id === 'terminal' ? 'terminal' : 'cli', installed: false, launchable: false, running: 0, blockedReason: 'platform-unsupported', stoppable: false, stopBlockedReason: 'platform-unsupported' })) };
    const local = environment.LOCALAPPDATA || '', roaming = environment.APPDATA || '', home = environment.USERPROFILE || '';
    const claude = [windows.join(home, '.local', 'bin', 'claude.exe'), windows.join(roaming, 'npm', 'claude.cmd')];
    const codex = [windows.join(roaming, 'npm', 'codex.cmd')];
    for (const area of ['Claude', 'Claude-3p']) claude.push(...await versioned(windows.join(local, area, 'claude-code'), 'claude.exe'));
    codex.push(...await versioned(windows.join(local, 'OpenAI', 'Codex', 'bin'), 'codex.exe'));
    for (const [name, candidates] of [['claude', claude], ['codex', codex]]) {
      try { const { stdout } = await run(windows.join(environment.SystemRoot || 'C:\\Windows', 'System32', 'where.exe'), [name], { timeout: 3000, maxBuffer: 32768, windowsHide: true }); candidates.push(...stdout.trim().split(/\r?\n/).slice(0, 16)); } catch {}
    }
    binaries = new Map();
    for (const [id, candidates] of [['claude-code', claude], ['codex-cli', codex]]) for (const candidate of candidates) { const found = await binary(candidate); if (found) { binaries.set(id, found); break; } }
    const { processes, processStatus } = await processSnapshot();
    const desktopCandidates = {
      'claude-desktop': [windows.join(local, 'Programs', 'Claude', 'Claude.exe'), windows.join(local, 'AnthropicClaude', 'Claude.exe'), ...await versioned(windows.join(local, 'AnthropicClaude'), 'Claude.exe')],
      'codex-desktop': [windows.join(local, 'Programs', 'Codex', 'ChatGPT.exe'), windows.join(local, 'Programs', 'Codex', 'Codex.exe'), windows.join(local, 'OpenAI', 'Codex', 'app', 'ChatGPT.exe'), windows.join(local, 'OpenAI', 'Codex', 'Codex.exe')],
    };
    try {
      const { stdout } = await run(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', "Get-AppxPackage | Where-Object {$_.Name -match '^(Claude|AnthropicClaude|OpenAI\\.Codex)$'} | Select-Object Name,InstallLocation | ConvertTo-Json -Compress"], { timeout: 5000, maxBuffer: 32768, windowsHide: true });
      const packages = stdout.trim() ? JSON.parse(stdout.replace(/^\uFEFF/, '').trim()) : [];
      for (const item of (Array.isArray(packages) ? packages : [packages]).slice(0, 8)) {
        if (!item || typeof item.InstallLocation !== 'string' || !['Claude', 'AnthropicClaude', 'OpenAI.Codex'].includes(item.Name)) continue;
        const location = item.InstallLocation;
        if (item.Name === 'OpenAI.Codex') desktopCandidates['codex-desktop'].unshift(windows.join(location, 'app', 'ChatGPT.exe'), windows.join(location, 'app', 'Codex.exe'));
        else desktopCandidates['claude-desktop'].push(windows.join(location, 'app', 'claude.exe'), windows.join(location, 'claude.exe'));
      }
    } catch {}
    for (const [id, candidates] of Object.entries(desktopCandidates)) for (const candidate of candidates) { const found = await binary(candidate); if (found) { binaries.set(id, found); break; } }
    desktopProcesses = new Map();
    const applications = Object.entries(targets).map(([id, label]) => {
      const kind = id.endsWith('-desktop') ? 'desktop' : id === 'terminal' ? 'terminal' : 'cli', family = id.startsWith('claude') ? 'claude' : 'codex';
      const matched = kind === 'terminal' ? [] : processes.filter(entry => kind === 'desktop' ? isDesktop(entry, family) : entry.ProcessName.toLowerCase() === family && isCli(entry, family));
      if (kind === 'desktop') desktopProcesses.set(id, matched);
      const running = matched.length;
      const installed = kind === 'terminal' || binaries.has(id) || kind === 'desktop' && running > 0;
      // An unreadable ChatGPT path may belong to this Codex package. Never try
      // another startup against a potentially running single-instance profile.
      const unknown = kind === 'desktop' && (processStatus !== 'observed' || family === 'codex' && binaries.has(id) && processes.some(entry => entry.ProcessName.toLowerCase() === 'chatgpt' && typeof entry.Path !== 'string'));
      const blockedReason = !installed ? 'not-installed' : kind === 'desktop' && running ? 'running-requires-restart' : unknown ? 'process-state-unknown' : !binaries.has(id) && kind !== 'terminal' ? 'not-installed' : null;
      const stopBlockedReason = kind !== 'desktop' ? 'close-manually' : unknown ? 'process-state-unknown' : !running ? 'not-running'
        : !binaries.has(id) || matched.some(entry => !samePath(entry.Path, binaries.get(id).path)) ? 'process-identity-unverified' : null;
      return { id, label, kind, installed, running, launchable: blockedReason === null, blockedReason, stoppable: stopBlockedReason === null, stopBlockedReason };
    });
    return { mock: false, processStatus, applications };
  }
  function assertDesktopIdle(inventory, id) {
    const target = inventory.applications.find(entry => entry.id === id);
    if (target?.blockedReason === 'running-requires-restart') throw fail('APPLICATION_RESTART_REQUIRED', '桌面应用正在运行。请自行完整退出后再从这里启动；已有进程不能继承新代理设置。也可使用已核验的全局 TUN。');
    if (target?.blockedReason === 'process-state-unknown') throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法确认桌面应用是否仍在运行。请自行检查并完整退出后刷新列表；未启动新进程。');
  }
  async function start(id) {
    if (typeof id !== 'string' || !Object.hasOwn(targets, id)) throw fail('APPLICATION_TARGET_INVALID', '应用启动目标无效。');
    if (!mock && platform !== 'win32') throw fail('APPLICATION_PLATFORM_UNSUPPORTED', '专用终端目前仅支持 Windows。');
    const inventory = await discover();
    const selected = binaries.get(id);
    const desktop = id.endsWith('-desktop');
    if (!mock && desktop) assertDesktopIdle(inventory, id);
    if (!mock && id !== 'terminal' && !selected) throw fail('APPLICATION_NOT_INSTALLED', '未找到此应用的可执行程序。请先安装，再刷新应用列表。');
    if (typeof applicationProxy !== 'function') throw fail('APPLICATION_PROXY_UNVERIFIED', '代理出口尚未通过核验，未启动应用。');
    if (!mock && desktop) await assertDesktopStillIdle(id);
    if (selected) { const current = await binary(selected.path); if (!current || current.path !== selected.path || current.size !== selected.size || current.mtimeMs !== selected.mtimeMs) throw fail('APPLICATION_BINARY_CHANGED', '应用程序已变化，请刷新列表后重试。'); }
    // Business HTTP diagnostics are user initiated through the controller.
    // Authorize once, after all local discovery; no external HEAD request or
    // further asynchronous inventory can make this final TUN lease stale.
    let proxy;
    try { proxy = await applicationProxy(id); }
    catch (cause) {
      if (controllerErrors.has(cause?.code)) throw fail(cause.code, '启动前的连接核验未完成，应用未启动。请查看连接状态与诊断记录。');
      throw fail(id === 'terminal' ? 'APPLICATION_PROXY_UNVERIFIED' : 'APPLICATION_SYSTEM_PROTECTION_REQUIRED', '当前代理会话无法核验，未启动应用。请重新连接并核验当前系统出口。');
    }
    if (mock) return { started: true, mock: true, id };
    if (proxy?.exitStatus !== 'verified') throw fail('APPLICATION_PROXY_UNVERIFIED', '代理出口尚未通过核验，未启动应用。');
    if (id !== 'terminal' && !systemVerified(proxy)) throw fail('APPLICATION_SYSTEM_PROTECTION_REQUIRED', '应用登录会打开系统默认浏览器。请先连接全局 TUN 并核验当前系统出口，再启动应用；断网锁可选。');
    const lease = id === 'terminal' ? null : leaseIdentity(proxy);
    if (id !== 'terminal' && !lease) throw fail('APPLICATION_PROXY_UNVERIFIED', '代理会话身份尚未通过核验，未启动应用。');
    const launchUrl = lease?.url ?? proxy.url;
    const childEnv = proxyEnvironment(environment, launchUrl);
    const coverageMessage = id === 'terminal' ? '不要在应用分流模式下发起网页登录：默认浏览器可能使用真实公网出口。' : '当前全局 TUN 出口已核验；断网锁可选，未开启时断线可能恢复直连。';
    const script = `$Host.UI.RawUI.WindowTitle = ${quote(`MC Proxy · ${targets[id]}`)}\nWrite-Host ${quote('此终端仅配置 MC Proxy HTTP 代理；它不保证所有程序或系统浏览器走代理。')}\nWrite-Host ${quote(coverageMessage)}\nWrite-Host ${quote('关闭此终端清除它的代理环境；断开 MC Proxy 会停止本地代理。')}\n${id === 'terminal' ? '' : `& ${quote(selected.path)}\n`}`;
    if (!desktop) {
      // A detached process with NUL stdio is unsuitable for an interactive CLI.
      // Start-Process gives the new terminal its own console and inherited env.
      const encoded = Buffer.from(script, 'utf16le').toString('base64');
      const helper = `$ErrorActionPreference='Stop'; Start-Process -FilePath ${quote(ps)} -WindowStyle Normal -ArgumentList @('-NoLogo','-NoProfile','-NoExit','-EncodedCommand',${quote(encoded)})`;
      try { await run(ps, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(helper, 'utf16le').toString('base64')], { env: childEnv, timeout: 5000, maxBuffer: 32768, windowsHide: true }); }
      catch { throw fail('APPLICATION_LAUNCH_FAILED', '专用终端未能启动。'); }
      return { started: true, mock: false, id };
    }
    let child;
    try {
      child = launch(selected.path, [`--proxy-server=${launchUrl}`, '--proxy-bypass-list=localhost;127.0.0.1;[::1]', '--disable-quic'], { env: childEnv, detached: true, stdio: 'ignore', windowsHide: false });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(fail('APPLICATION_LAUNCH_TIMEOUT', '尚未确认应用启动，请检查是否已有窗口。')), launchTimeoutMs);
        child.once('spawn', () => { clearTimeout(timer); resolve(); });
        child.once('error', () => { clearTimeout(timer); reject(fail('APPLICATION_LAUNCH_FAILED', '应用未能启动。')); });
      });
    } catch (cause) {
      if (cause.code === 'APPLICATION_LAUNCH_TIMEOUT') throw cause;
      throw fail('APPLICATION_LAUNCH_FAILED', '应用未能启动。');
    } finally { child?.unref?.(); }
    return { started: true, mock: false, id };
  }
  async function stop(id) {
    if (typeof id !== 'string' || !Object.hasOwn(targets, id)) throw fail('APPLICATION_TARGET_INVALID', '应用退出目标无效。');
    if (mock) return { stopped: true, mock: true, id };
    if (platform !== 'win32') throw fail('APPLICATION_PLATFORM_UNSUPPORTED', '应用退出入口目前仅支持 Windows。');
    // Existing CLI consoles have no owned window identity. Never close a user's
    // terminal, including this Codex session, by process name or parent tree.
    if (!id.endsWith('-desktop')) throw fail('APPLICATION_CLOSE_MANUALLY', '请在此应用自己的终端结束任务并关闭窗口；未结束任何现有 CLI 进程。');
    const inventory = await discover(), target = inventory.applications.find(entry => entry.id === id);
    if (target.stopBlockedReason === 'process-state-unknown') throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法确认应用进程身份，请手动检查后刷新。');
    if (!target.running) return { stopped: true, alreadyExited: true, mock: false, id };
    if (!target.stoppable) throw fail('APPLICATION_PROCESS_IDENTITY_CHANGED', '应用进程身份无法确认，未关闭任何窗口。请手动退出后刷新。');
    const selected = binaries.get(id), observed = desktopProcesses.get(id);
    let identities;
    try { identities = await processTools.listProcesses(windows.basename(selected.path)); }
    catch { throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法安全读取应用进程身份，未关闭任何窗口。'); }
    if (!Array.isArray(identities) || identities.length > 256) throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法安全读取应用进程身份，未关闭任何窗口。');
    const matched = identities.filter(item => item && typeof item.executable === 'string' && windows.normalize(item.executable).toLowerCase() === windows.normalize(selected.path).toLowerCase());
    if (matched.some(item => !sameProcess(item, item) || item.pid > 0xffffffff || !item.commandLine || !Number.isSafeInteger(item.parentPid) || item.parentPid < 0 || item.parentPid > 0xffffffff)
      || new Set(matched.map(item => item.pid)).size !== matched.length || observed.some(entry => !matched.some(item => item.pid === entry.Id))) throw fail('APPLICATION_PROCESS_IDENTITY_CHANGED', '应用进程身份已变化，未关闭任何窗口。请刷新后重试。');
    const roots = matched.filter(item => !matched.some(parent => parent.pid === item.parentPid));
    if (!roots.length || roots.length > 8) throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法安全确认应用主窗口，未关闭任何窗口。');
    // Validate every root before posting any close request. The process helper
    // rechecks identity while holding its handle and never force-kills here.
    try {
      for (const identity of roots) if (!sameProcess(identity, await processTools.inspectProcess(identity.pid))) throw fail('APPLICATION_PROCESS_IDENTITY_CHANGED', '应用进程身份已变化，未关闭任何窗口。请刷新后重试。');
    } catch (cause) {
      if (cause.code === 'APPLICATION_PROCESS_IDENTITY_CHANGED') throw cause;
      throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '无法安全确认应用主窗口，未关闭任何窗口。');
    }
    const results = await Promise.allSettled(roots.map(identity => processTools.stopProcess(identity, { graceful: true, timeoutMs: 5000 })));
    const failed = results.find(result => result.status === 'rejected');
    if (failed) {
      if (failed.reason?.code === 'BROWSER_CLOSE_TIMEOUT') throw fail('APPLICATION_CLOSE_TIMEOUT', '应用尚未关闭。请完成未保存内容或确认提示后重试；未强制结束应用。');
      if (failed.reason?.code === 'PROCESS_IDENTITY_MISMATCH') throw fail('APPLICATION_PROCESS_IDENTITY_CHANGED', '应用进程身份已变化，未强制结束应用。请刷新后重试。');
      throw fail('APPLICATION_CLOSE_FAILED', '应用未能正常关闭，请手动完成退出后刷新；未强制结束应用。');
    }
    const after = await discover(), remaining = after.applications.find(entry => entry.id === id);
    if (after.processStatus !== 'observed') throw fail('APPLICATION_PROCESS_STATE_UNKNOWN', '已请求正常关闭，但无法确认退出状态，请手动检查后刷新。');
    if (remaining.running) throw fail('APPLICATION_CLOSE_TIMEOUT', '应用仍在运行。请完成未保存内容或确认提示后重试；未强制结束应用。');
    return { stopped: true, mock: false, id };
  }
  return { discover: () => locked(discover), start: id => locked(() => start(id)), stop: id => locked(() => stop(id)),
    // Trusted main-process integration only; executable paths never enter the
    // public inventory. Generic node.exe is not treated as a particular CLI.
    routingPaths: () => locked(async () => {
      if (mock || platform !== 'win32') return [];
      await discover();
      return [...new Set([...binaries.values()].map(value => value.path).filter(value => /^[A-Za-z]:[\\/]/.test(value) && /\.exe$/i.test(value)))].slice(0, 16);
    }),
  };
}
