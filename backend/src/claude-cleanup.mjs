import os from 'node:os';
import path from 'node:path';
import { execFile as nodeExecFile } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { UserError } from './config.mjs';

const error = (code, message) => new UserError(code, message);
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const INPUT = 'PROXYPILOT_CLAUDE_CLEANUP_INPUT';
const MESSAGES = {
  CLAUDE_PATH_UNSAFE: 'Claude 数据目录包含链接、目录联接或非预期路径；未继续清理',
  CLAUDE_RUNNING: 'Claude Code、Claude Desktop 或相关终端仍在运行，请先正常退出后重新预览',
  CLAUDE_PROCESS_UNREADABLE: '无法确认 Claude 相关进程已经退出，清理已拒绝',
  CLAUDE_PROJECT_PRESENT: 'Claude 数据目录中存在 worktrees 项目目录，请先迁移或处理项目；未删除任何项目',
  CLAUDE_INVENTORY_CHANGED: '预览后的文件清单发生变化，请重新预览并确认',
  CLAUDE_CLEANUP_FAILED: 'Claude 本地数据清理未完整完成，请重新预览检查残留；不会删除项目目录',
  CLAUDE_INSPECT_FAILED: '无法安全检查 Claude 本地目录或进程，请检查权限后重试',
};
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROXYPILOT_CLAUDE_CLEANUP_INPUT)) | ConvertFrom-Json
function Full([string]$value) {
  $absolute = [IO.Path]::GetFullPath($value)
  $volume = [IO.Path]::GetPathRoot($absolute)
  if ($absolute.Length -gt $volume.Length) { return $absolute.TrimEnd([char]92) }
  return $absolute
}
function Assert-Safe([string]$target) {
  $full = Full $target
  $allowed = $false
  foreach ($root in $request.roots) {
    $base = Full ([string]$root)
    if ($full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) { $allowed = $true }
  }
  if (-not $allowed) { throw 'CLAUDE_PATH_UNSAFE' }
  $cursor = $full
  while ($cursor) {
    $item = $null
    try { $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { }
    if ($null -ne $item) {
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'CLAUDE_PATH_UNSAFE' }
      if ((Full $item.FullName) -ine $cursor) { throw 'CLAUDE_PATH_UNSAFE' }
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if ($parent -eq $cursor) { break }
    $cursor = $parent
  }
  return $full
}
function Processes {
  $claudeProcesses = @()
  foreach ($process in @(Get-CimInstance Win32_Process)) {
    $name = [string]$process.Name
    if ($name -imatch '^(claude|claude-code)(\.exe)?$') { $claudeProcesses += @{pid=[int]$process.ProcessId;name=$name}; continue }
    if ($name -imatch '^(node|bun|bash|wsl|wslhost|python)(\.exe)?$') {
      if (-not $process.CommandLine) { throw 'CLAUDE_PROCESS_UNREADABLE' }
      if ($process.CommandLine -imatch '(@anthropic-ai[\\/]claude-code|[\\/]claude(?:-code)?(?:\.exe|\.js)?(?:["\s]|$)|claude-code|\bclaude\s)') { $claudeProcesses += @{pid=[int]$process.ProcessId;name=$name} }
    }
  }
  return $claudeProcesses
}
function Inventory([string]$target) {
  $full = Assert-Safe $target
  if (-not (Test-Path -LiteralPath $full)) { return $null }
  $entries = [Collections.Generic.List[object]]::new()
  $stack = [Collections.Generic.Stack[string]]::new()
  $stack.Push($full)
  [long]$bytes = 0
  [long]$files = 0
  while ($stack.Count -gt 0) {
    $next = $stack.Pop()
    [void](Assert-Safe $next)
    $item = Get-Item -LiteralPath $next -Force
    if ($item.PSIsContainer -and $item.Name -ieq 'worktrees') { throw 'CLAUDE_PROJECT_PRESENT' }
    $relative = $item.FullName.Substring($full.Length)
    $entry = [ordered]@{relative=$relative;directory=[bool]$item.PSIsContainer;length=$(if ($item.PSIsContainer) { '0' } else { [string]$item.Length });modified=[string]$item.LastWriteTimeUtc.Ticks;created=[string]$item.CreationTimeUtc.Ticks}
    $entries.Add($entry)
    if ($entries.Count -gt 250000) { throw 'CLAUDE_INSPECT_FAILED' }
    if ($item.PSIsContainer) { foreach ($child in @(Get-ChildItem -LiteralPath $next -Force)) { $stack.Push($child.FullName) } }
    else { $files++; $bytes += $item.Length }
  }
  $sorted = @($entries | Sort-Object { $_.relative })
  $serialized = ConvertTo-Json -InputObject $sorted -Depth 5 -Compress
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $fingerprint = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($serialized))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
  return @{path=$full;kind=$(if ((Get-Item -LiteralPath $full -Force).PSIsContainer) { 'directory' } else { 'file' });files=$files;bytes=$bytes;fingerprint=$fingerprint;entries=$sorted}
}
function Targets {
  $all = @($request.targets)
  foreach ($item in @(Get-ChildItem -LiteralPath ([string]$request.homeDir) -Force)) {
    if ($item.Name -match '^\.claude\.json\.(backup|bak)([.-][0-9]+)?$') { $all += $item.FullName }
  }
  return @($all | Sort-Object -Unique)
}
function Safe-Remove($inventory) {
  # No recursive Remove-Item: each entry and its ancestors are rechecked before
  # a literal-path leaf deletion. A junction is never traversed during deletion.
  foreach ($entry in @($inventory.entries | Sort-Object { $_.relative.Length } -Descending)) {
    $location = $inventory.path + $entry.relative
    [void](Assert-Safe $location)
    $item = Get-Item -LiteralPath $location -Force
    if ([bool]$item.PSIsContainer -ne [bool]$entry.directory -or [string]$item.CreationTimeUtc.Ticks -ne [string]$entry.created) { throw 'CLAUDE_INVENTORY_CHANGED' }
    if (-not $entry.directory -and ([string]$item.Length -ne [string]$entry.length -or [string]$item.LastWriteTimeUtc.Ticks -ne [string]$entry.modified)) { throw 'CLAUDE_INVENTORY_CHANGED' }
    if ($entry.directory -and @(Get-ChildItem -LiteralPath $location -Force).Count -ne 0) { throw 'CLAUDE_INVENTORY_CHANGED' }
    Remove-Item -LiteralPath $location -Force -ErrorAction Stop
  }
}
try {
  $running = @(Processes)
  $inventories = @()
  foreach ($target in @(Targets)) { $inventory = Inventory ([string]$target); if ($inventory) { $inventories += $inventory } }
  $residuals = @()
  foreach ($scope in @('Process','User','Machine')) {
    # Registry enumeration reads names only for persisted environment variables.
    # The inherited process environment is already held by this process.
    if ($scope -eq 'Process') { $names = @([Environment]::GetEnvironmentVariables('Process').Keys) }
    elseif ($scope -eq 'User') { $key = Get-Item -LiteralPath 'HKCU:\Environment' -ErrorAction SilentlyContinue; $names = $(if ($key) { @($key.GetValueNames()) } else { @() }) }
    else { $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'; $names = @($key.GetValueNames()) }
    foreach ($name in @('ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN','CLAUDE_CODE_OAUTH_TOKEN','CLAUDE_CONFIG_DIR','CLAUDE_CODE_TMPDIR','CLAUDE_CODE_API_KEY_HELPER_TTL_MS')) {
      if ($names -contains $name) { $residuals += @{kind='environment';scope=$scope;name=$name} }
    }
  }
  if ($request.operation -eq 'remove') {
    if ($running.Count -gt 0) { throw 'CLAUDE_RUNNING' }
    if ($inventories.Count -ne @($request.expected).Count) { throw 'CLAUDE_INVENTORY_CHANGED' }
    foreach ($inventory in $inventories) {
      $expected = @($request.expected | Where-Object { $_.path -ieq $inventory.path })
      if ($expected.Count -ne 1 -or $expected[0].fingerprint -cne $inventory.fingerprint) { throw 'CLAUDE_INVENTORY_CHANGED' }
    }
    # Process state is checked again immediately before destructive work.
    if (@(Processes).Count -gt 0) { throw 'CLAUDE_RUNNING' }
    foreach ($inventory in $inventories) { Safe-Remove $inventory }
    $value = @{deleted=@($inventories | ForEach-Object { $_.path });residuals=$residuals}
  } elseif ($request.operation -eq 'inspect') {
    $public = @($inventories | ForEach-Object { @{path=$_.path;kind=$_.kind;files=$_.files;bytes=$_.bytes;fingerprint=$_.fingerprint} })
    $value = @{targets=$public;runningProcesses=$running;residuals=$residuals}
  } else { throw 'CLAUDE_INSPECT_FAILED' }
  ConvertTo-Json -InputObject @{ok=$true;value=$value} -Depth 8 -Compress
} catch {
  $allowed = @('CLAUDE_PATH_UNSAFE','CLAUDE_RUNNING','CLAUDE_PROCESS_UNREADABLE','CLAUDE_PROJECT_PRESENT','CLAUDE_INVENTORY_CHANGED','CLAUDE_INSPECT_FAILED')
  $code = [string]$_.Exception.Message
  if ($allowed -cnotcontains $code) { $code = $(if ($request.operation -eq 'remove') { 'CLAUDE_CLEANUP_FAILED' } else { 'CLAUDE_INSPECT_FAILED' }) }
  ConvertTo-Json -InputObject @{ok=$false;code=$code} -Compress
}
`;

export function createWindowsClaudeCleanupAdapter({ platform = process.platform, execFile = nodeExecFile } = {}) {
  async function call(operation, input) {
    if (platform !== 'win32') throw error('PLATFORM_UNSUPPORTED', 'Claude 本地清理目前需要 Windows');
    const raw = await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(SCRIPT, 'utf16le').toString('base64')], {
      env: { ...process.env, [INPUT]: Buffer.from(JSON.stringify({ operation, ...input })).toString('base64') }, encoding: 'utf8', windowsHide: true, timeout: 120000, maxBuffer: 2 * 1024 * 1024,
    }, (err, stdout) => err ? reject(error(operation === 'remove' ? 'CLAUDE_CLEANUP_FAILED' : 'CLAUDE_INSPECT_FAILED', MESSAGES[operation === 'remove' ? 'CLAUDE_CLEANUP_FAILED' : 'CLAUDE_INSPECT_FAILED'])) : resolve(stdout)));
    let result;
    try { result = JSON.parse(raw.replace(/^\uFEFF/, '').trim()); } catch { /* fail closed */ }
    if (!result?.ok) { const code = Object.hasOwn(MESSAGES, result?.code) ? result.code : 'CLAUDE_INSPECT_FAILED'; throw error(code, MESSAGES[code]); }
    return result.value;
  }
  return { inspect: input => call('inspect', input), remove: input => call('remove', input) };
}

export function createClaudeCleanupManager({ homeDir = os.homedir(), localAppDataDir = process.env.LOCALAPPDATA, roamingAppDataDir = process.env.APPDATA, configDir = process.env.CLAUDE_CONFIG_DIR, adapter, mock = false, now = Date.now, ttlMs = 5 * 60_000 } = {}) {
  const windowsPath = path.win32;
  if (!mock && !windowsPath.isAbsolute(homeDir)) throw error('CLAUDE_PATH_UNSAFE', 'Claude 清理需要绝对用户目录');
  const home = windowsPath.resolve(mock ? 'C:\\MockUser' : homeDir);
  const under = (root, target) => { const relative = windowsPath.relative(root, target); return Boolean(relative) && !relative.startsWith('..') && !windowsPath.isAbsolute(relative); };
  const roots = [home];
  const targets = [windowsPath.join(home, '.claude'), windowsPath.join(home, '.claude.json')];
  const warnings = ['清理永久删除预览中的登录状态、会话、插件和用户缓存，不可一键撤销；项目目录不在清理范围。', 'WSL、其他用户、云端记录、Windows 凭据管理器、IDE/桌面应用私有存储和自定义临时目录需另行检查；无法承诺全机无残留。', '关闭 Claude IDE 扩展与桌面应用；它们再次运行可能重建用户数据。此操作不会撤销服务端会话或删除云端记录。'];
  if (!mock && localAppDataDir && windowsPath.isAbsolute(localAppDataDir) && under(home, localAppDataDir)) { roots.push(windowsPath.resolve(localAppDataDir)); targets.push(windowsPath.join(localAppDataDir, 'claude-cli-nodejs')); }
  if (!mock && configDir) {
    const resolved = windowsPath.resolve(configDir);
    const relative = windowsPath.relative(home, resolved);
    // A custom directory must be a dedicated Claude home directory, not a repo,
    // profile root, or a parent of documents. Unknown locations are reported.
    if (windowsPath.isAbsolute(configDir) && under(home, resolved) && /^\.claude(?:[-_][A-Za-z0-9_-]+)?$/.test(relative)) targets.push(resolved);
    else warnings.push('CLAUDE_CONFIG_DIR 指向未受支持的自定义位置：保留该目录，未自动清理。');
  }
  void roamingAppDataDir; // Claude Desktop private storage intentionally excluded.
  const input = { homeDir: home, roots: [...new Set(roots)], targets: [...new Set(targets)] };
  const mockTargets = [{ path: windowsPath.join(home, '.claude'), kind: 'directory', files: 7, bytes: 1024, fingerprint: 'mock-only' }];
  const api = mock ? { inspect: async () => ({ targets: structuredClone(mockTargets), runningProcesses: [], residuals: [] }), remove: async () => ({ deleted: mockTargets.splice(0).map(item => item.path), residuals: [] }) } : adapter || createWindowsClaudeCleanupAdapter();
  const plans = new Map();
  let serial = Promise.resolve();
  const locked = action => { const task = serial.then(action, action); serial = task.catch(() => {}); return task; };
  const describe = inspected => ({ targets: inspected.targets.map(({ fingerprint, ...target }) => target), runningProcesses: inspected.runningProcesses, residuals: inspected.residuals, warnings: [...warnings], mock });
  function validateInspected(inspected) {
    if (!inspected || !Array.isArray(inspected.targets) || !Array.isArray(inspected.runningProcesses) || !Array.isArray(inspected.residuals)) throw error('CLAUDE_INSPECT_FAILED', MESSAGES.CLAUDE_INSPECT_FAILED);
    for (const item of inspected.targets) {
      const basename = windowsPath.basename(item.path || '');
      const allowed = input.targets.some(target => windowsPath.relative(target, item.path || '') === '') || (windowsPath.relative(home, windowsPath.dirname(item.path || '')) === '' && /^\.claude\.json\.(backup|bak)([.-][0-9]+)?$/.test(basename));
      if (!allowed || !under(home, item.path) || !['directory', 'file'].includes(item.kind) || typeof item.fingerprint !== 'string' || !Number.isSafeInteger(item.files) || !Number.isSafeInteger(item.bytes)) throw error('CLAUDE_PATH_UNSAFE', MESSAGES.CLAUDE_PATH_UNSAFE);
    }
    return inspected;
  }
  return {
    preview: () => locked(async () => {
      const inspected = validateInspected(await api.inspect(input));
      for (const [token, plan] of plans) if (plan.expiresAt <= now()) plans.delete(token);
      if (plans.size >= 16) plans.delete(plans.keys().next().value);
      const confirmationToken = randomBytes(24).toString('hex');
      const expiresAt = now() + ttlMs;
      plans.set(confirmationToken, { expiresAt, digest: hash(inspected), expected: inspected.targets });
      return { ...describe(inspected), confirmationToken, expiresAt: new Date(expiresAt).toISOString(), canConfirm: inspected.runningProcesses.length === 0, totalFiles: inspected.targets.reduce((sum, item) => sum + item.files, 0), totalBytes: inspected.targets.reduce((sum, item) => sum + item.bytes, 0) };
    }),
    confirm: ({ confirmationToken, confirmed } = {}) => locked(async () => {
      if (confirmed !== true) throw error('CONFIRMATION_REQUIRED', '请先预览并手动确认永久清理 Claude 本地数据');
      const plan = plans.get(confirmationToken);
      plans.delete(confirmationToken);
      if (!plan || now() >= plan.expiresAt) throw error('CONFIRMATION_INVALID', '清理确认已过期或已使用，请重新预览');
      const inspected = validateInspected(await api.inspect(input));
      if (inspected.runningProcesses.length) throw error('CLAUDE_RUNNING', MESSAGES.CLAUDE_RUNNING);
      if (hash(inspected) !== plan.digest) throw error('CLAUDE_INVENTORY_CHANGED', MESSAGES.CLAUDE_INVENTORY_CHANGED);
      const result = await api.remove({ ...input, expected: plan.expected });
      const remaining = validateInspected(await api.inspect(input));
      return { ...describe(remaining), deleted: result.deleted, complete: remaining.targets.length === 0, scope: 'known-windows-user-data', residuals: remaining.residuals, cleanedAt: new Date(now()).toISOString() };
    }),
  };
}
