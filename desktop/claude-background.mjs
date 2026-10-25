import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile, realpath, rm } from 'node:fs/promises';
import { createPrivateDirectory, writePrivate, renamePrivate } from '../backend/src/private-files.mjs';

const execute = promisify(execFile), inputName = 'MC_PROXY_CLAUDE_SERVICE_INPUT';
const nativeScript = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$nativeModules = Join-Path ([Environment]::GetEnvironmentVariable('SystemRoot','Process')) 'System32\WindowsPowerShell\v1.0\Modules'
# PowerShell 7 launchers can inherit a PSModulePath which hides the 5.1
# Authenticode/hash cmdlets. Import the fixed Windows modules explicitly.
Import-Module (Join-Path $nativeModules 'Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1')
Import-Module (Join-Path $nativeModules 'Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$failureCode = 'CLAUDE_BACKGROUND_CHECK_FAILED'
function Read-RegistryStartup {
  $result = @{registryStart=$null;registryDelayedPresent=$false;registryDelayedValue=$null;readStatus='unknown'}
  $key = $null
  try {
    $key = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\CoworkVMService'
    $names = @($key.GetValueNames())
    if ($names -notcontains 'Start' -or $key.GetValueKind('Start') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { $result.readStatus='invalid'; return $result }
    $result.registryStart = [int]$key.GetValue('Start')
    if ($result.registryStart -notin @(0,1,2,3,4)) { $result.readStatus='invalid'; return $result }
    $result.registryDelayedPresent = ($names -contains 'DelayedAutoStart')
    if ($result.registryDelayedPresent) {
      if ($key.GetValueKind('DelayedAutoStart') -ne [Microsoft.Win32.RegistryValueKind]::DWord) { $result.readStatus='invalid'; return $result }
      $result.registryDelayedValue = [int]$key.GetValue('DelayedAutoStart')
      if ($result.registryDelayedValue -notin @(0,1)) { $result.readStatus='invalid'; return $result }
    }
    $result.readStatus = 'ok'
  } catch {
    if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::PermissionDenied -or $_.Exception -is [UnauthorizedAccessException] -or $_.Exception -is [Security.SecurityException]) { $result.readStatus='denied' }
  } finally { if ($key) { $key.Close() } }
  return $result
}
function Read-Observation {
  $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='CoworkVMService'"
  if ($null -eq $service) { return @{present=$false} }
  $executable = [string]$service.PathName
  if ($executable -match '^"([^"]+\.exe)"$') { $executable = $Matches[1] }
  $programFiles = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
  $pattern = '^' + [Regex]::Escape((Join-Path $programFiles 'WindowsApps')) + '\\Claude_\d+\.\d+\.\d+\.\d+_(x64|arm64|x86)__pzs8sxrjxfjjc\\app\\resources\\cowork-svc\.exe$'
  $packagePath = ($executable -match $pattern)
  $signature = $null; $fileHash = ''; $thumbprint = ''
  if ($packagePath) {
    try {
      $item = Get-Item -LiteralPath $executable
      for ($directory = $item.Directory; $directory.FullName -ne (Join-Path $programFiles 'WindowsApps'); $directory = $directory.Parent) {
        if (-not $directory -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe package directory' }
      }
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe package file' }
      $signature = Get-AuthenticodeSignature -LiteralPath $executable
      $fileHash = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
      if ($signature.SignerCertificate) { $thumbprint = $signature.SignerCertificate.Thumbprint }
    } catch { $signature = $null }
  }
  $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { '' }
  $registry = Read-RegistryStartup
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return @{
    present=$true; name=[string]$service.Name; state=[string]$service.State; startMode=[string]$service.StartMode
    systemAccount=([string]$service.StartName -eq 'LocalSystem'); executable=$executable; programFiles=$programFiles
    signatureStatus=$(if ($signature) { [string]$signature.Status } else { 'Unavailable' }); signer=$signer
    fileHash=$fileHash; signerThumbprint=$thumbprint; delayedAuto=($registry.registryDelayedValue -eq 1)
    registryStart=$registry.registryStart;registryDelayedPresent=$registry.registryDelayedPresent;registryDelayedValue=$registry.registryDelayedValue;readStatus=$registry.readStatus
    userSid=$identity.User.Value; machineGuid=(Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
}
try {
  $request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:MC_PROXY_CLAUDE_SERVICE_INPUT)) | ConvertFrom-Json
  if ($request.operation -notin @('inspect','disable','restore')) { throw 'Invalid fixed action' }
  $before = Read-Observation
  if ($request.operation -eq 'inspect') { @{ok=$true;observation=$before} | ConvertTo-Json -Compress -Depth 4; exit 0 }
  $failureCode = 'CLAUDE_STARTUP_ADMIN_REQUIRED'
  if (-not $before.elevated) { throw 'Administrator token required' }
  $failureCode = 'CLAUDE_STARTUP_IDENTITY_UNVERIFIED'
  if ($before.name -cne 'CoworkVMService' -or $before.signatureStatus -cne 'Valid' -or $before.signer -cne 'Anthropic, PBC' -or -not $before.fileHash) { throw 'Unverified service' }
  $failureCode = 'CLAUDE_STARTUP_REGISTRY_UNREADABLE'
  if ($before.readStatus -ne 'ok') { throw 'Registry startup values cannot be verified' }
  $failureCode = 'CLAUDE_STARTUP_CONFLICT'
  foreach ($field in @('executable','fileHash','signerThumbprint','userSid','machineGuid','startMode','delayedAuto','registryStart','registryDelayedPresent','registryDelayedValue','readStatus')) {
    if ($before[$field] -ne $request.expected.$field) { throw 'Service identity or configuration changed' }
  }
  $failureCode = 'CLAUDE_STARTUP_UNCONFIRMED'
  $mode = if ($request.operation -eq 'disable') { 'disabled' } else { [string]$request.restoreMode }
  if ($mode -notin @('disabled','auto','delayed-auto','demand') -or ($request.operation -eq 'restore' -and $mode -eq 'disabled')) { $failureCode='CLAUDE_STARTUP_CONFLICT'; throw 'Invalid startup mode' }
  $sc = Join-Path ([Environment]::GetEnvironmentVariable('SystemRoot','Process')) 'System32\sc.exe'
  & $sc 'config' 'CoworkVMService' 'start=' $mode | Out-Null
  if ($LASTEXITCODE -eq 5) { $failureCode = 'CLAUDE_STARTUP_ACCESS_DENIED'; throw 'Packaged service configuration denied' }
  if ($LASTEXITCODE -ne 0) { throw 'Service configuration not confirmed' }
  $after = Read-Observation
  if ($after.signatureStatus -cne 'Valid' -or $after.signer -cne 'Anthropic, PBC') { throw 'Service signature changed after configuration' }
  foreach ($field in @('executable','fileHash','signerThumbprint','userSid','machineGuid')) {
    if ($before[$field] -ne $after[$field]) { throw 'Service identity changed after configuration' }
  }
  if ($after.readStatus -ne 'ok') { throw 'Startup registry readback not confirmed' }
  $expectedMode = if ($mode -eq 'disabled') { 'Disabled' } elseif ($mode -eq 'demand') { 'Manual' } else { 'Auto' }
  $expectedStart = if ($mode -eq 'disabled') { 4 } elseif ($mode -eq 'demand') { 3 } else { 2 }
  if ($after.startMode -ne $expectedMode -or $after.registryStart -ne $expectedStart -or ($mode -eq 'delayed-auto' -and -not $after.delayedAuto) -or ($mode -eq 'auto' -and $after.delayedAuto)) { throw 'Startup mode not confirmed' }
  @{ok=$true;observation=$after} | ConvertTo-Json -Compress -Depth 4
} catch { @{ok=$false;code=$failureCode} | ConvertTo-Json -Compress }
`;

const error = code => Object.assign(new Error(), { code });
const unknown = code => ({ present: false, state: 'unknown', startMode: 'unknown', identity: 'unknown', systemAccount: false, mock: false, trusted: 'unverified', canRestore: false, startupManaged: false,
  registryStart: null, readStatus: 'unknown', code });
function windowsDirectory(systemRoot) {
  if (typeof systemRoot !== 'string' || !/^[a-z]:\\[^\x00-\x1f]+$/i.test(systemRoot)
    || systemRoot.split(/[\\/]/).some(part => part === '.' || part === '..')) throw error('CLAUDE_BACKGROUND_CHECK_FAILED');
  return path.win32.normalize(systemRoot);
}
function publicObservation(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw error('CLAUDE_BACKGROUND_CHECK_FAILED');
  if (value.present === false) return { ...unknown('CLAUDE_BACKGROUND_NOT_FOUND'), state: 'stopped' };
  if (value.present !== true || value.name !== 'CoworkVMService') throw error('CLAUDE_BACKGROUND_CHECK_FAILED');
  const expectedRoot = typeof value.programFiles === 'string' && /^[a-z]:\\[^\x00-\x1f]+$/i.test(value.programFiles) ? path.win32.join(value.programFiles, 'WindowsApps') : '';
  const executable = typeof value.executable === 'string' ? value.executable : '';
  const relative = expectedRoot ? path.win32.relative(expectedRoot, executable) : '';
  const packagePath = expectedRoot && path.win32.isAbsolute(executable) && !/[\x00-\x1f]/.test(executable)
    && !executable.split(/[\\/]/).some(part => part === '.' || part === '..')
    && /^Claude_\d+\.\d+\.\d+\.\d+_(?:x64|arm64|x86)__pzs8sxrjxfjjc\\app\\resources\\cowork-svc\.exe$/i.test(relative);
  const trusted = !packagePath ? false : value.signatureStatus === 'Unavailable' ? 'unverified' : value.signatureStatus === 'Valid' && value.signer === 'Anthropic, PBC';
  return { present: true, state: value.state === 'Running' ? 'running' : value.state === 'Stopped' ? 'stopped' : 'unknown',
    startMode: { Auto: 'automatic', Manual: 'manual', Disabled: 'disabled' }[value.startMode] || 'unknown',
    identity: trusted === true ? 'verified' : 'unverified', systemAccount: value.systemAccount === true, mock: false, trusted,
    registryStart: Number.isInteger(value.registryStart) && value.registryStart >= 0 && value.registryStart <= 4 ? value.registryStart : null,
    readStatus: ['ok','denied','invalid'].includes(value.readStatus) ? value.readStatus : 'unknown',
    canRestore: false, startupManaged: false, code: trusted === true ? 'CLAUDE_BACKGROUND_VERIFIED' : trusted === 'unverified' ? 'CLAUDE_BACKGROUND_CHECK_FAILED' : 'CLAUDE_BACKGROUND_IDENTITY_UNVERIFIED' };
}
async function nativeObservation(settings, request = { operation: 'inspect' }) {
  const powershell = path.win32.join(windowsDirectory(settings.systemRoot), 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  try {
    const result = await settings.executeFile(powershell, ['-NoProfile', '-NonInteractive', '-Command', nativeScript], {
      windowsHide: true, timeout: 15_000, maxBuffer: 16 * 1024, encoding: 'utf8',
      env: { ...process.env, [inputName]: Buffer.from(JSON.stringify(request)).toString('base64') },
    });
    const reply = JSON.parse(result.stdout.replace(/^\uFEFF/, '').trim());
    if (!reply?.ok) throw error(['CLAUDE_STARTUP_ADMIN_REQUIRED','CLAUDE_STARTUP_IDENTITY_UNVERIFIED','CLAUDE_STARTUP_CONFLICT','CLAUDE_STARTUP_ACCESS_DENIED','CLAUDE_STARTUP_UNCONFIRMED','CLAUDE_STARTUP_REGISTRY_UNREADABLE'].includes(reply?.code) ? reply.code : 'CLAUDE_BACKGROUND_CHECK_FAILED');
    publicObservation(reply.observation);
    return reply.observation;
  } catch (cause) { throw error(['CLAUDE_BACKGROUND_CHECK_FAILED','CLAUDE_STARTUP_ADMIN_REQUIRED','CLAUDE_STARTUP_IDENTITY_UNVERIFIED','CLAUDE_STARTUP_CONFLICT','CLAUDE_STARTUP_ACCESS_DENIED','CLAUDE_STARTUP_UNCONFIRMED','CLAUDE_STARTUP_REGISTRY_UNREADABLE'].includes(cause?.code) ? cause.code : request.operation === 'inspect' ? 'CLAUDE_BACKGROUND_CHECK_FAILED' : 'CLAUDE_STARTUP_UNCONFIRMED'); }
}

export async function getClaudeBackground({ mock = false, platform = process.platform, systemRoot = process.env.SystemRoot || 'C:\\Windows', executeFile = execute } = {}) {
  if (mock) return { present: true, state: 'running', startMode: 'automatic', identity: 'verified', systemAccount: true, mock: true, trusted: true, canRestore: false, startupManaged: false,
    registryStart: 2, readStatus: 'ok', code: 'CLAUDE_BACKGROUND_MOCK' };
  if (platform !== 'win32') return unknown('CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
  try { return publicObservation(await nativeObservation({ systemRoot, executeFile })); }
  catch { return unknown('CLAUDE_BACKGROUND_CHECK_FAILED'); }
}
export async function openClaudeServices({ mock = false, platform = process.platform, systemRoot = process.env.SystemRoot || 'C:\\Windows', openPath } = {}) {
  if (mock) return { opened: false, mock: true };
  if (platform !== 'win32') throw error('CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
  try {
    const target = path.win32.join(windowsDirectory(systemRoot), 'System32', 'services.msc');
    if (typeof openPath !== 'function' || await openPath(target)) throw new Error();
    return { opened: true, mock: false };
  } catch { throw error('CLAUDE_SERVICES_OPEN_FAILED'); }
}

// No startup reads or mutations. Intent precedes the native operation; only a
// verified completion permits automatic restoration from the private journal.
export function createClaudeBackgroundManager({ userData, mock = false, platform = process.platform,
  systemRoot = process.env.SystemRoot || 'C:\\Windows', executeFile = execute, openPath,
  createDirectory = createPrivateDirectory, writeFile = writePrivate, renameFile = renamePrivate } = {}) {
  const settings = { systemRoot, executeFile }, directory = path.join(userData, 'claude-background'), file = path.join(directory, 'startup.json');
  let busy = false, mockDisabled = false;
  const validDelayed = value => value && typeof value.present === 'boolean' && (value.present ? [0,1].includes(value.value) : value.value === null);
  const delayed = value => {
    const result = { present: value.registryDelayedPresent, value: value.registryDelayedValue };
    if (value.readStatus !== 'ok' || !validDelayed(result)) throw error('CLAUDE_STARTUP_REGISTRY_UNREADABLE');
    return result;
  };
  const sameDelayed = (expected, value) => validDelayed(expected) && expected.present === value.registryDelayedPresent && expected.value === value.registryDelayedValue;
  async function assertDirectory() {
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (await realpath(directory)).toLowerCase() !== path.resolve(directory).toLowerCase()) throw error('CLAUDE_STARTUP_RECORD_FAILED');
  }
  async function readRecord() {
    try {
      await assertDirectory(); const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink > 1 || stat.size > 16 * 1024 || (await realpath(file)).toLowerCase() !== path.resolve(file).toLowerCase()) throw new Error();
      const record = JSON.parse(await readFile(file, 'utf8'));
      if (record.version !== 1 || record.service !== 'CoworkVMService' || !['intent','applied','restored'].includes(record.phase)
        || !/^[a-f0-9]{64}$/.test(record.binding) || !record.identity || typeof record.identity.executable !== 'string'
        || !/^[a-f0-9]{64}$/i.test(record.identity.fileHash) || !/^[a-f0-9]{40,128}$/i.test(record.identity.signerThumbprint)
        || !['Auto','Manual'].includes(record.originalMode) || typeof record.delayedAuto !== 'boolean') throw new Error();
      // Old restored records are historical, not restoration authority. Old
      // applied/intent records cannot authorize writes without full metadata.
      if (record.phase !== 'restored' && (!['scm','registry'].includes(record.method) || ![2,3].includes(record.originalRegistryStart)
        || !validDelayed(record.originalDelayedAuto) || (record.phase === 'applied' && (!validDelayed(record.appliedDelayedAuto) || record.appliedRegistryStart !== 4)))) throw new Error();
      return record;
    } catch (cause) { if (cause.code === 'ENOENT') return null; throw error('CLAUDE_STARTUP_RECORD_FAILED'); }
  }
  async function saveRecord(record) {
    try {
      try { await assertDirectory(); } catch (cause) { if (cause.code !== 'ENOENT') throw cause; await createDirectory(directory); }
      await assertDirectory(); await readRecord();
      const temporary = path.join(directory, `${randomUUID()}.tmp`);
      try { await writeFile(temporary, JSON.stringify(record)); await assertDirectory(); await renameFile(temporary, file); }
      finally { await rm(temporary, { force: true }).catch(() => {}); }
    } catch { throw error('CLAUDE_STARTUP_RECORD_FAILED'); }
  }
  function identity(value) {
    if (!/^[a-f0-9]{64}$/i.test(value.fileHash || '') || !/^[a-f0-9]{40,128}$/i.test(value.signerThumbprint || '')
      || !/^S-1-\d+(?:-\d+)+$/.test(value.userSid || '') || !/^[a-f0-9-]{32,36}$/i.test(value.machineGuid || '')) throw error('CLAUDE_STARTUP_IDENTITY_UNVERIFIED');
    return { binding: createHash('sha256').update(value.machineGuid.toLowerCase() + '\0' + value.userSid).digest('hex'),
      identity: { executable: value.executable.toLowerCase(), fileHash: value.fileHash.toLowerCase(), signerThumbprint: value.signerThumbprint.toLowerCase() } };
  }
  function matches(record, value) {
    const current = identity(value);
    return record.binding === current.binding && Object.keys(current.identity).every(key => record.identity[key] === current.identity[key]);
  }
  async function summary(value) {
    const result = publicObservation(value), record = await readRecord();
    if (record && record.phase !== 'restored') {
      if (record.method !== 'scm' || result.trusted !== true || !matches(record, value) || value.readStatus !== 'ok' || value.registryStart !== 4
        || value.startMode !== 'Disabled' || (record.phase === 'applied' && !sameDelayed(record.appliedDelayedAuto, value))) return { ...result, code: 'CLAUDE_STARTUP_CONFLICT' };
      return { ...result, startupManaged: record.phase === 'applied', canRestore: record.phase === 'applied',
        code: record.phase === 'applied' ? 'CLAUDE_STARTUP_DISABLED' : 'CLAUDE_STARTUP_UNCONFIRMED' };
    }
    return result;
  }
  async function sequence(action) {
    if (busy) throw error('CLAUDE_BACKGROUND_BUSY'); busy = true;
    try { return await action(); } finally { busy = false; }
  }
  async function changeStartup(restore) {
    if (mock) {
      const changed = mockDisabled !== !restore; mockDisabled = !restore;
      return { ...await getClaudeBackground({ mock: true }), startMode: mockDisabled ? 'disabled' : 'automatic', registryStart: mockDisabled ? 4 : 2,
        startupManaged: mockDisabled, canRestore: mockDisabled, changed, code: restore ? 'CLAUDE_STARTUP_RESTORED' : 'CLAUDE_STARTUP_DISABLED' };
    }
    if (platform !== 'win32') throw error('CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
    const before = await nativeObservation(settings), status = publicObservation(before);
    if (!before.elevated) throw error('CLAUDE_STARTUP_ADMIN_REQUIRED');
    if (status.trusted !== true) throw error('CLAUDE_STARTUP_IDENTITY_UNVERIFIED');
    if (before.readStatus !== 'ok' || ![2,3,4].includes(before.registryStart)) throw error('CLAUDE_STARTUP_REGISTRY_UNREADABLE');
    delayed(before);
    const current = identity(before), record = await readRecord();
    if (restore) {
      if (!record || record.phase !== 'applied' || record.method !== 'scm' || !matches(record, before) || before.registryStart !== 4 || !sameDelayed(record.appliedDelayedAuto, before)
        || before.startMode !== 'Disabled') throw error('CLAUDE_STARTUP_CONFLICT');
      const restoreMode = record.originalMode === 'Manual' ? 'demand' : record.delayedAuto ? 'delayed-auto' : 'auto';
      const after = await nativeObservation(settings, { operation: 'restore', expected: before, restoreMode });
      if (publicObservation(after).trusted !== true || !matches(record, after) || after.readStatus !== 'ok' || after.registryStart !== record.originalRegistryStart
        || after.startMode !== record.originalMode || after.delayedAuto !== record.delayedAuto) throw error('CLAUDE_STARTUP_UNCONFIRMED');
      try { await saveRecord({ ...record, phase: 'restored' }); } catch { throw error('CLAUDE_STARTUP_UNCONFIRMED'); }
      return { ...publicObservation(after), changed: true, code: 'CLAUDE_STARTUP_RESTORED' };
    }
    if (record && record.phase !== 'restored') {
      if (record.phase !== 'applied' || record.method !== 'scm' || !matches(record, before) || before.registryStart !== 4 || !sameDelayed(record.appliedDelayedAuto, before)
        || before.startMode !== 'Disabled') throw error('CLAUDE_STARTUP_CONFLICT');
      return { ...status, startupManaged: true, canRestore: true, changed: false, code: 'CLAUDE_STARTUP_DISABLED' };
    }
    if (record && record.binding !== current.binding) throw error('CLAUDE_STARTUP_CONFLICT');
    if (before.registryStart === 4) return { ...status, changed: false, code: 'CLAUDE_STARTUP_ALREADY_DISABLED' };
    if (!['Auto','Manual'].includes(before.startMode) || typeof before.delayedAuto !== 'boolean') throw error('CLAUDE_STARTUP_CONFLICT');
    if (before.registryStart !== (before.startMode === 'Auto' ? 2 : 3)) throw error('CLAUDE_STARTUP_CONFLICT');
    const pending = { version: 1, service: 'CoworkVMService', phase: 'intent', ...current, originalMode: before.startMode, delayedAuto: before.delayedAuto,
      method: 'scm', originalRegistryStart: before.registryStart, originalDelayedAuto: delayed(before) };
    await saveRecord(pending);
    let after;
    try { after = await nativeObservation(settings, { operation: 'disable', expected: before }); }
    catch (cause) {
      // A rejected operation is retryable only after a fresh read proves the
      // original configuration and identity never changed.
      if (cause.code === 'CLAUDE_STARTUP_ACCESS_DENIED' || cause.code === 'CLAUDE_STARTUP_ADMIN_REQUIRED') {
        try { const unchanged = await nativeObservation(settings); if (matches(pending, unchanged) && unchanged.startMode === before.startMode && unchanged.readStatus === 'ok'
          && unchanged.registryStart === before.registryStart && sameDelayed(pending.originalDelayedAuto, unchanged)) await saveRecord({ ...pending, phase: 'restored' }); } catch {}
      }
      throw cause;
    }
    if (publicObservation(after).trusted !== true || !matches(pending, after) || after.readStatus !== 'ok' || after.registryStart !== 4
      || after.startMode !== 'Disabled') throw error('CLAUDE_STARTUP_UNCONFIRMED');
    try { await saveRecord({ ...pending, phase: 'applied', appliedRegistryStart: 4, appliedDelayedAuto: delayed(after) }); } catch { throw error('CLAUDE_STARTUP_UNCONFIRMED'); }
    return { ...publicObservation(after), startupManaged: true, canRestore: true, changed: true, code: 'CLAUDE_STARTUP_DISABLED' };
  }
  return {
    inspect: () => sequence(async () => {
      if (mock) return { ...await getClaudeBackground({ mock: true }), startMode: mockDisabled ? 'disabled' : 'automatic', startupManaged: mockDisabled, canRestore: mockDisabled,
        registryStart: mockDisabled ? 4 : 2 };
      if (platform !== 'win32') return unknown('CLAUDE_BACKGROUND_PLATFORM_UNSUPPORTED');
      try { return await summary(await nativeObservation(settings)); } catch (cause) { return unknown(cause.code === 'CLAUDE_STARTUP_RECORD_FAILED' ? cause.code : 'CLAUDE_BACKGROUND_CHECK_FAILED'); }
    }),
    openServices: () => sequence(() => openClaudeServices({ mock, platform, systemRoot, openPath })),
    disableStartup: () => sequence(() => changeStartup(false)),
    restoreStartup: () => sequence(() => changeStartup(true)),
  };
}
