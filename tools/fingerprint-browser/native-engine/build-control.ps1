[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
  [ValidateSet('Status', 'Pause', 'Resume', 'SelfTest')][string]$Action = 'Status',
  [ValidateRange(1, 12)][int]$Jobs = 6
)

$controlJobs = $Jobs
. (Join-Path $PSScriptRoot 'build-windows.ps1') -Jobs $controlJobs
$root = Resolve-NativeBuildRoot -Path $BuildRoot
$reviewed = Read-NativeBuildManifest
$pauseFile = Join-Path $root '.mc-native-paused.json'
$ninjaFile = Join-Path $root 'src\third_party\ninja\ninja.exe'
$mainOutput = Join-Path $root 'src\out\MCProxy'
$focusedOutput = Join-Path $root 'src\out\PatchCheck'
$mainBatch = Join-Path $root 'build-chrome.cmd'

function Select-OwnedBuildProcesses {
  param([object[]]$Processes)
  foreach ($process in $Processes) {
    if (-not $process.ExecutablePath -or -not $process.CommandLine) { continue }
    if ($process.ExecutablePath.Equals($ninjaFile, [StringComparison]::OrdinalIgnoreCase)) {
      if ($process.CommandLine -match '(?:^|\s)(?:-n|--dry-run)(?:\s|$)') { continue }
      $directoryMatches = [regex]::Matches($process.CommandLine, '(?:^|\s)-C\s+(?:"([^"]+)"|(\S+))')
      if ($directoryMatches.Count -ne 1) { continue }
      $directory = if ($directoryMatches[0].Groups[1].Success) { $directoryMatches[0].Groups[1].Value } else { $directoryMatches[0].Groups[2].Value }
      if ($directory.Equals($mainOutput, [StringComparison]::OrdinalIgnoreCase) -or
          $directory.Equals($focusedOutput, [StringComparison]::OrdinalIgnoreCase)) { $process }
    } elseif ($process.ExecutablePath.Equals($env:ComSpec, [StringComparison]::OrdinalIgnoreCase)) {
      # The main launcher may be running GN/bindgen before Ninja exists.
      $batch = [regex]::Escape($mainBatch)
      if ($process.CommandLine -match ('^(?:"[^"]+"|\S+)\s+/d\s+/c\s+(?:"' + $batch + '"|' + $batch + ')\s*$')) { $process }
    }
  }
}

function Read-PauseRecord {
  if (-not (Test-Path -LiteralPath $pauseFile)) { return $null }
  $item = Get-Item -LiteralPath $pauseFile -Force
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PAUSE_RECORD_PATH_UNSAFE' }
  $record = Get-Content -LiteralPath $pauseFile -Raw | ConvertFrom-Json
  if ($record.kind -ne 'mc-native-build-pause' -or $record.buildRoot -ne $root -or
      $record.sourceManifestSha256 -ne $reviewed.sha256) { throw 'PAUSE_RECORD_OWNERSHIP_MISMATCH' }
  return $record
}

function Write-PauseRecord {
  param($Record)
  $null = Resolve-NativeBuildRoot -Path $root
  $null = Read-PauseRecord
  $temporary = Join-Path $root ('.mc-native-paused-' + [guid]::NewGuid().ToString('N') + '.tmp')
  [IO.File]::WriteAllText($temporary, ($Record | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $temporary -Destination $pauseFile -Force
}

function Get-OwnedBuildProcesses {
  $processes = @(Get-CimInstance Win32_Process -Filter "Name='ninja.exe' OR Name='cmd.exe'")
  return @(Select-OwnedBuildProcesses -Processes $processes)
}

function Test-BuildProcessIdentityComplete {
  param($Process)
  return ($Process -and $Process.ProcessId -gt 0 -and
    $Process.CreationDate -is [DateTime] -and $Process.CreationDate -ne [DateTime]::MinValue -and
    -not [string]::IsNullOrWhiteSpace($Process.ExecutablePath) -and
    -not [string]::IsNullOrWhiteSpace($Process.CommandLine))
}

function Read-VerifiedBuildProcess {
  param($Expected, [Parameter(Mandatory)][scriptblock]$ReadProcess,
    [scriptblock]$Wait = { Start-Sleep -Milliseconds 100 }, [switch]$WaitForExit)
  if (-not (Test-BuildProcessIdentityComplete $Expected) -or
      @(Select-OwnedBuildProcesses -Processes @($Expected)).Count -ne 1) {
    throw 'BUILD_PROCESS_IDENTITY_UNVERIFIABLE: original snapshot cannot authorize a stop.'
  }
  for ($attempt = 0; $attempt -lt 4; $attempt++) {
    $current = & $ReadProcess $Expected.ProcessId
    if (-not $current) { return $null }
    # Missing CIM fields during teardown do not authorize a stop. Known
    # contradictory fields still fail immediately, including a reused PID.
    if (($current.ProcessId -and $current.ProcessId -ne $Expected.ProcessId) -or
        ($current.CreationDate -is [DateTime] -and $current.CreationDate -ne $Expected.CreationDate) -or
        ($current.CommandLine -and $current.CommandLine -cne $Expected.CommandLine) -or
        ($current.ExecutablePath -and -not $current.ExecutablePath.Equals($Expected.ExecutablePath, [StringComparison]::OrdinalIgnoreCase))) {
      throw 'BUILD_PROCESS_IDENTITY_CHANGED: no process stopped for this PID.'
    }
    $complete = Test-BuildProcessIdentityComplete $current
    if ($complete) {
      if (@(Select-OwnedBuildProcesses -Processes @($current)).Count -ne 1) {
        throw 'BUILD_PROCESS_IDENTITY_CHANGED: no process stopped for this PID.'
      }
      if (-not $WaitForExit) { return $current }
    }
    if ($attempt -lt 3) { & $Wait }
  }
  if ($complete) { throw 'BUILD_PROCESS_STOP_FAILED: verified process remains after bounded exit confirmation.' }
  throw 'BUILD_PROCESS_IDENTITY_UNVERIFIABLE: incomplete CIM identity; pause marker retained.'
}

function Show-BuildStatus {
  $paused = Read-PauseRecord
  $owned = @(Get-OwnedBuildProcesses)
  Write-Host ('暂停标记：' + $(if ($paused) { '已暂停，等待手动继续' } else { '未暂停' }))
  Write-Host ('受控构建进程（含启动器）：' + $owned.Count)
  foreach ($process in $owned) { Write-Host ('  PID ' + $process.ProcessId + '  ' + $process.CommandLine) }
  $latest = Get-ChildItem -LiteralPath $root -Filter 'build-chrome-*.log' -File | Sort-Object Name | Select-Object -Last 1
  if ($latest) { Write-Host ('最近日志：' + $latest.FullName); Get-Content -LiteralPath $latest.FullName -Tail 4 | Write-Host }
  if (Test-Path -LiteralPath (Join-Path $root '.mc-native-build.json')) { Write-Host '存在完整编译记录；原生浏览器验收结果另行记录。' }
  Write-Host '源码、对象文件和 Ninja 缓存保存在 D 盘；暂停和正常关机均不删除这些文件。'
}

if ($Action -eq 'SelfTest') {
  $valid = [pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = ('"' + $ninjaFile + '" -C "' + $mainOutput + '" -j 6 chrome') }
  $cases = @(
    @($valid, 1),
    @([pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = ('ninja -C "' + $focusedOutput + '" -j 2 obj/check.obj') }, 1),
    @([pscustomobject]@{ ExecutablePath = 'C:\other\ninja.exe'; CommandLine = $valid.CommandLine }, 0),
    @([pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = 'ninja -C D:\customer -j 6 chrome' }, 0),
    @([pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = 'ninja -C src\out\MCProxy -j 6 chrome' }, 0),
    @([pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = ($valid.CommandLine + ' -C D:\other') }, 0),
    @([pscustomobject]@{ ExecutablePath = $ninjaFile; CommandLine = ($valid.CommandLine + ' -n') }, 0),
    @([pscustomobject]@{ ExecutablePath = 'C:\Program Files\Google\Chrome\Application\chrome.exe'; CommandLine = $valid.CommandLine }, 0),
    @([pscustomobject]@{ ExecutablePath = $env:ComSpec; CommandLine = ('"' + $env:ComSpec + '" /d /c "' + $mainBatch + '"') }, 1),
    @([pscustomobject]@{ ExecutablePath = $env:ComSpec; CommandLine = ('cmd /d /c "' + $mainBatch + '" & echo other') }, 0)
  )
  foreach ($case in $cases) { if (@(Select-OwnedBuildProcesses -Processes @($case[0])).Count -ne $case[1]) { throw 'PROCESS_OWNERSHIP_SELF_TEST_FAILED' } }
  $identity = [pscustomobject]@{ ProcessId = 4242; CreationDate = [DateTime]'2026-10-18T01:00:00Z'; ExecutablePath = $ninjaFile; CommandLine = $valid.CommandLine }
  $noCommand = $identity.PSObject.Copy(); $noCommand.CommandLine = $null
  $noExecutable = $identity.PSObject.Copy(); $noExecutable.ExecutablePath = $null
  $noDate = $identity.PSObject.Copy(); $noDate.CreationDate = $null
  $newDate = $identity.PSObject.Copy(); $newDate.CreationDate = $identity.CreationDate.AddSeconds(1)
  $newCommand = $identity.PSObject.Copy(); $newCommand.CommandLine += ' --other'
  $foreignExecutable = $identity.PSObject.Copy(); $foreignExecutable.ExecutablePath = 'C:\other\ninja.exe'
  $newPid = $identity.PSObject.Copy(); $newPid.ProcessId++
  $partialConflict = $noCommand.PSObject.Copy(); $partialConflict.CreationDate = $newDate.CreationDate
  # Query and delay are injected: these scenarios never inspect or stop a real process.
  $identityCases = @(
    @('already gone', $identity, @($null), $false, $null, 1, $false),
    @('complete match', $identity, @($identity), $false, $null, 1, $true),
    @('missing command then gone', $identity, @($noCommand, $null), $false, $null, 2, $false),
    @('missing executable then match', $identity, @($noExecutable, $identity), $false, $null, 2, $true),
    @('missing creation date then gone', $identity, @($noDate, $null), $false, $null, 2, $false),
    @('persistent partial', $identity, @($noCommand), $false, 'BUILD_PROCESS_IDENTITY_UNVERIFIABLE', 4, $false),
    @('reused PID creation date', $identity, @($newDate), $false, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('different command', $identity, @($newCommand), $false, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('foreign executable', $identity, @($foreignExecutable), $false, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('different PID', $identity, @($newPid), $false, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('invalid original creation date', $noDate, @($identity), $false, 'BUILD_PROCESS_IDENTITY_UNVERIFIABLE', 0, $false),
    @('partial with known conflict', $identity, @($partialConflict), $false, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('post-stop residual then gone', $identity, @($identity, $noCommand, $null), $true, $null, 3, $false),
    @('post-stop still alive', $identity, @($identity), $true, 'BUILD_PROCESS_STOP_FAILED', 4, $false),
    @('post-stop persistently partial', $identity, @($noCommand), $true, 'BUILD_PROCESS_IDENTITY_UNVERIFIABLE', 4, $false),
    @('post-stop identity changed', $identity, @($newDate), $true, 'BUILD_PROCESS_IDENTITY_CHANGED', 1, $false),
    @('CIM error is not disappearance', $identity, @([InvalidOperationException]::new('CIM_QUERY_FAILED')), $false, 'CIM_QUERY_FAILED', 1, $false)
  )
  foreach ($case in $identityCases) {
    $state = @{ index = 0; waits = 0; rows = $case[2] }
    $read = { param($ExpectedPid) $row = $state.rows[[Math]::Min($state.index, $state.rows.Count - 1)]; $state.index++; if ($row -is [Exception]) { throw $row }; return $row }.GetNewClosure()
    $wait = { $state.waits++ }.GetNewClosure()
    $result = $null; $failure = $null
    try { $result = Read-VerifiedBuildProcess -Expected $case[1] -ReadProcess $read -Wait $wait -WaitForExit:([bool]$case[3]) }
    catch { $failure = $_.Exception.Message.Split(':')[0] }
    if ($failure -cne $case[4] -or $state.index -ne $case[5] -or
        [bool]$result -ne $case[6] -or $state.waits -ne [Math]::Max(0, $state.index - 1)) {
      throw ('PROCESS_IDENTITY_SELF_TEST_FAILED: ' + $case[0])
    }
  }
  [pscustomobject]@{ passed = $cases.Count + $identityCases.Count; ownershipPassed = $cases.Count;
    identityPassed = $identityCases.Count; failed = 0; stoppedProcesses = 0; filesChanged = 0 } | ConvertTo-Json -Compress
  exit
}

if ($Action -eq 'Status') { Show-BuildStatus; exit }

if ($Action -eq 'Pause') {
  $owned = @(Get-OwnedBuildProcesses)
  if (-not $PSCmdlet.ShouldProcess($root, '写入暂停标记并停止本项目编译进程树（保留全部文件）')) { return }
  $record = [pscustomobject]@{ kind = 'mc-native-build-pause'; schemaVersion = 1; buildRoot = $root;
    sourceManifestSha256 = $reviewed.sha256; pausedAt = [DateTime]::UtcNow.ToString('o'); jobs = $controlJobs;
    reason = 'user pause for normal shutdown'; processes = @($owned | Select-Object ProcessId, CreationDate, CommandLine) }
  Write-PauseRecord -Record $record
  # Stop the verified cmd launcher before its children, so a new Ninja cannot
  # appear between the pause flag and process-tree termination.
  $readProcess = { param($ExpectedPid) Get-CimInstance Win32_Process -Filter ('ProcessId=' + $ExpectedPid) }
  foreach ($process in @($owned | Sort-Object @{Expression = { $_.ExecutablePath -ne $env:ComSpec }})) {
    $current = Read-VerifiedBuildProcess -Expected $process -ReadProcess $readProcess
    if (-not $current) { continue }
    & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $current.ProcessId /T /F
    # A nonzero taskkill result can mean the parent tree already killed this
    # child. Confirm disappearance with the same strict, bounded identity read.
    $null = Read-VerifiedBuildProcess -Expected $process -ReadProcess $readProcess -WaitForExit
  }
  if (@(Get-OwnedBuildProcesses).Count) { throw 'BUILD_STILL_RUNNING: pause marker retained; inspect status.' }
  Write-Host '已暂停编译，文件和增量缓存均已保留。现在可以通过 Windows 开始菜单正常关机。'
  Write-Host '开机后双击“继续编译.cmd”，即可接着编译。'
  return
}

if (@(Get-OwnedBuildProcesses).Count) { Write-Host '编译已经在运行，已避免重复启动。'; Show-BuildStatus; return }
$resumeMutex = New-NativeBuildMutex -Output $mainOutput
$ownsResumeMutex = $false
try {
  try { $ownsResumeMutex = $resumeMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsResumeMutex = $true }
  if (-not $ownsResumeMutex) { Write-Host '主编译已经启动或正在准备，已避免重复启动。'; return }
  $paused = Read-PauseRecord
  if (-not $PSCmdlet.ShouldProcess($root, '继续完整浏览器编译，复用已完成的对象文件')) { return }
  if ($paused) { [IO.File]::Delete($pauseFile) }
  try {
  & (Join-Path $PSScriptRoot 'build-windows.ps1') -Build -BuildRoot $root -Jobs $controlJobs `
    -VisualStudioRoot (Join-Path $root 'msvc') -WindowsSdkRoot (Join-Path $root 'sdk-overlay')
  Write-Host '完整内核编译已完成；请回到当前对话继续原生浏览器验收。尚未激活或打包。'
} catch {
  if ($paused -and -not (Test-Path -LiteralPath $pauseFile)) { Write-PauseRecord -Record $paused }
  throw
  }
} finally {
  if ($ownsResumeMutex) { $resumeMutex.ReleaseMutex() }
  $resumeMutex.Dispose()
}
