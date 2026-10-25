Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'build-windows.ps1'
. $runner
$sourceProject = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$passed = 0
foreach ($file in @($runner, (Join-Path $PSScriptRoot 'resource-preflight.ps1'))) {
  $tokens = $null; $parseErrors = $null
  $null = [Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
  if (@($parseErrors).Count) { throw ('PowerShell parse failed: ' + $file) }
  $passed++
}
foreach ($unsafe in @([IO.Path]::GetPathRoot($sourceProject), $sourceProject, (Join-Path $sourceProject 'backend\runtime\customer'),
    (Join-Path $sourceProject 'deliverables\old'), (Join-Path $sourceProject '.cache\fingerprint-browser-canvas-r1'), '\\server\share', 'relative')) {
  $rejected = $false
  try { $null = Resolve-NativeBuildRoot -Path $unsafe } catch { $rejected = $true }
  if (-not $rejected) { throw ('Unsafe build root accepted: ' + $unsafe) }
  $passed++
}
foreach ($unsafe in @('D:\test & whoami', 'D:\%TEMP%', "D:\test`npath", 'D:\测试')) {
  $rejected = $false
  try { Assert-NativeCommandPath -Path $unsafe } catch { $rejected = $true }
  if (-not $rejected) { throw ('Unsafe command path accepted: ' + $unsafe) }
  $passed++
}
Assert-NativeCommandPath -Path 'C:\Program Files (x86)\Windows Kits\10'
$passed++

$probeRoot = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\.cache'))) ('native-build-readonly-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $probeRoot) { throw 'Probe root already exists' }
$json = & $runner -BuildRoot $probeRoot
$report = $json | ConvertFrom-Json
if ($report.mode -ne 'read-only-preflight' -or -not $report.resources.readOnly -or $report.resources.buildRoot -ne $probeRoot) {
  throw 'Preflight did not preserve requested root or read-only contract'
}
if (Test-Path -LiteralPath $probeRoot) { throw 'Preflight wrote a build directory' }
$passed++
$blocked = $false
try { & $runner -Build -BuildRoot $probeRoot | Out-Null }
catch { $blocked = $true }
if (-not $blocked -or (Test-Path -LiteralPath $probeRoot)) { throw 'Unprepared source build was not safely refused' }
$passed++
[pscustomobject]@{ passed = $passed; failed = 0; noDownloads = $true; noDirectoriesCreated = $true; sourceBuildExecuted = $false } | ConvertTo-Json -Compress
