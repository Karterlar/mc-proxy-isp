[CmdletBinding()]
param(
  [string]$BuildRoot = (Join-Path $PSScriptRoot '..\..\..\.cache\native-engine-build'),
  [string]$OutRoot,
  [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-NativeBuildRoot {
  param([Parameter(Mandatory)][string]$Path)
  if ($Path -match '[\x00-\x1f\x7f]' -or $Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.StartsWith('\\')) {
    throw 'BuildRoot must be an absolute local Windows path.'
  }
  $absolute = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
  $volume = [IO.Path]::GetPathRoot($absolute)
  if ($absolute.Length -le $volume.Length -or $absolute -match '[<>|?*]') {
    throw 'BuildRoot cannot be a drive root or a wildcard path.'
  }
  $project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..')).TrimEnd('\')
  $protected = @($project, (Join-Path $project 'backend\runtime'), (Join-Path $project 'deliverables'), (Join-Path $project '.git'))
  foreach ($item in $protected) {
    if ($absolute.Equals($item, [StringComparison]::OrdinalIgnoreCase) -or
        ($item -ne $project -and $absolute.StartsWith($item + '\', [StringComparison]::OrdinalIgnoreCase))) {
      throw 'BuildRoot overlaps project source, delivery, or customer runtime data.'
    }
  }
  if ($absolute -match '(?i)[\\/](?:browser-profiles|fingerprint-browser[^\\/]*)(?:[\\/]|$)') {
    throw 'BuildRoot cannot reuse a browser component or customer profile directory.'
  }
  $cursor = $absolute
  while ($cursor) {
    if (Test-Path -LiteralPath $cursor) {
      $entry = Get-Item -LiteralPath $cursor -Force
      if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'BuildRoot and its existing parents must be ordinary directories, without links or junctions.'
      }
    }
    $parent = [IO.Directory]::GetParent($cursor)
    if ($null -eq $parent) { break }
    $cursor = $parent.FullName
  }
  return $absolute
}

function Get-NativeBuildResources {
  param([Parameter(Mandatory)][string]$Path, [string]$OutputPath)
  $root = Resolve-NativeBuildRoot -Path $Path
  $output = if ($OutputPath) { Resolve-NativeBuildRoot -Path $OutputPath } else { Join-Path $root 'src\out\MCProxy' }
  $errors = [Collections.Generic.List[string]]::new()
  $drives = @()
  $computer = $null
  $processors = @()
  try { $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID, FileSystem, Size, FreeSpace) }
  catch { $errors.Add('DRIVE_QUERY_FAILED: ' + $_.Exception.Message) }
  try { $computer = Get-CimInstance Win32_ComputerSystem }
  catch { $errors.Add('MEMORY_QUERY_FAILED: ' + $_.Exception.Message) }
  try { $processors = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors) }
  catch { $errors.Add('CPU_QUERY_FAILED: ' + $_.Exception.Message) }

  $driveName = [IO.Path]::GetPathRoot($root).TrimEnd('\')
  $drive = @($drives | Where-Object { $_.DeviceID -eq $driveName }) | Select-Object -First 1
  $outputDrive = @($drives | Where-Object { $_.DeviceID -eq [IO.Path]::GetPathRoot($output).TrimEnd('\') }) | Select-Object -First 1
  $ram = if ($computer) { [long]$computer.TotalPhysicalMemory } else { 0 }
  $tools = [ordered]@{}
  foreach ($name in @('git', 'python', 'python3', 'cl', 'clang-cl', 'gn', 'ninja', 'gclient', 'autoninja')) {
    $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
    $tools[$name] = if ($command) { $command.Source } else { $null }
  }
  $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
  $tools['bundledPython'] = if (Test-Path -LiteralPath $bundledPython -PathType Leaf) { $bundledPython } else { $null }
  $tools['tar'] = if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\tar.exe') -PathType Leaf) { Join-Path $env:SystemRoot 'System32\tar.exe' } else { $null }
  $sevenz = Get-Command '7z' -ErrorAction SilentlyContinue | Select-Object -First 1
  $portableSevenZip = Join-Path $root 'bootstrap\7zip\7z.exe'
  $tools['7z'] = if ($sevenz) { $sevenz.Source } elseif (Test-Path -LiteralPath $portableSevenZip -PathType Leaf) { $portableSevenZip } else { $null }

  $visualStudio = @()
  foreach ($location in @((Join-Path $root 'msvc'), (Join-Path $root 'vs'))) {
    if (Test-Path -LiteralPath (Join-Path $location 'VC\Auxiliary\Build\vcvars64.bat') -PathType Leaf) { $visualStudio += $location }
  }
  $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
  if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    $installed = @(& $vswhere -products '*' -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    foreach ($location in $installed) {
      if ($location -and (Test-Path -LiteralPath (Join-Path $location 'VC\Auxiliary\Build\vcvars64.bat') -PathType Leaf)) { $visualStudio += $location }
    }
  }
  $visualStudio = @($visualStudio | Select-Object -Unique)
  $sdkRoot = 'C:\Program Files (x86)\Windows Kits\10'
  try {
    $kits = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' -Name KitsRoot10 -ErrorAction Stop
    if ($kits.KitsRoot10) { $sdkRoot = $kits.KitsRoot10 }
  } catch { }
  # A physical copy of the installed public SDK plus signed debugging tools
  # permits isolated builds without changing the registered system SDK.
  $sdkOverlay = Join-Path $root 'sdk-overlay'
  if ((Test-Path -LiteralPath (Join-Path $sdkOverlay '.mc-native-sdk.json') -PathType Leaf) -and
      (Test-Path -LiteralPath (Join-Path $sdkOverlay 'Include\10.0.26100.0\um\Windows.h') -PathType Leaf) -and
      (Test-Path -LiteralPath (Join-Path $sdkOverlay 'Debuggers\x64\cdb.exe') -PathType Leaf)) {
    $null = Resolve-NativeBuildRoot -Path $sdkOverlay
    $sdkRoot = $sdkOverlay
  }
  $sdkVersions = @()
  $longPathsEnabled = $null
  try { $longPathsEnabled = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled).LongPathsEnabled }
  catch { }
  $sdkLib = Join-Path $sdkRoot 'Lib'
  if (Test-Path -LiteralPath $sdkLib) {
    $sdkVersions = @(Get-ChildItem -LiteralPath $sdkLib -Directory | Where-Object { $_.Name -match '^10\.0\.\d+\.\d+$' } | Select-Object -ExpandProperty Name)
  }
  $blocked = [Collections.Generic.List[string]]::new()
  # The official minimum is a lower bound, not an estimate of this recipe's
  # extracted source, tools and release output. Keep larger estimates advisory.
  $requiredFree = [long](100000000000)
  if (-not $drive) { $blocked.Add('BUILD_VOLUME_UNKNOWN') }
  elseif ($drive.FileSystem -ne 'NTFS') { $blocked.Add('BUILD_VOLUME_MUST_BE_NTFS') }
  elseif ([long]$drive.FreeSpace -lt $requiredFree) { $blocked.Add('FRESH_SOURCE_VOLUME_REQUIRES_100_GB_FREE') }
  if ($ram -lt 8GB) { $blocked.Add('AT_LEAST_8_GIB_RAM_REQUIRED_OR_UNVERIFIED') }
  if (-not $tools['git']) { $blocked.Add('GIT_NOT_FOUND') }
  if ($visualStudio.Count -eq 0) { $blocked.Add('VISUAL_STUDIO_CPP_NOT_INSTALLED') }
  if ($sdkVersions.Count -eq 0) { $blocked.Add('WINDOWS_SDK_NOT_INSTALLED') }
  $debuggerPath = Join-Path $sdkRoot 'Debuggers\x64\cdb.exe'
  if (-not (Test-Path -LiteralPath $debuggerPath -PathType Leaf)) { $blocked.Add('WINDOWS_SDK_DEBUGGING_TOOLS_NOT_INSTALLED') }
  if ($longPathsEnabled -ne 1) { $blocked.Add('DOCUMENTED_LONG_PATH_SUPPORT_DISABLED_OR_UNVERIFIED') }
  if ($errors.Count) { $blocked.Add('HOST_RESOURCE_QUERY_INCOMPLETE') }
  [pscustomobject]@{
    schemaVersion = 1
    recordedAt = [DateTime]::UtcNow.ToString('o')
    buildRoot = $root
    outputRoot = $output
    readOnly = $true
    readyForFreshSourceBuild = ($blocked.Count -eq 0)
    blockedReasons = @($blocked.ToArray())
    memoryBytes = $ram
    cpu = $processors
    drives = $drives
    tools = $tools
    visualStudioLocations = $visualStudio
    windowsSdk = [pscustomobject]@{ root = $sdkRoot; versions = $sdkVersions; debuggingToolsInstalled = (Test-Path -LiteralPath $debuggerPath -PathType Leaf) }
    longPathsEnabled = $longPathsEnabled
    capacity = [pscustomobject]@{
      officialDocumentedMinimum = '8 GB RAM; 100 GB free NTFS disk (Chromium 150 Windows instructions)'
      freshBuildRequiredFreeBytes = $requiredFree
      buildVolumeFreeBytes = if ($drive) { [long]$drive.FreeSpace } else { 0 }
      outputVolumeFreeBytes = if ($outputDrive) { [long]$outputDrive.FreeSpace } else { 0 }
      additionalFreeBytesNeeded = if ($drive) { [Math]::Max([long]0, [long]($requiredFree - [long]$drive.FreeSpace)) } else { $requiredFree }
      recommendedRam = 'More than 16 GB; use limited parallel jobs on this 32 GB host.'
      capacityWarning = 'Actual archive extraction, source dependencies, SDK/toolchain and release output may exceed the documented minimum. Measure prepared source and available output capacity before compiling. A separate output volume can be selected explicitly; free space on unrelated volumes is not automatically pooled.'
    }
    errors = @($errors.ToArray())
    references = @('https://chromium.googlesource.com/chromium/src/+/150.0.7871.186/docs/windows_build_instructions.md')
    notes = @(
      'Default invocation is read-only: no downloads, installs, cleanup, global settings, customer profiles, or engine changes.',
      'This resource check does not prove a particular VS workload or SDK patch version is valid; the build runner checks exact tools before execution.',
      'Free capacity is per volume, not the sum of unrelated drives. No customer cache, installer, dist, or profile files are deleted.',
      'Windows SDK and Visual Studio require Microsoft installers. Existing installations may be reused; this script never installs or reconfigures them.'
      'If longPathsEnabled is not 1, the upstream Windows recipe long-path requirement is not met. This script only reports it; it does not modify the registry. Source preparation and build tools need a tested path-handling strategy.'
    )
  }
}

if ($MyInvocation.InvocationName -ne '.') {
  $report = Get-NativeBuildResources -Path $BuildRoot -OutputPath $OutRoot
  if ($AsObject) { $report } else { $report | ConvertTo-Json -Depth 8 }
}
