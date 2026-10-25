[CmdletBinding()]
param(
  [switch]$Build,
  [string]$BuildRoot = (Join-Path $PSScriptRoot '..\..\..\.cache\native-engine-build'),
  [string]$OutRoot,
  [string]$VisualStudioRoot,
  [string]$WindowsSdkRoot,
  [string]$Python,
  [ValidateSet('2026', '2022')][string]$VisualStudioVersion = '2026',
  [ValidateRange(1, 12)][int]$Jobs = 4
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'resource-preflight.ps1') -BuildRoot $BuildRoot -OutRoot $OutRoot

# Updated with the reviewed source manifest, never selected by a writable build
# receipt. A draft pin intentionally prevents execution before review is ready.
$ExpectedManifestSha256 = '0bf63619ff8d5bae8e3cd4fae65f7f0f0bb19543456a0c4dd331e7feb7880680'
$ExpectedChromiumRevision = '0fcdce5f4fdec8d442d7df760cb541f1ca6e446d'

function Read-NativeBuildManifest {
  $file = Join-Path $PSScriptRoot 'source-manifest.json'
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'SOURCE_MANIFEST_MISSING' }
  $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($sha -ne $ExpectedManifestSha256) { throw 'SOURCE_MANIFEST_NOT_REVIEWED_OR_CHANGED' }
  $manifest = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
  if ($manifest.schemaVersion -ne 1 -or $manifest.chromium.revision -ne $ExpectedChromiumRevision -or
      $manifest.chromium.version -ne '150.0.7871.186' -or $manifest.build.target -ne 'chrome') {
    throw 'SOURCE_MANIFEST_CONTRACT_INVALID'
  }
  foreach ($patch in $manifest.patches) {
    if ($patch.path -notmatch '^[A-Za-z0-9_./-]+\.patch$' -or $patch.path -match '(^|/)\.\.(/|$)' -or
        $patch.path.StartsWith('/') -or $patch.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'SOURCE_PATCH_PATH_INVALID' }
    $patchPath = Join-Path $PSScriptRoot $patch.path
    if ((Get-FileHash -LiteralPath $patchPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $patch.sha256) {
      throw ('SOURCE_PATCH_CHANGED: ' + $patch.path)
    }
  }
  return [pscustomobject]@{ manifest = $manifest; sha256 = $sha }
}

function Assert-NativeCommandPath {
  param([Parameter(Mandatory)][string]$Path)
  # All paths below become literal batch arguments. Refuse cmd expansion and
  # control characters; no Invoke-Expression or string-selected command runs.
  if ($Path -match '[^\x20-\x7e]' -or $Path -match '["%!?&|<>^]') { throw 'BUILD_COMMAND_PATH_UNSAFE: use an ASCII local path without cmd expansion characters.' }
}

function Assert-NativePreparedSource {
  param([string]$Root, $Reviewed)
  $receiptPath = Join-Path $Root '.mc-native-source.json'
  if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw 'PREPARED_SOURCE_RECEIPT_MISSING' }
  $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
  if ($receipt.schemaVersion -ne 1 -or $receipt.sourceReady -ne $true -or
      $receipt.sourceManifestSha256 -ne $Reviewed.sha256 -or $receipt.headChromium -ne $ExpectedChromiumRevision) {
    throw 'PREPARED_SOURCE_RECEIPT_INVALID'
  }
  $expected = @($Reviewed.manifest.patches | ForEach-Object { $_.path + ':' + $_.sha256 } | Sort-Object)
  $actual = @($receipt.patchesVerified | ForEach-Object { $_.path + ':' + $_.sha256 } | Sort-Object)
  if (($expected -join "`n") -cne ($actual -join "`n")) { throw 'PREPARED_SOURCE_PATCH_SET_MISMATCH' }
  $source = Join-Path $Root 'src'
  foreach ($file in @('BUILD.gn', '.gn', 'chrome\VERSION', 'tools\gn\bootstrap\bootstrap.py', 'third_party\ninja\ninja.exe',
      'third_party\llvm-build\Release+Asserts\bin\clang-cl.exe', 'third_party\rust-toolchain\bin\rustc.exe')) {
    $candidate = Join-Path $source $file
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw ('PREPARED_SOURCE_INCOMPLETE: ' + $file) }
    $null = Resolve-NativeBuildRoot -Path (Split-Path -Parent $candidate)
  }
  # A source archive has no .git HEAD to inspect. The preparation process must
  # record hashes of all altered source files; recheck those before compilation.
  if (-not $receipt.PSObject.Properties['preparedFiles'] -or @($receipt.preparedFiles).Count -eq 0) {
    throw 'PREPARED_SOURCE_FILE_HASHES_MISSING'
  }
  foreach ($file in $receipt.preparedFiles) {
    # Upstream source lists include @npm scopes, Unicode, spaces and commas.
    # These are literal file paths, never batch commands. Reject traversal,
    # alternate separators/streams and characters invalid in Windows filenames.
    if ($file.path -isnot [string] -or -not $file.path -or $file.path -match '[\\:\x00-\x1f\x7f<>|?*\"]' -or
        $file.path -match '(^|/)\.{1,2}(/|$)' -or $file.path.Contains('//') -or $file.path.StartsWith('/') -or
        $file.sha256 -notmatch '^[a-f0-9]{64}$') { throw 'PREPARED_FILE_PATH_INVALID' }
    $preparedPath = Join-Path $source $file.path
    $null = Resolve-NativeBuildRoot -Path (Split-Path -Parent $preparedPath)
    $preparedItem = Get-Item -LiteralPath $preparedPath -Force
    if ($preparedItem.PSIsContainer -or ($preparedItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PREPARED_FILE_PATH_UNSAFE' }
    if ((Get-FileHash -LiteralPath $preparedPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) {
      throw ('PREPARED_SOURCE_FILE_CHANGED: ' + $file.path)
    }
  }
  return $source
}

function New-NativeBuildMutex {
  param([Parameter(Mandatory)][string]$Output)
  $hasher = [Security.Cryptography.SHA256]::Create()
  try { $mutexKey = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($output.ToLowerInvariant()))).Replace('-', '').Substring(0, 24) }
  finally { $hasher.Dispose() }
  return [Threading.Mutex]::new($false, ('Local\MCProxyNativeBuild-' + $mutexKey))
}

function Invoke-NativeBrowserBuild {
  $root = Resolve-NativeBuildRoot -Path $BuildRoot
  $pauseMarker = Join-Path $root '.mc-native-paused.json'
  if (Test-Path -LiteralPath $pauseMarker) { throw 'NATIVE_BUILD_PAUSED: use build-control.ps1 -Action Resume.' }
  $output = if ($OutRoot) { Resolve-NativeBuildRoot -Path $OutRoot } else { Join-Path $root 'src\out\MCProxy' }
  $buildMutex = New-NativeBuildMutex -Output $output
  $ownsMutex = $false
  try {
  try { $ownsMutex = $buildMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
  if (-not $ownsMutex) { throw 'NATIVE_BUILD_ALREADY_RUNNING: output is owned by an active build.' }
  if ($root -match '\s') { throw 'BUILD_ROOT_MUST_NOT_CONTAIN_SPACES' }
  $resources = Get-NativeBuildResources -Path $root -OutputPath $OutRoot
  $reviewed = Read-NativeBuildManifest
  if ($reviewed.manifest.build.ready -ne $true) { throw 'SOURCE_PORT_NOT_READY: draft patches must not be built or activated.' }
  if ($resources.memoryBytes -lt 8GB -or $resources.errors.Count) { throw 'HOST_RESOURCE_VERIFICATION_FAILED' }
  $source = Assert-NativePreparedSource -Root $root -Reviewed $reviewed
  Assert-NativeCommandPath -Path $root
  Assert-NativeCommandPath -Path $output
  if ($output.Equals($source, [StringComparison]::OrdinalIgnoreCase) -or $source.StartsWith($output + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BUILD_OUTPUT_OVERLAPS_SOURCE'
  }
  $outputDrive = @($resources.drives | Where-Object { $_.DeviceID -eq [IO.Path]::GetPathRoot($output).TrimEnd('\') }) | Select-Object -First 1
  if (-not $outputDrive -or $outputDrive.FileSystem -ne 'NTFS' -or [long]$outputDrive.FreeSpace -lt 30000000000) {
    throw 'BUILD_OUTPUT_REQUIRES_AT_LEAST_30_GB_FREE_NTFS: this is a minimum guard, not a proven full-build estimate.'
  }
  $vsRoot = if ($VisualStudioRoot) { [IO.Path]::GetFullPath($VisualStudioRoot) }
    elseif ($resources.visualStudioLocations.Count) { $resources.visualStudioLocations[0] }
    else { Join-Path $root 'msvc' }
  $sdkRoot = if ($WindowsSdkRoot) { [IO.Path]::GetFullPath($WindowsSdkRoot) } else { $resources.windowsSdk.root }
  $pythonPath = if ($Python) { [IO.Path]::GetFullPath($Python) } else {
    Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
  }
  foreach ($value in @($vsRoot, $sdkRoot, $pythonPath)) { Assert-NativeCommandPath -Path $value }
  $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
  foreach ($file in @($vcvars, $pythonPath, (Join-Path $sdkRoot 'Include\10.0.26100.0\um\Windows.h'),
      (Join-Path $sdkRoot 'bin\10.0.26100.0\x64\rc.exe'),
      (Join-Path $sdkRoot 'Debuggers\x64\cdb.exe'))) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw ('BUILD_TOOLCHAIN_INCOMPLETE: ' + $file) }
  }
  foreach ($check in @(@('bin\10.0.26100.0\x64\rc.exe', '10.0.26100.7705'), @('Debuggers\x64\cdb.exe', '10.0.26100.3323'))) {
    $fileVersion = (Get-Item -LiteralPath (Join-Path $sdkRoot $check[0])).VersionInfo.FileVersion
    $matched = [regex]::Match($fileVersion, '\d+\.\d+\.\d+\.\d+')
    if (-not $matched.Success -or [version]$matched.Value -lt [version]$check[1]) { throw ('WINDOWS_SDK_PACKAGE_TOO_OLD_OR_UNVERIFIED: ' + $check[0]) }
  }
  $msvcVersionFile = Join-Path $vsRoot 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
  if (-not (Test-Path -LiteralPath $msvcVersionFile -PathType Leaf)) { throw 'VISUAL_STUDIO_CPP_WORKLOAD_MISSING' }
  $msvcVersion = (Get-Content -LiteralPath $msvcVersionFile -Raw).Trim()
  if ($msvcVersion -notmatch '^14\.\d+\.\d+$' -or
      -not (Test-Path -LiteralPath (Join-Path $vsRoot ('VC\Tools\MSVC\' + $msvcVersion + '\atlmfc\include\atlbase.h')) -PathType Leaf)) {
    throw 'VISUAL_STUDIO_ATL_MFC_COMPONENT_MISSING'
  }
  $version = & $pythonPath -c 'import sys; print("%d.%d" % sys.version_info[:2])'
  if ($LASTEXITCODE -ne 0 -or [version]$version -lt [version]'3.11') { throw 'BUILD_REQUIRES_PYTHON_3_11_OR_NEWER' }
  $outputMarker = Join-Path $output '.mc-native-output.json'
  if (Test-Path -LiteralPath $output) {
    if (-not (Test-Path -LiteralPath $outputMarker -PathType Leaf)) { throw 'OUTPUT_DIRECTORY_HAS_NO_OWNERSHIP_MARKER' }
    $owner = Get-Content -LiteralPath $outputMarker -Raw | ConvertFrom-Json
    if ($owner.sourceManifestSha256 -ne $reviewed.sha256 -or $owner.buildRoot -ne $root) { throw 'OUTPUT_OWNERSHIP_MISMATCH' }
  } else {
    $null = New-Item -ItemType Directory -Path $output
    [pscustomobject]@{ schemaVersion = 1; sourceManifestSha256 = $reviewed.sha256; buildRoot = $root } |
      ConvertTo-Json | Set-Content -LiteralPath $outputMarker -Encoding UTF8
  }
  $temp = Join-Path $root 'tmp'
  $null = New-Item -ItemType Directory -Path $temp -Force
  # Chromium's pinned .gn explicitly requests python3.exe or python3.bat.
  # Keep the bundled interpreter untouched; only this child build sees the shim.
  $pythonTools = Join-Path $root 'tools'
  $null = Resolve-NativeBuildRoot -Path $pythonTools
  $null = New-Item -ItemType Directory -Path $pythonTools -Force
  $pythonShim = Join-Path $pythonTools 'python3.bat'
  if ((Test-Path -LiteralPath $pythonShim) -and ((Get-Item -LiteralPath $pythonShim -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'BUILD_PYTHON_SHIM_PATH_UNSAFE'
  }
  $pythonShimText = '@echo off' + "`r`n" + '"' + $pythonPath + '" %*' + "`r`n" + 'exit /b %errorlevel%' + "`r`n"
  if ((Test-Path -LiteralPath $pythonShim) -and (Get-Content -LiteralPath $pythonShim -Raw) -cne $pythonShimText) {
    throw 'BUILD_PYTHON_SHIM_CHANGED: existing build tool was preserved.'
  }
  [IO.File]::WriteAllText($pythonShim, $pythonShimText, [Text.Encoding]::ASCII)
  $gn = Join-Path $output 'gn.exe'
  $ninja = Join-Path $source 'third_party\ninja\ninja.exe'
  $argsFile = Join-Path $output 'args.gn'
  @($reviewed.manifest.build.gnArgs) -join "`n" | Set-Content -LiteralPath $argsFile -Encoding UTF8
  $commandFile = Join-Path $root 'build-chrome.cmd'
  $pauseGate = 'if exist "' + $pauseMarker + '" exit /b 75'
  $command = @(
    '@echo off', 'setlocal', ('call "' + $vcvars + '" >nul'), 'if errorlevel 1 exit /b 1',
    'set "DEPOT_TOOLS_WIN_TOOLCHAIN=0"', ('set "vs' + $VisualStudioVersion + '_install=' + $vsRoot + '"'),
    ('set "GYP_MSVS_VERSION=' + $VisualStudioVersion + '"'), ('set "WINDOWSSDKDIR=' + $sdkRoot + '"'),
    ('set "TEMP=' + $temp + '"'), ('set "TMP=' + $temp + '"'),
    ('set "NINJA=' + $ninja + '"'),
    ('set "PATH=' + $pythonTools + ';' + (Split-Path -Parent $pythonPath) + ';' + (Split-Path -Parent $ninja) + ';%PATH%"'), ('cd /d "' + $source + '"'),
    $pauseGate, ('if not exist "' + $gn + '" "' + $pythonPath + '" tools\gn\bootstrap\bootstrap.py -o "' + $gn + '" --build-path "' + $output + '" -j ' + $Jobs + ' --skip-generate-buildfiles'),
    'if errorlevel 1 exit /b 1', $pauseGate, ('"' + $gn + '" gen "' + $output + '" --fail-on-unused-args'), 'if errorlevel 1 exit /b 1',
    $pauseGate, ('if not exist third_party\rust-toolchain\bin\bindgen.exe "' + $pythonPath + '" tools\rust\build_bindgen.py --skip-test'), 'if errorlevel 1 exit /b 1', $pauseGate,
    ('"' + $ninja + '" -C "' + $output + '" -j ' + $Jobs + ' chrome'), 'exit /b %errorlevel%'
  )
  $command -join "`r`n" | Set-Content -LiteralPath $commandFile -Encoding ASCII
  $log = Join-Path $root ('build-chrome-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.log')
  & $env:ComSpec /d /c $commandFile 2>&1 | Tee-Object -FilePath $log
  if ($LASTEXITCODE -ne 0) { throw ('CHROME_BUILD_FAILED: ' + $log) }
  $afterBuild = Read-NativeBuildManifest
  if ($afterBuild.sha256 -ne $reviewed.sha256) { throw 'SOURCE_MANIFEST_CHANGED_DURING_BUILD' }
  $builtFiles = @()
  foreach ($name in @('chrome.exe', 'chrome.dll')) {
    $file = Join-Path $output $name
    $item = Get-Item -LiteralPath $file -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'BUILD_OUTPUT_BINARY_PATH_UNSAFE' }
    $builtFiles += [pscustomobject]@{ path = $name; sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
  }
  $buildReceipt = [pscustomobject]@{ schemaVersion = 1; built = $true; activated = $false; packaged = $false;
    buildRoot = $root; output = $output; log = $log; completedAt = [DateTime]::UtcNow.ToString('o');
    sourceManifestSha256 = $reviewed.sha256; files = $builtFiles;
    preparedSourceReceiptSha256 = (Get-FileHash -LiteralPath (Join-Path $root '.mc-native-source.json') -Algorithm SHA256).Hash.ToLowerInvariant() }
  $buildReceipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root '.mc-native-build.json') -Encoding UTF8
  $buildReceipt | ConvertTo-Json -Depth 5
  } finally {
    if ($ownsMutex) { $buildMutex.ReleaseMutex() }
    $buildMutex.Dispose()
  }
}

if ($MyInvocation.InvocationName -ne '.') {
  if ($Build) { Invoke-NativeBrowserBuild }
  else {
    $report = Get-NativeBuildResources -Path $BuildRoot -OutputPath $OutRoot
    $manifestState = try { $reviewed = Read-NativeBuildManifest; [pscustomobject]@{ reviewed = $true; ready = $reviewed.manifest.build.ready; sha256 = $reviewed.sha256 } }
      catch { [pscustomobject]@{ reviewed = $false; ready = $false; error = $_.Exception.Message } }
    [pscustomobject]@{ mode = 'read-only-preflight'; resources = $report; source = $manifestState;
      action = 'Read-only mode never downloads. -Build requires prepared source and verified tools; its pinned upstream bindgen bootstrap can fetch public source/Cargo dependencies into the build tree. It never packages or activates a browser.' } | ConvertTo-Json -Depth 9
  }
}
