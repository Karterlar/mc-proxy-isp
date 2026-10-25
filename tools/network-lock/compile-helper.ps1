[CmdletBinding()]
param([switch]$SelfTest)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$source = Join-Path $repo 'backend\native\NetworkLock.cs'
$outputDirectory = Join-Path $repo 'backend\.cache\network-lock'
$output = Join-Path $outputDirectory 'MCProxy.NetworkLock.exe'
$provenance = Join-Path $outputDirectory 'provenance.json'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
function Assert-PlainPath([string]$Path, [bool]$Directory) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not ($full -eq $repo -or $full.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'NETWORK_LOCK_BUILD_PATH_INVALID' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.LinkType) { throw 'NETWORK_LOCK_BUILD_PATH_INVALID' }
            if ($current -eq $full -and [bool]$item.PSIsContainer -ne $Directory) { throw 'NETWORK_LOCK_BUILD_PATH_INVALID' }
        }
        $parent = [IO.Directory]::GetParent($current)
        if (-not $parent) { break }
        $current = $parent.FullName
    }
}
Assert-PlainPath $source $false
if ((Get-Item -LiteralPath $source).Length -gt 1MB) { throw 'NETWORK_LOCK_BUILD_SOURCE_INVALID' }
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'NETWORK_LOCK_BUILD_COMPILER_UNAVAILABLE' }
foreach ($directory in @((Join-Path $repo 'backend\.cache'), $outputDirectory)) {
    Assert-PlainPath $directory $true
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory | Out-Null }
    Assert-PlainPath $directory $true
}
Assert-PlainPath $output $false
Assert-PlainPath $provenance $false
$temporary = Join-Path $outputDirectory ('build-' + [Guid]::NewGuid().ToString('N') + '.exe')
$temporaryProvenance = Join-Path $outputDirectory ('provenance-' + [Guid]::NewGuid().ToString('N') + '.json')
try {
    & $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.ServiceProcess.dll ('/out:' + $temporary) $source
    if ($LASTEXITCODE -ne 0) { throw 'NETWORK_LOCK_BUILD_FAILED' }
    $selfTestResult = & $temporary --self-test
    if ($LASTEXITCODE -ne 0 -or -not $selfTestResult) { throw 'NETWORK_LOCK_BUILD_SELF_TEST_FAILED' }
    $parsed = $selfTestResult | ConvertFrom-Json
    if ($parsed.ok -ne $true -or $parsed.value.selfTest -ne $true -or $parsed.value.mutationCalls -ne 0) { throw 'NETWORK_LOCK_BUILD_SELF_TEST_FAILED' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceHash) { throw 'NETWORK_LOCK_BUILD_SOURCE_CHANGED' }
    Assert-PlainPath $output $false
    if (Test-Path -LiteralPath $output) { [IO.File]::Replace($temporary, $output, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $output) }
    $record = [ordered]@{ version=1; source='backend/native/NetworkLock.cs'; sourceSha256=$sourceHash; helper='MCProxy.NetworkLock.exe'; helperSha256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant(); target='x64'; framework='net48'; protocolVersion=1; selfTest=@{ passed=$true; bootProtected=$false } }
    [IO.File]::WriteAllText($temporaryProvenance, ($record | ConvertTo-Json -Depth 4 -Compress) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Assert-PlainPath $provenance $false
    if (Test-Path -LiteralPath $provenance) { [IO.File]::Replace($temporaryProvenance, $provenance, [NullString]::Value) }
    else { [IO.File]::Move($temporaryProvenance, $provenance) }
    if ($SelfTest) { $selfTestResult } else { @{ built=$true; selfTest=$true; mutationCalls=0 } | ConvertTo-Json -Compress }
} finally {
    if (Test-Path -LiteralPath $temporary) { Assert-PlainPath $temporary $false; Remove-Item -LiteralPath $temporary -Force }
    if (Test-Path -LiteralPath $temporaryProvenance) { Assert-PlainPath $temporaryProvenance $false; Remove-Item -LiteralPath $temporaryProvenance -Force }
}
