import { execFile as nodeExecFile } from 'node:child_process';
import { UserError } from './config.mjs';

const INPUT = 'PROXYPILOT_ENVIRONMENT_INPUT';
const stages = ['invoke', 'scopeHash', 'snapshot', 'defaultLanguage', 'mapTimeZone', 'mapHomeRegion', 'apply-validation', 'apply-timezone', 'apply-home-region', 'apply-language-list', 'apply-culture', 'apply-ui-language', 'apply-input-method', 'apply-culture-opt-out'];
const fields = ['timeZoneId', 'daylightSavingDisabled', 'homeGeoId', 'culture', 'uiLanguageOverride', 'languages', 'defaultInputMethod', 'cultureFromLanguageListOptOut'];
export function sanitizeEnvironmentDiagnostic(value) {
  const result = stages.includes(value?.environmentStage) ? { environmentStage: value.environmentStage } : {};
  for (const key of ['environmentFields', 'rollbackEnvironmentFields']) {
    const names = Array.isArray(value?.[key]) ? fields.filter(field => value[key].includes(field)) : [];
    if (names.length) result[key] = names;
  }
  return Object.keys(result).length ? result : null;
}
const failureMessages = {
  ENVIRONMENT_WINDOWS_FAILED: 'Windows 环境操作失败，请检查权限和语言支持；原始快照已保留',
  ENVIRONMENT_PERMISSION_DENIED: 'Windows 拒绝环境操作权限；请检查权限，原始快照已保留',
  ENVIRONMENT_TIMEOUT: 'Windows 环境操作超时；实际设置将重新检查，原始快照已保留',
};
function failure(code = 'ENVIRONMENT_WINDOWS_FAILED', diagnostic) {
  const error = new UserError(code, failureMessages[code]);
  error.diagnostic = sanitizeEnvironmentDiagnostic(diagnostic) || { environmentStage: 'invoke' };
  return error;
}
function validApplyTarget(value) {
  const tag = item => typeof item === 'string' && /^[a-z]{2,3}(?:-[a-zA-Z0-9]{2,8}){0,3}$/.test(item);
  const tip = item => typeof item === 'string' && /^[a-fA-F0-9:{}-]{1,120}$/.test(item);
  return value && typeof value === 'object' && !Array.isArray(value)
    && typeof value.timeZoneId === 'string' && /^[A-Za-z0-9 .()+-]{1,80}$/.test(value.timeZoneId)
    && typeof value.daylightSavingDisabled === 'boolean' && tag(value.culture)
    && (value.uiLanguageOverride === null || tag(value.uiLanguageOverride))
    && (value.defaultInputMethod === null || tip(value.defaultInputMethod)) && typeof value.cultureFromLanguageListOptOut === 'boolean'
    && (value.homeGeoId === undefined || (Number.isInteger(value.homeGeoId) && value.homeGeoId >= 0 && value.homeGeoId <= 2147483647))
    && Array.isArray(value.languages) && value.languages.length > 0 && value.languages.length <= 100
    && value.languages.every(item => tag(item?.languageTag) && typeof item.handwriting === 'boolean' && Array.isArray(item.inputMethodTips) && item.inputMethodTips.length <= 100 && item.inputMethodTips.every(tip));
}
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROXYPILOT_ENVIRONMENT_INPUT)) | ConvertFrom-Json
function Language($item) {
  return @{languageTag=[string]$item.LanguageTag;inputMethodTips=@($item.InputMethodTips);handwriting=[bool]$item.Handwriting}
}
function LanguageIdentity($tag) {
  return ([string]$tag).ToLowerInvariant() -replace '^zh-hans-(cn|sg)$','zh-$1' -replace '^zh-hant-(tw|hk|mo)$','zh-$1'
}
function InputTipsIdentity($tips) {
  return (@($tips | ForEach-Object { ([string]$_).ToUpperInvariant() } | Sort-Object -Unique) -join '|')
}
function SameLanguages($left, $right) {
  if (@($left).Count -ne @($right).Count) { return $false }
  for ($i = 0; $i -lt @($left).Count; $i++) {
    if ((LanguageIdentity $left[$i].languageTag) -cne (LanguageIdentity $right[$i].languageTag) -or $left[$i].handwriting -ne $right[$i].handwriting -or
        (InputTipsIdentity $left[$i].inputMethodTips) -cne (InputTipsIdentity $right[$i].inputMethodTips)) { return $false }
  }
  return $true
}
function BuildLanguages($languages) {
  if (@($languages).Count -lt 1 -or @($languages).Count -gt 100) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
  $list = New-WinUserLanguageList -Language ([string]$languages[0].languageTag)
  $list.Clear()
  foreach ($language in $languages) {
    $entry = (New-WinUserLanguageList -Language ([string]$language.languageTag))[0]
    $entry.InputMethodTips.Clear()
    foreach ($tip in $language.inputMethodTips) { $entry.InputMethodTips.Add([string]$tip) }
    $entry.Handwriting = [bool]$language.handwriting
    $list.Add($entry)
  }
  return ,$list
}
function ErrorCode($record) {
  if ([string]$record.CategoryInfo.Category -in @('PermissionDenied','SecurityError')) { return 'ENVIRONMENT_PERMISSION_DENIED' }
  $exception = $record.Exception
  while ($null -ne $exception) {
    if ($exception -is [UnauthorizedAccessException] -or $exception.HResult -eq -2147024891) { return 'ENVIRONMENT_PERMISSION_DENIED' }
    $exception = $exception.InnerException
  }
  return 'ENVIRONMENT_WINDOWS_FAILED'
}
function ApplyStep($field, $step, [scriptblock]$action) {
  $script:stage = $step
  try { & $action | Out-Null }
  catch {
    if (-not $request.bestEffort) { throw }
    $script:failures.Add(@{field=$field;code=(ErrorCode $_);environmentStage=$step})
  }
}
function SavedCulture {
  $international = Get-ItemProperty -LiteralPath 'HKCU:\Control Panel\International'
  $locale = [string]$international.Locale
  if ($locale -notmatch '^[0-9a-fA-F]{4,8}$') { throw 'ENVIRONMENT_WINDOWS_FAILED' }
  $lcid = [Convert]::ToInt32($locale, 16)
  $named = $null
  if ($international.LocaleName) {
    try { $named = [Globalization.CultureInfo]::GetCultureInfo([string]$international.LocaleName) } catch {}
  }
  # Set-Culture can update Locale and date/number formats while leaving the
  # optional LocaleName stale. Prefer a matching name; otherwise resolve the
  # persisted standard LCID, never the calling process's cached Get-Culture.
  # Custom locales share an LCID and must retain their actual locale name.
  if ($lcid -in @(0x1000, 0x0c00, 0x1400)) {
    if (-not $named -or -not $named.Name -or $named.LCID -notin @(0x1000, 0x0c00, 0x1400)) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
    return $named.Name
  }
  if ($lcid -in @(0, 0x007f, 0x0400, 0x0800)) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
  if ($named -and $named.LCID -eq $lcid -and $named.Name) { return $named.Name }
  $resolved = [Globalization.CultureInfo]::GetCultureInfo($lcid)
  if (-not $resolved.Name) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
  return $resolved.Name
}
function HomeCountryCode($geoId) {
  # CurrentRegion follows the culture, not Windows' independent home location.
  # Reverse only known country identities; never invent a country for an
  # unassigned or aggregate GeoID. This reads in-memory .NET locale metadata.
  if ($geoId -le 0) { return $null }
  foreach ($culture in [Globalization.CultureInfo]::GetCultures([Globalization.CultureTypes]::SpecificCultures)) {
    try {
      $region = New-Object Globalization.RegionInfo($culture.Name)
      if ($region.GeoId -eq $geoId -and $region.TwoLetterISORegionName -cmatch '^[A-Z]{2}$') { return [string]$region.TwoLetterISORegionName }
    } catch {}
  }
  return $null
}
function Snapshot {
  $ui = Get-WinUILanguageOverride
  $defaultInput = Get-WinDefaultInputMethodOverride
  $languageList = Get-WinUserLanguageList
  # Get-Culture describes this process's CultureInfo, which can remain cached
  # after Set-Culture. Verify the persisted current-user locale independently;
  # retain the process observation so delayed activation is never hidden.
  $savedCulture = SavedCulture
  $fonts = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts'
  $fontNames = @($fonts.PSObject.Properties.Name)
  $homeGeoId = [int](Get-WinHomeLocation).GeoId
  return @{
    timeZoneId=[string](Get-TimeZone).Id
    daylightSavingDisabled=[bool](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation').DynamicDaylightTimeDisabled
    homeGeoId=$homeGeoId
    homeCountryCode=(HomeCountryCode $homeGeoId)
    culture=$savedCulture
    activeCulture=[string](Get-Culture).Name
    uiLanguageOverride=$(if ($ui) { [string]$ui.Name } else { $null })
    # The cmdlet emits its List<WinUserLanguage> as one pipeline object. foreach
    # enumerates entries without merging language tags or input methods.
    languages=@(foreach ($language in $languageList) { Language $language })
    defaultInputMethod=$(if ($defaultInput) { [string]$defaultInput.InputMethodTip } else { $null })
    cultureFromLanguageListOptOut=[bool](Get-WinCultureFromLanguageListOptOut)
    installedUiLanguages=@(Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages' | ForEach-Object { $_.PSChildName })
    fonts=@{segoeUI=[bool]($fontNames -match '^Segoe UI ');microsoftYaHei=[bool]($fontNames -match 'Microsoft YaHei');simSun=[bool]($fontNames -match 'SimSun')}
  }
}
try {
  $stage = [string]$request.operation
  $value = $null
  switch ($request.operation) {
    'scopeHash' {
      $machine = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
      $user = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
      if (-not $machine -or -not $user) { throw 'ENVIRONMENT_IDENTITY_UNAVAILABLE' }
      $hash = [Security.Cryptography.SHA256]::Create()
      try { $value = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($machine.ToLowerInvariant() + ':' + $user))).Replace('-','').ToLowerInvariant() }
      finally { $hash.Dispose() }
    }
    'snapshot' { $value = Snapshot }
    'defaultLanguage' { $value = Language (New-WinUserLanguageList -Language ([string]$request.language))[0] }
    'mapTimeZone' {
      $mapped = $null
      if ([TimeZoneInfo].GetMethods().Name -contains 'TryConvertIanaIdToWindowsId') {
        if ([TimeZoneInfo]::TryConvertIanaIdToWindowsId([string]$request.iana, [ref]$mapped)) { $value = $mapped }
      }
    }
    'mapHomeRegion' {
      $country = [string]$request.countryCode
      if ($country -cnotmatch '^[A-Z]{2}$') { throw 'ENVIRONMENT_WINDOWS_FAILED' }
      $region = New-Object Globalization.RegionInfo($country)
      if ($region.TwoLetterISORegionName -cne $country -or $region.GeoId -le 0) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
      $value = [int]$region.GeoId
    }
    'apply' {
      $stage = 'apply-validation'
      $target = $request.target
      $script:failures = New-Object 'Collections.Generic.List[object]'
      # Strict callers retain prevalidation. Explicit best-effort actions validate
      # each independent setting in its own step, so one unsupported language
      # cannot prevent a valid time zone, country or regional format from applying.
      if (-not $request.bestEffort) {
        [void][TimeZoneInfo]::FindSystemTimeZoneById([string]$target.timeZoneId)
        [void][Globalization.CultureInfo]::GetCultureInfo([string]$target.culture)
        [void](BuildLanguages $target.languages)
        if ($null -ne $target.homeGeoId -and ($target.homeGeoId -isnot [int] -or $target.homeGeoId -lt 0)) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
      }
      $before = Snapshot
      $languageChanged = -not (SameLanguages $before.languages $target.languages)
      $uiChanged = $before.uiLanguageOverride -cne $target.uiLanguageOverride
      $cultureChanged = $before.culture -cne $target.culture
      $optOutChanged = $before.cultureFromLanguageListOptOut -ne $target.cultureFromLanguageListOptOut
      if ($before.timeZoneId -ne $target.timeZoneId -or $before.daylightSavingDisabled -ne $target.daylightSavingDisabled) {
        ApplyStep 'timeZoneId' 'apply-timezone' {
          [void][TimeZoneInfo]::FindSystemTimeZoneById([string]$target.timeZoneId)
          $zoneArgument = [string]$target.timeZoneId
          if ($target.daylightSavingDisabled) { $zoneArgument += '_dstoff' }
          & tzutil.exe /s $zoneArgument 2>&1 | Out-Null
          if ($LASTEXITCODE -ne 0) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
        }
      }
      if ($null -ne $target.homeGeoId -and $before.homeGeoId -ne $target.homeGeoId) {
        ApplyStep 'homeGeoId' 'apply-home-region' {
          if ($target.homeGeoId -isnot [int] -or $target.homeGeoId -lt 0) { throw 'ENVIRONMENT_WINDOWS_FAILED' }
          Set-WinHomeLocation -GeoId ([int]$target.homeGeoId)
        }
      }
      # Display-language changes can reassign Culture when opt-out is false.
      # Shield the transition, restore the requested opt-out, then write Culture
      # last. A separate snapshot process still verifies every requested value.
      if (($languageChanged -or $uiChanged) -and -not $before.cultureFromLanguageListOptOut) {
        ApplyStep 'cultureFromLanguageListOptOut' 'apply-culture-opt-out' { Set-WinCultureFromLanguageListOptOut -OptOut $true }
      }
      if ($languageChanged) {
        ApplyStep 'languages' 'apply-language-list' { Set-WinUserLanguageList -LanguageList (BuildLanguages $target.languages) -Force }
      }
      if ($uiChanged) {
        ApplyStep 'uiLanguageOverride' 'apply-ui-language' {
          if ($null -eq $target.uiLanguageOverride) { Set-WinUILanguageOverride } else { Set-WinUILanguageOverride -Language ([string]$target.uiLanguageOverride) }
        }
      }
      ApplyStep 'defaultInputMethod' 'apply-input-method' {
        $currentInput = Get-WinDefaultInputMethodOverride
        $currentInputTip = $(if ($currentInput) { [string]$currentInput.InputMethodTip } else { $null })
        if ($currentInputTip -ine $target.defaultInputMethod) {
          if ($null -ne $target.defaultInputMethod) {
            Set-WinDefaultInputMethodOverride -InputTip ([string]$target.defaultInputMethod)
          } else {
            Set-WinDefaultInputMethodOverride
            # Some Windows versions leave the previous override after a no-argument
            # setter. Restore absence of this one value, preserving the profile key.
            if ($null -ne (Get-WinDefaultInputMethodOverride)) {
              Remove-ItemProperty -LiteralPath 'HKCU:\Control Panel\International\User Profile' -Name InputMethodOverride -ErrorAction Stop
            }
          }
        }
      }
      ApplyStep 'cultureFromLanguageListOptOut' 'apply-culture-opt-out' {
        if ((Get-WinCultureFromLanguageListOptOut) -ne $target.cultureFromLanguageListOptOut) {
          Set-WinCultureFromLanguageListOptOut -OptOut ([bool]$target.cultureFromLanguageListOptOut)
        }
      }
      if ($cultureChanged -or $languageChanged -or $uiChanged -or $optOutChanged) {
        ApplyStep 'culture' 'apply-culture' {
          [void][Globalization.CultureInfo]::GetCultureInfo([string]$target.culture)
          Set-Culture -CultureInfo ([string]$target.culture)
        }
      }
      $value = @{applied=$true}
      if ($request.bestEffort) { $value = @{applied=($script:failures.Count -eq 0); failures=@($script:failures.ToArray())} }
    }
    default { throw 'ENVIRONMENT_OPERATION_INVALID' }
  }
  ConvertTo-Json -InputObject @{ok=$true;value=$value} -Depth 12 -Compress
} catch {
  $code = ErrorCode $_
  ConvertTo-Json -InputObject @{ok=$false;code=$code;diagnostic=@{environmentStage=$stage}} -Compress
}
`;
// Windows limits the entire command line to 32,767 characters. This fixed
// script has no here-strings or multiline string literals: remove only blank
// lines, comment-only lines and surrounding indentation before base64 encoding.
const ENCODED_SCRIPT = Buffer.from(SCRIPT.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#')).join('\n'), 'utf16le').toString('base64');

export function createWindowsEnvironmentAdapter({ platform = process.platform, execFile = nodeExecFile } = {}) {
  async function call(request) {
    if (platform !== 'win32') throw new UserError('PLATFORM_UNSUPPORTED', '环境管理需要 Windows');
    const raw = await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', ENCODED_SCRIPT], {
      env: { ...process.env, [INPUT]: Buffer.from(JSON.stringify(request)).toString('base64') }, encoding: 'utf8', windowsHide: true, timeout: 60000, maxBuffer: 1024 * 1024,
    }, (error, stdout) => {
      if (!error) return resolve(stdout);
      const code = ['EACCES','EPERM'].includes(error.code) ? 'ENVIRONMENT_PERMISSION_DENIED'
        : error.code === 'ETIMEDOUT' || (error.killed && error.code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER') ? 'ENVIRONMENT_TIMEOUT' : 'ENVIRONMENT_WINDOWS_FAILED';
      reject(failure(code));
    }));
    let result;
    try { result = JSON.parse(raw.replace(/^\uFEFF/, '').trim()); } catch { /* fail closed */ }
    if (result?.ok !== true) throw failure(Object.hasOwn(failureMessages, result?.code) ? result.code : 'ENVIRONMENT_WINDOWS_FAILED', result?.diagnostic);
    return result.value;
  }
  return {
    scopeHash: () => call({ operation: 'scopeHash' }), snapshot: () => call({ operation: 'snapshot' }),
    defaultLanguage: language => call({ operation: 'defaultLanguage', language }), mapTimeZone: iana => call({ operation: 'mapTimeZone', iana }),
    mapHomeRegion: async countryCode => {
      if (typeof countryCode !== 'string' || !/^[A-Z]{2}$/.test(countryCode)) throw failure();
      const value = await call({ operation: 'mapHomeRegion', countryCode });
      if (!Number.isInteger(value) || value <= 0 || value > 2147483647) throw failure();
      return value;
    },
    apply: async (target, { bestEffort = false } = {}) => {
      if (!validApplyTarget(target)) throw failure();
      const value = await call({ operation: 'apply', target, ...(bestEffort === true ? { bestEffort: true } : {}) });
      if (bestEffort !== true) return value;
      if (!value || typeof value.applied !== 'boolean' || !Array.isArray(value.failures) || value.failures.length > 16 || value.applied !== (value.failures.length === 0) || value.failures.some(item => !fields.includes(item?.field) || !Object.hasOwn(failureMessages, item?.code) || !stages.includes(item?.environmentStage))) throw failure();
      return { applied: value.applied, failures: value.failures.map(({ field, code, environmentStage }) => ({ field, code, environmentStage })) };
    },
  };
}
