import path from 'node:path';
import { lstat, readFile, realpath, rm, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { createWindowsEnvironmentAdapter, sanitizeEnvironmentDiagnostic } from './windows-environment.mjs';
import { WINDOWS_TIME_ZONES, localeForGeo } from './environment-regions.mjs';
import { createEnvironmentProfiles, defaultEnvironmentPreferences, ENVIRONMENT_PRESETS, ENVIRONMENT_TIME_ZONES } from './environment-profiles.mjs';
import { UserError } from './config.mjs';

const fail = (code, message, diagnostic) => { const error = new UserError(code, message); if (diagnostic) error.diagnostic = diagnostic; throw error; };
const clone = value => structuredClone(value);
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const fields = ['timeZoneId', 'daylightSavingDisabled', 'culture', 'uiLanguageOverride', 'languages', 'defaultInputMethod', 'cultureFromLanguageListOptOut', 'homeGeoId'];
const signOutFields = ['uiLanguageOverride', 'languages', 'defaultInputMethod'];
const settings = snapshot => Object.fromEntries(fields.filter(key => snapshot[key] !== undefined).map(key => [key, snapshot[key]]));
const normalizedTips = tips => [...new Set(tips.map(tip => tip.toLowerCase()))].sort();
const normalizedLanguages = list => list.map(item => ({ ...item, languageTag: languageIdentity(item.languageTag), inputMethodTips: normalizedTips(item.inputMethodTips) }));
const fieldEqual = (field, left, right) => field === 'languages' ? equal(normalizedLanguages(left), normalizedLanguages(right))
  : ['culture', 'uiLanguageOverride'].includes(field) ? (left === null || right === null ? left === right : languageIdentity(left) === languageIdentity(right))
  : field === 'defaultInputMethod' ? left?.toLowerCase() === right?.toLowerCase() : equal(left, right);
const differentSettings = (observed, target) => fields.filter(field => target[field] !== undefined && !fieldEqual(field, observed[field], target[field]));
const fixedFields = value => Array.isArray(value) ? fields.filter(field => value.includes(field)) : [];
const validTag = tag => typeof tag === 'string' && /^[a-z]{2,3}(?:-[a-zA-Z0-9]{2,8}){0,3}$/.test(tag);
const languageIdentity = tag => tag.toLowerCase().replace(/^zh-hans-(cn|sg)$/, 'zh-$1').replace(/^zh-hant-(tw|hk|mo)$/, 'zh-$1');
const optimizationErrors = {
  EXIT_GEO_UNVERIFIED: '出口位置证据不足，未调整系统设置。',
  GEO_UNVERIFIED: '无法可靠确认出口国家、城市和时区，未调整系统设置。',
  TIMEZONE_UNSUPPORTED: '出口时区没有可靠的 Windows 映射，该项保持原样；其他项目仍可应用。',
  ENVIRONMENT_STATE_INVALID: '环境快照或语言输入法信息无效，请保留备份后检查。',
  ENVIRONMENT_SNAPSHOT_INVALID: '本机时区、语言或输入法快照格式无效，未更改系统设置或覆盖环境备份。',
  ENVIRONMENT_WINDOWS_FAILED: 'Windows 环境操作失败，请检查权限和语言支持。',
  ENVIRONMENT_PERMISSION_DENIED: 'Windows 拒绝环境操作权限，未完整应用设置；请检查权限，原始快照已保留。',
  ENVIRONMENT_TIMEOUT: 'Windows 环境操作超时；已完成的设置保留，请查看逐项结果后重试。',
  ENVIRONMENT_VERIFY_FAILED: '部分环境设置尚未匹配；已成功的设置保留，可直接重试未完成项目。',
  ENVIRONMENT_PARTIAL: '部分环境设置尚未匹配；已成功的设置保留，可重新应用。',
  ENVIRONMENT_DAILY_REQUIRED: '请先保存日常环境方案，再恢复日常环境；原始快照可在高级恢复中使用。',
  ENVIRONMENT_PROFILE_INVALID: '环境方案无法读取，请检查已保存的设置；高级原始快照恢复仍可使用。',
  ENVIRONMENT_PROFILE_FOREIGN: '环境方案属于其他电脑或 Windows 用户，未应用该方案。',
  ENVIRONMENT_PROFILE_CONFLICT: '环境方案已被其他窗口修改，请重新检查后再保存。',
  ENVIRONMENT_RESTORE_REQUIRED: '上次环境操作未完成，原始快照已保留；可手动重新应用出口环境，或还原初始环境；代理连接可继续。',
  ENVIRONMENT_CONFLICT: '环境设置或恢复记录已发生变化；可手动重新应用出口环境，或还原初始环境。恢复记录冲突时请退出其他 MC Proxy 实例后重试。',
  ENVIRONMENT_BACKUP_DRIFT: '当前环境与初始快照不同；可手动重新应用出口环境，或还原初始环境；原始快照保持不变。',
  ENVIRONMENT_BACKUP_FOREIGN: '环境备份来自其他电脑或 Windows 用户；请重建本机快照，旧设置不会应用到本机。',
  ENVIRONMENT_BACKUP_UNBOUND: '旧环境备份没有设备身份信息；请重建本机快照，旧恢复记录将保留归档。',
  ENVIRONMENT_IDENTITY_UNAVAILABLE: '无法确认当前电脑和 Windows 用户身份，未修改环境备份或系统设置。',
  ENVIRONMENT_REBUILD_REQUIRED: '请明确重建本机环境快照；旧记录将归档，不会应用到本机。',
  ENVIRONMENT_PATH_INVALID: '环境备份路径异常，未继续优化。',
};
function validateLanguage(item) {
  if (!validTag(item?.languageTag) || !Array.isArray(item.inputMethodTips) || item.inputMethodTips.some(tip => typeof tip !== 'string' || !/^[a-fA-F0-9:{}-]{1,120}$/.test(tip)) || typeof item.handwriting !== 'boolean') fail('ENVIRONMENT_STATE_INVALID', '语言或输入法快照无效');
  return item;
}
function validateSnapshot(value) {
  if (!value || typeof value.timeZoneId !== 'string' || !/^[A-Za-z0-9 .()+-]{1,80}$/.test(value.timeZoneId) || typeof value.daylightSavingDisabled !== 'boolean' || !validTag(value.culture) || (value.uiLanguageOverride !== null && !validTag(value.uiLanguageOverride)) || !Array.isArray(value.languages) || !value.languages.length || value.languages.length > 100 || typeof value.cultureFromLanguageListOptOut !== 'boolean') fail('ENVIRONMENT_STATE_INVALID', '环境快照无效，请保留备份后人工检查');
  for (const item of value.languages) validateLanguage(item);
  if (value.defaultInputMethod !== null && (typeof value.defaultInputMethod !== 'string' || !/^[a-fA-F0-9:{}-]{1,120}$/.test(value.defaultInputMethod))) fail('ENVIRONMENT_STATE_INVALID', '默认输入法快照无效');
  if (!Array.isArray(value.installedUiLanguages) || value.installedUiLanguages.some(tag => !validTag(tag))) fail('ENVIRONMENT_STATE_INVALID', '已安装语言信息无效');
  if (value.activeCulture !== undefined && !validTag(value.activeCulture)) fail('ENVIRONMENT_STATE_INVALID', '检测进程区域格式无效');
  if (value.homeGeoId !== undefined && (!Number.isInteger(value.homeGeoId) || value.homeGeoId < 0 || value.homeGeoId > 0x7fffffff)) fail('ENVIRONMENT_STATE_INVALID', '国家和地区信息无效');
  return value;
}
export function createMockEnvironmentAdapter() {
  const geoIds = { CN: 45, TW: 237, US: 244, JP: 122, KR: 134, SG: 215, HK: 104, GB: 242, DE: 94, CA: 39, AU: 12, FR: 84 };
  let current = { timeZoneId: 'Taipei Standard Time', daylightSavingDisabled: false, culture: 'zh-CN', homeGeoId: 45, homeCountryCode: 'CN', uiLanguageOverride: null, languages: [{ languageTag: 'zh-Hans-CN', inputMethodTips: ['0804:00000804'], handwriting: false }], defaultInputMethod: null, cultureFromLanguageListOptOut: false, installedUiLanguages: ['zh-CN', 'en-US', 'ja-JP', 'fr-FR', 'fr-CA', 'de-DE'], fonts: { segoeUI: true, microsoftYaHei: true, simSun: true } };
  return { scopeHash: async () => 'a'.repeat(64), snapshot: async () => clone(current), apply: async target => { current = { ...current, ...clone(target) }; current.homeCountryCode = Object.keys(geoIds).find(code => geoIds[code] === current.homeGeoId) || null; }, defaultLanguage: async languageTag => ({ languageTag, inputMethodTips: [], handwriting: false }), mapTimeZone: async iana => WINDOWS_TIME_ZONES[iana] || null, mapHomeRegion: async code => geoIds[code] ?? null };
}

export function createEnvironmentManager({ stateDir, adapter, mock = false, now = Date.now, writeArchive = writePrivate } = {}) {
  if (!mock && (!stateDir || !path.isAbsolute(stateDir))) fail('ENVIRONMENT_PATH_INVALID', '环境备份目录必须为绝对路径');
  const root = stateDir ? path.resolve(stateDir) : null;
  const stateFile = root && path.join(root, 'state.json');
  const windows = mock ? createMockEnvironmentAdapter() : (adapter || createWindowsEnvironmentAdapter());
  let optimization = { status: 'not-requested' };
  let loaded = false; let record = null; let recordBytes = null; let scopeHash = null; let cached = { status: 'unchecked', ownership: 'none', canRefresh: true, canAdoptCurrent: false, needsCheck: true, current: null, snapshot: null, backup: null, warnings: [], optimization, mock };
  let serial = Promise.resolve();
  let preferences = defaultEnvironmentPreferences();
  let profileError = null;
  const profiles = createEnvironmentProfiles({ stateDir: root, scopeHash: currentScope, mock });
  const locked = action => { const task = serial.then(action, action); serial = task.catch(() => {}); return task; };
  const ownership = () => !record ? 'none' : record.version === 1 ? 'unbound' : record.scopeHash === scopeHash ? 'matched' : 'foreign';
  async function currentScope() {
    if (scopeHash) return scopeHash;
    try {
      const value = await windows.scopeHash?.();
      if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('identity');
      scopeHash = value;
      cached = { ...cached, canAdoptCurrent: true };
      return value;
    } catch {
      cached = { ...cached, status: 'error', canRefresh: false, canAdoptCurrent: false, needsCheck: true, warnings: [optimizationErrors.ENVIRONMENT_IDENTITY_UNAVAILABLE] };
      fail('ENVIRONMENT_IDENTITY_UNAVAILABLE', optimizationErrors.ENVIRONMENT_IDENTITY_UNAVAILABLE);
    }
  }
  function validateRecord(value) {
    if (![1, 2].includes(value?.version) || typeof value.backup?.id !== 'string' || !/^[a-f0-9-]{36}$/.test(value.backup.id) || (value.version === 2 && (typeof value.scopeHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.scopeHash)))) fail('ENVIRONMENT_STATE_INVALID', '环境恢复记录无效，请保留备份后检查');
    validateSnapshot(value.backup.snapshot);
    if (value.lastApplied) validateSnapshot(value.lastApplied);
    if (value.lastObserved) validateSnapshot(value.lastObserved);
    if (value.pending) { validateSnapshot(value.pending.before); validateSnapshot(value.pending.target); }
    if (value.optimization?.target !== undefined) {
      if (!value.optimization.target || typeof value.optimization.target !== 'object' || Array.isArray(value.optimization.target)) fail('ENVIRONMENT_STATE_INVALID', '已保存的环境目标无效');
      validateSnapshot({ ...value.backup.snapshot, ...settings(value.optimization.target) });
    }
    if (value.supplementalOriginalSettings && (Object.keys(value.supplementalOriginalSettings).some(key => key !== 'homeGeoId') || !Number.isInteger(value.supplementalOriginalSettings.homeGeoId) || value.supplementalOriginalSettings.homeGeoId < 0 || value.supplementalOriginalSettings.homeGeoId > 0x7fffffff)) fail('ENVIRONMENT_STATE_INVALID', '新增地区设置的恢复记录无效');
    return value;
  }
  function requireOwned() {
    const own = ownership();
    if (own === 'foreign' || own === 'unbound') fail(own === 'foreign' ? 'ENVIRONMENT_BACKUP_FOREIGN' : 'ENVIRONMENT_BACKUP_UNBOUND', optimizationErrors[own === 'foreign' ? 'ENVIRONMENT_BACKUP_FOREIGN' : 'ENVIRONMENT_BACKUP_UNBOUND']);
  }
  async function readCurrentSnapshot() {
    const value = await windows.snapshot();
    try { return validateSnapshot(value); }
    catch (cause) {
      if (cause.code !== 'ENVIRONMENT_STATE_INVALID') throw cause;
      fail('ENVIRONMENT_SNAPSHOT_INVALID', optimizationErrors.ENVIRONMENT_SNAPSHOT_INVALID);
    }
  }

  async function safe(file) {
    const relative = path.relative(root, file);
    if (relative.startsWith('..') || path.isAbsolute(relative)) fail('ENVIRONMENT_PATH_INVALID', '环境备份路径越界');
    let cursor = path.parse(file).root;
    for (const piece of file.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, piece);
      let stat;
      try { stat = await lstat(cursor); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (stat.isSymbolicLink() || path.resolve(await realpath(cursor)).toLowerCase() !== path.resolve(cursor).toLowerCase()) fail('ENVIRONMENT_PATH_INVALID', '环境备份目录包含链接，操作已拒绝');
    }
  }
  async function readStateBytes() {
    if (mock) return null;
    await safe(stateFile);
    try { return await readFile(stateFile); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function assertStateUnchanged(previous) {
    const latest = await readStateBytes();
    if ((previous === null) !== (latest === null) || (previous && !previous.equals(latest))) fail('ENVIRONMENT_CONFLICT', '环境恢复记录在准备期间发生变化，未覆盖新记录');
  }
  async function save(value, expectedBytes) {
    if (mock) { record = clone(value); return; }
    await ensureRoot();
    await safe(stateFile);
    const temporary = path.join(root, `${randomUUID()}.tmp`);
    const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
    try {
      await writePrivate(temporary, bytes);
      const handle = await open(temporary, 'r+');
      try { await handle.sync(); } finally { await handle.close(); }
      await safe(stateFile);
      // Every ordinary write must retain the version this manager read. A
      // stale check must not erase another instance's pending recovery record.
      await assertStateUnchanged(expectedBytes === undefined ? recordBytes : expectedBytes);
      await renamePrivate(temporary, stateFile);
      record = clone(value); recordBytes = bytes;
    } finally { await rm(temporary, { force: true }).catch(() => {}); }
  }
  async function ensureRoot() {
    if (mock) return;
    await safe(root);
    try { if (!(await lstat(root)).isDirectory()) fail('ENVIRONMENT_PATH_INVALID', '环境备份位置不是目录'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; await createPrivateDirectory(root); }
  }
  async function load() {
    if (loaded) return;
    await currentScope();
    await loadPreferences();
    if (!mock) {
      await safe(root);
      try { if (!(await lstat(root)).isDirectory()) fail('ENVIRONMENT_PATH_INVALID', '环境备份位置不是目录'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      await safe(stateFile);
      try {
        let value;
        try { recordBytes = await readStateBytes(); if (recordBytes !== null) value = JSON.parse(recordBytes.toString('utf8')); }
        catch { fail('ENVIRONMENT_STATE_INVALID', '环境备份无法读取，请保留文件后人工检查'); }
        if (recordBytes !== null) record = validateRecord(value);
      } catch (error) {
        cached = { ...cached, status: 'error', ownership: 'invalid', canRefresh: true, needsCheck: true, backup: null, warnings: [error.message] };
        throw error;
      }
      if (record) {
        if (record.optimization && ['not-requested', 'applied', 'partial', 'failed', 'recovery-required', 'restored'].includes(record.optimization.status)) optimization = clone(record.optimization);
        if (record.pending) optimization = { status: 'recovery-required', code: 'ENVIRONMENT_RESTORE_REQUIRED', message: optimizationErrors.ENVIRONMENT_RESTORE_REQUIRED, stage: 'interrupted', attemptedAt: record.pending.startedAt, ...(fixedFields(record.optimization?.differingFields).length ? { differingFields: fixedFields(record.optimization.differingFields) } : {}), ...(fixedFields(record.optimization?.rollbackDifferingFields).length ? { rollbackDifferingFields: fixedFields(record.optimization.rollbackDifferingFields) } : {}) };
      }
    }
    loaded = true;
  }
  async function loadPreferences() {
    try { preferences = await profiles.load() || defaultEnvironmentPreferences(); profileError = null; }
    catch (cause) {
      preferences = defaultEnvironmentPreferences();
      const code = Object.hasOwn(optimizationErrors, cause.code) ? cause.code : 'ENVIRONMENT_PROFILE_INVALID';
      profileError = { code, message: optimizationErrors[code] };
    }
  }
  function requirePreferences() { if (profileError) fail(profileError.code, profileError.message); }
  async function backup(snapshot) {
    const value = { id: randomUUID(), createdAt: new Date(now()).toISOString(), scopeHash, snapshot: clone(snapshot) };
    if (!mock) {
      await ensureRoot();
      const file = path.join(root, `backup-${value.id}.json`);
      await safe(file);
      await writePrivate(file, `${JSON.stringify(value, null, 2)}\n`);
      const handle = await open(file, 'r+');
      try { await handle.sync(); } finally { await handle.close(); }
    }
    return value;
  }
  function originalSettings() {
    return { ...settings(record.backup.snapshot), ...(record.supplementalOriginalSettings ? { homeGeoId: record.supplementalOriginalSettings.homeGeoId } : {}) };
  }
  async function preserveNewOriginalFields(current) {
    // Older releases never recorded or changed home location. Capture it once
    // before this release's first write, without rewriting the original backup.
    if (record.backup.snapshot.homeGeoId === undefined && !record.supplementalOriginalSettings && current.homeGeoId !== undefined) {
      await save({ ...record, supplementalOriginalSettings: { homeGeoId: current.homeGeoId } });
    }
  }
  const publicFailure = (field, cause, phase = 'preparation') => ({ field, phase,
    code: Object.hasOwn(optimizationErrors, cause?.code) ? cause.code : 'ENVIRONMENT_WINDOWS_FAILED',
    ...sanitizeEnvironmentDiagnostic(cause?.diagnostic),
  });
  async function prepareTarget(current, { countryCode, timeZoneId, timezone, preferredLanguage, culture, localize = true }) {
    const target = clone(current), failures = [], warnings = [];
    try {
      const mapped = timeZoneId || WINDOWS_TIME_ZONES[timezone] || await windows.mapTimeZone?.(timezone);
      if (!mapped) fail('TIMEZONE_UNSUPPORTED', optimizationErrors.TIMEZONE_UNSUPPORTED);
      target.timeZoneId = mapped; target.daylightSavingDisabled = false;
    } catch (cause) { failures.push(publicFailure('timeZoneId', cause)); }
    if (countryCode) {
      try {
        const mapped = await windows.mapHomeRegion?.(countryCode);
        if (!Number.isInteger(current.homeGeoId) || !Number.isInteger(mapped) || mapped <= 0 || mapped > 0x7fffffff) fail('ENVIRONMENT_WINDOWS_FAILED', '无法读取或映射国家和地区');
        target.homeGeoId = mapped;
      } catch (cause) { failures.push(publicFailure('homeGeoId', cause)); }
    }
    if (localize) {
      target.culture = culture || 'zh-SG';
      target.cultureFromLanguageListOptOut = true;
      if (preferredLanguage) {
        try {
          const languages = clone(current.languages);
          const preferredIdentity = languageIdentity(preferredLanguage);
          const preferred = validateLanguage(languages.find(item => languageIdentity(item.languageTag) === preferredIdentity) || await windows.defaultLanguage(preferredLanguage));
          if (languageIdentity(preferred.languageTag) !== preferredIdentity) fail('ENVIRONMENT_STATE_INVALID', 'Windows 返回的首选语言与目标不一致');
          const simplifiedChinese = /^zh-(cn|sg)$/.test(preferredIdentity);
          const isPreferredVariant = item => simplifiedChinese ? /^zh-(cn|sg)$/.test(languageIdentity(item.languageTag)) : languageIdentity(item.languageTag) === preferredIdentity;
          if (simplifiedChinese) {
            // Windows merges CN/SG Simplified Chinese into one language entry.
            // Carry its existing keyboards to the requested region instead of
            // asking Windows to keep two entries it cannot persist independently.
            const variants = languages.filter(isPreferredVariant);
            const tips = [preferred, ...variants].flatMap(item => item.inputMethodTips);
            preferred.inputMethodTips = [...new Map(tips.map(tip => [tip.toLowerCase(), tip])).values()];
            preferred.handwriting ||= variants.some(item => item.handwriting);
          }
          target.languages = [preferred, ...languages.filter(item => !isPreferredVariant(item))];
          target.defaultInputMethod = preferred.inputMethodTips[0] || null;
          if (current.installedUiLanguages.some(tag => languageIdentity(tag) === languageIdentity(preferredLanguage))) target.uiLanguageOverride = preferredLanguage;
          else warnings.push(`首选语言设为 ${preferredLanguage}；未安装对应显示语言包，Windows 显示语言保留原值。`);
        } catch (cause) { failures.push(publicFailure('languages', cause)); }
      } else {
        failures.push({ field: 'languages', code: 'ENVIRONMENT_LANGUAGE_UNMAPPED', phase: 'preparation' });
        warnings.push('出口没有明确的首选语言映射，可在工作环境中手动指定；其他设置仍会应用。');
      }
    }
    validateSnapshot(target);
    return { target, failures, warnings };
  }
  function operationResult(result, operation, attemptedAt, warnings = []) {
    const { observed, target, failures } = result;
    const differingFields = fields.filter(field => differentSettings(observed, target).includes(field) || failures.some(item => item.field === field));
    const matchedFields = fields.filter(field => target[field] !== undefined && !differingFields.includes(field));
    return { status: differingFields.length ? 'partial' : operation === 'restore' ? 'restored' : 'applied', operation,
      ...(differingFields.length ? { code: 'ENVIRONMENT_PARTIAL', message: operation === 'restore' ? '部分设置尚未恢复；已恢复的设置保留，可再次恢复目标环境。' : optimizationErrors.ENVIRONMENT_PARTIAL } : {}),
      attemptedAt, completedAt: new Date(now()).toISOString(), target: settings(target), differingFields, matchedFields,
      changedFields: result.appliedFields, failures,
      fieldResults: fields.filter(field => target[field] !== undefined || differingFields.includes(field)).map(field => ({ field, status: differingFields.includes(field) ? 'unmatched' : 'matched', ...failures.find(item => item.field === field) })), warnings,
    };
  }
  function verifySnapshot(current, own, source, checkedAt) {
    const target = optimization.target;
    const failures = Array.isArray(optimization.failures) ? optimization.failures : [];
    // Preparation failures retain the previous value as a placeholder, not a
    // known requested target. Older records did not distinguish this phase.
    const unknownFields = new Set(failures.filter(item => item?.phase !== 'apply').map(item => item?.field));
    const canVerify = own === 'matched' && !record?.pending && target && failures.every(item => fields.includes(item?.field));
    const differences = canVerify ? differentSettings(current, target) : [];
    const fieldResults = fields.filter(field => target?.[field] !== undefined || unknownFields.has(field)).map(field => ({
      field, status: !canVerify || target[field] === undefined || unknownFields.has(field) ? 'unknown' : differences.includes(field) ? 'unmatched' : 'matched',
    }));
    const differingFields = fieldResults.filter(item => item.status === 'unmatched').map(item => item.field);
    const status = differingFields.length ? 'partial' : !fieldResults.length || fieldResults.some(item => item.status === 'unknown') ? 'unverified' : 'matched';
    return { status, fieldResults, differingFields, checkedAt, source };
  }
  function publish(current, warnings = [], extra = {}) {
    const own = ownership(); const matched = own === 'matched'; const quarantined = ['foreign', 'unbound'].includes(own);
    const snapshotSource = extra.snapshotSource ?? cached.snapshotSource ?? 'saved';
    const checkedAt = extra.checkedAt ?? cached.checkedAt ?? null;
    const active = Boolean(record?.lastApplied || record?.pending);
    const recoveryTarget = record?.optimization?.status === 'restored' && record.optimization.restoreSource === 'daily' && record.optimization.target ? record.optimization.target : record ? originalSettings() : {};
    const driftedFields = matched && !active ? differentSettings(current, recoveryTarget) : [];
    const conflict = matched && record?.lastApplied && differentSettings(current, record.lastApplied).length > 0;
    const daily = preferences.daily;
    const dailyDiffers = daily && (current.timeZoneId !== daily.timeZoneId || languageIdentity(current.culture) !== languageIdentity(daily.culture)
      || languageIdentity(current.languages[0].languageTag) !== languageIdentity(daily.preferredLanguage) || current.homeCountryCode !== daily.countryCode);
    const incompleteRestore = optimization.status === 'partial' && optimization.operation === 'restore';
    const visibleOptimization = quarantined ? { status: 'not-requested', message: optimizationErrors[own === 'foreign' ? 'ENVIRONMENT_BACKUP_FOREIGN' : 'ENVIRONMENT_BACKUP_UNBOUND'] } : optimization;
    const needsApplicationRestart = Boolean(current.activeCulture && current.activeCulture !== current.culture);
    cached = { status: quarantined ? own : record?.pending ? 'recovery-required' : conflict ? 'conflict' : record?.lastApplied ? 'optimized' : 'ready', ownership: own, canRefresh: !matched || !active, canAdoptCurrent: Boolean(scopeHash), needsCheck: quarantined,
      current: clone(current), snapshot: clone(current), backup: record ? { id: record.backup.id, createdAt: record.backup.createdAt, ownership: own, canRestore: matched, restoreNeeded: matched && (active || incompleteRestore || (daily ? Boolean(dailyDiffers) : driftedFields.length > 0)), drifted: driftedFields.length > 0, driftedFields, path: mock ? null : path.join(root, `backup-${record.backup.id}.json`) } : null,
      capabilities: { windows: true, timezone: true, language: true, fontPolicy: 'preserve-windows-fonts', preferredFont: 'Segoe UI', chineseFallback: 'Microsoft YaHei, SimSun' }, optimization: clone(visibleOptimization), verification: verifySnapshot(current, own, snapshotSource, checkedAt), snapshotSource, checkedAt, needsSignOut: matched && Boolean(record?.needsSignOut), needsApplicationRestart, ...(matched && record?.appliedRegion ? { appliedRegion: clone(record.appliedRegion) } : {}),
      preferences: clone(preferences), profileError: clone(profileError), profileCatalog: { presets: ENVIRONMENT_PRESETS, timeZones: ENVIRONMENT_TIME_ZONES },
      warnings: [...new Set([...warnings, ...(profileError ? [profileError.message] : []), ...(visibleOptimization.warnings || []), ...(visibleOptimization.message ? [visibleOptimization.message] : []), ...(driftedFields.length ? [optimizationErrors.ENVIRONMENT_BACKUP_DRIFT] : []), ...(needsApplicationRestart ? ['保存的区域格式与检测进程仍在使用的格式不同；保存结果已单独核验，请重新打开应用，必要时重新登录 Windows。'] : [])])], mock, ...extra };
    return clone(cached);
  }
  async function saveOptimization(result) {
    const persist = record && ownership() === 'matched';
    optimization = { ...clone(result), ...(!persist ? { persisted: false } : {}) };
    if (persist) await save({ ...record, optimization });
  }
  async function noteOptimizationFailure(cause, stage = 'preflight', attemptedAt = new Date(now()).toISOString()) {
    const code = Object.hasOwn(optimizationErrors, cause?.code) ? cause.code : 'ENVIRONMENT_OPTIMIZATION_FAILED';
    const differingFields = fixedFields(cause?.diagnostic?.environmentFields);
    const rollbackDifferingFields = fixedFields(cause?.diagnostic?.rollbackEnvironmentFields);
    const windowsStage = sanitizeEnvironmentDiagnostic(cause?.diagnostic)?.environmentStage;
    const result = { status: record?.pending ? 'recovery-required' : 'failed', code, message: optimizationErrors[code] || '环境优化未完成，请检查备份和本机权限。', stage, attemptedAt, completedAt: new Date(now()).toISOString(), ...(windowsStage ? { windowsStage } : {}), ...(differingFields.length ? { differingFields } : {}), ...(rollbackDifferingFields.length ? { rollbackDifferingFields } : {}) };
    try { await saveOptimization(result); }
    catch { optimization = { ...result, persisted: false }; }
    if (cached.current) return publish(cached.current, cached.warnings.filter(warning => warning !== cached.optimization?.message));
    cached = { ...cached, optimization: clone(optimization), warnings: [result.message] };
    return clone(cached);
  }
  async function rebuildUnlocked({ acceptCurrent = false } = {}) {
    await currentScope();
    let previous = null; let parsed = null;
    previous = await readStateBytes();
    if (mock) parsed = record;
    else if (previous) { try { parsed = JSON.parse(previous.toString('utf8')); } catch { /* Invalid records are archived as bytes, never applied. */ } }
    if (!acceptCurrent && parsed?.version === 2 && parsed.scopeHash === scopeHash && (parsed.lastApplied || parsed.pending)) fail('ENVIRONMENT_BACKUP_ACTIVE', '本机环境优化或恢复尚未结束；请先一键复原，不能覆盖待恢复的原始快照');
    const current = await readCurrentSnapshot();
    let archivedStatePath = null;
    if (!mock) {
      await ensureRoot();
      await assertStateUnchanged(previous);
      if (previous) {
        archivedStatePath = path.join(root, `state-archive-${randomUUID()}.json`);
        await safe(archivedStatePath);
        await writeArchive(archivedStatePath, previous);
        const handle = await open(archivedStatePath, 'r+');
        try { await handle.sync(); } finally { await handle.close(); }
        if (!previous.equals(await readFile(archivedStatePath))) fail('ENVIRONMENT_STATE_INVALID', '旧恢复记录归档不完整，未覆盖原记录');
      }
    }
    const currentBackup = await backup(current);
    const latestSnapshot = await readCurrentSnapshot();
    if (!equal(current, latestSnapshot)) fail('ENVIRONMENT_CONFLICT', '环境在快照准备期间被修改，请重新检查；未采纳新基线或更改系统设置', { environmentFields: differentSettings(latestSnapshot, current) });
    const checkedAt = new Date(now()).toISOString();
    await save({ version: 2, scopeHash, backup: currentBackup, lastApplied: null, pending: null, appliedRegion: null, needsSignOut: false, lastObserved: current, checkedAt, optimization: { status: 'not-requested' } }, previous);
    loaded = true; optimization = { status: 'not-requested' };
    return publish(current, [acceptCurrent ? '已采纳当前 Windows 设置作为新基线；旧恢复记录已归档，所有旧备份保留，未修改系统设置。' : '已按当前电脑和 Windows 用户重建快照；旧恢复记录已归档，旧备份文件保留。'], { snapshotSource: 'live', checkedAt, needsCheck: false, backupRefreshed: true, backupRebuilt: true, ...(acceptCurrent ? { adoptedCurrent: true } : {}), archivedStatePath });
  }
  async function checkUnlocked({ refreshBackup = false, rebuildBackup = false } = {}) {
    if (rebuildBackup) {
      if (!refreshBackup) fail('ENVIRONMENT_REBUILD_REQUIRED', '重建本机快照必须同时明确刷新备份');
      return rebuildUnlocked();
    }
    await load();
    await loadPreferences();
    const own = ownership();
    if (['foreign', 'unbound'].includes(own)) {
      if (refreshBackup) fail('ENVIRONMENT_REBUILD_REQUIRED', optimizationErrors.ENVIRONMENT_REBUILD_REQUIRED);
      return publish(await readCurrentSnapshot(), [], { snapshotSource: 'live', checkedAt: new Date(now()).toISOString(), needsCheck: true, backupRefreshed: false });
    }
    if (refreshBackup && (record?.lastApplied || record?.pending)) fail('ENVIRONMENT_BACKUP_ACTIVE', '环境优化或恢复尚未结束；请先一键复原，再重新检查并备份，避免丢失原始设置');
    const current = await readCurrentSnapshot();
    const checkedAt = new Date(now()).toISOString();
    if (!record || refreshBackup) {
      const outcome = refreshBackup ? { status: 'not-requested' } : optimization;
      await save({ version: 2, scopeHash, backup: await backup(current), lastApplied: null, pending: null, lastObserved: current, checkedAt, optimization: outcome });
      optimization = clone(outcome);
    }
    else await save({ ...record, lastObserved: current, checkedAt });
    const warnings = ['系统字体保留 Windows 默认字体及微软简中字库；界面语言和区域格式可按出口调整。'];
    if (record.pending) warnings.push(optimizationErrors.ENVIRONMENT_RESTORE_REQUIRED);
    return publish(current, warnings, { snapshotSource: 'live', checkedAt, needsCheck: false, backupRefreshed: refreshBackup });
  }
  async function inspectSavedUnlocked() {
    await load();
    if (!record) return { ...clone(cached), preferences: clone(preferences), profileError: clone(profileError), profileCatalog: { presets: ENVIRONMENT_PRESETS, timeZones: ENVIRONMENT_TIME_ZONES } };
    const snapshot = record.lastObserved || record.pending?.before || record.lastApplied || record.backup.snapshot;
    return publish(snapshot, ['显示上次保存的环境快照；本次启动未重新检查或修改 Windows 设置。', ...(ownership() === 'matched' && record.pending ? [optimizationErrors.ENVIRONMENT_RESTORE_REQUIRED] : [])], { snapshotSource: 'saved', checkedAt: record.checkedAt || record.backup.createdAt, needsCheck: true });
  }
  async function applyTransaction(current, target, progress = () => {}, { force = false, failures = [] } = {}) {
    // Preserve each verified write. A language failure must not undo a working
    // timezone/region. Durable intent is retained if the final read is unavailable.
    progress('pre-apply-check');
    const latest = await readCurrentSnapshot();
    const changedFields = differentSettings(latest, current);
    if (!force && changedFields.length) {
      publish(latest, [], { snapshotSource: 'live', checkedAt: new Date(now()).toISOString(), needsCheck: false });
      fail('ENVIRONMENT_CONFLICT', '环境在操作准备期间被修改，请重新检查；未覆盖新设置', { environmentFields: changedFields });
    }
    if (force) current = latest;
    const requestedFields = differentSettings(current, target);
    await preserveNewOriginalFields(current);
    await save({ ...record, pending: { before: current, target, startedAt: new Date(now()).toISOString() } });
    let nativeResult, nativeError;
    progress('applying');
    if (requestedFields.length) {
      try { nativeResult = await windows.apply(target, { bestEffort: true }); }
      catch (cause) { nativeError = cause; }
    }
    progress('verifying');
    const observed = await readCurrentSnapshot();
    const unmatched = differentSettings(observed, target);
    const reported = [...failures, ...(nativeResult?.failures || []).map(item => ({ ...item, phase: 'apply' }))];
    if (nativeError) for (const field of unmatched) reported.push(publicFailure(field, nativeError, 'apply'));
    // A command may report an error after persisting its value. Actual saved
    // state wins; preparation errors stay visible because their target is unknown.
    const remainingFailures = fields.flatMap(field => {
      const failure = reported.find(item => item.field === field);
      return failure && (unmatched.includes(field) || failures.some(item => item.field === field)) ? [failure] : [];
    });
    await save({ ...record, lastApplied: differentSettings(observed, originalSettings()).length ? observed : null, pending: null, lastObserved: observed, checkedAt: new Date(now()).toISOString() });
    return { observed, target, before: current, appliedFields: differentSettings(observed, current), failures: remainingFailures };
  }
  return {
    status: () => ({ ...clone(cached), preferences: clone(preferences), profileError: clone(profileError), profileCatalog: { presets: ENVIRONMENT_PRESETS, timeZones: ENVIRONMENT_TIME_ZONES } }),
    savePreferences: value => locked(async () => {
      preferences = await profiles.save(value);
      profileError = null;
      return cached.current ? publish(cached.current, cached.warnings.filter(warning => warning !== cached.optimization?.message))
        : { ...clone(cached), preferences: clone(preferences), profileError: null, profileCatalog: { presets: ENVIRONMENT_PRESETS, timeZones: ENVIRONMENT_TIME_ZONES } };
    }),
    check: (options = {}) => locked(() => checkUnlocked(options)),
    adoptCurrent: () => locked(() => rebuildUnlocked({ acceptCurrent: true })),
    inspectSaved: () => locked(inspectSavedUnlocked),
    initialize: ({ checkIfMissing = true } = {}) => locked(async () => {
      await load();
      if (!record && !checkIfMissing) return { ...clone(cached), preferences: clone(preferences), profileError: clone(profileError), profileCatalog: { presets: ENVIRONMENT_PRESETS, timeZones: ENVIRONMENT_TIME_ZONES } };
      return !record && checkIfMissing ? checkUnlocked() : inspectSavedUnlocked();
    }),
    optimize: (options = {}) => locked(async () => {
      const attemptedAt = new Date(now()).toISOString();
      let stage = 'preflight';
      try {
      const { geo, localize = true } = options;
      const force = options.force === true;
      await load();
      await checkUnlocked();
      requirePreferences();
      const custom = preferences.work.mode === 'custom';
      if (!custom && (!geo || geo.verified !== true || !isIP(geo.ip || '') || !/^[A-Z]{2}$/.test(geo.countryCode || '') || typeof geo.timezone !== 'string' || !/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+){0,2}$/.test(geo.timezone))) fail('EXIT_GEO_UNVERIFIED', '需要同一受管代理出口的已核验 IP、国家和 IANA 时区');
      requireOwned();
      if (!force && record.pending) fail('ENVIRONMENT_RESTORE_REQUIRED', optimizationErrors.ENVIRONMENT_RESTORE_REQUIRED);
      const current = await readCurrentSnapshot();
      const conflictFields = record.lastApplied ? differentSettings(current, record.lastApplied) : [];
      if (!force && conflictFields.length) fail('ENVIRONMENT_CONFLICT', '环境已发生变化；可手动重新应用出口环境，或还原初始环境', { environmentFields: conflictFields });
      const driftFields = !record.lastApplied ? differentSettings(current, originalSettings()) : [];
      if (!force && driftFields.length) fail('ENVIRONMENT_BACKUP_DRIFT', optimizationErrors.ENVIRONMENT_BACKUP_DRIFT, { environmentFields: driftFields });
      stage = 'target-validation';
      const locale = localize ? custom ? preferences.work.preferredLanguage : localeForGeo(geo) || ENVIRONMENT_PRESETS.find(item => item.countryCode === geo.countryCode)?.preferredLanguage : null;
      const plan = await prepareTarget(current, custom ? { ...preferences.work, localize } : { ...geo, preferredLanguage: locale, culture: 'zh-SG', localize });
      const { target, warnings } = plan;
      const result = await applyTransaction(current, target, value => { stage = value; }, { force, failures: plan.failures });
      const { observed, appliedFields } = result;
      publish(observed, [], { snapshotSource: 'live', checkedAt: record.checkedAt, needsCheck: false });
      const needsSignOut = Boolean(record.needsSignOut || appliedFields.some(field => signOutFields.includes(field)));
      warnings.push(needsSignOut ? '各项保存结果已分别核验；显示语言或输入法可能需要注销后生效，原有语言和输入法保留。' : '各项保存结果已分别核验；已打开的应用可能需要重新打开才能显示新的区域格式。');
      const appliedRegion = { countryCode: custom ? preferences.work.countryCode : geo.countryCode, city: custom ? '' : String(geo.city || '').slice(0, 120), timezone: custom ? target.timeZoneId : geo.timezone, locale, mode: custom ? 'custom' : 'exit' };
      await save({ ...record, needsSignOut, appliedRegion });
      await saveOptimization(operationResult(result, 'optimize', attemptedAt, warnings));
      return publish(observed, warnings, { snapshotSource: 'live', checkedAt: record.checkedAt, needsCheck: false });
      } catch (cause) {
        await noteOptimizationFailure(cause, stage, attemptedAt);
        throw cause;
      }
    }),
    noteOptimizationFailure: (cause, stage) => locked(async () => { await load(); return noteOptimizationFailure(cause, stage); }),
    restore: ({ original = false } = {}) => locked(async () => {
      let restorationStarted = false;
      try {
      await checkUnlocked();
      requireOwned();
      if (!original) {
        requirePreferences();
        if (!preferences.daily) fail('ENVIRONMENT_DAILY_REQUIRED', optimizationErrors.ENVIRONMENT_DAILY_REQUIRED);
      }
      const current = await readCurrentSnapshot();
      const daily = !original && preferences.daily;
      const plan = daily ? await prepareTarget(current, daily) : { target: { ...clone(current), ...originalSettings() }, failures: [], warnings: [] };
      restorationStarted = true;
      const result = await applyTransaction(current, plan.target, undefined, { force: true, failures: plan.failures });
      const { observed, appliedFields } = result;
      const needsSignOut = Boolean(record.needsSignOut || appliedFields.some(field => signOutFields.includes(field)));
      const outcome = { ...operationResult(result, 'restore', new Date(now()).toISOString(), plan.warnings), restoreSource: daily ? 'daily' : 'original' };
      const restored = outcome.status === 'restored';
      await save({ ...record, lastApplied: restored ? null : record.lastApplied, pending: null, lastObserved: observed, checkedAt: new Date(now()).toISOString(), appliedRegion: null, needsSignOut });
      await saveOptimization(outcome);
      return publish(observed, [restored ? daily ? '已按保存的日常环境覆盖并逐项核验。' : '已按原始快照覆盖并逐项核验。' : '已恢复的设置保留，未完成的项目可重试。', ...(needsSignOut ? ['显示语言或输入法可能需注销生效。'] : [])], { snapshotSource: 'live', checkedAt: record.checkedAt, needsCheck: false, restored, needsSignOut, ...(!appliedFields.length ? { noChange: true } : {}) });
      } catch (cause) {
        await noteOptimizationFailure(cause, restorationStarted ? 'restoring' : 'restore-preflight');
        throw cause;
      }
    }),
  };
}
