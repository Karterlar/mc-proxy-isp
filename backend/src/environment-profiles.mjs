import path from 'node:path';
import { lstat, readFile, realpath, rm, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { WINDOWS_TIME_ZONES } from './environment-regions.mjs';
import { UserError } from './config.mjs';

// Presets are editable starting points; a country's label never implies that it
// has only one time zone or one preferred language.
export const ENVIRONMENT_PRESETS = Object.freeze([
  ['US', '美国 · 纽约', 'Eastern Standard Time', 'en-US'],
  ['JP', '日本', 'Tokyo Standard Time', 'ja-JP'],
  ['KR', '韩国', 'Korea Standard Time', 'ko-KR'],
  ['HK', '中国香港', 'China Standard Time', 'zh-HK'],
  ['SG', '新加坡', 'Singapore Standard Time', 'en-SG'],
  ['TW', '中国台湾', 'Taipei Standard Time', 'zh-TW'],
  ['GB', '英国 · 伦敦', 'GMT Standard Time', 'en-GB'],
  ['DE', '德国', 'W. Europe Standard Time', 'de-DE'],
  ['CA', '加拿大 · 多伦多', 'Eastern Standard Time', 'en-CA'],
  ['AU', '澳大利亚 · 悉尼', 'AUS Eastern Standard Time', 'en-AU'],
  ['CN', '中国大陆', 'China Standard Time', 'zh-CN'],
].map(([countryCode, label, timeZoneId, preferredLanguage]) => Object.freeze({ id: countryCode, label, countryCode, timeZoneId, preferredLanguage, culture: 'zh-SG' })));
export const ENVIRONMENT_TIME_ZONES = Object.freeze([...new Set(Object.values(WINDOWS_TIME_ZONES))].sort());
const countryCodes = new Set(('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW').split(' '));
const validCountry = value => typeof value === 'string' && countryCodes.has(value);
const knownGeoIds = Object.freeze({ 244: 'US', 122: 'JP', 134: 'KR', 104: 'HK', 215: 'SG', 237: 'TW', 242: 'GB', 94: 'DE', 39: 'CA', 12: 'AU', 45: 'CN' });
const validBinding = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const keys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => allowed.includes(key));
const fail = (code, message) => { throw new UserError(code, message); };
const invalid = () => fail('ENVIRONMENT_PROFILE_INVALID', '环境方案无效，请检查国家、时区、首选语言和区域格式');

function languageTag(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z]{2,3}(?:-[a-zA-Z0-9]{2,8}){0,3}$/.test(value)) invalid();
  try { return Intl.getCanonicalLocales(value)[0]; } catch { invalid(); }
}
function validateProfile(value, work) {
  if (!keys(value, ['countryCode', 'timeZoneId', 'preferredLanguage', 'culture', ...(work ? ['mode'] : [])]) || !validCountry(value.countryCode) || !ENVIRONMENT_TIME_ZONES.includes(value.timeZoneId) || work && !['exit', 'custom'].includes(value.mode)) invalid();
  const preferredLanguage = languageTag(value.preferredLanguage), culture = languageTag(value.culture);
  if (work && culture !== 'zh-SG') invalid();
  return { ...(work ? { mode: value.mode } : {}), countryCode: value.countryCode, timeZoneId: value.timeZoneId, preferredLanguage, culture };
}
export function validateEnvironmentPreferences(value) {
  if (!keys(value, ['work', 'daily']) || !Object.hasOwn(value, 'daily')) invalid();
  return { work: validateProfile(value.work, true), daily: value.daily === null ? null : validateProfile(value.daily, false) };
}
export function defaultEnvironmentPreferences() {
  return { work: { mode: 'exit', countryCode: 'US', timeZoneId: 'Eastern Standard Time', preferredLanguage: 'en-US', culture: 'zh-SG' }, daily: null };
}
export function profileFromSnapshot(snapshot) {
  const countryCode = validCountry(snapshot?.homeCountryCode) ? snapshot.homeCountryCode : knownGeoIds[snapshot?.homeGeoId];
  if (!countryCode) return null;
  try { return validateProfile({ countryCode, timeZoneId: snapshot.timeZoneId, preferredLanguage: snapshot.languages?.[0]?.languageTag, culture: snapshot.culture }, false); }
  catch { return null; }
}

export function createEnvironmentProfiles({ stateDir, scopeHash, mock = false } = {}) {
  if (!mock && (!stateDir || !path.isAbsolute(stateDir))) fail('ENVIRONMENT_PATH_INVALID', '环境方案目录必须为绝对路径');
  const root = stateDir ? path.resolve(stateDir) : null, file = root && path.join(root, 'envprefs.json');
  let loaded = false, loadedScope = null, previous = null, memory = null, serial = Promise.resolve();
  const locked = action => { const next = serial.then(action, action); serial = next.catch(() => {}); return next; };
  async function binding() {
    let value; try { value = await scopeHash?.(); } catch { /* Fail closed when machine/user identity is unavailable. */ }
    if (!validBinding(value)) fail('ENVIRONMENT_IDENTITY_UNAVAILABLE', '无法确认当前电脑和 Windows 用户，未保存环境方案');
    return value;
  }
  async function safe(target) {
    const relative = path.relative(root, target);
    if (relative.startsWith('..') || path.isAbsolute(relative)) fail('ENVIRONMENT_PATH_INVALID', '环境方案路径越界');
    let cursor = path.parse(target).root;
    for (const segment of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      let info; try { info = await lstat(cursor); } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
      const actual = path.resolve(await realpath(cursor)), expected = path.resolve(cursor);
      if (info.isSymbolicLink() || (process.platform === 'win32' ? actual.toLowerCase() !== expected.toLowerCase() : actual !== expected)) fail('ENVIRONMENT_PATH_INVALID', '环境方案目录包含链接，操作已拒绝');
    }
  }
  async function read() {
    await safe(file);
    try {
      const info = await lstat(file);
      if (!info.isFile() || info.size > 16384) fail('ENVIRONMENT_PROFILE_INVALID', '环境方案文件类型或大小无效，原文件已保留');
      return await readFile(file);
    } catch (cause) { if (cause.code === 'ENOENT') return null; throw cause; }
  }
  async function load() {
    const scope = await binding();
    if (mock) { loaded = true; loadedScope = scope; return structuredClone(memory); }
    const bytes = await read();
    let preferences = null;
    if (bytes !== null) {
      let record; try { record = JSON.parse(bytes.toString('utf8')); } catch { fail('ENVIRONMENT_PROFILE_INVALID', '环境方案无法解析，原文件已保留'); }
      if (!keys(record, ['version', 'scopeHash', 'preferences']) || record.version !== 1 || !validBinding(record.scopeHash)) invalid();
      if (record.scopeHash !== scope) fail('ENVIRONMENT_PROFILE_FOREIGN', '环境方案属于其他电脑或 Windows 用户，原文件已保留');
      preferences = validateEnvironmentPreferences(record.preferences);
    }
    previous = bytes; loadedScope = scope; loaded = true;
    return preferences;
  }
  return {
    load: () => locked(load),
    save: value => locked(async () => {
      const preferences = validateEnvironmentPreferences(value), scope = await binding();
      if (!loaded) await load();
      if (loadedScope !== scope) fail('ENVIRONMENT_PROFILE_FOREIGN', 'Windows 用户或设备身份已变化，请重新读取环境方案');
      if (mock) { memory = structuredClone(preferences); return structuredClone(preferences); }
      await safe(root);
      try { if (!(await lstat(root)).isDirectory()) fail('ENVIRONMENT_PATH_INVALID', '环境方案位置不是目录'); }
      catch (cause) { if (cause.code !== 'ENOENT') throw cause; await createPrivateDirectory(root); }
      const temporary = path.join(root, `.envprefs-${randomUUID()}.tmp`);
      const bytes = Buffer.from(`${JSON.stringify({ version: 1, scopeHash: scope, preferences }, null, 2)}\n`);
      try {
        await writePrivate(temporary, bytes);
        const handle = await open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
        const latest = await read();
        if ((previous === null) !== (latest === null) || previous && !previous.equals(latest)) fail('ENVIRONMENT_PROFILE_CONFLICT', '环境方案已被其他窗口修改，请刷新后再保存；未覆盖新方案');
        await renamePrivate(temporary, file); previous = bytes;
      } finally { await rm(temporary, { force: true }).catch(() => {}); }
      return structuredClone(preferences);
    }),
  };
}
