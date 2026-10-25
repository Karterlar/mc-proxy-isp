const fail = () => { throw Object.assign(new Error('OBSERVATION_REPORT_INVALID'), { code: 'OBSERVATION_REPORT_INVALID', status: 400 }); };
const keys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => allowed.includes(key));
const text = (value, max = 512) => typeof value === 'string' && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
const integer = value => Number.isInteger(value) && value >= 0 && value <= 1024;
export const validDeviceMemory = value => typeof value === 'number' && Number.isFinite(value) && value > 0 && value <= 1024;
const contextNames = ['iframe', 'dedicatedWorker', 'sharedWorker'];
const names = { iframe: '同源 iframe', dedicatedWorker: 'Dedicated Worker', sharedWorker: 'Shared Worker' };
const comparable = value => typeof value === 'string' && value.length > 0;
const same = values => new Set(values.map(value => JSON.stringify(value))).size === 1;
const brands = value => [...value].sort((a, b) => a.brand.localeCompare(b.brand));
const language = value => { try { return new Intl.Locale(value).baseName; } catch { return value; } };

export function validateIdentityUaCh(value) {
  if (!keys(value, ['status', 'platform', 'mobile', 'architecture', 'bitness', 'platformVersion', 'brands']) || !['measured', 'unverified', 'failed'].includes(value.status)
    || Object.entries(value).some(([key, entry]) => !['status', 'mobile', 'brands'].includes(key) && !text(entry, 100))
    || ('mobile' in value && typeof value.mobile !== 'boolean')
    || ('brands' in value && (!Array.isArray(value.brands) || value.brands.length > 12 || !value.brands.every(item => keys(item, ['brand', 'version']) && text(item.brand, 100) && text(item.version, 64))))) fail();
  return value;
}

function surface(value) {
  if (!keys(value, ['userAgent', 'language', 'languages', 'timezone', 'platform', 'hardwareConcurrency', 'deviceMemory', 'uaCh', 'screen'])
    || !text(value.userAgent) || !text(value.language, 64) || !text(value.timezone, 100) || !text(value.platform, 100) || !integer(value.hardwareConcurrency)
    || !Array.isArray(value.languages) || value.languages.length > 16 || !value.languages.every(item => text(item, 64))
    || 'deviceMemory' in value && !validDeviceMemory(value.deviceMemory)) fail();
  validateIdentityUaCh(value.uaCh);
  if (value.screen !== undefined && (!keys(value.screen, ['width', 'height', 'pixelRatio']) || Object.keys(value.screen).length !== 3 || !Object.values(value.screen).every(entry => typeof entry === 'number' && Number.isFinite(entry) && entry > 0 && entry <= 100000))) fail();
  return value;
}

export function normalizeConsistencyInput(value) {
  if (value == null) return null;
  if (!keys(value, ['version', 'contexts']) || value.version !== 1 || !keys(value.contexts, contextNames) || Object.keys(value.contexts).length !== contextNames.length) fail();
  for (const name of contextNames) {
    const entry = value.contexts[name];
    if (!keys(entry, ['status', 'reason', 'surface']) || !['measured', 'unverified'].includes(entry.status) || 'reason' in entry && !/^[A-Z_]{1,64}$/.test(entry.reason)) fail();
    if (entry.status === 'measured') surface(entry.surface);
    else if ('surface' in entry) fail();
  }
  return structuredClone(value);
}

function compareSurface(main, observed) {
  const conflicts = [], missing = [];
  for (const field of ['userAgent', 'language', 'timezone', 'platform']) {
    if (!comparable(main[field]) || !comparable(observed[field])) missing.push(field);
    else if (main[field] !== observed[field]) conflicts.push(field);
  }
  if (!main.languages?.length || !observed.languages.length) missing.push('languages');
  else if (!same([main.languages, observed.languages])) conflicts.push('languages');
  if (!main.hardwareConcurrency || !observed.hardwareConcurrency) missing.push('hardwareConcurrency');
  else if (main.hardwareConcurrency !== observed.hardwareConcurrency) conflicts.push('hardwareConcurrency');
  if (!validDeviceMemory(main.deviceMemory) || !validDeviceMemory(observed.deviceMemory)) missing.push('deviceMemory');
  else if (main.deviceMemory !== observed.deviceMemory) conflicts.push('deviceMemory');
  for (const field of ['platform', 'platformVersion', 'architecture', 'bitness']) {
    if (!comparable(main.uaCh?.[field]) || !comparable(observed.uaCh[field])) missing.push(`uaCh.${field}`);
    else if (main.uaCh[field] !== observed.uaCh[field]) conflicts.push(`uaCh.${field}`);
  }
  if (typeof main.uaCh?.mobile !== 'boolean' || typeof observed.uaCh.mobile !== 'boolean') missing.push('uaCh.mobile');
  else if (main.uaCh.mobile !== observed.uaCh.mobile) conflicts.push('uaCh.mobile');
  if (!main.uaCh?.brands?.length || !observed.uaCh.brands?.length) missing.push('uaCh.brands');
  else if (!same([brands(main.uaCh.brands), brands(observed.uaCh.brands)])) conflicts.push('uaCh.brands');
  return { conflicts, missing };
}

function headerBrands(value) {
  if (!value) return [];
  const results = [...value.matchAll(/"((?:\\.|[^"\\])*)";v="([0-9.]+)"/g)];
  try { return results.map(match => ({ brand: JSON.parse(`"${match[1]}"`), version: match[2] })); } catch { return []; }
}
function quoted(value) { try { const parsed = JSON.parse(value); return typeof parsed === 'string' ? parsed : null; } catch { return null; } }

export function browserConsistencyChecks({ input, browser, headers = null, expectedIdentity = null, mock = false } = {}) {
  const normalized = normalizeConsistencyInput(input), checks = [];
  const status = (conflicts, missing) => mock ? 'mocked' : conflicts.length ? 'mismatch' : missing.length ? 'unverified' : 'verified';
  const detail = (conflicts, missing) => conflicts.length ? `发现冲突：${conflicts.join('、')}。` : missing.length ? `缺少观测：${missing.join('、')}；未判为匹配。` : '本次已采集字段一致；不代表匿名性或网站风控通过。';
  for (const name of contextNames) {
    const entry = normalized?.contexts[name];
    if (!entry || entry.status !== 'measured') { checks.push({ id: `identity-${name}`, label: `${names[name]} 身份一致性`, status: mock ? 'mocked' : 'unverified', detail: entry?.reason || '未取得该上下文的读数；不以主页面读数代替。' }); continue; }
    const { conflicts, missing } = compareSurface(browser, entry.surface);
    checks.push({ id: `identity-${name}`, label: `${names[name]} 身份一致性`, status: status(conflicts, missing), detail: detail(conflicts, missing) });
  }
  const conflicts = [], missing = [];
  if (!headers?.['user-agent']) missing.push('User-Agent');
  else if (headers['user-agent'] !== browser.userAgent) conflicts.push('User-Agent');
  if (!headers?.['accept-language'] || !browser.language) missing.push('Accept-Language');
  else if (language(headers['accept-language'].split(',')[0].split(';')[0].trim()) !== language(browser.language)) conflicts.push('Accept-Language');
  if (!headers?.['sec-ch-ua-platform'] || !browser.uaCh.platform) missing.push('Sec-CH-UA-Platform');
  else if (quoted(headers['sec-ch-ua-platform']) !== browser.uaCh.platform) conflicts.push('Sec-CH-UA-Platform');
  if (!headers?.['sec-ch-ua-platform-version'] || !browser.uaCh.platformVersion) missing.push('Sec-CH-UA-Platform-Version');
  else if (quoted(headers['sec-ch-ua-platform-version']) !== browser.uaCh.platformVersion) conflicts.push('Sec-CH-UA-Platform-Version');
  if (!headers?.['sec-ch-ua-mobile'] || typeof browser.uaCh.mobile !== 'boolean') missing.push('Sec-CH-UA-Mobile');
  else if (headers['sec-ch-ua-mobile'] !== (browser.uaCh.mobile ? '?1' : '?0')) conflicts.push('Sec-CH-UA-Mobile');
  const fullBrands = headerBrands(headers?.['sec-ch-ua-full-version-list']);
  if (!fullBrands.length || !browser.uaCh.brands?.length) missing.push('Sec-CH-UA-Full-Version-List');
  else if (!same([brands(fullBrands), brands(browser.uaCh.brands)])) conflicts.push('Sec-CH-UA-Full-Version-List');
  const memoryHeaders = ['device-memory', 'sec-ch-device-memory'].filter(name => headers?.[name] !== undefined);
  if (!memoryHeaders.length) missing.push('Device-Memory / Sec-CH-Device-Memory');
  if (!validDeviceMemory(browser.deviceMemory)) missing.push('navigator.deviceMemory');
  for (const name of memoryHeaders) {
    const value = headers[name];
    if (typeof value !== 'string' || !/^(?:\d+)(?:\.\d+)?$/.test(value) || !validDeviceMemory(Number(value))) missing.push(name);
    else if (validDeviceMemory(browser.deviceMemory) && Number(value) !== browser.deviceMemory) conflicts.push(name);
  }
  checks.push({ id: 'identity-http', label: 'HTTP 请求头与页面一致性', status: status(conflicts, missing), detail: `${detail(conflicts, missing)} 请求头由本机 HTTP 服务直接记录。` });
  const expectedConflicts = [], expectedMissing = [];
  if (!expectedIdentity) expectedMissing.push('受管身份目标');
  else {
    if (!browser.platform || !browser.userAgent || !browser.uaCh.platform) expectedMissing.push('Windows 平台');
    else if (browser.platform !== 'Win32' || !/Windows NT 10\.0/.test(browser.userAgent) || browser.uaCh.platform !== 'Windows') expectedConflicts.push('Windows 平台');
    if (!browser.uaCh.platformVersion) expectedMissing.push('平台版本');
    else if (browser.uaCh.platformVersion !== expectedIdentity.platformVersion) expectedConflicts.push('平台版本');
    if (!browser.hardwareConcurrency) expectedMissing.push('CPU 并发数');
    else if (browser.hardwareConcurrency !== expectedIdentity.cores) expectedConflicts.push('CPU 并发数');
    const major = /\b(?:Chrome|Chromium)\/(\d+)\./.exec(browser.userAgent)?.[1], actual = browser.uaCh.brands?.filter(entry => /^(?:Chromium|Google Chrome)$/.test(entry.brand));
    if (!major || !actual?.length) expectedMissing.push('Chromium 版本');
    else if (major !== expectedIdentity.engineVersion.split('.')[0] || actual.some(entry => entry.version !== expectedIdentity.engineVersion)) expectedConflicts.push('Chromium 版本');
  }
  checks.push({ id: 'identity-target', label: '页面与当前环境目标', status: status(expectedConflicts, expectedMissing), detail: `${detail(expectedConflicts, expectedMissing)} 图形策略属于配置，不凭页面自报判定其已生效。` });
  const frameScreen = normalized?.contexts.iframe.status === 'measured' ? normalized.contexts.iframe.surface.screen : null;
  const screen = browser.viewport, screenMissing = !screen || !frameScreen || !screen.screenWidth || !screen.screenHeight || !screen.pixelRatio;
  const screenConflict = !screenMissing && (screen.screenWidth !== frameScreen.width || screen.screenHeight !== frameScreen.height || screen.pixelRatio !== frameScreen.pixelRatio);
  checks.push({ id: 'identity-screen', label: '屏幕与 DPR 一致性', status: mock ? 'mocked' : screenMissing ? 'unverified' : screenConflict ? 'mismatch' : 'verified', detail: screenMissing ? '未取得主页面和同源 iframe 的完整屏幕读数。' : screenConflict ? '同一时刻页面与 iframe 的屏幕或 DPR 不同；请核对缩放和显示器变化。' : '本次主页面与 iframe 的屏幕尺寸和 DPR 一致；不将窗口大小当作硬件真实性证明。' });
  return { checks, measurements: { contexts: normalized?.contexts || null, headers: headers ? structuredClone(headers) : null } };
}
