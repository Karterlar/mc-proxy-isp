const fields = {
  timeZoneId: '时区', daylightSavingDisabled: '夏令时', culture: '区域格式', homeGeoId: '国家或地区',
  uiLanguageOverride: '显示语言偏好', languages: '语言与输入法列表',
  defaultInputMethod: '默认输入法', cultureFromLanguageListOptOut: '区域格式自动联动',
};
const stages = {
  invoke: '调用 Windows', scopeHash: '核对本机身份', snapshot: '读取系统设置',
  defaultLanguage: '读取语言支持', mapTimeZone: '匹配时区', mapHomeRegion: '匹配国家或地区', 'apply-validation': '校验目标设置',
  'apply-timezone': '写入时区', 'apply-language-list': '写入语言列表',
  'apply-culture': '写入区域格式', 'apply-home-region': '写入国家或地区', 'apply-ui-language': '写入显示语言偏好',
  'apply-input-method': '写入默认输入法', 'apply-culture-opt-out': '写入区域格式联动',
};

export function sanitizeEnvironmentFeedback(value) {
  const result = {};
  if (typeof value?.environmentStage === 'string' && Object.hasOwn(stages, value.environmentStage)) result.environmentStage = value.environmentStage;
  for (const key of ['environmentFields', 'rollbackEnvironmentFields']) {
    const names = Array.isArray(value?.[key]) ? [...new Set(value[key].filter(name => typeof name === 'string' && Object.hasOwn(fields, name)))].slice(0, 8) : [];
    if (names.length) result[key] = names;
  }
  return result;
}

export function environmentDiagnosticText(value) {
  const safe = sanitizeEnvironmentFeedback(value), parts = [];
  if (safe.environmentStage) parts.push(`失败步骤：${stages[safe.environmentStage]}`);
  if (safe.environmentFields) parts.push(`尚未匹配：${safe.environmentFields.map(name => fields[name]).join('、')}`);
  if (safe.rollbackEnvironmentFields) parts.push(`自动回滚尚未匹配：${safe.rollbackEnvironmentFields.map(name => fields[name]).join('、')}`);
  return parts.join('；');
}

export function environmentOutcomeNotice(environment, { mock = false, operation = 'optimize' } = {}) {
  const outcome = environment?.optimization || {}, partial = outcome.status === 'partial';
  const detail = environmentDiagnosticText({ environmentFields: outcome.differingFields });
  if (partial) return { partial, text: `${operation === 'restore' ? '部分设置已复原' : '部分环境设置已生效'}，成功项目已保留。${detail ? `${detail}。` : ''}可再次重试未完成项目；原始快照保留。${mock ? '这是模拟结果，系统未更改。' : ''}` };
  if (mock) return { partial, text: operation === 'restore' ? '模拟复原完成，系统未更改' : '模拟环境调整完成，系统未更改' };
  const completion = operation === 'restore' ? '系统环境已复原，原始快照保留。' : '目标环境已应用并核验。';
  return { partial, text: completion + (environment?.needsSignOut ? '部分语言或输入法需重新登录 Windows。' : environment?.needsApplicationRestart ? '已打开的应用需重新打开。' : '') };
}

export function environmentVerificationView(environment = {}) {
  const verification = environment.verification;
  if (!verification || !['matched', 'partial', 'unverified'].includes(verification.status)) return null;
  const results = Array.isArray(verification.fieldResults) ? verification.fieldResults : [];
  if (!results.length) return null;
  const status = verification.status === 'partial' || results.some(item => item?.status === 'unmatched') ? 'partial'
    : verification.status === 'matched' && results.length && results.every(item => item?.status === 'matched') ? 'matched' : 'unverified';
  const saved = verification.source !== 'live', changed = environment.status === 'conflict' || environment.backup?.drifted === true, subject = saved ? '上次检查的设置' : '当前设置';
  const label = saved ? status === 'matched' ? '上次检查已匹配' : '待重新核验' : status === 'matched' ? '当前已匹配' : status === 'partial' ? '当前部分匹配' : '当前待核验';
  let summary = status === 'matched' ? `${subject}与上次目标匹配。` : status === 'partial' ? `${subject}仍有项目未匹配上次目标，已生效的设置保留。` : '部分环境项目尚无法确认，请重新核验。';
  if (saved) summary += '本次尚未重新读取 Windows。';
  if (changed) summary += '上次操作后设置有变化，历史记录保留。';
  if (['partial', 'failed', 'recovery-required'].includes(environment.optimization?.status)) summary += '上次操作记录保留。';
  return { status, saved, changed, label, summary, needsReview: saved || status !== 'matched' || changed };
}

export function environmentSettingRows(environment = {}) {
  const outcome = environment.optimization || {}, target = outcome.target || {};
  const verification = environmentVerificationView(environment), results = verification ? environment.verification.fieldResults : outcome.fieldResults;
  const saved = verification ? verification.saved : environment.snapshotSource === 'saved';
  const current = ['foreign', 'unbound'].includes(environment.ownership) && environment.snapshotSource === 'saved' ? {} : environment.current || {};
  const languageName = tag => {
    if (typeof tag !== 'string' || !/^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/i.test(tag)) return '未记录';
    try { return `${new Intl.DisplayNames(['zh-CN'], { type: 'language' }).of(tag)}（${tag}）`; } catch { return tag; }
  };
  const languageDetail = () => {
    const observed = current.languages, intended = target.languages, details = [];
    const identity = item => String(item?.languageTag || item || '').toLowerCase().replace(/^zh-hans-(cn|sg)$/, 'zh-$1').replace(/^zh-hant-(tw|hk|mo)$/, 'zh-$1');
    const tips = list => [...new Set(list.map(tip => String(tip).toLowerCase()))].sort().join('|');
    if (Array.isArray(observed) && observed.length && Array.isArray(intended) && intended.length) {
      if (identity(observed[0]) !== identity(intended[0])) details.push(`首选语言未切换至${languageName(intended[0]?.languageTag || intended[0])}`);
      const missing = intended.filter(item => !observed.some(other => identity(other) === identity(item)));
      if (missing.length) details.push(`目标语言尚未加入：${missing.slice(0, 2).map(item => languageName(item?.languageTag || item)).join('、')}${missing.length > 2 ? '等' : ''}`);
      const pairs = intended.map(item => [item, observed.find(other => identity(other) === identity(item))]).filter(([, actual]) => actual);
      if (pairs.some(([item, actual]) => Array.isArray(item.inputMethodTips) && Array.isArray(actual.inputMethodTips) && tips(item.inputMethodTips) !== tips(actual.inputMethodTips))) details.push('输入法条目尚未匹配');
      if (pairs.some(([item, actual]) => typeof item.handwriting === 'boolean' && typeof actual.handwriting === 'boolean' && item.handwriting !== actual.handwriting)) details.push('手写输入设置尚未匹配');
      if (!details.length && observed.map(identity).join('|') !== intended.map(identity).join('|')) details.push('语言排列顺序尚未匹配');
    }
    if (!details.length) details.push('上次语言列表核验未通过，需重新核验');
    if (Array.isArray(results) && results.some(item => item?.field === 'defaultInputMethod' && item.status === 'matched')) details.push(saved ? '上次检查的默认输入法已匹配' : '默认输入法已匹配');
    return details.join('；') + '。';
  };
  const valueText = (field, value, snapshot) => {
    if (field === 'languages') return Array.isArray(value) && value.length ? value.slice(0, 16).map(item => languageName(item?.languageTag || item)).join('、') : '未记录';
    if (field === 'culture') return value === 'zh-SG' ? '中文（简体，新加坡）· zh-SG' : languageName(value);
    if (field === 'homeGeoId') {
      if (!Number.isInteger(value)) return '未记录';
      const country = snapshot?.homeCountryCode || (current.homeGeoId === value ? current.homeCountryCode : null) || (outcome.operation !== 'restore' && target.homeGeoId === value ? environment.appliedRegion?.countryCode : null);
      if (/^[A-Z]{2}$/.test(country || '')) {
        try { return `${new Intl.DisplayNames(['zh-CN'], { type: 'region' }).of(country)}（${country}）`; } catch {}
      }
      return `Windows 地区编号 ${value}`;
    }
    return typeof value === 'string' && value ? value.slice(0, 100) : '未记录';
  };
  return ['timeZoneId', 'languages', 'homeGeoId', 'culture'].map(field => {
    const result = (Array.isArray(results) ? results : []).find(item => item?.field === field);
    const status = ['matched', 'unmatched'].includes(result?.status) ? result.status : 'unknown';
    return { field, label: field === 'languages' ? '首选语言与输入法' : fields[field], current: valueText(field, current[field], current), target: valueText(field, target[field], target), status, currentLabel: saved ? '上次记录' : '当前', statusLabel: (saved ? '上次' : '') + (status === 'matched' ? '已匹配' : status === 'unmatched' ? '尚未匹配' : '待核验'), detail: field === 'languages' && status === 'unmatched' ? languageDetail() : '' };
  });
}
