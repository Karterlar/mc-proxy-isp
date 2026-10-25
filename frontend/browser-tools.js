import { setText, setHtml } from './dom-updates.js';

const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const bounded = value => typeof value === 'string' ? value.slice(0, 700) : '';
export const browserLabels = { chrome: 'Chrome', edge: 'Edge', fingerprint: '指纹浏览器' };
const checkLabels = { verified:'已实测', measured:'已采集', mismatch:'不一致', failed:'检查失败', unverified:'待核验', unsupported:'暂不支持', configured:'仅已配置', mocked:'模拟 · 未实测', stale:'已失效', restricted:'目标受限' };

// A fingerprint choice is intentional even before the optional engine is installed.
export function browserSelection(options, selected, preferred, autoFallback = false) {
  const choices = (Array.isArray(options) ? options : []).filter(item => Object.hasOwn(browserLabels, item.id) && typeof item.available === 'boolean');
  if (autoFallback && choices.some(item => item.id === preferred && item.available)) return { selected: preferred, autoFallback: false, notice: '' };
  if (selected === 'fingerprint') return { selected, autoFallback: false, notice: choices.some(item => item.id === selected && item.available) ? '' : '指纹浏览器引擎尚未准备。请在应用接入页准备引擎，再打开独立窗口。' };
  const fallback = choices.find(item => item.available && item.id !== 'fingerprint');
  if (!choices.some(item => item.id === selected && item.available) && fallback) return { selected: fallback.id, autoFallback: true, notice: `未识别到 ${browserLabels[selected] || '首选浏览器'} 的安装路径，本次使用 ${browserLabels[fallback.id]}；首选浏览器保留` };
  if (!choices.some(item => item.id === selected && item.available)) return { selected, autoFallback, notice: `未识别到 ${browserLabels[selected] || '所选浏览器'}。请安装官方浏览器，或在应用接入重新识别、指定程序路径；指纹浏览器需自行选择。` };
  return { selected, autoFallback, notice: '' };
}

export function browserObservationView(observation = {}, { mock = false, connected = true, now = Date.now() } = {}) {
  const report = observation.report, expired = observation.expiresAt && Number.isFinite(Date.parse(observation.expiresAt)) && Date.parse(observation.expiresAt) <= now;
  const stale = observation.stale === true || observation.status === 'stale' || !connected || Boolean(report && observation.status === 'unverified') || Boolean(expired);
  const simulated = mock || observation.status === 'mocked' || report?.source?.kind === 'fixture';
  const state = stale ? 'stale' : simulated ? 'mocked' : report?.summary?.status === 'mismatch' ? 'mismatch' : observation.status === 'failed' ? 'failed' : report ? 'completed' : observation.status === 'waiting' ? 'waiting' : 'unverified';
  const stateLabel = { stale:'已失效', mocked:'模拟 · 未实测', mismatch:'发现不一致', failed:'检测未完成', completed:'结果已收到', waiting:'等待浏览器测量', unverified:'未检测' }[state];
  const summaries = {
    stale:'上一轮结果已失效，请在当前线路重新检测。旧数据仅供排障参考。',
    mocked:'当前为演示结果，没有访问真实检测服务或启动真实浏览器。',
    mismatch:'浏览器测得值与当前目标不一致，请查看逐项结果；这些数据仅用于诊断。',
    failed:'本轮检测未完成，请查看错误记录并重新生成检测页面。',
    completed:'已收到检测页面所在浏览器的结果。逐项核对出口和隐私项；这不证明其他窗口或桌面应用已被接管。',
    waiting:'请在需要检测的浏览器打开下方链接，再刷新结果。页面只能说明该浏览器当时的网络环境。',
    unverified:'连接后点击检测。原来已打开的浏览器需要单独打开检测链接。',
  };
  const checks = (Array.isArray(report?.checks) ? report.checks : []).slice(0, 24).map(item => {
    const status = stale ? 'stale' : simulated ? 'mocked' : Object.hasOwn(checkLabels, item.status) ? item.status : 'unverified';
    return { label: bounded(item.label) || '浏览器检查', status, statusLabel:checkLabels[status], detail: bounded(item.detail), value: typeof item.value === 'string' || typeof item.value === 'number' ? String(item.value).slice(0, 160) : '' };
  });
  return { state, stateLabel, summary: summaries[state], checks, report, link: stale ? '' : localObservationUrl(observation.url), reason: bounded(observation.reason) };
}

export function localObservationUrl(value) {
  if (typeof value !== 'string' || value.length > 4096) return '';
  try { const url = new URL(value); return url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) && !url.username && !url.password ? url.href : ''; } catch { return ''; }
}

export function applicationDiagnosisView(diagnosis) {
  if (!diagnosis || typeof diagnosis !== 'object') return { summary:'', layers:[] };
  return { summary:bounded(diagnosis.summary), layers:(Array.isArray(diagnosis.layers) ? diagnosis.layers : []).slice(0, 8).map(layer => ({ label:bounded(layer.label) || '链路阶段', status:Object.hasOwn(checkLabels, layer.status) ? layer.status : 'unverified', detail:bounded(layer.detail), code:/^[A-Z][A-Z0-9_]{0,79}$/.test(layer.code || '') ? layer.code : '' })) };
}

export function fingerprintRegionSummary(settings = {}, { ready = true, revision, exitIp, now = Date.now() } = {}) {
  const automatic = settings.language === 'auto' || settings.timezone === 'auto';
  const changed = settings.alignmentRevision !== undefined && revision !== undefined && settings.alignmentRevision !== revision
    || settings.alignmentExitIp && exitIp && settings.alignmentExitIp !== exitIp
    || settings.alignmentExpiresAt && (!Number.isFinite(Date.parse(settings.alignmentExpiresAt)) || Date.parse(settings.alignmentExpiresAt) <= now);
  if (automatic && (!ready || changed)) return '当前自动地区待核验，上一轮匹配不能沿用。连接后启动浏览器会重新匹配；手动设置的项目保留。';
  if (!settings.resolvedLanguage || !settings.resolvedTimezone) return '使用自动匹配时，启动前经当前 ISP 核验语言与时区。';
  const sources = { 'verified-exit':'已核验出口', 'applied-environment':'已优化环境', 'local-environment':'本机环境 · 未匹配出口', manual:'手动设置' };
  const languageSource = settings.languageSource || (settings.language === 'auto' ? settings.alignmentSource : 'manual');
  const timezoneSource = settings.timezoneSource || (settings.timezone === 'auto' ? settings.alignmentSource : 'manual');
  const fallback = [languageSource,timezoneSource].some(source => !['manual','verified-exit'].includes(source));
  const detail = settings.alignmentCode === 'GEO_UNVERIFIED' ? '本次出口地区未能核验；可手动选择，稍后重开会重试。'
    : fallback ? '尚未完成出口地区匹配；启动前自动核验，无法匹配的项目保留本机值。'
      : languageSource === 'manual' && timezoneSource === 'manual' ? '使用手动地区设置；已打开的窗口需重开才生效。' : '自动项随当前出口地区匹配；已打开的窗口需重开才生效。';
  return `下次启动：语言 ${bounded(settings.resolvedLanguage)}（${sources[languageSource] || '来源待核验'}）；时区 ${bounded(settings.resolvedTimezone)}（${sources[timezoneSource] || '来源待核验'}）。${detail}`;
}

const evidenceMarkup = rows => rows.map(row => `<article class="browser-evidence-row"><div><strong>${escape(row.label)}</strong><span class="browser-check-state" data-state="${escape(row.status)}">${escape(row.statusLabel || checkLabels[row.status])}</span></div><p>${escape([row.value, row.detail, row.code].filter(Boolean).join(' · '))}</p></article>`).join('');

export function createBrowserTools({ root = document, request, operation, confirm, getState, onNotice = () => {}, onProfilesChanged = () => {}, clipboard = globalThis.navigator?.clipboard } = {}) {
  const find = id => root.querySelector('#'+id);
  let observation = {}, fingerprint = null, settingsLoaded = false, settingsDirty = false, refreshPending = false, diagnosis = null, diagnosisStale = false, securityChecking = false;
  let profiles = null, profileContextKey = '', profileRequestId = 0, profilesLoading = false, profileError = '', profileMessage = '';

  function profileContext() {
    const state = getState(), workspaceId = state.browserRunning && state.workspaceId || '', browser = workspaceId ? state.activeBrowser || state.browser : state.browser;
    const freshRunning = Boolean(state.browserRunning && !workspaceId && state.activeFresh);
    return { browser, workspaceId, freshRunning, key:`${browser}:${workspaceId}:${Boolean(state.connected)}:${freshRunning}`, blocked:state.locked || !state.connected || freshRunning || !Object.hasOwn(browserLabels,browser) || Boolean(state.browserRunning && !workspaceId && state.activeBrowser && state.activeBrowser !== browser) };
  }

  function renderProfiles() {
    const context = profileContext(), archives = profiles?.browser === context.browser ? profiles.archives : [], select = find('browserProfileArchiveChoice');
    setText(find('browserProfileTitle'), context.workspaceId ? '想从空白资料重新开始？' : '管理默认保留资料');
    setText(find('browserProfileHint'), context.workspaceId ? '为当前用户环境创建替代环境，网站需要重新登录；原环境保留，可在用户浏览器环境中恢复。' : context.freshRunning ? '当前窗口是纯净空间，不属于默认保留资料；刷新与恢复已暂停。请先关闭纯净窗口；需要长期使用和恢复的资料，请到“用户浏览器环境”创建环境。纯净资料不会进入这里的历史。' : `这里只管理 ${browserLabels[context.browser] || '所选浏览器'} 的默认保留资料，不包括纯净空间或用户环境。新建空白资料后需要重新登录；已有的默认资料会保留到历史，可以恢复。${context.browser === 'fingerprint' ? '新资料也会使用新的指纹身份。' : ''}`);
    setText(find('browserProfileRefreshButton').querySelector('span'), context.workspaceId ? '为当前环境新建空白资料' : '刷新默认保留资料');
    find('browserProfileRefreshButton').disabled = context.blocked || profilesLoading;
    find('browserProfileHistory').hidden = Boolean(context.workspaceId);
    const selected = select.value;
    const choicesChanged = setHtml(select, archives.length ? '<option value="">请选择之前的资料</option>' + archives.map(item => {
      const date = Date.parse(item.createdAt), label = Number.isFinite(date) ? new Date(date).toLocaleString('zh-CN',{hour12:false}) : `资料 ${item.id.slice(0,8)}`;
      return `<option value="${escape(item.id)}">${escape(label)}</option>`;
    }).join('') : '<option value="">尚无保留资料</option>');
    if (choicesChanged && archives.some(item => item.id === selected)) select.value = selected;
    select.disabled = context.blocked || profilesLoading || !archives.length;
    find('browserProfileRestoreButton').disabled = context.blocked || profilesLoading || !archives.some(item => item.id === select.value);
    const mismatch = getState().browserRunning && !context.workspaceId && getState().activeBrowser && getState().activeBrowser !== context.browser;
    setText(find('browserProfileStatus'), profileError || (profilesLoading ? '正在读取保留的资料…' : context.freshRunning ? '请先关闭纯净窗口，再管理默认保留资料。' : mismatch ? '请先关闭正在运行的浏览器，再管理其他浏览器的资料。' : profileMessage));
    find('browserProfileStatus').dataset.error = String(Boolean(profileError));
  }

  async function refreshProfiles({quiet = false} = {}) {
    const context = profileContext(), id = ++profileRequestId;
    if (profileContextKey !== context.key) profiles = null;
    profileContextKey = context.key; profileError = ''; profilesLoading = false;
    if (!getState().connected || context.workspaceId) { renderProfiles(); return; }
    profilesLoading = true; renderProfiles();
    try {
      const result = await request(`/api/browser/profiles?browser=${encodeURIComponent(context.browser)}`);
      if (id !== profileRequestId || profileContext().key !== context.key) return;
      if (result?.browser !== context.browser || !Array.isArray(result.archives)) throw new Error('浏览器资料列表不完整，请重试。');
      profiles = {...result,archives:result.archives.filter(item => typeof item?.id === 'string' && item.id.length > 0 && item.id.length <= 160).slice(0,200)};
    } catch (error) {
      if (id !== profileRequestId || profileContext().key !== context.key) return;
      profileError = `${error.message || '读取保留资料失败'} 原资料保留，可稍后重试。`;
      if (!quiet) onNotice(profileError,true);
    } finally { if (id === profileRequestId && profileContext().key === context.key) { profilesLoading = false; renderProfiles(); } }
  }

  function changeProfile(restore = false) {
    const context = profileContext(), archiveId = find('browserProfileArchiveChoice').value;
    if (context.blocked || profilesLoading || restore && (context.workspaceId || !profiles?.archives?.some(item => item.id === archiveId))) return;
    const title = restore ? '恢复之前的默认保留资料' : context.workspaceId ? '为当前环境新建空白资料' : '刷新默认保留资料';
    const explanation = restore ? '将恢复所选资料中的登录、Cookie 和网站存储；当前默认保留资料也会保留。纯净空间和用户环境不受影响。' : context.workspaceId ? '将创建空白的替代环境，网站需要重新登录。原用户环境保留，可到“用户浏览器环境”查看和恢复。' : `将为 ${browserLabels[context.browser]} 的默认保留模式创建空白资料，网站需要重新登录。原资料保留，可在这里恢复；纯净空间和用户环境不在归档范围内。${context.browser === 'fingerprint' ? '新资料会使用新的指纹身份。' : ''}之后持续使用这份新资料。`;
    confirm(title,`${explanation}${!context.workspaceId && getState().fresh ? ' 同时关闭“每次开启纯净空间”，之后保留这份资料。' : ''} 运行中的受管浏览器会安全关闭，请先保存未保存内容。完成后不会自动打开窗口。`, () => {
      if (profileContext().key !== context.key || profileContext().blocked) { onNotice('浏览器或当前环境已变化，请重新选择操作。',true); return; }
      return operation(restore ? '正在恢复浏览器资料…' : '正在创建空白浏览器资料…', async () => {
        let result;
        try { result = await request(context.workspaceId ? '/api/workspaces/refresh' : restore ? '/api/browser/profiles/restore' : '/api/browser/profiles/refresh', {confirm:true,...(context.workspaceId ? {id:context.workspaceId} : {browser:context.browser,...(restore ? {archiveId} : {})})}); }
        catch (error) { profileError = `${error.message || '操作未完成'} 原资料保留，请检查后重试。`; renderProfiles(); throw error; }
        profileError = '';
        const message = restore ? '已恢复所选默认资料。下次打开将继续使用，替换前已有的默认资料也已保留。' : !context.workspaceId && result?.changed === false ? '当前没有默认保留资料可归档。已切换为保留资料模式，下次打开会创建空白资料。' : context.workspaceId ? '空白替代环境已准备。下次打开需要重新登录，原环境已保留。' : '空白默认资料已准备。下次打开需要重新登录，原默认资料已保留。';
        await onProfilesChanged({browser:context.browser,...(context.workspaceId ? {workspaceId:result?.workspace?.id || result?.id} : {})});
        profileMessage = message; await refreshProfiles({quiet:true}); onNotice(message);
      }, 'browser-profile');
    });
  }

  function renderObservation(data = observation) {
    observation = data || {};
    const state = getState(), view = browserObservationView(observation, { mock:state.mock, connected:state.connected && state.ready });
    setText(find('browserObservationState'), view.stateLabel);
    find('browserObservationState').dataset.state = view.state;
    setText(find('browserObservationSummary'), view.summary);
    setText(find('diagnosticsBrowserObservationSummary'), `${view.stateLabel}。${view.summary}`);
    setHtml(find('browserObservationResults'), view.checks.length ? evidenceMarkup(view.checks) : '<p class="empty-state">尚无真实浏览器检测结果。</p>');
    if (find('browserObservationUrl').value !== view.link) find('browserObservationUrl').value = view.link;
    find('browserObservationLinkPanel').hidden = !view.link;
    const report = view.report, metadata = [];
    if (report) {
      metadata.push(['检测对象', report.source?.managedIdentityVerified === true ? browserLabels[report.source?.requestedBrowser] || '受管浏览器' : '打开此页面的浏览器 · 自报环境']);
      if (report.source?.workspaceId) metadata.push(['目标用户环境', `环境 ${bounded(report.source.workspaceId).slice(0,8)}`]);
      else if (report.source?.managedLaunchVerified === true) metadata.push(['目标资料', '默认浏览器环境']);
      if (Number.isFinite(Date.parse(report.observedAt))) metadata.push(['检测时间',new Date(report.observedAt).toLocaleString('zh-CN', { hour12:false })]);
      if (report.browser?.language) metadata.push(['浏览器语言', bounded(report.browser.language)]);
      if (report.browser?.timezone) metadata.push(['浏览器时区', bounded(report.browser.timezone)]);
    }
    setHtml(find('browserObservationContext'), metadata.map(([name,value]) => `<div><dt>${escape(name)}</dt><dd>${escape(value)}</dd></div>`).join(''));
  }

  function renderFingerprint(data = fingerprint) {
    if (data) fingerprint = data;
    const state = getState(), workspaceActive = Boolean(state.browserRunning && state.workspaceId), selected = (workspaceActive ? state.activeBrowser || state.browser : state.browser) === 'fingerprint';
    find('fingerprintSettings').hidden = !selected;
    const option = state.browserOptions?.find(item => item.id === 'fingerprint');
    if (option?.runtime) fingerprint = {...fingerprint, runtime:option.runtime, ...(option.install ? {install:option.install} : {})};
    if (option?.available && fingerprint?.install && ['downloading','verifying','extracting','installing','copying-bundle'].includes(fingerprint.install.status)) fingerprint = {...fingerprint,install:{...fingerprint.install,status:'installed'}};
    const runtime = fingerprint?.runtime || {}, install = fingerprint?.install || {}, installing = ['downloading','verifying','extracting','installing','copying-bundle'].includes(install.status), available = state.browserOptions?.some(item => item.id === 'fingerprint' && item.available) === true;
    const supported = runtime.state !== 'unsupported' && install.status !== 'unsupported';
    const labels = {downloading:'正在下载', verifying:'正在校验', extracting:'正在解压', installing:'正在准备', failed:'准备失败', 'copying-bundle':'正在复制随包引擎'};
    setText(find('fingerprintEngineState'), state.mock ? '演示 · 未实测' : installing || install.status === 'failed' ? labels[install.status] : available ? `已准备${runtime.version ? ' · '+String(runtime.version).slice(0,40) : ''}` : !supported ? '暂不支持此平台' : runtime.state === 'invalid' ? '引擎校验未通过' : '尚未准备');
    find('fingerprintEngineState').dataset.state = state.mock ? 'mocked' : available ? 'configured' : install.status === 'failed' ? 'failed' : 'unverified';
    setText(find('fingerprintEngineHint'), installing ? '引擎在后台准备，可以继续查看连接和结束会话。刷新结果可读取进度。' : available ? '只作用于这里启动的独立窗口。WebRTC 与出口仍需下方浏览器实测；字体、音频和 GPU 默认保留真实值。' : !supported ? '当前平台没有可用的指纹浏览器引擎，请继续使用 Chrome 或 Edge。' : install.code === 'BROWSER_FINGERPRINT_BUNDLE_REQUIRED' ? '缺少随版本提供的新内核组件，请使用完整版本。Chrome 可以继续使用，你的浏览器资料仍保留。' : '首次使用需准备可选引擎。准备完成前保留你的选择，网站按钮暂不可用。');
    const security = fingerprint?.security, securityHint = find('fingerprintSecurityHint');
    securityHint.dataset.state = security?.status || 'unverified';
    const securityText = security?.status === 'outdated' ? `安全版本落后：当前 ${bounded(security.engineVersion)}，已核对的官方稳定基线为 ${bounded(security.baselineVersion)}。本轮功能修复不包含后续全部安全更新，日常使用推荐 Chrome。` : security?.status === 'meets-baseline' ? `已达到 ${bounded(security.baselineVersion)} 安全版本基线；这不代表浏览器不存在漏洞。` : security?.status === 'mocked' ? '演示模式未访问版本服务。' : '安全版本尚未取得有效核对结果。';
    setText(securityHint, securityText + (security?.checkError ? ' 在线检查失败，保留上次已知结果。' : security?.checkedAt ? ` 最近检查：${bounded(security.checkedAt)}。` : ''));
    find('fingerprintCheckSecurityButton').disabled = !state.connected || securityChecking;
    setText(find('fingerprintCheckSecurityButton'), securityChecking ? '正在检查安全版本…' : '检查安全版本');
    find('fingerprintInstallButton').hidden = available;
    setText(find('fingerprintInstallButton'), installing ? '引擎准备中…' : install.status === 'failed' ? '重新准备指纹浏览器引擎' : '准备指纹浏览器引擎');
    find('fingerprintInstallButton').disabled = state.locked || !state.connected || state.browserRunning || installing || !supported;
    find('fingerprintSaveButton').disabled = state.locked || !state.connected || !settingsLoaded || !settingsDirty || workspaceActive;
    find('fingerprintProfilePreferencesButton').disabled = state.locked || !state.connected;
    find('fingerprintRotateButton').disabled = state.locked || !state.connected || !available || state.fresh && !workspaceActive;
    setText(find('fingerprintRotateButton'), workspaceActive ? '更换当前环境指纹，保留资料' : '更换默认指纹，保留资料');
    setText(find('fingerprintSettingsHint'), workspaceActive ? '当前正在运行用户环境：请到“用户浏览器环境 → 更多 → 编辑环境设置”修改其专属设置。下面的轮换只影响当前环境，保留登录和网站资料。' : state.fresh ? '纯净空间每次新建资料与指纹身份，无需轮换。下面设置用于默认浏览器和新建环境；已保存用户环境的设置分别管理。' : '默认浏览器持续使用固定身份。下面设置用于默认浏览器和新建环境；已保存用户环境的设置分别管理。更换指纹保留 Cookie 与登录。');
    for (const id of ['fingerprintLanguage','fingerprintTimezone','fingerprintCanvasProtection']) find(id).disabled = state.locked || !state.connected || !settingsLoaded || workspaceActive;
    if (fingerprint?.settings && !settingsDirty) {
      for (const [id,key] of [['fingerprintLanguage','language'],['fingerprintTimezone','timezone']]) {
        const input = find(id), value = fingerprint.settings[key] || 'auto';
        if (![...input.options].some(item => item.value === value)) { const option = root.createElement('option'); option.value = value; option.textContent = value; input.append(option); }
        input.value = value;
      }
      find('fingerprintCanvasProtection').checked = fingerprint.settings.nativeGraphics === false;
    }
    find('fingerprintCanvasWarning').hidden = !find('fingerprintCanvasProtection').checked;
    setText(find('fingerprintResolvedRegion'), fingerprintRegionSummary(fingerprint?.settings, state));
  }

  function update() {
    const state = getState(), browserAvailable = !state.browserOptions || state.browserOptions.some(item => item.id === state.browser && item.available);
    if (profileContext().key !== profileContextKey) { profileMessage = ''; void refreshProfiles({quiet:true}); } else renderProfiles();
    renderObservation();
    const activeWorkspace = state.browserRunning && state.workspaceId;
    setText(find('browserObservationStartButton'), activeWorkspace ? '检测当前用户环境' : `检测${browserLabels[state.browser] || '所选浏览器'}`);
    find('browserObservationStartButton').disabled = state.locked || !state.ready || !activeWorkspace && (!browserAvailable || state.browserRunning);
    setText(find('browserObservationLinkButton'), activeWorkspace ? '生成当前环境检测链接' : '准备原 Chrome 检测链接');
    find('browserObservationLinkButton').disabled = state.locked || !state.ready;
    find('browserObservationRefreshButton').disabled = state.locked || !state.connected;
    find('browserObservationCopyButton').disabled = state.locked || !find('browserObservationUrl').value;
    renderFingerprint();
    if (!state.ready && diagnosis) diagnosisStale = true;
    renderDiagnosis();
  }

  // Only time-based expiry needs a timer; normal state changes use update().
  function tick() {
    const state = getState();
    const view = browserObservationView(observation, { mock:state.mock, connected:state.connected && state.ready });
    if (find('browserObservationState').dataset.state !== view.state) {
      renderObservation();
      find('browserObservationCopyButton').disabled = state.locked || !view.link;
    }
    if (find('fingerprintResolvedRegion').textContent !== fingerprintRegionSummary(fingerprint?.settings, state)) renderFingerprint();
  }

  function renderDiagnosis(data) {
    if (data !== undefined) { diagnosis = data; diagnosisStale = false; }
    const view = applicationDiagnosisView(diagnosis);
    find('applicationDiagnosis').hidden = !view.layers.length && !view.summary;
    setText(find('applicationDiagnosisSummary'), diagnosisStale ? '上一轮链路检查已失效，请连接当前线路后重新检查。' : view.summary);
    setHtml(find('applicationDiagnosisLayers'), evidenceMarkup(view.layers.map(layer => diagnosisStale ? {...layer,status:'stale'} : layer)));
  }

  async function refresh({quiet = false} = {}) {
    if (refreshPending || !getState().connected) return;
    refreshPending = true;
    try {
      const results = await Promise.allSettled([request('/api/browser-observation'), request('/api/browser/fingerprint')]);
      if (results[0].status === 'fulfilled') renderObservation(results[0].value);
      if (results[1].status === 'fulfilled') { fingerprint = results[1].value; settingsLoaded = true; renderFingerprint(fingerprint); }
      for (const result of results) if (result.status === 'rejected' && !quiet) onNotice(result.reason?.message || '读取检测结果失败，请稍后刷新。',true);
      update();
    } catch (error) { if (!quiet) onNotice(error.message, true); }
    finally { refreshPending = false; }
  }

  function start(launch) {
    const state = getState();
    return operation(launch ? '正在打开真实浏览器检测页面…' : '正在准备本机浏览器检测链接…', async () => {
      const workspaceId = state.browserRunning ? state.workspaceId : undefined;
      const result = await request('/api/browser-observation/start', {confirm:true, browser:workspaceId ? state.activeBrowser || state.browser : state.browser, launch,...(workspaceId?{workspaceId}:{})});
      renderObservation(result.observation || result); await refresh({quiet:true});
      onNotice(state.mock ? '模拟检测链接已准备，未访问真实检测站' : launch ? '检测页面已打开，完成后刷新结果' : '链接已准备，请复制到原来打开的 Chrome');
    }, 'browser');
  }

  find('browserObservationStartButton').addEventListener('click', () => start(true));
  find('browserProfileRefreshButton').addEventListener('click', () => changeProfile());
  find('browserProfileRestoreButton').addEventListener('click', () => changeProfile(true));
  find('browserProfileArchiveChoice').addEventListener('change', renderProfiles);
  find('browserProfileHistory').addEventListener('toggle', () => { if (find('browserProfileHistory').open && profileError) void refreshProfiles(); });
  find('browserObservationLinkButton').addEventListener('click', () => start(false));
  find('browserObservationRefreshButton').addEventListener('click', () => refresh());
  find('browserObservationCopyButton').addEventListener('click', async () => {
    const url = localObservationUrl(find('browserObservationUrl').value);
    if (!url) return;
    try { if (!clipboard?.writeText) throw new Error('复制不可用，请选中并复制检测链接。'); await clipboard.writeText(url); onNotice('本机检测链接已复制'); } catch (error) { onNotice(error.message,true); }
  });
  for (const id of ['fingerprintLanguage','fingerprintTimezone','fingerprintCanvasProtection']) find(id).addEventListener('change', () => { settingsDirty = true; update(); });
  find('fingerprintSaveButton').addEventListener('click', () => operation('正在保存指纹浏览器地区设置…', async () => {
    const result = await request('/api/browser/fingerprint/settings', {confirm:true, language:find('fingerprintLanguage').value, timezone:find('fingerprintTimezone').value, nativeGraphics:!find('fingerprintCanvasProtection').checked});
    settingsDirty = false; fingerprint = result; settingsLoaded = true; renderFingerprint(result); onNotice('地区设置已保存，下次启动时生效');
  }, 'browser-settings'));
  find('fingerprintCheckSecurityButton').addEventListener('click', async () => {
    if (securityChecking || !getState().connected) return;
    securityChecking = true; renderFingerprint();
    try { const result = await request('/api/browser/fingerprint/security', {confirm:true}); fingerprint = {...fingerprint, security:result.security}; }
    catch { onNotice('安全版本检查未完成，已保留上次结果。', true); }
    finally { securityChecking = false; renderFingerprint(); }
  });
  find('fingerprintInstallButton').addEventListener('click', () => confirm('准备指纹浏览器引擎', '从当前安装包复制并校验新指纹内核，无需联网。若缺少组件，请安装完整版本；Chrome 仍可继续使用，原有浏览器资料保留。', () => operation('正在开始准备指纹浏览器引擎…', async () => {
    const result = await request('/api/browser/fingerprint/install', {confirm:true}); fingerprint = {...fingerprint, ...result}; renderFingerprint(); await refresh({quiet:true}); onNotice('引擎准备已开始，可继续操作连接');
  }, 'browser')));
  find('fingerprintRotateButton').addEventListener('click', () => {
    const state=getState(),workspaceId=state.browserRunning?state.workspaceId:undefined;
    confirm('更换指纹，保留资料', `${workspaceId?'只更换当前用户环境':'更换默认浏览器资料'}的指纹种子。运行中的指纹浏览器将关闭并重开，未保存内容可能丢失。Cookie、网站登录和网站存储均保留。需要全新资料，请到“用户浏览器环境”创建替代环境。`, () => operation('正在更换指纹…', async () => {
      await request('/api/browser/fingerprint/rotate', {confirm:true,...(workspaceId?{workspaceId}:{})}); await refresh({quiet:true}); onNotice('所选指纹已更换，Cookie、登录和代理绑定保留');
    }, 'browser'));
  });

  return { update, tick, refresh, refreshProfiles, renderObservation, renderFingerprint, renderDiagnosis };
}
