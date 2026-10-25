// Workspaces orchestrate the existing verified connection; they never own a route.
import { setText, setHtml } from './dom-updates.js';
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
const sites = { chatgpt:'ChatGPT', claude:'Claude', google:'Google', wikipedia:'Wikipedia', github:'GitHub', youtube:'YouTube', tiktok:'TikTok', ping0:'Ping0', cleanip:'CleanIP', ippure:'IPPure', exit:'查看出口' };
const date = value => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toLocaleString('zh-CN', { dateStyle:'medium', timeStyle:'short' }) : '未登记';
const source = { license:'签名许可', provider:'订阅提供方', manual:'手动登记', unknown:'未提供' };
const bytes = value => Number.isSafeInteger(value) && value >= 0 ? value >= 1073741824 ? `${(value/1073741824).toFixed(1)} GB` : `${(value/1048576).toFixed(1)} MB` : '未知';
const languageChoices = [['auto','按已核验 ISP 自动匹配'],['en-US','English (US)'],['en-GB','English (UK)'],['ja-JP','日本語'],['ko-KR','한국어'],['zh-HK','中文（香港）'],['zh-TW','中文（台湾）'],['en-SG','English (Singapore)'],['zh-CN','中文（简体）']];
const timezoneChoices = [['auto','按已核验 ISP 自动匹配'],['America/New_York','美国 · 纽约'],['America/Los_Angeles','美国 · 洛杉矶'],['Asia/Tokyo','日本 · 东京'],['Asia/Seoul','韩国 · 首尔'],['Asia/Hong_Kong','香港'],['Asia/Taipei','台湾'],['Asia/Singapore','新加坡'],['Europe/London','英国 · 伦敦']];
const identityDefault = {language:'auto',timezone:'auto',nativeGraphics:false};
const identityValue = value => value === 'auto' ? '随 ISP 自动匹配' : value || '待保存';
const workspaceBrowser = item => item?.browser || 'fingerprint';
const browserLabels = {chrome:'Chrome',edge:'Edge',fingerprint:'指纹浏览器'};
const observationLabel = item => {
  const observation = item.lastObservation;
  if (!observation || observation.workspaceId && observation.workspaceId !== item.id) return '未检测 · 打开后可检查此环境';
  const labels = { measured:'已采集', completed:'已采集', partial:'已采集 · 部分项目待测', mismatch:'发现不匹配', unverified:'尚未核验', mocked:'模拟 · 未实测' };
  return `${labels[observation.status] || '尚未核验'} · ${date(observation.observedAt)}`;
};

export function createExperienceTools({request, operation, confirm, notice, getState, navigate, afterImport, cancel, beforeStart = async()=>{}, desktop = window.mcDesktop}) {
  const $ = selector => document.querySelector(selector);
  const rawRequest = request;
  request = async (...args) => {
    try { return await rawRequest(...args); }
    catch (error) {
      const messages = { DELIVERY_CONFLICT:'当前配置已变化，请重新选择交付文件并预览。', DELIVERY_DEVICE_INVALID:'这份许可与当前电脑不匹配，请向维护者索取本机交付文件。',
        DELIVERY_LICENSE_INACTIVE:'交付文件中的许可已失效，请先向维护者续期。', DELIVERY_LICENSE_INVALID:'交付文件中的许可校验失败，请向维护者重新获取。',
        DELIVERY_INVALID:'交付文件格式无效，请选择维护者提供的 .mcproxy.json 文件。', DELIVERY_SIZE_INVALID:'交付文件为空或超出大小限制，请重新选择。',
        DELIVERY_VPN_INVALID:'交付文件中的 VPN 配置无效，请向维护者重新生成。', DELIVERY_ISP_INVALID:'交付文件中的 ISP 信息不完整，请向维护者重新生成。',
        DELIVERY_RECOVERY_REQUIRED:'上次导入曾被中断，请在诊断与恢复中处理后再导入。', REMINDERS_CONFLICT:'提醒已在其他操作中更新，请刷新后重新保存。',
        REMINDERS_INPUT_INVALID:'请选择当前 VPN 或 ISP，并填写有效的到期日期。', REMINDERS_STATE_INVALID:'本地提醒记录异常，连接与原有授权仍可使用，请保存故障报告。',
        SUPPORT_REPORT_WRITE_FAILED:'报告保存失败，请选择一个可写的本地目录。' };
      if (messages[error.code]) error.message = messages[error.code];
      throw error;
    }
  };
  let workspaces = {items:[],configured:false,pinned:false}, reminders = {items:[]}, selected = null, editing = null, deliveryPlan = null, refreshing = null, reminderRefreshing = null, reminderDraftDirty = false;
  const section = document.createElement('section');
  section.className = 'screen workspace-page experience-screen'; section.id = 'screen-workspaces'; section.dataset.screen = 'workspaces'; section.hidden = true;
  section.setAttribute('aria-labelledby', 'experienceTitle');
  section.innerHTML = `<div class="screen-heading experience-heading"><div><p class="eyebrow">BROWSER ENVIRONMENTS</p><h1 id="experienceTitle">用户浏览器环境<span>。</span></h1><p>每位用户单独保存浏览器和登录资料，选好环境直接打开。</p></div><button class="secondary-button" id="experienceRefresh" type="button">刷新</button></div>
    <div class="workspace-page-content experience-content" id="workspacesContent">
      <section class="experience-hero" aria-labelledby="workspaceListTitle"><div class="experience-section-title"><div><p class="section-kicker">ISOLATED USER ENVIRONMENTS</p><h2 id="workspaceListTitle">我的用户环境</h2></div><button class="secondary-button" id="workspaceNew" type="button">＋ 新建用户环境</button></div>
        <p class="microcopy" id="workspacePurpose">一位用户建一个环境。推荐 Chrome，固定保存 Cookie 和登录；指纹浏览器可选。需要空白资料时，创建替代环境。</p>
        <div id="workspaceSetup" class="workspace-setup-hint" hidden><strong>先完成连接配置，再创建用户环境</strong><p>到连接配置页保存 VPN 和 ISP，并核验出口。之后创建环境不用重复填写线路。</p><button class="primary-button" id="workspaceConfigure" type="button">去配置线路</button></div>
        <div id="workspaceFirstGuide" class="workspace-first-guide"><strong>第一次用，照这三步就行</strong><ol><li><span>1</span><div>新建用户环境<small>给每位用户起个名字，例如“客户 A”。</small></div></li><li><span>2</span><div>选浏览器与常用网站<small>推荐 Chrome，固定保存登录资料；指纹浏览器按需选用。</small></div></li><li><span>3</span><div>点击“打开此环境”<small>自动连接并核验出口。首次登录后，以后在同一环境继续使用。</small></div></li></ol></div>
        <div class="workspace-direct-option" id="workspaceOptional"><span>只用一个账号？仍可从应用接入打开原来的默认浏览器资料。</span><button class="text-button" id="workspaceDirect" type="button">直接去连接 →</button></div>
        <div id="workspaceList" class="workspace-list" role="group" aria-label="选择用户浏览器环境"></div>
        <div class="workspace-start-row" id="workspaceStartRow"><div><strong id="workspaceSelectedTitle">先创建一个用户环境</strong><p id="workspaceStartHint" class="microcopy" role="status">创建后，点击“打开此环境”。</p></div><div class="workspace-primary-actions"><button class="primary-button" id="workspaceStart" type="button">打开此环境 ↗</button><button class="secondary-button" id="workspaceObserve" type="button">检测此环境</button><button class="danger-outline" id="workspaceCancel" type="button" hidden>取消并断开</button></div></div>
        <form id="workspaceEditor" class="experience-editor" hidden><h3 id="workspaceEditorTitle">新建用户环境</h3><label>1. 用户环境名称<input id="workspaceName" maxlength="40" placeholder="例如：我的日常账号、客户 A" required autocomplete="off"></label><label>2. 此环境使用的浏览器<select id="workspaceBrowser" aria-describedby="workspaceBrowserHint"><option value="chrome">Chrome · 推荐，保留登录</option><option value="edge">Edge · 保留登录</option><option value="fingerprint">指纹浏览器 · 可选</option></select></label><p id="workspaceBrowserHint" class="microcopy" role="status"></p><fieldset><legend>3. 打开环境时访问的网站</legend><div class="workspace-site-choices">${Object.entries(sites).map(([id,label])=>`<label><input type="checkbox" name="workspaceSite" value="${id}" ${['chatgpt','claude'].includes(id)?'checked':''}><span>${label}</span></label>`).join('')}</div></fieldset><fieldset class="workspace-identity-fields" id="workspaceIdentityFields"><legend>4. 这个环境的指纹设置</legend><div class="experience-field-row"><label>浏览器语言<select id="workspaceLanguage">${languageChoices.map(([value,label])=>`<option value="${value}">${label}</option>`).join('')}</select></label><label>浏览器时区<select id="workspaceTimezone">${timezoneChoices.map(([value,label])=>`<option value="${value}">${label}</option>`).join('')}</select></label></div><label class="workspace-graphics-choice"><input id="workspaceCanvasProtection" type="checkbox" checked><span>种子 Canvas 与布局保护<small>字体、音频与 GPU 保留真实值；关闭后 Canvas 与布局也使用真实值。</small></span></label></fieldset><p class="microcopy" id="workspaceEditorHint">设置只作用于此环境；每次打开沿用同一份独立资料，网站会话到期时仍可能需要重新登录。</p><div class="experience-actions"><button class="primary-button" type="submit">保存用户环境</button><button class="text-button" id="workspaceEditorCancel" type="button">取消</button></div></form>
        <details class="workspace-archive-section" id="workspaceArchives" hidden><summary>已归档环境 <span id="workspaceArchiveCount">0</span></summary><p class="microcopy">资料留在本机；恢复后可继续使用原来的浏览器和登录资料。</p><div id="workspaceArchiveList" class="workspace-list"></div></details>
        <details class="workspace-help" id="workspaceHelp"><summary>新建、创建替代环境和更换指纹有什么区别？</summary><p>新建用于不同用户，各自保存资料。创建替代环境会沿用原浏览器类型并使用空白资料；指纹环境同时生成新指纹。旧环境归档，不继承登录和网站存储；不会解除网站对原账号的限制。</p><p>指纹浏览器的“更多”中提供“更换指纹，保留资料”，只更新种子，Cookie 和网站资料仍保留。Chrome / Edge 使用浏览器原生信息。每次只运行一个环境，沿用已核验的 ISP，切换环境不会自动换线路。原有默认浏览器资料仍可从应用接入打开。</p></details>
      </section>
      <section class="detail-section" aria-labelledby="reminderTitle"><div class="experience-section-title"><div><p class="section-kicker">SERVICE REMINDERS</p><h2 id="reminderTitle">到期提醒</h2></div><span class="state-chip" id="reminderCount">正在读取</span></div><div id="reminderCards" class="reminder-cards"></div><p class="microcopy">软件与离线许可期限来自原有授权。VPN / ISP 日期仅用于提醒，不限制软件使用；未提供的日期显示未知。</p><form id="reminderEditor" class="reminder-editor"><label>登记服务<select id="reminderKind"><option value="vpn">VPN</option><option value="isp">ISP</option></select></label><label>手动到期日期<input id="reminderDate" type="date" min="2000-01-01" max="9999-12-31" aria-describedby="reminderEditHint"></label><button class="secondary-button" id="reminderSave" type="submit">保存提醒</button><button class="text-button" id="reminderClear" type="button">清除手动提醒</button></form><p id="reminderEditHint" class="microcopy" role="status"></p></section>
      <section class="detail-section delivery-panel" id="deliveryPanel" aria-labelledby="deliveryTitle"><p class="section-kicker">ONE FILE, READY TO CONNECT</p><h2 id="deliveryTitle">单文件交付</h2><p>选择维护者提供的 <code>.mcproxy.json</code>，预览后导入许可、VPN 和 ISP。已有客户仍可使用原来的许可导入与续费入口。</p><div class="experience-actions"><button class="secondary-button" id="deliveryChoose" type="button">选择交付文件</button><button class="text-button" id="deliveryLicenseLink" type="button">原有授权入口</button></div><input type="file" id="deliveryFile" accept=".json,application/json" hidden><div id="deliveryPreview" class="delivery-preview" hidden></div><div class="experience-actions"><button class="primary-button" id="deliveryApply" type="button" hidden>确认导入</button><button class="text-button" id="deliveryCancel" type="button" hidden>取消导入</button></div><p id="deliveryStatus" class="microcopy" role="status">文件包含连接凭据，请只交给对应客户。导入前先结束当前连接。</p></section>
      <details class="detail-section" id="deliveryExportPanel" hidden><summary>开发者 · 制作单文件交付</summary><p>先在授权管理中为客户生成许可，再在这里合并客户的连接配置。授权库与签发流程保持原样。</p><form id="deliveryExportForm" class="experience-editor"><label>客户 VPN 配置文件<input id="deliveryVpnFile" type="file" accept=".yaml,.yml,.json,.txt,.conf"></label><label>ISP 协议<select id="deliveryIspType"><option value="socks">SOCKS5</option><option value="http">HTTP</option></select></label><div class="experience-field-row"><label>ISP 地址<input id="deliveryIspHost" required autocomplete="off" placeholder="IP 或域名"></label><label>端口<input id="deliveryIspPort" type="number" min="1" max="65535" required></label></div><div class="experience-field-row"><label>账号<input id="deliveryIspUser" autocomplete="off"></label><label>密码<input id="deliveryIspPassword" type="password" autocomplete="new-password"></label></div><label>预期出口 IP<input id="deliveryIspExit" autocomplete="off" placeholder="可留空，导入时实测核验后绑定"></label><label>默认接管方式<select id="deliveryTakeover"><option value="global">全局 TUN</option><option value="smart">智能 TUN</option><option value="application">仅应用代理</option></select></label><button class="primary-button" type="submit">选择客户许可并保存交付文件</button><p class="microcopy" id="deliveryExportStatus" role="status">保存时选择已生成的签名许可；不会签发新授权或新增收费。</p></form></details>
      <section class="detail-section experience-support" aria-labelledby="supportTitle"><div><p class="section-kicker">ONE CLICK SUPPORT</p><h2 id="supportTitle">一键故障报告</h2><p>检查当前链路，生成可发给维护者的脱敏报告。</p><p class="microcopy">不会上传。包含检查状态和错误码，不包含账号密码、配置原文、IP、订阅地址或浏览器资料。</p></div><button class="secondary-button" id="supportExport" type="button">检查并保存报告</button><p id="supportStatus" class="microcopy" role="status"></p></section>
    </div><div class="screen-footer workspace-page-footer"><button class="text-button" id="experienceConnection" type="button">返回连接工作台</button><span class="microcopy">沿用已验证的连接与授权</span></div>`;
  $('#screenHost').append(section);
  const canvasWarning=document.createElement('p');canvasWarning.className='microcopy';canvasWarning.id='workspaceCanvasWarning';canvasWarning.hidden=true;
  canvasWarning.textContent='使用带 Canvas 读回修正的引擎。更新可能改变检测结果；环境种子与登录资料保留。';
  $('#workspaceCanvasProtection').closest('fieldset').append(canvasWarning);
  $('#workspaceCanvasProtection').setAttribute('aria-describedby','workspaceCanvasWarning');
  // Keep the selected workspace's action above a long list of profiles.
  $('#workspaceList').before(section.querySelector('.workspace-start-row'),$('#workspaceEditor'));
  section.querySelector('.workspace-start-row').after($('#workspaceOptional'));
  const reminderAlert=document.createElement('button');reminderAlert.type='button';reminderAlert.className='experience-reminder-alert';reminderAlert.id='experienceReminderAlert';reminderAlert.hidden=true;
  $('#appHeader')?.after(reminderAlert);reminderAlert.addEventListener('click',()=>navigate('workspaces','reminderTitle'));
  const nav = document.createElement('button'); nav.type='button'; nav.id='workspaceSpacesButton'; nav.textContent='用户浏览器环境'; $('#workspaceNav').insertBefore(nav,$('#workspaceApplicationButton'));
  nav.addEventListener('click',()=>navigate('workspaces'));
  function shortcut(parent, label, target) { const button=document.createElement('button');button.type='button';button.className='secondary-button experience-shortcut';button.textContent=label;button.addEventListener('click',()=>navigate('workspaces',target));$(parent)?.prepend(button); }
  shortcut('#configurationContent','已有交付文件？一键导入','deliveryPanel');
  shortcut('#licenseContent','导入单文件交付','deliveryPanel');
  shortcut('#licensing-adminContent','制作单文件交付','deliveryExportPanel');
  shortcut('#diagnosticsContent','一键故障报告','supportTitle');
  const current = () => workspaces.items.find(item=>item.id===selected&&!item.archivedAt);
  const availableItems = () => workspaces.items.filter(item=>!item.archivedAt);
  const locked = () => { const s=getState();return s.busy||s.modal||!s.connected; };
  function updateBrowserEditor() {
    const fingerprint=$('#workspaceBrowser').value==='fingerprint';
    $('#workspaceBrowser').disabled=locked()||Boolean(editing);
    $('#workspaceIdentityFields').hidden=!fingerprint;
    $('#workspaceIdentityFields').disabled=locked()||!fingerprint;
    setText($('#workspaceBrowserHint'),editing?'此环境继续使用原浏览器，保留同一份登录资料。要使用其他浏览器，请新建环境。':fingerprint?'为此用户单独保存指纹和登录资料；重新打开或切换中转节点不会自动更换指纹。':'使用官方浏览器及固定独立资料，保存 Cookie、登录和书签；与日常浏览器资料分开，不修改浏览器指纹。');
    canvasWarning.hidden=!fingerprint||!$('#workspaceCanvasProtection').checked;
  }
  function update() {
    const s=getState(), item=current(), active=s.status?.browser,needsSetup=workspaces.configured===false||workspaces.pinned===false,items=availableItems(),otherRunning=active?.running&&active.workspaceId!==item?.id;
    const navigationLocked=Boolean(s.busy||s.modal);
    $('#connectionWorkspaceButton').disabled=navigationLocked;
    nav.disabled=navigationLocked;
    section.querySelectorAll('button,input,select').forEach(el=>el.disabled=locked());
    for(const id of ['experienceConnection','workspaceDirect','deliveryLicenseLink','workspaceEditorCancel','deliveryCancel'])$(`#${id}`).disabled=navigationLocked;
    $('#experienceRefresh').disabled=navigationLocked||Boolean(refreshing);
    updateBrowserEditor();
    $('#workspaceStart').disabled=locked()||needsSetup||!item||item.bindingMatches===false||s.status?.license?.allowed===false;
    const totalLimit=workspaces.limits?.total||96,activeLimit=workspaces.limits?.active||24;
    $('#workspaceNew').disabled=locked()||needsSetup||items.length>=activeLimit||workspaces.items.length>=totalLimit;
    const editorOpen=!$('#workspaceEditor').hidden;
    setText($('#workspaceNew'),items.length?'＋ 新建用户环境':'创建第一个用户环境');
    $('#workspaceNew').classList.toggle('primary-button',items.length===0);$('#workspaceNew').classList.toggle('secondary-button',items.length>0);
    $('#workspaceNew').hidden=editorOpen||needsSetup;$('#workspaceStartRow').hidden=!item||editorOpen||needsSetup;
    $('#workspaceFirstGuide').hidden=needsSetup||items.length>0||editorOpen;$('#workspaceSetup').hidden=!needsSetup;
    $('#workspaceOptional').hidden=editorOpen;$('#workspaceHelp').hidden=editorOpen;$('#workspaceList').hidden=items.length===0||editorOpen;
    $('#workspaceArchives').hidden=editorOpen||!workspaces.items.some(entry=>entry.archivedAt);
    $('#workspaceConfigure').disabled=locked()||s.status?.proxy?.running===true||active?.running===true;
    setText($('#experienceConnection'),workspaces.items.length?'返回连接工作台':'只想上网？去连接工作台');
    $('#workspaceNew').title=$('#workspaceNew').disabled&&!locked()&&!needsSetup?workspaces.items.length>=totalLimit?`最多保存 ${totalLimit} 个环境（含归档）。`:`最多使用 ${activeLimit} 个环境，请先归档不用的环境。`:'';
    section.querySelectorAll('[data-edit],[data-archive],[data-rebind],[data-replace]').forEach(button=>{const id=button.dataset.edit||button.dataset.archive||button.dataset.rebind||button.dataset.replace;const activeWorkspace=active?.running&&active.workspaceId===id;button.disabled=locked()||activeWorkspace||Boolean(button.dataset.replace&&(needsSetup||workspaces.items.length>=totalLimit));button.title=activeWorkspace?'请先在应用接入关闭此环境，再修改或归档。':button.dataset.replace&&workspaces.items.length>=totalLimit?`已达到 ${totalLimit} 个保存环境的上限。`:'';});
    section.querySelectorAll('[data-restore]').forEach(button=>{button.disabled=locked()||items.length>=activeLimit;button.title=items.length>=activeLimit?`最多使用 ${activeLimit} 个环境，请先归档一个现有环境。`:'';});
    section.querySelectorAll('[data-rotate]').forEach(button=>{const other=active?.running&&active.workspaceId!==button.dataset.rotate;button.disabled=locked()||other;button.title=other?'请先关闭正在运行的其他浏览器环境。':'';});
    section.querySelectorAll('[data-start]').forEach(button=>{const entry=workspaces.items.find(entry=>entry.id===button.dataset.start);button.disabled=locked()||needsSetup||entry?.bindingMatches===false||s.status?.license?.allowed===false;});
    setText($('#workspaceStart'),active?.running&&active.workspaceId===selected?'继续使用此环境':'打开此环境 ↗');
    $('#workspaceObserve').disabled=locked()||!item||needsSetup||item.bindingMatches===false||!s.status?.proxy?.running||otherRunning||s.status?.license?.allowed===false;
    $('#workspaceObserve').title=otherRunning?'请先关闭正在运行的其他环境，再检测所选环境。':!s.status?.proxy?.running?'请先打开此环境，完成连接与出口核验。':'在此环境内打开检测页面，不会另建资料目录。';
    $('#workspaceCancel').hidden=!(s.busy&&s.operationKind==='connect'||s.status?.connectionCancellation?.active);
    $('#workspaceCancel').disabled=Boolean(s.ending)||s.cancelled===true||!(s.busy&&s.operationKind==='connect'||s.status?.connectionCancellation?.active);
    $('#workspaceStart').hidden=!$('#workspaceCancel').hidden;
    $('#workspaceObserve').hidden=!$('#workspaceCancel').hidden;
    $('#deliveryChoose').disabled=locked()||s.status?.proxy?.running===true||active?.running===true;
    $('#deliveryApply').disabled=$('#deliveryChoose').disabled||!deliveryPlan;
    $('#deliveryExportPanel').hidden=!s.admin||typeof desktop?.licenseAdminExportDelivery!=='function';
    setText($('#workspaceSelectedTitle'),item?.name||'先创建一个用户环境');
    setText($('#workspaceStartHint'),item ? item.bindingMatches===false?'当前 ISP 与此环境绑定不一致。请切回原出口，或在“更多”中明确重新绑定。':active?.running&&active.workspaceId===item.id?'此用户环境已打开。可继续使用，或检测当前窗口的实际浏览器信息与出口。':`下一步：点“打开此环境”使用 ${browserLabels[workspaceBrowser(item)]} 访问 ${item.services.map(id=>sites[id]||id).join('、')}，首次登录后在此环境保留资料。` : '创建后，点击“打开此环境”。');
    const reminder=reminders.items.find(item=>item.kind===$('#reminderKind').value);
    for(const id of ['reminderDate','reminderSave'])$(`#${id}`).disabled=locked()||reminder?.editable!==true;
    $('#reminderClear').disabled=locked()||reminder?.editable!==true||!reminder.expiresOn;
    reminderAlert.hidden=!(s.connected&&reminders.noticeCount>0);reminderAlert.disabled=s.modal===true;
  }
  function renderWorkspaces() {
    const items=availableItems(),archives=workspaces.items.filter(item=>item.archivedAt);
    if(!items.some(item=>item.id===selected))selected=items[0]?.id||null;
    setHtml($('#workspaceList'),items.map(item=>{
      const identity=item.identity||{},id=esc(item.id),browser=workspaceBrowser(item),fingerprint=browser==='fingerprint';
      const identitySummary=fingerprint?`<div><dt>语言</dt><dd>${esc(identityValue(identity.language))}</dd></div><div><dt>时区</dt><dd>${esc(identityValue(identity.timezone))}</dd></div><div><dt>图形策略</dt><dd>${identity.nativeGraphics===true?'使用真实 Canvas 与布局':'种子 Canvas 与布局保护'}</dd></div>`:'<div><dt>登录资料</dt><dd>固定独立资料，重新打开继续使用</dd></div><div><dt>浏览器信息</dt><dd>沿用原生信息</dd></div>';
      return `<article class="workspace-card ${selected===item.id?'is-selected':''}" data-browser="${esc(browser)}"><button class="workspace-select" type="button" data-select="${id}" aria-pressed="${selected===item.id}"><span class="workspace-monogram" aria-hidden="true">${esc([...item.name][0])}</span><span><strong>${esc(item.name)}</strong><small>${esc(browserLabels[browser])} · ${workspaces.activeId===item.id?'正在运行':fingerprint?'独立指纹与登录资料':'固定独立登录资料'} · ${item.services.length} 个网站</small></span></button><dl class="workspace-identity-summary">${identitySummary}<div data-binding-state="${item.bindingMatches===false?'mismatch':'bound'}"><dt>绑定出口</dt><dd>${item.bindingMatches===false?'当前 ISP 不匹配':'沿用已绑定 ISP'}</dd></div><div class="workspace-last-observation"><dt>最近检测</dt><dd>${esc(observationLabel(item))}</dd></div></dl><div class="workspace-card-actions"><button type="button" class="secondary-button" data-start="${id}">打开</button><button type="button" class="text-button" data-replace="${id}">创建替代环境</button><details class="workspace-more"><summary>更多</summary><div><button type="button" class="text-button" data-edit="${id}">编辑环境设置</button>${fingerprint?`<button type="button" class="text-button" data-rotate="${id}">更换指纹，保留资料</button>`:''}${item.bindingMatches===false?`<button type="button" class="text-button" data-rebind="${id}">重新绑定当前 ISP</button>`:''}<button type="button" class="text-button" data-archive="${id}">归档环境</button></div></details></div></article>`;
    }).join(''));
    setText($('#workspaceArchiveCount'),archives.length);
    setHtml($('#workspaceArchiveList'),archives.map(item=>`<article class="workspace-card workspace-card-archived"><div class="workspace-archive-heading"><strong>${esc(item.name)} · ${esc(browserLabels[workspaceBrowser(item)])}</strong><small>归档于 ${esc(date(item.archivedAt))}</small></div><p class="microcopy">原浏览器和登录资料保留在本机。</p><button class="secondary-button" type="button" data-restore="${esc(item.id)}">恢复此环境</button></article>`).join(''));
    update();
  }
  function renderReminders() {
    setText($('#reminderCount'),reminders.noticeCount?`${reminders.noticeCount} 项需关注`:'暂无到期提醒');
    setHtml($('#reminderCards'),reminders.items.map(item=>`<article class="reminder-card" data-state="${esc(item.state)}"><span>${esc(item.label)}</span><strong>${item.state==='not-required'?'无需授权':item.state==='unknown'?'日期未知':item.state==='expired'?'已到期':`${Math.max(0,item.daysRemaining??0)} 天后到期`}</strong><small>${item.state==='not-required'?'此版本无使用期限':`${esc(source[item.source]||'未提供')} · ${esc(date(item.expiresAt))}`}</small>${item.usage?`<small>${item.usage.exhausted?'供应商记录：流量已用尽':`剩余 ${esc(bytes(item.usage.remaining))} / 总量 ${item.usage.total===0?'未限制或未提供':esc(bytes(item.usage.total))}`}</small>`:''}${item.observedAt?`<small>订阅记录于 ${esc(date(item.observedAt))}，非实时余额</small>`:''}</article>`).join(''));
    setText(reminderAlert,`${reminders.noticeCount} 项服务即将到期、已到期或流量用尽 · 查看提醒 →`);
    syncReminderEditor();
  }
  function syncReminderEditor({reset=false}={}) {
    const item=reminders.items.find(item=>item.kind===$('#reminderKind').value);
    if(reset||!reminderDraftDirty){$('#reminderDate').value=item?.expiresOn||'';reminderDraftDirty=false;}
    setText($('#reminderEditHint'),item?.editable!==true?'保存对应连接配置后，即可登记该服务的提醒。':item.source==='provider'?'上方以供应商返回的日期为准。这里保存的手动日期仅在供应商未提供到期日时使用。':'手动日期按本机当天结束计算，仅用于提醒；不会影响连接和授权。');
    update();
  }
  async function refreshReminders({quiet=false}={}) {
    if(reminderRefreshing)return reminderRefreshing;
    reminderRefreshing=(async()=>{try{reminders=await request('/api/reminders');renderReminders();}catch(error){if(!quiet)notice(error.message,true);}finally{update();}})().finally(()=>reminderRefreshing=null);return reminderRefreshing;
  }
  async function refresh({quiet=false}={}) {
    if(refreshing)return refreshing;
    refreshing=(async()=>{const results=await Promise.allSettled([request('/api/workspaces'),refreshReminders({quiet})]);if(results[0].status==='fulfilled'){workspaces=results[0].value;renderWorkspaces();}const failed=results.find(r=>r.status==='rejected');if(failed&&!quiet)notice(failed.reason.message,true);})().finally(()=>{refreshing=null;update();});update();return refreshing;
  }
  function edit(item=null) {
    editing=item?.id||null;
    $('#workspaceEditorTitle').textContent=item?'编辑此用户环境':'新建用户环境';
    $('#workspaceName').value=item?.name||'我的日常账号';
    $('#workspaceBrowser').value=item?workspaceBrowser(item):workspaces.defaultBrowser||'chrome';
    section.querySelectorAll('[name="workspaceSite"]').forEach(el=>el.checked=(item?.services||['chatgpt','claude']).includes(el.value));
    const identity={...identityDefault,...workspaces.defaultIdentity,...item?.identity};
    for(const [id,key]of [['workspaceLanguage','language'],['workspaceTimezone','timezone']]){
      const input=$(`#${id}`),value=identity[key];
      if(![...input.options].some(option=>option.value===value)){const option=document.createElement('option');option.value=value;option.textContent=value;input.append(option);}
      input.value=value;
    }
    $('#workspaceCanvasProtection').checked=identity.nativeGraphics===false;
    canvasWarning.hidden=!$('#workspaceCanvasProtection').checked;
    $('#workspaceEditor').hidden=false;update();$('#workspaceName').focus();$('#workspaceName').select();
  }
  $('#workspaceNew').addEventListener('click',()=>edit());
  $('#workspaceBrowser').addEventListener('change',updateBrowserEditor);
  $('#workspaceCanvasProtection').addEventListener('change',updateBrowserEditor);
  $('#workspaceEditorCancel').addEventListener('click',()=>{$('#workspaceEditor').hidden=true;editing=null;update();$('#workspaceNew').focus();});
  $('#workspaceConfigure').addEventListener('click',()=>$('#editIspButton').click());
  $('#workspaceDirect').addEventListener('click',()=>navigate('connection'));
  $('#workspaceEditor').addEventListener('submit',async event=>{event.preventDefault();const services=[...section.querySelectorAll('[name="workspaceSite"]:checked')].map(el=>el.value);if(!services.length){notice('请至少选择一个网站。',true);section.querySelector('[name="workspaceSite"]').focus();return;}const oldIds=new Set(workspaces.items.map(item=>item.id)),wasEditing=editing;const saved=await operation('正在保存用户环境…',async()=>{await request(`/api/workspaces/${editing?'update':'create'}`,{confirm:true,...(editing?{id:editing}:{browser:$('#workspaceBrowser').value}),name:$('#workspaceName').value,services,...($('#workspaceBrowser').value==='fingerprint'?{identity:{version:1,language:$('#workspaceLanguage').value,timezone:$('#workspaceTimezone').value,nativeGraphics:!$('#workspaceCanvasProtection').checked}}:{})});$('#workspaceEditor').hidden=true;editing=null;await refresh();if(!wasEditing){selected=workspaces.items.find(item=>!oldIds.has(item.id)&&!item.archivedAt)?.id||selected;renderWorkspaces();}});if(saved!==false)$('#workspaceStart').focus();});
  $('#workspaceList').addEventListener('click',event=>{
    const button=event.target.closest('button');if(!button||button.disabled||locked())return;
    if(button.dataset.select){selected=button.dataset.select;renderWorkspaces();[...section.querySelectorAll('[data-select]')].find(button=>button.dataset.select===selected)?.focus({preventScroll:true});return;}
    const id=button.dataset.edit||button.dataset.archive||button.dataset.rebind||button.dataset.replace||button.dataset.rotate||button.dataset.start,item=workspaces.items.find(entry=>entry.id===id&&!entry.archivedAt);
    if(!item)return;
    if(button.dataset.start){selected=id;renderWorkspaces();return startWorkspace();}
    if(button.dataset.edit){selected=id;return edit(item);}
    if(button.dataset.rotate&&workspaceBrowser(item)==='fingerprint')return confirm('更换指纹，保留资料',`只更换“${item.name}”的指纹种子；Cookie、登录状态和网站存储仍保留。若此环境正在运行，将关闭并重开，请先保存未提交内容。需要空白资料时，请选择“创建替代环境”。`,()=>operation('正在更换所选环境的指纹…',async()=>{await request('/api/browser/fingerprint/rotate',{confirm:true,workspaceId:id});await refresh();notice('此环境指纹已更换，原登录和网站资料保留。');},'browser'));
    if(button.dataset.replace)return confirm('创建替代环境',`为“${item.name}”创建${workspaceBrowser(item)==='fingerprint'?'新指纹和':''}空白浏览器资料，继续使用 ${browserLabels[workspaceBrowser(item)]}，不继承 Cookie、登录状态或网站存储。旧环境会归档并留在本机，可随时恢复。此操作不会解除原账号的封禁。`,()=>operation('正在创建替代环境…',async()=>{const result=await request('/api/workspaces/replace',{confirm:true,id});selected=result.workspace?.id||null;await refresh();notice('替代环境已创建，旧环境已归档；点击打开后重新登录。');}));
    const rebind=Boolean(button.dataset.rebind);
    confirm(rebind?'重新绑定当前 ISP':'归档用户环境',rebind?`“${item.name}”的浏览器和登录资料保留，以后将使用当前 ISP 出口。请确认这是你希望使用的新出口。`:`“${item.name}”会移入已归档列表。原浏览器和登录资料留在本机，之后可以恢复。`,()=>operation('正在更新用户环境…',async()=>{await request(`/api/workspaces/${rebind?'update':'archive'}`,{confirm:true,id,...(rebind?{rebind:true}:{})});await refresh();notice(rebind?'ISP 绑定已更新。':'环境已归档，原资料保留。');}));
  });
  $('#workspaceArchiveList').addEventListener('click',event=>{const button=event.target.closest('[data-restore]');if(!button||button.disabled||locked())return;void operation('正在恢复归档环境…',async()=>{selected=button.dataset.restore;await request('/api/workspaces/restore',{confirm:true,id:selected});await refresh();notice('环境已恢复，继续使用原浏览器和登录资料。');});});
  function startWorkspace(){const item=current();if(!item||locked())return;const active=getState().status?.browser;const switching=active?.running&&active.workspaceId!==item.id;const start=()=>operation('正在准备用户环境，连接并核验出口…',async()=>{await beforeStart();const s=getState();if(s.cancelled)return;const result=await request('/api/workspaces/start',{confirm:true,id:item.id,...(switching?{confirmSwitch:true}:{}),...(s.vpnInput||{})});if(getState().cancelled)return;await refresh();if(getState().cancelled)return;notice(result?.mock===true||result?.result?.mode==='mocked'||getState().status?.service?.mock===true?'模拟工作区启动完成，未启动真实浏览器。':result?.reused?'环境已就绪，继续使用现有浏览器窗口。':`用户环境已打开，使用此环境保存的 ${browserLabels[workspaceBrowser(item)]} 和登录资料。`);},'connect');if(switching)confirm('切换用户环境','将正常关闭当前受管浏览器，再打开所选环境。请先保存网页中未提交的内容。',start);else void start();}
  $('#workspaceStart').addEventListener('click',startWorkspace);
  $('#workspaceObserve').addEventListener('click',()=>{const item=current();if(!item||locked()||$('#workspaceObserve').disabled)return;void operation('正在此环境中打开真实检测页面…',async()=>{await request('/api/browser-observation/start',{confirm:true,browser:workspaceBrowser(item),workspaceId:item.id,launch:true});await refresh();navigate('applications','browserObservationSection');notice('检测页面已在所选环境打开；稍后刷新检测结果。');},'browser');});
  $('#workspaceCancel').addEventListener('click',()=>cancel());
  async function saveReminder(clear=false) {await operation('正在保存到期提醒…',async()=>{await request('/api/reminders/save',{confirm:true,kind:$('#reminderKind').value,expiresOn:clear?null:$('#reminderDate').value,expectedRevision:reminders.revision});reminderDraftDirty=false;await refreshReminders();notice(clear?'手动提醒已清除。':'提醒已保存，软件授权未改变。');});}
  $('#reminderKind').addEventListener('change',()=>syncReminderEditor({reset:true}));$('#reminderDate').addEventListener('input',()=>reminderDraftDirty=true);
  $('#reminderEditor').addEventListener('submit',event=>{event.preventDefault();if(!$('#reminderDate').value)return notice('请选择日期。',true);void saveReminder();});$('#reminderClear').addEventListener('click',()=>saveReminder(true));
  function clearDelivery() {deliveryPlan=null;$('#deliveryFile').value='';$('#deliveryPreview').replaceChildren();$('#deliveryPreview').hidden=true;$('#deliveryApply').hidden=true;$('#deliveryCancel').hidden=true;}
  function renderDeliveryPreview(preview={}) {
    const modes={global:'全局 TUN',smart:'智能 TUN',application:'仅应用代理'};
    const rows=[['连接方式',preview.connectionMode==='vpn-import'?'客户 VPN → 指定 ISP':'当前版本暂不支持此交付线路'],
      ['VPN 节点',`${Number.isSafeInteger(preview.vpn?.supported)?preview.vpn.supported:0} 个可用${preview.vpn?.unsupported?`，另有 ${preview.vpn.unsupported} 个不支持的节点`:''}`],
      ['ISP 入口',`${preview.isp?.type==='http'?'HTTP':'SOCKS5'} · ${preview.isp?.authenticated?'账号密码认证':'无账号认证'} · ${preview.isp?.pinnedExits?'已指定预期出口':'导入时核验出口'}`],
      ['接管方式',modes[preview.takeoverMode]||'未识别'],['文件内软件有效期',date(preview.license?.expiresAt)],['文件内离线许可有效期',date(preview.license?.offlineUntil)]];
    for(const [key,label]of Object.entries({vpnExpiresAt:'VPN 参考日期',ispExpiresAt:'ISP 参考日期',vpsExpiresAt:'VPS 参考日期'}))if(Number.isSafeInteger(preview.reminders?.[key]))rows.push([label,date(preview.reminders[key])]);
    const licensing=preview.mock?'当前为演示模式，只预览，不应用许可或配置。':preview.license?.required===false?'开发者模式不应用许可；原授权签发和续费入口保留。':preview.license?.verified===true?'已核验许可签名与本机匹配。':'正式导入仍须完成许可签名与本机匹配校验。';
    $('#deliveryPreview').innerHTML=`<strong>将导入以下客户配置</strong><dl class="delivery-preview-grid">${rows.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><p class="microcopy">${licensing} 文件中的账号、密码和订阅地址不会显示在此预览中。</p>${preview.remindersNotice?'<p class="microcopy">资源日期仅供参考，不会自动登记或限制连接；导入后请在“到期提醒”中确认。</p>':''}`;
    $('#deliveryPreview').hidden=false;
  }
  $('#deliveryChoose').addEventListener('click',()=>$('#deliveryFile').click());
  $('#deliveryCancel').addEventListener('click',()=>{clearDelivery();$('#deliveryStatus').textContent='已取消，本机配置未修改。';});
  $('#deliveryFile').addEventListener('change',async()=>{const file=$('#deliveryFile').files?.[0];clearDelivery();if(!file)return;if(file.size>1536*1024)return notice('交付文件不能超过 1.5 MiB。',true);const checked=await operation('正在检查交付文件与本机授权…',async()=>{const result=await request('/api/delivery/preview',{text:await file.text()});deliveryPlan=result;renderDeliveryPreview(result.preview);$('#deliveryApply').hidden=false;$('#deliveryCancel').hidden=false;$('#deliveryStatus').textContent='预览有效期 5 分钟。确认后验证线路并保存；失败时保留原配置。';});if(checked!==false)$('#deliveryApply').focus();});
  $('#deliveryApply').addEventListener('click',()=>{if(!deliveryPlan)return;const token=deliveryPlan.token,preview=deliveryPlan.preview||{};const confirmation=preview.mock?'当前为演示模式，本次只验证交互，不会写入连接配置或授权。':preview.license?.required===false?'将替换本机 VPN、ISP 与接管偏好。开发者模式不应用许可，工作区资料与原授权续费入口保留。':'将替换本机 VPN、ISP 与接管偏好，并按原有规则导入签名许可。工作区资料与原授权续费入口保留。';confirm('导入此客户交付',confirmation,()=>operation('正在验证并导入交付…',async()=>{
    const result=await request('/api/delivery/import',{confirm:true,token});clearDelivery();
    if(result.imported!==true){$('#deliveryStatus').textContent=result.mock?'模拟预览完成，没有写入连接配置或授权。':'本次没有确认导入成功，请刷新状态后再检查。';notice($('#deliveryStatus').textContent,result.mock!==true);return;}
    let refreshFailed=false;try{await afterImport();await refresh();}catch{refreshFailed=true;}
    $('#deliveryStatus').textContent=refreshFailed?'交付已保存，状态刷新失败，请刷新或重启查看。':result.cleanupPending?'交付已保存，恢复记录将在下次启动时完成收尾。': '交付导入成功。可创建工作区，或到连接工作台开始连接。';
    if(result.remindersNotice)$('#deliveryStatus').textContent+=' 资源日期仅供参考，请在到期提醒中确认登记。';
    notice(refreshFailed?'交付已保存，请刷新查看当前状态。':result.cleanupPending?'交付已保存，下次启动将完成收尾。':'交付已导入。',refreshFailed);
  }));});
  $('#deliveryLicenseLink').addEventListener('click',()=>navigate('license'));
  $('#deliveryExportForm').addEventListener('submit',async event=>{event.preventDefault();const file=$('#deliveryVpnFile').files?.[0];if(!file||file.size>1024*1024)return notice('请选择不超过 1 MiB 的客户 VPN 配置。',true);await operation('正在制作客户交付文件…',async()=>{const result=await desktop.licenseAdminExportDelivery({vpnText:await file.text(),connectionMode:'vpn-import',takeoverMode:$('#deliveryTakeover').value,isp:{type:$('#deliveryIspType').value,host:$('#deliveryIspHost').value.trim(),port:Number($('#deliveryIspPort').value),username:$('#deliveryIspUser').value,password:$('#deliveryIspPassword').value,expectedExitIps:$('#deliveryIspExit').value.split(/[,，\s]+/).filter(Boolean)}});$('#deliveryExportStatus').textContent=result.canceled?'已取消，未创建交付文件。':'交付文件已保存。请只发给对应客户，原许可文件也可继续使用。';if(!result.canceled){$('#deliveryExportForm').reset();}});});
  $('#supportExport').addEventListener('click',()=>operation('正在检查链路并生成脱敏报告…',async()=>{if(desktop?.exportSupportReport){const result=await desktop.exportSupportReport();$('#supportStatus').textContent=result.canceled?'已取消保存。':'故障报告已保存，可将这个 JSON 文件发给维护者。';}else{const report=await request('/api/support/report',{});const link=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));link.href=url;link.download='MC-Proxy-support-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);$('#supportStatus').textContent='已生成脱敏报告，请查看浏览器下载。';}}));
  $('#experienceRefresh').addEventListener('click',()=>refresh());$('#experienceConnection').addEventListener('click',()=>navigate('connection'));
  return {refresh,refreshReminders,update,selectWorkspace:async id=>{await refresh();if(workspaces.items.some(item=>item.id===id&&!item.archivedAt)){selected=id;renderWorkspaces();}},clearSensitive:()=>{clearDelivery();$('#deliveryExportForm').reset();}};
}

