import { createControllerClient } from './controller-client.js';
import { connectionReady, connectionControls, connectionView, connectionEvidenceView, systemProtectionReady, systemExitReady, failureDetails, sessionPreferenceDefaults, sessionPreferencePayload, createPreferenceWriter, preferredTakeoverMode } from './workspace-view.js';
import { initLayoutPreferences } from './layout-preferences.js';
import { createLicensePage } from './license-page.js';
import { createLicensingAdminPage, licensingAdminAvailable } from './licensing-admin-page.js';
import { createBrowserTools, browserLabels, browserSelection } from './browser-tools.js';
import { createExperienceTools } from './experience-tools.js';
import { environmentDiagnosticText, environmentOutcomeNotice, environmentSettingRows, environmentVerificationView } from './environment-feedback.js';
import { setText, setHtml } from './dom-updates.js';

const controllerClient = createControllerClient();
const api = controllerClient.request;
let connectionRead = null, connectionReadGeneration = 0;
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const STEPS = ['configuration', 'environment', 'preferences', 'connection'];
const WORKSPACE_PAGES = ['connection', 'workspaces', 'applications', 'diagnostics', 'license', 'licensing-admin'];
const app = { step:'splash', connected:false, status:null, onboarding:null, configuration:{}, relay:{}, vpnConfig:{}, vpnLatency:null, relayCheck:null, configurationBaseline:null, configurationEditing:false, environment:{}, browserOptions:null, browserSelectionNotice:'', browserAutoFallback:false, preferences:{...sessionPreferenceDefaults}, environmentChecked:false, environmentStage:'idle', busy:false, operationKind:null, operationId:0, drawer:null, modalAction:null, lastFocused:null, cleanupPlan:null, claudePlan:null, report:null, quality:null, maxStep:0 };
const layoutPreferences=initLayoutPreferences({canEdit:()=>!app.modalAction});
const licensePage=createLicensePage({request:api,onStatus:license=>{app.status={...(app.status||{}),license};updateControls();}});
const licensingAdminPage=createLicensingAdminPage({desktop:window.mcDesktop});
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const mock = () => app.status?.service?.mock === true;
const adminAvailable = () => licensingAdminAvailable(app.desktopInfo,mock());
const savedConnectionMode = () => ['vpn-compat','vpn-import'].includes(app.configuration.connectionMode) ? app.configuration.connectionMode : 'relay';
const connectionMode = () => proxy().running ? proxy().connectionMode || savedConnectionMode() : savedConnectionMode();
const vpnCompat = () => connectionMode() !== 'relay';
const externalVpn = () => connectionMode() === 'vpn-compat';
const importedVpn = () => connectionMode() === 'vpn-import';
const draftVpnCompat = () => $('#connectionMode').value !== 'relay';
const draftExternalVpn = () => $('#connectionMode').value === 'vpn-compat';
const draftImportedVpn = () => $('#connectionMode').value === 'vpn-import';
const vpnProxyInput = () => $('#vpnProxyType').value === 'auto' ? {} : {vpnProxy:{type:$('#vpnProxyType').value,host:'127.0.0.1',port:Number($('#vpnProxyPort').value)}};
const vpnProxyValid = () => $('#vpnProxyType').value === 'auto' || $('#vpnProxyPort').value !== '' && $('#vpnProxyPort').validity.valid;
const relayMissing = (mode = savedConnectionMode()) => mode === 'relay' && app.relay.required === true && !app.relay.configured && !mock();
const proxy = () => app.status?.proxy || {};
const connectionButtons = () => {
  const control=connectionControls({ status: app.status || {}, busy: app.busy, operationKind: app.operationKind, ending: app.connectionEnding, quitting: app.quitting });
  return app.repairPending?{...control,canEnd:false,canQuit:false,canResume:false}:control;
};
const browserRunning = () => app.status?.browser?.running === true;
const selectedBrowserName = () => browserLabels[$('#browserChoice').value] || 'Chrome';
const activeBrowserName = () => browserRunning() ? browserLabels[app.status.browser.browser] || '受管浏览器' : selectedBrowserName();
const renderApplicationBrowserIcon = () => {
  const fingerprint=$('#applicationBrowserChoice').value==='fingerprint',icon=$('#applicationBrowserIcon');
  icon.hidden=fingerprint;$('#applicationFingerprintIcon').toggleAttribute('hidden',!fingerprint);
  const source=`./assets/brands/${$('#applicationBrowserChoice').value==='edge'?'edge':'chrome'}.png`;
  if(icon.getAttribute('src')!==source)icon.src=source;
};
const environmentNeedsReview = () => environmentVerificationView(app.environment)?.needsReview ?? (['partial','conflict','recovery-required'].includes(app.environment.status) || ['partial','recovery-required'].includes(app.environment.optimization?.status) || app.environment.backup?.drifted === true);
const liveEnvironment = env => env.snapshotSource === 'live' && typeof env.current?.timeZoneId === 'string' && typeof env.current?.culture === 'string' && !['error','failed'].includes(env.status);
const ready = () => connectionReady(app.status, app.connected);
const systemProtected = () => systemProtectionReady(app.status, app.connected);
const systemExitVerified = () => systemExitReady(app.status, app.connected);
const alive = plan => Boolean((plan?.token || plan?.planId) && Number.isFinite(Date.parse(plan.expiresAt)) && Date.parse(plan.expiresAt) > Date.now());
const timeLabel = value => Number.isFinite(Date.parse(value)) ? new Date(value).toLocaleString('zh-CN',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}) : '—';
const cleanupItems = () => $$('input[name="cleanupItem"]:checked').map(input => input.value);
const cleanupSignature = () => JSON.stringify({browser:$('#cleanupBrowser').value,items:cleanupItems(),revision:app.status?.revision});
const configurationSignature = () => JSON.stringify([...['#ispHost','#ispPort','#ispType','#ispAuth','#ispUsername','#ispPassword','#expectedExitIps','#connectionMode'].map(id=>$(id).value),draftImportedVpn()?`${app.vpnConfig?.id||''}:${app.vpnConfig?.selectedIndex??'auto'}`:'']);
const configurationDirty = () => app.configurationBaseline!==null&&configurationSignature()!==app.configurationBaseline;
const labels = {verified:'出口匹配',mocked:'模拟',reachable:'可达',failed:'失败',mismatch:'出口不一致',restricted:'访问受限',pass:'通过',partial:'部分完成',unverified:'未验证',locked:'已锁定',unlocked:'未锁定',unavailable:'不可用',unsupported:'不支持',error:'状态异常',conflict:'策略冲突',locking:'锁定中','recovery-required':'需要恢复'};
const browserTools=createBrowserTools({request:api,operation:action,confirm:confirmAction,onNotice:toast,onProfilesChanged:async({workspaceId,browser}={})=>{if(!workspaceId)await savePreferenceChanges(browser==='fingerprint'?{fingerprintFresh:false}:{fresh:false});hydrateOnboarding(await api('/api/onboarding'));await refreshStatus({force:true});if(workspaceId){setScreen('workspaces');await experienceTools.selectWorkspace(workspaceId);}},getState:()=>({connected:app.connected,ready:ready(),mock:mock(),locked:app.busy||Boolean(app.modalAction)||Boolean(app.repairPending),browser:$('#browserChoice').value,activeBrowser:app.status?.browser?.browser,browserOptions:app.browserOptions,revision:app.status?.revision,exitIp:proxy().exit?.ip,browserRunning:browserRunning(),activeFresh:app.status?.browser?.fresh===true,workspaceId:app.status?.browser?.workspaceId,fresh:$('#freshProfile').checked})});
const experienceTools=createExperienceTools({request:api,operation:action,confirm:confirmAction,notice:toast,navigate:openWorkspacePage,beforeStart:()=>preferenceWriter.flush(),cancel:()=>endSession({cancel:true}),afterImport:async()=>{hydrateOnboarding(await api('/api/onboarding'));await refreshStatus({force:true});},getState:()=>({connected:app.connected,busy:app.busy,modal:Boolean(app.modalAction),ending:app.connectionEnding,cancelled:app.cancelledOperationId===app.operationId,operationKind:app.operationKind,status:app.status,admin:adminAvailable(),vpnInput:externalVpn()?{vpnConfirmed:$('#vpnConfirmed').checked,...vpnProxyInput()}:undefined})});
const preferenceWriter=createPreferenceWriter({
  request:payload=>api('/api/onboarding/preferences',sessionPreferencePayload(payload),{timeoutMs:10000}),
  onSaved:(result,snapshot)=>{app.onboarding={...(app.onboarding||{}),...result,preferences:snapshot};},
  onState:(state,error)=>{
    app.preferenceSaveState=state;
    $('#preferencesSaveStatus').textContent=state==='saving'?'正在保存偏好…':state==='saved'?'偏好已保存':'偏好未保存；请重试保存，当前选择已保留。';
    $('#takeoverModeHint').textContent=(state==='failed'?'接管方式未保存，请重试。':state==='saving'?'正在保存接管偏好。':'接管方式自动保存。')+' 使用 TUN 前请关闭其他 VPN。';
    if(state==='failed'){showError(`偏好保存失败：${error.message} 当前选择已保留；可在“会话偏好”重试保存。`);app.preferenceSaveErrorText=app.errorMessage;}
    if(state==='saved'&&app.preferenceSaveErrorText){if(app.errorMessage===app.preferenceSaveErrorText)showError();app.preferenceSaveErrorText=null;}
  },
});

function renderErrorNotice() {
  for(const [drawer,notice,text,dismiss] of [[false,'errorNotice','errorNoticeText','dismissErrorButton'],[true,'drawerErrorNotice','drawerErrorText','dismissDrawerErrorButton']]) {
    const visible=Boolean(app.errorMessage)&&Boolean(app.drawer)===drawer;
    const container=document.getElementById(notice);
    container.hidden=!visible;
    setText(document.getElementById(text),visible?app.errorMessage:'');
    document.getElementById(dismiss).hidden=app.errorPersistent===true;
  }
}
function showError(message='',{persistent=false}={}) {
  if(!message&&app.errorPersistent&&(app.startupRecovery?.required||app.onboarding?.recoveryRequired))return;
  app.errorMessage=message+(/环境|快照|时区|语言|输入法/.test(message)&&environmentNeedsReview()&&app.environment.backup?.canRestore===true?' 可在“系统环境”重新应用工作设置，或恢复已保存的日常环境。':'');
  app.errorPersistent=Boolean(message)&&persistent;
  if(message)$('#toastStack').replaceChildren();
  renderErrorNotice();
}
function dismissError() {
  if(app.errorPersistent)return;
  const focused=document.activeElement;
  showError();
  if(focused?.id==='dismissErrorButton'||focused?.id==='dismissDrawerErrorButton') {
    const target=app.drawer?$('#closeDrawerButton'):$(`#screen-${app.step} h1`);
    target?.focus({preventScroll:true});
  }
}
function toast(message, failed=false) {
  if(failed){showError(message);return;}
  const item=document.createElement('div');item.className='toast';item.textContent=message;$('#toastStack').replaceChildren(item);window.setTimeout(()=>item.remove(),5500);
}
function readPreferences() { const fingerprint=$('#browserChoice').value==='fingerprint';return {autoOptimize:$('#autoOptimize').checked,browser:$('#browserChoice').value,fresh:fingerprint?app.preferences.fresh:$('#freshProfile').checked,fingerprintFresh:fingerprint?$('#freshProfile').checked:app.preferences.fingerprintFresh===true,externalReport:$('#autoExternalReport').checked}; }
const selectedBrowserFresh = () => $('#browserChoice').value==='fingerprint'?readPreferences().fingerprintFresh:readPreferences().fresh;
function changeBrowserSelection(browser){$('#browserChoice').value=browser;$('#freshProfile').checked=browser==='fingerprint'?app.preferences.fingerprintFresh===true:app.preferences.fresh===true;app.browserSelectionNotice='';app.browserAutoFallback=false;renderBrowserOptions();rememberPreferences({browser:$('#browserChoice').value});if(browser==='fingerprint')void browserTools.refresh({quiet:true});}
function savePreferenceChanges(changes={},options={}){
  const pending=preferenceWriter.write({...readPreferences(),browser:app.browserAutoFallback?app.preferences.browser:$('#browserChoice').value,...changes},options);
  app.preferences=preferenceWriter.values();
  return pending;
}
function rememberPreferences(changes={}){void savePreferenceChanges(changes).catch(()=>{});updateControls();}
const selectedTakeoverMode = () => preferredTakeoverMode(savedConnectionMode(),app.preferences);
function renderNavigation() {
  const splash=app.step==='splash',setup=['configuration','environment','preferences'].includes(app.step);
  $('#appHeader').hidden=splash;$('#stepTrack').hidden=splash||!setup;$('#workspaceNav').hidden=splash;
}
function setScreen(step,{allowFuture=false}={}) {
  if (step!=='splash'&&!STEPS.includes(step)&&!WORKSPACE_PAGES.includes(step)) return;
  if(step==='licensing-admin'&&!adminAvailable())return;
  if(app.step==='license'&&step!=='license')licensePage.clearInputs();
  if(app.step==='workspaces'&&step!=='workspaces')experienceTools.clearSensitive();
  if(app.step==='licensing-admin'&&step!=='licensing-admin')licensingAdminPage.clearInputs();
  const index=STEPS.indexOf(step), prior=STEPS.indexOf(app.step); if(index>=0&&index>app.maxStep&&!allowFuture)return;
  closeDrawer(); app.step=step; if(index>=0&&index<3)app.setupNavigation=true; connectionReadGeneration++; if(step!=='applications')$('#observeConnections').checked=false; $('#appFrame').dataset.currentScreen=step; app.maxStep=Math.max(app.maxStep,index);
  $$('[data-screen]').forEach(screen=>{const selected=screen.dataset.screen===step;screen.hidden=!selected;screen.classList.toggle('is-back',selected&&index>=0&&prior>=0&&index<prior);if(selected)screen.scrollTop=0;});
  renderNavigation();$('#mockNotice').hidden=!mock()||step==='splash';
  for(const[id,page]of Object.entries({workspaceConnectionButton:'connection',workspaceSpacesButton:'workspaces',workspaceApplicationButton:'applications',workspaceRecoveryButton:'diagnostics'})){if(step===page)$('#'+id).setAttribute('aria-current','page');else $('#'+id).removeAttribute('aria-current');}
  $$('[data-step]').forEach(button=>{const n=STEPS.indexOf(button.dataset.step);button.classList.toggle('is-current',n===index);button.classList.toggle('is-complete',n<index);if(n===index)button.setAttribute('aria-current','step');else button.removeAttribute('aria-current');});
  const heading=$(`#screen-${step} h1`);if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
  updateControls();
  if(step==='diagnostics')void refreshClientLogState();
}
function adminAccessStatusText(access){
  if(access?.mock===true)return '管理员权限：演示模式未检查。';
  if(access?.checked!==true||access.errorCode==='ADMIN_CHECK_FAILED')return '管理员权限：暂时无法确认，请重新启动核验。';
  if(access.errorCode==='ADMIN_CAPABILITY_DENIED'&&access.elevated===true&&access.tokenMatched===true)return '管理员权限：已提权，但系统未允许所需的管理员能力。';
  if(access.errorCode==='ADMIN_REQUIRED'||access.elevated===false)return '管理员权限：尚未提权，连接操作保持锁定。';
  if(access.elevated===true&&access.adminMember===true&&['high','system'].includes(access.integrity)&&access.tokenMatched===true&&access.capabilityVerified===true&&access.errorCode===null)return '管理员权限与能力已验证。';
  return '管理员权限：暂时无法确认，请重新启动核验。';
}
async function refreshClientLogState(){
  if(typeof window.mcDesktop?.getInfo!=='function'){$('#adminAccessStatus').textContent=adminAccessStatusText();return;}
  try{const info=await window.mcDesktop.getInfo();app.desktopInfo=info;$('#adminAccessStatus').textContent=adminAccessStatusText(info.adminAccess);$('#clientLogStatus').textContent=info.clientLog?.ok===false?`客户端日志未能写入（${info.clientLog.errorCode||'DESKTOP_LOG_WRITE_FAILED'}），请检查用户目录权限，旧日志保留。`:'客户端日志按大小滚动保存，最多三份。';}catch{$('#adminAccessStatus').textContent=adminAccessStatusText();$('#clientLogStatus').textContent='客户端日志状态暂时无法读取。';}
}
function openWorkspacePage(page,section){
  if(app.modalAction||app.busy&&!['connection','diagnostics'].includes(page))return;
  if(page==='licensing-admin'&&!adminAvailable())return;
  if(!WORKSPACE_PAGES.includes(app.step))app.workspaceOrigin=app.step;
  setScreen(page,{allowFuture:true});
  if(page==='diagnostics'){
    const environment=section==='diagnosticsEnvironment';$('#screen-diagnostics').dataset.section=section||'';
    $('#diagnosticsTitle').textContent=environment?'系统环境':'诊断与恢复';
    $('#diagnosticsTitle').nextElementSibling.textContent=environment?'工作时应用，结束后恢复你保存的日常设置。':'查看最近错误，分别处理网络、系统环境与连接保护。';
    $('#diagnosticsRefreshButton').innerHTML=`${environment?'重新核验环境':'刷新状态'} <svg class="icon"><use href="#i-refresh"/></svg>`;
  }
  const content=$(`#${page}Content`);if(content)content.scrollTop=0;
  if(section&&content)requestAnimationFrame(()=>{const target=document.getElementById(section);if(target){const disclosure=target.closest('details');if(disclosure)disclosure.open=true;content.scrollTop+=target.getBoundingClientRect().top-content.getBoundingClientRect().top;target.tabIndex=-1;target.focus({preventScroll:true});}});
  if(page==='applications'){void refreshApplications();void browserTools.refresh({quiet:true});}
  if(page==='license')void licensePage.open();
  if(page==='licensing-admin')void licensingAdminPage.open();
  if(page==='workspaces')void experienceTools.refresh();
}
function returnToWorkspace(){const target=app.maxStep>=3?'connection':STEPS.includes(app.workspaceOrigin)?app.workspaceOrigin:'configuration';setScreen(target);}
function hydrateOnboarding(data) {
  app.onboarding=data.onboarding||{};app.configuration=data.configuration||{};app.startupRecovery=data.startupRecovery||null;if(data.environment)app.environment=data.environment;if(data.relay)app.relay=data.relay;
  if(data.vpnConfig)app.vpnConfig=data.vpnConfig;
  if(Object.hasOwn(data,'vpnLatency'))app.vpnLatency=data.vpnLatency;
  app.preferences=preferenceWriter.hydrate(app.onboarding.preferences);
  $('#autoOptimize').checked=app.preferences.autoOptimize!==false;$('#browserChoice').value=Object.hasOwn(browserLabels,app.preferences.browser)?app.preferences.browser:sessionPreferenceDefaults.browser;$('#freshProfile').checked=app.preferences.browser==='fingerprint'?app.preferences.fingerprintFresh===true:app.preferences.fresh===true;
  $('#autoExternalReport').checked=app.preferences.externalReport===true;
  app.browserSelectionNotice='';app.browserAutoFallback=false;renderBrowserOptions(data.browserOptions);
  const cfg=app.configuration;$('#ispHost').value=cfg.host||'';$('#ispPort').value=cfg.port||'';$('#ispType').value=cfg.type==='socks'?'socks':'http';$('#ispAuth').value=cfg.auth==='none'?'none':'basic';$('#ispUsername').value=cfg.username||'';$('#ispPassword').value='';$('#expectedExitIps').value=(cfg.expectedExitIps||[]).join(', ');$('#connectionMode').value=savedConnectionMode();
  $('#passwordHint').textContent=cfg.credentialsConfigured?'已保存 · 同端点留空保留':'保存在本机受限目录';
  $('#configurationNote').textContent=cfg.credentialsConfigured?'已有本机凭据。端点与协议不变时，账户和密码均留空可保留。':'凭据只提交给本机控制服务，不在页面回显。';
  if(cfg.readOnly)$('#configurationNote').textContent='当前使用外部配置文件，可继续连接与质量检测。此处只读，请在原配置文件中修改 ISP。';
  const saved=Boolean(app.onboarding.completedAt||app.onboarding.firstRun===false);$('#preferencesIntro').textContent=saved?'已载入上次偏好；修改后自动保存，清理仍由你逐次确认。':'偏好修改后自动保存，清理由你逐次确认。';$('#preferencesContinueButton').innerHTML=`${saved?'沿用偏好，准备连接':'保存偏好，准备连接'} <svg class="icon" aria-hidden="true"><use href="#i-arrow"/></svg>`;
  app.configurationBaseline=configurationSignature();app.configurationEditing=!cfg.available;renderConfiguration();renderRelay();renderConnectionOptions();renderVpnConfig();renderEnvironment();updateAuth();
}
function renderConnectionOptions(){
  const compat=draftVpnCompat(),imported=draftImportedVpn(),port=Number(app.status?.applicationProxy?.port || proxy().port || 17890),address=`http://127.0.0.1:${Number.isInteger(port)&&port>0&&port<=65535?port:17890}`;
  $('#vpnOptions').hidden=!draftExternalVpn();$('#vpnImportSettings').hidden=!imported;$('#relaySettings').hidden=compat;$('#applicationProxySettings').hidden=false;$('#vpnProxyPortField').hidden=$('#vpnProxyType').value==='auto';
  $('#takeoverModeField').hidden=draftExternalVpn();
  $('#takeoverMode option[value="application"]').disabled=!imported;
  $('#takeoverMode').value=proxy().running&&$('#connectionMode').value===connectionMode()?proxy().mode==='tun'?proxy().routingMode==='global'?'global':'smart':'application':preferredTakeoverMode($('#connectionMode').value,app.preferences);
  $('#applicationRoutingStatus').textContent=app.status?.applicationProxy?.running&&app.status.applicationProxy.policy==='private-direct-public-isp'?'智能应用入口已启用：局域网与私网直连，公网经已核验 ISP；只有接入此地址的应用使用分流。':'智能应用入口待启动；启动应用前将核验出口并准备入口。当前地址为本地核心 HTTP 代理。';
  $('#connectionModeHint').textContent=imported?'导入节点 → ISP，不经 VPS，无需开启外部 VPN。导入只在本机保存；保存 ISP、开始连接或验证链路时才探测。':compat?'外部 VPN → ISP，不经 VPS。自动选择可用路线并核验 ISP 出口；更换线路后需重新保存 ISP。':'本机 TUN → VPS → ISP。更换线路后需重新保存 ISP 并验证出口。';
  $('#localProxyAddress').value=address;$('#terminalProxyExample').textContent=`$env:HTTP_PROXY = $env:http_proxy = '${address}'\n$env:HTTPS_PROXY = $env:https_proxy = '${address}'\nRemove-Item Env:ALL_PROXY, Env:all_proxy -ErrorAction SilentlyContinue\n$env:NO_PROXY = $env:no_proxy = 'localhost,127.0.0.1,::1,.localhost,.local,.lan'\n$env:NODE_USE_ENV_PROXY = '1'`;
  $('#openProxySettingsButton').hidden=!vpnCompat();
  const route=ready()?proxy().compatibility:null;
  const importedResult=app.status?.compatibility,winningIndex=importedResult?.strategy==='imported-node'&&['verified','mocked'].includes(importedResult.status)?importedResult.winningNodeIndex:route?.winningNodeIndex;
  const routeName=route?.strategy==='imported-node'?Number.isInteger(winningIndex)?`导入节点 ${winningIndex}`:'导入节点路线':route?.strategy==='system'?'系统默认网络':route?.proxy?`本地 VPN ${route.strategy==='socks-proxy'?'SOCKS5':'HTTP'} ${route.proxy.host}:${route.proxy.port}`:null;
  $('#vpnRouteStatus').textContent=routeName?`${mock()?'模拟 · ':''}本次已选${routeName}${mock()?'，未检测真实 VPN 或 ISP。':'，并通过 ISP 出口核验。'}`:'自动检测系统网络及已配置的本地代理；发现不到时填写 VPN 软件提供的代理端口。出口核验不能证明外部 VPN 全程开启。';
  if(importedVpn()&&!routeName)$('#vpnRouteStatus').textContent='连接时经导入节点核验 ISP 出口；无需运行外部 VPN。';
  else if(!vpnCompat()&&!routeName)$('#vpnRouteStatus').textContent='默认模式经 TUN → VPS → ISP；本地 HTTP 地址也可用于单独配置的应用。';
  $('#applicationScopeHint').textContent=systemExitVerified()?`${proxy().routingMode==='global'?'全局':'智能规则'} TUN 当前出口已核验。${systemProtected()?'断网锁已开启。':'断网锁未开启，断线后普通应用可能恢复直连。'}启动前复核受管核心并复用有效出口证据；目标服务检测可手动进行。默认浏览器登录与真实应用会话需要实际确认。`:'仅显式 HTTP 代理无法接管默认浏览器和已有应用。Claude/Codex 启动需要已核验的 TUN；断网锁可选。';
  renderApplications();
}
function renderApplications(){
  const inventory=app.applications,labels={'claude-desktop':'Claude Desktop','claude-code':'Claude Code','codex-cli':'Codex CLI',terminal:'代理终端','codex-desktop':'Codex Desktop'};
  const supported=typeof window.mcDesktop?.getApplications==='function'&&typeof window.mcDesktop?.launchApplication==='function';
  $('#refreshApplicationsButton').disabled=!supported||app.busy||app.applicationDiscovering;
  const backgroundSupported=typeof window.mcDesktop?.getClaudeBackground==='function'&&typeof window.mcDesktop?.openClaudeServices==='function';
  $('#claudeBackgroundPanel').hidden=!backgroundSupported;
  $('#checkClaudeBackgroundButton').disabled=!backgroundSupported||app.busy||Boolean(app.modalAction);
  $('#openClaudeServicesButton').disabled=!backgroundSupported||app.busy||Boolean(app.modalAction);
  $('#disableClaudeStartupButton').disabled=typeof window.mcDesktop?.disableClaudeStartup!=='function'||app.busy||Boolean(app.modalAction);
  $('#restoreClaudeStartupButton').disabled=typeof window.mcDesktop?.restoreClaudeStartup!=='function'||app.busy||Boolean(app.modalAction)||app.claudeBackground?.canRestore!==true;
  setText($('#applicationDiscoveryStatus'),!supported?'此启动入口需要 MC Proxy 桌面客户端。':app.applicationDiscovering?'正在识别本机应用…':inventory?.mock?'模拟应用列表，未读取本机安装或进程。':inventory?.processStatus==='unknown'?'安装列表已读取，运行状态暂时无法确认。':inventory?'已识别安装与运行状态。':'进入此页面后识别已安装应用。');
  const applicationOrder=['claude-desktop','codex-desktop','claude-code','codex-cli','terminal'];
  const rows=Array.isArray(inventory?.applications)?inventory.applications.filter(item=>Object.hasOwn(labels,item.id)).slice(0,5).sort((a,b)=>applicationOrder.indexOf(a.id)-applicationOrder.indexOf(b.id)):[];
  const reasons={'running-requires-restart':'正在运行。请先安全退出，再从这里启动。','process-state-unknown':'无法确认运行状态，暂不重复启动。','not-installed':'未识别到安装位置。','platform-unsupported':'此平台暂不支持启动。'};
  const markup=rows.map(item=>{
    const count=Number.isInteger(item.running)?Math.max(0,Math.min(256,item.running)):0;
    const desktop=['claude-desktop','codex-desktop'].includes(item.id),terminal=item.id==='terminal';
    const protectedLaunch=terminal||mock()||systemExitVerified();
    const disabled=app.busy||!ready()||!protectedLaunch||item.launchable!==true||desktop&&count>0;
    const reason=reasons[item.blockedReason]||(!ready()?'连接通过核验后可启动。':!protectedLaunch?'先连接全局 TUN 并核验出口；断网锁为可选功能。':desktop&&count?'请先安全退出再启动。':inventory?.processStatus==='unknown'?'运行状态未知。':'');
    const canStop=typeof window.mcDesktop?.stopApplication==='function'&&item.stoppable===true&&!app.busy;
    const brand=item.id.startsWith('claude')?'claude':item.id.startsWith('codex')?'codex':'terminal';
    const state=inventory?.processStatus==='unknown'?'unknown':count?'running':item.installed?'installed':'missing';
    const brandIcon=terminal?'<svg class="icon"><use href="#i-code"/></svg>':`<img class="brand-icon" src="./assets/brands/${brand}.png" alt="" width="26" height="26">`;
    return `<div class="application-row" data-application-kind="${desktop?'desktop':terminal?'terminal':'cli'}" data-application-brand="${brand}"><span class="application-mark" aria-hidden="true">${brandIcon}</span><div class="application-copy"><strong>${labels[item.id]}</strong><small class="application-status" data-state="${state}">${item.installed?'已安装':'未识别'}${count?` · 正在运行 ${count} 个进程`:''}</small>${reason?`<small>${reason}</small>`:''}${item.stopBlockedReason==='close-manually'?'<small>请在原终端结束任务并关闭窗口。</small>':''}</div><div class="application-actions"><button class="secondary-button application-launch" data-application="${item.id}" type="button" ${disabled?'disabled':''}>${desktop?'代理启动':terminal?'打开终端':'新终端启动'}</button><button class="secondary-button" data-stop-application="${item.id}" type="button" ${canStop?'':'disabled'}>关闭此应用</button></div></div>`;
  }).join('')||'<p class="empty-state">'+(app.applicationDiscovering?'正在识别应用…':'暂无应用记录，请点击“重新识别”。')+'</p>';
  if(app.applicationMarkup!==markup){$('#applicationList').innerHTML=markup;app.applicationMarkup=markup;}
}
async function refreshApplications(){
  if(app.applicationDiscovering||typeof window.mcDesktop?.getApplications!=='function')return;
  app.applicationDiscovering=true;renderApplications();
  try{app.applications=await window.mcDesktop.getApplications();}catch{app.applications=null;toast('暂时无法识别本机应用，请重试',true);}finally{app.applicationDiscovering=false;renderApplications();}
}
async function launchApplication(id){
  if(!ready()||app.busy||!['claude-desktop','claude-code','codex-desktop','codex-cli','terminal'].includes(id)||typeof window.mcDesktop?.launchApplication!=='function')return;
  await action('正在确认受管连接并启动应用…',async()=>{const result=await window.mcDesktop.launchApplication(id);if(app.cancelledOperationId===app.operationId)return;if(result?.started!==true)throw new Error('应用尚未启动，请重试。');$('#applicationLaunchStatus').textContent=result.mock?'模拟启动完成，未启动真实程序。':id==='terminal'?'代理终端已打开。终端代理环境不覆盖系统浏览器登录；请确认全局 TUN 和登录页实际出口。断网锁为可选功能。':'应用启动已提交，已复核受管 TUN 并复用有效 ISP 出口证据。目标服务检测可手动进行；请在应用中确认真实会话。未开锁时断线可能恢复直连。';toast(result.mock?'模拟应用启动完成':'应用启动已提交，请查看新窗口');},'application');
  await refreshApplications();
}
async function checkClaudeBackground(){
  if(app.busy||typeof window.mcDesktop?.getClaudeBackground!=='function')return;
  await action('正在核对 Claude 后台服务…',async()=>{
    const result=await window.mcDesktop.getClaudeBackground();app.claudeBackground=result;
    const state={running:'正在运行',stopped:'已停止',unknown:'运行状态未确认'},mode={automatic:'开机自动启动',manual:'手动启动',disabled:'已禁用',unknown:'启动方式未确认'};
    $('#claudeBackgroundStatus').textContent=result.mock?'模拟服务信息，未检查本机。':result.state==='unknown'&&result.code?'检查未完成，不能判断服务是否存在；请重试或打开系统服务管理。':result.present===false?'未发现 CoworkVMService。':result.identity==='verified'?`官方 Anthropic 签名有效 · ${state[result.state]||state.unknown} · ${mode[result.startMode]||mode.unknown}${result.systemAccount===true?' · 系统权限运行':''}。服务是否运行不代表 Cowork 任务是否活跃。`:'服务身份尚未确认，请通过系统服务管理核对；仅凭进程名不能判断来源或安全。';
  },'application');
}
async function openClaudeServices(){
  if(app.busy||typeof window.mcDesktop?.openClaudeServices!=='function')return;
  await action('正在打开 Windows 服务管理…',async()=>{
    const result=await window.mcDesktop.openClaudeServices();
    $('#claudeBackgroundStatus').textContent=result.mock?'模拟打开，未操作系统服务。':'已打开系统服务管理。停止前结束 Cowork 任务；系统拒绝更改时请保留现状。';
  },'application');
}
async function changeClaudeStartup(restore=false){
  const method=restore?'restoreClaudeStartup':'disableClaudeStartup';
  if(app.busy||typeof window.mcDesktop?.[method]!=='function')return;
  await action(restore?'正在恢复 Claude 服务启动设置…':'正在禁止 Claude 服务开机启动…',async()=>{
    const result=await window.mcDesktop[method]();if(result.canceled)return;app.claudeBackground=result;
    $('#claudeBackgroundStatus').textContent=result.mock?'模拟操作，未修改真实服务。':restore?'原服务启动设置已恢复并核验。':`已核验服务开机启动已禁用。${result.state==='running'?'当前服务仍在运行；本次没有中断任务，重启 Windows 后不会按此设置自动启动。':'当前服务未运行。'}软件更新后请再检查。`;
  },'application');
}
async function stopApplication(id){
  if(app.busy||typeof window.mcDesktop?.stopApplication!=='function'||!['claude-desktop','claude-code','codex-desktop','codex-cli','terminal'].includes(id))return;
  await action('正在请求应用安全退出…',async()=>{const result=await window.mcDesktop.stopApplication(id);if(result?.canceled)return;if(result?.stopped!==true)throw new Error('尚未确认应用退出，请检查原窗口。');$('#applicationLaunchStatus').textContent=result.mock?'模拟退出完成，未关闭真实程序。':'应用已确认退出，可重新代理启动。';toast(result.mock?'模拟退出完成':'应用已安全退出');},'application');
  await refreshApplications();
}
async function checkApplicationNetwork(service,path){
  if(app.busy||!ready()||!['claude','codex','browser'].includes(service)||!['proxy','system'].includes(path))return;
  await action('正在并行检查所选目标服务…',async()=>{const result=await api('/api/applications/check',{service,path});if(app.cancelledOperationId===app.operationId)return;browserTools.renderDiagnosis(result.diagnosis);const checks=Array.isArray(result.checks)?result.checks:[];$('#applicationNetworkResult').textContent=(result.status==='mocked'?'模拟检查，未访问真实服务。 ':`${service==='browser'?'网页对照':service==='claude'?'Claude':'Codex'} · ${path==='system'?'系统 TUN':'应用代理'}： `)+checks.map(item=>`${String(item.label||item.target||item.id||'目标').slice(0,80)} ${item.transportReachable===true?'隧道/TLS可达':item.status==='mocked'?'模拟':item.stage==='proxy-connect'?'代理建隧道失败':item.stage==='tls'?'TLS未通过':item.code||'传输未通过'}${Number.isInteger(item.connectHttpStatus)?`（CONNECT ${item.connectHttpStatus}）`:Number.isInteger(item.targetHttpStatus??item.httpStatus)?`（目标 HTTP ${item.targetHttpStatus??item.httpStatus}）`:''}${item.transportReachable===true&&item.status!=='reachable'?'，目标服务错误或限制':''}${item.transportReachable!==true&&item.code?` · ${item.code}`:''}`).join('；')+(result.transportReady===true?'。仅完成传输检查，登录与模型访问尚未验证。':'。请结合核心错误定位失败阶段；不会切换到直连重试。');},'application-check');
}
async function quitSafely(){
  if(!connectionButtons().canQuit||app.modalAction||typeof window.mcDesktop?.quit!=='function')return;
  const ownedBusy=!app.busy;app.quitting=true;app.busy=true;if(ownedBusy)app.operationKind='quit';updateControls();
  try{await window.mcDesktop.quit();}catch(error){showError(error.message);}finally{app.quitting=false;if(ownedBusy||app.operationKind==='quit'){app.busy=false;app.operationKind=null;}updateControls();}
}
function renderVpnConfig(){
  const config=app.vpnConfig||{},nodes=(config.nodes||[]).filter(node=>Number.isInteger(node.index)&&node.index>0&&node.index<=256),imported=draftImportedVpn();
  $('#vpnImportOverviewButton').hidden=!imported;$('#relayOverviewButton').hidden=imported;
  const formats={'clash-yaml':'Clash / Mihomo YAML','sing-box':'sing-box JSON','v2ray-json':'V2Ray / Xray JSON','share-uri':'分享链接','base64-subscription':'Base64 节点文本','surge-ini':'Surge 配置'},protocols={ss:'Shadowsocks',vmess:'VMess',vless:'VLESS',trojan:'Trojan',hysteria2:'Hysteria2',tuic:'TUIC',http:'HTTP',socks:'SOCKS5'},transports={tcp:'TCP',ws:'WebSocket',grpc:'gRPC',httpupgrade:'HTTP Upgrade',http:'HTTP',quic:'QUIC'};
  const summary=config.available?`支持 ${Number(config.supported)||0} / ${Number(config.total)||0} 个节点 · 不支持 ${Number(config.unsupported)||0} 个`:'尚未导入本地配置';
  $('#vpnConfigSummary').textContent=summary+(config.available?'。配置已在本机保存，导入未探测外网。':'。选择文件后只在本机解析保存。');
  if(config.available&&Object.hasOwn(formats,config.format))$('#vpnConfigSummary').textContent+=` 已识别 ${formats[config.format]}。`;
  if(config.duplicates)$('#vpnConfigSummary').textContent+=` 已合并 ${Number(config.duplicates)||0} 个重复节点。`;
  if(config.changeSummary){const change=config.changeSummary;$('#vpnConfigSummary').textContent+=` 本次新增 ${Number(change.added)||0}，移除 ${Number(change.removed)||0}，保留 ${Number(change.kept)||0}。`;}
  $('#vpnSubscriptionStatus').textContent=config.subscription?.configured?`已保存私有订阅地址；最近更新：${timeLabel(config.subscription.lastUpdatedAt)}。刷新只经核验链路；节点变化会安全结束会话。`:'先导入本地配置并连接，订阅仅经核验链路下载。节点变化会安全结束当前会话，请重新连接。';
  renderVpnImportIssues();
  $('#vpnImportOverviewTitle').textContent=config.available?summary:'导入配置 · 无需开启 VPN';
  $('#vpnImportOverviewDetail').textContent=config.available?`${config.selectedIndex===null?'自动测速择优':`已选节点 ${config.selectedIndex}`} · 查看导入与节点设置`:'本地配置 → 导入节点 → ISP';
  setHtml($('#vpnNodeChoice'),'<option value="auto">自动选择 · 已测通节点中最快者</option>'+nodes.map(node=>`<option value="${node.index}">节点 ${node.index} · ${esc(String(node.name||'未命名').slice(0,120))}${Object.hasOwn(protocols,node.protocol)?` · ${protocols[node.protocol]}`:''}${Object.hasOwn(transports,node.transport)?` / ${transports[node.transport]}`:''}</option>`).join(''));
  $('#vpnNodeChoice').value=config.selectedIndex===null||config.selectedIndex===undefined?'auto':String(config.selectedIndex);
  renderVpnLatency();
  const result=app.status?.compatibility;
  if(result?.strategy==='imported-node'){
    const errorLabels={VPN_NODE_RESOLVE_FAILED:'节点地址解析失败',SETUP_CHECK_FAILED:'双出口核验失败',CORE_START_FAILED:'节点代理启动失败',VPN_IMPORT_CONFLICT:'本机节点配置已改变',ISP_EXIT_MISMATCH:'出口不一致',ISP_EXIT_UNVERIFIED:'双出口核验未通过',EXIT_MISMATCH:'出口不一致',VPN_IMPORT_NO_ROUTE:'已尝试节点未通过'};
    const attempts=(Array.isArray(result.attempts)?result.attempts:[]).filter(item=>Number.isInteger(item.nodeIndex)&&item.nodeIndex>0&&item.nodeIndex<=256).slice(0,256).map(item=>{const code=typeof item.errorCode==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(item.errorCode)?item.errorCode:null;return `节点 ${item.nodeIndex}：${item.status==='verified'?'核验通过':item.status==='checking'?'正在核验':code?`${errorLabels[code]||'核验失败'}（${code}）`:'核验失败'}`;});
    const heading=['verified','mocked'].includes(result.status)?`${mock()?'模拟 · ':''}导入链路已通过出口核验`:result.status==='checking'?'正在核验导入链路':'导入链路未通过核验';
    const detail=`${heading}。${attempts.length?attempts.join('；')+'。':''}范围仅为本地 HTTP 代理；运行中不自动切换节点，不能证明外部 VPN 已关闭。`;
    $('#vpnCheckResult').textContent=detail;$('#vpnDiagnosticsResult').textContent=detail;
  }else $('#vpnDiagnosticsResult').textContent='尚无导入链路验证结果。可在连接来源设置导入配置，并在保存 ISP 后验证。';
}
function renderVpnImportIssues(){
  const failed=app.vpnImportFailure!==undefined&&app.vpnImportFailure!==null,source=failed?app.vpnImportFailure:app.vpnConfig?.unsupportedNodes,issues=Array.isArray(source)?source:[],reasons={VPN_NODE_TYPE_UNSUPPORTED:'协议不支持',VPN_NODE_TRANSPORT_UNSUPPORTED:'传输方式不支持',VPN_NODE_TLS_UNSAFE:'TLS 校验设置无效或不安全',VPN_NODE_FIELD_UNSUPPORTED:'节点字段不支持',VPN_NODE_INVALID:'节点字段无效或不完整',VPN_NODE_CIPHER_UNSUPPORTED:'加密方式不支持',VPN_NODE_METHOD_UNSUPPORTED:'加密方式不支持',VPN_NODE_FINGERPRINT_UNSUPPORTED:'TLS 指纹缺失或不受支持',VPN_NODE_REALITY_INVALID:'Reality 参数无效',VPN_NODE_PLUGIN_UNSUPPORTED:'节点插件不支持',VPN_NODE_URI_INVALID:'分享链接格式无效',VPN_NODE_FLOW_UNSUPPORTED:'VLESS 流控不支持',VPN_NODE_PACKET_ENCODING_UNSUPPORTED:'数据包编码不支持'};
  const rows=issues.slice(0,256).filter(item=>Number.isInteger(item?.index)&&item.index>0&&item.index<=256&&typeof item.code==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(item.code)).map(item=>`节点 ${item.index}：${reasons[item.code]||'节点无法使用'}（${item.code}）`);
  $('#vpnImportIssues').hidden=!failed&&!rows.length;$('#vpnImportIssues').dataset.failed=String(failed);$('#vpnImportIssues').textContent=(failed?'本次未导入，旧配置保留。':rows.length?'未导入以下节点：':'')+rows.join('；')+(failed&&!rows.length?'请查看错误提示并核对配置内容。':'');
}
function renderVpnLatency(){
  const latency=app.vpnLatency,config=app.vpnConfig||{},current=Boolean(latency&&latency.profileId===config.id&&latency.scope==='node-isp-https'),nodes=(config.nodes||[]).filter(node=>Number.isInteger(node.index)&&node.index>0&&node.index<=256),nodeIndices=new Set(nodes.map(node=>node.index));
  const rows=current&&Array.isArray(latency.results)?latency.results.filter(row=>nodeIndices.has(row.nodeIndex)&&['verified','failed'].includes(row.status)).slice(0,3):[];
  const shortlist=current&&Array.isArray(latency.shortlistedNodeIndices)?latency.shortlistedNodeIndices.filter(index=>nodeIndices.has(index)).slice(0,3):[];
  for(const index of shortlist)if(!rows.some(row=>row.nodeIndex===index))rows.push({nodeIndex:index,status:'untested',latencyMs:null});
  const measured=row=>!mock()&&row.status==='verified'&&Number.isFinite(row.latencyMs)&&row.latencyMs>=0&&row.latencyMs<=300000;
  rows.sort((a,b)=>(measured(a)?a.latencyMs:Infinity)-(measured(b)?b.latencyMs:Infinity)||a.nodeIndex-b.nodeIndex);
  const recommended=latency?.stale!==true&&rows.find(row=>row.nodeIndex===latency?.recommendedNodeIndex&&measured(row)),tested=current&&Number.isInteger(latency.tested)?Math.max(0,Math.min(256,latency.tested)):0,total=current&&Number.isInteger(latency.total)?Math.max(0,Math.min(256,latency.total)):0;
  const scope='完整链路延迟为节点 → ISP → 双站 HTTPS 请求耗时，不含核心启动。有时间预算，仅入围节点参与完整核验与排名；运行中不切换节点。';
  const screening=current?latency.screening:null,screened=Number.isInteger(screening?.screened)?Math.max(0,Math.min(256,screening.screened)):0,candidates=current&&Number.isInteger(latency.candidateCount)?Math.max(0,Math.min(256,latency.candidateCount)):nodes.length;
  $('#vpnScreeningSummary').textContent=!current?'连接前先轻筛节点，再对入围节点核验完整链路。':latency.status==='mocked'||mock()?`模拟轻筛 ${candidates} 个候选，未测量真实 TCP 延迟。`:screening?.scope==='cached-shortlist'?'使用已缓存的入围节点，仍须复核完整出口。':screening?.scope==='selected-node'?'手动指定节点，跳过订阅排序，仅核验此节点。':`TCP 轻筛 ${screened} / ${candidates} 个候选，入围 ${shortlist.length} 个（最多 3 个）。TCP 握手时间不代表 ISP 完整链路延迟。`;
  $('#vpnLatencySummary').textContent=!current?'保存 ISP 后可检测完整链路延迟。自动模式选择已测通节点中最快者，再次连接仍须复核出口。'+scope:latency.status==='checking'?`正在${mock()?'模拟':''}检测 ${tested} / ${total} 个节点。${mock()?'未测量真实延迟。':''}`+scope:latency.status==='mocked'||mock()?'模拟完整链路核验，未测量真实延迟。'+scope:`${latency.status==='failed'?'检测未通过':latency.stale===true?'结果已过期，连接前重新检测':'已检测'} ${tested} / ${total} 个节点。${recommended?`已测通最快：节点 ${recommended.nodeIndex}（${Math.round(recommended.latencyMs)} ms）。`:''}${config.selectedIndex!==null?'手动模式只检测指定节点。':''}`+scope;
  $('#vpnLatencyResults').innerHTML=rows.map(row=>{const code=typeof row.errorCode==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(row.errorCode)?row.errorCode:null;return `<div class="vpn-latency-row" data-recommended="${Boolean(recommended&&recommended.nodeIndex===row.nodeIndex)}"><strong>节点 ${row.nodeIndex}</strong><span>${measured(row)?`${Math.round(row.latencyMs)} ms`:row.status==='untested'?'未测 · 不参与排名':row.status==='verified'?mock()?'模拟核验':'已核验 · 未测得延迟':'核验失败'}</span>${code?`<small>${esc(code)}</small>`:''}</div>`;}).join('');
  if(current&&latency.status==='checking'&&latency.phase==='screening')$('#vpnLatencySummary').textContent=`正在${mock()?'模拟':''}筛选入围节点，尚未进行完整 ISP 核验。${mock()?'未测量真实延迟。':''}`+scope;
}
function renderRelay(){
  const compat=draftVpnCompat();
  const relay=app.relay||{},configured=relay.configured===true,checkStatus=relay.checkStatus||'unchecked',failed=['auth-failed','disabled','unavailable'].includes(checkStatus),checked=checkStatus==='ready';
  const state=mock()?'演示':failed?checkStatus==='auth-failed'?'账号待核验':checkStatus==='disabled'?'已停用':'不可达':checked?'最近核验通过':configured?'注册已保存':'待配发';
  $('#relayOverviewButton').dataset.state=compat?'compatible':mock()?'mock':configured?'configured':'missing';
  $('#configurationRouteDescription').textContent=draftImportedVpn()?'导入节点 → ISP，无需开启外部 VPN。':compat?'外部 VPN → ISP，不经 VPS；只代理明确配置的应用。':'经专属 VPS 中转，连接你的 ISP 出口。';
  $('#relayOverviewTitle').textContent=compat?draftImportedVpn()?'导入配置 · 不经 VPS':'VPN 兼容 · 不经 VPS':mock()?'演示中转 · 未连接真实 VPS':failed?'VPS 入口需要处理':configured?'免费可选 VPS · 注册已保存':'免费可选 VPS · 待配发注册';
  $('#relayOverviewDetail').textContent=compat?draftImportedVpn()?'导入节点 → ISP · 可使用 TUN':'外部 VPN → ISP · 仅显式代理应用':mock()?'模拟完整准备流程':failed?'可改用导入配置 → ISP，再核验出口':checked?'最近入口核验通过 · ISP 出口须另行核验':configured?'可选中转尚未核验':'导入独立中转注册文件，再连接 ISP';
  $('#relayOverviewState').textContent=$('#connectionMode').value!==savedConnectionMode()?'待保存':compat?'兼容模式':state;$('#relayDetailState').textContent=state;
  $('#relayEndpoint').textContent=configured?`${relay.host}:${relay.port}`:'尚未导入中转配置';
  $('#relayDetailDescription').textContent=mock()?'演示数据不会用于真实连接或发起外部网络请求。':failed?(checkStatus==='auth-failed'?'账号认证失败或已停用，请联系管理员核验。':checkStatus==='disabled'?'中转账号已停用，请联系管理员核验。':'中转入口当前无法通过检测，请检查网络或联系管理员。')+' VPS 为免费可选入口，可在连接方式中选择“导入配置 → ISP”；不会自动改成直连网站。':configured?'专属注册文件已保存，需核验服务与账号；连接时使用加密中转访问 ISP，无需开启 XVPN。':'所有交付版均可由管理员配发免费可选 VPS，包括自带 ISP 的客户。独立中转注册文件与软件许可、ISP 账号分别交付和保存。';
  $('#connectionLocalLabel').textContent=proxy().running&&proxy().mode==='tun'?'本机 TUN':vpnCompat()?'本地 HTTP 代理':'本机 TUN';$('#connectionRelayLabel').textContent=importedVpn()?'导入节点':vpnCompat()?'外部 VPN':mock()?'演示 VPS':configured?'VPS 中转':'VPS 待配置';
  $('#connectionChain').setAttribute('aria-label',importedVpn()?`${proxy().running&&proxy().mode==='tun'?'本机 TUN':'本地 HTTP 代理'}经过导入节点到达 ISP 出口`:vpnCompat()?'本地 HTTP 代理经过外部 VPN 到达 ISP 出口，不经 VPS':'连接经过本机 TUN、VPS 中转和 ISP 出口');
  $('#connectionChain').dataset.ready=String(ready());
  if(app.status?.networkLock?.locked)$('#relayCheckResult').textContent='断网锁正在保护网络。需要检测或更换入口时，请先结束会话，再手动解除断网锁。';
  else if(failed)$('#relayCheckResult').textContent=`最近入口检测未通过${relay.checkedAt?` · ${timeLabel(relay.checkedAt)}`:''}${/^[A-Z_]{1,60}$/.test(relay.errorCode||'')?`（${relay.errorCode}）`:''}。注册文件仍保留，可重新检测或选择其他连接来源。`;
  else if(checked)$('#relayCheckResult').textContent=mock()||app.relayCheck?.mock?'模拟入口检测完成，未连接真实 VPS。':`最近入口 TLS 与中转账号核验通过${relay.checkedAt?` · ${timeLabel(relay.checkedAt)}`:''}，不代表 ISP 完整链路通过。`;
  else if(!app.relayCheck)$('#relayCheckResult').textContent='注册已保存不代表服务当前可用；入口检测仅验证 VPS TLS 与中转账号，ISP 出口须另行核验。';
}
function renderApplicationBrowserHint(){
  $('#applicationBrowserChoiceLabel').textContent=browserRunning()?'下次默认方案':'浏览器方案';
  const detected=app.browserOptions?.some(item=>item.available);
  setText($('#applicationBrowserHint'),browserRunning()?`当前运行：${activeBrowserName()}${app.status.browser.workspaceId?'用户环境':''}。下拉框显示下次默认方案；当前窗口使用原资料。`:app.browserSelectionNotice||(!detected?'未识别到安装位置。请重新识别，或在下方指定 chrome.exe / msedge.exe。':mock()?'演示浏览器，未检测本机安装。':`${selectedBrowserName()} · ${$('#browserChoice').value==='fingerprint'?'可选指纹引擎；原有身份与资料继续保留。':selectedBrowserFresh()?'每次新建空白资料，不沿用上次登录。':'使用本机浏览器与固定独立资料，关闭后保留登录；与日常浏览器分开。'}`));
}
function renderBrowserOptions(options){
  if(Array.isArray(options))app.browserOptions=options.filter(item=>Object.hasOwn(browserLabels,item.id)&&typeof item.available==='boolean');
  if(!app.browserOptions)return;
  const choices=app.browserOptions,selection=browserSelection(choices,$('#browserChoice').value,app.preferences.browser,app.browserAutoFallback);
  $('#browserChoice').value=selection.selected;app.browserAutoFallback=selection.autoFallback;if(selection.notice||!app.browserAutoFallback)app.browserSelectionNotice=selection.notice;
  $$('#browserChoice option,#applicationBrowserChoice option').forEach(option=>option.disabled=option.value!=='fingerprint'&&!choices.some(item=>item.id===option.value&&item.available));
  const available=choices.filter(item=>item.available);
  $('#applicationBrowserChoice').value=$('#browserChoice').value;
  renderApplicationBrowserIcon();
  $('#browserAvailabilityHint').textContent=app.browserSelectionNotice||(!available.length?'未识别到 Chrome / Edge，可重新识别或指定路径':mock()?'演示选择，未检测本机安装':'与日常浏览器数据分开');
  renderApplicationBrowserHint();
  browserTools.renderFingerprint();
}
function renderConfiguration(){
  const cfg=app.configuration,editing=app.configurationEditing||!cfg.available;
  $('#configurationForm').hidden=!editing;$('#savedConfiguration').hidden=editing;
  $('#configurationSaveButton').hidden=!editing;
  $('#cancelConfigEdit').hidden=!editing||!cfg.available;
  $('#qualityEntry').hidden=!cfg.available||editing;$('#configurationContinueButton').hidden=!cfg.available||editing;
  $('#savedHost').textContent=cfg.host||'已保存 ISP';$('#savedEndpoint').textContent=`${cfg.type==='socks'?'SOCKS5':'HTTP'} · ${cfg.port||'—'} · ${cfg.credentialsConfigured?'账户认证':'无需认证'}`;
  $('#configurationTitle').textContent=editing?'配置 ISP 出口':'已保存 ISP 出口';
}
function editConfiguration(){app.configurationEditing=true;renderConfiguration();setScreen('configuration');$('#ispHost').focus({preventScroll:true});}
function preserveIspCredentials(){const cfg=app.configuration;return cfg.auth==='password'&&cfg.credentialsConfigured&&$('#ispAuth').value!=='none'&&$('#ispHost').value.trim()===cfg.host&&Number($('#ispPort').value)===Number(cfg.port)&&$('#ispType').value===cfg.type&&!$('#ispPassword').value&&(!$('#ispUsername').value||$('#ispUsername').value===cfg.username);}
function updateAuth() { const auth=$('#ispAuth').value!=='none';$('#credentialFields').hidden=!auth;const preserve=preserveIspCredentials();$('#ispUsername').required=auth&&!preserve;$('#ispPassword').required=auth&&!preserve; }
async function refreshStatus({force=false,quiet=true,inspect=false}={}) {
  if(app.busy&&!force)return null;
  try{const data=await controllerClient.readStatus({inspect});if(data)renderStatus(data);return data;}
  catch(error){app.connected=false;app.readError={code:error.code};$('#serviceStatus').classList.remove('service-online');setHtml($('#serviceStatus'),'<i class="status-dot"></i>'+(error.code==='CONTROLLER_UNAVAILABLE'?'本地服务未连接':error.code==='CONTROLLER_REQUEST_TIMEOUT'?'读取状态超时':'状态读取失败'));renderWorkspace();if(!quiet)showError(error.message);updateControls();return null;}
}
function renderWorkspace(){
  const target=selectedTakeoverMode(),control=connectionButtons(),presentation=control.connecting||control.stopping?{...app.status,connectionCancellation:{...app.status?.connectionCancellation,active:control.connecting,requested:control.stopping}}:app.status,view=connectionView({status:presentation,connected:app.connected,readError:app.readError,configuration:app.configuration,vpnConfirmed:$('#vpnConfirmed').checked,relayConfigured:app.relay.configured,targetMode:target!=='application'?'tun':'http',targetRoutingMode:target==='smart'?'safe-rules':'global'});
  for(const[id,value]of Object.entries({...view.fields,...connectionEvidenceView({status:app.status,active:view.active,state:view.state})})){const element=document.getElementById(id);if(element)setText(element,value);}
  const nodeIndex=app.status?.compatibility?.winningNodeIndex??app.status?.compatibility?.nodeIndex??app.vpnConfig?.selectedIndex;
  setText($('#routeEntryDetail'),importedVpn()?Number.isInteger(nodeIndex)?`节点 ${nodeIndex}`:'自动选择导入节点':externalVpn()?'外部 VPN 保持开启':'加密中转入口');
  setText($('#routeLocalDetail'),view.scope.includes('TUN')?'系统默认网络':'仅显式代理应用');
  $('#screen-connection').dataset.connectionState=view.state;
  setText($('#applicationExitIp'),view.fields.exitIp);setText($('#applicationCaptureScope'),view.active?view.scope:`计划：${view.scope}`);
  const lifecycle=app.status?.networkLifecycle;setText($('#networkLifecycleStatus'),lifecycle?.state==='stable'?'网络状态稳定。切换网卡或恢复唤醒后会撤销旧租约并重新核验。':lifecycle?.state==='suspended'?'系统已暂停，旧出口租约已撤销。':lifecycle?.state==='checking'?'网络变化后正在核验；完成前暂停应用启动。':lifecycle?.state==='unverified'?'网络变化核验未完成，请结束会话后重新连接。':'');
  const capabilities=app.status?.capabilities;setText($('#proxyCapabilitySummary'),capabilities?`配置目标：${capabilities.engine.name} ${capabilities.engine.version}。支持 ${capabilities.entryProtocols.length} 种入口协议、${capabilities.inputFormats.length} 类输入格式。最终 ISP 链路为 TCP；DNS 单独处理，其他 UDP 拒绝。IPv6 字面地址取决于 ISP 支持；V2Ray/Xray JSON 是输入格式，并未运行 Xray 核心。`:'等待配置能力信息。');
  setText($('#diagnosticsConnectionState'),view.fields.connectionModeLabel);setText($('#diagnosticsRecoverySummary'),view.fields.workspaceRecoverySummary);
  setText($('#diagnosticsFailureDetails'),failureDetails(app.status,app.lastFailure));
}
function renderStatus(data) {
  app.status=data;app.connected=true;app.readError=null;$('#serviceStatus').classList.add('service-online');setHtml($('#serviceStatus'),'<i class="status-dot"></i>'+(data.service?.mock?'演示工作空间':data.health?.state==='checking'?'本地服务已连接 · 后台核验中':data.statusRead?.state==='checking'?'本地服务已连接 · 本机状态检查中':'本地服务已连接'));app.startupRecovery=data.startupRecovery||null;if(data.environment)app.environment=data.environment;if(data.report)app.report=data.report;if(data.relay)app.relay=data.relay;
  if(data.vpnConfig)app.vpnConfig=data.vpnConfig;
  if(Object.hasOwn(data,'vpnLatency'))app.vpnLatency=data.vpnLatency;
  if(app.startupRecovery?.required)showError(app.startupRecovery.error?.message||'启动恢复尚未完成，请保留恢复记录并检查后重新启动。',{persistent:true});
  else if(app.errorPersistent&&!app.onboarding?.recoveryRequired)showError();
  $('#mockNotice').hidden=!mock()||app.step==='splash';renderWorkspace();
  licensePage.render(app.status.license);
  renderRelay();renderConnectionOptions();renderVpnConfig();renderBrowserOptions(data.browserOptions);renderEnvironment();renderReport();if(Object.hasOwn(data,'browserObservation'))browserTools.renderObservation(data.browserObservation);else browserTools.renderObservation();updateControls();
}
function updateControls() {
  renderNavigation();
  renderErrorNotice();
  if(!app.busy&&app.status)renderWorkspace();
  const recoveryRequired=app.startupRecovery?.required===true||app.onboarding?.recoveryRequired===true,locked=app.busy||Boolean(app.repairPending)||Boolean(app.modalAction),available=app.connected&&!locked&&!recoveryRequired;
  $('#retryButton').disabled=locked||app.initializing===true;
  $('#environmentRecoveryButton').disabled=!available||app.environment.backup?.canRestore!==true;$('#environmentResolveButton').disabled=!available;$('#cancelConfigEdit').disabled=!available;$('#openEnvironmentOptions').disabled=!available;
  $$('input,select,textarea').filter(input=>!input.closest('#screen-license,#screen-licensing-admin')).forEach(input=>input.disabled=locked||recoveryRequired);if(app.configuration.readOnly)$$('#configurationForm input,#configurationForm select').forEach(input=>input.disabled=true);$$('[data-step]').forEach(button=>button.disabled=locked||recoveryRequired||STEPS.indexOf(button.dataset.step)>app.maxStep||configurationDirty()&&button.dataset.step!=='configuration');
  $('#workspaceHomeButton').disabled=locked||recoveryRequired||!app.connected||!app.configuration.available||!(app.onboarding?.completedAt||app.onboarding?.firstRun===false)||configurationDirty();$('#backButton').disabled=locked||!WORKSPACE_PAGES.includes(app.step)&&STEPS.indexOf(app.step)<=0;$('#refreshButton').disabled=locked;
  ['#networkRepairButton','#diagnosticsNetworkRepairButton'].forEach(id=>$(id).disabled=locked||typeof window.mcDesktop?.repairNetwork!=='function');
  if(app.repairPending?.reloadRequired&&!app.busy&&!app.modalAction)['#networkRepairButton','#diagnosticsNetworkRepairButton'].forEach(id=>$(id).disabled=typeof window.mcDesktop?.repairNetwork!=='function');
  $('#safeQuitButton').disabled=Boolean(app.modalAction)||!connectionButtons().canQuit||typeof window.mcDesktop?.quit!=='function';
  $('#openClientLogButton').disabled=Boolean(app.modalAction)||typeof window.mcDesktop?.openClientLog!=='function';
  $$('[data-application-check]').forEach(button=>button.disabled=!available||!ready()||button.dataset.path==='system'&&!systemExitVerified()&&!mock());
  $('#settingsButton').disabled=locked;['#workspaceApplicationButton','#workspaceRecoveryButton','#workspaceConnectionButton'].forEach(id=>$(id).disabled=locked);$('#workspaceRecoveryStatus').disabled=locked;['#openConnectionSettingsButton','#openEnvironmentPanelButton','#openApplicationProxyButton','#openDiagnosticsButton','#diagnosticsEnvironmentButton','#diagnosticsProtectionButton'].forEach(id=>$(id).disabled=locked);$('#openSessionPreferencesButton').disabled=!available||!app.configuration.available;
  ['#routeApplicationsButton','#quickClaudeButton','#quickCodexButton','#allApplicationsButton','#connectionScopeButton','#connectionEnvironmentDetailsButton'].forEach(id=>$(id).disabled=locked);
  $('#openLicenseButton').disabled=locked;$('#licenseBackButton').disabled=locked;
  $('#openLicensingAdminButton').hidden=!adminAvailable();$('#openLicensingAdminButton').disabled=locked||!adminAvailable();$('#adminBackButton').disabled=locked;licensingAdminPage.setEnabled(adminAvailable());
  $('#workspaceConnectionButton').disabled=locked||app.maxStep<3;['#applicationsBackButton','#diagnosticsBackButton','#licenseBackButton','#adminBackButton'].forEach(id=>setText($(id+'Label'),app.maxStep>=3?'返回连接工作台':'返回连接准备'));
  ['#workspaceRecoveryButton','#workspaceRecoveryStatus','#openDiagnosticsButton','#diagnosticsEnvironmentButton','#diagnosticsProtectionButton'].forEach(id=>$(id).disabled=Boolean(app.modalAction));
  $('#workspaceConnectionButton').disabled=Boolean(app.modalAction)||app.maxStep<3;
  $('#advancedConfigButton').disabled=!available||proxy().running;$('#editSavedConfiguration').disabled=!available||app.configuration.readOnly||proxy().running||browserRunning();$('#passwordToggle').disabled=locked||app.configuration.readOnly;$('#configurationSaveButton').disabled=!available||app.configuration.readOnly||relayMissing($('#connectionMode').value)||draftExternalVpn()&&(!$('#vpnConfirmed').checked||!vpnProxyValid())||draftImportedVpn()&&!app.vpnConfig.available||proxy().running||browserRunning();$('#configurationContinueButton').disabled=!available||!app.configuration.available||configurationDirty()||relayMissing();$('#qualityCheckButton').disabled=!available||!app.configuration.available||configurationDirty()||relayMissing()||externalVpn()&&!vpnProxyValid()||proxy().running||browserRunning();
  $('#relayOverviewButton').disabled=!available;$('#relayImportButton').disabled=!available||draftVpnCompat()||app.configuration.readOnly||proxy().running||browserRunning()||app.status?.networkLock?.locked===true;$('#relayCheckButton').disabled=!available||draftVpnCompat()||!app.relay.configured||proxy().running||browserRunning()||app.status?.networkLock?.locked===true;$('#exportDiagnosticsButton').disabled=!available;
  $('#connectionMode').disabled=!available||app.configuration.readOnly||proxy().running||browserRunning()||app.status?.networkLock?.locked===true;$('#vpnProxyType').disabled=!available||proxy().running||browserRunning();$('#vpnProxyPort').disabled=!available||proxy().running||browserRunning();$('#vpnConfirmed').disabled=!available||proxy().running||browserRunning();
  const sourceLocked=!available||app.configuration.readOnly||proxy().running||browserRunning()||app.status?.networkLock?.locked===true;$('#vpnImportOverviewButton').disabled=!available;$('#vpnImportButton').disabled=sourceLocked;$('#vpnConfigFile').disabled=sourceLocked;$('#vpnNodeChoice').disabled=sourceLocked||!app.vpnConfig.available;$('#vpnChainCheckButton').disabled=sourceLocked||!app.vpnConfig.available||savedConnectionMode()!=='vpn-import'||configurationDirty();
  $('#vpnPasteToggleButton').disabled=sourceLocked;$('#vpnConfigText').disabled=sourceLocked;$('#vpnPasteImportButton').disabled=sourceLocked||!$('#vpnConfigText').value.trim();$('#vpnLatencyButton').disabled=sourceLocked||!app.vpnConfig.available||savedConnectionMode()!=='vpn-import'||configurationDirty();
  $('#applicationConnectionSettingsButton').disabled=!available;
  $('#takeoverMode').disabled=!available||proxy().running||browserRunning()||draftExternalVpn();
  $('#refreshConnectionsButton').disabled=!available||app.step!=='applications'||Boolean(connectionRead);
  $('#previewDiagnosticSummaryButton').disabled=!available;
  $('#copyDiagnosticSummaryButton').disabled=locked||!$('#diagnosticShareText').value;
  $('#vpnSubscriptionRefreshButton').disabled=!available||!ready()||mock()||!draftImportedVpn()||!app.vpnConfig.subscription?.configured&&!$('#vpnSubscriptionUrl').value.trim();
  $('#vpnSubscriptionClearButton').disabled=!available||!app.vpnConfig.subscription?.configured;
  $('#vpnQrImportButton').disabled=!available||proxy().running||browserRunning();
  $('#recoverFakeIpCacheButton').disabled=!available||proxy().running||browserRunning()||!$('#cacheApplicationsClosed').checked;
  renderApplications();
  $('#expectedExitIps').disabled=locked||recoveryRequired||app.configuration.readOnly||proxy().running;
  $('#qualityResultButton').hidden=!app.quality||configurationDirty();
  $('#reuseBackupButton').disabled=!available||['foreign','unbound','invalid'].includes(app.environment.ownership);$('#refreshBackupButton').disabled=!available||app.environment.canRefresh===false||proxy().running||browserRunning();$('#environmentContinueButton').disabled=!available||!app.environmentChecked||['foreign','unbound','invalid'].includes(app.environment.ownership);$('#environmentRetryButton').disabled=!available;
  ['#environmentAdoptButton','#protectionEnvironmentAdoptButton'].forEach(id=>$(id).disabled=!available||app.environment.canAdoptCurrent!==true||proxy().running||browserRunning());
  $('#preferencesContinueButton').disabled=!available;['#environmentRestoreButton','#connectionEnvironmentRestoreButton'].forEach(id=>$(id).disabled=!available);$('#openBrowserCleanupButton').disabled=!available;$('#openClaudeCleanupButton').disabled=!available;
  $('#protectionEnvironmentRestoreButton').disabled=!available||!['Country','Timezone','Language','Culture'].every(suffix=>$('#environmentDaily'+suffix).value.trim());
  $('#environmentOriginalRestoreButton').disabled=!available||app.environment.backup?.canRestore!==true;
  $('#environmentSaveProfilesButton').disabled=!available||!app.environment.preferences;
  $('#environmentCaptureDailyButton').disabled=!available;
  $$('#environmentProfiles input,#environmentProfiles select').forEach(input=>input.disabled=!available);
  const control=connectionButtons(),sessionRunning=control.sessionRunning;$('#connectButton').disabled=Boolean(app.modalAction)||control.stopping||app.quitting||(!control.canEnd&&(!available||!app.configuration.available||sessionRunning||configurationDirty()||relayMissing()||externalVpn()&&(!$('#vpnConfirmed').checked||!vpnProxyValid())||importedVpn()&&!app.vpnConfig.available));$('#connectButton').classList.toggle('is-connected',ready());$('#connectButton').classList.toggle('is-connecting',control.connecting||control.stopping);
  setText($('#connectSymbol'),sessionRunning||control.connecting?'■':'▶');setText($('#connectButtonLabel'),control.stopping?'正在取消':control.connecting?'取消连接':sessionRunning?(proxy().trafficBlocked||['pending','failed','blocked'].includes(proxy().trafficHoldStatus))?'结束连接 / 恢复普通网络':'结束连接':mock()?'模拟连接':'建立连接');$('#openProxySettingsButton').disabled=!available;
  $('#resumeProxyButton').hidden=!proxy().trafficBlocked;$('#resumeProxyButton').disabled=!available||!control.canResume;setText($('#resumeProxyButton'),app.busy&&app.operationKind==='resume'?'正在恢复代理连接':'恢复代理连接');
  const prefs=readPreferences(),browserAvailable=!app.browserOptions||app.browserOptions.some(item=>item.id===prefs.browser&&item.available);$('#browserChoice').disabled=!available||browserRunning();$('#safeAccessButton').disabled=!available||!ready()||browserRunning()||!browserAvailable;setText($('#safeAccessTitle'),`打开${selectedBrowserName()}`);setText($('#browserCloseButton'),`关闭${activeBrowserName()}`);setText($('#safeAccessLabel'),browserAvailable?`${selectedBrowserFresh()?'纯净':'保留空间'} ${browserLabels[prefs.browser]}`:prefs.browser==='fingerprint'?'指纹引擎待准备':'未找到浏览器');
  setText($('#freshProfileHint'),prefs.browser==='fingerprint'?selectedBrowserFresh()?'每次新建资料与指纹身份，不沿用登录':'保留资料与固定指纹身份，适合持续登录':selectedBrowserFresh()?'每次新建空白资料，不沿用上次登录':'沿用固定独立资料，保留 Cookie、网站登录与书签');
  $('#applicationBrowserChoice').disabled=!available||browserRunning();$('#applicationBrowserChoice').value=prefs.browser;
  renderApplicationBrowserHint();
  renderApplicationBrowserIcon();
  $$('[data-website]').forEach(button=>button.disabled=!available||!ready()||browserRunning()||!browserAvailable);
  setText($('#websiteLaunchStatus'),browserRunning()?`${activeBrowserName()}正在运行，可在该窗口访问其他网站；关闭后可从这里选择新入口。`:ready()?`网站将使用已核验的 ISP 链路和${selectedBrowserName()}。`:'连接通过核验后可打开；不会自动访问网站。');
  $('#rescanBrowsersButton').disabled=!available;$('#setBrowserPathButton').disabled=!available||browserRunning()||!$('#browserExecutablePath').value.trim();$('#clearBrowserPathButton').disabled=!available||browserRunning();
  ['#applicationsBackButton','#diagnosticsBackButton','#diagnosticsRefreshButton'].forEach(id=>$(id).disabled=locked);
  $('#diagnosticsBackButton').disabled=Boolean(app.modalAction);$('#diagnosticsRefreshButton').disabled=Boolean(app.modalAction)||app.busy&&$('#screen-diagnostics').dataset.section==='diagnosticsEnvironment';
  $('#returnPreferencesButton').disabled=locked;$('#editIspButton').disabled=locked||proxy().running||browserRunning();$('#probeButton').disabled=!available||!ready();$('#environmentOptimizeButton').disabled=!available||!app.environment.preferences||$('#environmentWorkMode').value==='exit'&&!ready();
  $('#networkLockButton').disabled=!available||externalVpn()||!ready()||proxy().mode!=='tun'||app.status?.networkLock?.status!=='unlocked'||app.status?.networkLock?.canArm===false;$('#networkLockButton').hidden=app.status?.networkLock?.locked===true;
  $('#networkUnlockButton').disabled=!available||app.status?.networkLock?.canUnlock!==true||proxy().running||browserRunning();$('#browserCloseButton').disabled=!available||!browserRunning();
  if(app.cleanupPlan&&(!alive(app.cleanupPlan)||app.cleanupPlan.signature!==cleanupSignature()||browserRunning()))invalidateCleanup('预览已过期或会话变化，请重新预览。');if(app.claudePlan&&!alive(app.claudePlan))invalidateClaude('预览已过期，请重新扫描。');
  $('#cleanupPreviewButton').disabled=!available||browserRunning()||!cleanupItems().length;$('#cleanupApplyButton').disabled=!available||!app.cleanupPlan||browserRunning();$('#claudePreviewButton').disabled=!available;$('#claudeApplyButton').disabled=!available||!app.claudePlan||app.claudePlan.canConfirm===false;
  if(app.cleanupPlan)setText($('#cleanupExpiry'),`预览有效至 ${timeLabel(app.cleanupPlan.expiresAt)}`);if(app.claudePlan)setText($('#claudeExpiry'),`预览有效至 ${timeLabel(app.claudePlan.expiresAt)}`);
  layoutPreferences.refresh();
  browserTools.update();
  experienceTools.update();
}
async function action(label,work,kind='general') {
  if(app.busy||app.repairPending&&!(kind==='repair'&&app.repairPending.reloadRequired))return false;
  const trigger=document.activeElement,originStep=app.step,originDrawer=app.drawer;
  let focusMoved=false;
  const trackFocus=event=>{if(event.target!==document.body&&event.target!==trigger)focusMoved=true;};
  const trackPointer=event=>{if(event.target!==trigger&&!trigger?.contains(event.target))focusMoved=true;};
  controllerClient.invalidateStatus();app.busy=true;app.operationKind=kind;const id=++app.operationId;app.cancelledOperationId=null;showError();$('#operationNotice').hidden=false;$('#operationText').textContent=label;$('#drawerOperation').textContent=label;$('#drawerOperation').hidden=!app.drawer;updateControls();
  document.addEventListener('focusin',trackFocus);document.addEventListener('pointerdown',trackPointer);
  let progressPending=false;
  const timer=window.setInterval(async()=>{if(progressPending||!app.busy||app.operationId!==id)return;progressPending=true;try{const progress=await api('/api/progress');if(app.busy&&app.operationId===id){if(Object.hasOwn(progress,'connectionCancellation')){app.status={...(app.status||{}),connectionCancellation:progress.connectionCancellation};updateControls();}if(Object.hasOwn(progress,'vpnLatency')){app.vpnLatency=progress.vpnLatency;renderVpnLatency();}if(progress.operation?.message&&!app.connectionEnding){$('#operationText').textContent=progress.operation.message;$('#drawerOperation').textContent=progress.operation.message;if(kind==='environment')$('#environmentMessage').textContent=progress.operation.message;if(['connect','resume'].includes(kind))$('#connectionDetail').textContent=progress.operation.message;}}}catch{}finally{progressPending=false;}},1500);
  try{await work();return app.cancelledOperationId!==id;}
  catch(error){
    if(app.cancelledOperationId===id&&['CONNECTION_CANCELED','SESSION_CHANGED','CONTROLLER_REQUEST_TIMEOUT'].includes(error.code))return false;
    const detail=environmentDiagnosticText(error.diagnostic),message=error.message+(detail?` ${detail}。`:'')+(/^(ENVIRONMENT_|BROWSER_|PROCESS_)/.test(error.code||'')?`（${error.code}）`:'');
    app.lastFailure={code:/^[A-Z][A-Z0-9_]{0,79}$/.test(error.code||'')?error.code:'OPERATION_FAILED',message:error.message,at:new Date().toISOString(),...(error.diagnostic?{diagnostic:error.diagnostic}:{})};if(kind==='vpn-import'){app.vpnImportFailure=error.unsupportedNodes||[];renderVpnImportIssues();}showError(message);return false;
  }finally{
    window.clearInterval(timer);
    if(app.connectionEndRequest)await app.connectionEndRequest;
    ++app.operationId;controllerClient.invalidateStatus();
    try{await refreshStatus({force:true});}finally{
      app.busy=app.quitting===true;app.operationKind=app.quitting?'quit':null;$('#operationNotice').hidden=!app.repairPending;$('#drawerOperation').hidden=true;if(app.repairPending)renderRepairState(app.repairPending);updateControls();
      document.removeEventListener('focusin',trackFocus);document.removeEventListener('pointerdown',trackPointer);
      if(!focusMoved&&!app.modalAction&&app.step===originStep&&app.drawer===originDrawer&&document.activeElement===document.body){
        const usable=trigger?.isConnected&&!trigger.disabled&&!trigger.closest('[inert]')&&trigger.getClientRects().length;
        const target=usable?trigger:app.drawer?$('#closeDrawerButton'):$(`#screen-${app.step} h1`);
        target?.focus({preventScroll:true});
      }
    }
  }
}
function confirmAction(title,message,callback,{duringRead=false,tone='danger',confirmLabel='确认'}={}){if(app.busy&&!(duringRead&&connectionButtons().canEnd)||app.modalAction)return;app.lastFocused=document.activeElement;app.modalAction=callback;$('#modalTitle').textContent=title;$('#modalBody').textContent=message;$('#modalConfirm').classList.toggle('danger-button',tone==='danger');$('#modalConfirm').classList.toggle('primary-button',tone!=='danger');setText($('#modalConfirmLabel'),confirmLabel);$('#modalConfirmIcon').hidden=tone!=='danger';$('#confirmModal').hidden=false;$('#appFrame').inert=true;updateControls();$('#modalCancel').focus();}
function closeModal(){app.modalAction=null;$('#confirmModal').hidden=true;$('#appFrame').inert=false;updateControls();app.lastFocused?.focus();}
function openDrawer(name){if(app.modalAction||app.busy&&!['diagnostics','environment','protection'].includes(name))return;const pages={applicationProxy:['applications'],diagnostics:['diagnostics','diagnosticsOverview'],environment:['diagnostics','diagnosticsEnvironment'],protection:['diagnostics','diagnosticsProtection']};if(pages[name]){openWorkspacePage(...pages[name]);return;}const titles={settings:['WORKSPACE SETTINGS','设置与工具'],advanced:['CONNECTION SETTINGS','连接来源设置'],quality:['ISP QUALITY','ISP 质量报告'],browserCleanup:['BROWSER DATA','缓存与 Cookie'],claudeCleanup:['CLAUDE CODE','本机资料清理'],report:['CONNECTION REPORT','多站出口报告']};if(!titles[name])return;if(!app.drawer)app.drawerFocus=document.activeElement;app.drawer=name;$('#advancedActions').hidden=name!=='advanced';$('#drawerEyebrow').textContent=titles[name][0];$('#drawerTitle').textContent=titles[name][1];$$('[data-drawer]').forEach(panel=>panel.hidden=panel.dataset.drawer!==name);$('#drawerBackdrop').hidden=false;['#screenHost','#appHeader','#stepTrack','#workspaceNav'].forEach(id=>$(id).inert=true);$('.drawer-content').scrollTop=0;$('#closeDrawerButton').focus();updateControls();}
function closeDrawer(){const wasOpen=Boolean(app.drawer);app.drawer=null;$('#drawerBackdrop').hidden=true;renderErrorNotice();['#screenHost','#appHeader','#stepTrack','#workspaceNav'].forEach(id=>$(id).inert=false);if(wasOpen&&app.drawerFocus?.isConnected&&!app.drawerFocus.disabled)app.drawerFocus.focus({preventScroll:true});}

async function checkRelay(){
  await action('正在验证 VPS 入口证书与中转账号…',async()=>{
    app.relayCheck=null;
    const result=await api('/api/relay/check',{});
    app.relayCheck=result;
    $('#relayCheckResult').textContent=mock()||result.mock?'模拟入口检测完成，未连接真实 VPS。':`入口 TLS 与中转账号已验证 · ${timeLabel(result.checkedAt)}。ISP 出口仍需另行检测。`;
    toast(mock()||result.mock?'模拟检测完成':'VPS 入口验证通过，下一步检查 ISP');renderRelay();
  },'relay');
}
function showAutomaticDiagnosticsOutcome(result,savedLabel){
  const detail=$('#diagnosticsExportResult');
  if(result?.diagnosticsExported===true&&detail.dataset.automaticFailure==='true'){
    detail.textContent=result.diagnostics?.mock?'演示诊断清单已更新，未写入真实文件。':'离线诊断包已随本次配置更新。可点击“准备离线诊断包”打开目录。';
    delete detail.dataset.automaticFailure;
  }
  if(result?.diagnosticsExported!==false)return false;
  const message=`${savedLabel}已保存，但离线诊断包未更新。请在“诊断与恢复”重新准备${importedVpn()?'。导入模式无需开启外部 VPN。':externalVpn()?'。外部 VPN 模式需保持 VPN 开启。':'，成功后再关闭 XVPN。'}`;
  detail.textContent=message;detail.dataset.automaticFailure='true';
  toast(message,true);
  return true;
}
async function importRelayFile(event){
  const input=event.target,file=input.files?.[0];if(!file)return;
  let enrollment;
  try{
    if(file.size>65536)throw new Error('中转配置文件过大，请选择维护者提供的 JSON 文件。');
    try{enrollment=JSON.parse((await file.text()).replace(/^\uFEFF/,''));}catch{throw new Error('无法读取有效的中转 JSON 配置，请核对文件。');}
    if(!enrollment||typeof enrollment!=='object'||Array.isArray(enrollment))throw new Error('中转配置必须是 JSON 对象。');
  }catch(error){showError(error.message);return;}
  finally{input.value='';}
  confirmAction('导入 VPS 中转配置',app.relay.configured?'将替换此设备保存的中转入口与授权。确认文件来自你的维护者？':'将把中转入口与授权保存到本机受限目录。确认文件来自你的维护者？',()=>action('正在保存中转配置…',async()=>{
    const saved=await api('/api/relay/import',{confirm:true,enrollment});enrollment=null;app.relayCheck=null;
    const data=await api('/api/onboarding');app.relay=data.relay||{};app.onboarding=data.onboarding||app.onboarding;
    // Importing an entry must not wipe unsaved ISP form edits.
    app.configuration=data.configuration||app.configuration;renderConfiguration();renderRelay();updateAuth();
    $('#relayCheckResult').textContent=mock()?'演示配置已导入，可继续模拟流程。':'中转配置已保存，可先检测入口再保存 ISP。';
    if(!showAutomaticDiagnosticsOutcome(saved,'中转配置'))toast(mock()?'演示中转配置已导入':'VPS 中转配置已保存');
  },'relay'));
}
async function exportDiagnostics(){
  await action('正在准备离线诊断与恢复工具…',async()=>{
    const result=await api('/api/diagnostics/export',{});
    if(result.mock){delete $('#diagnosticsExportResult').dataset.automaticFailure;$('#diagnosticsExportResult').textContent='演示诊断清单已生成，未写入真实诊断包。正式模式会导出当前配置、测试脚本与手动恢复说明。';toast('演示诊断完成，未生成真实文件');return;}
    if(typeof result.directory!=='string'||!result.directory)throw new Error('诊断包没有返回有效目录，请重试。');
    delete $('#diagnosticsExportResult').dataset.automaticFailure;
    $('#diagnosticsExportResult').textContent=`已保存：${result.directory}。${importedVpn()?'导入模式无需外部 VPN。此会话为本地 HTTP 代理，旧 TUN 验收脚本不适用。':externalVpn()?'外部 VPN 模式需保持 VPN 开启。此会话为本地 HTTP 代理，旧 TUN 验收脚本不适用。':'先运行 run-preflight.cmd；连接后运行 run-connected-test.cmd。'}`;
    if(window.mcDesktop?.revealDiagnostics){try{await window.mcDesktop.revealDiagnostics();toast('诊断包已准备，文件夹已打开');}catch{toast('诊断包已保存，请按详情中的路径打开');}}
    else toast(`诊断包已保存：${result.directory}`);
  },'diagnostics');
}

async function importVpnFile(event){
  const input=event.target,file=input.files?.[0];if(!file)return;
  let text;
  try{if(file.size>1048576)throw new Error('配置文件不能超过 1 MiB。');text=(await file.text()).replace(/^\uFEFF/,'');}
  catch(error){showError(error.message);return;}finally{input.value='';}
  confirmVpnImport(text);
}
function confirmVpnImport(text){
  try{if(!text.trim())throw new Error('配置内容为空，请选择包含节点的配置。');if(new Blob([text]).size>1048576)throw new Error('配置内容不能超过 1 MiB。');}catch(error){showError(error.message);return;}
  const expectedId=app.vpnConfig.id;
  confirmAction('导入本地配置','将仅在本机自动识别格式并保存支持的节点，不下载订阅、URL 或脚本，也不探测外网。现有导入配置将被替换；保存 ISP、测速或验证链路时才连接。确认导入？',()=>action('正在本机解析并保存节点…',async()=>{
    const data=await api('/api/vpn/import',{text,confirm:true,...(expectedId?{expectedId}:{})});text=null;$('#vpnConfigText').value='';app.vpnConfig=data.vpnConfig;app.vpnImportFailure=null;clearVpnResults();app.configurationEditing=true;renderConfiguration();renderVpnConfig();$('#vpnCheckResult').textContent='配置已在本机保存，尚未探测外网。请保存 ISP 后测速并验证完整链路；需要独立测试时请自行关闭外部 VPN。';toast(`已导入 ${app.vpnConfig.supported} 个支持节点；请保存 ISP 以验证此线路`);
  },'vpn-import'),{tone:'primary',confirmLabel:expectedId?'替换并导入':'导入配置'});
}
async function selectVpnNode(){
  const nodeIndex=$('#vpnNodeChoice').value==='auto'?null:Number($('#vpnNodeChoice').value),expectedId=app.vpnConfig.id;
  await action('正在保存本机节点选择…',async()=>{const data=await api('/api/vpn/select',{nodeIndex,confirm:true,...(expectedId?{expectedId}:{})});app.vpnConfig=data.vpnConfig;app.vpnImportFailure=null;clearVpnResults();app.configurationEditing=true;renderConfiguration();renderVpnConfig();$('#vpnCheckResult').textContent='节点选择已更改，请重新保存 ISP 并验证此线路。';toast('节点选择已保存，请重新保存 ISP 以验证');},'vpn-select');
}
function clearVpnResults(){app.quality=null;app.report=null;app.vpnLatency=null;$('#qualityResultButton').hidden=true;$('#reportCount').textContent='—';$('#vpnDiagnosticsResult').textContent='节点配置已改变，旧链路结果失效。请保存 ISP 后重新验证。';}
async function checkVpnLatency(){
  await action('正在测量导入节点 → ISP → HTTPS 的完整链路延迟…',async()=>{const data=await api('/api/vpn/latency',{});app.vpnLatency=data.vpnLatency||null;if(data.vpnConfig)app.vpnConfig=data.vpnConfig;if(data.compatibility&&app.status)app.status.compatibility=data.compatibility;renderVpnConfig();toast(mock()?'模拟完整链路核验完成，未测量真实延迟':'完整链路检测完成，请查看已测节点的延迟与失败结果');},'vpn-latency');
}
async function checkImportedChain(){
  await action('正在验证导入节点 → ISP 的完整出口…',async()=>{const data=await api('/api/vpn/check',{});if(data.vpnConfig)app.vpnConfig=data.vpnConfig;const route=data.compatibility||{},index=route.winningNodeIndex;$('#vpnCheckResult').textContent=mock()?'模拟链路验证通过，未连接真实节点或 ISP。':`导入节点${Number.isInteger(index)?` ${index}`:''} → ISP 双出口核验通过；范围为本地 HTTP 代理，未接管全系统，也不能证明外部 VPN 已关闭。`;renderVpnConfig();toast(mock()?'模拟导入链路通过，未建立真实连接':'导入节点 → ISP 出口核验通过');},'vpn-check');
}

async function saveConfiguration(event){
  event.preventDefault();updateAuth();if(!$('#configurationForm').reportValidity())return;
  const external=draftExternalVpn();if(external&&(!$('#vpnConfirmed').checked||!vpnProxyValid())){openDrawer('advanced');showError('请确认外部 VPN 已开启，并填写有效的本地代理端口。');return;}if(draftImportedVpn()&&!app.vpnConfig.available){openDrawer('advanced');showError('请先导入包含支持节点的配置。');return;}
  const preserve=preserveIspCredentials(),body={host:$('#ispHost').value.trim(),port:Number($('#ispPort').value),type:$('#ispType').value,clearCredentials:$('#ispAuth').value==='none',username:$('#ispAuth').value==='none'||preserve?'':$('#ispUsername').value.trim(),password:$('#ispAuth').value==='none'||preserve?'':$('#ispPassword').value,expectedExitIps:$('#expectedExitIps').value.split(/[\s,;，；]+/).filter(Boolean),connectionMode:$('#connectionMode').value,...(external?{vpnConfirmed:true,...vpnProxyInput()}:{})};
  await action('正在校验出口并保存 ISP 配置…',async()=>{const saved=await api('/api/configuration/save',body);$('#ispPassword').value='';hydrateOnboarding(await api('/api/onboarding'));if(!app.configuration.available)throw new Error('配置未通过校验，请检查服务商信息。');app.environmentChecked=false;app.maxStep=0;app.quality=null;$('#qualityResultButton').hidden=true;if(!showAutomaticDiagnosticsOutcome(saved,'ISP 配置'))toast('ISP 配置已保存，可以检测质量或继续');});
}
function safeUrl(value,{local=false}={}){if(typeof value!=='string'||!value.trim())return null;try{const url=new URL(value,location.origin);if(!['http:','https:'].includes(url.protocol)||local&&url.origin!==location.origin)return null;return url.href;}catch{return null;}}
async function checkQuality(){const ok=await action('正在经 ISP 检测 CleanIP、IPPure 与 Ping0…',async()=>{const data=await api('/api/quality/check',externalVpn()?vpnProxyInput():{});app.quality=data;$('#qualityScore').textContent=Number.isFinite(data.score)?Math.max(0,Math.min(100,data.score)).toFixed(0):'—';$('#qualityResultButton').hidden=false;$('#qualitySummary').textContent=`${mock()?'模拟结果 · ':''}MC Proxy 连通质量评分 ${Number.isFinite(data.score)?data.score:'—'}/100。${typeof data.summary==='string'?data.summary:'分数反映本次经 ISP 发起的请求，不是第三方官方信誉分。'}`;$('#qualityReports').innerHTML=(data.results||[]).map(row=>{const report=safeUrl(row.reportUrl,{local:true}),source=safeUrl(row.sourceUrl);return `<article class="quality-report"><h3>${esc(row.label||row.id)}<span>${esc(labels[row.status]||row.status)}</span></h3><p>${Number.isFinite(row.elapsedMs)?`${Math.round(row.elapsedMs)} ms · `:''}${Number.isFinite(row.httpStatus)?`HTTP ${row.httpStatus}`:'未获得 HTTP 状态'} · ${Number.isFinite(row.score)?`${row.score} 分`:'未评分'}</p>${report?`<a href="${esc(report)}" target="_blank" rel="noopener noreferrer">本次完整报告 ↗</a>`:'<p>本次报告未生成</p>'}${source?`<a href="${esc(source)}" target="_blank" rel="noopener noreferrer">检测站原地址 ↗</a>`:''}</article>`;}).join('');},'quality');if(ok)openDrawer('quality');}
function showEnvironmentChoices(){
  const env=app.environment||{},ownership=env.ownership,foreign=ownership==='foreign',unbound=ownership==='unbound',invalid=ownership==='invalid',failed=env.status==='error'||env.status==='failed';
  $('#backupChoice').hidden=false;$('#environmentResult').hidden=true;
  $('#reuseBackupButton').hidden=!env.backup||foreign||unbound||invalid;
  $('#environmentRecoveryButton').hidden=env.backup?.canRestore!==true;
  $('#reuseBackupButton').innerHTML=`${environmentNeedsReview()?'检查当前环境，继续准备':'沿用此电脑的快照'} <svg class="icon"><use href="#i-check"/></svg>`;
  $('#backupChoiceText').textContent=foreign?'快照来自其他电脑或用户。请重建此电脑的恢复快照。':unbound?'旧快照未绑定此电脑。请重建本机快照，建立本次恢复起点。':invalid?'旧恢复记录无法使用。点击“重建恢复快照”，保留旧记录并重新检查此电脑。':failed?'未能读取本机环境设置。请查看错误提示，检查本机语言与输入法设置后重新检查。':environmentNeedsReview()?'当前设置有变化，原始快照仍可使用。可直接复原，或继续连接后重新应用出口设置。':env.backup?.canRestore?'原始快照已保留，可继续准备；需要时可按此快照强制复原。':'可沿用此电脑的快照；只有需要更换恢复起点时才重建。';
}
function enterEnvironment(){setScreen('environment',{allowFuture:true});if(app.environmentChecked){renderEnvironment();return;}const existing=Boolean(app.onboarding?.backupExists||app.environment.backup||['foreign','unbound','invalid'].includes(app.environment.ownership)||['error','failed'].includes(app.environment.status));if(existing){app.environmentStage='choice';$('#environmentIntro').textContent='原始快照用于高级恢复；日常恢复按你保存的方案执行。';showEnvironmentChoices();setRing('idle','确认本机快照','重新检查不会替换原始快照');$('#environmentMessage').textContent=app.environment.backup?`上次备份：${timeLabel(app.environment.backup.createdAt)}`:'可重建本机恢复快照后继续。';updateControls();}else runEnvironmentCheck(false);}
function setRing(state,label,detail){
  const changed=$('#checkRing').dataset.state!==state;
  $('#screen-environment').dataset.stage=state;$('#checkRing').dataset.state=state;
  $('#ringLabel').textContent=label;$('#ringDetail').textContent=detail;$('#ringSymbol').textContent=state==='done'?'✓':state==='error'?'!':'◈';
  if(changed)$('.environment-content').scrollTop=0;
}
async function runEnvironmentCheck(refreshBackup){app.environmentStage='checking';app.environmentChecked=false;$('#backupChoice').hidden=true;$('#environmentResult').hidden=true;$('#environmentRetryButton').hidden=true;setRing('checking','正在检查',refreshBackup?'保存此电脑当前环境的新快照':'读取环境与原始快照');const ok=await action('正在检查并备份系统环境…',async()=>{const data=await api('/api/environment/check',refreshBackup?{refreshBackup:true,rebuildBackup:true,confirm:true}:{});app.environment=data.environment||data;if(!app.environment.backup||!liveEnvironment(app.environment)||['foreign','unbound','invalid'].includes(app.environment.ownership))throw new Error(app.environment.warnings?.join('；')||'请先重建本机恢复快照。');app.environmentChecked=true;app.environmentStage='done';renderEnvironment();if(refreshBackup)toast(mock()?'模拟快照已重建，系统未更改':'本机快照已重建，旧恢复记录已归档');},'environment');if(!ok){app.environmentStage='error';setRing('error','需要检查','请检查本机设置读取结果');$('#environmentMessage').textContent='本机环境读取与备份未完成，请查看错误提示后重新检查。';showEnvironmentChoices();$('#environmentRetryButton').hidden=false;}updateControls();}
function selectEnvironmentProfile(profile,{focus=false}={}){
  app.environmentProfileTab=profile==='daily'?'daily':'work';
  for(const name of ['work','daily']){const prefix=name==='work'?'Work':'Daily',active=app.environmentProfileTab===name,tab=$('#environment'+prefix+'Tab');tab.setAttribute('aria-selected',String(active));tab.tabIndex=active?0:-1;$('#environment'+prefix+'Panel').hidden=!active;if(active&&focus)tab.focus({preventScroll:true});}
  $('#environmentOptimizeButton').hidden=app.environmentProfileTab!=='work';$('#protectionEnvironmentRestoreButton').hidden=app.environmentProfileTab!=='daily';
}
function renderEnvironmentProfiles(){
  const env=app.environment||{},catalog=env.profileCatalog||{},presets=Array.isArray(catalog.presets)?catalog.presets:[],preferences=env.preferences;
  if(!preferences)return;
  selectEnvironmentProfile(app.environmentProfileTab);
  const catalogKey=JSON.stringify(catalog);
  if(app.environmentCatalogKey!==catalogKey){
    const existing=Object.fromEntries($$('#environmentProfiles select').map(input=>[input.id,input.value]));
    for(const prefix of ['Work','Daily']){
      $('#environment'+prefix+'Preset').innerHTML='<option value="">选择预设后仍可调整</option>'+presets.map(item=>`<option value="${esc(item.id)}">${esc(item.label)}</option>`).join('');
      $('#environment'+prefix+'Country').innerHTML='<option value="">请选择国家或地区</option>'+presets.filter((item,index,all)=>all.findIndex(other=>other.countryCode===item.countryCode)===index).map(item=>`<option value="${esc(item.countryCode)}">${esc(item.label)}</option>`).join('');
      $('#environment'+prefix+'Timezone').innerHTML='<option value="">请选择时区</option>'+(Array.isArray(catalog.timeZones)?catalog.timeZones:[]).map(zone=>{const label=({'China Standard Time':'北京 / 香港','Eastern Standard Time':'纽约 / 多伦多'})[zone]||[...new Set(presets.filter(item=>item.timeZoneId===zone).map(item=>item.label))].join(' / ');return `<option value="${esc(zone)}">${label?esc(label)+' · ':''}${esc(zone)}</option>`;}).join('');
    }
    $('#environmentLanguageOptions').innerHTML=[...new Set(['zh-CN','zh-SG',...presets.map(item=>item.preferredLanguage)])].map(tag=>{let label=tag;try{label=new Intl.DisplayNames(['zh-CN'],{type:'language'}).of(tag);}catch{}return `<option value="${esc(tag)}">${esc(label)}</option>`;}).join('');
    for(const[id,value]of Object.entries(existing))if($('#'+id).querySelector(`option[value="${CSS.escape(value)}"]`))$('#'+id).value=value;
    app.environmentCatalogKey=catalogKey;
  }
  if(!app.environmentProfilesDirty){
    $('#environmentWorkMode').value=preferences.work?.mode==='custom'?'custom':'exit';
    fillEnvironmentProfile('Work',preferences.work||{});fillEnvironmentProfile('Daily',preferences.daily||{});
    $('#environmentProfilesStatus').textContent=preferences.daily?'工作与日常方案已保存。仅保存不会更改 Windows。':'日常环境尚未保存，请选择预设或读取当前环境。';
  }
  $('#environmentWorkCustom').hidden=$('#environmentWorkMode').value!=='custom';
  $('#environmentWorkAutoHint').hidden=$('#environmentWorkMode').value==='custom';
}
function fillEnvironmentProfile(prefix,profile){
  for(const[field,suffix]of [['countryCode','Country'],['timeZoneId','Timezone'],['preferredLanguage','Language'],['culture','Culture']]){
    if(prefix==='Work'&&field==='culture')continue;
    const input=$('#environment'+prefix+suffix),value=profile[field]||'';
    if(input.tagName==='SELECT'&&value&&![...input.options].some(option=>option.value===value))input.add(new Option(value,value));
    input.value=value;
  }
}
function environmentProfileDraft(){
  const read=prefix=>({countryCode:$('#environment'+prefix+'Country').value.trim().toUpperCase(),timeZoneId:$('#environment'+prefix+'Timezone').value.trim(),preferredLanguage:$('#environment'+prefix+'Language').value.trim(),culture:prefix==='Work'?'zh-SG':$('#environmentDailyCulture').value.trim()});
  const work={...read('Work'),mode:$('#environmentWorkMode').value},daily=read('Daily');
  const validate=(profile,label)=>{if(!/^[A-Z]{2}$/.test(profile.countryCode)||!profile.timeZoneId||![profile.preferredLanguage,profile.culture].every(value=>/^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$/i.test(value)))throw new Error(`请完整填写${label}的国家或地区、时区、首选语言与区域格式。`);};
  if(work.mode==='custom')validate(work,'工作环境');
  if(Object.values(daily).some(Boolean))validate(daily,'日常环境');
  return {work:work.mode==='exit'?{...(app.environment.preferences?.work||{}),mode:'exit',culture:'zh-SG'}:work,daily:Object.values(daily).some(Boolean)?daily:null};
}
function environmentProfilesChanged(){
  app.environmentProfilesDirty=true;$('#environmentProfilesStatus').textContent='有未保存的设置。可仅保存，或保存后立即应用。';
  $('#environmentWorkCustom').hidden=$('#environmentWorkMode').value!=='custom';$('#environmentWorkAutoHint').hidden=$('#environmentWorkMode').value==='custom';updateControls();
}
async function saveEnvironmentProfiles(){
  const draft=environmentProfileDraft(),data=await api('/api/environment/preferences',{confirm:true,...draft});
  app.environment=data.environment||data;app.environmentProfilesDirty=false;renderEnvironment();return draft;
}
function captureDailyEnvironment(){return action('正在读取当前环境，不修改 Windows…',async()=>{
  const data=await api('/api/environment/check',{});app.environment=data.environment||data;
  if(!liveEnvironment(app.environment))throw new Error('未能读取当前环境，请重新检查后再保存日常设置。');
  const current=app.environment.current;renderEnvironmentProfiles();fillEnvironmentProfile('Daily',{countryCode:current.homeCountryCode||'',timeZoneId:current.timeZoneId,preferredLanguage:current.languages?.[0]?.languageTag||'',culture:current.culture});environmentProfilesChanged();
  toast(current.homeCountryCode?'已填入当前环境，点击保存后才会成为日常设置':'已填入当前环境；请补选国家或地区后保存');
},'environment');}
function inspectEnvironmentCurrent(){return action('正在重新核验环境，不修改 Windows…',async()=>{
  const data=await api('/api/environment/check',{});app.environment=data.environment||data;renderEnvironment();
  const verification=environmentVerificationView(app.environment);toast(verification?.summary||'环境已重新读取，请查看逐项结果。',verification?.needsReview===true);
},'environment');}
function renderEnvironment(){
  const env=app.environment||{},unsafeSaved=env.snapshotSource==='saved'&&['foreign','unbound'].includes(env.ownership),current=unsafeSaved?{}:env.current||env.snapshot||{},outcome=env.optimization||{};
  renderEnvironmentProfiles();
  const verification=environmentVerificationView(env),partial=verification?verification.status==='partial':outcome.status==='partial',failed=verification?verification.status==='unverified':['failed','recovery-required'].includes(outcome.status),review=environmentNeedsReview(),adoptAvailable=env.canAdoptCurrent===true;
  $('#screen-environment').dataset.attention=String(review);
  $('#screen-environment').dataset.checked=String(app.environmentChecked);
  $('#environmentAdoptButton').hidden=!adoptAvailable||!review;
  $('#protectionEnvironmentAdoptButton').hidden=!adoptAvailable;
  $('#refreshBackupButton').hidden=adoptAvailable&&review&&env.canRefresh===false;
  $('#environmentFooterNote').textContent=review?'中途改过设置也可复原，无需重建原始快照':'重建会更换今后的恢复起点，旧快照归档保留';
  $('#environmentRecoveryButton').hidden=env.backup?.canRestore!==true;
  $('#currentTimezone').textContent=current.timeZoneId||'待检查';
  $('#currentLanguage').textContent=(current.languages||[]).map(item=>item.languageTag||item).join('、')||current.culture||'待检查';
  $('#backupResult').textContent=env.backup?'已保存 · '+timeLabel(env.backup.createdAt):'待确认';
  $('#environmentWarning').textContent=verification?verification.summary:(env.warnings||[]).join('；');
  if(['foreign','unbound','invalid'].includes(env.ownership)){app.environmentChecked=false;if(app.environmentStage!=='checking'){showEnvironmentChoices();setRing('error','需要本机快照','请重建后继续');}}
  if(app.environmentStage==='choice'||app.environmentStage==='error')showEnvironmentChoices();
  if(app.environmentChecked){
    $('#environmentResult').hidden=false;$('#backupChoice').hidden=true;
    const attention=review;
    setRing(failed?'error':'done',verification?verification.label:partial?'部分完成':attention?'快照已保留':env.restored?'已复原':'检查完成',partial?'已生效的设置保留，可继续使用':attention?'可重新应用或复原原始设置':'原始设置快照已保存');
    $('#environmentMessage').textContent=verification?verification.summary:partial?'部分设置尚未匹配，成功项目已保留，连接可继续。':attention?'当前设置有变化，连接可继续；可应用工作环境或恢复已保存的日常环境。':'环境检查已完成，原始快照保留用于高级恢复。';
  }
  const region=env.appliedRegion;
  const regionText=region?'上次已匹配 '+[region.countryCode,region.city].filter(Boolean).join(' · ')+'，'+region.timezone+(region.locale?' / '+region.locale:'')+'。':'';
  const drift=env.backup?.drifted===true,conflict=env.status==='conflict';
  const restoreNeeded=env.backup?.restoreNeeded===true;
  const restoreStatus=verification?`${verification.summary} ${env.preferences?.daily?'可按保存的日常设置覆盖恢复；原始快照另在高级恢复中。':'保存日常设置后，可按该方案恢复。'}`:partial&&outcome.operation==='restore'?'部分设置已恢复，成功项目保留；可再次重试未匹配项目。':env.restored||outcome.status==='restored'?'本次恢复已完成，可随时再次覆盖为保存的日常环境。':env.preferences?.daily?'“恢复日常环境”会强制应用你保存的日常设置；原始快照复原另在高级恢复中。':'先选择预设或读取当前环境，再保存为日常设置；以后可直接覆盖恢复。';
  $('#environmentRestoreStatus').textContent=restoreStatus;
  ['#connectionEnvironmentRestoreButton','#protectionEnvironmentRestoreButton'].forEach(id=>{$(id).dataset.needed=String(restoreNeeded);$(id).title=restoreStatus;});
  const lock=app.status?.networkLock||{};
  $('#connectionNote').textContent=(importedVpn()?proxy().running&&proxy().mode==='tun'?lock.locked?'全局 TUN 与断网锁已开启；无需运行外部 VPN。结束连接后断网锁仍保留。':'全局 TUN 当前出口已核验，应用启动无需开锁；断线后普通应用可能恢复直连。':'普通浏览器与 CLI 需设置本地 HTTP 代理；无需运行外部 VPN。':externalVpn()?'普通浏览器与 CLI 需设置本地 HTTP 代理；外部 VPN 请保持开启。':lock.locked?'结束连接后断网锁仍保留。恢复直连须手动解除。':lock.developmentPaused?'新断网锁开发已暂停，连接与应用接入不依赖它。断线后普通应用可能恢复直连。':ready()?'断网锁未开启，可在防护详情中手动开启。':'TUN 需管理员权限；连接后可手动开启断网锁。')+(!proxy().running&&restoreNeeded?' 系统环境待恢复，请点击“恢复日常环境”。':env.restored&&!restoreNeeded?' 系统环境已复原。':'');
  $('#environmentResolveButton').hidden=!(failed||review);
  const environmentDetail=environmentDiagnosticText({environmentFields:outcome.differingFields,rollbackEnvironmentFields:outcome.rollbackDifferingFields});
  $('#environmentSummary').textContent=(verification?verification.summary:(partial?environmentOutcomeNotice(env,{operation:outcome.operation}).text:failed?(outcome.message||'环境优化未完成。')+' ':review?'当前系统设置有变化，可以直接覆盖为工作或日常环境。':env.restored?'本次恢复已完成。':regionText||'时区、首选语言、国家或地区随出口调整；区域格式固定为中文（简体，新加坡）。')+(!partial&&environmentDetail?' '+environmentDetail+'。':'')+(env.warnings?.length?' '+[...new Set(env.warnings)].join('；'):''))+(env.needsSignOut?' 部分语言设置需重新登录 Windows。':'')+(failed||review?verification?.status==='matched'?' 连接可继续，按需选择工作或日常方案。':' 连接可继续。可重试工作环境，或恢复已保存的日常环境。':'');
  $('#environmentSettingResults').hidden=!env.current&&!outcome.target;
  $('#environmentSettingResults').innerHTML=environmentSettingRows(env).map(row=>`<div data-field="${row.field}" data-state="${row.status}"><dt>${esc(row.label)}<span>${esc(row.statusLabel)}</span></dt><dd><span>${outcome.operation==='restore'?'恢复目标':'应用目标'}：${esc(row.target)}</span><span>${esc(row.currentLabel)}：${esc(row.current)}</span>${row.detail?`<span>${esc(row.detail)}</span>`:''}</dd></div>`).join('');
  $('#environmentConnectionStatus').textContent=verification?verification.label:partial?'部分完成':!proxy().running&&restoreNeeded?'待复原':failed?'未完成':review?'设置有变化':outcome.status==='restored'||env.restored?'已复原':outcome.status==='applied'?'已匹配':!readPreferences().autoOptimize?'保持原样':'待优化';
  $('#connectionWarning').hidden=!(failed||review);
  $('#connectionWarningTitle').textContent=verification?verification.changed&&verification.status==='matched'?`${verification.label} · 设置有变化`:verification.saved?'环境状态待重新核验':verification.status==='partial'?'当前环境尚未匹配目标':'当前环境待核验':partial?outcome.operation==='restore'?'环境部分复原 · 成功项已保留':'环境部分生效 · 成功项已保留':outcome.status==='recovery-required'?'环境需要恢复':drift?'原始快照与当前环境有差异':conflict?'环境存在外部改动':ready()?'代理已连接 · 环境优化未完成':'环境优化未完成';
  $('#connectionWarningText').textContent=(verification?verification.summary:partial?environmentOutcomeNotice(env,{operation:outcome.operation}).text:outcome.message||(drift?'原始快照已保留。':(env.warnings||[]).join('；'))||'请查看环境详情。')+' 连接可继续；可重新核验或应用环境。';
}

async function savePreferences(){const ok=await action('正在保存会话偏好…',async()=>{await savePreferenceChanges({}, {completed:true});});if(ok)setScreen('connection',{allowFuture:true});}
function restoreEnvironment({saveDraft=false,original=false}={}){
  if(!original&&!saveDraft&&!app.environment.preferences?.daily){openDrawer('environment');selectEnvironmentProfile('daily');toast('请先设置并保存日常环境；原始快照复原位于高级恢复。');return;}
  const message=original?'将逐项覆盖当前时区（含夏令时）、显示语言偏好、国家或地区、区域格式、语言与输入法列表、默认输入法和区域格式联动，恢复到本机原始快照。':'将逐项覆盖 Windows 的时区、国家或地区、首选语言和区域格式等设置，直接恢复到你保存的日常环境。';
  confirmAction(original?'按原始快照强制复原':saveDraft?'保存并恢复日常环境':'恢复已保存的日常环境',message+'中途改过的设置也会覆盖。个别项目未完成时，其他成功项目保留；原始快照不变。部分语言设置可能需重新登录 Windows。',()=>action('正在逐项恢复环境设置…',async()=>{
    if(saveDraft){const draft=environmentProfileDraft();if(!draft.daily)throw new Error('请先填写日常环境。');await saveEnvironmentProfiles();}
    const data=await api(original?'/api/environment/restore-original':'/api/environment/restore',{confirm:true});app.environment=data.environment||data;app.environmentChecked=true;app.environmentStage='done';renderEnvironment();const notice=environmentOutcomeNotice(app.environment,{mock:mock(),operation:'restore'});toast(notice.text,notice.partial);
  },'environment'));
}
function optimizeEnvironment(){
  const custom=$('#environmentWorkMode').value==='custom';
  confirmAction('保存并应用工作环境',(custom?'将使用你指定的工作环境。':'将按已验证出口设置时区、首选语言、国家或地区。')+'区域格式固定为中文（简体，新加坡），保留中文输入法。中途改过的这些设置也会覆盖；逐项应用，成功项目不会因其他项目失败而回滚。原始恢复快照保持不变；部分语言设置可能需重新登录 Windows。',()=>action('正在逐项应用工作环境…',async()=>{
    await saveEnvironmentProfiles();const data=await api('/api/environment/optimize',{confirm:true});app.environment=data.environment||data;renderEnvironment();const notice=environmentOutcomeNotice(app.environment,{mock:mock()});toast(notice.text,notice.partial);
  },'environment'));
}
async function adoptCurrentEnvironment(){
  let current;
  const checked=await action('正在读取当前时区与区域格式…',async()=>{const data=await api('/api/environment/check',{});app.environment=data.environment||data;if(!liveEnvironment(app.environment))throw new Error('无法读取当前系统环境，请重新检查后再采纳；旧快照保留。');current=app.environment.current;if(app.environment.backup&&!['foreign','unbound','invalid'].includes(app.environment.ownership)){app.environmentChecked=true;app.environmentStage='done';}renderEnvironment();},'environment');
  if(!checked)return;
  confirmAction('将当前环境设为新的恢复起点',`当前时区：${current.timeZoneId}；区域格式：${current.culture}。这是更换恢复起点，不是修复或还原。将归档旧恢复记录，并保留旧快照；当前 Windows 设置不会被修改。此后的“按原始快照强制复原”将回到现在的环境；已保存的工作与日常方案不变。若要回到最初设置，请取消并使用高级恢复。确认更换？`,()=>action('正在保存新的恢复起点…',async()=>{const data=await api('/api/environment/adopt',{confirm:true});app.environment=data.environment||data;app.environmentChecked=true;app.environmentStage='done';renderEnvironment();toast(mock()?'模拟采纳完成，系统未更改':'已保存新的恢复起点，旧快照已归档，Windows 设置未修改');},'environment'));
}
async function copyProxyText(element){
  const value=element.value||element.textContent;
  try{await navigator.clipboard.writeText(value);toast('已复制，仅在你选择的应用或终端中使用');}
  catch{if(element.select){element.focus();element.select();}else{const range=document.createRange();range.selectNodeContents(element);const selection=window.getSelection();selection.removeAllRanges();selection.addRange(range);}toast('已选中文字，请按 Ctrl+C 复制');}
}
async function refreshConnectionRecords(){
  if(connectionRead||app.step!=='applications'||document.hidden||app.busy||!app.connected)return;
  const generation=connectionReadGeneration,revision=app.status?.revision;
  const work=api('/api/connections');connectionRead=work;updateControls();
  try{
    const data=await work;if(generation!==connectionReadGeneration||revision!==app.status?.revision||app.step!=='applications'||document.hidden)return;
    const statusLabels={observed:'已观察到连接',idle:'暂无连接',unavailable:'当前核心未提供记录',failed:'记录读取失败',mocked:'模拟记录 · 未观察真实网络'};
    $('#connectionsSummary').textContent=`${statusLabels[data.status]||'记录状态待确认'} · 活跃 ${Number(data.active)||0} · 已观察 ${Number(data.observed)||0}${typeof data.code==='string'&&/^[A-Z_]{1,80}$/.test(data.code)?` · ${data.code}`:''}。未出现记录不代表已直连。`;
    const rows=Array.isArray(data.connections)?data.connections.slice(0,64):[];
    const routeLabels={isp:'ISP 链路','private-direct':'本机 / 局域网',reject:'已拒绝',unknown:'路由未知'},targets={'ai-service':'AI 服务','exit-check':'出口检测','ip-literal':'IP 直连请求','other-domain':'其他域名',unknown:'目标未识别'},applications={claude:'Claude',codex:'Codex',chrome:'Chrome',edge:'Edge',node:'Node 程序',electron:'Electron 程序',unknown:'未识别应用'};
    $('#connectionRecords').innerHTML=rows.map(row=>`<article class="connection-record"><strong>${esc(applications[row.application]||'未识别应用')}</strong><span>${esc(targets[row.target]||'未分类目标')} · ${esc(routeLabels[row.route]||'路由未知')}</span><small>${esc(row.network||'未知')} · ${row.active?'活跃':'已结束'} · ↑ ${Number(row.upload)||0} B / ↓ ${Number(row.download)||0} B${row.diagnostic?` · ${esc(row.diagnostic)}`:''}</small></article>`).join('');
  }catch(error){if(generation===connectionReadGeneration&&app.step==='applications')$('#connectionsSummary').textContent=`记录暂时不可用：${error.message}。不会因此判定应用直连。`;}
  finally{if(connectionRead===work)connectionRead=null;updateControls();}
}
async function previewDiagnosticSummary(){await action('正在生成可分享摘要…',async()=>{$('#diagnosticShareText').value=JSON.stringify(await api('/api/diagnostics/summary'),null,2);$('#diagnosticSharePreview').hidden=false;},'diagnostics');}
function refreshSubscription(){
  const url=$('#vpnSubscriptionUrl').value.trim(),expectedId=app.vpnConfig.id;
  confirmAction('更新私有订阅','只经当前核验链路下载，不跟随跳转。节点变化时将安全结束当前连接和受管浏览器；随后需重新连接。失败保留旧配置。',()=>action('正在通过核验链路更新订阅…',async()=>{try{const data=await api('/api/vpn/subscription/refresh',{confirm:true,expectedId,...(url?{url}:{})});app.vpnConfig=data.vpnConfig;renderVpnConfig();toast(data.sessionEnded?'订阅已更新，旧会话已结束，请重新连接':'订阅已更新，节点未变化');}finally{$('#vpnSubscriptionUrl').value='';}},'vpn-import'));
}
async function importQrFile(event){
  const file=event.target.files?.[0];event.target.value='';if(!file)return;
  let bitmap;
  try{
    if(typeof BarcodeDetector!=='function'||!['image/png','image/jpeg','image/webp'].includes(file.type)||file.size>4*1024*1024)throw new Error('二维码图片仅支持本机 PNG/JPEG/WebP，且不能超过 4 MiB。');
    bitmap=await createImageBitmap(file);if(bitmap.width>4096||bitmap.height>4096||bitmap.width*bitmap.height>16*1024*1024)throw new Error('二维码图片尺寸过大。');
    const codes=await new BarcodeDetector({formats:['qr_code']}).detect(bitmap);if(codes.length!==1)throw new Error('请使用仅包含一个节点二维码的图片。');
    const text=codes[0].rawValue;if(/^https?:/i.test(text))throw new Error('这是订阅地址，请在订阅地址栏填写，并通过已核验链路更新。');
    confirmVpnImport(text);
  }catch(error){showError(error.message);}finally{bitmap?.close();}
}
async function toggleConnection(){
  if(connectionButtons().stopping||app.quitting)return;
  if(connectionButtons().connecting){await endSession({cancel:true});return;}
  if(app.busy&&!connectionButtons().canEnd)return;
  if(proxy().running||browserRunning()){
    const note=importedVpn()?'导入节点的连接也将停止；使用本地代理的应用将暂时无法通过此代理联网。':externalVpn()?'外部 VPN 保持原样；使用本地代理的应用将暂时无法通过此代理联网。':app.status?.networkLock?.locked?'断网锁继续阻断，恢复直连须另行解除。':'断网锁未确认启用，系统可能恢复直连。';
    const held=proxy().trafficBlocked||['pending','failed','blocked'].includes(proxy().trafficHoldStatus);
    confirmAction(held?'结束连接并恢复普通网络':'结束当前连接','将关闭受管浏览器并停止代理，未保存内容可能丢失。'+note+(held?'结束保留的 TUN 后，系统和应用可能通过真实 IP 直连。请先关闭需要代理的应用，确认恢复普通网络。':'')+'环境设置与浏览器资料保留。',()=>endSession(),{duringRead:true});return;
  }
  const compat=vpnCompat();if(externalVpn()&&(!$('#vpnConfirmed').checked||!vpnProxyValid())){openDrawer('advanced');showError('请先确认外部 VPN 已开启。');return;}
  await action(importedVpn()?'正在经导入节点建立 ISP 链路并核验出口…':compat?'正在探测 VPN 路线并核验 ISP 出口…':'正在建立 TUN 并核验 ISP 出口…',async()=>{
    await preferenceWriter.flush();
    if(app.cancelledOperationId===app.operationId)return;
    const target=selectedTakeoverMode(),mode=target==='application'?'http':'tun';
    renderStatus(await api('/api/proxy/start',{confirm:true,mode,...(mode==='tun'?{routingMode:target==='global'?'global':'safe-rules'}:{}),optimize:readPreferences().autoOptimize,externalReport:readPreferences().externalReport,...(externalVpn()?{vpnConfirmed:true,...vpnProxyInput()}:{})}));
    if(app.cancelledOperationId===app.operationId)return;
    // This successful POST returns the completed operation while its queue is
    // still marked busy. Final fresh status controls subsequent app launches.
    if(!['connected','connected-with-warnings','mocked'].includes(app.status?.connectionResult?.status))throw new Error(app.status?.connectionResult?.message||'代理尚未通过出口校验，请检查连接状态。');
    renderReport();
    const environmentCheck=environmentVerificationView(app.environment),incomplete=environmentCheck?environmentCheck.needsReview:app.status?.connectionResult?.status==='connected-with-warnings'||['partial','failed','recovery-required'].includes(app.environment.optimization?.status);
    toast(incomplete?environmentCheck?`代理已连接；${environmentCheck.summary}`:app.environment.optimization?.status==='partial'?'代理已连接；环境部分生效，成功项目已保留。':'代理已连接，但环境优化未完成。请查看连接页提示。':mock()?'演示连接就绪，未改变真实网络':'代理已连接，ISP 出口已核验',incomplete);
  },'connect');
}

async function endSession({cancel=false}={}){
  if(app.connectionEndRequest||!connectionButtons().canEnd)return;
  const ownedBusy=!app.busy;
  if(!ownedBusy)app.cancelledOperationId=app.operationId;
  else{app.busy=true;app.operationKind='disconnect';controllerClient.invalidateStatus();}
  app.connectionEnding=true;$('#operationNotice').hidden=false;$('#operationText').textContent=cancel?'正在取消连接并清理会话…':'正在结束代理会话…';$('#drawerOperation').textContent=$('#operationText').textContent;renderWorkspace();updateControls();
  app.connectionEndRequest=(async()=>{
    try{
      renderStatus(await api('/api/session/end',{confirm:true}));
      toast(cancel?'连接已取消，会话清理完成':app.environment.backup?.restoreNeeded?'连接已结束，可点击“恢复日常环境”':'连接已结束，请留意断网锁状态');
    }catch(error){app.lastFailure={code:error.code||'OPERATION_FAILED',message:error.message,at:new Date().toISOString()};showError(error.message);}
    finally{
      app.connectionEnding=false;controllerClient.invalidateStatus();await refreshStatus({force:true});
      app.connectionEndRequest=null;
      if(ownedBusy){app.busy=false;app.operationKind=null;$('#operationNotice').hidden=true;$('#drawerOperation').hidden=true;}
      updateControls();
    }
  })();
  return app.connectionEndRequest;
}

async function resumeProxy(){
  if(!connectionButtons().canResume)return;
  await action('正在保留 TUN 并恢复代理连接、重新核验出口…',async()=>{
    const result=await api('/api/proxy/resume',{confirm:true});
    if(app.cancelledOperationId===app.operationId)return;
    renderStatus(result);toast('代理恢复已提交，完成出口核验后可继续使用');
  },'resume');
}

async function safeAccess(service='exit'){if(!['exit','google','wikipedia','github','youtube','chatgpt','claude','tiktok','ping0','cleanip','ippure'].includes(service))return;const prefs=readPreferences();return action(`正在验证出口并打开${selectedBrowserName()}…`,async()=>{const plan=await api('/api/browser/plan',{browser:prefs.browser,fresh:selectedBrowserFresh(),service});if(app.cancelledOperationId===app.operationId)return;if(!alive(plan))throw new Error('启动计划已过期，请重试。');const result=await api('/api/browser/launch',{token:plan.token,confirm:true});if(app.cancelledOperationId===app.operationId)return;void browserTools.refresh({quiet:true});toast(mock()||result.mode==='mocked'?'模拟安全访问完成，未启动真实浏览器':service==='exit'?`${selectedBrowserName()}已打开，页面将显示实际出口 IP`:`网站已在${selectedBrowserName()}中打开`);},'browser');}
async function rescanBrowsers(){await action('正在重新识别浏览器安装位置…',async()=>{app.browserSelectionNotice='';const result=await api('/api/browsers/rescan',{});renderBrowserOptions(result.browserOptions);toast(mock()?'模拟浏览器识别完成':'浏览器安装位置已重新识别');},'browser');}
async function setBrowserPath(clear=false){await action('正在验证浏览器程序位置…',async()=>{const browser=$('#browserPathKind').value,result=await api('/api/browsers/path',{browser,executable:clear?null:$('#browserExecutablePath').value.trim(),confirm:true});app.browserSelectionNotice='';if(!clear){$('#browserChoice').value=browser;$('#freshProfile').checked=app.preferences.fresh===true;app.browserAutoFallback=false;await savePreferenceChanges({browser});}renderBrowserOptions(result.browserOptions);$('#browserExecutablePath').value='';toast(clear?'已恢复自动识别':'浏览器位置与首选浏览器已保存');},'browser-settings');}
function renderReport(){const report=app.report;if(!report){$('#reportCount').textContent='—';return;}const rows=Array.isArray(report.results)?report.results:[],summary=report.summary||{};$('#reportCount').textContent=`${rows.length} 项`;$('#reportSummary').textContent=report.stale?`历史报告 · ${timeLabel(report.generatedAt)}，请重新验证。`:mock()?'模拟结果，不代表真实出口。':`${summary.consistent?'多站出口一致':'出口一致性尚未确认'} · ${timeLabel(report.generatedAt)}`;$('#reportResults').innerHTML=rows.map(row=>`<div class="report-row"><strong>${esc(row.label||row.id||'检测站')}</strong><span class="${['verified','reachable'].includes(row.status)?'result-good':['failed','mismatch'].includes(row.status)?'result-bad':'result-warning'}">${esc(labels[row.status]||row.status||'待检查')}</span><small>${esc(mock()?'模拟数据':row.exitIp||row.ip||row.scope||row.errorCode||'仅连通性检查')}</small></div>`).join('')||'<p class="empty-state">没有额外检测结果。</p>';}
function lockNetwork(){confirmAction('手动开启断网锁','开启后，停止代理或退出客户端仍会阻断普通直连。恢复普通网络需结束会话并手动解除断网锁。',()=>action('正在开启断网锁并重新核验连接…',async()=>{renderStatus(await api('/api/network-lock/arm',{confirm:true}));toast(mock()?'模拟断网锁已开启，系统未更改':'断网锁已开启，连接已重新核验');}));}
function unlockNetwork(){confirmAction('解除断网锁，允许直连','解除后，系统和其他应用可经本机默认网络直接联网，可能暴露本地出口 IP。确认恢复普通网络？',()=>action('正在解除断网锁…',async()=>{await api('/api/network-lock/unlock',{confirm:true});toast(mock()?'模拟解锁完成':'已请求解除，请查看实际状态');}));}
async function repairNetwork(){
  if(app.busy||typeof window.mcDesktop?.repairNetwork!=='function')return;
  await action('正在打开离线网络修复工具…',async()=>{
    const result=await window.mcDesktop.repairNetwork();
    if(result.pending===true){renderRepairState(result);toast('网络修复仍在进行，恢复结果尚未确认；可查看诊断报告。');}
    else if(result.mock)toast('模拟修复完成，系统未更改');
    else if(result.completed&&result.success){toast('网络修复已完成，客户端继续运行');$('#diagnosticsExportResult').textContent=`修复报告：${result.reportPath||'运行目录 network-repair/last-result.json'}${result.skippedAllowRules?`；保留 ${result.skippedAllowRules} 条外部改动规则。`:''}`;}
    else if(result.launched)toast('修复工具已启动，请接受管理员权限提示并查看修复结果');
  },'repair');
}

let repairPoll=null,repairPollBusy=false;
function renderRepairState(state){
  if(!state||typeof state!=='object')return;
  const wasPending=Boolean(app.repairPending);
  if(state.pending===true){
    app.repairPending=state;
    $('#operationNotice').hidden=false;$('#operationText').textContent=state.reloadRequired?'修复工具已结束，本机恢复状态尚未重新载入；请点网络修复重试载入。':'网络修复仍在进行，等待管理员工具的实际结果…';
    $('#diagnosticsExportResult').textContent=`${state.reloadRequired?'恢复状态未载入':'修复尚未完成'}${state.code?`（${state.code}）`:''}；报告：${state.reportPath||'尚未生成'}`;
    if(!repairPoll&&typeof window.mcDesktop?.getInfo==='function')repairPoll=window.setInterval(async()=>{if(repairPollBusy)return;repairPollBusy=true;try{const info=await window.mcDesktop.getInfo();renderRepairState(info.networkRepair);}catch{}finally{repairPollBusy=false;}},1500);
  }else if(state.completed===true){
    app.repairPending=null;if(repairPoll){window.clearInterval(repairPoll);repairPoll=null;}
    $('#diagnosticsExportResult').textContent=`${state.success===true?'网络修复已完成':'网络修复未完成'}${state.code?`（${state.code}）`:''}；报告：${state.reportPath||'尚未生成'}`;
    if(wasPending){if(!app.busy)$('#operationNotice').hidden=true;toast(state.success===true?'网络修复已完成，已收到实际结果':'网络修复未完成，请查看报告与错误码',state.success!==true);void refreshStatus({force:true});}
  }
  updateControls();
}

function invalidateCleanup(message='选择项目后生成预览。'){app.cleanupPlan=null;$('#cleanupPlan').innerHTML=`<p class="empty-state">${esc(message)}</p>`;setText($('#cleanupExpiry'),'');}
function invalidateClaude(message='扫描不会删除资料。'){app.claudePlan=null;$('#claudePlan').innerHTML=`<p class="empty-state">${esc(message)}</p>`;setText($('#claudeExpiry'),'');}
async function previewCleanup(){return action('正在生成浏览器清理预览…',async()=>{invalidateCleanup();const signature=cleanupSignature(),plan=await api('/api/cleanup/preview',{browser:$('#cleanupBrowser').value,items:cleanupItems()});if(!alive(plan))throw new Error('没有有效确认令牌，请重新预览。');app.cleanupPlan={...plan,signature};$('#cleanupPlan').innerHTML=(plan.targets||[]).map(item=>`<div class="target-row"><strong>${item.item==='browserCookies'?'Cookie':'缓存'}</strong><span>${esc(item.displayPath||item.path||item.label||'受管浏览器数据')}</span>${item.exists===false?'<small>不存在，执行时跳过</small>':''}</div>`).join('')||'<p class="empty-state">没有现存目标数据。</p>';});}
function applyCleanup(){updateControls();const plan=app.cleanupPlan;if(!plan)return;confirmAction(mock()?'确认模拟清理':'确认删除所选浏览器数据',mock()?'仅演示流程，不删除任何文件。':'将永久删除预览中的所选数据。Cookie 清理会退出网站登录，环境备份不能恢复这些数据。',()=>action('正在清理已确认的浏览器数据…',async()=>{if(app.cleanupPlan!==plan||!alive(plan)||browserRunning())throw new Error('预览已失效，请重新生成。');invalidateCleanup('本次确认已使用。');await api('/api/cleanup/apply',{token:plan.token,confirm:true});$('#cleanupPlan').innerHTML=`<p class="empty-state">${mock()?'模拟完成，未删除文件。':'已执行所选范围，可重新预览检查。'}</p>`;}));}
function formatBytes(n){return!Number.isFinite(n)?'大小待确认':n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(1)} MB`;}
function residualLabel(item){if(typeof item==='string')return item;if(item?.kind==='environment')return`环境变量 ${item.name||'未命名'}（${{Process:'进程',User:'当前用户',Machine:'系统'}[item.scope]||item.scope||'范围未知'}）仍保留；不读取或显示变量值。`;return item?.message||item?.detail||item?.path||item?.name||'存在未覆盖范围，请检查。';}
function warningHtml(items){return items.length?`<div class="warning-box">${items.map(item=>`<p>${esc(residualLabel(item))}</p>`).join('')}</div>`:'';}
async function previewClaude(){return action('正在扫描 Claude Code 用户资料…',async()=>{invalidateClaude();const data=await api('/api/claude/cleanup-plan',{}),plan=data.plan||data;if(!alive(plan))throw new Error('没有有效确认令牌，请重新扫描。');app.claudePlan=plan;const running=plan.runningProcesses||[],notice=running.length?`<div class="warning-box">先关闭以下进程，再重新扫描：${running.map(item=>`<p>${esc(item.name||item.processName||'Claude Code')} · PID ${esc(item.pid||item.processId||'未知')}</p>`).join('')}</div>`:'';$('#claudePlan').innerHTML=notice+((plan.targets||[]).map(item=>`<div class="target-row"><strong>${esc(item.label||(item.kind==='directory'?'用户资料目录':item.kind)||'用户资料')}</strong><span>${esc(item.displayPath||item.path)}</span><small>${Number.isFinite(item.files)?`${item.files} 个文件 · `:''}${formatBytes(item.bytes)}</small></div>`).join('')||'<p class="empty-state">未发现待删除目标。</p>')+warningHtml([...(plan.warnings||[]),...(plan.residuals||[])]);});}
function applyClaude(){updateControls();const plan=app.claudePlan;if(!plan||plan.canConfirm===false)return;confirmAction(mock()?'确认模拟重置 Claude Code':'确认删除预览中的 Claude Code 资料',mock()?'仅演示清理流程，不删除文件或凭据。':'将永久删除已预览范围的账户凭据、会话与缓存，可能需重新登录。请先关闭 Claude Code；环境备份无法撤销删除。',()=>action('正在清理确认范围内的 Claude Code 资料…',async()=>{if(app.claudePlan!==plan||!alive(plan))throw new Error('预览已失效，请重新扫描。');invalidateClaude('本次确认已使用。');const result=await api('/api/claude/cleanup',{token:plan.token,planId:plan.planId,confirm:true});$('#claudePlan').innerHTML=`<p class="empty-state">${mock()?'模拟完成，未删除本机资料。':result.complete?'已清理已知用户范围，请继续核对残留提示。':'操作已执行，仍有残留，请重新扫描。'}</p>`+warningHtml([...(result.warnings||[]),...(result.residuals||[])]);}));}

async function initialize(){
  if(app.initializing||app.busy)return;
  app.initializing=true;controllerClient.invalidateStatus();
  const operationAtStart=app.operationId;
  app.maxStep=0;setScreen('splash',{allowFuture:true});$('#retryButton').hidden=true;$('#retryButton').disabled=true;
  $('#splashStatus').textContent='正在读取本地配置…';showError();
  try{
    const[onboarding,status]=await Promise.all([
      api('/api/onboarding'),controllerClient.readStatus(),
      new Promise(resolve=>window.setTimeout(resolve,window.matchMedia('(prefers-reduced-motion: reduce)').matches?0:800)),
    ]);
    if(!status||operationAtStart!==app.operationId){$('#splashStatus').textContent='准备流程已被当前操作中断，完成后请重新读取本地配置。';$('#retryButton').hidden=false;return;}
    hydrateOnboarding(onboarding);renderStatus(status);void experienceTools.refreshReminders({quiet:true});
    if(app.configuration.available&&(app.onboarding.completedAt||app.onboarding.firstRun===false))setScreen('connection',{allowFuture:true});
    else if(app.configuration.available)enterEnvironment();else setScreen('configuration',{allowFuture:true});
  }catch(error){
    if(operationAtStart===app.operationId){app.connected=false;$('#serviceStatus').classList.remove('service-online');setHtml($('#serviceStatus'),'<i class="status-dot"></i>本地服务未连接');}
    $('#splashStatus').textContent=error.message;$('#retryButton').hidden=false;updateControls();
  }finally{app.initializing=false;$('#retryButton').disabled=app.busy;}
}
$$('[data-step]').forEach(button=>button.addEventListener('click',()=>button.dataset.step==='environment'?enterEnvironment():setScreen(button.dataset.step)));
$('#backButton').addEventListener('click',()=>WORKSPACE_PAGES.includes(app.step)&&app.step!=='connection'?returnToWorkspace():setScreen(STEPS[Math.max(0,STEPS.indexOf(app.step)-1)]));$('#refreshButton').addEventListener('click',()=>refreshStatus({quiet:false,inspect:true}));$('#retryButton').addEventListener('click',initialize);
$('#configurationForm').addEventListener('submit',saveConfiguration);$('#configurationContinueButton').addEventListener('click',enterEnvironment);$('#qualityCheckButton').addEventListener('click',checkQuality);$('#qualityResultButton').addEventListener('click',()=>openDrawer('quality'));
['#ispAuth','#ispHost','#ispPort','#ispType','#ispUsername','#ispPassword','#expectedExitIps'].forEach(id=>$(id).addEventListener('input',()=>{updateAuth();updateControls();}));
$('#reuseBackupButton').addEventListener('click',()=>runEnvironmentCheck(false));$('#refreshBackupButton').addEventListener('click',()=>confirmAction('重建恢复快照','将读取此电脑当前的时区、语言和输入法，作为今后的恢复起点；原始快照将归档保留。若要回到原始设置，请取消并使用高级恢复中的“按原始快照强制复原”。工作与日常方案不变；本次不会修改 Windows 设置。确认重建？',()=>runEnvironmentCheck(true)));$('#environmentRetryButton').addEventListener('click',()=>runEnvironmentCheck(false));$('#environmentContinueButton').addEventListener('click',()=>setScreen('preferences',{allowFuture:true}));
$('#preferencesContinueButton').addEventListener('click',savePreferences);$('#environmentRestoreButton').addEventListener('click',restoreEnvironment);$('#returnPreferencesButton').addEventListener('click',()=>setScreen('preferences'));$('#editIspButton').addEventListener('click',editConfiguration);$('#connectButton').addEventListener('click',toggleConnection);$('#resumeProxyButton').addEventListener('click',resumeProxy);$('#safeAccessButton').addEventListener('click',()=>safeAccess());
$('#connectionEnvironmentRestoreButton').addEventListener('click',()=>restoreEnvironment());
$('#protectionEnvironmentRestoreButton').addEventListener('click',()=>restoreEnvironment({saveDraft:true}));
$('#environmentOriginalRestoreButton').addEventListener('click',()=>restoreEnvironment({original:true}));
$('#environmentSaveProfilesButton').addEventListener('click',()=>action('正在保存工作与日常环境设置…',async()=>{await saveEnvironmentProfiles();toast('设置已保存，Windows 环境未更改');},'environment'));
$('#environmentCaptureDailyButton').addEventListener('click',captureDailyEnvironment);
for(const profile of ['work','daily']){
  const tab=$('#environment'+(profile==='work'?'Work':'Daily')+'Tab');
  tab.addEventListener('click',()=>selectEnvironmentProfile(profile));
  tab.addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();selectEnvironmentProfile(event.key==='Home'?'work':event.key==='End'?'daily':profile==='work'?'daily':'work',{focus:true});}});
}
$$('#environmentProfiles input,#environmentProfiles select').forEach(input=>input.addEventListener('input',environmentProfilesChanged));
$$('[data-environment-preset]').forEach(input=>input.addEventListener('change',()=>{const preset=app.environment.profileCatalog?.presets?.find(item=>item.id===input.value);if(preset){const work=input.dataset.environmentPreset==='work';fillEnvironmentProfile(work?'Work':'Daily',{...preset,culture:work?'zh-SG':preset.preferredLanguage});environmentProfilesChanged();}}));
['#environmentAdoptButton','#protectionEnvironmentAdoptButton'].forEach(id=>$(id).addEventListener('click',adoptCurrentEnvironment));
$('#browserChoice').addEventListener('change',()=>changeBrowserSelection($('#browserChoice').value));
$('#openBrowserCleanupButton').addEventListener('click',()=>openDrawer('browserCleanup'));$('#openClaudeCleanupButton').addEventListener('click',()=>openDrawer('claudeCleanup'));$('#openReportButton').addEventListener('click',()=>openDrawer('report'));$('#openProtectionButton').addEventListener('click',()=>openDrawer('protection'));
$('#closeDrawerButton').addEventListener('click',closeDrawer);$('#drawerBackdrop').addEventListener('click',event=>{if(event.target===$('#drawerBackdrop'))closeDrawer();});
$('#cleanupPreviewButton').addEventListener('click',previewCleanup);$('#cleanupApplyButton').addEventListener('click',applyCleanup);$('#claudePreviewButton').addEventListener('click',previewClaude);$('#claudeApplyButton').addEventListener('click',applyClaude);$('#cleanupBrowser').addEventListener('change',()=>{invalidateCleanup();updateControls();});$$('input[name="cleanupItem"]').forEach(input=>input.addEventListener('change',()=>{invalidateCleanup();updateControls();}));['#autoOptimize','#freshProfile'].forEach(id=>$(id).addEventListener('change',()=>{rememberPreferences();renderBrowserOptions();renderEnvironment();}));
$('#probeButton').addEventListener('click',()=>action('正在比对多个出口检测站…',async()=>{const report=await api('/api/probes',{multi:true,thirdParty:true});if(app.cancelledOperationId===app.operationId)return;app.report=report;renderReport();},'probe'));$('#environmentOptimizeButton').addEventListener('click',optimizeEnvironment);$('#networkLockButton').addEventListener('click',lockNetwork);$('#networkUnlockButton').addEventListener('click',unlockNetwork);$('#browserCloseButton').addEventListener('click',()=>confirmAction(`关闭${activeBrowserName()}`,'未保存内容可能丢失，代理与浏览器资料保留。',()=>action(`正在关闭${activeBrowserName()}…`,async()=>{await api('/api/browser/close',{confirm:true});})));
$('#modalCancel').addEventListener('click',closeModal);$('#modalConfirm').addEventListener('click',()=>{const callback=app.modalAction;if(!callback)return;closeModal();callback();});$('#confirmModal').addEventListener('click',event=>{if(event.target===$('#confirmModal'))closeModal();});
document.addEventListener('keydown',event=>{if(event.key==='Escape'){if(app.modalAction)closeModal();else if(app.drawer&&!app.busy)closeDrawer();}const overlay=app.modalAction?$('.confirm-modal'):app.drawer?$('.drawer'):null;if(event.key!=='Tab'||!overlay)return;const items=$$('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href]',overlay).filter(item=>item.getClientRects().length),first=items[0],last=items.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}});

$('#editSavedConfiguration').addEventListener('click',editConfiguration);
$('#cancelConfigEdit').addEventListener('click',()=>hydrateOnboarding({onboarding:app.onboarding,configuration:app.configuration,environment:app.environment,startupRecovery:app.startupRecovery}));
$('#environmentResolveButton').addEventListener('click',()=>{app.environmentChecked=false;enterEnvironment();});
$('#environmentRecoveryButton').addEventListener('click',()=>restoreEnvironment({original:true}));
$('#openEnvironmentOptions').addEventListener('click',()=>{closeDrawer();app.environmentChecked=false;enterEnvironment();});
$('#advancedConfigButton').addEventListener('click',()=>openDrawer('advanced'));
$('#relayOverviewButton').addEventListener('click',()=>openDrawer('advanced'));
$('#vpnImportOverviewButton').addEventListener('click',()=>openDrawer('advanced'));
$('#vpnImportButton').addEventListener('click',()=>$('#vpnConfigFile').click());$('#vpnConfigFile').addEventListener('change',importVpnFile);$('#vpnNodeChoice').addEventListener('change',selectVpnNode);$('#vpnChainCheckButton').addEventListener('click',checkImportedChain);
$('#vpnSubscriptionUrl').addEventListener('input',updateControls);$('#vpnSubscriptionRefreshButton').addEventListener('click',refreshSubscription);
$('#vpnSubscriptionClearButton').addEventListener('click',()=>confirmAction('移除订阅地址','只移除本机保存的订阅 URL，节点配置保留。',()=>action('正在移除订阅地址…',async()=>{const data=await api('/api/vpn/subscription/clear',{confirm:true,expectedId:app.vpnConfig.id});app.vpnConfig=data.vpnConfig;renderVpnConfig();},'vpn-import')));
$('#refreshConnectionsButton').addEventListener('click',refreshConnectionRecords);$('#observeConnections').addEventListener('change',()=>{connectionReadGeneration++;if($('#observeConnections').checked)void refreshConnectionRecords();});
$('#previewDiagnosticSummaryButton').addEventListener('click',previewDiagnosticSummary);$('#copyDiagnosticSummaryButton').addEventListener('click',()=>copyProxyText($('#diagnosticShareText')));
$('#cacheApplicationsClosed').addEventListener('change',updateControls);
$('#recoverFakeIpCacheButton').addEventListener('click',()=>confirmAction('恢复 Fake-IP 映射','请确认已正常退出所有受影响的普通浏览器、Claude、Codex 与终端任务。将清理一次系统 DNS 缓存，并归档原映射供排查。旧应用缓存可能失效，完成后需重新连接并重新打开应用。不会清除浏览器账号或资料。',()=>action('正在归档并恢复受管映射…',async()=>{const result=await api('/api/network/cache/recover',{confirm:true,applicationsClosed:true});$('#cacheApplicationsClosed').checked=false;toast(result.mock?'模拟映射恢复完成，未更改系统':'原映射已归档，请重新连接并重新打开应用');},'diagnostics')));
$('#vpnImportSettings').addEventListener('dragover',event=>{event.preventDefault();});$('#vpnImportSettings').addEventListener('drop',event=>{event.preventDefault();if(app.busy||proxy().running||browserRunning())return;const files=event.dataTransfer?.files;if(files?.length===1)void importVpnFile({target:{files,value:''}});});
$('#vpnQrImportButton').addEventListener('click',()=>$('#vpnQrFile').click());$('#vpnQrFile').addEventListener('change',importQrFile);
if(typeof BarcodeDetector==='function')BarcodeDetector.getSupportedFormats().then(formats=>{$('#vpnQrImportButton').hidden=!formats.includes('qr_code');}).catch(()=>{});
$('#vpnPasteToggleButton').addEventListener('click',()=>{const open=$('#vpnPastePanel').hidden;$('#vpnPastePanel').hidden=!open;$('#vpnPasteToggleButton').setAttribute('aria-expanded',String(open));if(open)$('#vpnConfigText').focus();});$('#vpnConfigText').addEventListener('input',updateControls);$('#vpnPasteImportButton').addEventListener('click',()=>confirmVpnImport($('#vpnConfigText').value.replace(/^\uFEFF/,'')));$('#vpnLatencyButton').addEventListener('click',checkVpnLatency);
$('#settingsButton').addEventListener('click',()=>openDrawer('settings'));
$('#workspaceHomeButton').addEventListener('click',()=>setScreen('connection',{allowFuture:true}));
$('#workspaceConnectionButton').addEventListener('click',()=>setScreen('connection'));
$('#connectionWorkspaceButton').addEventListener('click',()=>openWorkspacePage('workspaces'));
$('#workspaceApplicationButton').addEventListener('click',()=>{openDrawer('applicationProxy');void refreshApplications();});
['#routeApplicationsButton','#quickClaudeButton','#quickCodexButton','#allApplicationsButton'].forEach(id=>$(id).addEventListener('click',()=>$('#workspaceApplicationButton').click()));
$('#connectionScopeButton').addEventListener('click',()=>openDrawer('protection'));
$('#connectionEnvironmentDetailsButton').addEventListener('click',()=>openDrawer('environment'));
$('#workspaceRecoveryButton').addEventListener('click',()=>openDrawer('diagnostics'));
$('#workspaceRecoveryStatus').addEventListener('click',()=>openDrawer('diagnostics'));

$('#openConnectionSettingsButton').addEventListener('click',()=>{closeDrawer();setScreen('configuration',{allowFuture:true});$('#connectionMode').focus({preventScroll:true});});
$('#openEnvironmentPanelButton').addEventListener('click',()=>openDrawer('environment'));$('#openApplicationProxyButton').addEventListener('click',()=>openDrawer('applicationProxy'));$('#openDiagnosticsButton').addEventListener('click',()=>openDrawer('diagnostics'));
$('#diagnosticsEnvironmentButton').addEventListener('click',()=>openDrawer('environment'));$('#diagnosticsProtectionButton').addEventListener('click',()=>openDrawer('protection'));$('#openSessionPreferencesButton').addEventListener('click',()=>{closeDrawer();setScreen('preferences',{allowFuture:true});});
$('#relayCheckButton').addEventListener('click',checkRelay);
$('#relayImportButton').addEventListener('click',()=>$('#relayEnrollmentFile').click());
$('#relayEnrollmentFile').addEventListener('change',importRelayFile);
$('#exportDiagnosticsButton').addEventListener('click',exportDiagnostics);
$('#advancedDoneButton').addEventListener('click',()=>{closeDrawer();if(configurationDirty())setScreen('configuration');$('#advancedConfigButton').focus({preventScroll:true});updateControls();});
$('#connectionMode').addEventListener('change',()=>{
  $('#vpnConfirmed').checked=false;
  app.configurationEditing=true;renderConfiguration();renderConnectionOptions();renderRelay();renderVpnConfig();updateAuth();updateControls();
});
$('#vpnConfirmed').addEventListener('change',()=>{if(app.status)renderStatus(app.status);else updateControls();});
['#vpnProxyType','#vpnProxyPort'].forEach(id=>$(id).addEventListener('input',()=>{renderConnectionOptions();updateControls();}));
$('#openProxySettingsButton').addEventListener('click',()=>openWorkspacePage('applications','applicationAdvanced'));
$('#applicationConnectionSettingsButton').addEventListener('click',()=>openDrawer('advanced'));
$('#copyProxyAddressButton').addEventListener('click',()=>copyProxyText($('#localProxyAddress')));
$('#copyTerminalProxyButton').addEventListener('click',()=>copyProxyText($('#terminalProxyExample')));
$('#refreshApplicationsButton').addEventListener('click',refreshApplications);
$('#checkClaudeBackgroundButton').addEventListener('click',checkClaudeBackground);
$('#openClaudeServicesButton').addEventListener('click',openClaudeServices);
$('#disableClaudeStartupButton').addEventListener('click',()=>changeClaudeStartup());
$('#restoreClaudeStartupButton').addEventListener('click',()=>changeClaudeStartup(true));
$('#openApplicationProxyButton').addEventListener('click',refreshApplications);
$('#openProxySettingsButton').addEventListener('click',refreshApplications);
$('#applicationList').addEventListener('click',event=>{const button=event.target.closest('button[data-application],button[data-stop-application]');if(button&&!button.disabled){if(button.dataset.stopApplication)void stopApplication(button.dataset.stopApplication);else void launchApplication(button.dataset.application);}});
$$('[data-application-check]').forEach(button=>button.addEventListener('click',()=>checkApplicationNetwork(button.dataset.applicationCheck,button.dataset.path)));
$('#applicationProtectionButton').addEventListener('click',()=>openWorkspacePage('diagnostics','diagnosticsProtection'));
$('#websiteShortcuts').addEventListener('click',event=>{const button=event.target.closest('button[data-website]');if(button&&!button.disabled)void safeAccess(button.dataset.website);});
$('#applicationBrowserChoice').addEventListener('change',()=>changeBrowserSelection($('#applicationBrowserChoice').value));
$('#fingerprintProfilePreferencesButton').addEventListener('click',()=>setScreen('preferences',{allowFuture:true}));
$('#openBrowserObservationButton').addEventListener('click',()=>openWorkspacePage('applications','browserObservationSection'));$('#openApplicationDiagnosisButton').addEventListener('click',()=>openWorkspacePage('applications','applicationAdvanced'));
$('#rescanBrowsersButton').addEventListener('click',rescanBrowsers);$('#browserExecutablePath').addEventListener('input',updateControls);$('#setBrowserPathButton').addEventListener('click',()=>setBrowserPath());$('#clearBrowserPathButton').addEventListener('click',()=>setBrowserPath(true));
['#applicationsBackButton','#diagnosticsBackButton','#licenseBackButton','#adminBackButton'].forEach(id=>$(id).addEventListener('click',returnToWorkspace));$('#diagnosticsRefreshButton').addEventListener('click',()=>$('#screen-diagnostics').dataset.section==='diagnosticsEnvironment'?inspectEnvironmentCurrent():refreshStatus({force:true,quiet:false,inspect:!app.busy}));
$('#openLicenseButton').addEventListener('click',()=>openWorkspacePage('license'));
$('#openLicensingAdminButton').addEventListener('click',()=>openWorkspacePage('licensing-admin'));
$('#takeoverMode').addEventListener('change',()=>{if(!draftExternalVpn()&&!proxy().running)rememberPreferences({[draftImportedVpn()?'takeoverMode':'relayRoutingMode']:$('#takeoverMode').value});renderConnectionOptions();updateControls();});
$('#autoExternalReport').addEventListener('change',()=>rememberPreferences({externalReport:$('#autoExternalReport').checked}));
$('#connectionWarningDetails').addEventListener('click',()=>openDrawer('environment'));
$('#passwordToggle').addEventListener('click',()=>{const visible=$('#ispPassword').type==='password';$('#ispPassword').type=visible?'text':'password';$('#passwordToggle').setAttribute('aria-label',visible?'隐藏密码':'显示密码');$('#passwordToggle').setAttribute('aria-pressed',String(visible));});
if(window.mcDesktop?.isDesktop){
 document.documentElement.classList.add('desktop');
 $('#windowControls').hidden=false;$('#desktopMode').textContent='DESKTOP';
 $('#networkRepairButton').hidden=typeof window.mcDesktop.repairNetwork!=='function';
 $('#diagnosticsNetworkRepairButton').hidden=typeof window.mcDesktop.repairNetwork!=='function';
 $('#safeQuitButton').hidden=typeof window.mcDesktop.quit!=='function';
 $('#safeQuitButton').addEventListener('click',quitSafely);
 $('#networkRepairButton').addEventListener('click',repairNetwork);
 $('#diagnosticsNetworkRepairButton').addEventListener('click',repairNetwork);
 $('#minimizeWindow').addEventListener('click',()=>window.mcDesktop.minimize().catch(()=>toast('暂时无法最小化窗口',true)));
 $('#closeWindow').addEventListener('click',()=>window.mcDesktop.close().catch(()=>toast('窗口仍在运行，请使用系统托盘',true)));
 window.mcDesktop.getInfo().then(info=>{app.desktopInfo=info;$('#appVersion').textContent='v'+info.version;$('#adminAccessStatus').textContent=adminAccessStatusText(info.adminAccess);renderRepairState(info.networkRepair);updateControls();}).catch(()=>{$('#adminAccessStatus').textContent=adminAccessStatusText();});
}
$('#dismissErrorButton').addEventListener('click',dismissError);
$('#dismissDrawerErrorButton').addEventListener('click',dismissError);
updateControls();initialize();
// Only expiry-dependent views need a clock. State and input events update controls.
const controlsTimer=window.setInterval(()=>{
  if(document.hidden)return;
  if(app.cleanupPlan&&!alive(app.cleanupPlan)||app.claudePlan&&!alive(app.claudePlan))updateControls();
  browserTools.tick();
},1000);
const statusTimer=window.setInterval(()=>{if(!document.hidden&&!app.busy&&app.step!=='splash')void refreshStatus();},15000);
const remindersTimer=window.setInterval(()=>{if(!document.hidden&&!app.busy&&app.step!=='splash')void experienceTools.refreshReminders({quiet:true});},60000);
const connectionsTimer=window.setInterval(()=>{if(!document.hidden&&$('#observeConnections').checked)void refreshConnectionRecords();},3000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden){updateControls();if(!app.busy&&app.step!=='splash')void refreshStatus();}});
window.addEventListener('pagehide',event=>{if(!event.persisted){window.clearInterval(controlsTimer);window.clearInterval(statusTimer);window.clearInterval(remindersTimer);window.clearInterval(connectionsTimer);if(repairPoll)window.clearInterval(repairPoll);connectionReadGeneration++;controllerClient.invalidateStatus();}});

$('#openClientLogButton').addEventListener('click',async()=>{if(app.modalAction||typeof window.mcDesktop?.openClientLog!=='function')return;try{await window.mcDesktop.openClientLog();}catch(error){showError(error.message);}});
