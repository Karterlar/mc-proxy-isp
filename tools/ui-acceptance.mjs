// Repeatable, local-only UI acceptance. Every controller dependency runs in mock
// mode, with a separate in-memory configuration and a disposable Chromium profile.
// Run: node tools/ui-acceptance.mjs
// Optional: BROWSER_BIN, PLAYWRIGHT_MODULE, MC_UI_ACCEPTANCE_OUT, MC_UI_ACCEPTANCE_SIZE.
// MC_UI_ACCEPTANCE_SCENARIO=splash-repair-race runs only the short startup race;
// workspace-pages checks the new pages without the longer historical flows.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { startController } from '../backend/src/local-controller.mjs';
import { createEnvironmentManager } from '../backend/src/environment-manager.mjs';
import { exportChainDiagnostics } from '../backend/src/diagnostics-export.mjs';
import { relayCertificate } from '../backend/test/relay-fixture.mjs';
import { createHash, X509Certificate } from 'node:crypto';
import { auditRouteVisibility, auditStableNodes, auditIdleMutations, auditDrawerError } from './frontend-review-acceptance.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const applicationVersion = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')).version;
const output = path.resolve(process.env.MC_UI_ACCEPTANCE_OUT || path.join(root, '.cache', 'ui-acceptance'));
const runId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}`;
const directory = path.join(output, runId);
const sizes = process.env.MC_UI_ACCEPTANCE_SIZE ? [process.env.MC_UI_ACCEPTANCE_SIZE.split('x').map(Number)] : [[1080, 760], [900, 800], [480, 900], [480, 827], [420, 760], [380, 650]];
const selectedScenario = process.env.MC_UI_ACCEPTANCE_SCENARIO || null;
assert.ok(selectedScenario === null || ['splash-repair-race', 'workspace-pages', 'connection-controls', 'licensing-workflow', 'environment-force'].includes(selectedScenario), 'Unknown MC_UI_ACCEPTANCE_SCENARIO');
assert.ok(sizes.every(size => size.length === 2 && size.every(value => Number.isInteger(value) && value >= 320 && value <= 2000)), 'MC_UI_ACCEPTANCE_SIZE must be WIDTHxHEIGHT');
const require = createRequire(import.meta.url);
const report = { startedAt: new Date().toISOString(), mock: true, network: 'localhost only', browser: null, checks: [], layouts: [], screenshots: [], scenarios: [], errors: [] };
const expectedScenarios = (selectedScenario === 'splash-repair-race' ? 0 : sizes.length) + 1;

function finishScenario(entry, start, completed = true) {
  const checks = report.checks.slice(start);
  report.scenarios.push({ ...entry, completed, passed: completed && checks.length > 0 && checks.every(item => item.passed), checksPassed: checks.filter(item => item.passed).length, checksFailed: checks.filter(item => !item.passed).length });
}

function loadPlaywright() {
  const candidates = [process.env.PLAYWRIGHT_MODULE, 'playwright'].filter(Boolean);
  for (const candidate of candidates) {
    try { return require(candidate); } catch (cause) { if (cause.code !== 'MODULE_NOT_FOUND') throw cause; }
  }
  throw new Error('Playwright is unavailable. Set PLAYWRIGHT_MODULE to an existing installation; this script never installs dependencies.');
}

async function chromePath() {
  for (const candidate of [process.env.BROWSER_BIN, process.env.PROGRAMFILES && path.join(process.env.PROGRAMFILES, 'Google/Chrome/Application/chrome.exe'),
    'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    'C:/Program Files/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium'].filter(Boolean)) {
    try { await access(candidate); return candidate; } catch {}
  }
  throw new Error('A Chromium browser was not found. Set BROWSER_BIN to a local executable; this script never downloads a browser.');
}

function check(name, passed, details = null) {
  report.checks.push({ name, passed: Boolean(passed), ...(details === null ? {} : { details }) });
  return passed;
}

const errorNotice = page => page.locator('#drawerErrorNotice:visible, #errorNotice:visible');

async function settle(page) {
  await page.evaluate(async () => {
    await document.fonts.ready;
    const finite = document.getAnimations().filter(animation => animation.effect?.getComputedTiming().iterations !== Infinity);
    await Promise.race([Promise.all(finite.map(animation => animation.finished.catch(() => {}))), new Promise(resolve => setTimeout(resolve, 1600))]);
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
}

async function idle(page) {
  await page.waitForFunction(() => document.querySelector('#operationNotice')?.hidden === true, { timeout: 10000 });
}

async function preferencesIdle(page, failed = false) {
  await page.waitForFunction(failed => document.querySelector('#preferencesSaveStatus')?.textContent === (failed ? '偏好未保存；请重试保存，当前选择已保留。' : '偏好已保存'), failed, { timeout: 10000 });
}

async function screen(page, name) {
  await page.locator(`[data-screen="${name}"]`).waitFor({ state: 'visible' });
  await settle(page);
}

async function auditTypography(page, label) {
  const result = await page.evaluate(() => {
    const expected = getComputedStyle(document.body).fontFamily;
    const technical = 'pre,code,textarea,.license-identifier,.relay-endpoint,.diagnostic-failure-text,.saved-configuration > p:not(.eyebrow),.proxy-copy-row input';
    const selectors = 'h1,h2,h3,p,.eyebrow,.section-kicker,.brand strong,button,input,select,label,summary,.license-plan-price strong,.admin-summary strong';
    const items = [...document.querySelectorAll(selectors)].filter(element => !element.matches(technical));
    const mismatch = items.filter(element => getComputedStyle(element).fontFamily !== expected).map(element => ({ id: element.id, selector: element.tagName, font: getComputedStyle(element).fontFamily }));
    const mono = getComputedStyle(document.querySelector('#terminalProxyExample')).fontFamily;
    const technicalMismatch = ['exitIp','diagnosticsFailureDetails','licenseId','licenseDeviceId','adminApplicationText','licenseImportText'].filter(id => getComputedStyle(document.getElementById(id)).fontFamily !== mono);
    return { expected, controls: items.length, mismatch, mono, technicalMismatch };
  });
  check(`${label}: all pages and controls use one UI font family, technical fields one mono family`, result.expected.includes('Segoe UI Variable') && result.expected.includes('Microsoft YaHei UI') && result.mismatch.length === 0 && result.technicalMismatch.length === 0, result);
}

async function capture(page, name, animated = false) {
  await page.screenshot({ path: path.join(directory, name), fullPage: false, animations: animated ? 'allow' : 'disabled' });
  report.screenshots.push(name);
}

async function layout(page, viewport, state, { overlay = false, animated = false } = {}) {
  if (!animated) await settle(page);
  else await page.evaluate(() => {
    // Freeze only the finite page transition; leave the loading ring and logo
    // animating. Transition travel itself is not a layout overflow defect.
    const active = [...document.querySelectorAll('[data-screen]')].find(element => !element.hidden);
    for (const animation of active?.getAnimations() || []) if (animation.effect?.getComputedTiming().iterations !== Infinity) animation.finish();
  });
  const metrics = await page.evaluate(({ overlay }) => {
    const visible = element => element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
    const rect = element => {
      const box = element.getBoundingClientRect();
      return { x: box.x, y: box.y, width: box.width, height: box.height, right: box.right, bottom: box.bottom };
    };
    const active = [...document.querySelectorAll('[data-screen]')].filter(visible);
    const modal = document.querySelector('.confirm-modal');
    const region = overlay ? modal && visible(modal) ? modal : [...document.querySelectorAll('[role="dialog"]')].find(visible) : active[0];
    const buttons = [...(region?.querySelectorAll('button') || [])].filter(visible).map(button => ({ id: button.id || button.textContent.trim(), scrollable:Boolean(button.closest('.configuration-content,.workspace-content,.workspace-page-content,.preferences-content,.environment-content,.environment-result,#screen-connection'))||overlay&&Boolean(button.closest('.drawer-content')), ...rect(button) }));
    const environmentScreen = document.querySelector('#screen-environment');
    let environmentSpacing = null;
    if (environmentScreen && visible(environmentScreen)) {
      const content = environmentScreen.querySelector('.environment-content');
      const measure = selector => {
        const element = environmentScreen.querySelector(selector);
        if (!element || !visible(element)) return null;
        const box = rect(element);
        // Compare the content's logical flow even after a button scrolls it.
        // Offscreen content is valid; overlapping siblings are not.
        if (content?.contains(element) && element !== content) {
          box.y += content.scrollTop;
          box.bottom += content.scrollTop;
        }
        return box;
      };
      environmentSpacing = { heading: measure('.screen-heading'), content: measure('.environment-content'), center: measure('.environment-center'), ring: measure('#checkRing'), message: measure('#environmentMessage'), choice: measure('#backupChoice'), result: measure('#environmentResult'), footer: measure('.screen-footer') };
    }
    return { environmentSpacing, viewport: { width: innerWidth, height: innerHeight }, document: { width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight },
      body: { width: document.body.scrollWidth, height: document.body.scrollHeight }, region: region ? rect(region) : null,
      screens: active.map(element => ({ id: element.id, overflow: getComputedStyle(element).overflow, scrollWidth: element.scrollWidth, clientWidth: element.clientWidth, scrollHeight: element.scrollHeight, clientHeight: element.clientHeight, ...rect(element) })), buttons };
  }, { overlay });
  const tolerance = 2;
  const failures = [];
  for (const [name, item] of [['document', metrics.document], ['body', metrics.body]]) {
    if (item.width > viewport.width + tolerance || item.height > viewport.height + tolerance) failures.push(`${name} overflow: ${item.width}x${item.height}`);
  }
  if (metrics.screens.length !== 1) failures.push(`${metrics.screens.length} screens visible`);
  if (!overlay && metrics.environmentSpacing) {
    const spacing = metrics.environmentSpacing;
    const overlaps = (a, b) => a && b && Math.min(a.right, b.right) - Math.max(a.x, b.x) > tolerance && Math.min(a.bottom, b.bottom) - Math.max(a.y, b.y) > tolerance;
    if (overlaps(spacing.ring, spacing.message)) failures.push('environment ring overlaps its status message');
    if (spacing.center) {
      for (const name of ['ring', 'message']) {
        const item = spacing[name];
        if (item && (item.y < spacing.center.y - tolerance || item.bottom > spacing.center.bottom + tolerance)) failures.push(`environment ${name} overflows its center`);
      }
    }
    const flow = ['heading', 'center', 'choice', 'result'].filter(name => spacing[name]);
    for (let index = 1; index < flow.length; index++) {
      if (spacing[flow[index - 1]].bottom > spacing[flow[index]].y + tolerance) failures.push(`environment ${flow[index - 1]} overlaps ${flow[index]}`);
    }
    if (spacing.content && spacing.footer && spacing.content.bottom > spacing.footer.y + tolerance) failures.push('environment scroll region overlaps its footer');
  }
  for (const item of metrics.screens) {
    // Splash uses deliberately oversized decorative art inside overflow:hidden;
    // no form, text flow, or controls depend on scrolling that background.
    if (item.id !== 'screen-splash' && (item.scrollWidth > item.clientWidth + tolerance || item.id !== 'screen-connection' && item.scrollHeight > item.clientHeight + tolerance)) failures.push(`${item.id} scroll overflow: ${item.scrollWidth}x${item.scrollHeight} in ${item.clientWidth}x${item.clientHeight}`);
    if (item.x < -tolerance || item.y < -tolerance || item.right > viewport.width + tolerance || item.bottom > viewport.height + tolerance) failures.push(`${item.id} outside viewport`);
  }
  // Connection fields and detailed drawers scroll within the bounded window.
  // Main save/continue footers and confirmation actions remain visible.
  for (const button of metrics.buttons) {
    if (button.x < -tolerance || button.right > viewport.width + tolerance || !button.scrollable&&(button.y < -tolerance || button.bottom > viewport.height + tolerance)) failures.push(`button ${button.id} outside viewport`);
    if (metrics.region && (button.x < metrics.region.x - tolerance || button.right > metrics.region.right + tolerance || !button.scrollable&&(button.y < metrics.region.y - tolerance || button.bottom > metrics.region.bottom + tolerance))) failures.push(`button ${button.id} clipped by its screen or dialog`);
  }
  const name = `${viewport.width}x${viewport.height}-${state}.png`;
  await capture(page, name, animated);
  const entry = { size: `${viewport.width}x${viewport.height}`, state, passed: failures.length === 0, failures, screenshot: name, metrics };
  report.layouts.push(entry);
  check(`${entry.size}: ${state} fits its bounded viewport and scroll regions`, entry.passed, failures);
}

async function scenario(browser, width, height) {
  const viewport = { width, height };
  const name = `${width}x${height}`;
  const checkStart = report.checks.length;
  const calls = [];
  const pageErrors = [];
  const assetFailures = [];
  const blocked = [];
  let failOptimization = false;
  let environmentPartialFixture = null;
  let environmentHistoryFixture = false;
  let failAutomaticDiagnostics = true;
  let serviceUnavailable = false;
  let startupRecoveryRequired = false;
  let failEnvironmentCheck = false;
  let failLiveSnapshot = false;
  let environmentFixture = null;
  let pendingEnvironmentChecked = false;
  let browserOptionsFixture = null;
  let browserSessionFixture = false;
  let mockBrowserRunning = false;
  let systemNetworkFixture = null;
  let compatibilityFixture = null;
  let latencyFixture = null;
  let applicationCoverageFixture = null;
  let failModeSave = false;
  let failPreferenceSave = false, preferenceDelayMs = 0;
  let heldStart = false, startRelease, cleanupRelease, cleanupReached = false, startReached = false;
  let heldCheck = false, checkRelease, checkReached = false;
  let trafficHoldFixture = null;
  let environmentChecks = 0;
  const environmentOptimizations = [];
  const runtimeRoot = path.join(directory, `mock-runtime-${name}`);
  const memoryEnvironment = createEnvironmentManager({ mock: true, stateDir: path.join(runtimeRoot, '.environment') });
  // Presentation-only partial outcome. Windows calls remain mock=true; manager
  // failure isolation is verified separately by its adapter tests.
  const presentPartialEnvironment = saved => environmentPartialFixture ? { ...saved, restored: false, verification: {
    status: 'partial', source: 'live', checkedAt: saved.verification?.checkedAt,
    differingFields: ['languages'], fieldResults: ['timeZoneId', 'languages', 'homeGeoId', 'culture'].map(field => ({ field, status: field === 'languages' ? 'unmatched' : 'matched' })),
  }, optimization: {
    ...saved.optimization, status: 'partial', operation: environmentPartialFixture,
    differingFields: ['languages'], matchedFields: ['timeZoneId', 'culture', 'homeGeoId'],
    fieldResults: ['timeZoneId', 'languages', 'homeGeoId', 'culture'].map(field => ({ field, status: field === 'languages' ? 'unmatched' : 'matched' })),
  }, current: { ...saved.current, languages: [{ languageTag: 'fr-FR', inputMethodTips: ['040c:0000040c'] }] } } : environmentHistoryFixture ? { ...saved, optimization: { ...saved.optimization, status: 'partial', message: 'Historical partial result', differingFields: ['languages'], fieldResults: [{ field: 'languages', status: 'unmatched' }] } } : saved;
  const environment = { ...memoryEnvironment,
    status: () => presentPartialEnvironment(memoryEnvironment.status()),
    check: async options => { environmentChecks++; await delay(900); return memoryEnvironment.check(options); },
    optimize: async options => {
      environmentOptimizations.push(options);
      if (failOptimization) throw Object.assign(new Error('UI acceptance: controlled environment failure'), { code: 'ENVIRONMENT_APPLY_FAILED' });
      return presentPartialEnvironment(await memoryEnvironment.optimize(options));
    },
    restore: async options => presentPartialEnvironment(await memoryEnvironment.restore(options)),
  };
  // All native-capable managers are created by the controller with mock=true.
  // Paths point only into this test output; no production configuration is read.
  const controller = await startController({ host: '127.0.0.1', port: 0, mock: true, requireRelay: true, healthIntervalMs: 0, runtimeRoot,
    configPath: path.join(runtimeRoot, 'config.json'), secretsPath: path.join(runtimeRoot, 'fixture.secrets.env'), environment,
    exportDiagnostics: async options => {
      if(failAutomaticDiagnostics)throw Object.assign(new Error('Controlled offline export failure'),{code:'DIAGNOSTICS_EXPORT_FAILED'});
      return exportChainDiagnostics(options);
    } });
  const origin = `http://127.0.0.1:${controller.address().port}`;
  const context = await browser.newContext({ viewport, locale: 'zh-CN', colorScheme: 'light', reducedMotion: 'no-preference', serviceWorkers: 'block', extraHTTPHeaders: controller.controlHeaders() });
  await context.addInitScript(({version}) => {
    // Exercise the same titlebar markup as the desktop preload without providing
    // Node, Electron IPC, filesystem access, or native window operations.
    window.mcUiRepair = { calls: 0, result: { cancelled: true } };
    window.mcUiApplications={calls:[],stopCalls:[],quitCalls:0,logCalls:0,running:false,codexRunning:true,fail:false,stopFailure:false,stopCancelled:false};
    const adminNow=Date.now(),day=86400000;
    window.mcUiAdmin={configured:true,calls:[],saveBehavior:'saved',customers:[{licenseId:'a0000000-0000-4000-8000-000000000001',deviceId:'fixture-trial-device',plan:'isp-1d-trial',status:'active',resourcesMode:'customer',version:2,generation:1,expiresAt:adminNow+day,offlineUntil:adminNow+day,ispExpiresAt:null,vpsExpiresAt:null},{licenseId:'a0000000-0000-4000-8000-000000000002',deviceId:'fixture-paid-device',plan:'isp-30d-single',status:'active',resourcesMode:'included',version:2,generation:1,expiresAt:adminNow+7*day,offlineUntil:adminNow+7*day,ispExpiresAt:adminNow+8*day,vpsExpiresAt:adminNow-day}],orders:[]};
    const adminStatus=()=>{const state=window.mcUiAdmin;return {enabled:true,configured:state.configured,directory:'mock/private-issuer',publicKeyFingerprint:'f'.repeat(64),keyId:'mock-ui-public-key',customers:structuredClone(state.customers),orders:structuredClone(state.orders),summary:{licenseCount:state.customers.length,trialCount:state.customers.filter(item=>item.plan==='isp-1d-trial').length,paidLicenseCount:state.customers.filter(item=>item.plan==='isp-30d-single').length,totalReceivedFen:state.orders.reduce((sum,order)=>sum+order.amountFen,0),paidOrders:state.orders.length}};};
    window.mcDesktop = Object.freeze({ isDesktop: true, minimize: async () => {}, close: async () => {}, quit: async () => { window.mcUiApplications.quitCalls++; return {mock:true,quit:true}; },
      getApplications:async()=>({mock:true,processStatus:'simulated',applications:[{id:'claude-desktop',kind:'desktop',installed:true,launchable:!window.mcUiApplications.running,running:window.mcUiApplications.running?1:0,blockedReason:window.mcUiApplications.running?'running-requires-restart':null,stoppable:window.mcUiApplications.running,stopBlockedReason:window.mcUiApplications.running?null:'not-running'},{id:'claude-code',kind:'cli',installed:true,launchable:true,running:0,blockedReason:null,stoppable:false,stopBlockedReason:'close-manually'},{id:'codex-desktop',kind:'desktop',installed:true,launchable:!window.mcUiApplications.codexRunning,running:window.mcUiApplications.codexRunning?2:0,blockedReason:window.mcUiApplications.codexRunning?'running-requires-restart':null,stoppable:window.mcUiApplications.codexRunning,stopBlockedReason:window.mcUiApplications.codexRunning?null:'not-running'},{id:'codex-cli',kind:'cli',installed:true,launchable:true,running:1,blockedReason:null,stoppable:false,stopBlockedReason:'close-manually'},{id:'terminal',kind:'terminal',installed:true,launchable:true,running:0,blockedReason:null,stoppable:false,stopBlockedReason:'close-manually'}]}),
      launchApplication:async id=>{window.mcUiApplications.calls.push(id);if(window.mcUiApplications.fail)throw new Error('出口未核验，应用未启动');return {started:true,mock:true,id};},
      stopApplication:async id=>{window.mcUiApplications.stopCalls.push(id);if(window.mcUiApplications.stopCancelled)return {stopped:false,canceled:true,id};if(window.mcUiApplications.stopFailure){const error=new Error('应用尚未关闭，请完成未保存内容后重试；未强制结束应用。');error.code='APPLICATION_CLOSE_TIMEOUT';throw error;}if(id==='claude-desktop')window.mcUiApplications.running=false;else if(id==='codex-desktop')window.mcUiApplications.codexRunning=false;else throw new Error('请在自己的终端结束任务；未结束任何现有CLI进程。');return {stopped:true,mock:true,id};},
      repairNetwork: async () => { window.mcUiRepair.calls++; return structuredClone(window.mcUiRepair.result); },
      openClientLog: async () => { window.mcUiApplications.logCalls++; return { opened: true }; },
      licenseAdminStatus:async()=>adminStatus(),
      licenseAdminSelectStore:async()=>{window.mcUiAdmin.configured=true;return {selected:true};},
      licenseAdminGenerate:async payload=>{
        const state=window.mcUiAdmin;state.calls.push(structuredClone(payload));
        if(state.saveBehavior==='canceled')return {canceled:true};
        if(state.saveBehavior==='error')throw Object.assign(new Error('PRIVATE_UI_FIXTURE_NATIVE_ERROR'),{code:'OUTPUT_EXISTS'});
        const id=payload.licenseId||'a0000000-0000-4000-8000-000000000003';
        let customer=state.customers.find(item=>item.licenseId===id);
        if(!customer){customer={licenseId:id,deviceId:'fixture-new-device',version:2,generation:0};state.customers.push(customer);}
        Object.assign(customer,{resourcesMode:payload.resourcesMode||customer.resourcesMode||'included',plan:payload.action==='trial'?'isp-1d-trial':'isp-30d-single',status:'active',expiresAt:adminNow+(payload.action==='trial'?day:30*day),offlineUntil:adminNow+(payload.action==='trial'?day:30*day),ispExpiresAt:payload.ispExpiresAt?Date.parse(payload.ispExpiresAt):null,vpsExpiresAt:payload.vpsExpiresAt?Date.parse(payload.vpsExpiresAt):null,generation:customer.generation+1});
        if(payload.orderId&&!state.orders.some(order=>order.orderId===payload.orderId))state.orders.push({orderId:payload.orderId,kind:payload.action==='renew'?'renew':'offline',licenseId:id,resourcesMode:customer.resourcesMode,ispCostFen:customer.resourcesMode==='customer'?0:3500,amountFen:10000,paidAt:adminNow});
        return {saved:true,licenseId:id,filePath:'mock/customer-software-license.json',...adminStatus()};
      },
      getInfo: async () => ({ name: 'MC Proxy', version, edition:'developer', mock: true, closeBehavior: 'tray', networkRepair: window.mcUiRepair.result }) });
  }, {version:applicationVersion});
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) { blocked.push(url.origin); await route.abort(); return; }
    if (url.pathname.startsWith('/api/')) {
      let body;
      try { body = request.postDataJSON(); } catch {}
      calls.push({ method: request.method(), path: url.pathname, ...Object.fromEntries(['refreshBackup', 'rebuildBackup', 'confirm', 'browser', 'fresh', 'service', 'executable', 'connectionMode', 'mode', 'takeoverMode', 'relayRoutingMode', 'autoOptimize', 'completed', 'vpnConfirmed', 'vpnProxy', 'nodeIndex', 'externalReport', 'multi', 'thirdParty', 'force'].filter(key => body && Object.hasOwn(body, key)).map(key => [key, body[key]])), ...(body?.path ? {targetPath:body.path}:{} ) });
      if(heldStart&&url.pathname==='/api/proxy/start'&&request.method()==='POST'){
        startReached=true;await new Promise(resolve=>{startRelease=resolve;});
        await route.fulfill({status:409,contentType:'application/json',json:{ok:false,error:{code:'CONNECTION_CANCELED',message:'连接已取消'}}});return;
      }
      if(heldStart&&url.pathname==='/api/session/end'&&request.method()==='POST'){
        cleanupReached=true;startRelease?.();await new Promise(resolve=>{cleanupRelease=resolve;});
      }
      if(heldCheck&&url.pathname==='/api/applications/check'&&request.method()==='POST'){
        checkReached=true;await new Promise(resolve=>{checkRelease=resolve;});
        await route.fulfill({status:409,contentType:'application/json',json:{ok:false,error:{code:'SESSION_CHANGED',message:'会话已结束，检查取消'}}});return;
      }
      if(trafficHoldFixture&&url.pathname.startsWith('/api/license/')){
        if(url.pathname==='/api/license/import')trafficHoldFixture.allowed=true;
        await route.fulfill({status:200,contentType:'application/json',json:{ok:true,data:{mode:'required',status:trafficHoldFixture.allowed?'active':'expired',allowed:trafficHoldFixture.allowed,serviceConfigured:false}}});return;
      }
      if(trafficHoldFixture&&url.pathname==='/api/proxy/resume'){
        // Presentation fixture only. No real permit, proxy core or external request.
        trafficHoldFixture.resumed=true;
        const response=await route.fetch({url:origin+'/api/snapshot',method:'GET',postData:''}),payload=await response.json();
        payload.data.proxy={...payload.data.proxy,running:true,enabled:true,mode:'tun',trafficBlocked:false,trafficHoldStatus:null,exitStatus:'verified',systemNetwork:{status:'verified'}};
        await route.fulfill({status:200,contentType:'application/json',json:payload});return;
      }
      if(url.pathname==='/api/onboarding/preferences'&&request.method()==='POST'){
        if(preferenceDelayMs)await delay(preferenceDelayMs);
        if(failPreferenceSave){await route.fulfill({status:503,contentType:'application/json',json:{ok:false,error:{code:'PREFERENCES_SAVE_FAILED',message:'UI acceptance: controlled preference save failure'}}});return;}
      }
      if(failModeSave&&url.pathname==='/api/configuration/save'&&request.method()==='POST'){
        await route.fulfill({status:409,contentType:'application/json',json:{ok:false,error:{code:'VPN_COMPATIBILITY_UNAVAILABLE',message:'UI acceptance: VPN route could not verify the ISP exit; saved mode preserved.'}}});return;
      }
      if (serviceUnavailable) {
        await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ ok: false, error: { message: 'UI acceptance: local service unavailable' } }) });
        return;
      }
      if (url.pathname === '/api/proxy/start' && request.method() === 'POST') {
        const response = await route.fetch(), payload = await response.json();
        // A successful mutation returns its own result while status is still
        // busy. Only the following fresh GET authorizes further app launches.
        if (payload.ok) payload.data.statusRead = { state: 'busy', checkedAt: null };
        await route.fulfill({ response, json: payload }); return;
      }
      if (browserSessionFixture && request.method() === 'POST' && ['/api/browser/launch', '/api/browser/close', '/api/session/end', '/api/browsers/path'].includes(url.pathname)) {
        const response = await route.fetch(), payload = await response.json();
        // Native launch stays mocked (launched:false). Public state alone
        // exercises the single-session UI and explicit close confirmation.
        if (payload.ok) mockBrowserRunning = url.pathname === '/api/browser/launch';
        if (payload.ok && url.pathname === '/api/browsers/path') browserOptionsFixture = null;
        await route.fulfill({ response, json: payload }); return;
      }
      if (url.pathname === '/api/environment/check' && request.method() === 'POST') {
        if (failLiveSnapshot) {
          environmentFixture = 'live-invalid';
          await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ ok: false, error: { code: 'ENVIRONMENT_SNAPSHOT_INVALID', message: '无法读取本机环境的语言与输入法，请检查本机设置后重新检查；快照未更改。' } }) });
          return;
        } else if (body?.rebuildBackup === true && body.confirm === true) {
          failEnvironmentCheck = false; environmentFixture = null;
        } else if (failEnvironmentCheck) {
          environmentFixture = 'invalid';
          await route.fulfill({ status: 409, contentType: 'application/json', body: JSON.stringify({ ok: false, error: { code: 'ENVIRONMENT_STATE_INVALID', message: 'UI acceptance: copied snapshot cannot be read; refresh this computer snapshot.' } }) });
          return;
        }
        if (environmentFixture === 'pending') pendingEnvironmentChecked = true;
      }
      if (url.pathname === '/api/environment/adopt' && request.method() === 'POST' && body?.confirm === true) environmentFixture = null;
      if (environmentFixture === 'drift' && request.method() === 'POST' && body?.confirm === true && ['/api/environment/restore', '/api/environment/optimize'].includes(url.pathname)) environmentFixture = null;
      if ((startupRecoveryRequired || environmentFixture || browserOptionsFixture || browserSessionFixture || systemNetworkFixture || compatibilityFixture || latencyFixture || applicationCoverageFixture || trafficHoldFixture) && ['/api/status', '/api/snapshot', '/api/onboarding', '/api/environment/check'].includes(url.pathname)) {
        const response = await route.fetch(); const payload = await response.json();
        if(trafficHoldFixture&&['/api/status','/api/snapshot'].includes(url.pathname)){
          const resumed=trafficHoldFixture.resumed===true;
          payload.data.license={mode:'required',status:trafficHoldFixture.allowed?'active':'expired',allowed:trafficHoldFixture.allowed,serviceConfigured:false};
          payload.data.proxy={...payload.data.proxy,running:true,enabled:resumed,mode:'tun',trafficBlocked:!resumed,trafficHoldStatus:resumed?null:'blocked',exitStatus:resumed?'verified':'unverified',systemNetwork:{status:resumed?'verified':'unverified'}};
        }
        if(compatibilityFixture&&['/api/status', '/api/snapshot'].includes(url.pathname))payload.data.compatibility=compatibilityFixture;
        if(latencyFixture&&['/api/status', '/api/snapshot'].includes(url.pathname)){payload.data.vpnLatency=latencyFixture;payload.data.service.mock=false;}
        if (browserOptionsFixture) payload.data.browserOptions = browserOptionsFixture;
        if (browserSessionFixture && ['/api/status', '/api/snapshot'].includes(url.pathname) && mockBrowserRunning) payload.data.browser = { ...payload.data.browser, running: true, browser: 'edge', mode: 'mocked' };
        if (systemNetworkFixture && ['/api/status', '/api/snapshot'].includes(url.pathname)) {
          // Presentation-only fixture: no native runtime or external request.
          payload.data.service.mock = false;
          payload.data.proxy = { ...payload.data.proxy, mode: 'tun', running: true, enabled: true, requestedStop: false, exitStatus: 'verified', systemNetwork: { status: systemNetworkFixture } };
        }
        if (applicationCoverageFixture && ['/api/status', '/api/snapshot'].includes(url.pathname)) {
          // Public-state presentation only: the controller remains mock=true.
          const coverage = applicationCoverageFixture;
          payload.data.service.mock = false;
          payload.data.proxy = { ...payload.data.proxy, mode: coverage.mode, running: true, enabled: true, requestedStop: false, exitStatus: 'verified', systemNetwork: { status: coverage.mode === 'tun' ? 'verified' : 'unverified' } };
          payload.data.networkLock = { ...payload.data.networkLock, locked: coverage.killSwitch };
          payload.data.protection = { ...payload.data.protection, systemProtected: coverage.systemProtected };
          payload.data.applicationProxy = { ...payload.data.applicationProxy, coverage };
        }
        if (startupRecoveryRequired) {
          payload.data.startupRecovery = { required: true, error: { code: 'STARTUP_RECOVERY_REQUIRED', message: 'UI acceptance: startup recovery required' } };
          if (url.pathname === '/api/onboarding') {
            payload.data.onboarding.recoveryRequired = true;
            payload.data.configuration.available = false;
          }
        }
        if (environmentFixture) {
          const saved = payload.data.environment || (url.pathname === '/api/environment/check' ? payload.data : {}), invalid = environmentFixture === 'invalid', liveInvalid = environmentFixture === 'live-invalid';
          const pending = environmentFixture === 'pending', drift = environmentFixture === 'drift';
          payload.data.environment = drift ? { ...saved, status: 'conflict', ownership: 'matched', restored: false, canRefresh: false, canAdoptCurrent: true,
            backup: { ...saved.backup, ownership: 'matched', canRestore: true, restoreNeeded: true, drifted: true }, optimization: { status: 'idle' }, warnings: ['当前设置有变化，原始快照已保留。'] }
            : pending ? { ...saved, verification: null, status: 'recovery-required', ownership: 'matched', canRefresh: false, canAdoptCurrent: true, needsCheck: !pendingEnvironmentChecked, snapshotSource: pendingEnvironmentChecked ? 'live' : 'saved', current: pendingEnvironmentChecked ? saved.current : { ...saved.current, timeZoneId: 'UTC', culture: 'en-US' },
            backup: { ...saved.backup, ownership: 'matched', canRestore: true, restoreNeeded: true }, optimization: { status: 'recovery-required', message: '上次环境操作未完成，旧恢复记录已保留。' }, warnings: ['当前 Windows 已由用户手动调整，可重新应用或还原。'] }
            : { ...saved, status: invalid || liveInvalid ? 'error' : environmentFixture, ownership: liveInvalid ? 'none' : environmentFixture, canRefresh: true, canAdoptCurrent: !liveInvalid, needsCheck: true,
              backup: invalid || liveInvalid || !saved.backup ? null : { ...saved.backup, ownership: environmentFixture, canRestore: false, restoreNeeded: false },
              warnings: [liveInvalid ? '无法读取本机环境的语言与输入法，未建立新快照。' : 'UI acceptance: preserved snapshot belongs to a different or unknown environment.'] };
          if (url.pathname === '/api/onboarding') payload.data.onboarding.backupExists = Boolean(payload.data.environment.backup);
        }
        await route.fulfill({ response, json: payload });
        return;
      }
    }
    await route.continue();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('pageerror', cause => pageErrors.push(cause.message));
  const cosmosResources = new Map();
  const cosmosResourcePaths = ['/cosmos.css', '/cosmos-surfaces.css', '/assets/earth-nasa-globe-east.jpg'];
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.origin === origin && cosmosResourcePaths.includes(url.pathname)) cosmosResources.set(url.pathname, response.status());
    if(url.origin===origin&&response.status()>=400&&['script','stylesheet','image','font'].includes(response.request().resourceType()))assetFailures.push({path:url.pathname,status:response.status()});
  });
  await page.addInitScript(() => {
    window.mcUiCspViolations = [];
    document.addEventListener('securitypolicyviolation', event => window.mcUiCspViolations.push(event.violatedDirective));
  });
  const get = async endpoint => {
    const response = await context.request.get(origin + endpoint);
    assert.equal(response.status(), 200, endpoint);
    const result = await response.json();
    assert.equal(result.ok, true, endpoint);
    return result.data;
  };
  const count = endpoint => calls.filter(call => call.method === 'POST' && call.path === endpoint).length;
  const click = async selector => { await page.locator(selector).click(); await idle(page); };
  const leaveTools = async () => {
    if (await page.locator('#drawerBackdrop').isVisible()) await click('#closeDrawerButton');
    if (await page.locator('#screen-applications').isVisible()) await click('#applicationsBackButton');
    else if (await page.locator('#screen-diagnostics').isVisible()) await click('#diagnosticsBackButton');
  };
  const openGroup = async id => { if(await page.locator('#drawerBackdrop').isVisible())await leaveTools();await click('#settingsButton');await click(id); };
  // Returning customers open the connection workspace. Recovery scenarios enter
  // the existing environment editor explicitly instead of expecting old startup navigation.
  const reopenEnvironment = async () => {
    await page.reload({ waitUntil: 'domcontentloaded' });
    await screen(page, 'connection');
    await openGroup('#openEnvironmentPanelButton');
    if(!await page.locator('.environment-advanced').evaluate(element=>element.open))await click('.environment-advanced > summary');
    await click('#openEnvironmentOptions');
    await screen(page, 'environment');
  };
  try {
    assert.equal((await get('/api/status')).service.mock, true, 'test controller must never enter live mode');
    await page.goto(origin, { waitUntil: 'domcontentloaded' });
    if(selectedScenario==='environment-force'){
      await screen(page,'configuration');
      await page.locator('#ispHost').fill('192.0.2.1');await page.locator('#ispPort').fill('8080');await page.locator('#ispUsername').fill('ui-fixture');await page.locator('#ispPassword').fill('not-a-real-secret');
      await click('#configurationSaveButton');await click('#configurationContinueButton');await idle(page);await click('#environmentContinueButton');
      await page.locator('#autoOptimize').uncheck();await preferencesIdle(page);await click('#preferencesContinueButton');
      const originalBackup=(await get('/api/onboarding')).environment.backup.id;
      check(`${name}: unchanged initial snapshot remains restorable without a false pending warning`,!await page.locator('#connectionEnvironmentRestoreButton').isDisabled()&&!/待复原/.test(await page.locator('#workspaceRecoverySummary').textContent()));
      await click('#connectionEnvironmentRestoreButton');
      check(`${name}: missing daily settings open the editor without silently restoring a snapshot`,await page.locator('#environmentProfiles').isVisible()&&await page.locator('#protectionEnvironmentRestoreButton').isDisabled()&&count('/api/environment/restore')===0&&count('/api/environment/restore-original')===0);
      const editorTop=async()=>{await page.waitForFunction(()=>document.querySelector('#toastStack').children.length===0,{timeout:7000});await page.evaluate(()=>{document.activeElement?.blur();document.querySelector('#diagnosticsContent').scrollTop=0;});await settle(page);};
      await click('#environmentWorkTab');await editorTop();await layout(page,viewport,'environment-work-auto-editor');
      check(`${name}: full-card profile tabs show only one editor`,await page.locator('#environmentWorkPanel').isVisible()&&await page.locator('#environmentDailyPanel').isHidden()&&await page.locator('#environmentWorkTab').getAttribute('aria-selected')==='true');
      await page.locator('#environmentWorkTab').focus();await page.keyboard.press('ArrowRight');
      check(`${name}: keyboard navigation selects the daily profile tab`,await page.locator('#environmentDailyPanel').isVisible()&&await page.locator('#environmentWorkPanel').isHidden()&&await page.locator('#environmentDailyTab').getAttribute('aria-selected')==='true');
      const beforeCurrent=(await get('/api/onboarding')).environment.current;
      await click('#environmentCaptureDailyButton');
      check(`${name}: capture fills actual daily settings without saving or changing Windows`,await page.locator('#environmentDailyCulture').inputValue()===beforeCurrent.culture&&count('/api/environment/preferences')===0);
      await page.locator('#environmentDailyPreset').selectOption('CN');
      check(`${name}: daily presets remain editable and use the selected language regional format`,await page.locator('#environmentDailyCulture').inputValue()==='zh-CN');
      check(`${name}: shared time zones name representative cities instead of the first matching country`,(await page.locator('#environmentDailyTimezone option:checked').textContent()).startsWith('北京 / 香港 · ')&&(await page.locator('#environmentWorkTimezone option[value="Eastern Standard Time"]').textContent()).startsWith('纽约 / 多伦多 · '));
      await editorTop();await layout(page,viewport,'environment-daily-editor');
      await click('#environmentWorkTab');
      await page.locator('#environmentWorkMode').selectOption('custom');await page.locator('#environmentWorkPreset').selectOption('JP');
      check(`${name}: custom work settings can apply without a proxy connection and keep fixed Singapore format`,!await page.locator('#environmentOptimizeButton').isDisabled()&&await page.locator('#environmentWorkCulture').getAttribute('readonly')!==null&&/zh-SG/.test(await page.locator('#environmentWorkCulture').inputValue()));
      await click('#environmentSaveProfilesButton');
      const savedProfiles=(await get('/api/onboarding')).environment;
      check(`${name}: save-only persists both profiles and never applies Windows settings`,savedProfiles.preferences.work.countryCode==='JP'&&savedProfiles.preferences.daily.countryCode==='CN'&&savedProfiles.preferences.daily.culture==='zh-CN'&&JSON.stringify(savedProfiles.current)===JSON.stringify(beforeCurrent)&&environmentOptimizations.length===0&&count('/api/environment/restore')===0);
      await page.locator('#environmentWorkLanguage').fill('fr-FR');await click('#refreshButton');
      check(`${name}: status refresh preserves unsaved profile edits`,await page.locator('#environmentWorkLanguage').inputValue()==='fr-FR'&&/未保存/.test(await page.locator('#environmentProfilesStatus').textContent()));
      await page.locator('#environmentWorkLanguage').fill('ja-JP');
      await editorTop();await layout(page,viewport,'environment-work-custom-editor');
      const beforeApply=count('/api/environment/optimize');await click('#environmentOptimizeButton');
      check(`${name}: explicit apply confirms intermediate changes and original snapshot retention`,/中途.*覆盖/.test(await page.locator('#modalBody').textContent())&&/原始恢复快照保持不变/.test(await page.locator('#modalBody').textContent()));
      await click('#modalCancel');
      check(`${name}: cancel apply sends no mutation`,count('/api/environment/optimize')===beforeApply&&(await get('/api/onboarding')).environment.backup.id===originalBackup);
      await click('#environmentOptimizeButton');await click('#modalConfirm');
      const applied=(await get('/api/onboarding')).environment;
      check(`${name}: custom apply uses force with saved target and preserves snapshot`,count('/api/environment/optimize')===beforeApply+1&&environmentOptimizations.at(-1)?.force===true&&applied.current.culture==='zh-SG'&&applied.current.homeGeoId===122&&applied.current.languages[0].languageTag==='ja-JP'&&applied.backup.id===originalBackup);
      await leaveTools();await click('#connectButton');await openGroup('#openEnvironmentPanelButton');
      check(`${name}: connection with environment preference disabled performs no extra apply`,environmentOptimizations.length===1);
      environmentPartialFixture='optimize';await click('#environmentOptimizeButton');await click('#modalConfirm');
      check(`${name}: partial apply keeps successful rows and a usable verified connection`,/仍有项目未匹配.*已生效的设置保留/.test(await page.locator('#environmentSummary').textContent())&&await page.locator('#environmentSettingResults [data-field="culture"]').getAttribute('data-state')==='matched'&&await page.locator('#environmentSettingResults [data-field="languages"]').getAttribute('data-state')==='unmatched'&&/ja-JP/.test(await page.locator('#environmentSettingResults [data-field="languages"]').textContent())&&(await get('/api/status')).proxy.running);
      await page.locator('#environmentSettingResults').evaluate(element=>{element.scrollIntoView({block:'start'});document.activeElement?.blur();});
      await layout(page,viewport,'environment-partial-results');
      environmentPartialFixture=null;environmentHistoryFixture=true;const beforeCheck=count('/api/environment/check'),beforeVerifyApplies=environmentOptimizations.length;
      check(`${name}: environment page exposes an explicit current verification action`,/重新核验环境/.test(await page.locator('#diagnosticsRefreshButton').textContent()));
      await click('#diagnosticsRefreshButton');
      const verified=(await get('/api/onboarding')).environment,verifyCall=calls.filter(call=>call.path==='/api/environment/check').at(-1);
      check(`${name}: explicit verification clears stale red rows while retaining operation history and original backup`,count('/api/environment/check')===beforeCheck+1&&environmentOptimizations.length===beforeVerifyApplies&&!verifyCall.refreshBackup&&!verifyCall.rebuildBackup&&verified.backup.id===originalBackup&&verified.optimization.status==='partial'&&verified.verification.status==='matched'&&await page.locator('#environmentSettingResults [data-field="languages"]').getAttribute('data-state')==='matched'&&/当前设置.*目标匹配.*上次操作记录保留/.test(await page.locator('#environmentSummary').textContent())&&!/Historical partial result/.test(await page.locator('#environmentSummary').textContent())&&await page.locator('#connectionWarning').isHidden());
      environmentHistoryFixture=false;
      const beforeRestore=count('/api/environment/restore');environmentPartialFixture='restore';await click('#environmentDailyTab');await click('#protectionEnvironmentRestoreButton');
      check(`${name}: daily restore names saved settings and retaining completed items`,/日常环境/.test(await page.locator('#modalTitle').textContent())&&/成功项目保留/.test(await page.locator('#modalBody').textContent()));
      await click('#modalCancel');check(`${name}: cancel restore makes no restore mutation`,count('/api/environment/restore')===beforeRestore);
      await click('#protectionEnvironmentRestoreButton');await click('#modalConfirm');
      const partialRestoreFeedback = { noticeText: await errorNotice(page).textContent(), toastText: await page.locator('#toastStack').textContent(), warningHidden: await page.locator('#connectionWarning').evaluate(element => element.hidden), warningTitle: await page.locator('#connectionWarningTitle').textContent(), currentScreen: await page.locator('[data-screen]:visible').getAttribute('data-screen') };
      check(`${name}: partial restore reports its foreground error without claiming complete success`,/部分设置已复原/.test(partialRestoreFeedback.noticeText)&&!/系统环境已复原/.test(partialRestoreFeedback.toastText)&&!partialRestoreFeedback.warningHidden&&/当前环境尚未匹配目标/.test(partialRestoreFeedback.warningTitle),partialRestoreFeedback);
      environmentPartialFixture=null;await click('#protectionEnvironmentRestoreButton');await click('#modalConfirm');
      const restored=(await get('/api/onboarding')).environment;
      check(`${name}: daily restore follows saved daily values while keeping original backup`,restored.current.timeZoneId==='China Standard Time'&&restored.current.culture==='zh-CN'&&restored.current.homeGeoId===45&&restored.backup.id===originalBackup&&restored.optimization.status==='restored'&&count('/api/environment/adopt')===0);
      await click('.environment-advanced > summary');await click('#environmentOriginalRestoreButton');
      check(`${name}: original restoration remains an explicitly separate advanced operation`,/原始快照/.test(await page.locator('#modalTitle').textContent()));await click('#modalConfirm');
      check(`${name}: original restoration uses its own endpoint and keeps daily preferences`,count('/api/environment/restore-original')===1&&(await get('/api/onboarding')).environment.preferences.daily.timeZoneId==='China Standard Time');
      environmentFixture='foreign';await click('#refreshButton');
      check(`${name}: original snapshot from another machine or user cannot be restored`,await page.locator('#environmentOriginalRestoreButton').isDisabled());
      check(`${name}: environment acceptance uses no external traffic or real service and has no renderer errors`,blocked.length===0&&pageErrors.length===0&&(await get('/api/status')).service.mock===true,{blocked,pageErrors});
      finishScenario({name,networkRequests:calls,rendererErrors:pageErrors,blockedOrigins:blocked},checkStart);return;
    }
    if(selectedScenario==='licensing-workflow'){
      const adminIdle=async()=>{await page.waitForFunction(()=>document.querySelector('#screen-licensing-admin').getAttribute('aria-busy')==='false');await settle(page);};
      const adminClick=async selector=>{await page.locator(selector).click();await adminIdle();};
      const resetScroll=async()=>{await page.locator('#licensing-adminContent').evaluate(element=>{element.scrollTop=0;});};
      const application=JSON.stringify({request:{action:'offline',deviceId:'fixture-new-device',devicePublicKey:'PUBLIC_UI_FIXTURE'},signature:'MOCK_UI_ONLY'});
      await screen(page,'configuration');await page.evaluate(()=>{window.mcUiAdmin.configured=false;});
      await click('#settingsButton');await click('#openLicensingAdminButton');await screen(page,'licensing-admin');await adminIdle();
      check(`${name}: new administrator sees the original store requirement before any signing`,await page.locator('#adminGenerateButton').isDisabled()&&await page.locator('#adminTrialButton').isDisabled()&&/授权库/.test(await page.locator('#adminNextStep').textContent()));
      await auditStableNodes(page,check,`${name}: administrator missing requirements`,['#adminMissingList button'],{focus:'#adminMissingList button'});
      await adminClick('#adminSelectStoreButton');
      check(`${name}: reading an issuer exposes three daily operations and keeps ledgers and maintenance collapsed`,!await page.locator('#adminTrialButton').isDisabled()&&await page.locator('#adminActivateButton').isVisible()&&await page.locator('#adminRenewButton').isVisible()&&await page.locator('#adminMaintenanceDetails').evaluate(element=>!element.open)&&await page.locator('.admin-ledger').evaluate(element=>!element.open)&&await page.locator('#adminGenerateButton').isDisabled());
      await auditStableNodes(page,check,`${name}: administrator customer options`,['#adminCustomer option']);
      await auditTypography(page,`${name}: licensing workflow`);await resetScroll();await layout(page,viewport,'admin-daily-workflow');
      await page.locator('#adminApplicationText').fill('{bad-json');
      check(`${name}: malformed application cannot advance and names the correction`,await page.locator('#adminGenerateButton').isDisabled()&&/JSON/.test(await page.locator('#adminMissingList').textContent()));
      await page.locator('#adminApplicationFile').setInputFiles({name:'ui-device-application.json',mimeType:'application/json',buffer:Buffer.from(application)});await adminIdle();
      check(`${name}: application file enables identity preparation without silently confirming ISP delivery`,await page.locator('#adminApplicationText').inputValue()===application&&!await page.locator('#adminResourcesReady').isChecked()&&await page.locator('#adminGenerateButton').isDisabled()&&/真实ISP/.test(await page.locator('#adminMissingList').textContent()));
      await page.locator('#adminResourcesMode').selectOption('customer');
      check(`${name}: self-supplied ISP trial needs no supplier dates and fixes the offline window to one day`,await page.locator('#adminResourceFields').isHidden()&&!await page.locator('#adminGenerateButton').isDisabled()&&await page.locator('#adminOfflineDays').inputValue()==='1'&&await page.locator('#adminOfflineDays').isDisabled());
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='canceled';});await adminClick('#adminGenerateButton');
      check(`${name}: canceled trial save keeps the application and creates no order or delivery claim`,await page.locator('#adminApplicationText').inputValue()===application&&await page.locator('#adminSavedFile').isHidden()&&/已取消/.test(await page.locator('#adminOperationResult').textContent())&&await page.evaluate(()=>window.mcUiAdmin.orders.length)===0);
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='error';});await adminClick('#adminGenerateButton');
      check(`${name}: a failed save explains the next action without exposing the native error or erasing the draft`,/新.*JSON文件名/.test(await page.locator('#adminOperationResult').textContent())&&!/PRIVATE_UI_FIXTURE/.test(await page.locator('#adminOperationResult').textContent())&&await page.locator('#adminApplicationText').inputValue()===application);
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='saved';});await adminClick('#adminGenerateButton');
      check(`${name}: successful trial names software import and the separate optional VPS registration`,await page.locator('#adminDeliveryPanel').isVisible()&&/授权与续费/.test(await page.locator('#adminDeliveryInstructions').textContent())&&/另发.*中转注册JSON/.test(await page.locator('#adminDeliveryInstructions').textContent())&&await page.evaluate(()=>window.mcUiAdmin.orders.length)===0);
      const trialId='a0000000-0000-4000-8000-000000000003';
      check(`${name}: trial completion preselects the same customer for paid conversion without confirming payment`,await page.locator('#adminCustomer').inputValue()===trialId&&await page.locator('#adminAction').inputValue()==='renew'&&await page.locator('#adminResourcesMode').inputValue()==='customer'&&!await page.locator('#adminPaidConfirmed').isChecked()&&await page.locator('#adminGenerateButton').isDisabled());
      await page.locator('#adminDeliveryPanel').scrollIntoViewIfNeeded();await layout(page,viewport,'admin-trial-delivery');
      await adminClick('#adminRenewButton');
      const firstOrder=await page.locator('#adminOrderId').inputValue();await page.locator('#adminPaidConfirmed').check();
      check(`${name}: software conversion defaults to thirty days and requires an explicit received-payment confirmation`,/^MC-[0-9a-f-]{36}$/.test(firstOrder)&&await page.locator('#adminOfflineDays').inputValue()==='30'&&!await page.locator('#adminGenerateButton').isDisabled());
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='canceled';});await adminClick('#adminGenerateButton');
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='error';});await adminClick('#adminGenerateButton');
      check(`${name}: paid save cancellation and failure keep the original action and order for retry`,await page.locator('#adminAction').inputValue()==='renew'&&await page.locator('#adminOrderId').inputValue()===firstOrder&&await page.evaluate(()=>window.mcUiAdmin.orders.length)===0&&await page.evaluate(()=>window.mcUiAdmin.calls.filter(item=>item.action==='renew').every(item=>item.orderId===window.mcUiAdmin.calls.find(item=>item.action==='renew').orderId)));
      await page.evaluate(()=>{window.mcUiAdmin.saveBehavior='saved';});await adminClick('#adminGenerateButton');
      check(`${name}: conversion records exactly one self-ISP order and explains free reissue separately from the next payment`,await page.evaluate(()=>window.mcUiAdmin.orders.length===1&&window.mcUiAdmin.orders[0].licenseId==='a0000000-0000-4000-8000-000000000003'&&window.mcUiAdmin.orders[0].ispCostFen===0)&&/免费重签/.test(await page.locator('#adminDeliveryInstructions').textContent())&&await page.locator('#adminOrderId').inputValue()===firstOrder);
      await adminClick('#adminRenewButton');await page.locator('#adminCustomer').selectOption('a0000000-0000-4000-8000-000000000002');
      check(`${name}: selecting a supplied-ISP renewal carries the original ownership and requires fresh payment and resource confirmation`,await page.locator('#adminResourcesMode').inputValue()==='included'&&!await page.locator('#adminPaidConfirmed').isChecked()&&!await page.locator('#adminResourcesReady').isChecked()&&await page.locator('#adminGenerateButton').isDisabled());
      await page.locator('#adminPaidConfirmed').check();await page.locator('#adminResourcesReady').check();
      check(`${name}: an insufficient ISP term refuses thirty-day renewal before signing`,await page.locator('#adminGenerateButton').isDisabled()&&/ISP须完整覆盖/.test(await page.locator('#adminMissingList').textContent()));
      const supplierDate=await page.evaluate(()=>{const value=new Date(Date.now()+40*86400000);return new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0,16);});
      await page.locator('#adminIspExpiresAt').fill(supplierDate);
      check(`${name}: adequate ISP coverage permits renewal while an expired optional VPS reminder does not block software`,!await page.locator('#adminGenerateButton').isDisabled()&&await page.locator('#adminVpsExpiresAt').inputValue()!==''&&/免费可选 VPS/.test(await page.locator('#adminTermPreview').textContent()));
      await page.locator('#adminOrderId').fill(firstOrder);
      check(`${name}: a historical order for another customer cannot be reused`,await page.locator('#adminGenerateButton').isDisabled()&&/另一客户/.test(await page.locator('#adminMissingList').textContent()));
      await adminClick('#adminNewOrderButton');const nextOrder=await page.locator('#adminOrderId').inputValue();
      check(`${name}: only an explicit new-payment action replaces the order and clears payment confirmation`,nextOrder!==firstOrder&&/^MC-[0-9a-f-]{36}$/.test(nextOrder)&&!await page.locator('#adminPaidConfirmed').isChecked());
      await page.locator('#adminPaidConfirmed').check();await resetScroll();await layout(page,viewport,'admin-included-renewal');
      await auditTypography(page,`${name}: completed licensing workflow`);
      check(`${name}: issuing UI stays independent of network sessions and has no external requests or renderer failures`,count('/api/proxy/start')===0&&count('/api/session/end')===0&&pageErrors.length===0&&blocked.length===0,{pageErrors,blocked});
      finishScenario({name,networkRequests:calls,administratorCalls:await page.evaluate(()=>window.mcUiAdmin.calls),rendererErrors:pageErrors,blockedOrigins:blocked},checkStart);return;
    }
    if(selectedScenario==='connection-controls'){
      const hostWait=async condition=>{const until=Date.now()+10000;while(!condition()&&Date.now()<until)await delay(30);assert.ok(condition(),'local presentation fixture reached the expected request');};
      await screen(page,'configuration');await auditTypography(page,`${name}: initial configuration`);
      await page.locator('#ispHost').fill('192.0.2.1');await page.locator('#ispPort').fill('8080');await page.locator('#ispUsername').fill('ui-fixture');await page.locator('#ispPassword').fill('not-a-real-secret');
      await click('#configurationSaveButton');await click('#configurationContinueButton');await idle(page);await click('#environmentContinueButton');
      await page.locator('#autoOptimize').uncheck();await preferencesIdle(page);await click('#preferencesContinueButton');
      heldStart=true;await page.locator('#connectButton').click();await hostWait(()=>startReached);
      check(`${name}: connection work exposes cancel and safe quit while writes remain disabled`, !await page.locator('#connectButton').isDisabled()&&/取消连接/.test(await page.locator('#connectButtonLabel').textContent())&&!await page.locator('#safeQuitButton').isDisabled()&&await page.locator('#editIspButton').isDisabled());
      const environmentsDisabled=await page.locator('#workspaceSpacesButton').isDisabled();
      if(!environmentsDisabled){await page.locator('#workspaceSpacesButton').click();await screen(page,'workspaces');await page.locator('#experienceConnection').click();await screen(page,'connection');}
      check(`${name}: busy environment navigation is explicitly disabled or actually navigates`,environmentsDisabled||await page.locator('#screen-connection').isVisible());
      await page.locator('#safeQuitButton').click();
      check(`${name}: an immediate native quit reply cannot release the original connection work`, await page.evaluate(()=>window.mcUiApplications.quitCalls)===1&&await page.locator('#operationNotice').isVisible()&&await page.locator('#editIspButton').isDisabled());
      await page.locator('#workspaceRecoveryStatus').click();await screen(page,'diagnostics');
      await page.locator('#openClientLogButton').click();await page.locator('#diagnosticsRefreshButton').click();
      check(`${name}: read-only diagnostics and logs stay accessible during connection work`,await page.evaluate(()=>window.mcUiApplications.logCalls)===1&&!await page.locator('#diagnosticsRefreshButton').isDisabled()&&await page.locator('#diagnosticsNetworkRepairButton').isDisabled());
      await auditTypography(page,`${name}: busy diagnostics`);await page.locator('#diagnosticsBackButton').click();await screen(page,'connection');
      const endBefore=count('/api/session/end');await page.locator('#connectButton').evaluate(button=>{button.click();button.click();});await hostWait(()=>cleanupReached);
      check(`${name}: cancellation sends one immediate end request without a confirmation and retains busy until cleanup`,count('/api/session/end')===endBefore+1&&await page.locator('#confirmModal').isHidden()&&await page.locator('#connectButton').isDisabled()&&/正在取消/.test(await page.locator('#connectButtonLabel').textContent())&&await page.locator('#operationNotice').isVisible());
      await layout(page,viewport,'cancel-cleanup-pending');cleanupRelease();await idle(page);heldStart=false;
      check(`${name}: normal cancellation returns idle without a connection failure`,await page.locator('#connectButton').isEnabled()&&!await errorNotice(page).isVisible()&&!(await get('/api/status')).proxy.running);
      await click('#connectButton');await page.locator('#workspaceApplicationButton').click();await screen(page,'applications');await auditTypography(page,`${name}: applications`);
      await page.locator('#applicationAdvanced > summary').click();await settle(page);
      heldCheck=true;await page.locator('[data-application-check="claude"][data-path="proxy"]').click();await hostWait(()=>checkReached);
      await page.locator('#workspaceConnectionButton').click();await screen(page,'connection');await page.locator('#connectButton').click();await page.locator('#modalConfirm').click();
      await page.waitForFunction(()=>document.querySelector('#connectButtonLabel').textContent!=='正在取消');
      check(`${name}: session end stays available during a service check while original read owns busy`,count('/api/session/end')===endBefore+2&&await page.locator('#operationNotice').isVisible()&&await page.locator('#editIspButton').isDisabled());
      checkRelease();await idle(page);heldCheck=false;
      check(`${name}: ending a read-only check suppresses the expected session-changed error`,!await errorNotice(page).isVisible()&&!(await get('/api/status')).proxy.running);
      await page.evaluate(()=>{window.mcUiRepair.result={pending:true,completed:false,reportPath:'mock/network-repair/pending.json'};});await page.locator('#networkRepairButton').click();
      await page.waitForFunction(()=>document.querySelector('#operationText').textContent.includes('实际结果'));
      await page.locator('#workspaceRecoveryButton').click();await screen(page,'diagnostics');
      check(`${name}: pending repair exposes its report and blocks network writes without claiming success`,await page.locator('#operationNotice').isVisible()&&await page.locator('#networkRepairButton').isDisabled()&&/修复尚未完成/.test(await page.locator('#diagnosticsExportResult').textContent())&&!/网络修复已完成/.test(await page.locator('#toastStack').textContent()));
      await page.evaluate(()=>{window.mcUiRepair.result={pending:false,completed:true,success:false,code:'NETWORK_REPAIR_PARTIAL',reportPath:'mock/network-repair/result.json'};});
      await page.waitForFunction(()=>document.querySelector('#diagnosticsExportResult').textContent.includes('网络修复未完成'));
      check(`${name}: repair polling reports an actual failure and retains the report`,await page.locator('#operationNotice').isHidden()&&/NETWORK_REPAIR_PARTIAL/.test(await page.locator('#diagnosticsExportResult').textContent())&&!/网络修复已完成/.test(await page.locator('#toastStack').textContent()));
      trafficHoldFixture={allowed:false,resumed:false};await click('#diagnosticsRefreshButton');await click('#diagnosticsBackButton');
      check(`${name}: expired retained TUN offers explicit end and keeps resume disabled`,/恢复普通网络/.test(await page.locator('#connectButtonLabel').textContent())&&await page.locator('#resumeProxyButton').isDisabled()&&/流量已阻断/.test(await page.locator('#connectionTitle').textContent()));
      await page.locator('#connectButton').click();check(`${name}: ending retained TUN warns about real IP direct access`,/真实 IP 直连/.test(await page.locator('#modalBody').textContent()));await page.locator('#modalCancel').click();
      await click('#settingsButton');await click('#openLicenseButton');await screen(page,'license');await auditTypography(page,`${name}: license`);
      await page.locator('#licenseImportText').fill('{"fixture":true}');await page.locator('#licenseImportButton').click();await page.waitForFunction(()=>document.querySelector('#licenseState').textContent.includes('有效'));
      check(`${name}: importing a renewed permit never resumes a retained TUN automatically`,count('/api/proxy/resume')===0&&trafficHoldFixture.resumed===false);
      await click('#licenseBackButton');await page.locator('#resumeProxyButton').click();await idle(page);
      check(`${name}: a valid permit enables explicit in-place resume without ending the TUN`,count('/api/proxy/resume')===1&&count('/api/session/end')===endBefore+2&&trafficHoldFixture.resumed===true);
      await click('#settingsButton');await click('#openLicensingAdminButton');await screen(page,'licensing-admin');await auditTypography(page,`${name}: administrator`);await layout(page,viewport,'admin-resource-ownership');await click('#adminBackButton');
      await auditTypography(page,`${name}: connection`);await layout(page,viewport,'resumed-connection');
      check(`${name}: no renderer errors or external requests in presentation acceptance`,pageErrors.length===0&&blocked.length===0,{pageErrors,blocked});
      finishScenario({name,networkRequests:calls,rendererErrors:pageErrors,blockedOrigins:blocked},checkStart);return;
    }
    if (selectedScenario === 'workspace-pages') {
      await screen(page, 'configuration');
      await click('#settingsButton'); await click('#openApplicationProxyButton');
      check(`${name}: initial application page cannot bypass connection preparation`, await page.locator('#screen-applications').isVisible() && await page.locator('#workspaceConnectionButton').isDisabled() && /连接准备/.test(await page.locator('#applicationsBackButton').textContent()));
      await leaveTools();
      check(`${name}: initial application return retains the configuration step`, await page.locator('#screen-configuration').isVisible());
      await click('#settingsButton'); await click('#openDiagnosticsButton');
      check(`${name}: initial diagnostics stays accessible without enabling connection workspace`, await page.locator('#screen-diagnostics').isVisible() && await page.locator('#workspaceConnectionButton').isDisabled());
      await leaveTools();
      check(`${name}: initial diagnostics return retains the configuration step`, await page.locator('#screen-configuration').isVisible());
      check(`${name}: external quality reports default to an explicit opt-in`, !await page.locator('#autoExternalReport').isChecked() && (await get('/api/onboarding')).onboarding.preferences.externalReport === false);
      await page.locator('#configurationExtras').evaluate(element=>{element.open=true;});
      await page.locator('#autoExternalReport').check(); await preferencesIdle(page);
      check(`${name}: report opt-in saves immediately before continuing`, (await get('/api/onboarding')).onboarding.preferences.externalReport === true);
      await page.locator('#autoExternalReport').uncheck(); await preferencesIdle(page);
      await page.locator('#configurationExtras').evaluate(element=>{element.open=false;});
      check(`${name}: report opt-out saves immediately`, (await get('/api/onboarding')).onboarding.preferences.externalReport === false);
      const initialTakeover=await page.evaluate(()=>({source:document.querySelector('#connectionMode').value,value:document.querySelector('#takeoverMode').value,hidden:document.querySelector('#takeoverModeField').hidden,httpDisabled:document.querySelector('#takeoverMode option[value="application"]').disabled}));
      check(`${name}: VPS defaults to global TUN and forbids HTTP-only takeover`, initialTakeover.source==='relay'&&initialTakeover.value==='global'&&!initialTakeover.hidden&&initialTakeover.httpDisabled,initialTakeover);
      await page.locator('#takeoverMode').selectOption('smart');await preferencesIdle(page);
      await page.locator('#connectionMode').selectOption('vpn-import');
      check(`${name}: imported configuration independently defaults to global TUN`, await page.locator('#takeoverMode').inputValue()==='global'&&!await page.locator('#takeoverMode option[value="application"]').isDisabled());
      await page.locator('#takeoverMode').selectOption('application');await preferencesIdle(page);
      await page.locator('#connectionMode').selectOption('vpn-compat');
      const separatePreferences=(await get('/api/onboarding')).onboarding.preferences;
      check(`${name}: external VPN hides takeover without replacing saved imported/VPS choices`, !await page.locator('#takeoverModeField').isVisible()&&separatePreferences.takeoverMode==='application'&&separatePreferences.relayRoutingMode==='smart'&&!await page.locator('#vpnConfirmed').isChecked());
      await page.locator('#connectionMode').selectOption('relay');await click('#refreshButton');
      check(`${name}: status refresh retains the selected VPS preference`, await page.locator('#takeoverMode').inputValue()==='smart');
      await page.reload({waitUntil:'domcontentloaded'});await screen(page,'configuration');
      check(`${name}: page reopen restores the VPS preference`, await page.locator('#takeoverMode').inputValue()==='smart');
      await page.locator('#connectionMode').selectOption('vpn-import');
      check(`${name}: page reopen restores the separate imported preference`, await page.locator('#takeoverMode').inputValue()==='application');
      const beforeRapid=count('/api/onboarding/preferences');preferenceDelayMs=250;
      for(const mode of ['smart','global','application'])await page.locator('#takeoverMode').selectOption(mode);
      check(`${name}: preference saves do not block editing or occupy global operations`, !await page.locator('#takeoverMode').isDisabled()&&await page.locator('#operationNotice').isHidden());
      await preferencesIdle(page);preferenceDelayMs=0;
      const rapidCalls=calls.filter(call=>call.path==='/api/onboarding/preferences'&&call.method==='POST').slice(beforeRapid);
      check(`${name}: rapid choices save in order and keep the other source preference`, JSON.stringify(rapidCalls.map(call=>call.takeoverMode))===JSON.stringify(['smart','global','application'])&&rapidCalls.every(call=>call.relayRoutingMode==='smart'));
      failPreferenceSave=true;await page.locator('#takeoverMode').selectOption('global');await preferencesIdle(page,true);await click('#refreshButton');
      check(`${name}: failed preference writes retain the draft across refresh and keep the saved value`, await page.locator('#takeoverMode').inputValue()==='global'&&(await get('/api/onboarding')).onboarding.preferences.takeoverMode==='application'&&/偏好保存失败/.test(await errorNotice(page).textContent()));
      failPreferenceSave=false;await page.locator('#takeoverMode').selectOption('smart');await preferencesIdle(page);
      check(`${name}: a later successful edit saves the retained choices and clears only its save error`, (await get('/api/onboarding')).onboarding.preferences.takeoverMode==='smart'&&!await errorNotice(page).isVisible());
      await page.locator('#connectionMode').selectOption('relay');
      await page.locator('#ispHost').fill('192.0.2.1'); await page.locator('#ispPort').fill('8080');
      await page.locator('#ispUsername').fill('ui-fixture-account'); await page.locator('#ispPassword').fill('not-a-real-isp-password');
      await click('#configurationSaveButton'); await click('#configurationContinueButton');
      await idle(page); await click('#environmentContinueButton');
      browserOptionsFixture=[{id:'chrome',label:'Chrome',available:false},{id:'edge',label:'Edge',available:true}];await click('#refreshButton');
      await page.waitForFunction(()=>document.querySelector('#browserChoice').value==='edge');
      check(`${name}: temporary browser fallback preserves the saved Chrome preference`, await page.locator('#browserChoice').inputValue()==='edge'&&(await get('/api/onboarding')).onboarding.preferences.browser==='chrome');
      await page.locator('#autoOptimize').uncheck();await preferencesIdle(page);
      check(`${name}: saving another preference cannot persist a temporary browser fallback`, (await get('/api/onboarding')).onboarding.preferences.browser==='chrome');
      browserOptionsFixture=null;await click('#refreshButton');
      await page.waitForFunction(()=>document.querySelector('#browserChoice').value==='chrome');
      check(`${name}: the preferred browser returns when detection recovers`, await page.locator('#browserChoice').inputValue()==='chrome');
      await page.locator('#browserChoice').selectOption('edge');await page.locator('#autoOptimize').uncheck();await page.locator('#freshProfile').uncheck();await preferencesIdle(page);
      const sessionPreferences=(await get('/api/onboarding')).onboarding;
      check(`${name}: session settings save before wizard completion without persisting confirmations`, sessionPreferences.preferences.browser==='edge'&&sessionPreferences.preferences.autoOptimize===false&&sessionPreferences.preferences.fresh===false&&sessionPreferences.firstRun===true&&!Object.hasOwn(sessionPreferences.preferences,'vpnConfirmed'));
      await page.locator('#autoOptimize').check();await page.locator('#freshProfile').check();await preferencesIdle(page);await click('#preferencesContinueButton');
      await click('#connectButton');
      check(`${name}: successful start with a busy snapshot does not report a connection failure`, !await errorNotice(page).isVisible() && (await get('/api/status')).proxy.running);
      const firstStart = calls.filter(call => call.method === 'POST' && call.path === '/api/proxy/start').at(-1);
      check(`${name}: disabled external reports are passed to connect without automatic probe fallback`, firstStart.externalReport === false && count('/api/probes/run') === 0);
    } else {
    await layout(page, viewport, '00-splash', { animated: true });
    await screen(page, 'configuration');
    check(`${name}: screen transitions are animated`, await page.locator('[data-screen="configuration"]').evaluate(element => getComputedStyle(element).animationName !== 'none'));
    check(`${name}: quality is hidden until configuration is saved`, !await page.locator('#qualityEntry').isVisible());
    check(`${name}: global repair is available before ISP setup`, await page.locator('#networkRepairButton').isVisible() && !await page.locator('#networkRepairButton').isDisabled());
    await click('#networkRepairButton');
    check(`${name}: cancelled desktop repair never claims restoration`, await page.evaluate(() => window.mcUiRepair.calls) === 1 && !/修复工具已启动|模拟修复完成|网络已恢复/.test(await page.locator('#toastStack').textContent()));
    const mutationsBeforeRepair = calls.filter(call => call.method === 'POST').length;
    await page.evaluate(() => { window.mcUiRepair.result = { launched: false, mock: true }; });
    await click('#networkRepairButton');
    check(`${name}: mock repair is explicit and performs no controller mutation`, await page.evaluate(() => window.mcUiRepair.calls) === 2 && /模拟修复完成，系统未更改/.test(await page.locator('#toastStack').textContent()) && calls.filter(call => call.method === 'POST').length === mutationsBeforeRepair);
    await page.locator('#ispHost').fill('192.0.2.1');
    await page.locator('#ispPort').fill('8080');
    await page.locator('#ispUsername').fill('ui-fixture-account');
    await page.locator('#ispPassword').fill('not-a-real-isp-password');
    await layout(page, viewport, '01-configuration');
    check(`${name}: mock relay is identified without claiming real connectivity`, /演示中转/.test(await page.locator('#relayOverviewTitle').textContent()) && !await page.locator('#configurationSaveButton').isDisabled());
    await click('#relayOverviewButton');
    const enrollment = { version: 1, type: 'mc-proxy-relay', host: '192.0.2.50', port: 443, tlsServerName: 'localhost', certificate: relayCertificate,
      certificateSha256: createHash('sha256').update(new X509Certificate(relayCertificate).raw).digest('hex').toUpperCase(), username: 'ui-relay-account', password: 'ui-relay-secret-never-render' };
    const relayFile = { name: 'relay.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(enrollment)) };
    await page.locator('#relayEnrollmentFile').setInputFiles(relayFile);
    await page.locator('#confirmModal').waitFor({ state: 'visible' });
    await click('#modalCancel');
    check(`${name}: cancelling relay import leaves the entry unchanged`, count('/api/relay/import') === 0 && await page.locator('#relayEnrollmentFile').inputValue() === '');
    await page.locator('#relayEnrollmentFile').setInputFiles(relayFile);
    await page.locator('#confirmModal').waitFor({ state: 'visible' });
    await click('#modalConfirm');
    check(`${name}: relay import preserves unsaved ISP fields and clears the file input`, await page.locator('#ispHost').inputValue() === '192.0.2.1' && await page.locator('#ispPassword').inputValue() === 'not-a-real-isp-password' && await page.locator('#relayEnrollmentFile').inputValue() === '');
    check(`${name}: relay remains saved when offline export fails, with an actionable notice`, (await get('/api/onboarding')).relay.configured && /中转配置已保存，但离线诊断包未更新/.test(await errorNotice(page).textContent()) && /诊断与恢复/.test(await page.locator('#diagnosticsExportResult').textContent()));
    check(`${name}: relay credentials are never rendered`, !(await page.locator('body').textContent()).includes(enrollment.password) && !(await page.locator('body').textContent()).includes(enrollment.username));
    await click('#relayCheckButton');
    check(`${name}: relay check describes entry-only mock verification`, /模拟入口检测/.test(await page.locator('#relayCheckResult').textContent()) && count('/api/relay/check') === 1);
    await layout(page, viewport, '01-relay-settings', { overlay: true });
    const advancedDoneBounds=await page.locator('#advancedDoneButton').boundingBox();
    check(`${name}: advanced settings completion stays reachable in the drawer`, advancedDoneBounds&&advancedDoneBounds.y+advancedDoneBounds.height<=height);
    await leaveTools();
    await click('#configurationSaveButton');
    await page.locator('#qualityCheckButton').waitFor({ state: 'visible' });
    check(`${name}: password is cleared after save`, await page.locator('#ispPassword').inputValue() === '');
    check(`${name}: saved configuration replaces the form`, await page.locator('#savedConfiguration').isVisible() && !await page.locator('#configurationForm').isVisible());
    check(`${name}: ISP save succeeds while offline export failure stays explicit`, (await get('/api/onboarding')).configuration.available && /ISP 配置已保存，但离线诊断包未更新/.test(await errorNotice(page).textContent()));
    failAutomaticDiagnostics = false;
    await layout(page, viewport, '01-saved-configuration');
    await click('#qualityCheckButton');
    await page.locator('[data-drawer="quality"]').waitFor({ state: 'visible' });
    const links = await page.locator('#qualityReports a').evaluateAll(items => items.map(item => ({ href: item.href, text: item.textContent })));
    const reports = links.filter(link => new URL(link.href).origin === locationOrigin(origin) && new URL(link.href).pathname.startsWith('/reports/quality/'));
    assert.equal(reports.length, 3, 'each quality source must have a local report URL');
    for (const link of reports) {
      const response = await context.request.get(link.href);
      assert.equal(response.status(), 200);
      assert.match(await response.text(), /模拟报告/);
    }
    check(`${name}: quality has a score of at most 100 and three working report links`, Number(await page.locator('#qualityScore').textContent()) <= 100 && reports.length === 3);
    await capture(page, `${name}-quality-reports.png`);
    await leaveTools();
    await page.locator('#configurationContinueButton').click();
    await page.locator('#checkRing[data-state="checking"]').waitFor({ state: 'visible' });
    check(`${name}: the circular environment loader animates`, await page.locator('#checkRing > svg').evaluate(element => getComputedStyle(element).animationName === 'spin'));
    await layout(page, viewport, '02-environment-checking', { animated: true });
    await idle(page);
    await page.locator('#checkRing[data-state="done"]').waitFor({ state: 'visible' });
    check(`${name}: first visit checks and backs up automatically`, environmentChecks === 1 && Boolean((await get('/api/onboarding')).environment.backup));
    await layout(page, viewport, '02-environment-ready');
    await click('#environmentContinueButton');
    await screen(page, 'preferences');
    await layout(page, viewport, '03-preferences');

    await click('#openBrowserCleanupButton');
    await page.locator('input[name="cleanupItem"][value="browserCookies"]').check();
    await click('#cleanupPreviewButton');
    await click('#cleanupApplyButton');
    await page.locator('#confirmModal').waitFor({ state: 'visible' });
    await layout(page, viewport, '03-browser-confirmation', { overlay: true });
    await click('#modalCancel');
    check(`${name}: browser cleanup cancellation never applies deletion`, count('/api/cleanup/preview') === 1 && count('/api/cleanup/apply') === 0);
    await leaveTools();
    await click('#openClaudeCleanupButton');
    await click('#claudePreviewButton');
    await click('#claudeApplyButton');
    await page.locator('#confirmModal').waitFor({ state: 'visible' });
    await layout(page, viewport, '03-claude-confirmation', { overlay: true });
    await click('#modalCancel');
    check(`${name}: Claude cleanup cancellation never applies deletion`, count('/api/claude/cleanup-plan') === 1 && count('/api/claude/cleanup') === 0);
    await leaveTools();
    await click('#preferencesContinueButton');
    await screen(page, 'connection');
    check(`${name}: completed setup opens connection with always-visible workspace navigation`, await page.locator('#screen-connection').isVisible() && await page.locator('#workspaceNav').isVisible());
    await openGroup('#openApplicationProxyButton');
    check(`${name}: application entry is a complete page before connecting and does not launch automatically`, await page.locator('#screen-applications').isVisible() && await page.locator('#workspaceNav').isVisible() && !await page.locator('#drawerBackdrop').isVisible() && await page.locator('[data-application="claude-desktop"]').isDisabled() && (await page.evaluate(()=>window.mcUiApplications.calls)).length===0);
    await layout(page, viewport, '04-applications-idle');
    await leaveTools();
    await openGroup('#openDiagnosticsButton');
    check(`${name}: recovery is a complete page with persistent workspace navigation`, await page.locator('#screen-diagnostics').isVisible() && await page.locator('#workspaceNav').isVisible() && !await page.locator('#drawerBackdrop').isVisible() && !await page.locator('#diagnosticsNetworkRepairButton').isDisabled());
    await layout(page, viewport, '04-diagnostics-idle');
    await leaveTools();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    check(`${name}: reduced-motion preference disables screen animation`, await page.locator('[data-screen="connection"]').evaluate(element => getComputedStyle(element).animationName === 'none'));
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await layout(page, viewport, '04-connection-idle');
    check(`${name}: connection shows the complete planned route`, /本机 TUN/.test(await page.locator('#connectionChain').textContent()) && /ISP 出口/.test(await page.locator('#connectionChain').textContent()));
    await auditRouteVisibility(page,check,name);
    await auditIdleMutations(page,check,name);
    check(`${name}: footer back buttons retain their SVG icons`,await page.locator('#applicationsBackButton svg,#diagnosticsBackButton svg,#licenseBackButton svg,#adminBackButton svg').count()===4);
    await click('#openProtectionButton');
    check(`${name}: manual lock is unavailable before connecting`, await page.locator('#networkLockButton').isDisabled());
    await openGroup('#openDiagnosticsButton');
    await click('#exportDiagnosticsButton');
    check(`${name}: mock diagnostic export never claims real files were written`, /未写入真实诊断包/.test(await page.locator('#diagnosticsExportResult').textContent()) && count('/api/diagnostics/export') === 1);
    await leaveTools();

    failOptimization = true;
    await click('#connectButton');
    const failedEnvironment = await get('/api/status');
    assert.equal(failedEnvironment.proxy.running, true, 'mock proxy itself should remain connected');
    assert.equal(failedEnvironment.environment.optimization.status, 'failed');
    await page.locator('#connectionWarning').waitFor({ state: 'visible' });
    check(`${name}: connected proxy and failed environment are clearly distinguished`, /环境/.test(await page.locator('#connectionWarningTitle').textContent()) && (await page.locator('#connectionWarningText').textContent()).trim().length > 0);
    await layout(page, viewport, '04-environment-warning');
    await click('#connectionWarningDetails');
    await page.locator('#screen-diagnostics').waitFor({ state: 'visible' });
    check(`${name}: failure details remain available`, /未完成|失败|异常|应用/.test(await page.locator('#environmentSummary').textContent()));
    await leaveTools();await click('#openProtectionButton');
    check(`${name}: connecting never enables the network lock`, !(await get('/api/status')).networkLock.locked && !await page.locator('#networkLockButton').isDisabled());
    await click('#networkLockButton');
    await click('#modalCancel');
    check(`${name}: cancelling manual lock leaves networking unlocked`, count('/api/network-lock/arm') === 0 && !(await get('/api/status')).networkLock.locked);
    await click('#networkLockButton');
    await click('#modalConfirm');
    check(`${name}: manual lock confirms and rechecks the connected session`, (await get('/api/status')).networkLock.locked && (await get('/api/status')).proxy.running && count('/api/network-lock/arm') === 1);
    await leaveTools();
    await click('#connectButton');
    await click('#modalCancel');
    check(`${name}: cancelled disconnect keeps the mock session`, count('/api/session/end') === 0 && (await get('/api/status')).proxy.running);
    await click('#connectButton');
    await click('#modalConfirm');
    check(`${name}: ending a session retains the mock kill switch`, !(await get('/api/status')).proxy.running && (await get('/api/status')).networkLock.locked);
    await click('#openProtectionButton');
    await click('#networkUnlockButton');
    await click('#modalCancel');
    check(`${name}: cancelling unlock keeps the kill switch`, count('/api/network-lock/unlock') === 0);
    await click('#networkUnlockButton');
    await click('#modalConfirm');
    await leaveTools();

    const beforeReloadChecks = environmentChecks;
    const originalBackup = (await get('/api/onboarding')).environment.backup.id;
    await reopenEnvironment();
    await page.locator('#backupChoice').waitFor({ state: 'visible' });
    check(`${name}: saved ISP reopens connection and explicit environment review waits for backup choice without automatic mutation`, environmentChecks === beforeReloadChecks);
    await layout(page, viewport, '02-existing-backup-choice');
    await click('#reuseBackupButton');
    check(`${name}: reuse preserves the original backup ID`, (await get('/api/onboarding')).environment.backup.id === originalBackup);
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    await screen(page, 'connection');
    check(`${name}: the environment warning survives navigation and reload`, await page.locator('#connectionWarning').isVisible());
    const beforeRebackupChecks = environmentChecks;
    await reopenEnvironment();
    await page.locator('#backupChoice').waitFor({ state: 'visible' });
    failEnvironmentCheck = true;
    await click('#reuseBackupButton');
    check(`${name}: failed copied-snapshot check keeps refresh available and prevents advancing`, await page.locator('#refreshBackupButton').isVisible() && !await page.locator('#refreshBackupButton').isDisabled() && await page.locator('#environmentContinueButton').isDisabled() && await page.locator('#checkRing').getAttribute('data-state') === 'error');
    await layout(page, viewport, '02-environment-failed-refresh');
    const beforeRefreshRequests = count('/api/environment/check');
    await click('#refreshBackupButton');
    await layout(page, viewport, '02-rebackup-confirmation', { overlay: true });
    await click('#modalCancel');
    check(`${name}: cancelled rebackup preserves the baseline`, environmentChecks === beforeRebackupChecks && count('/api/environment/check') === beforeRefreshRequests && (await get('/api/onboarding')).environment.backup.id === originalBackup);
    await click('#refreshBackupButton');
    await click('#modalConfirm');
    const rebuilt = (await get('/api/onboarding')).environment;
    const rebuildCall = calls.filter(call => call.method === 'POST' && call.path === '/api/environment/check').at(-1);
    check(`${name}: confirmed rebackup explicitly creates a new baseline`, rebuilt.backup.id !== originalBackup && rebuilt.ownership === 'matched' && rebuildCall.refreshBackup === true && rebuildCall.rebuildBackup === true && rebuildCall.confirm === true);
    check(`${name}: rebuilding after a failed check enables the next step`, !await page.locator('#environmentContinueButton').isDisabled() && await page.locator('#checkRing').getAttribute('data-state') === 'done');
    await layout(page, viewport, '02-rebuilt-local-snapshot');
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    await screen(page, 'connection');

    // Simulate ownership metadata only; no copied snapshot, Windows adapter,
    // native restore or real user directory is involved in these UI fixtures.
    environmentFixture = 'foreign';
    await reopenEnvironment();
    check(`${name}: foreign snapshot cannot advance or restore and offers local refresh`, await page.locator('#environmentContinueButton').isDisabled()
      && (!await page.locator('#reuseBackupButton').isVisible() || await page.locator('#reuseBackupButton').isDisabled())
      && (!await page.locator('#environmentRecoveryButton').isVisible() || await page.locator('#environmentRecoveryButton').isDisabled())
      && await page.locator('#environmentOriginalRestoreButton').isDisabled()
      && await page.locator('#refreshBackupButton').isVisible() && !await page.locator('#refreshBackupButton').isDisabled());
    await layout(page, viewport, '02-foreign-snapshot');
    environmentFixture = 'unbound';
    await click('#refreshButton');
    check(`${name}: legacy snapshot without ownership cannot be reused or restored`, await page.locator('#environmentContinueButton').isDisabled()
      && (!await page.locator('#reuseBackupButton').isVisible() || await page.locator('#reuseBackupButton').isDisabled())
      && (!await page.locator('#environmentRecoveryButton').isVisible() || await page.locator('#environmentRecoveryButton').isDisabled())
      && !await page.locator('#refreshBackupButton').isDisabled());
    await layout(page, viewport, '02-unbound-snapshot');
    const beforeOwnedRebuild = (await get('/api/onboarding')).environment.backup.id;
    await click('#refreshBackupButton');
    await click('#modalConfirm');
    const ownedRebuild = (await get('/api/onboarding')).environment;
    check(`${name}: confirmed rebuild replaces an unbound UI snapshot with a matched baseline`, ownedRebuild.ownership === 'matched' && ownedRebuild.backup.id !== beforeOwnedRebuild && !await page.locator('#environmentContinueButton').isDisabled() && count('/api/environment/restore') === 0);
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    await screen(page, 'connection');

    // This fixture tests error presentation only. Filesystem recovery and real
    // Windows language-list serialization have separate backend regressions.
    const beforeLiveSnapshotBackup = (await get('/api/onboarding')).environment.backup.id;
    const beforeLiveSnapshotChecks = environmentChecks;
    failLiveSnapshot = true; environmentFixture = 'live-invalid';
    await reopenEnvironment();
    await layout(page, viewport, '02-live-snapshot-invalid');
    await click('#refreshBackupButton');
    await click('#modalConfirm');
    const liveFailureText = (await errorNotice(page).textContent()) + (await page.locator('#backupChoiceText').textContent());
    check(`${name}: invalid live snapshot describes local reading failure instead of a damaged old record`, /本机环境/.test(liveFailureText) && !/环境恢复记录无效|旧恢复记录无法使用/.test(liveFailureText) && /读取/.test(await page.locator('#environmentMessage').textContent()) && await page.locator('#environmentContinueButton').isDisabled());
    check(`${name}: failed live refresh preserves the previous baseline and keeps retry available`, environmentChecks === beforeLiveSnapshotChecks && (await get('/api/onboarding')).environment.backup.id === beforeLiveSnapshotBackup && await page.locator('#environmentRetryButton').isVisible() && !await page.locator('#refreshBackupButton').isDisabled());
    await layout(page, viewport, '02-live-snapshot-failed');
    await click('#environmentRetryButton');
    check(`${name}: repeated live reading failure never claims a new snapshot`, environmentChecks === beforeLiveSnapshotChecks && (await get('/api/onboarding')).environment.backup.id === beforeLiveSnapshotBackup && !/快照已刷新/.test(await page.locator('#environmentMessage').textContent()));
    await layout(page, viewport, '02-live-snapshot-retry-failed');
    failLiveSnapshot = false; environmentFixture = null;
    await click('#environmentRetryButton');
    check(`${name}: repaired live reading can continue without replacing the existing baseline`, !await page.locator('#environmentContinueButton').isDisabled() && (await get('/api/onboarding')).environment.backup.id === beforeLiveSnapshotBackup);
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    await screen(page, 'connection');
    failOptimization = false;
    await openGroup('#openEnvironmentPanelButton');await click('#environmentDailyTab');
    await click('#environmentCaptureDailyButton');await click('#environmentSaveProfilesButton');await leaveTools();
    await click('#connectButton');
    const beforeRestore = await get('/api/onboarding');
    check(`${name}: optimized environment exposes restore in connection actions`, beforeRestore.environment.backup.canRestore && await page.locator('#connectionEnvironmentRestoreButton').isVisible() && !await page.locator('#connectionEnvironmentRestoreButton').isDisabled());
    await openGroup('#openEnvironmentPanelButton');
    await click('#environmentDailyTab');
    check(`${name}: protection details offer a direct restore action`, await page.locator('#protectionEnvironmentRestoreButton').isVisible() && !await page.locator('#protectionEnvironmentRestoreButton').isDisabled());
    if(!await page.locator('.environment-advanced').evaluate(element=>element.open))await click('.environment-advanced > summary');
    check(`${name}: connected session disables current environment adoption`, await page.locator('#protectionEnvironmentAdoptButton').isVisible() && await page.locator('#protectionEnvironmentAdoptButton').isDisabled());
    await click('#protectionEnvironmentRestoreButton');
    check(`${name}: restore confirmation names the saved daily target and preserved completed items`, /时区/.test(await page.locator('#modalBody').textContent()) && /日常环境/.test(await page.locator('#modalBody').textContent()) && /成功项目保留/.test(await page.locator('#modalBody').textContent()));
    await click('#modalCancel');
    await leaveTools();
    const restoreRequests = count('/api/environment/restore'), cleanupRequests = count('/api/cleanup/apply');
    await click('#connectButton');
    await click('#modalConfirm');
    check(`${name}: disconnect retains matched environment and visible enabled restore action`, !(await get('/api/status')).proxy.running && (await get('/api/status')).environment.backup.canRestore && count('/api/environment/restore') === restoreRequests && !await page.locator('#connectionEnvironmentRestoreButton').isDisabled() && /恢复日常环境/.test(await page.locator('#connectionNote').textContent()) && /当前已匹配/.test(await page.locator('#environmentConnectionStatus').textContent()));
    await layout(page, viewport, '04-disconnected-restore');
    await click('#connectionEnvironmentRestoreButton');
    await layout(page, viewport, '04-restore-confirmation', { overlay: true });
    await click('#modalConfirm');
    const restored = await get('/api/onboarding');
    check(`${name}: confirmed restore keeps configuration, backup and browser data`, restored.environment.optimization.status === 'restored' && restored.environment.backup.id === beforeRestore.environment.backup.id && restored.environment.backup.canRestore && !restored.environment.backup.restoreNeeded && JSON.stringify(restored.configuration) === JSON.stringify(beforeRestore.configuration) && count('/api/environment/restore') === restoreRequests + 1 && count('/api/cleanup/apply') === cleanupRequests);
    check(`${name}: restored daily settings remain verified on connection screen`, /当前已匹配/.test(await page.locator('#environmentConnectionStatus').textContent()) && !await page.locator('#connectionEnvironmentRestoreButton').isDisabled());
    await layout(page, viewport, '04-environment-restored');

    const beforeAdopt = await get('/api/onboarding');
    const adoptRequests = count('/api/environment/adopt'), beforeAdoptRestores = count('/api/environment/restore');
    environmentFixture = 'pending'; pendingEnvironmentChecked = false;
    await reopenEnvironment();
    check(`${name}: old pending environment offers explicit adoption and keeps old restore`, await page.locator('#environmentAdoptButton').isVisible() && !await page.locator('#environmentAdoptButton').isDisabled() && await page.locator('#environmentRecoveryButton').isVisible() && !await page.locator('#environmentRecoveryButton').isDisabled() && count('/api/environment/adopt') === adoptRequests);
    await click('#reuseBackupButton');
    check(`${name}: valid live snapshot can continue despite pending old recovery`, !await page.locator('#environmentContinueButton').isDisabled() && /连接可继续/.test(await page.locator('#environmentMessage').textContent()) && await page.locator('#environmentAdoptButton').isVisible());
    await layout(page, viewport, '02-environment-pending');
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    check(`${name}: optional environment recovery does not disable connection preparation`, !await page.locator('#connectButton').isDisabled() && /连接可继续/.test(await page.locator('#connectionWarningText').textContent()));
    await openGroup('#openEnvironmentPanelButton');
    if(!await page.locator('.environment-advanced').evaluate(element=>element.open))await click('.environment-advanced > summary');
    check(`${name}: idle advanced recovery offers adoption beside original restoration`, !await page.locator('#protectionEnvironmentAdoptButton').isDisabled() && !await page.locator('#environmentOriginalRestoreButton').isDisabled());
    await click('#protectionEnvironmentAdoptButton');
    check(`${name}: adopt confirmation describes live fields and preserves Windows settings`, /当前时区：Taipei Standard Time/.test(await page.locator('#modalBody').textContent()) && /区域格式：zh-CN/.test(await page.locator('#modalBody').textContent()) && /归档旧恢复记录/.test(await page.locator('#modalBody').textContent()) && /Windows 设置不会被修改/.test(await page.locator('#modalBody').textContent()));
    await layout(page, viewport, '02-environment-adopt-confirmation', { overlay: true });
    await click('#modalCancel');
    check(`${name}: cancelled adoption keeps baseline and never restores old settings`, count('/api/environment/adopt') === adoptRequests && count('/api/environment/restore') === beforeAdoptRestores && (await get('/api/onboarding')).environment.backup.id === beforeAdopt.environment.backup.id);
    await leaveTools();
    await openGroup('#openEnvironmentPanelButton');
    await click('#openEnvironmentOptions');
    await click('#environmentAdoptButton');
    await click('#modalConfirm');
    const adopted = await get('/api/onboarding');
    const adoptCall = calls.filter(call => call.method === 'POST' && call.path === '/api/environment/adopt').at(-1);
    check(`${name}: confirmed adoption makes a new current baseline and preserves preferences`, adopted.environment.status === 'ready' && adopted.environment.backup.id !== beforeAdopt.environment.backup.id && adopted.environment.backup.canRestore && !adopted.environment.backup.restoreNeeded && JSON.stringify(adopted.environment.current) === JSON.stringify(beforeAdopt.environment.current) && JSON.stringify(adopted.configuration) === JSON.stringify(beforeAdopt.configuration) && adopted.onboarding.preferences.autoOptimize === beforeAdopt.onboarding.preferences.autoOptimize && adoptCall.confirm === true && count('/api/environment/adopt') === adoptRequests + 1 && count('/api/environment/restore') === beforeAdoptRestores);
    check(`${name}: adopted current baseline enables wizard continuation`, !await page.locator('#environmentContinueButton').isDisabled() && await page.locator('#checkRing').getAttribute('data-state') === 'done' && !await page.locator('#environmentAdoptButton').isVisible());
    await layout(page, viewport, '02-environment-adopted');
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');

    browserOptionsFixture = [{ id: 'chrome', label: 'Chrome', available: false }, { id: 'edge', label: 'Edge', available: true }];
    await click('#refreshButton');
    await click('#returnPreferencesButton');
    check(`${name}: missing saved Chrome visibly selects available Edge`, await page.locator('#browserChoice').inputValue() === 'edge' && /Chrome.*Edge/.test(await page.locator('#browserAvailabilityHint').textContent()) && await page.locator('#browserChoice option[value="chrome"]').isDisabled() && !await page.locator('#browserChoice option[value="edge"]').isDisabled());
    await layout(page, viewport, '03-available-edge');
    await click('#preferencesContinueButton');
    check(`${name}: temporary Edge fallback preserves the saved Chrome preference before launch`, (await get('/api/onboarding')).onboarding.preferences.browser === 'chrome' && /Edge/.test(await page.locator('#safeAccessLabel').textContent()));
    await click('#connectButton');
    browserOptionsFixture = [{ id: 'chrome', label: 'Chrome', available: false }, { id: 'edge', label: 'Edge', available: false }];
    await click('#refreshButton');
    await click('#returnPreferencesButton');
    check(`${name}: missing official browsers give rescan guidance and retain explicit optional-engine selection`, /重新识别.*指定.*路径/.test(await page.locator('#browserAvailabilityHint').textContent()) && await page.locator('#browserChoice option[value="chrome"]').isDisabled() && await page.locator('#browserChoice option[value="edge"]').isDisabled() && !await page.locator('#browserChoice option[value="fingerprint"]').isDisabled());
    await click('#preferencesContinueButton');
    check(`${name}: connected proxy cannot launch an unavailable browser`, (await get('/api/status')).proxy.running && await page.locator('#safeAccessButton').isDisabled() && /未找到浏览器/.test(await page.locator('#safeAccessLabel').textContent()));
    }
    browserOptionsFixture = [{ id: 'chrome', label: 'Chrome', available: true }, { id: 'edge', label: 'Edge', available: true }];
    await click('#refreshButton');
    browserSessionFixture = true;
    const visibleLaunchBrowser=await page.locator('#browserChoice').inputValue();
    await click('#safeAccessButton');
    check(`${name}: safe access defaults to the exit page in the visible selected browser`, ['chrome','edge'].includes(visibleLaunchBrowser) && calls.filter(call => call.method === 'POST' && call.path === '/api/browser/plan').at(-1)?.browser === visibleLaunchBrowser && calls.filter(call => call.path === '/api/browser/plan').at(-1)?.service === 'exit');
    await click('#workspaceApplicationButton');
    check(`${name}: application page exposes only fixed website shortcut IDs`, JSON.stringify(await page.locator('[data-website]').evaluateAll(buttons => buttons.map(button => button.dataset.website))) === JSON.stringify(['exit','google','wikipedia','github','youtube','chatgpt','claude']));
    check(`${name}: running independent browser disables new website launch until explicitly closed`, await page.locator('[data-website="google"]').isDisabled() && !await page.locator('#browserCloseButton').isDisabled() && /关闭后.*新入口/.test(await page.locator('#websiteLaunchStatus').textContent()));
    await click('#browserCloseButton'); await click('#modalConfirm');
    assert.equal(await page.locator('[data-website="google"]').isDisabled(), false, 'closed mock browser must reenable website buttons');
    const [googlePlan] = await Promise.all([page.waitForResponse(response => new URL(response.url()).pathname === '/api/browser/plan' && response.request().method() === 'POST'), click('[data-website="google"]')]);
    const googlePlanData = (await googlePlan.json()).data;
    check(`${name}: Google shortcut plans its fixed official URL without visiting it in the renderer`, googlePlanData.service === 'google' && googlePlanData.url === 'https://www.google.com/' && calls.filter(call => call.path === '/api/browser/plan').at(-1)?.service === 'google');
    await click('#browserCloseButton'); await click('#modalConfirm');
    const [exitPlan] = await Promise.all([page.waitForResponse(response => new URL(response.url()).pathname === '/api/browser/plan' && response.request().method() === 'POST'), click('[data-website="exit"]')]);
    const exitPlanData = (await exitPlan.json()).data;
    check(`${name}: exit shortcut displays the IP endpoint instead of choosing a service website`, exitPlanData.service === 'exit' && exitPlanData.url === 'https://api.ipify.org/');
    await click('#browserCloseButton'); await click('#modalConfirm');
    browserOptionsFixture = [{ id: 'chrome', label: 'Chrome', available: false }, { id: 'edge', label: 'Edge', available: true }];
    await click('#refreshButton');
    const beforeManualPath = await page.evaluate(() => ({ selected: document.querySelector('#applicationBrowserChoice').value, unavailableChrome: document.querySelector('#applicationBrowserChoice option[value="chrome"]').disabled, manualChromeDisabled: document.querySelector('#browserPathKind option[value="chrome"]').disabled, manualSelectDisabled: document.querySelector('#browserPathKind').disabled }));
    check(`${name}: unavailable Chrome still permits explicitly selecting its manual installation kind`, beforeManualPath.selected === 'edge' && beforeManualPath.unavailableChrome && !beforeManualPath.manualChromeDisabled && !beforeManualPath.manualSelectDisabled, beforeManualPath);
    const browserPath = path.join(runtimeRoot, 'fixture-browser', 'chrome.exe');
    await page.locator('.browser-path-options summary').click();
    await page.locator('#browserPathKind').selectOption('chrome');
    await page.locator('#browserExecutablePath').fill(browserPath); await click('#setBrowserPathButton');
    const setPathCall = calls.filter(call => call.path === '/api/browsers/path').at(-1);
    check(`${name}: manual Chrome path is independent of prior Edge preference and uses explicit confirmation only in mock`, setPathCall.browser === 'chrome' && setPathCall.executable === browserPath && setPathCall.confirm === true && await page.locator('#browserExecutablePath').inputValue() === '' && await page.locator('#applicationBrowserChoice').inputValue() === 'chrome' && (await get('/api/status')).service.mock === true);
    await click('#clearBrowserPathButton');
    check(`${name}: clearing the browser path explicitly restores automatic discovery`, calls.filter(call => call.path === '/api/browsers/path').at(-1)?.executable === null);
    await click('#rescanBrowsersButton');
    check(`${name}: browser rescan is explicit and mock never claims native detection`, count('/api/browsers/rescan') === 1 && /模拟浏览器识别完成/.test(await page.locator('#toastStack').textContent()));
    await auditStableNodes(page,check,`${name}: browser profile archive options`,['#browserProfileArchiveChoice option']);
    await layout(page, viewport, '04-applications-websites');
    await leaveTools();
    if (selectedScenario === 'workspace-pages') {
      await settle(page);
      const navLayout = await page.locator('#workspaceNav button').evaluateAll(buttons => buttons.map(button => {
        const bounds = button.getBoundingClientRect();
        const hit = document.elementFromPoint(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
        return { id: button.id, reachable: !button.disabled && button.tabIndex >= 0, unobstructed: hit === button || button.contains(hit), inViewport: bounds.width > 0 && bounds.height > 0 && bounds.x >= 0 && bounds.y >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight };
      }));
      check(`${name}: workspace navigation remains in view and unobstructed by the header`, JSON.stringify(navLayout.map(item=>item.id)) === JSON.stringify(['workspaceConnectionButton','workspaceSpacesButton','workspaceApplicationButton','workspaceRecoveryButton']) && navLayout.every(item => item.reachable && item.unobstructed && item.inViewport), navLayout);
      await page.locator('#workspaceConnectionButton').focus();
      await page.keyboard.press('Tab');
      check(`${name}: user environments are keyboard reachable before applications`, await page.locator('#workspaceSpacesButton').evaluate(button => document.activeElement === button && getComputedStyle(button).outlineStyle !== 'none' && parseFloat(getComputedStyle(button).outlineWidth) >= 2));
      await page.keyboard.press('Tab');
      check(`${name}: application navigation is keyboard reachable with a visible focus indicator`, await page.locator('#workspaceApplicationButton').evaluate(button => document.activeElement === button && getComputedStyle(button).outlineStyle !== 'none' && parseFloat(getComputedStyle(button).outlineWidth) >= 2));
      await page.keyboard.press('Tab');
      check(`${name}: diagnostics follows applications in the keyboard navigation order`, await page.locator('#workspaceRecoveryButton').evaluate(button => document.activeElement === button));
      const beforeQuickNavigation = { launches: await page.evaluate(() => window.mcUiApplications.calls.length), starts: count('/api/proxy/start'), stops: count('/api/proxy/stop'), ends: count('/api/session/end'), probes: count('/api/probes') };
      for (const selector of ['#quickClaudeButton', '#quickCodexButton', '#allApplicationsButton', '#routeApplicationsButton']) {
        await click(selector);
        check(`${name}: ${selector} opens application controls without launching or stopping a connection`, await page.locator('#screen-applications').isVisible() && await page.evaluate(() => window.mcUiApplications.calls.length) === beforeQuickNavigation.launches && count('/api/proxy/start') === beforeQuickNavigation.starts && count('/api/proxy/stop') === beforeQuickNavigation.stops && count('/api/session/end') === beforeQuickNavigation.ends && count('/api/probes') === beforeQuickNavigation.probes && (await get('/api/status')).proxy.running);
        await leaveTools();
      }
      const darkContrast = await page.evaluate(() => {
        const rgb = color => /^#[\da-f]{6}$/i.test(color) ? [1, 3, 5].map(index => parseInt(color.slice(index, index + 2), 16)) : color.match(/[\d.]+/g)?.slice(0, 3).map(Number);
        const luminance = color => rgb(color)?.map(channel => { const value = channel / 255; return value <= .04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4; }).reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
        const contrast = (foreground, background) => { const left = luminance(foreground), right = luminance(background); return Number.isFinite(left) && Number.isFinite(right) ? (Math.max(left, right) + .05) / (Math.min(left, right) + .05) : 0; };
        const rootStyle = getComputedStyle(document.documentElement);
        const rootInk = getComputedStyle(document.body).color;
        const paper = rootStyle.getPropertyValue('--paper').trim();
        return { dark: getComputedStyle(document.documentElement).colorScheme.includes('dark'), body: contrast(rootInk, paper), navigation: [...document.querySelectorAll('#workspaceNav button')].map(button => ({ id: button.id, ratio: contrast(getComputedStyle(button).color, button.hasAttribute('aria-current') ? getComputedStyle(button).backgroundColor : paper) })) };
      });
      check(`${name}: dark workspace text and navigation retain basic readable contrast`, darkContrast.dark && darkContrast.body >= 4.5 && darkContrast.navigation.every(item => item.ratio >= 4.5), darkContrast);
      await page.emulateMedia({ reducedMotion: 'reduce' });
      const reducedMotion = await page.evaluate(() => ({ running: document.querySelector('#appFrame').getAnimations({ subtree: true }).filter(animation => animation.playState === 'running').length, route: getComputedStyle(document.querySelector('.route-signal')).animationName }));
      check(`${name}: reduced motion stops decorative route and workspace animations`, reducedMotion.running === 0 && reducedMotion.route === 'none', reducedMotion);
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      await page.waitForFunction(() => document.fonts.status === 'loaded');
      check(`${name}: new local theme, font and Earth assets load without CSP violations`, cosmosResourcePaths.every(resource => cosmosResources.get(resource) === 200) && await page.evaluate(() => window.mcUiCspViolations.length) === 0, { resources: Object.fromEntries(cosmosResources), cspViolations: await page.evaluate(() => window.mcUiCspViolations) });
      await click('#workspaceApplicationButton');
      const beforeObservationProbes=count('/api/probes');
      await click('#refreshConnectionsButton');
      await page.waitForFunction(()=>/模拟记录|暂无连接|未提供记录/.test(document.querySelector('#connectionsSummary').textContent));
      await page.locator('#observeConnections').check();
      check(`${name}: connection observation is local and does not launch service probes`,count('/api/probes')===beforeObservationProbes&&await page.locator('#observeConnections').isChecked());
      check(`${name}: focused Codex Desktop is blocked while its safe close and simulated CLI launch remain available`, await page.locator('[data-application="codex-desktop"]').isDisabled() && !await page.locator('[data-application="codex-cli"]').isDisabled() && !await page.locator('[data-stop-application="codex-desktop"]').isDisabled() && await page.locator('[data-stop-application="codex-cli"]').isDisabled() && /安全退出/.test(await page.locator('.application-row').filter({has:page.locator('[data-application="codex-desktop"]')}).textContent()));
      const beforeChecks = count('/api/applications/check');
      await click('#applicationAdvanced > summary');
      check(`${name}: advanced application tools expand explicitly without new network probes`, await page.locator('#applicationAdvanced').getAttribute('open') !== null && count('/api/applications/check') === beforeChecks && count('/api/probes') === beforeObservationProbes);
      await click('[data-application-check="claude"][data-path="proxy"]');
      await click('[data-application-check="codex"][data-path="proxy"]');
      check(`${name}: fixed application checks use only their service and proxy scope without launches`, count('/api/applications/check') === beforeChecks + 2 && JSON.stringify(calls.filter(call => call.path === '/api/applications/check').map(call => [call.service,call.targetPath])) === JSON.stringify([['claude','proxy'],['codex','proxy']]) && /MOCKED|模拟/.test(await page.locator('#applicationNetworkResult').textContent()) && (await page.evaluate(()=>window.mcUiApplications.calls)).length === 0);
      await page.evaluate(()=>{window.mcUiApplications.stopCancelled=true;});
      await click('[data-stop-application="codex-desktop"]');
      check(`${name}: native close cancellation keeps the app running without a renderer confirmation`, (await page.evaluate(()=>window.mcUiApplications.codexRunning)) === true && !await page.locator('#confirmModal').isVisible() && !await page.locator('[data-stop-application="codex-desktop"]').isDisabled());
      await page.evaluate(()=>{window.mcUiApplications.stopCancelled=false;window.mcUiApplications.stopFailure=true;});
      await click('[data-stop-application="codex-desktop"]');
      check(`${name}: busy app close preserves running state and explains that no force kill occurred`, (await page.evaluate(()=>window.mcUiApplications.codexRunning)) === true && /未强制结束/.test(await errorNotice(page).textContent()) && await page.locator('[data-application="codex-desktop"]').isDisabled());
      await page.evaluate(()=>{window.mcUiApplications.stopFailure=false;});
      await click('[data-stop-application="codex-desktop"]');
      check(`${name}: successful app close reenables launch and disables close without touching network state`, (await page.evaluate(()=>window.mcUiApplications.codexRunning)) === false && !await page.locator('[data-application="codex-desktop"]').isDisabled() && await page.locator('[data-stop-application="codex-desktop"]').isDisabled() && (await get('/api/status')).proxy.running && /模拟退出完成/.test(await page.locator('#applicationLaunchStatus').textContent()));
      await click('[data-application="codex-cli"]');
      check(`${name}: focused Codex CLI launch uses its own ID without claiming a Desktop restart`, JSON.stringify(await page.evaluate(()=>window.mcUiApplications.calls)) === JSON.stringify(['codex-cli']) && /模拟启动完成/.test(await page.locator('#applicationLaunchStatus').textContent()) && !/Codex 桌面窗口已提交启动/.test(await page.locator('#applicationLaunchStatus').textContent()));
      await layout(page, viewport, '04-applications-codex');
      await page.locator('#applicationsContent').evaluate(element => { element.scrollTop = 0; });
      await capture(page, `${name}-04-applications-overview.png`);
      check(`${name}: native application entry precedes website shortcuts and desktop entries lead the list`, await page.locator('#applicationProxySettings').evaluate(element => Boolean(element.compareDocumentPosition(document.querySelector('.browser-launch-section')) & Node.DOCUMENT_POSITION_FOLLOWING)) && JSON.stringify(await page.locator('.application-row [data-application]').evaluateAll(buttons => buttons.slice(0,2).map(button => button.dataset.application))) === JSON.stringify(['claude-desktop','codex-desktop']));
      if (width <= 520 && height <= 710) check(`${name}: first desktop action remains above the fixed footer with notices visible`, await page.locator('[data-application="claude-desktop"]').evaluate(button => { const action=button.getBoundingClientRect(), content=document.querySelector('#applicationsContent').getBoundingClientRect();return action.top>=content.top && action.bottom<=content.bottom; }));
      await page.locator('#workspaceApplicationButton').hover();
      check(`${name}: current navigation stays readable on hover`, await page.locator('#workspaceApplicationButton').evaluate(element => { const style=getComputedStyle(element);return style.color!==style.backgroundColor; }));
      await page.emulateMedia({ reducedMotion: 'reduce' });
      check(`${name}: reduced motion suppresses page and panel animations`, await page.locator('#screen-applications').evaluate(element => element.getAnimations({subtree:true}).every(animation => animation.playState !== 'running')));
      await page.emulateMedia({ reducedMotion: 'no-preference' });
      for (const coverage of [
        {mode:'http',systemExitVerified:false,killSwitch:false,systemProtected:false},
        {mode:'tun',systemExitVerified:false,killSwitch:false,systemProtected:false},
      ]) {
        applicationCoverageFixture = coverage; await click('#refreshButton');
        await page.waitForFunction(()=>document.querySelector('[data-application="claude-code"]').disabled);
        check(`${name}: ${coverage.mode} lock=${coverage.killSwitch} coverage=${coverage.systemProtected} cannot authorize OAuth app launch`, await page.locator('[data-application="claude-code"]').isDisabled() && await page.locator('[data-application="codex-cli"]').isDisabled() && !await page.locator('[data-application="terminal"]').isDisabled() && await page.locator('[data-application-check="claude"][data-path="system"]').isDisabled());
      }
      applicationCoverageFixture = {mode:'tun',systemExitVerified:true,killSwitch:true,systemProtected:true}; await click('#refreshButton');
      await page.waitForFunction(()=>!document.querySelector('[data-application="claude-code"]').disabled);
      check(`${name}: verified active TUN with optional lock enables launch and system-target checks`, !await page.locator('[data-application="claude-code"]').isDisabled() && !await page.locator('[data-application-check="claude"][data-path="system"]').isDisabled());
      applicationCoverageFixture = {mode:'tun',systemExitVerified:true,killSwitch:false,systemProtected:false}; await click('#refreshButton');
      await page.waitForFunction(()=>!document.querySelector('[data-application="claude-code"]').disabled);
      check(`${name}: unlocked verified TUN enables desktop and CLI launch without claiming a persistent lock`, !await page.locator('[data-application="claude-desktop"]').isDisabled() && !await page.locator('[data-application="claude-code"]').isDisabled() && !await page.locator('[data-application-check="claude"][data-path="system"]').isDisabled() && /断网锁未开启.*恢复直连/.test(await page.locator('#applicationScopeHint').textContent()));
      await click('#applicationProtectionButton');
      check(`${name}: application protection action opens the complete diagnostics page`, await page.locator('#screen-diagnostics').isVisible() && !await page.locator('#drawerBackdrop').isVisible());
      check(`${name}: diagnostics retain the last public application failure with its code`, /APPLICATION_CLOSE_TIMEOUT/.test(await page.locator('#diagnosticsFailureDetails').textContent()));
      const beforeLog = calls.length; await click('#openClientLogButton');
      const logRequests = calls.slice(beforeLog);
      check(`${name}: the fixed client log action triggers no new chain or network probe`, (await page.evaluate(()=>window.mcUiApplications.logCalls)) === 1 && logRequests.every(call => call.method === 'GET' && ['/api/snapshot', '/api/status', '/api/connections', '/api/reminders'].includes(call.path)), { logCalls: await page.evaluate(()=>window.mcUiApplications.logCalls), requests: logRequests });
      applicationCoverageFixture = null; await click('#refreshButton'); await leaveTools();
      await click('#workspaceRecoveryButton');
      check(`${name}: leaving app records pauses automatic observation`,!await page.locator('#observeConnections').isChecked());
      await click('#previewDiagnosticSummaryButton');
      const share=await page.locator('#diagnosticShareText').inputValue();
      check(`${name}: share preview excludes addresses and private paths without uploading`,await page.locator('#diagnosticSharePreview').isVisible()&&JSON.parse(share).product==='MC Proxy'&&!/127\.0\.0\.1|203\.0|https?:|private/.test(share));
      await layout(page, viewport, '04-diagnostics-page');
      await page.locator('#diagnosticsContent').evaluate(element => { element.scrollTop = 0; });
      await capture(page, `${name}-04-diagnostics-overview.png`);
      await leaveTools();
      await click('#safeQuitButton');
      check(`${name}: safe software quit uses the native lifecycle without immediate network API mutation`, (await page.evaluate(()=>window.mcUiApplications.quitCalls)) === 1 && (await get('/api/status')).proxy.running);
      check(`${name}: focused pages have no renderer errors or external requests`, pageErrors.length === 0 && blocked.length === 0, { pageErrors, blocked });
      finishScenario({ size: name, name: 'workspace-pages', calls, rendererErrors: pageErrors, blockedOrigins: blocked }, checkStart); return;
    }
    await click('#connectButton');
    await click('#modalConfirm');
    browserOptionsFixture = null;
    systemNetworkFixture = 'unverified';
    await click('#refreshButton');
    // Status refresh does not show the operation notice used by click()/idle().
    // Wait for its rendered state instead of inspecting the preceding fixture.
    await page.waitForFunction(() => document.querySelector('#safeAccessButton').disabled && /重新验证/.test(document.querySelector('#connectionTitle').textContent), null, { timeout: 10000 }).catch(cause => { if (cause.name !== 'TimeoutError') throw cause; });
    const unverifiedNetworkView = await page.evaluate(() => ({ disabled: document.querySelector('#safeAccessButton').disabled, title: document.querySelector('#connectionTitle').textContent, detail: document.querySelector('#connectionDetail').textContent }));
    check(`${name}: local-proxy-only TUN status cannot enable safe browser access`, unverifiedNetworkView.disabled && /重新验证/.test(unverifiedNetworkView.title), unverifiedNetworkView);
    systemNetworkFixture = 'verified';
    await click('#refreshButton');
    await page.waitForFunction(() => !document.querySelector('#safeAccessButton').disabled && /系统默认网络出口已核验/.test(document.querySelector('#connectionDetail').textContent), null, { timeout: 10000 }).catch(cause => { if (cause.name !== 'TimeoutError') throw cause; });
    const verifiedNetworkView = await page.evaluate(() => ({ disabled: document.querySelector('#safeAccessButton').disabled, title: document.querySelector('#connectionTitle').textContent, detail: document.querySelector('#connectionDetail').textContent }));
    check(`${name}: verified default-network exit is stated without claiming every app`, !verifiedNetworkView.disabled && /系统默认网络出口已核验/.test(verifiedNetworkView.detail), verifiedNetworkView);
    systemNetworkFixture = null;
    await click('#refreshButton');
    const savedRelay = (await get('/api/onboarding')).relay;
    const relayChecksBeforeCompat = count('/api/relay/check');
    await click('#editIspButton');
    check(`${name}: existing connections retain the default relay mode`, await page.locator('#connectionMode').inputValue()==='relay');
    await page.locator('#connectionMode').selectOption('vpn-compat');
    await click('#advancedConfigButton');
    check(`${name}: selecting compatibility hides relay settings and requires VPN confirmation`, !await page.locator('#relaySettings').isVisible()&&await page.locator('#vpnConfirmed').isVisible()&&!await page.locator('#vpnConfirmed').isChecked()&&await page.locator('#configurationSaveButton').isDisabled());
    await page.locator('#vpnConfirmed').check();
    await page.locator('#vpnProxyType').selectOption('http');
    check(`${name}: a manual VPN proxy needs a valid local port`, await page.locator('#configurationSaveButton').isDisabled());
    await page.locator('#vpnProxyPort').fill('443');
    check(`${name}: manual candidates reject privileged ports`, await page.locator('#configurationSaveButton').isDisabled());
    await page.locator('#vpnProxyPort').fill('7890');
    await layout(page, viewport, '01-vpn-compatible-settings', { overlay: true });
    check(`${name}: compatibility exposes process-local HTTP proxy examples`, /127\.0\.0\.1/.test(await page.locator('#localProxyAddress').inputValue())&&/\$env:HTTP_PROXY/.test(await page.locator('#terminalProxyExample').textContent())&&/\$env:HTTPS_PROXY/.test(await page.locator('#terminalProxyExample').textContent())&&/当前终端/.test(await page.locator('#applicationProxySettings').textContent()));
    await click('#advancedDoneButton');
    check(`${name}: changing connection mode requires save before continuing`, await page.locator('#configurationContinueButton').isDisabled()&&await page.locator('#configurationForm').isVisible());
    failModeSave = true;
    await click('#configurationSaveButton');
    check(`${name}: failed compatibility verification preserves the saved mode and enrollment`, (await get('/api/onboarding')).configuration.connectionMode!=='vpn-compat'&&(await get('/api/onboarding')).relay.host===savedRelay.host&&/saved mode preserved/.test(await errorNotice(page).textContent()));
    failModeSave = false;
    await click('#configurationSaveButton');
    const compatConfiguration = await get('/api/onboarding');
    check(`${name}: compatibility saves explicitly without replacing the relay enrollment`, compatConfiguration.configuration.connectionMode==='vpn-compat'&&compatConfiguration.relay.host===savedRelay.host&&calls.filter(call=>call.path==='/api/configuration/save').at(-1)?.vpnConfirmed===true&&calls.filter(call=>call.path==='/api/configuration/save').at(-1)?.vpnProxy?.port===7890);
    await layout(page, viewport, '01-vpn-compatible-saved');
    await click('#relayOverviewButton');
    await page.locator('#vpnProxyType').selectOption('socks');
    await leaveTools();
    await click('#qualityCheckButton');
    const manualQuality=calls.filter(call=>call.path==='/api/quality/check').at(-1);
    check(`${name}: quality detection forwards a manual SOCKS5 candidate without repeating VPN consent`, manualQuality?.vpnProxy?.type==='socks'&&manualQuality.vpnProxy.host==='127.0.0.1'&&manualQuality.vpnProxy.port===7890&&!Object.hasOwn(manualQuality,'vpnConfirmed'));
    await leaveTools();
    await click('#configurationContinueButton');
    await click('#reuseBackupButton');
    await click('#environmentContinueButton');
    await click('#preferencesContinueButton');
    await screen(page,'connection');
    check(`${name}: compatibility visibly requires the external VPN and excludes VPS`, /外部 VPN/.test(await page.locator('#connectionChain').textContent())&&!/VPS/.test(await page.locator('#connectionChain').textContent())&&/不经 VPS/.test(await page.locator('#connectionDetail').textContent())&&await page.locator('#openProxySettingsButton').isVisible());
    await click('#openProxySettingsButton');await click('#applicationConnectionSettingsButton');
    await page.locator('#vpnProxyType').selectOption('auto');
    check(`${name}: automatic selection has no manual port requirement`, !await page.locator('#vpnProxyPortField').isVisible());
    await leaveTools();
    await click('#connectButton');
    const compatibilityState = await get('/api/status');
    const compatStart = calls.filter(call=>call.path==='/api/proxy/start').at(-1);
    check(`${name}: compatibility starts only an explicitly confirmed HTTP session`, compatibilityState.proxy.running&&compatibilityState.proxy.mode==='http'&&compatibilityState.proxy.connectionMode==='vpn-compat'&&compatStart.mode==='http'&&compatStart.vpnConfirmed===true&&!Object.hasOwn(compatStart,'vpnProxy'));
    check(`${name}: compatible ISP verification enables safe access without system TUN claims`, !await page.locator('#safeAccessButton').isDisabled()&&/不经 VPS/.test(await page.locator('#connectionDetail').textContent())&&!/系统默认网络出口已核验/.test(await page.locator('#connectionDetail').textContent())&&count('/api/relay/check')===relayChecksBeforeCompat);
    await layout(page, viewport, '04-vpn-compatible-connected');
    await click('#openProtectionButton');
    check(`${name}: compatibility cannot arm the kill switch or claim system DNS capture`, await page.locator('#networkLockButton').isDisabled()&&/不接管系统 DNS/.test(await page.locator('#dnsStatus').textContent())&&/不代表全系统/.test(await page.locator('#networkScopeHint').textContent()));
    await leaveTools();
    await click('#openProxySettingsButton');
    check(`${name}: selected compatibility route is shown after exit verification`, /本次已选/.test(await page.locator('#vpnRouteStatus').textContent()));
    await click('#copyProxyAddressButton');
    // Clipboard writes are asynchronous and do not use the operation indicator.
    // Await their user-visible outcome instead of checking immediately after click.
    await page.waitForFunction(() => /已复制|已选中文字/.test(document.querySelector('#toastStack').textContent), null, { timeout: 10000 });
    const copiedAddress = await page.evaluate(() => { const input=document.querySelector('#localProxyAddress');return { notice:document.querySelector('#toastStack').textContent,selected:document.activeElement===input&&input.selectionStart===0&&input.selectionEnd===input.value.length,valueLength:input.value.length }; });
    check(`${name}: copying the address gives success or a selectable fallback`, /已复制/.test(copiedAddress.notice) || /已选中文字/.test(copiedAddress.notice) && copiedAddress.selected && copiedAddress.valueLength > 0, copiedAddress);
    await page.evaluate(() => { document.querySelector('#toastStack').replaceChildren();window.mcUiClipboardWrite=navigator.clipboard.writeText;Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async()=>{throw new DOMException('Mock clipboard denial','NotAllowedError');}}); });
    await click('#copyProxyAddressButton');
    await page.waitForFunction(() => /已选中文字/.test(document.querySelector('#toastStack').textContent), null, { timeout: 10000 });
    const selectedAddress = await page.locator('#localProxyAddress').evaluate(input => ({ focused:document.activeElement===input,start:input.selectionStart,end:input.selectionEnd,length:input.value.length }));
    check(`${name}: clipboard denial selects the complete address for manual copying`,selectedAddress.focused&&selectedAddress.start===0&&selectedAddress.end===selectedAddress.length&&selectedAddress.length>0,selectedAddress);
    await page.evaluate(() => { Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:window.mcUiClipboardWrite});delete window.mcUiClipboardWrite; });
    await leaveTools();
    await click('#connectButton');
    await click('#modalConfirm');
    await page.reload({waitUntil:'domcontentloaded'});
    await screen(page,'connection');
    check(`${name}: reloading compatibility preserves the mode but requires fresh VPN confirmation`, (await get('/api/onboarding')).configuration.connectionMode==='vpn-compat'&&await page.locator('#connectButton').isDisabled());

    await click('#settingsButton');
    check(`${name}: developer settings retain connection, environment, apps, diagnostics and both license tasks`, JSON.stringify(await page.locator('[data-drawer="settings"] .settings-group').evaluateAll(items=>items.map(item=>item.id)))===JSON.stringify(['openLicenseButton','openLicensingAdminButton','openConnectionSettingsButton','openEnvironmentPanelButton','openApplicationProxyButton','openDiagnosticsButton']));
    await layout(page,viewport,'06-settings-groups',{overlay:true});
    await click('#openConnectionSettingsButton');
    check(`${name}: connection mode is visible in the first step`, await page.locator('#connectionMode').isVisible()&&await page.locator('#connectionMode option[value="vpn-import"]').count()===1);
    await page.locator('#connectionMode').selectOption('vpn-import');
    check(`${name}: imported mode cannot be saved without supported local nodes`, await page.locator('#configurationSaveButton').isDisabled()&&await page.locator('#configurationContinueButton').isDisabled());
    await click('#vpnImportOverviewButton');
    check(`${name}: imported configuration excludes external VPN consent and VPS settings`, await page.locator('#vpnImportSettings').isVisible()&&!await page.locator('#vpnConfirmed').isVisible()&&!await page.locator('#relaySettings').isVisible());
    const importBefore=count('/api/vpn/import'),probeBeforeImport=count('/api/vpn/check')+count('/api/quality/check')+count('/api/relay/check')+count('/api/proxy/start');
    const yamlFile=text=>({name:'local-config.yaml',mimeType:'application/yaml',buffer:Buffer.from(text)});
    await page.locator('#vpnConfigFile').setInputFiles(yamlFile(''));
    await errorNotice(page).filter({hasText:'内容为空'}).waitFor({state:'visible'});
    check(`${name}: empty YAML is rejected locally`, count('/api/vpn/import')===importBefore&&/内容为空/.test(await errorNotice(page).textContent()));
    await auditDrawerError(page,check,name,/内容为空/);
    await page.locator('#vpnConfigFile').setInputFiles(yamlFile('x'.repeat(1048577)));
    check(`${name}: oversized YAML is rejected before submission`, count('/api/vpn/import')===importBefore&&/1 MiB/.test(await errorNotice(page).textContent()));
    await page.locator('#vpnConfigFile').setInputFiles(yamlFile('proxies: [ invalid'));
    await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: invalid YAML never creates a profile`, !(await get('/api/vpn/config')).available&&await page.locator('#configurationSaveButton').isDisabled());
    const vpnNode={name:'UI local Reality',type:'vless',server:'127.0.0.1',port:443,uuid:'11111111-2222-4333-8444-555555555555',network:'tcp',tls:true,servername:'localhost',flow:'xtls-rprx-vision','client-fingerprint':'chrome','reality-opts':{'public-key':Buffer.from(Array.from({length:32},(_,index)=>index+1)).toString('base64url'),'short-id':'0123456789abcdef'}};
    const shareUri='vless://11111111-2222-4333-8444-555555555555@127.0.0.1:443?security=none&type=tcp#UI%20Share';
    await click('#vpnPasteToggleButton');await page.locator('#vpnConfigText').fill(shareUri);await click('#vpnPasteImportButton');await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: pasted sharing links are locally recognized and cleared after import`, (await get('/api/vpn/config')).format==='share-uri'&&await page.locator('#vpnConfigText').inputValue()===''&&/分享链接/.test(await page.locator('#vpnConfigSummary').textContent()));
    await auditStableNodes(page,check,`${name}: imported node selector`,['#vpnNodeChoice option'],{focus:'#vpnNodeChoice'});
    check(`${name}: public node options show only safe protocol and transport labels`, /VLESS.*TCP/.test(await page.locator('#vpnNodeChoice option[value="1"]').textContent())&&!(await page.locator('body').textContent()).includes(shareUri));
    const genericFile=(name,text)=>({name,mimeType:'text/plain',buffer:Buffer.from(text)});
    await page.locator('#vpnConfigFile').setInputFiles(genericFile('local-config.json',JSON.stringify({outbounds:[{type:'vless',tag:'UI JSON',server:'127.0.0.1',server_port:443,uuid:vpnNode.uuid}]})));await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: sing-box JSON files are automatically recognized`, (await get('/api/vpn/config')).format==='sing-box'&&/sing-box JSON/.test(await page.locator('#vpnConfigSummary').textContent()));
    await page.locator('#vpnConfigFile').setInputFiles(genericFile('local-config.txt',Buffer.from(shareUri).toString('base64')));await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: Base64 subscription text is parsed locally without download`, (await get('/api/vpn/config')).format==='base64-subscription'&&blocked.length===0);
    await page.locator('#vpnConfigFile').setInputFiles(genericFile('local-config.conf','[Proxy]\nUI HTTP = http, 127.0.0.1, 8080, username=fixture, password=fixture\n'));await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    const beforeUrlImport=await get('/api/vpn/config');
    check(`${name}: Surge config files are recognized and expose protocol metadata`, beforeUrlImport.format==='surge-ini'&&beforeUrlImport.nodes[0].protocol==='http'&&beforeUrlImport.nodes[0].transport==='tcp');
    await page.locator('#vpnConfigText').fill('https://must-never-download.invalid/subscription');await click('#vpnPasteImportButton');await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: plain remote URLs are never fetched and preserve the saved profile`, (await get('/api/vpn/config')).id===beforeUrlImport.id&&blocked.length===0);
    await page.locator('#vpnConfigText').fill('汉'.repeat(350000));
    const beforeLargePaste=count('/api/vpn/import');await click('#vpnPasteImportButton');
    check(`${name}: pasted UTF-8 size is checked before local submission`, count('/api/vpn/import')===beforeLargePaste&&/1 MiB/.test(await errorNotice(page).textContent()));
    await page.locator('#vpnConfigText').fill('');await click('#vpnPasteToggleButton');
    const importedFile=yamlFile(JSON.stringify({proxies:[vpnNode,{...vpnNode,name:'UI Reality 2',port:8443},{...vpnNode,name:'UI Reality 3',port:9443},{name:'unsupported fixture',type:'unsupported-test',server:'192.0.2.19',port:443,password:'ui-import-secret-never-render'}],rules:['MATCH,DIRECT'],'proxy-providers':{ignored:{url:'https://must-never-download.invalid/subscription'}}}));
    await page.locator('#vpnConfigFile').setInputFiles(importedFile);await page.locator('#confirmModal').waitFor({state:'visible'});
    check(`${name}: import confirmation limits parsing to the local file`, /仅在本机/.test(await page.locator('#modalBody').textContent())&&/不探测外网/.test(await page.locator('#modalBody').textContent()));
    await click('#modalCancel');
    check(`${name}: import cancellation keeps the previous local profile`, (await get('/api/vpn/config')).id===beforeUrlImport.id);
    await page.locator('#vpnConfigFile').setInputFiles(importedFile);await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    const imported=await get('/api/vpn/config');
    check(`${name}: partial YAML exposes supported and unsupported counts with original node indices`, imported.available&&imported.total===4&&imported.supported===3&&imported.unsupported===1&&imported.nodes[0].index===1&&imported.selectedIndex===null&&/支持 3 \/ 4/.test(await page.locator('#vpnConfigSummary').textContent()));
    check(`${name}: partial import identifies unsupported node indices and reasons`, /节点 4：协议不支持/.test(await page.locator('#vpnImportIssues').textContent())&&/VPN_NODE_TYPE_UNSUPPORTED/.test(await page.locator('#vpnImportIssues').textContent()));
    check(`${name}: importing a new route invalidates the previous local quality result`, !await page.locator('#qualityResultButton').isVisible());
    check(`${name}: import never runs chain checks or downloads YAML links`, probeBeforeImport===count('/api/vpn/check')+count('/api/quality/check')+count('/api/relay/check')+count('/api/proxy/start')&&blocked.length===0);
    check(`${name}: imported secrets and server fields are never displayed`, !(await page.locator('body').textContent()).includes(vpnNode.uuid)&&!(await page.locator('body').textContent()).includes('ui-import-secret-never-render')&&!JSON.stringify(imported).includes('server'));
    await page.locator('#vpnConfigFile').setInputFiles(yamlFile('proxies: []'));await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: unusable replacement preserves the saved imported profile`, (await get('/api/vpn/config')).id===imported.id&&await page.locator('#vpnNodeChoice option').count()===4);
    await page.locator('#vpnConfigFile').setInputFiles(yamlFile(JSON.stringify({proxies:[{type:'unsupported-test',name:'unsupported',password:'ui-rejected-secret-never-render'}]})));await page.locator('#confirmModal').waitFor({state:'visible'});await click('#modalConfirm');
    check(`${name}: failed unsupported import reports safe reasons while retaining old summary`, (await get('/api/vpn/config')).id===imported.id&&/支持 3 \/ 4/.test(await page.locator('#vpnConfigSummary').textContent())&&/旧配置保留/.test(await page.locator('#vpnImportIssues').textContent())&&/节点 1：协议不支持/.test(await page.locator('#vpnImportIssues').textContent())&&!(await page.locator('body').textContent()).includes('ui-rejected-secret-never-render'));
    await page.locator('#vpnNodeChoice').selectOption('1');await idle(page);
    check(`${name}: an explicit node selection saves locally and requires validation`, (await get('/api/vpn/config')).selectedIndex===1&&await page.locator('#vpnChainCheckButton').isDisabled());
    await page.locator('#vpnNodeChoice').selectOption('auto');await idle(page);
    check(`${name}: automatic mode is a persisted connection-time selection`, (await get('/api/vpn/config')).selectedIndex===null&&/最快者/.test(await page.locator('#vpnNodeChoice option[value="auto"]').textContent()));
    await layout(page,viewport,'06-import-settings',{overlay:true});
    await click('#advancedDoneButton');
    await layout(page,viewport,'06-import-unsaved');
    check(`${name}: imported mode changes require save before wizard or connection`, await page.locator('#configurationContinueButton').isDisabled()&&await page.locator('#connectButton').isDisabled());
    await click('#configurationSaveButton');
    const importSave=calls.filter(call=>call.path==='/api/configuration/save').at(-1);
    check(`${name}: imported mode saves without external VPN consent or candidate and keeps ISP credentials`, (await get('/api/onboarding')).configuration.connectionMode==='vpn-import'&&importSave.connectionMode==='vpn-import'&&!Object.hasOwn(importSave,'vpnConfirmed')&&!Object.hasOwn(importSave,'vpnProxy')&&(await get('/api/onboarding')).configuration.credentialsConfigured);
    await click('#vpnImportOverviewButton');await page.locator('#vpnLatencyButton').focus();await page.keyboard.press('Enter');await idle(page);
    check(`${name}: a keyboard-started import drawer action restores focus after completion`,await page.locator('#vpnLatencyButton').evaluate(button=>document.activeElement===button));
    await leaveTools();
    await page.locator('#takeoverMode').selectOption('global');
    check(`${name}: imported global capture is visible beside configuration and does not dirty saved ISP`,await page.locator('#takeoverModeField').isVisible()&&!await page.locator('#configurationContinueButton').isDisabled()&&await page.locator('#takeoverMode').inputValue()==='global');
    await page.locator('#takeoverMode').selectOption('application');
    await click('#vpnImportOverviewButton');
    const actualMockLatency=(await get('/api/status')).vpnLatency;
    check(`${name}: explicit node latency uses full mocked chains without invented timings`, count('/api/vpn/latency')===1&&actualMockLatency.scope==='node-isp-https'&&actualMockLatency.total===3&&actualMockLatency.results.every(row=>row.latencyMs===null)&&/未测量真实延迟/.test(await page.locator('#vpnLatencySummary').textContent())&&!/\d+ ms/.test(await page.locator('#vpnLatencyResults').textContent()));
    latencyFixture={profileId:(await get('/api/vpn/config')).id,status:'partial',phase:'verifying',scope:'node-isp-https',candidateCount:43,shortlistSize:3,shortlistedNodeIndices:[1,2,3],verifiedEligible:2,screening:{scope:'local-tcp-connect',durationMs:700,screened:43,total:43,results:[],complete:true},observedAt:new Date().toISOString(),results:[{nodeIndex:1,status:'verified',latencyMs:230},{nodeIndex:2,status:'verified',latencyMs:51}],recommendedNodeIndex:2,tested:2,total:3,stale:false};
    await leaveTools();await click('#refreshButton');await click('#vpnImportOverviewButton');
    check(`${name}: measured latency rows rank the fastest tested node first`, (await page.locator('#vpnLatencyResults .vpn-latency-row strong').allTextContents())[0]==='节点 2'&&/已测通最快：节点 2（51 ms）/.test(await page.locator('#vpnLatencySummary').textContent()));
    check(`${name}: untested nodes are excluded from ranking and budget is explained`, /未测 · 不参与排名/.test(await page.locator('#vpnLatencyResults .vpn-latency-row').filter({hasText:'节点 3'}).textContent())&&/时间预算/.test(await page.locator('#vpnLatencySummary').textContent()));
    check(`${name}: TCP screening is separate from full ISP shortlist`,/TCP 轻筛 43 \/ 43/.test(await page.locator('#vpnScreeningSummary').textContent())&&/最多 3/.test(await page.locator('#vpnScreeningSummary').textContent())&&await page.locator('#vpnLatencyResults .vpn-latency-row').count()===3);
    await page.locator('#vpnLatencyResults').scrollIntoViewIfNeeded();
    await layout(page,viewport,'07-latency-ranking',{overlay:true});
    latencyFixture={...latencyFixture,status:'failed',results:[{nodeIndex:1,status:'failed',latencyMs:null,errorCode:'VPN_NODE_RESOLVE_FAILED'},{nodeIndex:2,status:'failed',latencyMs:null,errorCode:'SETUP_CHECK_FAILED'}],recommendedNodeIndex:null};
    await leaveTools();await click('#refreshButton');await click('#vpnImportOverviewButton');
    check(`${name}: latency failures show safe error codes without a winner`, /VPN_NODE_RESOLVE_FAILED/.test(await page.locator('#vpnLatencyResults').textContent())&&/SETUP_CHECK_FAILED/.test(await page.locator('#vpnLatencyResults').textContent())&&!/已测通最快/.test(await page.locator('#vpnLatencySummary').textContent()));
    latencyFixture={...latencyFixture,status:'complete',results:[{nodeIndex:1,status:'verified',latencyMs:10}],recommendedNodeIndex:1,stale:true};
    await leaveTools();await click('#refreshButton');await click('#vpnImportOverviewButton');
    check(`${name}: expired measurements do not claim a current fastest node`, /已过期/.test(await page.locator('#vpnLatencySummary').textContent())&&!/已测通最快/.test(await page.locator('#vpnLatencySummary').textContent())&&await page.locator('#vpnLatencyResults [data-recommended="true"]').count()===0);
    latencyFixture=null;await leaveTools();await click('#refreshButton');await click('#vpnImportOverviewButton');
    await page.locator('#vpnNodeChoice').selectOption('1');await idle(page);await click('#advancedDoneButton');await click('#configurationSaveButton');await click('#vpnImportOverviewButton');await click('#vpnLatencyButton');
    check(`${name}: manual node latency contacts only the chosen node`, (await get('/api/status')).vpnLatency.total===1&&(await get('/api/status')).vpnLatency.results.every(row=>row.nodeIndex===1));
    await click('#vpnChainCheckButton');
    check(`${name}: imported chain verification is explicit and identifies the successful node`, count('/api/vpn/check')===1&&/模拟/.test(await page.locator('#vpnCheckResult').textContent())&&/节点 1/.test(await page.locator('#vpnCheckResult').textContent()));
    await leaveTools();await click('#configurationContinueButton');await click('#reuseBackupButton');await click('#environmentContinueButton');await click('#preferencesContinueButton');
    check(`${name}: imported mode is connectable without external VPN checkbox`, !await page.locator('#connectButton').isDisabled()&&/导入节点/.test(await page.locator('#connectionChain').textContent())&&/无需(?:开启|启动)外部 VPN/.test(await page.locator('#connectionDetail').textContent()));
    await click('#connectButton');
    const importedState=await get('/api/status'),importStart=calls.filter(call=>call.path==='/api/proxy/start').at(-1);
    check(`${name}: imported mode starts only HTTP using its own route`, importedState.proxy.running&&importedState.proxy.mode==='http'&&importedState.proxy.connectionMode==='vpn-import'&&importedState.proxy.compatibility.strategy==='imported-node'&&importStart.mode==='http'&&!Object.hasOwn(importStart,'vpnConfirmed')&&!Object.hasOwn(importStart,'vpnProxy'));
    await layout(page,viewport,'06-import-connected');await click('#openProtectionButton');
    check(`${name}: imported mode cannot arm a lock or claim system capture`, await page.locator('#networkLockButton').isDisabled()&&/未接管全系统/.test(await page.locator('#networkScopeHint').textContent()));await leaveTools();await click('#openProxySettingsButton');
    check(`${name}: imported route identifies the winning node and process-local application setup`, /导入节点 1/.test(await page.locator('#vpnRouteStatus').textContent())&&/当前终端/.test(await page.locator('#applicationProxySettings').textContent())&&/HTTP_PROXY/.test(await page.locator('#terminalProxyExample').textContent()));
    await page.locator('[data-application="claude-desktop"]').waitFor({state:'visible'});
    check(`${name}: desktop and CLI are distinct one-click application targets`,await page.locator('[data-application="claude-desktop"]').count()===1&&await page.locator('[data-application="claude-code"]').count()===1&&await page.locator('[data-application="codex-desktop"]').count()===1&&await page.locator('[data-application="codex-cli"]').count()===1);
    check(`${name}: running Codex Desktop clearly blocks proxy restart while its CLI stays launchable in simulation`,await page.locator('[data-application="codex-desktop"]').isDisabled()&&!await page.locator('[data-application="codex-cli"]').isDisabled()&&/正在运行.*安全退出/.test(await page.locator('.application-row').filter({has:page.locator('[data-application="codex-desktop"]')}).textContent()));
    await page.locator('[data-application="claude-desktop"]').focus();
    await page.waitForTimeout(1200);
    check(`${name}: periodic control updates preserve application keyboard focus`, await page.locator('[data-application="claude-desktop"]').evaluate(button=>document.activeElement===button));
    await click('[data-application="claude-desktop"]');await click('[data-application="codex-cli"]');await click('[data-application="terminal"]');
    check(`${name}: application buttons use fixed IPC targets and CLI never claims Desktop launch`,JSON.stringify(await page.evaluate(()=>window.mcUiApplications.calls))===JSON.stringify(['claude-desktop','codex-cli','terminal'])&&/模拟启动完成/.test(await page.locator('#applicationLaunchStatus').textContent())&&!/Codex 桌面窗口已提交启动/.test(await page.locator('#applicationLaunchStatus').textContent()));
    await page.evaluate(()=>{window.mcUiApplications.running=true;});await click('#refreshApplicationsButton');
    check(`${name}: already running Desktop offers safe close before proxy restart`,await page.locator('[data-application="claude-desktop"]').isDisabled()&&!await page.locator('[data-stop-application="claude-desktop"]').isDisabled()&&/安全退出/.test(await page.locator('#applicationList').textContent()));
    await page.evaluate(()=>{window.mcUiApplications.fail=true;});await click('[data-application="claude-code"]');
    check(`${name}: failed fresh proxy verification is visible`,/出口未核验/.test(await errorNotice(page).textContent()));
    await page.evaluate(()=>{window.mcUiApplications.running=false;window.mcUiApplications.fail=false;});await click('#refreshApplicationsButton');
    await layout(page,viewport,'06-import-application-proxy');await leaveTools();await click('#connectButton');await click('#modalConfirm');
    await click('#openProxySettingsButton');
    check(`${name}: disconnected application launches stay disabled`,await page.locator('[data-application="claude-code"]').isDisabled()&&await page.locator('[data-application="terminal"]').isDisabled());await leaveTools();
    compatibilityFixture={strategy:'imported-node',status:'failed',attempts:[{nodeIndex:1,status:'failed',errorCode:'VPN_NODE_RESOLVE_FAILED'},{nodeIndex:2,status:'failed',errorCode:'SETUP_CHECK_FAILED'}]};await click('#refreshButton');await openGroup('#openDiagnosticsButton');
    check(`${name}: diagnostics show each failed node without claiming success`, /节点 1：节点地址解析失败/.test(await page.locator('#vpnDiagnosticsResult').textContent())&&/节点 2：双出口核验失败/.test(await page.locator('#vpnDiagnosticsResult').textContent())&&!/已通过/.test(await page.locator('#vpnDiagnosticsResult').textContent()));
    await layout(page,viewport,'06-import-failure-diagnostics');await leaveTools();compatibilityFixture=null;
    await page.reload({waitUntil:'domcontentloaded'});await screen(page,'connection');
    check(`${name}: imported mode and chosen node persist and require no external consent after reload`, (await get('/api/onboarding')).configuration.connectionMode==='vpn-import'&&(await get('/api/vpn/config')).selectedIndex===1&&!await page.locator('#connectButton').isDisabled());
    startupRecoveryRequired = true;
    await page.reload({ waitUntil: 'domcontentloaded' });
    await screen(page, 'configuration');
    check(`${name}: startup recovery keeps global repair accessible while ordinary setup is blocked`, !await page.locator('#networkRepairButton').isDisabled() && await page.locator('#configurationSaveButton').isDisabled() && /startup recovery required/.test(await errorNotice(page).textContent()));
    await click('#networkRepairButton');
    check(`${name}: repair cancellation during startup recovery leaves recovery unresolved`, await page.evaluate(() => window.mcUiRepair.calls) === 1 && /startup recovery required/.test(await errorNotice(page).textContent()) && !/修复工具已启动|模拟修复完成|网络已恢复/.test(await page.locator('#toastStack').textContent()));
    startupRecoveryRequired = false;
    await page.reload({ waitUntil: 'domcontentloaded' });await screen(page,'connection');
    await click('#workspaceSpacesButton');await screen(page,'workspaces');
    serviceUnavailable = true;await click('#refreshButton');
    check(`${name}: offline user environments retain refresh and return navigation`,!await page.locator('#experienceRefresh').isDisabled()&&!await page.locator('#experienceConnection').isDisabled()&&await page.locator('#workspaceNew').isDisabled());
    await click('#experienceConnection');await screen(page,'connection');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.locator('#retryButton').waitFor({ state: 'visible' });
    check(`${name}: failed local service leaves global repair visible and enabled on splash`, await page.locator('#networkRepairButton').isVisible() && !await page.locator('#networkRepairButton').isDisabled() && /本地服务未连接/.test(await page.locator('#serviceStatus').textContent()));
    await page.evaluate(() => { window.mcUiRepair.result = { launched: false, mock: true }; });
    await click('#networkRepairButton');
    check(`${name}: repair uses desktop bridge while local service is unavailable`, await page.evaluate(() => window.mcUiRepair.calls) === 1 && /模拟修复完成，系统未更改/.test(await page.locator('#toastStack').textContent()));
    await layout(page, viewport, '05-offline-repair');
    check(`${name}: no renderer errors`, pageErrors.length === 0, pageErrors);
    check(`${name}: all frontend modules and local assets are served`,assetFailures.length===0,assetFailures);
    check(`${name}: no external browser requests`, blocked.length === 0, blocked);
    finishScenario({ size: name, calls, rendererErrors: pageErrors, blockedOrigins: blocked }, checkStart);
  } catch (cause) {
    const message = `${name}: ${cause.stack || cause.message}`;
    report.errors.push(message);
    finishScenario({ size: name, calls, rendererErrors: pageErrors, assetFailures, blockedOrigins: blocked }, checkStart, false);
    await capture(page, `${name}-failure.png`).catch(() => {});
    console.error(message);
  } finally {
    startRelease?.();cleanupRelease?.();checkRelease?.();
    await context.close();
    await controller.shutdown();
  }
}

const locationOrigin = value => new URL(value).origin;

async function splashRepairRace(browser) {
  const name = 'splash-repair-race', events = [], pageErrors = [], blocked = [], mutations = [];
  const checkStart = report.checks.length;
  const runtimeRoot = path.join(directory, 'mock-runtime-splash-repair-race');
  const controller = await startController({ host: '127.0.0.1', port: 0, mock: true, requireRelay: true, healthIntervalMs: 0,
    runtimeRoot, configPath: path.join(runtimeRoot, 'config.json'), secretsPath: path.join(runtimeRoot, 'fixture.secrets.env') });
  const origin = `http://127.0.0.1:${controller.address().port}`;
  const context = await browser.newContext({ viewport: { width: 380, height: 650 }, locale: 'zh-CN', serviceWorkers: 'block', extraHTTPHeaders: controller.controlHeaders() });
  let firstStatus = true, firstStatusFinished;
  const delayedStatus = new Promise(resolve => { firstStatusFinished = resolve; });
  await context.addInitScript(({version}) => {
    window.mcUiRepairRace = { calls: 0, enteredAt: null, releasedAt: null, release: null };
    window.mcDesktop = Object.freeze({ isDesktop: true, minimize: async () => {}, close: async () => {}, quit: async () => {},
      getInfo: async () => ({ name: 'MC Proxy', version, mock: true, closeBehavior: 'tray' }),
      repairNetwork: async () => {
        window.mcUiRepairRace.calls++; window.mcUiRepairRace.enteredAt = Date.now();
        await new Promise(resolve => { window.mcUiRepairRace.release = resolve; });
        window.mcUiRepairRace.releasedAt = Date.now(); return { cancelled: true };
      } });
  }, {version:applicationVersion});
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) { blocked.push(url.origin); await route.abort(); return; }
    if (url.pathname.startsWith('/api/') && request.method() !== 'GET') mutations.push(url.pathname);
    if (['/api/status', '/api/snapshot'].includes(url.pathname) && firstStatus) {
      firstStatus = false; events.push({ event: 'initial-status-started', at: Date.now() });
      try {
        const response = await route.fetch(); await delay(500);
        await route.fulfill({ response });
      } catch (cause) {
        // The action invalidates and aborts this deliberately delayed request.
        events.push({ event: 'initial-status-aborted', at: Date.now(), expected: true });
      } finally {
        events.push({ event: 'initial-status-delay-finished', at: Date.now() }); firstStatusFinished();
      }
      return;
    }
    if (['/api/status', '/api/snapshot'].includes(url.pathname)) events.push({ event: 'fresh-status-requested', at: Date.now() });
    await route.continue();
  });
  const page = await context.newPage(); page.setDefaultTimeout(10000);
  page.on('pageerror', cause => pageErrors.push(cause.message));
  page.on('requestfailed', request => {
    if (['/api/status', '/api/snapshot'].includes(new URL(request.url()).pathname)) events.push({ event: 'status-request-failed', at: Date.now(), failure: request.failure()?.errorText });
  });
  try {
    const baseline = await context.request.get(`${origin}/api/status`);
    assert.equal((await baseline.json()).data.service.mock, true);
    await page.goto(origin, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => document.querySelector('#networkRepairButton')?.hidden === false);
    assert.equal(firstStatus, false, 'initial status must be in flight before repair');
    assert.ok(!events.some(event => event.event === 'initial-status-delay-finished'), 'repair must begin before initial response completes');
    await page.locator('#networkRepairButton').click();
    await page.waitForFunction(() => window.mcUiRepairRace.calls === 1);
    const enteredAt = await page.evaluate(() => window.mcUiRepairRace.enteredAt);
    events.push({ event: 'repair-entered', at: enteredAt });
    assert.ok(check(`${name}: repair truly overlaps the delayed initial status read`, enteredAt < events.find(event => event.event === 'initial-status-delay-finished')?.at || !events.some(event => event.event === 'initial-status-delay-finished')));
    await delayedStatus;
    await page.locator('#retryButton').waitFor({ state: 'visible' });
    assert.ok(check(`${name}: interrupted initialization exposes retry while pending repair keeps it disabled`, await page.locator('#screen-splash').isVisible() && await page.locator('#retryButton').isDisabled() && await page.locator('#operationNotice').isVisible()));
    await page.evaluate(() => window.mcUiRepairRace.release());
    await idle(page);
    await page.waitForFunction(() => document.querySelector('#retryButton')?.disabled === false);
    assert.ok(check(`${name}: repair cancellation leaves retry enabled and fresh service connected`, await page.locator('#retryButton').isVisible() && await page.locator('#serviceStatus').evaluate(element => element.classList.contains('service-online')) && !/未连接/.test(await page.locator('#serviceStatus').textContent())));
    assert.ok(check(`${name}: stale initialization does not hydrate a setup page or report restoration`, await page.locator('#screen-splash').isVisible() && /中断/.test(await page.locator('#splashStatus').textContent()) && !/网络已恢复|网络修复已完成/.test(await page.locator('#toastStack').textContent())));
    await capture(page, `${name}-retry.png`);
    await page.locator('#retryButton').click();
    await screen(page, 'configuration');
    assert.ok(check(`${name}: retry opens normal configuration and retains connected service`, await page.locator('#configurationForm').isVisible() && await page.locator('#serviceStatus').evaluate(element => element.classList.contains('service-online'))));
    await capture(page, `${name}-configuration.png`);
    assert.ok(check(`${name}: no renderer errors, external requests or controller mutations`, pageErrors.length === 0 && blocked.length === 0 && mutations.length === 0, { pageErrors, blocked, mutations }));
    finishScenario({ name, events, rendererErrors: pageErrors, blockedOrigins: blocked, mutations }, checkStart);
  } catch (cause) {
    report.errors.push(`${name}: ${cause.stack || cause.message}`);
    finishScenario({ name, events, rendererErrors: pageErrors, blockedOrigins: blocked, mutations }, checkStart, false);
    await capture(page, `${name}-failure.png`).catch(() => {});
  } finally { await context.close(); await controller.shutdown(); }
}

await mkdir(directory, { recursive: true });
let browser;
try {
  const { chromium } = loadPlaywright();
  const executablePath = await chromePath();
  browser = await chromium.launch({ executablePath, headless: true, args: ['--no-proxy-server', '--disable-quic', '--webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-background-networking'] });
  report.browser = { executablePath, version: browser.version() };
  if (selectedScenario !== 'splash-repair-race') for (const [width, height] of sizes) await scenario(browser, width, height);
  await splashRepairRace(browser);
} catch (cause) {
  report.errors.push(cause.stack || cause.message);
  console.error(cause.stack || cause.message);
} finally {
  await browser?.close();
  report.finishedAt = new Date().toISOString();
  report.passed = report.errors.length === 0 && report.scenarios.length === expectedScenarios && report.scenarios.every(item => item.completed && item.passed) && report.checks.length > 0 && report.checks.every(item => item.passed);
  report.summary = { checksPassed: report.checks.filter(item => item.passed).length, checksFailed: report.checks.filter(item => !item.passed).length, screenshots: report.screenshots.length, scenarios: report.scenarios.length, expectedScenarios, scenariosCompleted: report.scenarios.filter(item => item.completed).length, scenariosAborted: report.scenarios.filter(item => !item.completed).length, scenariosNotRun: Math.max(0,expectedScenarios-report.scenarios.length), scenariosFailed: report.scenarios.filter(item => !item.passed).length, errors: report.errors.length };
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2));
  await writeFile(path.join(output, 'latest.json'), JSON.stringify({ directory, report: path.join(directory, 'report.json'), passed: report.passed, ...report.summary }, null, 2));
  console.log(JSON.stringify({ passed: report.passed, ...report.summary, report: path.join(directory, 'report.json') }));
  if (!report.passed) process.exitCode = 1;
}
