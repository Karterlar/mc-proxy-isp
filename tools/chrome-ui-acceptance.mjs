// Real app.js with a disposable mock controller; no customer data or native launch.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { startController } from '../backend/src/local-controller.mjs';
import { createOnboardingManager } from '../backend/src/onboarding.mjs';
import { createImportedVpnStore } from '../backend/src/imported-vpn-store.mjs';

const root=path.resolve(import.meta.dirname,'..'),output=path.join(root,'.cache','chrome-ui-acceptance',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const require=createRequire(import.meta.url),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
const report={mock:true,network:'loopback only',checks:[],screenshots:[],errors:[]},calls=[],blocked=[];
const check=(name,condition)=>{report.checks.push({name,passed:Boolean(condition)});assert.ok(condition,name);};
let browser,controller,context,page,activeBrowserFixture=null;
let browserOptions=[{id:'chrome',available:true},{id:'edge',available:true},{id:'fingerprint',available:true,runtime:{state:'installed',verified:true,version:'synthetic UI fixture'}}];
try {
  let executablePath;
  for(const candidate of [process.env.BROWSER_BIN,path.join(root,'.cache','chrome-retained-acceptance-engine','155.0.8059.84','extracted','chrome-win64','chrome.exe'),'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',path.join(root,'.cache','fingerprint-browser-canvas-r1','chrome.exe')].filter(Boolean))try{await access(candidate);executablePath=candidate;break;}catch{}
  assert.ok(executablePath,'Existing Chromium is required; no browser is downloaded');
  browser=await chromium.launch({executablePath,headless:true,args:['--no-proxy-server','--disable-quic','--disable-background-networking','--webrtc-ip-handling-policy=disable_non_proxied_udp']});
  const runtimeRoot=path.join(output,'mock-runtime'),onboarding=createOnboardingManager({runtimeRoot,mock:true}),vpnConfigStore=createImportedVpnStore({stateDir:path.join(runtimeRoot,'.vpn-config'),mock:true});
  await vpnConfigStore.import('proxies:\n  - name: synthetic-entry\n    type: ss\n    server: 203.0.113.9\n    port: 443\n    cipher: aes-128-gcm\n    password: synthetic-fixture-only\n');
  await onboarding.saveConfiguration({host:'203.0.113.8',port:1080,type:'socks',expectedExitIps:['203.0.113.8'],connectionMode:'vpn-import'});
  await onboarding.preferences({completed:true,autoOptimize:false,takeoverMode:'global'});
  controller=await startController({host:'127.0.0.1',port:0,mock:true,requireRelay:false,healthIntervalMs:0,runtimeRoot,onboarding,vpnConfigStore,appVersion:version,configPath:path.join(runtimeRoot,'config.json'),secretsPath:path.join(runtimeRoot,'fixture.secrets.env')});
  // Seed an in-memory retained profile; mock mode never starts an actual browser.
  await controller.browsers.launch(await controller.browsers.plan({browser:'chrome',port:17890}));
  const origin=`http://127.0.0.1:${controller.address().port}`;
  context=await browser.newContext({viewport:{width:1080,height:800},locale:'zh-CN',reducedMotion:'reduce',serviceWorkers:'block',extraHTTPHeaders:controller.controlHeaders()});
  await context.addInitScript(({version})=>{
    window.mcDesktop={isDesktop:true,getInfo:async()=>({name:'MC Proxy',version,edition:'developer',mock:true,closeBehavior:'tray',windowLayout:{preset:'wide',bounds:{width:1080,height:800}}}),getApplications:async()=>({mock:true,applications:[]}),licenseAdminStatus:async()=>({enabled:true,configured:false,customers:[],orders:[],summary:{}})};
  },{version});
  await context.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.origin!==origin){blocked.push(url.origin);return route.abort();}
    if(!url.pathname.startsWith('/api/'))return route.continue();
    let body;try{body=route.request().postDataJSON();}catch{}
    calls.push({path:url.pathname,body});
    if(['/api/browser/launch','/api/workspaces/start','/api/proxy/start','/api/browser/fingerprint/install'].includes(url.pathname))throw Error('UI-only test attempted native launch, network start or installation: '+url.pathname);
    if(url.pathname==='/api/workspaces/refresh'){
      const response=await route.fetch(),payload=await response.json();
      if(payload.ok)activeBrowserFixture=null; // The UI fixture models successful normal closure.
      return route.fulfill({response,json:payload});
    }
    if(['/api/onboarding','/api/status','/api/snapshot','/api/browsers/rescan'].includes(url.pathname)){
      const response=await route.fetch(),payload=await response.json();
      if(payload.ok){payload.data.browserOptions=structuredClone(browserOptions);if(activeBrowserFixture&&['/api/status','/api/snapshot'].includes(url.pathname))payload.data.browser={...payload.data.browser,...structuredClone(activeBrowserFixture)};}
      return route.fulfill({response,json:payload});
    }
    return route.continue();
  });
  page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',error=>report.errors.push(error.message));
  const idle=()=>page.waitForFunction(()=>document.querySelector('#operationNotice')?.hidden===true);
  const startup=async()=>{await page.waitForFunction(()=>document.querySelector('#appFrame')?.dataset.currentScreen==='connection');await idle();};
  const savedChange=async action=>{const response=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/onboarding/preferences'&&response.request().method()==='POST');await action();assert.equal((await(await response).json()).ok,true);await page.waitForFunction(()=>document.querySelector('#preferencesSaveStatus')?.textContent==='偏好已保存');};
  const sameSelectors=async value=>await page.locator('#browserChoice').inputValue()===value&&await page.locator('#applicationBrowserChoice').inputValue()===value;
  const shot=async filename=>{await page.screenshot({path:path.join(output,filename),animations:'disabled'});report.screenshots.push(filename);};
  const confirmMutation=async endpoint=>{
    const response=page.waitForResponse(response=>new URL(response.url()).pathname===endpoint&&response.request().method()==='POST');
    await page.locator('#modalConfirm').click();const payload=await(await response).json();assert.equal(payload.ok,true,JSON.stringify(payload));await idle();return payload.data;
  };
  await page.goto(origin);await startup();
  const initial=(await onboarding.status()).preferences;
  check('new saved setup defaults to Chrome with persistent data',initial.browser==='chrome'&&initial.fresh===false&&initial.fingerprintFresh===false&&await sameSelectors('chrome')&&!await page.locator('#freshProfile').isChecked());
  check('startup never launches a browser or changes the network',!calls.some(call=>['/api/browser/launch','/api/proxy/start','/api/workspaces/start'].includes(call.path)));
  await page.locator('#returnPreferencesButton').click();
  check('persistent Chrome clearly retains cookies, login and bookmarks',/固定独立资料.*Cookie.*登录.*书签/.test(await page.locator('#freshProfileHint').textContent()));
  await shot('chrome-persistent-preferences-1080x800.png');
  await savedChange(()=>page.locator('#freshProfile').check());
  check('fresh Chrome explicitly creates blank data without reusing login',(await onboarding.status()).preferences.fresh===true&&/每次新建空白资料.*不沿用上次登录/.test(await page.locator('#freshProfileHint').textContent()));
  await savedChange(()=>page.locator('#browserChoice').selectOption('fingerprint'));
  check('fingerprint remains available with its own persistent default',await sameSelectors('fingerprint')&&!await page.locator('#freshProfile').isChecked()&&/固定指纹身份/.test(await page.locator('#freshProfileHint').textContent()));
  await savedChange(()=>page.locator('#freshProfile').check());
  check('fingerprint fresh mode saves its own preference independently',(await onboarding.status()).preferences.fingerprintFresh===true&&(await onboarding.status()).preferences.fresh===true);
  await savedChange(()=>page.locator('#browserChoice').selectOption('chrome'));
  check('switching to Chrome restores its previous fresh switch',await sameSelectors('chrome')&&await page.locator('#freshProfile').isChecked());
  await savedChange(()=>page.locator('#freshProfile').uncheck());
  await savedChange(()=>page.locator('#browserChoice').selectOption('fingerprint'));
  check('returning to fingerprint preserves its fresh choice while Chrome stays persistent',await page.locator('#freshProfile').isChecked()&&(await onboarding.status()).preferences.fresh===false&&(await onboarding.status()).preferences.fingerprintFresh===true);
  await page.locator('#workspaceApplicationButton').click();await idle();
  check('application selector retains the existing fingerprint entry and settings',await sameSelectors('fingerprint')&&await page.locator('#fingerprintSettings').isVisible()&&await page.locator('#applicationFingerprintIcon').isVisible());
  await savedChange(()=>page.locator('#applicationBrowserChoice').selectOption('chrome'));
  check('application selector synchronizes Chrome and hides fingerprint controls',await sameSelectors('chrome')&&!await page.locator('#fingerprintSettings').isVisible()&&await page.locator('#applicationBrowserIcon').isVisible()&&!await page.locator('#freshProfile').isChecked());
  await page.reload();await startup();
  check('renderer reload retains Chrome, persistent data and separate fingerprint fresh preference',await sameSelectors('chrome')&&!await page.locator('#freshProfile').isChecked()&&(await onboarding.status()).preferences.fingerprintFresh===true);
  await page.locator('#returnPreferencesButton').click();await savedChange(()=>page.locator('#freshProfile').check());
  await page.locator('#workspaceApplicationButton').click();await idle();await page.locator('#browserProfileRefreshButton').click();
  check('manual refresh explains blank login, retained old data and disabling every-time fresh mode',/空白资料.*重新登录.*原资料保留/.test(await page.locator('#modalBody').textContent())&&/关闭“每次开启纯净空间”/.test(await page.locator('#modalBody').textContent()));
  const refreshed=await confirmMutation('/api/browser/profiles/refresh');
  check('full app refresh replaces only the Chrome default profile and leaves fingerprint fresh enabled',Boolean(refreshed.archiveId)&&(await onboarding.status()).preferences.fresh===false&&(await onboarding.status()).preferences.fingerprintFresh===true);
  await page.locator('#browserProfileHistory').locator('summary').click();await page.locator('#browserProfileArchiveChoice').selectOption(refreshed.archiveId);
  check('newly archived old Chrome data is available through restore controls',await page.locator('#browserProfileRestoreButton').isEnabled());
  await shot('chrome-refreshed-profile-history-1080x800.png');
  await page.locator('#workspaceConnectionButton').click();await page.locator('#returnPreferencesButton').click();
  check('refresh callback updates the existing preference writer and visible switch',!await page.locator('#freshProfile').isChecked()&&/固定独立资料/.test(await page.locator('#freshProfileHint').textContent()));
  await savedChange(()=>page.locator('#browserChoice').selectOption('edge'));await savedChange(()=>page.locator('#browserChoice').selectOption('chrome'));
  check('later preference writes do not bring back the previous fresh value',(await onboarding.status()).preferences.fresh===false&&!await page.locator('#freshProfile').isChecked());
  await page.reload();await startup();
  check('manual refresh remains persistent after renderer reload',(await onboarding.status()).preferences.fresh===false&&!await page.locator('#freshProfile').isChecked());
  await page.locator('#returnPreferencesButton').click();await savedChange(()=>page.locator('#freshProfile').check());
  await page.locator('#workspaceApplicationButton').click();await idle();
  if(!await page.locator('#browserProfileHistory').evaluate(element=>element.open))await page.locator('#browserProfileHistory').locator('summary').click();
  await page.locator('#browserProfileArchiveChoice').selectOption(refreshed.archiveId);await page.locator('#browserProfileRestoreButton').click();
  const restored=await confirmMutation('/api/browser/profiles/restore');
  check('history restore returns the selected old profile and disables every-time fresh',restored.restored===true&&(await onboarding.status()).preferences.fresh===false&&(await onboarding.status()).preferences.fingerprintFresh===true);
  await page.locator('#workspaceConnectionButton').click();await page.locator('#returnPreferencesButton').click();
  check('history restore also reconciles the visible preference writer',!await page.locator('#freshProfile').isChecked());
  await page.reload();await startup();
  check('restored profile stays retained after renderer reload',!await page.locator('#freshProfile').isChecked()&&(await onboarding.status()).preferences.fresh===false);
  await page.locator('#returnPreferencesButton').click();await savedChange(()=>page.locator('#browserChoice').selectOption('fingerprint'));
  check('reloaded fingerprint selection restores its own fresh switch',await page.locator('#freshProfile').isChecked());
  await savedChange(()=>page.locator('#browserChoice').selectOption('chrome'));
  browserOptions=browserOptions.map(item=>item.id==='chrome'?{...item,available:false}:item);
  await page.locator('#workspaceApplicationButton').click();await page.locator('#rescanBrowsersButton').click();await idle();
  check('missing Chrome explicitly falls back to Edge without selecting fingerprint',await sameSelectors('edge')&&/未识别到 Chrome.*本次使用 Edge.*首选浏览器保留/.test(await page.locator('#applicationBrowserHint').textContent())&&!await page.locator('#fingerprintSettings').isVisible());
  check('temporary Edge fallback does not overwrite the Chrome preference',(await onboarding.status()).preferences.browser==='chrome');
  await shot('chrome-missing-edge-fallback-1080x800.png');
  await page.reload();await startup();
  check('reload preserves the stated Edge fallback and original Chrome preference',await sameSelectors('edge')&&/本次使用 Edge/.test(await page.locator('#browserAvailabilityHint').textContent())&&(await onboarding.status()).preferences.browser==='chrome');
  browserOptions=browserOptions.map(item=>item.id==='chrome'?{...item,available:true}:item);
  await page.locator('#workspaceApplicationButton').click();await page.locator('#rescanBrowsersButton').click();await idle();
  check('rediscovering Chrome returns both selectors to the retained preferred browser',await sameSelectors('chrome')&&!await page.locator('#freshProfile').isChecked());
  await page.locator('#workspaceConnectionButton').click();await page.locator('#returnPreferencesButton').click();
  for(const[width,height]of[[1080,800],[480,800],[380,650]]){
    await page.setViewportSize({width,height});
    const size=await page.evaluate(()=>({document:document.documentElement.scrollWidth,width:innerWidth,main:document.querySelector('#screen-preferences').scrollWidth,client:document.querySelector('#screen-preferences').clientWidth}));
    check(`${width}x${height}: Chrome preference layout has no horizontal overflow`,size.document<=size.width+2&&size.main<=size.client+2);
    if(width<1080)await shot(`chrome-persistent-preferences-${width}x${height}.png`);
  }
  await page.setViewportSize({width:1080,height:800});await savedChange(()=>page.locator('#browserChoice').selectOption('fingerprint'));
  await page.locator('#workspaceSpacesButton').click();await idle();await page.locator('#workspaceNew').click();
  await page.locator('#workspaceName').fill('资料刷新集成测试');await page.locator('#workspaceBrowser').selectOption('chrome');
  const createdResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/workspaces/create'&&response.request().method()==='POST');
  await page.locator('#workspaceEditor button[type="submit"]').click();assert.equal((await(await createdResponse).json()).ok,true);await idle();
  const originalWorkspaceId=await page.locator('#workspaceList [data-select]').first().getAttribute('data-select'),preferencesBeforeWorkspaceRefresh=(await onboarding.status()).preferences;
  activeBrowserFixture={running:true,managed:true,browser:'chrome',workspaceId:originalWorkspaceId};
  await page.reload();await startup();await page.locator('#workspaceApplicationButton').click();await idle();
  check('running named Chrome environment offers blank replacement without default history',await page.locator('#browserProfileRefreshButton').textContent().then(text=>text.includes('为当前环境新建空白资料'))&&!await page.locator('#browserProfileHistory').isVisible());
  await page.locator('#browserProfileRefreshButton').click();const replaced=await confirmMutation('/api/workspaces/refresh');
  const nextWorkspaceId=replaced.workspace?.id;
  check('named refresh navigates to and selects the new replacement card',Boolean(nextWorkspaceId)&&nextWorkspaceId!==originalWorkspaceId&&await page.locator('#appFrame').getAttribute('data-current-screen')==='workspaces'&&await page.locator(`#workspaceList [data-select="${nextWorkspaceId}"]`).getAttribute('aria-pressed')==='true');
  check('named refresh archives the previous workspace and preserves all global browser preferences',Boolean(replaced.items.find(item=>item.id===originalWorkspaceId)?.archivedAt)&&JSON.stringify((await onboarding.status()).preferences)===JSON.stringify(preferencesBeforeWorkspaceRefresh));
  check('named refresh keeps its Chrome type and services',replaced.workspace.browser==='chrome'&&JSON.stringify(replaced.workspace.services)===JSON.stringify(['chatgpt','claude']));
  await shot('chrome-workspace-refreshed-selected-1080x800.png');
  const preferenceWritesBeforeRunning=calls.filter(call=>call.path==='/api/onboarding/preferences').length;
  activeBrowserFixture={running:true,browser:'chrome',workspaceId:'synthetic-current-chrome-environment'};
  await page.reload();await startup();await page.locator('#workspaceApplicationButton').click();await idle();
  check('a running Chrome workspace labels the fingerprint selector as the next default',await sameSelectors('fingerprint')&&await page.locator('#applicationBrowserChoice').isDisabled()&&await page.locator('#applicationBrowserChoiceLabel').textContent()==='下次默认方案');
  check('the running workspace hint identifies actual Chrome and preserved current data',/当前运行：Chrome用户环境.*下拉框显示下次默认方案.*当前窗口使用原资料/.test(await page.locator('#applicationBrowserHint').textContent())&&!await page.locator('#fingerprintSettings').isVisible());
  check('displaying active Chrome keeps the explicit fingerprint preference and icon semantics',(await onboarding.status()).preferences.browser==='fingerprint'&&calls.filter(call=>call.path==='/api/onboarding/preferences').length===preferenceWritesBeforeRunning&&await page.locator('#applicationFingerprintIcon').isVisible()&&!await page.locator('#applicationBrowserIcon').isVisible());
  await shot('chrome-workspace-fingerprint-next-default-1080x800.png');
  activeBrowserFixture={running:true,managed:true,browser:'chrome',fresh:true};
  const profileMutationsBeforeFresh=calls.filter(call=>['/api/browser/profiles/refresh','/api/browser/profiles/restore'].includes(call.path)).length;
  await page.reload();await startup();await page.locator('#workspaceApplicationButton').click();await idle();
  check('real app status passes active fresh scope to profile controls without relying on the saved fresh preference',await page.locator('#browserProfileRefreshButton').isDisabled()&&await page.locator('#browserProfileRestoreButton').isDisabled()&&/当前窗口是纯净空间.*纯净资料不会进入这里的历史/.test(await page.locator('#browserProfileHint').textContent())&&calls.filter(call=>['/api/browser/profiles/refresh','/api/browser/profiles/restore'].includes(call.path)).length===profileMutationsBeforeFresh);
  await shot('chrome-active-fresh-default-profile-guard-1080x800.png');
  check('no external request was issued',blocked.length===0);
  check('renderer completed without exceptions',report.errors.length===0);
}catch(error){report.errors.push(error.stack||error.message);if(page){await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});report.failureState=await page.evaluate(()=>({screen:document.querySelector('#appFrame')?.dataset.currentScreen,error:document.querySelector('#errorNotice')?.textContent,splash:document.querySelector('#splashStatus')?.textContent,operation:document.querySelector('#operationText')?.textContent,profileStatus:document.querySelector('#browserProfileStatus')?.textContent,profileArchives:document.querySelector('#browserProfileArchiveChoice')?.innerHTML,fresh:document.querySelector('#freshProfile')?.checked})).catch(()=>null);}process.exitCode=1;}
finally{
  await context?.close();await controller?.shutdown();await browser?.close();
  report.passed=report.errors.length===0&&report.checks.every(check=>check.passed);report.apiCounts=Object.fromEntries([...new Set(calls.map(call=>call.path))].map(endpoint=>[endpoint,calls.filter(call=>call.path===endpoint).length]));
  await writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,output,errors:report.errors}));
}
