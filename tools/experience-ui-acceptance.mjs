// Real renderer + mock local controller. No production configuration, browser
// profile, provider account or network setting is read or changed.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { startController } from '../backend/src/local-controller.mjs';
import { createOnboardingManager } from '../backend/src/onboarding.mjs';
import { createImportedVpnStore } from '../backend/src/imported-vpn-store.mjs';

const root=path.resolve(import.meta.dirname,'..'), output=path.join(root,'.cache','experience-ui-acceptance',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
const report={mock:true,network:'loopback only',checks:[],layouts:[],screenshots:[],errors:[]};
const check=(name,condition)=>{report.checks.push({name,passed:Boolean(condition)});assert.ok(condition,name);};
let browser,controller,context,heldRelease,preferenceRelease,page;
try {
  let executablePath;
  for(const candidate of [process.env.BROWSER_BIN,'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean))try{await access(candidate);executablePath=candidate;break;}catch{}
  assert.ok(executablePath,'A locally installed Chromium browser is required');
  browser=await chromium.launch({executablePath,headless:true,args:['--no-proxy-server','--disable-quic','--disable-background-networking','--webrtc-ip-handling-policy=disable_non_proxied_udp']});
  const runtimeRoot=path.join(output,'mock-runtime'),onboarding=createOnboardingManager({runtimeRoot,mock:true});
  const vpnConfigStore=createImportedVpnStore({stateDir:path.join(runtimeRoot,'.vpn-config'),mock:true});
  await vpnConfigStore.import('proxies:\n  - name: synthetic-entry\n    type: ss\n    server: 203.0.113.9\n    port: 443\n    cipher: aes-128-gcm\n    password: synthetic-fixture-only\n');
  await onboarding.saveConfiguration({host:'203.0.113.8',port:1080,type:'socks',expectedExitIps:['203.0.113.8'],connectionMode:'vpn-import'});
  await onboarding.preferences({completed:true,browser:'fingerprint',autoOptimize:false,takeoverMode:'global'});
  controller=await startController({host:'127.0.0.1',port:0,mock:true,requireRelay:false,healthIntervalMs:0,runtimeRoot,onboarding,vpnConfigStore,appVersion:version,
    configPath:path.join(runtimeRoot,'config.json'),secretsPath:path.join(runtimeRoot,'fixture.secrets.env')});
  const origin=`http://127.0.0.1:${controller.address().port}`;
  context=await browser.newContext({viewport:{width:1080,height:800},locale:'zh-CN',reducedMotion:'reduce',serviceWorkers:'block',extraHTTPHeaders:controller.controlHeaders(),acceptDownloads:true});
  await context.addInitScript(({version})=>{
    window.experienceFixture={supportCalls:0,exports:[],layoutCalls:[],windowLayout:JSON.parse(sessionStorage.getItem('fixture-window-layout')||'null')||{preset:'wide',bounds:{x:0,y:0,width:1080,height:760}}};
    window.mcDesktop={isDesktop:true,getInfo:async()=>({name:'MC Proxy',version,edition:'developer',mock:true,closeBehavior:'tray',windowLayout:window.experienceFixture.windowLayout}),
      setWindowLayout:async preset=>{window.experienceFixture.layoutCalls.push(preset);if(window.experienceFixture.layoutHeld)await new Promise(resolve=>window.experienceFixture.layoutRelease=resolve);if(window.experienceFixture.layoutFailure)throw new Error('模拟窗口调整失败');const bounds={wide:[1080,760],standard:[900,800],tall:[480,800]}[preset];if(!bounds)throw new Error('未知预设');const result=window.experienceFixture.windowLayout={preset,bounds:{x:0,y:0,width:bounds[0],height:bounds[1]}};sessionStorage.setItem('fixture-window-layout',JSON.stringify(result));return result;},
      getApplications:async()=>({mock:true,applications:[]}),exportSupportReport:async()=>{window.experienceFixture.supportCalls++;return{canceled:false};},
      licenseAdminStatus:async()=>({enabled:true,configured:false,customers:[],orders:[],summary:{}}),
      licenseAdminExportDelivery:async input=>{window.experienceFixture.exports.push(input);return window.experienceFixture.exportCanceled?{canceled:true}:{saved:true};}};
  },{version});
  const calls=[],blocked=[],rendererErrors=[];let browserId=null,heldStart=false,heldReached=false,holdPreference=false,preferenceReached=false,previewCount=0,importCount=0,reminderFixture=null,importResult={imported:true,mock:true},previewExtras={},onboardingFailure=false,startupFixture=null;
  await context.route('**/*',async route=>{
    const url=new URL(route.request().url());
    if(url.origin!==origin){blocked.push(url.origin);return route.abort();}
    if(!url.pathname.startsWith('/api/'))return route.continue();
    const method=route.request().method();let body;try{body=route.request().postDataJSON();}catch{}
    calls.push({path:url.pathname,method,...(/^\/api\/workspaces\/(create|update|start)$/.test(url.pathname)?{workspace:body}: {})});
    const respond=(data,status=200)=>route.fulfill({status,contentType:'application/json',json:{ok:true,data}});
    if(url.pathname==='/api/onboarding/preferences'&&holdPreference){preferenceReached=true;await new Promise(resolve=>preferenceRelease=resolve);return route.continue();}
    if(url.pathname==='/api/onboarding'&&onboardingFailure){onboardingFailure=false;return route.fulfill({status:503,contentType:'application/json',json:{ok:false,error:{code:'SERVICE_UNAVAILABLE',message:'模拟状态读取失败'}}});}
    if(url.pathname==='/api/reminders'&&reminderFixture)return respond(reminderFixture);
    if(url.pathname==='/api/workspaces/start'){
      if(heldStart){heldReached=true;await new Promise(resolve=>heldRelease=resolve);return route.fulfill({status:409,contentType:'application/json',json:{ok:false,error:{code:'CONNECTION_CANCELED',message:'连接已取消'}}});}
      if(browserId&&browserId!==body.id)assert.equal(body.confirmSwitch,true,'switch explicitly confirmed');
      browserId=body.id;return respond({workspaceId:body.id,mock:true});
    }
    if(url.pathname==='/api/progress'&&heldReached)return respond({connectionCancellation:{active:true,requested:false},operation:{stage:'verifying-exit',message:'模拟：等待出口核验'}});
    if(url.pathname==='/api/session/end'){browserId=null;heldRelease?.();heldStart=false;heldReached=false;return respond({ended:true,mock:true});}
    if(url.pathname==='/api/delivery/preview'){
      previewCount++;return respond({token:'fixture-preview-token',expiresAt:Date.now()+300000,preview:{connectionMode:'vpn-import',takeoverMode:'global',isp:{type:'socks',authenticated:true,pinnedExits:1},
        vpn:{included:true,supported:12,unsupported:2},license:{verified:true,expiresAt:Date.now()+30*86400000,offlineUntil:Date.now()+86400000},password:'PRIVATE_PREVIEW_VALUE',summary:'PRIVATE_PREVIEW_VALUE',...previewExtras}});
    }
    if(url.pathname==='/api/delivery/import'){assert.equal(body.token,'fixture-preview-token');importCount++;return respond(importResult);}
    if(['/api/status','/api/snapshot','/api/workspaces','/api/onboarding'].includes(url.pathname)){
      const response=await route.fetch(),payload=await response.json();
      if(payload.ok&&url.pathname==='/api/onboarding'&&startupFixture){payload.data.configuration={...payload.data.configuration,...startupFixture.configuration};payload.data.onboarding={...payload.data.onboarding,...startupFixture.onboarding};}
      if(payload.ok&&url.pathname==='/api/workspaces'){payload.data.activeId=browserId;if(startupFixture?.configuration.available===false){payload.data.configured=false;payload.data.pinned=false;}}
      else if(payload.ok&&browserId)payload.data.browser={...payload.data.browser,running:true,browser:'fingerprint',workspaceId:browserId};
      return route.fulfill({response,json:payload});
    }
    return route.continue();
  });
  page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',error=>{rendererErrors.push(error.message);report.errors.push(error.message);});
  const idle=()=>page.waitForFunction(()=>document.querySelector('#operationNotice')?.hidden===true);
  async function checkEntrances(label,width,height){
    await page.setViewportSize({width,height});await page.evaluate(()=>document.fonts.ready);await idle();
    const metrics=await page.evaluate(()=>{
      const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden';};
      const rect=el=>{const r=el.getBoundingClientRect();return{id:el.id||el.dataset.step,left:r.left,top:r.top,right:r.right,bottom:r.bottom,width:r.width,height:r.height};};
      const buttons=[...document.querySelectorAll('#appHeader> .header-actions>button,#workspaceNav>button,#stepTrack>button')].filter(visible).map(rect),overlaps=[];
      for(let a=0;a<buttons.length;a++)for(let b=a+1;b<buttons.length;b++){const x=buttons[a],y=buttons[b];if(Math.min(x.right,y.right)-Math.max(x.left,y.left)>1&&Math.min(x.bottom,y.bottom)-Math.max(x.top,y.top)>1)overlaps.push([x.id,y.id]);}
      const layout=document.querySelector('#layoutButton'),workspace=document.querySelector('#workspaceSpacesButton'),main=document.querySelector('[data-screen]:not([hidden])'),entry=document.querySelector('#connectionWorkspaceEntry'),entryButton=document.querySelector('#connectionWorkspaceButton');
      return{pageWidth:document.documentElement.scrollWidth,viewport:innerWidth,mainWidth:main.scrollWidth,mainClient:main.clientWidth,layoutText:layout.innerText,layout:rect(layout),workspace:rect(workspace),connectionWorkspace:visible(entry)?rect(entry):null,connectionWorkspaceButton:visible(entryButton)?rect(entryButton):null,overlaps,buttons};
    });
    report.layouts.push({screen:label,width,height,...metrics});
    check(`${label} ${width}x${height}: page and main region have no horizontal overflow`,metrics.pageWidth<=width+2&&metrics.mainWidth<=metrics.mainClient+2);
    check(`${label} ${width}x${height}: top controls and navigation never overlap`,metrics.overlaps.length===0);
    check(`${label} ${width}x${height}: browser workspace remains a visible text entry`,metrics.workspace.left>=0&&metrics.workspace.right<=width+1&&metrics.workspace.bottom<=height&&metrics.workspace.width>0);
    check(`${label} ${width}x${height}: layout retains a visible text label`,/窗口布局/.test(metrics.layoutText)&&metrics.layout.left>=0&&metrics.layout.right<=width+1&&metrics.layout.bottom<=height);
    if(label==='normal-startup')check(`${label} ${width}x${height}: optional workspace explanation and action are visible on the first screen`,metrics.connectionWorkspace?.top>=0&&metrics.connectionWorkspace?.bottom<=height&&metrics.connectionWorkspaceButton?.right<=width+1);
    const file=`${label}-${width}x${height}.png`;await page.screenshot({path:path.join(output,file),animations:'disabled'});report.screenshots.push(file);
  }
  await page.goto(origin);await page.waitForFunction(()=>document.querySelector('#appFrame')?.dataset.currentScreen==='connection');await idle();
  check('a completed saved configuration opens the connection workbench directly',await page.locator('#screen-connection').isVisible()&&!await page.locator('#stepTrack').isVisible());
  check('normal startup exposes browser workspaces without first connecting',await page.locator('#workspaceSpacesButton').isVisible()&&await page.locator('#workspaceSpacesButton').isEnabled());
  const initialStarts=calls.filter(item=>['/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length;
  for(const [width,height]of[[1080,800],[900,800],[760,800],[480,800],[380,650]])await checkEntrances('normal-startup',width,height);
  check('startup entry changes do not initiate a proxy or browser session',calls.filter(item=>['/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length===initialStarts&&initialStarts===0);
  await page.setViewportSize({width:1080,height:800});
  await page.locator('#connectionWorkspaceButton').click();await page.locator('#screen-workspaces').waitFor({state:'visible'});
  check('connection workbench workspace entry opens its management page',await page.locator('#workspacePurpose').isVisible());await page.locator('#experienceConnection').click();
  await page.locator('#layoutButton').click();await page.locator('#layoutMenu').waitFor({state:'visible'});
  const layoutOption=preset=>page.locator(`button[data-layout-preset="${preset}"]`);
  async function clickLayout(preset,label,target){
    const option=layoutOption(preset),before=await page.evaluate(()=>window.experienceFixture.layoutCalls.length);
    if(['top-left','top-right','bottom-left','bottom-right'].includes(target)){
      const bounds=await option.boundingBox();assert.ok(bounds,'layout card has bounds');
      const position={x:target.endsWith('right')?bounds.width-6:6,y:target.startsWith('bottom')?bounds.height-6:6};
      const hit=await option.evaluate((el,position)=>{const rect=el.getBoundingClientRect(),target=document.elementFromPoint(rect.left+position.x,rect.top+position.y);return{preset:target?.closest('[data-layout-preset]')?.dataset.layoutPreset,marker:Boolean(target?.closest('.window-layout-selected'))};},position);
      check(`${label} ${target} is a clickable card area outside the selection marker`,hit.preset===preset&&!hit.marker);
      await option.click({position});
    }else await option.locator(target).click();
    await page.waitForFunction(p=>window.experienceFixture.windowLayout.preset===p,preset);
    const calls=await page.evaluate(()=>window.experienceFixture.layoutCalls);
    check(`${label} ${target} click reaches the desktop once and selects the whole card`,calls.length===before+1&&calls.at(-1)===preset&&await option.getAttribute('aria-pressed')==='true'&&await page.locator('[data-layout-preset][aria-pressed="true"]').count()===1&&(await page.locator('#windowLayoutCurrent').textContent())===label);
  }
  // Click the areas users see, rather than a synthetic radio.check() operation.
  for(const target of['.window-layout-preview','strong','small','top-left','top-right','bottom-left','bottom-right'])for(const[preset,label]of[['standard','标准'],['tall','纵向'],['wide','横向']])await clickLayout(preset,label,target);
  check('layout cards expose button semantics rather than tiny radio targets',await page.locator('#layoutMenu input[type=radio]').count()===0&&await page.locator('#layoutMenu button[data-layout-preset]').count()===3);
  for(const[preset,label,key]of[['standard','标准','Space'],['tall','纵向','Enter']]){
    const before=await page.evaluate(()=>window.experienceFixture.layoutCalls.length);await layoutOption(preset).focus();await page.keyboard.press(key);await page.waitForFunction(p=>window.experienceFixture.windowLayout.preset===p,preset);
    check(`${label} layout activates with keyboard ${key} and retains focus`,await page.evaluate(()=>window.experienceFixture.layoutCalls.length)===before+1&&await layoutOption(preset).getAttribute('aria-pressed')==='true'&&await layoutOption(preset).evaluate(el=>el===document.activeElement));
  }
  await clickLayout('wide','横向','strong');
  await page.evaluate(()=>window.experienceFixture.layoutHeld=true);const pendingClick=layoutOption('standard').click();await pendingClick;
  await page.waitForFunction(()=>typeof window.experienceFixture.layoutRelease==='function');
  check('all layout cards disable while the desktop resize is pending',await page.locator('[data-layout-preset]:disabled').count()===3&&await layoutOption('wide').getAttribute('aria-pressed')==='true');
  await page.evaluate(()=>{window.experienceFixture.layoutHeld=false;window.experienceFixture.layoutRelease();});await page.waitForFunction(()=>window.experienceFixture.windowLayout.preset==='standard');await clickLayout('wide','横向','small');
  await page.evaluate(()=>window.experienceFixture.layoutFailure=true);await layoutOption('tall').locator('.window-layout-preview').click();await page.waitForFunction(()=>document.querySelector('#windowLayoutStatus').textContent.includes('未调整'));
  check('layout failure preserves the previous whole-card selection and gives useful feedback',await layoutOption('wide').getAttribute('aria-pressed')==='true'&&await layoutOption('tall').getAttribute('aria-pressed')==='false'&&(await page.locator('#windowLayoutCurrent').textContent())==='横向');
  const beforeManualResize=await page.evaluate(()=>window.experienceFixture.layoutCalls.length);
  await page.evaluate(()=>{window.experienceFixture.layoutFailure=false;window.experienceFixture.windowLayout={preset:'custom',bounds:{x:0,y:0,width:1020,height:790}};window.dispatchEvent(new Event('resize'));});await page.waitForFunction(()=>document.querySelector('#windowLayoutCurrent').textContent==='自定');
  check('manual desktop resize refreshes host dimensions without choosing a preset',await page.locator('[data-layout-preset][aria-pressed="true"]').count()===0&&await page.evaluate(()=>window.experienceFixture.layoutCalls.length)===beforeManualResize&&/1020 × 790/.test(await page.locator('#windowLayoutStatus').textContent()));
  await page.evaluate(()=>{window.experienceFixture.windowLayout={preset:'wide',bounds:{x:0,y:0,width:1080,height:760}};window.dispatchEvent(new Event('resize'));});await page.waitForFunction(()=>document.querySelector('#windowLayoutCurrent').textContent==='横向');
  for(const[width,height]of[[1080,800],[480,800],[380,650]]){
    await page.setViewportSize({width,height});const bounds=await page.locator('#layoutMenu').boundingBox(),metrics=await page.locator('#layoutMenu').evaluate(el=>({scroll:el.scrollWidth,client:el.clientWidth}));
    check(`${width}x${height}: layout cards fit on screen without horizontal scroll`,bounds&&bounds.x>=0&&bounds.x+bounds.width<=width+1&&bounds.y>=0&&bounds.y+bounds.height<=height+1&&metrics.scroll<=metrics.client+1);
    await clickLayout('standard','标准','top-left');await clickLayout('tall','纵向','.window-layout-preview');await clickLayout('wide','横向','bottom-right');
    const file=`layout-cards-${width}x${height}.png`;await page.screenshot({path:path.join(output,file),animations:'disabled'});report.screenshots.push(file);
  }
  await page.setViewportSize({width:1080,height:800});await page.keyboard.press('Escape');
  check('layout menu closes with Escape and restores focus to its text button',!await page.locator('#layoutMenu').isVisible()&&await page.locator('#layoutButton').evaluate(el=>el===document.activeElement));
  await page.locator('#editIspButton').click();
  await page.locator('#configurationContent .experience-shortcut').waitFor({state:'visible'});
  const shortcutLayout=await page.evaluate(()=>{const button=document.querySelector('#configurationContent>.experience-shortcut').getBoundingClientRect(),panel=document.querySelector('.setup-route-panel').getBoundingClientRect();return{buttonBottom:button.bottom,panelTop:panel.top,buttonHeight:button.height};});
  check('setup shortcut spans its grid row and does not displace the route panel',shortcutLayout.buttonBottom<=shortcutLayout.panelTop+2&&shortcutLayout.buttonHeight<=48);
  await page.screenshot({path:path.join(output,'configuration-shortcut-1080x800.png'),animations:'disabled'});report.screenshots.push('configuration-shortcut-1080x800.png');
  await page.locator('#configurationContent .experience-shortcut').click();
  await page.locator('#screen-workspaces').waitFor({state:'visible'});await page.locator('#workspaceNew').waitFor({state:'visible'});
  check('first-time environment page offers a three-step guide and one create action',await page.locator('#workspaceFirstGuide').isVisible()&&await page.locator('#workspaceFirstGuide ol li').count()===3&&await page.locator('#workspaceNew').textContent()==='创建第一个用户环境'&&!await page.locator('#workspaceStartRow').isVisible());
  check('advanced browser storage details remain optional rather than first-time instructions',!await page.locator('#workspaceHelp').evaluate(el=>el.open)&&await page.locator('#workspaceHelp summary').isVisible());
  const beforeDirect=calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length;
  await page.locator('#workspaceDirect').click();await page.locator('#screen-connection').waitFor({state:'visible'});
  check('normal browsing has a direct route back to the original connection without creating or starting a workspace',calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length===beforeDirect&&await page.locator('#connectButton').isVisible());
  await page.locator('#workspaceSpacesButton').click();await page.locator('#screen-workspaces').waitFor({state:'visible'});
  for(const[width,height]of[[1080,800],[480,800],[380,650]]){
    await page.setViewportSize({width,height});await page.evaluate(()=>{document.querySelector('#workspacesContent').scrollTop=0;});
    const metrics=await page.evaluate(()=>{const button=document.querySelector('#workspaceNew').getBoundingClientRect(),content=document.querySelector('#workspacesContent');return{button:{top:button.top,bottom:button.bottom,left:button.left,right:button.right},scroll:content.scrollWidth,client:content.clientWidth};});
    check(`${width}x${height}: first-workspace creation is visible without scrolling and guidance does not overflow`,metrics.button.top>=0&&metrics.button.bottom<=height&&metrics.button.left>=0&&metrics.button.right<=width+1&&metrics.scroll<=metrics.client+1);
    if(width===380){
      const guide=await page.evaluate(()=>{const bounds=el=>{const r=el.getBoundingClientRect();return{top:r.top,bottom:r.bottom,left:r.left,right:r.right};};return{steps:[...document.querySelectorAll('#workspaceFirstGuide ol li>div')].map(el=>({...bounds(el),text:el.innerText.trim()})),content:bounds(document.querySelector('#workspacesContent')),skip:bounds(document.querySelector('#experienceConnection'))};});report.layouts.push({screen:'first-workspace-guide',width,height,...guide});
      check('380x650: all three first-use actions are readable on the first screen without scrolling',guide.steps.length===3&&guide.steps.every(step=>step.text&&step.top>=guide.content.top&&step.bottom<=Math.min(height,guide.content.bottom)+1));
      check('380x650: the normal-browsing footer exit remains visible and usable',guide.skip.top>=0&&guide.skip.bottom<=height&&guide.skip.left>=0&&guide.skip.right<=width+1&&await page.locator('#experienceConnection').isEnabled());
    }
    const file=`workspace-first-use-${width}x${height}.png`;await page.screenshot({path:path.join(output,file),animations:'disabled'});report.screenshots.push(file);
  }
  const beforeFooterSkip=calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length;
  await page.locator('#experienceConnection').click();await page.locator('#screen-connection').waitFor({state:'visible'});
  check('first-use narrow-window footer returns to normal browsing without creating or starting anything',await page.locator('#connectButton').isVisible()&&calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length===beforeFooterSkip);
  await page.locator('#workspaceSpacesButton').click();await page.locator('#screen-workspaces').waitFor({state:'visible'});
  await page.setViewportSize({width:1080,height:800});await page.locator('#workspaceNew').click();
  check('the first create step has a usable example name, selected text, selected websites, and no connection form',await page.locator('#workspaceName').inputValue()==='我的日常账号'&&await page.locator('#workspaceName').evaluate(el=>el===document.activeElement&&el.selectionStart===0&&el.selectionEnd===el.value.length)&&JSON.stringify(await page.locator('[name=workspaceSite]:checked').evaluateAll(elements=>elements.map(el=>el.value)))===JSON.stringify(['chatgpt','claude'])&&await page.locator('#workspaceEditor input[type=password]').count()===0&&!await page.locator('#workspaceNew').isVisible()&&!await page.locator('#workspaceFirstGuide').isVisible()&&!await page.locator('#workspaceOptional').isVisible());
  for(const input of await page.locator('[name=workspaceSite]').all())if(await input.isChecked())await input.locator('..').click();
  const beforeEmptySave=calls.filter(item=>item.path==='/api/workspaces/create').length;await page.locator('#workspaceEditor button[type=submit]').click();
  check('saving without a website stays in the form, focuses a choice, and makes no creation request',await page.locator('#workspaceEditor').isVisible()&&await page.locator('[name=workspaceSite]').first().evaluate(el=>el===document.activeElement)&&calls.filter(item=>item.path==='/api/workspaces/create').length===beforeEmptySave);
  await page.locator('#workspaceEditorCancel').click();
  check('canceling first creation returns to guidance with no saved or running workspace',await page.locator('#workspaceFirstGuide').isVisible()&&await page.locator('.workspace-card').count()===0&&browserId===null);
  async function create(name,services){await page.locator('#workspaceNew').click();if(name!==undefined)await page.locator('#workspaceName').fill(name);if(services)for(const input of await page.locator('[name=workspaceSite]').all()){const value=await input.getAttribute('value');if(await input.isChecked()!==services.includes(value))await input.locator('..').click();}await page.locator('#workspaceEditor button[type=submit]').click();await idle();}
  await create();check('first-time user can accept the supplied defaults and save directly through the real controller',await page.locator('#workspaceSelectedTitle').textContent()==='我的日常账号');
  const firstSaved=calls.find(item=>item.path==='/api/workspaces/create')?.workspace;
  check('successful first save preserves the chosen name and websites and hands off to the visible start step',firstSaved.name==='我的日常账号'&&JSON.stringify(firstSaved.services)===JSON.stringify(['chatgpt','claude'])&&await page.locator('#workspaceStartRow').isVisible()&&await page.locator('#workspaceStart').isEnabled()&&await page.locator('#workspaceStart').evaluate(el=>el===document.activeElement)&&!await page.locator('#workspaceEditor').isVisible()&&!await page.locator('#workspaceFirstGuide').isVisible()&&/ChatGPT.*Claude/.test(await page.locator('#workspaceStartHint').textContent()));
  await create('<img src=x onerror=alert(1)>',['claude','google']);
  const customSaved=calls.filter(item=>item.path==='/api/workspaces/create').at(-1).workspace;
  check('a named workspace saves the sites the user actually checked and names them in the next-step instruction',customSaved.name==='<img src=x onerror=alert(1)>'&&JSON.stringify(customSaved.services)===JSON.stringify(['claude','google'])&&/Claude.*Google/.test(await page.locator('#workspaceStartHint').textContent())&&!/ChatGPT/.test(await page.locator('#workspaceStartHint').textContent()));
  check('workspace names are escaped in both cards and selected title',await page.locator('#workspaceList img').count()===0&&(await page.locator('#workspaceSelectedTitle').textContent()).startsWith('<img'));
  await page.locator('#workspaceList .workspace-more summary').last().click();await page.locator('#workspaceList [data-edit]').last().click();await page.locator('#workspaceName').fill('客户工作');await page.locator('#workspaceEditor button[type=submit]').click();await idle();
  check('editing preserves selection and updates its visible label',await page.locator('#workspaceSelectedTitle').textContent()==='客户工作');
  holdPreference=true;await page.locator('#experienceConnection').click();await page.locator('#returnPreferencesButton').click();
  const preferenceRequest=page.waitForRequest(request=>request.url().endsWith('/api/onboarding/preferences'));
  await page.locator('#autoOptimize').check();await preferenceRequest;
  await page.locator('#settingsButton').click();await page.locator('#openApplicationProxyButton').click();await page.locator('#workspaceSpacesButton').click();
  const startsBeforeFlush=calls.filter(item=>item.path==='/api/workspaces/start').length;
  await page.locator('#workspaceStart').click();
  check('preference save can be canceled before any connection request exists',preferenceReached&&await page.locator('#workspaceCancel').isEnabled());
  await page.locator('#workspaceCancel').click();await page.waitForFunction(()=>document.querySelector('#toastStack')?.textContent.includes('连接已取消'));
  const endedWhilePending=calls.filter(item=>item.path==='/api/session/end').length;
  holdPreference=false;preferenceRelease();await idle();
  check('cancel during preference flush never starts a later connection when the save completes',endedWhilePending===1&&calls.filter(item=>item.path==='/api/workspaces/start').length===startsBeforeFlush&&browserId===null);
  await page.locator('#workspaceStart').click();await idle();check('one-click start uses the selected workspace',Boolean(browserId));
  check('simulated workspace start never claims a real browser launched',/模拟工作区启动完成，未启动真实浏览器/.test(await page.locator('#toastStack').textContent()));
  await page.locator('#workspaceList [data-select]').first().click();await page.locator('#workspaceStart').click();
  check('switch asks to save unsent browser work first',await page.locator('#confirmModal').isVisible()&&/未提交/.test(await page.locator('#modalBody').textContent()));
  await page.locator('#modalConfirm').click();await idle();
  check('confirmed switch opens first workspace',browserId===await page.locator('#workspaceList [data-select]').first().getAttribute('data-select'));
  browserId=null;heldStart=true;await page.locator('#experienceRefresh').click();
  // Force a fresh status from the same controller, avoiding a stale presentation fixture.
  await page.locator('#refreshButton').click();await idle();await page.locator('#workspaceStart').click();
  await page.locator('#workspaceCancel:not([disabled])').waitFor({state:'visible'});check('start exposes cancel while verification is pending',heldReached);
  await page.locator('#workspaceCancel').click();await idle();check('cancel releases the held start without opening another workspace',browserId===null&&!heldReached);
  await page.locator('#reminderKind').selectOption('isp');await page.locator('#reminderDate').fill('2026-01-01');await page.locator('#reminderSave').click();await idle();
  check('manual reminder persists and produces a nonblocking notification',await page.locator('#reminderDate').inputValue()==='2026-01-01'&&await page.locator('#experienceReminderAlert').isVisible());
  await page.locator('#reminderDate').fill('2027-01-01');await page.locator('#experienceRefresh').click();
  check('background refresh preserves an unsaved date draft',await page.locator('#reminderDate').inputValue()==='2027-01-01');
  await page.locator('#reminderKind').selectOption('vpn');await page.locator('#reminderKind').selectOption('isp');
  check('service switching reloads the saved date rather than an unrelated draft',await page.locator('#reminderDate').inputValue()==='2026-01-01');
  await page.locator('#reminderClear').click();await idle();check('manual reminder can be cleared',await page.locator('#reminderDate').inputValue()==='');
  reminderFixture={revision:3,noticeCount:1,items:[{kind:'vpn',label:'VPN 套餐',source:'provider',state:'due-soon',daysRemaining:2,expiresAt:Date.now()+2*86400000,editable:true,expiresOn:'2027-01-01',observedAt:'2026-10-13T00:00:00.000Z',usage:{upload:10,download:30,total:100,remaining:60}}]};
  await page.locator('#experienceRefresh').click();await page.waitForFunction(()=>document.querySelector('#reminderCards')?.textContent.includes('非实时余额'));
  await page.locator('#reminderKind').selectOption('vpn');
  check('provider dates show provenance, observation time and stale-balance caveat while manual fallback remains explicit',/订阅提供方/.test(await page.locator('#reminderCards').textContent())&&/供应商未提供到期日/.test(await page.locator('#reminderEditHint').textContent())&&await page.locator('#reminderDate').inputValue()==='2027-01-01');
  reminderFixture=null;await page.locator('#experienceRefresh').click();
  await page.locator('#deliveryFile').setInputFiles({name:'customer.mcproxy.json',mimeType:'application/json',buffer:Buffer.from('{"fixture":true}')});await idle();
  check('delivery preview is Chinese and never renders arbitrary preview fields',previewCount===1&&/12 个可用/.test(await page.locator('#deliveryPreview').textContent())&&!/PRIVATE_PREVIEW_VALUE|"isp"/.test(await page.locator('#deliveryPreview').textContent()));
  await page.locator('#deliveryApply').click();await page.locator('#modalConfirm').click();await idle();check('confirmed delivery uses only its prepared token',importCount===1&&!await page.locator('#deliveryPreview').isVisible());
  importResult={imported:false,mock:true,code:'DELIVERY_MOCK_PREVIEW_ONLY'};previewExtras={mock:true,license:{required:false,verified:false},reminders:{ispExpiresAt:Date.now()},remindersNotice:'PRIVATE_REFERENCE_NOTICE'};
  await page.locator('#deliveryFile').setInputFiles({name:'customer.mcproxy.json',mimeType:'application/json',buffer:Buffer.from('{"fixture":true}')});await idle();
  check('mock preview and reference reminder dates are clearly explained without arbitrary text',/演示模式，只预览/.test(await page.locator('#deliveryPreview').textContent())&&/ISP 参考日期/.test(await page.locator('#deliveryPreview').textContent())&&!/PRIVATE_REFERENCE/.test(await page.locator('#deliveryPreview').textContent()));
  await page.locator('#deliveryApply').click();check('mock-only confirmation explains no configuration or authorization will be written',/演示模式.*不会写入/.test(await page.locator('#modalBody').textContent()));await page.locator('#modalConfirm').click();await idle();
  check('mock-only import never claims credentials or authorization were written',/没有写入/.test(await page.locator('#deliveryStatus').textContent())&&!/交付已导入/.test(await page.locator('#toastStack').textContent()));
  importResult={imported:true,cleanupPending:true};previewExtras={license:{required:false,verified:false}};
  await page.locator('#deliveryFile').setInputFiles({name:'customer.mcproxy.json',mimeType:'application/json',buffer:Buffer.from('{"fixture":true}')});await idle();
  check('developer preview does not imply a license is applied',/开发者模式不应用许可/.test(await page.locator('#deliveryPreview').textContent()));
  await page.locator('#deliveryApply').click();check('developer confirmation accurately preserves the existing license',/开发者模式不应用许可/.test(await page.locator('#modalBody').textContent()));await page.locator('#modalConfirm').click();await idle();
  check('committed delivery with deferred journal cleanup is reported honestly',/下次启动.*收尾/.test(await page.locator('#deliveryStatus').textContent()));
  importResult={imported:true};previewExtras={};
  await page.locator('#deliveryFile').setInputFiles({name:'customer.mcproxy.json',mimeType:'application/json',buffer:Buffer.from('{"fixture":true}')});await idle();onboardingFailure=true;
  await page.locator('#deliveryApply').click();await page.locator('#modalConfirm').click();await idle();
  check('post-commit refresh failure cannot be mistaken for failed import',/交付已保存，状态刷新失败/.test(await page.locator('#deliveryStatus').textContent()));
  await page.locator('#supportExport').click();await idle();check('support report is an explicit one-click local save',await page.evaluate(()=>window.experienceFixture.supportCalls)===1&&/已保存/.test(await page.locator('#supportStatus').textContent()));
  await page.evaluate(()=>delete window.mcDesktop.exportSupportReport);
  const downloadPromise=page.waitForEvent('download');await page.locator('#supportExport').click();const download=await downloadPromise;await idle();
  const reportFile=path.join(output,'downloaded-support-report.json');await download.saveAs(reportFile);const actualReport=JSON.parse(await readFile(reportFile,'utf8'));
  check('browser fallback uses the actual report endpoint and downloads sanitized evidence',actualReport.privacy?.redacted===true&&actualReport.privacy?.uploaded===false&&Array.isArray(actualReport.untested));
  await page.locator('#deliveryFile').setInputFiles({name:'customer.mcproxy.json',mimeType:'application/json',buffer:Buffer.from('{"fixture":true}')});await idle();
  await page.locator('#deliveryLicenseLink').click();await page.locator('#screen-license').waitFor({state:'visible'});
  check('existing authorization page retains a delivery shortcut',await page.locator('#licenseContent .experience-shortcut').count()===1);
  await page.locator('#licenseContent .experience-shortcut').click();await page.locator('#screen-workspaces').waitFor({state:'visible'});
  check('leaving workspace clears pending sensitive delivery preview',!await page.locator('#deliveryPreview').isVisible());
  await page.locator('#deliveryExportPanel summary').click();
  await page.locator('#deliveryVpnFile').setInputFiles({name:'synthetic-vpn.yaml',mimeType:'text/plain',buffer:Buffer.from('proxies: []')});
  await page.locator('#deliveryIspHost').fill('203.0.113.10');await page.locator('#deliveryIspPort').fill('1080');await page.locator('#deliveryIspUser').fill('synthetic-user');await page.locator('#deliveryIspPassword').fill('synthetic-password');await page.locator('#deliveryIspExit').fill('203.0.113.10');
  await page.evaluate(()=>window.experienceFixture.exportCanceled=true);await page.locator('#deliveryExportForm button[type=submit]').click();await idle();
  check('canceling the native delivery export keeps the editable draft and never claims a saved file',/已取消/.test(await page.locator('#deliveryExportStatus').textContent())&&await page.locator('#deliveryIspPassword').inputValue()==='synthetic-password');
  await page.evaluate(()=>window.experienceFixture.exportCanceled=false);await page.locator('#deliveryExportForm button[type=submit]').click();await idle();
  const exported=await page.evaluate(()=>window.experienceFixture.exports.at(-1));
  check('developer delivery export sends the selected VPN and ISP through the native bridge',exported.vpnText==='proxies: []'&&exported.isp.host==='203.0.113.10'&&exported.isp.port===1080&&exported.isp.username==='synthetic-user'&&exported.takeoverMode==='global');
  check('successful native delivery export clears credentials and file input',/交付文件已保存/.test(await page.locator('#deliveryExportStatus').textContent())&&await page.locator('#deliveryIspPassword').inputValue()===''&&await page.locator('#deliveryVpnFile').inputValue()==='');
  await page.locator('#deliveryExportPanel summary').click();
  await page.evaluate(async()=>{await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));document.querySelector('#workspacesContent').scrollTop=0;});await page.screenshot({path:path.join(output,'workspaces-overview.png'),animations:'disabled'});report.screenshots.push('workspaces-overview.png');
  const headers={...controller.controlHeaders(),'content-type':'application/json'};
  for(let index=0;index<10;index++){const response=await fetch(origin+'/api/workspaces/create',{method:'POST',headers,body:JSON.stringify({confirm:true,name:`一个较长的工作区名称用于核对布局 ${index+1}`,services:['claude','chatgpt','google']})});assert.equal(response.status,200);}
  await page.locator('#experienceRefresh').click();await page.waitForFunction(()=>document.querySelectorAll('.workspace-card').length===12);
  for(const [width,height] of [[1080,800],[900,800],[760,800],[480,800],[380,650]]){
    await page.setViewportSize({width,height});await page.evaluate(()=>document.fonts.ready);
    const metrics=await page.evaluate(()=>({pageWidth:document.documentElement.scrollWidth,viewport:innerWidth,contentWidth:document.querySelector('#workspacesContent').scrollWidth,contentClient:document.querySelector('#workspacesContent').clientWidth,
      screenHeight:document.querySelector('#screen-workspaces').scrollHeight,screenClient:document.querySelector('#screen-workspaces').clientHeight,
      font:getComputedStyle(document.body).fontFamily,mismatches:[...document.querySelectorAll('#screen-workspaces button,#screen-workspaces input,#screen-workspaces select,#screen-workspaces h1,#screen-workspaces h2')].filter(el=>getComputedStyle(el).fontFamily!==getComputedStyle(document.body).fontFamily).map(el=>el.id)}));
    report.layouts.push({width,height,...metrics});check(`${width}x${height}: page and content have no horizontal overflow`,metrics.pageWidth<=width+2&&metrics.contentWidth<=metrics.contentClient+2);
    check(`${width}x${height}: controls and headings share the existing UI font`,metrics.mismatches.length===0);
    check(`${width}x${height}: scrolling stays in the content region`,metrics.screenHeight<=metrics.screenClient+2);
    await page.evaluate(()=>document.querySelector('#workspacesContent').scrollTop=0);
    const startBounds=await page.locator('#workspaceStart').boundingBox(),contentBounds=await page.locator('#workspacesContent').boundingBox();
    report.layouts.push({screen:'workspace-primary-action',width,height,startBounds,contentBounds});
    check(`${width}x${height}: start-work action stays visible above the workspace list without scrolling`,startBounds&&contentBounds&&startBounds.y>=contentBounds.y&&startBounds.y+startBounds.height<=Math.min(height,contentBounds.y+contentBounds.height)+1);
    const name=`workspaces-${width}x${height}.png`;await page.screenshot({path:path.join(output,name),animations:'disabled'});report.screenshots.push(name);
    await page.locator('#supportExport').scrollIntoViewIfNeeded();check(`${width}x${height}: support action remains reachable below long workspace lists`,await page.locator('#supportExport').isVisible());
    await checkEntrances('browser-workspaces',width,height);
  }
  await page.setViewportSize({width:1080,height:800});await page.locator('#layoutButton').click();await clickLayout('standard','标准','strong');await page.locator('#layoutCloseButton').click();
  await page.reload();await page.waitForFunction(()=>document.querySelector('#appFrame')?.dataset.currentScreen==='connection');await idle();
  check('renderer restart returns to the saved normal connection entry',await page.locator('#workspaceSpacesButton').isVisible()&&!await page.locator('#stepTrack').isVisible());
  await page.waitForFunction(()=>document.querySelector('#windowLayoutCurrent')?.textContent==='标准');await page.locator('#layoutButton').click();
  check('layout button reads the previously saved host preset after renderer restart',await layoutOption('standard').getAttribute('aria-pressed')==='true');await page.locator('#layoutCloseButton').click();
  startupFixture={configuration:{available:false,credentialsConfigured:false},onboarding:{firstRun:true,completedAt:null,backupExists:false}};
  await page.reload();await page.waitForFunction(()=>document.querySelector('#appFrame')?.dataset.currentScreen==='configuration');await idle();
  check('an unconfigured first launch keeps the original configuration wizard',await page.locator('#screen-configuration').isVisible()&&await page.locator('#stepTrack').isVisible());
  for(const [width,height]of[[1080,800],[900,800],[760,800],[480,800],[380,650]])await checkEntrances('first-setup',width,height);
  await page.locator('#workspaceSpacesButton').click();await page.locator('#screen-workspaces').waitFor({state:'visible'});
  check('first setup routes the user to configure the connection before creating or starting a workspace',await page.locator('#workspaceSetup').isVisible()&&await page.locator('#workspaceConfigure').isEnabled()&&await page.locator('#workspaceNew').isDisabled()&&await page.locator('#workspaceStart').isDisabled()&&!await page.locator('#workspaceFirstGuide').isVisible());
  const beforeConfigure=calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length;
  await page.locator('#workspaceConfigure').click();await page.locator('#screen-configuration').waitFor({state:'visible'});
  check('the configure action opens the original configuration form without changing a connection or workspace',await page.locator('#connectionMode').isVisible()&&calls.filter(item=>['/api/workspaces/create','/api/workspaces/start','/api/proxy/start','/api/browser/launch'].includes(item.path)).length===beforeConfigure);
  check('renderer completed without exceptions',rendererErrors.length===0);check('no external request was issued',blocked.length===0);
  report.apiCounts=Object.fromEntries([...new Set(calls.map(item=>item.path))].map(endpoint=>[endpoint,calls.filter(item=>item.path===endpoint).length]));
}catch(error){report.errors.push(error.stack||error.message);if(page){await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});report.failureState=await page.evaluate(()=>({screen:document.querySelector('#appFrame')?.dataset.currentScreen,error:document.querySelector('#errorNotice')?.textContent,splash:document.querySelector('#splashStatus')?.textContent,operation:document.querySelector('#operationText')?.textContent})).catch(()=>null);}process.exitCode=1;}finally{
  heldRelease?.();preferenceRelease?.();await context?.close();await controller?.shutdown();await browser?.close();
  report.passed=report.errors.length===0&&report.checks.every(check=>check.passed);await writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));
  console.log(JSON.stringify({passed:report.passed,checks:report.checks.length,output,errors:report.errors}));
}
