// Real workspace HTML + synthetic loopback-only APIs. No client data or native launch.
// Run: node desktop/test/browser-tools-dom-acceptance.mjs
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url), root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
let playwright;
for (const candidate of [process.env.PLAYWRIGHT_MODULE,'playwright'].filter(Boolean)) { try { playwright = require(candidate); break; } catch {} }
assert.ok(playwright,'Existing Playwright is required; this test never installs dependencies');
let executablePath;
for (const candidate of [process.env.BROWSER_BIN,'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean)) { try { await access(candidate); executablePath=candidate; break; } catch {} }
assert.ok(executablePath,'Existing Chromium is required; this test never downloads a browser');
const output = path.join(root,'.cache','browser-tools-review',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const server = createServer(async(req,res) => {
  try {
    const pathname = new URL(req.url,'http://localhost').pathname;
    if (pathname==='/app.js') { res.writeHead(200,{'content-type':'text/javascript'});res.end('');return; }
    const file = path.resolve(root,'frontend','.'+(pathname==='/'?'/index.html':decodeURIComponent(pathname)));
    if (!file.startsWith(path.join(root,'frontend')+path.sep)) {res.writeHead(404);res.end();return;}
    const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png'};
    res.writeHead(200,{'content-type':types[path.extname(file)]||'application/octet-stream'});res.end(await readFile(file));
  } catch {res.writeHead(404);res.end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await playwright.chromium.launch({executablePath,headless:true,args:['--no-first-run','--no-default-browser-check']});
const report={mode:'synthetic component test',network:'loopback only',checks:[],screenshots:[],errors:[]};
function check(name,passed){report.checks.push({name,passed});assert.ok(passed,name);}
try {
  for (const [width,height] of [[1080,760],[380,650]]) {
    const page=await browser.newPage({viewport:{width,height},locale:'zh-CN',reducedMotion:'reduce'});
    page.on('pageerror',error=>report.errors.push(error.message));
    await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
    await page.goto(origin);
    await page.evaluate(async()=>{
      document.querySelector('#appFrame').dataset.currentScreen='applications';
      document.querySelectorAll('[data-screen]').forEach(screen=>screen.hidden=screen.dataset.screen!=='applications');
      for (const id of ['appHeader','workspaceNav']) document.getElementById(id).hidden=false;
      document.querySelector('#workspaceConnectionButton').removeAttribute('aria-current');document.querySelector('#workspaceApplicationButton').setAttribute('aria-current','page');
      window.fixture={state:{connected:true,ready:true,mock:false,locked:false,browser:'fingerprint',browserRunning:false,fresh:false,browserOptions:[{id:'chrome',available:true},{id:'fingerprint',available:false,runtime:{state:'missing'}}]},calls:[],copied:[],notices:[],observation:{status:'unverified'},engine:{settings:{language:'auto',timezone:'auto',nativeGraphics:true,resolvedLanguage:'en-US',resolvedTimezone:'America/New_York',alignmentSource:'local-environment'},runtime:{state:'missing'},install:{status:'idle'}}};
      const fixture=window.fixture,{createBrowserTools}=await import('/browser-tools.js');
      fixture.profiles=Object.fromEntries(['chrome','edge','fingerprint'].map(browser=>[browser,{browser,currentAvailable:true,archives:[]} ]));fixture.profileChanges=[];fixture.profileSequence=0;
      const request=async(endpoint,body)=>{
        fixture.calls.push({endpoint,body});
        if(endpoint.startsWith('/api/browser/profiles?')){const browser=new URL(endpoint,location.origin).searchParams.get('browser');if(fixture.deferProfiles===browser)return new Promise(resolve=>{fixture.resolveProfiles=resolve;});return structuredClone(fixture.profiles[browser]);}
        if(endpoint==='/api/browser/profiles/refresh'||endpoint==='/api/browser/profiles/restore'){if(fixture.profileFailure)throw new Error('磁盘空间不足');const profiles=fixture.profiles[body.browser];if(fixture.profileNoChange)return {changed:false,archiveId:null,archives:structuredClone(profiles.archives)};if(body.archiveId)profiles.archives=profiles.archives.filter(item=>item.id!==body.archiveId);profiles.archives.unshift({id:`${body.browser}-archive-${++fixture.profileSequence}`,createdAt:new Date().toISOString()});return {...structuredClone(profiles),changed:true};}
        if(endpoint==='/api/workspaces/refresh')return {workspace:{id:'replacement-user-environment'}};
        if(endpoint==='/api/browser-observation')return structuredClone(fixture.observation);
        if(endpoint==='/api/browser/fingerprint')return structuredClone(fixture.engine);
        if(endpoint==='/api/browser/fingerprint/security'){if(fixture.deferSecurity)await new Promise(resolve=>fixture.resolveSecurity=resolve);return {security:structuredClone(fixture.securityResult||fixture.engine.security)};}
        if(endpoint==='/api/browser/fingerprint/install'){fixture.engine.install.status='downloading';return {install:{status:'downloading'}};}
        if(endpoint==='/api/browser/fingerprint/settings'){fixture.engine.settings={...fixture.engine.settings,...body,resolvedLanguage:body.language==='auto'?'en-US':body.language,resolvedTimezone:body.timezone==='auto'?'America/New_York':body.timezone};return structuredClone(fixture.engine);}
        if(endpoint==='/api/browser/fingerprint/rotate')return {rotated:true,relaunched:true};
        if(endpoint==='/api/browser-observation/start'){fixture.observation={status:'waiting',url:location.origin+'/browser-observation#token=synthetic',expiresAt:'2099-01-01T00:00:00Z'};return structuredClone(fixture.observation);}
        throw new Error('Unexpected API');
      };
      window.tools=createBrowserTools({request,getState:()=>fixture.state,clipboard:{writeText:async text=>fixture.copied.push(text)},onNotice:(message,error)=>fixture.notices.push({message,error}),onProfilesChanged:async data=>{fixture.profileChanges.push(data);fixture.state.browserRunning=false;fixture.state.workspaceId=undefined;if(!data.workspaceId)fixture.state.fresh=false;},operation:async(label,work)=>{fixture.state.locked=true;tools.update();try{await work();}catch(error){fixture.notices.push({message:error.message,error:true});}finally{fixture.state.locked=false;tools.update();}},confirm:(title,message,callback)=>{document.querySelector('#modalTitle').textContent=title;document.querySelector('#modalBody').textContent=message;document.querySelector('#confirmModal').hidden=false;fixture.confirm=callback;}});
      document.querySelector('#modalConfirm').addEventListener('click',()=>{document.querySelector('#confirmModal').hidden=true;fixture.confirm();});
      document.querySelector('#modalCancel').addEventListener('click',()=>{document.querySelector('#confirmModal').hidden=true;fixture.confirm=null;});
      document.querySelector('#applicationBrowserChoice').value='fingerprint';document.querySelector('#applicationBrowserIcon').hidden=true;document.querySelector('#applicationFingerprintIcon').removeAttribute('hidden');
      await tools.refresh();tools.renderObservation();tools.update();
    });
    check(`${width}: optional unavailable engine remains selected and cannot launch`,await page.locator('#applicationBrowserChoice').inputValue()==='fingerprint'&&await page.locator('#browserObservationStartButton').isDisabled()&&await page.locator('#fingerprintInstallButton').isEnabled());
    await page.locator('#fingerprintInstallButton').click();
    check(`${width}: installation waits for explicit confirmation`,await page.evaluate(()=>!fixture.calls.some(call=>call.endpoint==='/api/browser/fingerprint/install')));
    await page.locator('#modalCancel').click();await page.locator('#fingerprintInstallButton').click();await page.locator('#modalConfirm').click();
    await page.waitForFunction(()=>document.querySelector('#fingerprintInstallButton').disabled);
    check(`${width}: background download is visible without a global locked operation`,await page.evaluate(()=>!fixture.state.locked&&fixture.engine.install.status==='downloading'));
    await page.evaluate(()=>{fixture.engine.install.status='extracting';tools.renderFingerprint(fixture.engine);tools.update();});
    check(`${width}: extracting engine cannot be installed twice`,await page.locator('#fingerprintInstallButton').isDisabled()&&/解压/.test(await page.locator('#fingerprintEngineState').textContent()));
    await page.evaluate(()=>{fixture.engine.runtime={state:'installed',version:'150',verified:true};fixture.engine.install.status='installed';fixture.state.browserOptions[1].available=true;fixture.state.browserOptions[1].runtime=fixture.engine.runtime;tools.renderFingerprint(fixture.engine);tools.update();});
    check(`${width}: stable profile permits explicit rotation; fresh profile does not`,await page.locator('#fingerprintRotateButton').isEnabled());
    await page.evaluate(()=>{fixture.engine.security={status:'outdated',engineVersion:'150.0.7871.186',baselineVersion:'155.0.8059.85'};tools.renderFingerprint(fixture.engine);});
    check(`${width}: prepared engine separately reports its outdated security baseline`,/安全版本落后.*150\.0\.7871\.186.*155\.0\.8059\.85/.test(await page.locator('#fingerprintSecurityHint').textContent()));
    await page.evaluate(()=>{fixture.deferSecurity=true;});await page.locator('#fingerprintCheckSecurityButton').click();
    await page.waitForFunction(()=>typeof fixture.resolveSecurity==='function');
    check(`${width}: security check never holds the global operation lock`,await page.evaluate(()=>!fixture.state.locked)&&await page.locator('#fingerprintCheckSecurityButton').isDisabled());
    await page.evaluate(()=>{fixture.securityResult={...fixture.engine.security,checkError:'FINGERPRINT_SECURITY_CHECK_FAILED'};fixture.resolveSecurity();});
    await page.waitForFunction(()=>!document.querySelector('#fingerprintCheckSecurityButton').disabled);
    check(`${width}: failed online check retains known warning and does not claim up to date`,/安全版本落后.*在线检查失败/.test(await page.locator('#fingerprintSecurityHint').textContent()));
    await page.evaluate(()=>{fixture.state.fresh=true;tools.update();});check(`${width}: fresh mode prevents meaningless rotation`,await page.locator('#fingerprintRotateButton').isDisabled());
    await page.evaluate(()=>{fixture.state.fresh=false;tools.update();});
    await page.locator('.fingerprint-options summary').click();
    check(`${width}: native graphics shows no seeded Canvas compatibility warning`,!await page.locator('#fingerprintCanvasWarning').isVisible());
    check(`${width}: automatic local region never claims a verified ISP region`,/本机环境/.test(await page.locator('#fingerprintResolvedRegion').textContent())&&/未匹配出口/.test(await page.locator('#fingerprintResolvedRegion').textContent()));
    await page.locator('#fingerprintLanguage').selectOption('ja-JP');await page.locator('#fingerprintTimezone').selectOption('Asia/Tokyo');await page.locator('#fingerprintSaveButton').click();
    await page.waitForFunction(()=>fixture.engine.settings.language==='ja-JP');
    check(`${width}: language and timezone save together without native graphics rewrite`,await page.evaluate(()=>fixture.calls.find(call=>call.endpoint==='/api/browser/fingerprint/settings').body.timezone==='Asia/Tokyo'&&fixture.engine.settings.nativeGraphics===true));
    check(`${width}: manually selected browser region is identified as manual`,/ja-JP（手动设置）.*Asia\/Tokyo（手动设置）/.test(await page.locator('#fingerprintResolvedRegion').textContent()));
    await page.locator('#fingerprintCanvasProtection').check();
    check(`${width}: enabling seeded Canvas explains the corrected engine and retained identity data`,await page.locator('#fingerprintCanvasWarning').isVisible()&&/Canvas 读回修正.*环境种子与登录资料保留/.test(await page.locator('#fingerprintCanvasWarning').textContent()));
    await page.locator('#fingerprintSaveButton').click();await page.waitForFunction(()=>fixture.engine.settings.nativeGraphics===false);
    check(`${width}: Canvas and layout protection explicitly persists nativeGraphics false`,await page.evaluate(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser/fingerprint/settings').at(-1).body.nativeGraphics===false));
    await page.locator('#fingerprintSettings').scrollIntoViewIfNeeded();const fingerprintScreenshot=`${width}x${height}-fingerprint-settings.png`;await page.screenshot({path:path.join(output,fingerprintScreenshot),animations:'disabled'});report.screenshots.push(fingerprintScreenshot);
    await page.locator('#browserObservationLinkButton').click();await page.waitForFunction(()=>document.querySelector('#browserObservationUrl').value.includes('synthetic'));await page.locator('#browserObservationCopyButton').click();
    check(`${width}: existing browser link is copied locally and launches no new browser`,await page.evaluate(()=>fixture.copied.length===1&&fixture.calls.find(call=>call.endpoint==='/api/browser-observation/start').body.launch===false));
    await page.evaluate(()=>{fixture.observation={status:'completed',report:{observedAt:new Date().toISOString(),source:{kind:'browser-self-report',requestedBrowser:'fingerprint',managedIdentityVerified:false},browser:{language:'ja-JP',timezone:'Asia/Tokyo'},summary:{status:'partial'},checks:[{id:'https-exit',label:'HTTPS 出口',status:'verified',value:'203.0.113.8',detail:'本轮浏览器页面实测，与指定 ISP 一致'},{id:'webrtc',label:'WebRTC',status:'unverified',detail:'未产生可判断的候选，不能证明完全无泄漏'},{id:'dns',label:'DNS 泄漏',status:'configured',detail:'当前配置已开启；独立 DNS 测试未执行'},{id:'ipv6',label:'IPv6',status:'unverified',detail:'IPv6 专用探针未得到结果'}]}};tools.renderObservation(fixture.observation);tools.update();});
    check(`${width}: measured/configured/pending evidence stay separate`,await page.locator('#browserObservationResults [data-state="verified"]').count()===1&&await page.locator('#browserObservationResults [data-state="configured"]').count()===1&&await page.locator('#browserObservationResults [data-state="unverified"]').count()===2);
    await page.locator('#browserObservationSection').scrollIntoViewIfNeeded();
    const bounds=await page.evaluate(()=>({width:innerWidth,document:document.documentElement.scrollWidth,body:document.body.scrollWidth,content:document.querySelector('#applicationsContent').scrollWidth,client:document.querySelector('#applicationsContent').clientWidth,fonts:[...document.querySelectorAll('#browserObservationSection button,#fingerprintSettings select')].every(node=>getComputedStyle(node).fontFamily===getComputedStyle(document.body).fontFamily)}));
    check(`${width}: browser tooling fits without horizontal overflow and uses the UI font`,bounds.document<=bounds.width+2&&bounds.body<=bounds.width+2&&bounds.content<=bounds.client+2&&bounds.fonts);
    const filename=`${width}x${height}-browser-observation.png`;await page.screenshot({path:path.join(output,filename),animations:'disabled'});report.screenshots.push(filename);
    await page.evaluate(async()=>{fixture.state.browser='chrome';fixture.state.fresh=true;document.querySelector('#applicationBrowserChoice').value='chrome';document.querySelector('#applicationBrowserIcon').hidden=false;document.querySelector('#applicationFingerprintIcon').hidden=true;tools.update();await tools.refreshProfiles();});
    await page.locator('#browserProfileRefreshButton').click();await page.evaluate(async()=>{fixture.state.browser='edge';tools.update();await tools.refreshProfiles();});await page.locator('#modalConfirm').click();
    check(`${width}: confirmation cannot mutate a different browser after selection changes`,await page.evaluate(()=>!fixture.calls.some(call=>call.endpoint==='/api/browser/profiles/refresh')&&fixture.notices.some(item=>/当前环境已变化/.test(item.message))));
    await page.evaluate(async()=>{fixture.state.browser='chrome';tools.update();await tools.refreshProfiles();});
    await page.locator('#browserProfileRefreshButton').click();
    check(`${width}: refreshing profile clearly preserves old data and requires confirmation`,/空白资料.*重新登录.*原资料保留.*关闭“每次开启纯净空间”.*未保存内容.*不会自动打开/s.test(await page.locator('#modalBody').textContent())&&await page.evaluate(()=>!fixture.calls.some(call=>call.endpoint==='/api/browser/profiles/refresh')));
    await page.locator('#modalCancel').click();
    check(`${width}: canceling profile refresh makes no mutation request`,await page.evaluate(()=>!fixture.calls.some(call=>call.endpoint==='/api/browser/profiles/refresh')));
    await page.locator('#browserProfileRefreshButton').click();await page.locator('#modalConfirm').click();
    await page.waitForFunction(()=>fixture.profileChanges.length===1&&!fixture.state.locked);
    check(`${width}: refresh requests chosen browser, updates state and retains the old archive`,await page.evaluate(()=>{const call=fixture.calls.find(call=>call.endpoint==='/api/browser/profiles/refresh');return call.body.browser==='chrome'&&call.body.confirm===true&&!fixture.state.fresh&&fixture.profileChanges[0].browser==='chrome'&&fixture.profiles.chrome.archives.length===1;})&&/下次打开需要重新登录.*原默认资料已保留/.test(await page.locator('#browserProfileStatus').textContent()));
    await page.locator('#browserProfileHistory summary').click();await page.locator('#browserProfileArchiveChoice').selectOption('chrome-archive-1');await page.locator('#browserProfileRestoreButton').click();
    check(`${width}: restoring profile explains current data also stays available`,/恢复所选资料.*当前默认保留资料也会保留/s.test(await page.locator('#modalBody').textContent()));
    await page.locator('#modalConfirm').click();await page.waitForFunction(()=>fixture.profileChanges.length===2&&!fixture.state.locked);
    check(`${width}: restore sends selected archive and keeps a recoverable replacement`,await page.evaluate(()=>{const call=fixture.calls.find(call=>call.endpoint==='/api/browser/profiles/restore');return call.body.browser==='chrome'&&call.body.archiveId==='chrome-archive-1'&&fixture.profiles.chrome.archives[0].id==='chrome-archive-2';}));
    await page.evaluate(()=>{fixture.profileFailure=true;});await page.locator('#browserProfileRefreshButton').click();await page.locator('#modalConfirm').click();
    await page.waitForFunction(()=>!fixture.state.locked&&document.querySelector('#browserProfileStatus').dataset.error==='true');
    check(`${width}: profile error is visible without discarding archives`,/磁盘空间不足.*原资料保留/.test(await page.locator('#browserProfileStatus').textContent())&&await page.evaluate(()=>fixture.profileChanges.length===2&&fixture.profiles.chrome.archives[0].id==='chrome-archive-2'));
    await page.evaluate(async()=>{fixture.profileFailure=false;fixture.deferProfiles='edge';fixture.state.browser='edge';tools.update();await Promise.resolve();fixture.state.browser='chrome';tools.update();await tools.refreshProfiles();fixture.resolveProfiles({browser:'edge',currentAvailable:true,archives:[{id:'edge-old',createdAt:new Date().toISOString()}]});});
    check(`${width}: late response for a previous browser never replaces current profile history`,await page.locator('#browserProfileArchiveChoice option[value="chrome-archive-2"]').count()===1&&await page.locator('#browserProfileArchiveChoice option[value="edge-old"]').count()===0);
    await page.evaluate(()=>{fixture.state.locked=true;tools.update();});check(`${width}: busy operation blocks profile mutation`,await page.locator('#browserProfileRefreshButton').isDisabled()&&await page.locator('#browserProfileArchiveChoice').isDisabled());
    await page.evaluate(()=>{fixture.state.locked=false;fixture.state.connected=false;tools.update();});check(`${width}: controller loss blocks profile refresh and restore`,await page.locator('#browserProfileRefreshButton').isDisabled()&&await page.locator('#browserProfileRestoreButton').isDisabled());
    await page.evaluate(async()=>{fixture.state.connected=true;fixture.state.browserRunning=true;fixture.state.activeBrowser='edge';tools.update();await tools.refreshProfiles();});
    check(`${width}: another running browser cannot be refreshed by a mismatched selection`,await page.locator('#browserProfileRefreshButton').isDisabled()&&/先关闭正在运行的浏览器/.test(await page.locator('#browserProfileStatus').textContent()));
    await page.evaluate(()=>{fixture.state.activeBrowser='chrome';fixture.state.activeFresh=true;fixture.state.fresh=false;fixture.profileCallsBeforeFresh=fixture.calls.filter(call=>call.endpoint==='/api/browser/profiles/refresh').length;tools.update();});
    check(`${width}: active fresh mode blocks default refresh and restore even if its saved preference was changed`,await page.locator('#browserProfileRefreshButton').isDisabled()&&await page.locator('#browserProfileRestoreButton').isDisabled()&&/纯净空间.*默认保留资料.*纯净资料不会进入这里的历史/.test(await page.locator('#browserProfileHint').textContent())&&/先关闭纯净窗口/.test(await page.locator('#browserProfileStatus').textContent()));
    await page.locator('#browserProfileRefreshButton').dispatchEvent('click');
    check(`${width}: a synthetic click on disabled fresh refresh cannot mutate or show a misleading modal`,await page.evaluate(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser/profiles/refresh').length===fixture.profileCallsBeforeFresh&&document.querySelector('#confirmModal').hidden));
    await page.evaluate(()=>{fixture.state.activeFresh=false;});
    await page.evaluate(()=>{fixture.state.browserRunning=false;fixture.state.activeBrowser=undefined;tools.update();});
    await page.locator('#browserProfileTools').scrollIntoViewIfNeeded();
    const profileBounds=await page.locator('#browserProfileTools').evaluate(node=>({width:node.clientWidth,scroll:node.scrollWidth,button:node.querySelector('button').getBoundingClientRect().width,tool:node.getBoundingClientRect().width}));
    check(`${width}: profile tools fit narrow and desktop layouts with a whole visible button`,profileBounds.scroll<=profileBounds.width+2&&profileBounds.button>80&&profileBounds.button<=profileBounds.tool);
    const profileScreenshot=`${width}x${height}-browser-profiles.png`;await page.screenshot({path:path.join(output,profileScreenshot),animations:'disabled'});report.screenshots.push(profileScreenshot);
    await page.evaluate(()=>{fixture.state.browser='fingerprint';fixture.state.browserRunning=true;fixture.state.activeBrowser='chrome';fixture.state.workspaceId='original-chrome-environment';tools.update();});
    check(`${width}: running named environment offers its own blank replacement and hides default archives`,await page.locator('#browserProfileRefreshButton').textContent()==='为当前环境新建空白资料'&&!await page.locator('#browserProfileHistory').isVisible());
    await page.locator('#browserProfileRefreshButton').click();await page.locator('#modalConfirm').click();await page.waitForFunction(()=>fixture.profileChanges.length===3&&!fixture.state.locked);
    check(`${width}: named refresh targets workspace replacement instead of resetting global browser profile`,await page.evaluate(()=>{const call=fixture.calls.find(call=>call.endpoint==='/api/workspaces/refresh');return call.body.id==='original-chrome-environment'&&call.body.confirm===true&&!Object.hasOwn(call.body,'browser')&&fixture.profileChanges.at(-1).workspaceId==='replacement-user-environment'&&fixture.calls.filter(call=>call.endpoint==='/api/browser/profiles/refresh').length===2;}));
    await page.evaluate(async()=>{fixture.state.browser='chrome';fixture.state.browserRunning=false;fixture.state.workspaceId=undefined;fixture.state.activeBrowser=undefined;fixture.profileNoChange=true;fixture.notices=[];tools.update();await tools.refreshProfiles();});
    await page.locator('#browserProfileRefreshButton').click();await page.locator('#modalConfirm').click();await page.waitForFunction(()=>fixture.profileChanges.length===4&&!fixture.state.locked);
    check(`${width}: unchanged refresh explicitly reports no archive and never claims old fresh data was retained in history`,/没有默认保留资料可归档.*下次打开会创建空白资料/.test(await page.locator('#browserProfileStatus').textContent())&&await page.evaluate(()=>fixture.notices.some(item=>/没有默认保留资料可归档/.test(item.message))&&!fixture.notices.some(item=>/原.*资料已保留/.test(item.message))));
    await page.evaluate(()=>{fixture.profileNoChange=false;});
    await page.evaluate(()=>{fixture.state.activeBrowser=undefined;fixture.state.browser='fingerprint';tools.update();});
    await page.evaluate(()=>{fixture.state.workspaceId='synthetic-user-environment';fixture.state.browserRunning=true;tools.update();});
    check(`${width}: active user environment permits in-place detection and locks unrelated defaults`,await page.locator('#browserObservationStartButton').isEnabled()&&await page.locator('#browserObservationStartButton').textContent()==='检测当前用户环境'&&await page.locator('#fingerprintLanguage').isDisabled()&&await page.locator('#fingerprintSaveButton').isDisabled());
    await page.locator('#browserObservationStartButton').click();
    await page.waitForFunction(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').length===2);
    check(`${width}: detection uses the named active environment rather than a temporary default profile`,await page.evaluate(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').at(-1).body.workspaceId==='synthetic-user-environment'));
    await page.locator('#fingerprintRotateButton').click();
    check(`${width}: current-environment rotation explicitly preserves website data`,/当前用户环境.*Cookie.*网站存储.*保留/s.test(await page.locator('#modalBody').textContent()));
    await page.locator('#modalConfirm').click();
    await page.waitForFunction(()=>fixture.calls.some(call=>call.endpoint==='/api/browser/fingerprint/rotate'));
    check(`${width}: browser tooling rotation carries the same environment identifier`,await page.evaluate(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser/fingerprint/rotate').at(-1).body.workspaceId==='synthetic-user-environment'));
    await page.evaluate(()=>{fixture.state.activeBrowser='chrome';fixture.state.workspaceId='synthetic-chrome-environment';fixture.state.browser='fingerprint';tools.update();});
    check(`${width}: an active Chrome workspace permits observation and hides fingerprint controls despite a fingerprint default`,await page.locator('#browserObservationStartButton').isEnabled()&&!await page.locator('#fingerprintSettings').isVisible());
    await page.locator('#browserObservationStartButton').click();
    await page.waitForFunction(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').length===3);
    check(`${width}: observation uses the active Chrome type and named profile instead of the global fingerprint preference`,await page.evaluate(()=>{const call=fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').at(-1);return call.body.browser==='chrome'&&call.body.workspaceId==='synthetic-chrome-environment'&&call.body.launch===true;}));
    check(`${width}: link action names the running environment`,await page.locator('#browserObservationLinkButton').textContent()==='生成当前环境检测链接');
    await page.locator('#browserObservationLinkButton').click();
    await page.waitForFunction(()=>fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').length===4);
    check(`${width}: link-only observation retains the active Chrome environment and launches nothing`,await page.evaluate(()=>{const call=fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').at(-1);return call.body.browser==='chrome'&&call.body.workspaceId==='synthetic-chrome-environment'&&call.body.launch===false;}));
    await page.evaluate(()=>{fixture.observation={status:'completed',report:{source:{requestedBrowser:'chrome'},summary:{status:'partial'},checks:[{id:'https-exit',label:'HTTPS 出口',status:'verified',value:'203.0.113.8',detail:'模拟 · 仅 UI 验收'}]}};tools.renderObservation(fixture.observation);tools.update();});
    await page.evaluate(()=>{fixture.state.connected=false;fixture.state.ready=false;tools.update();});
    check(`${width}: controller loss alone invalidates measured green results`,await page.locator('#browserObservationResults [data-state="verified"]').count()===0&&/失效/.test(await page.locator('#browserObservationSummary').textContent()));
    await page.close();
  }
  check('no renderer errors',report.errors.length===0);
} finally {await browser.close();await new Promise(resolve=>server.close(resolve));await writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({output,checks:report.checks.length,passed:report.checks.filter(check=>check.passed).length,errors:report.errors}));}
