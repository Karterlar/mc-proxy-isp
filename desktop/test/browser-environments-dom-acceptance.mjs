// Actual product markup and component logic; synthetic APIs and loopback assets only.
// Run: node desktop/test/browser-environments-dom-acceptance.mjs
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';

const root=path.resolve(import.meta.dirname,'../..'),require=createRequire(import.meta.url);
let playwright,executablePath;
for(const candidate of [process.env.PLAYWRIGHT_MODULE,'playwright'].filter(Boolean))try{playwright=require(candidate);break;}catch{}
for(const candidate of [process.env.BROWSER_BIN,'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean))try{await access(candidate);executablePath=candidate;break;}catch{}
assert.ok(playwright&&executablePath,'An existing Playwright module and Chromium browser are required');
const output=path.join(root,'.cache','browser-environments-review',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const report={mode:'synthetic UI acceptance',network:'loopback only',checks:[],screenshots:[],errors:[]};
const check=(name,passed)=>{report.checks.push({name,passed:Boolean(passed)});assert.ok(passed,name);};
const server=createServer(async(req,res)=>{
  try{
    const pathname=new URL(req.url,'http://localhost').pathname;
    if(pathname==='/app.js'){res.writeHead(200,{'content-type':'text/javascript'});res.end('');return;}
    const file=path.resolve(root,'frontend','.'+(pathname==='/'?'/index.html':decodeURIComponent(pathname)));
    if(!file.startsWith(path.join(root,'frontend')+path.sep))throw Error('Outside asset directory');
    res.writeHead(200,{'content-type':({'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png'})[path.extname(file)]||'application/octet-stream'});res.end(await readFile(file));
  }catch{res.writeHead(404);res.end();}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin=`http://127.0.0.1:${server.address().port}`,browser=await playwright.chromium.launch({executablePath,headless:true,args:['--no-first-run','--no-default-browser-check','--disable-background-networking']});
let page;
try{
  for(const [width,height]of [[1080,800],[380,650]]){
    page=await browser.newPage({viewport:{width,height},locale:'zh-CN',reducedMotion:'reduce'});
    page.on('pageerror',error=>report.errors.push(error.message));
    await page.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
    await page.goto(origin);
    await page.evaluate(async()=>{
      window.fixture={calls:[],notices:[],navigation:[],state:{connected:true,busy:false,modal:false,status:{license:{allowed:true},proxy:{running:false},browser:{running:false}}},workspaces:{items:[],configured:true,pinned:true,activeId:null,limits:{active:24,total:96},defaultBrowser:'chrome',defaultIdentity:{language:'auto',timezone:'auto',nativeGraphics:false}},next:1,failSave:false};
      const f=window.fixture,{createExperienceTools}=await import('/experience-tools.js');
      const copy=value=>structuredClone(value);
      const request=async(endpoint,body)=>{
        f.calls.push({endpoint,body:copy(body)});
        if(endpoint==='/api/workspaces')return copy(f.workspaces);
        if(endpoint==='/api/reminders')return{items:[],noticeCount:0};
        if(endpoint==='/api/workspaces/create'){
          if(f.failSave)throw Error('模拟保存失败，原资料未改动');
          const item={id:'environment-'+f.next++,name:body.name,browser:body.browser,services:body.services,identity:{version:1,language:'auto',timezone:'auto',nativeGraphics:false,...body.identity},bindingMatches:true,archivedAt:null};f.workspaces.items.push(item);return copy(item);
        }
        const item=f.workspaces.items.find(item=>item.id===(body?.id||body?.workspaceId));
        if(endpoint==='/api/workspaces/update'){if(Object.hasOwn(body,'browser'))throw Error('Browser type is immutable');Object.assign(item,{name:body.name||item.name,services:body.services||item.services,identity:{...item.identity,...body.identity},bindingMatches:true});return copy(item);}
        if(endpoint==='/api/workspaces/replace'){
          item.archivedAt=new Date().toISOString();const replacement={...copy(item),id:'environment-'+f.next++,name:item.name+' · 替代环境',archivedAt:null,replacesId:item.id};f.workspaces.items.push(replacement);return{...copy(f.workspaces),workspace:copy(replacement)};
        }
        if(endpoint==='/api/workspaces/archive'){item.archivedAt=new Date().toISOString();return copy(f.workspaces);}
        if(endpoint==='/api/workspaces/restore'){item.archivedAt=null;return copy(f.workspaces);}
        if(endpoint==='/api/workspaces/start'){f.workspaces.activeId=item.id;f.state.status.proxy.running=true;f.state.status.browser={running:true,browser:item.browser||'fingerprint',workspaceId:item.id};return{workspaceId:item.id,mock:true};}
        if(endpoint==='/api/browser/fingerprint/rotate')return{rotated:true,workspaceId:body.workspaceId};
        if(endpoint==='/api/browser-observation/start'){item.lastObservation={workspaceId:item.id,observedAt:new Date().toISOString(),status:'measured'};return{status:'waiting'};}
        throw Error('Unexpected endpoint: '+endpoint);
      };
      const operation=async(label,action,kind)=>{f.state.busy=true;f.state.operationKind=kind;window.experience.update();try{await action();return true;}catch(error){f.notices.push(error.message);return false;}finally{f.state.busy=false;window.experience.update();}};
      const confirm=(title,message,callback)=>{f.state.modal=true;document.querySelector('#modalTitle').textContent=title;document.querySelector('#modalBody').textContent=message;document.querySelector('#confirmModal').hidden=false;f.pending=callback;window.experience.update();};
      window.experience=createExperienceTools({request,operation,confirm,notice:message=>f.notices.push(message),getState:()=>f.state,navigate:(...args)=>f.navigation.push(args),cancel:()=>{},afterImport:async()=>{},desktop:{}});
      document.querySelector('#modalConfirm').addEventListener('click',()=>{const callback=f.pending;f.pending=null;f.state.modal=false;document.querySelector('#confirmModal').hidden=true;callback();});
      document.querySelector('#modalCancel').addEventListener('click',()=>{f.pending=null;f.state.modal=false;document.querySelector('#confirmModal').hidden=true;window.experience.update();});
      document.querySelectorAll('[data-screen]').forEach(node=>node.hidden=node.dataset.screen!=='workspaces');document.querySelector('#appFrame').dataset.currentScreen='workspaces';
      document.querySelector('#appHeader').hidden=false;document.querySelector('#workspaceNav').hidden=false;
      await window.experience.refresh();
    });
    const idle=()=>page.waitForFunction(()=>!fixture.state.busy&&!fixture.state.modal);
    const more=id=>page.locator(`[data-select="${id}"]`).locator('..').locator('.workspace-more summary');
    const resetRunning=()=>page.evaluate(()=>{fixture.state.status.browser={running:false};fixture.workspaces.activeId=null;experience.update();});
    check(`${width}: explicit user-environment entry and first-use guide`,await page.locator('#workspaceSpacesButton').textContent()==='用户浏览器环境'&&await page.locator('#workspaceFirstGuide').isVisible());
    await page.locator('#workspaceNew').click();
    check(`${width}: new environment recommends Chrome with fixed login data and hides fingerprint controls`,await page.locator('#workspaceBrowser').inputValue()==='chrome'&&await page.locator('#workspaceBrowser').isEnabled()&&!await page.locator('#workspaceIdentityFields').isVisible()&&/固定独立资料.*登录/.test(await page.locator('#workspaceBrowserHint').textContent()));
    await page.locator('#workspaceBrowser').selectOption('fingerprint');
    check(`${width}: new environment uses defaults and has no provider credential inputs`,await page.locator('#workspaceLanguage').inputValue()==='auto'&&await page.locator('#workspaceCanvasProtection').isChecked()&&await page.locator('#workspaceEditor input[type=password]').count()===0);
    check(`${width}: seeded graphics correction note retains the default protection and existing data`,await page.locator('#workspaceCanvasWarning').isVisible()&&/Canvas 读回修正.*环境种子与登录资料保留/.test(await page.locator('#workspaceCanvasWarning').textContent())&&/种子 Canvas 与布局保护/.test(await page.locator('.workspace-graphics-choice').textContent()));
    await page.locator('#workspaceName').fill('客户 A');await page.locator('#workspaceLanguage').selectOption('ja-JP');await page.locator('#workspaceTimezone').selectOption('Asia/Tokyo');await page.locator('#workspaceCanvasProtection').uncheck();
    check(`${width}: native graphics hides the seeded compatibility warning`,!await page.locator('#workspaceCanvasWarning').isVisible());
    await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: first save persists the chosen per-environment identity and selects its open action`,await page.evaluate(()=>{const call=fixture.calls.find(call=>call.endpoint==='/api/workspaces/create');return call.body.identity.version===1&&call.body.identity.language==='ja-JP'&&call.body.identity.timezone==='Asia/Tokyo'&&call.body.identity.nativeGraphics===true;})&&await page.locator('#workspaceStart').evaluate(el=>el===document.activeElement));
    check(`${width}: card presents language, timezone, graphics, binding and explicit undetected state`,/ja-JP.*Asia\/Tokyo.*真实 Canvas.*已绑定 ISP.*未检测/s.test(await page.locator('#workspaceList').textContent()));
    await page.locator('#workspaceNew').click();
    check(`${width}: another user starts from defaults rather than the previous user's identity`,await page.locator('#workspaceLanguage').inputValue()==='auto'&&await page.locator('#workspaceTimezone').inputValue()==='auto'&&await page.locator('#workspaceCanvasProtection').isChecked());
    check(`${width}: another new environment still defaults to Chrome`,await page.locator('#workspaceBrowser').inputValue()==='chrome');
    await page.locator('#workspaceBrowser').selectOption('fingerprint');
    await page.locator('#workspaceName').fill('<img src=x onerror=alert(1)>');await page.evaluate(()=>fixture.failSave=true);await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: failed save preserves the draft and existing environment`,await page.locator('#workspaceEditor').isVisible()&&await page.locator('#workspaceName').inputValue()==='<img src=x onerror=alert(1)>'&&await page.locator('#workspaceList .workspace-card').count()===1);
    await page.evaluate(()=>fixture.failSave=false);await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: environment names cannot inject HTML`,await page.locator('#workspaceList img').count()===0&&/\<img/.test(await page.locator('#workspaceSelectedTitle').textContent()));
    await more('environment-1').click();await page.locator('[data-edit="environment-1"]').click();
    check(`${width}: existing fingerprint browser type is visible and locked`,await page.locator('#workspaceBrowser').inputValue()==='fingerprint'&&await page.locator('#workspaceBrowser').isDisabled());
    check(`${width}: edit reads this environment's saved identity`,await page.locator('#workspaceLanguage').inputValue()==='ja-JP'&&await page.locator('#workspaceTimezone').inputValue()==='Asia/Tokyo'&&!await page.locator('#workspaceCanvasProtection').isChecked()&&!await page.locator('#workspaceCanvasWarning').isVisible());
    await page.locator('#workspaceLanguage').selectOption('en-US');await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: edit only updates its own identity without changing the browser`,await page.evaluate(()=>fixture.workspaces.items[0].identity.language==='en-US'&&fixture.workspaces.items[1].identity.language==='auto'&&fixture.calls.filter(call=>call.endpoint==='/api/workspaces/update').every(call=>!Object.hasOwn(call.body,'browser'))));
    await page.evaluate(async()=>{delete fixture.workspaces.items[0].browser;await experience.refresh();});
    check(`${width}: legacy environments without browser retain fingerprint actions`,await page.locator('[data-rotate="environment-1"]').count()===1&&await page.locator('[data-select="environment-1"]').locator('..').getAttribute('data-browser')==='fingerprint');
    await page.locator('[data-start="environment-1"]').click();await idle();
    check(`${width}: card open uses its own environment without a hidden global choice`,await page.evaluate(()=>fixture.state.status.browser.workspaceId==='environment-1'));
    await more('environment-1').click();
    check(`${width}: a running environment cannot be edited, replaced or archived`,await page.locator('[data-edit="environment-1"]').isDisabled()&&await page.locator('[data-replace="environment-1"]').isDisabled()&&await page.locator('[data-archive="environment-1"]').isDisabled());
    await page.locator('[data-select="environment-2"]').click();
    check(`${width}: detecting another environment cannot close the running one`,await page.locator('#workspaceObserve').isDisabled()&&await page.evaluate(()=>fixture.state.status.browser.workspaceId==='environment-1'));
    await more('environment-2').click();check(`${width}: another running environment also prevents fingerprint rotation`,await page.locator('[data-rotate="environment-2"]').isDisabled());
    await page.locator('[data-select="environment-1"]').click();await page.locator('#workspaceObserve').click();await idle();
    check(`${width}: detection is explicitly bound to the current user environment`,await page.evaluate(()=>{const call=fixture.calls.find(call=>call.endpoint==='/api/browser-observation/start');return call.body.workspaceId==='environment-1'&&call.body.browser==='fingerprint'&&call.body.launch===true;})&&/已采集/.test(await page.locator('#workspaceList').textContent())&&!/匹配成功/.test(await page.locator('#workspaceList').textContent()));
    await more('environment-1').click();await page.locator('[data-rotate="environment-1"]').click();
    check(`${width}: rotate confirmation distinguishes retained site data from a new environment`,/Cookie.*网站存储.*保留/s.test(await page.locator('#modalBody').textContent())&&/创建替代环境/.test(await page.locator('#modalBody').textContent()));
    await page.locator('#modalConfirm').click();await idle();check(`${width}: rotation targets only the chosen identity`,await page.evaluate(()=>fixture.calls.find(call=>call.endpoint==='/api/browser/fingerprint/rotate').body.workspaceId==='environment-1'));
    await resetRunning();await page.locator('[data-replace="environment-1"]').click();
    check(`${width}: replacement confirmation clearly discloses blank data and retained archive`,/不继承 Cookie.*旧环境.*归档/s.test(await page.locator('#modalBody').textContent()));
    await page.locator('#modalCancel').click();check(`${width}: cancel replacement creates nothing`,await page.evaluate(()=>fixture.workspaces.items.length===2&&!fixture.calls.some(call=>call.endpoint==='/api/workspaces/replace')));
    await page.locator('[data-replace="environment-1"]').click();await page.locator('#modalConfirm').click();await idle();
    check(`${width}: replacement selects its new environment and exposes the original as recoverable archive`,await page.locator('[data-select="environment-3"]').getAttribute('aria-pressed')==='true'&&await page.locator('#workspaceList [data-select="environment-1"]').count()===0&&await page.locator('#workspaceArchiveCount').textContent()==='1');
    await page.locator('#workspaceArchives summary').click();await page.locator('[data-restore="environment-1"]').click();await idle();
    check(`${width}: restore recovers and selects the same original environment`,await page.locator('[data-select="environment-1"]').getAttribute('aria-pressed')==='true'&&await page.evaluate(()=>fixture.workspaces.items[0].identity.language==='en-US'&&!fixture.workspaces.items[0].archivedAt));
    await more('environment-2').click();await page.locator('[data-archive="environment-2"]').click();await page.locator('#modalConfirm').click();await idle();
    check(`${width}: archive retains the saved identity and adds a restore action`,await page.locator('#workspaceArchiveCount').textContent()==='1'&&await page.evaluate(()=>fixture.workspaces.items.find(item=>item.id==='environment-2').identity.language==='auto'));
    await page.evaluate(async()=>{fixture.workspaces.limits.active=2;await experience.refresh();});
    check(`${width}: active limit blocks creation and restoration but still permits replacement`,await page.locator('#workspaceNew').isDisabled()&&await page.locator('[data-restore="environment-2"]').isDisabled()&&await page.locator('[data-replace="environment-1"]').isEnabled());
    await page.evaluate(async()=>{fixture.workspaces.limits.total=3;await experience.refresh();});
    check(`${width}: retained-archive total limit also stops replacements`,await page.locator('[data-replace="environment-1"]').isDisabled());
    await page.evaluate(async()=>{fixture.workspaces.limits={active:24,total:96};fixture.workspaces.items[0].bindingMatches=false;await experience.refresh();});
    check(`${width}: a changed ISP disables launch and detection until explicitly rebound`,await page.locator('#workspaceStart').isDisabled()&&await page.locator('#workspaceObserve').isDisabled()&&await page.locator('[data-start="environment-1"]').isDisabled()&&/当前 ISP 不匹配/.test(await page.locator('#workspaceList').textContent()));
    await more('environment-1').click();await page.locator('[data-rebind="environment-1"]').click();await page.locator('#modalConfirm').click();await idle();
    check(`${width}: ISP reassignment requires confirmation and preserves the environment identity`,await page.evaluate(()=>fixture.calls.some(call=>call.endpoint==='/api/workspaces/update'&&call.body.id==='environment-1'&&call.body.rebind===true)&&fixture.workspaces.items[0].identity.language==='en-US')&&await page.locator('#workspaceStart').isEnabled());
    await page.locator('#workspaceNew').click();
    check(`${width}: Chrome new environment hides all fingerprint language/timezone/Canvas controls`,await page.locator('#workspaceBrowser').inputValue()==='chrome'&&!await page.locator('#workspaceIdentityFields').isVisible()&&!await page.locator('#workspaceCanvasWarning').isVisible());
    await page.locator('#workspaceName').fill('Chrome 日常账号');await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: Chrome create saves its browser type without hidden identity overrides`,await page.evaluate(()=>{const call=fixture.calls.filter(call=>call.endpoint==='/api/workspaces/create').at(-1);return call.body.browser==='chrome'&&!Object.hasOwn(call.body,'identity');}));
    const chromeCard=page.locator('[data-select="environment-4"]').locator('..');
    check(`${width}: Chrome card promises persistent login data and has no fingerprint rotation`,/Chrome.*固定独立登录资料/s.test(await chromeCard.textContent())&&!/种子 Canvas/.test(await chromeCard.textContent())&&await chromeCard.locator('[data-rotate]').count()===0);
    await more('environment-4').click();await page.locator('[data-edit="environment-4"]').click();
    check(`${width}: editing Chrome locks its type and explains preserving existing data`,await page.locator('#workspaceBrowser').inputValue()==='chrome'&&await page.locator('#workspaceBrowser').isDisabled()&&!await page.locator('#workspaceIdentityFields').isVisible()&&/保留同一份登录资料/.test(await page.locator('#workspaceBrowserHint').textContent()));
    await page.locator('#workspaceName').fill('Chrome 工作账号');await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: Chrome edit omits browser and fingerprint identity fields`,await page.evaluate(()=>{const call=fixture.calls.filter(call=>call.endpoint==='/api/workspaces/update'&&call.body.id==='environment-4').at(-1);return !Object.hasOwn(call.body,'browser')&&!Object.hasOwn(call.body,'identity');}));
    await page.locator('[data-start="environment-4"]').click();await idle();
    check(`${width}: running Chrome environment can be observed without a fingerprint-only gate`,await page.locator('#workspaceObserve').isEnabled());
    await page.locator('#workspaceObserve').click();await idle();
    check(`${width}: Chrome observation uses the same environment and actual browser type`,await page.evaluate(()=>{const call=fixture.calls.filter(call=>call.endpoint==='/api/browser-observation/start').at(-1);return call.body.browser==='chrome'&&call.body.workspaceId==='environment-4'&&call.body.launch===true&&fixture.state.status.browser.workspaceId==='environment-4';}));
    await resetRunning();await page.locator('[data-replace="environment-4"]').click();
    check(`${width}: replacing Chrome explains blank data without claiming a new fingerprint`,/继续使用 Chrome.*不继承 Cookie/s.test(await page.locator('#modalBody').textContent())&&!/新指纹/.test(await page.locator('#modalBody').textContent()));
    await page.locator('#modalConfirm').click();await idle();
    check(`${width}: Chrome replacement retains browser type`,await page.evaluate(()=>fixture.workspaces.items.find(item=>item.id==='environment-5').browser==='chrome'));
    await page.locator('#workspaceNew').click();await page.locator('#workspaceBrowser').selectOption('edge');await page.locator('#workspaceName').fill('Edge 工作账号');await page.locator('#workspaceEditor button[type=submit]').click();await idle();
    check(`${width}: Edge is independently selectable without fingerprint controls`,await page.locator('[data-select="environment-6"]').locator('..').getAttribute('data-browser')==='edge'&&await page.locator('[data-rotate="environment-6"]').count()===0&&await page.evaluate(()=>fixture.calls.filter(call=>call.endpoint==='/api/workspaces/create').at(-1).body.browser==='edge'));
    await page.evaluate(async()=>{fixture.workspaces.defaultBrowser='fingerprint';await experience.refresh();});await page.locator('#workspaceNew').click();
    check(`${width}: explicit fingerprint creation preference remains honored`,await page.locator('#workspaceBrowser').inputValue()==='fingerprint'&&await page.locator('#workspaceIdentityFields').isVisible());
    await page.locator('#workspaceEditorCancel').click();
    await page.evaluate(async()=>{delete fixture.workspaces.defaultBrowser;await experience.refresh();});await page.locator('#workspaceNew').click();
    check(`${width}: absent creation preference safely falls back to Chrome`,await page.locator('#workspaceBrowser').inputValue()==='chrome');await page.locator('#workspaceEditorCancel').click();
    // End the boundary fixtures before taking normal-state component previews.
    await page.evaluate(async()=>{
      const f=fixture;f.workspaces.limits={active:24,total:96};
      Object.assign(f.workspaces.items[0],{name:'客户 A · 日本账号',identity:{version:1,language:'ja-JP',timezone:'Asia/Tokyo',nativeGraphics:false},bindingMatches:true});
      Object.assign(f.workspaces.items[1],{name:'客户 A · 原环境'});
      Object.assign(f.workspaces.items[2],{name:'客户 B · 香港账号',identity:{version:1,language:'zh-HK',timezone:'Asia/Hong_Kong',nativeGraphics:false}});
      f.state.status.browser={running:true,browser:'fingerprint',workspaceId:'environment-1'};f.workspaces.activeId='environment-1';
      document.querySelector('#workspaceConnectionButton').removeAttribute('aria-current');document.querySelector('#workspaceSpacesButton').setAttribute('aria-current','page');
      document.querySelector('#serviceStatus').textContent='组件预览 · 模拟资料';
      await experience.refresh();
    });
    await page.locator('#workspacesContent').evaluate(el=>el.scrollTop=0);
    const metrics=await page.evaluate(()=>({document:document.documentElement.scrollWidth,width:innerWidth,content:document.querySelector('#workspacesContent').scrollWidth,client:document.querySelector('#workspacesContent').clientWidth,fonts:[...document.querySelectorAll('#workspaceList button,#workspaceEditor select')].every(el=>getComputedStyle(el).fontFamily===getComputedStyle(document.body).fontFamily)}));
    check(`${width}: environment cards fit the viewport and use the common UI font`,metrics.document<=metrics.width+2&&metrics.content<=metrics.client+2&&metrics.fonts);
    const screenshot=`user-environments-${width}x${height}.png`;await page.screenshot({path:path.join(output,screenshot),animations:'disabled'});report.screenshots.push(screenshot);
    if(width===1080){await page.locator('#workspaceList').scrollIntoViewIfNeeded();const cards='user-environments-cards-1080x800.png';await page.screenshot({path:path.join(output,cards),animations:'disabled'});report.screenshots.push(cards);}
    await page.close();page=null;
  }
  check('no renderer errors',report.errors.length===0);
}catch(error){report.errors.push(error.stack||error.message);if(page)await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});process.exitCode=1;}
finally{await browser.close();await new Promise(resolve=>server.close(resolve));await writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2));console.log(JSON.stringify({output,checks:report.checks.length,passed:report.checks.filter(check=>check.passed).length,errors:report.errors}));}
