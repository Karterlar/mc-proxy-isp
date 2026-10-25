// Loads the standalone permission gate with a synthetic bridge. No backend,
// UAC prompt, customer configuration, license or network settings are touched.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdir,readFile,writeFile,access} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

const root=path.resolve(import.meta.dirname,'..');
const output=path.join(root,'.cache','admin-gate-ui-acceptance',new Date().toISOString().replace(/[:.]/g,'-'));
await mkdir(output,{recursive:true});
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const report={mock:true,network:'no network; local file assets only',checks:[],screenshots:[],errors:[]};
const check=(name,value)=>{report.checks.push({name,passed:Boolean(value)});assert.ok(value,name);};
let browser,context,page;
try{
  let executablePath;
  for(const candidate of [process.env.BROWSER_BIN,'C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean))try{await access(candidate);executablePath=candidate;break;}catch{}
  assert.ok(executablePath,'A locally installed Chromium browser is required');
  browser=await chromium.launch({executablePath,headless:true,args:['--no-proxy-server','--disable-quic','--disable-background-networking','--webrtc-ip-handling-policy=disable_non_proxied_udp']});
  context=await browser.newContext({viewport:{width:620,height:660},locale:'zh-CN',reducedMotion:'reduce',serviceWorkers:'block'});
  const blocked=[];
  await context.route(/^https?:/,route=>{blocked.push(route.request().url());return route.abort();});
  await context.addInitScript(()=>{
    window.fixture={restartCalls:0,minimizeCalls:0,closeCalls:0,result:{canceled:true},holdInfo:true,holdRestart:false,throwRestart:false,throwClose:false};
    window.mcAdminGate={
      info:async()=>{if(window.fixture.holdInfo)await new Promise(resolve=>window.fixture.releaseInfo=resolve);if(window.fixture.throwInfo)throw new Error('synthetic private info failure');return{productName:'MC Proxy',version:'1.6.3',reason:window.fixture.reason||'admin-required'};},
      restart:async()=>{window.fixture.restartCalls++;if(window.fixture.holdRestart)await new Promise(resolve=>window.fixture.releaseRestart=resolve);if(window.fixture.throwRestart)throw new Error('synthetic private restart failure');return window.fixture.result;},
      minimize:async()=>{window.fixture.minimizeCalls++;},
      close:async()=>{window.fixture.closeCalls++;if(window.fixture.throwClose)throw new Error('synthetic private close failure');}
    };
  });
  page=await context.newPage();page.on('pageerror',error=>report.errors.push(error.message));page.setDefaultTimeout(8000);
  await page.goto(pathToFileURL(path.join(root,'frontend','admin-required.html')).href);
  check('checking state starts locked with restart disabled',await page.locator('#restartButton').isDisabled());
  check('checking state is announced',/正在检查/.test(await page.locator('#gateStatus').innerText()));
  check('no business controls or account form can be operated',await page.locator('input,select,textarea,form,a').count()===0);
  await page.evaluate(()=>window.fixture.releaseInfo());await page.locator('#restartButton:not([disabled])').waitFor();
  await page.evaluate(()=>document.fonts.ready);
  check('brand asset loads from local file',await page.locator('.brand img').evaluate(el=>el.complete&&el.naturalWidth>0));
  check('version is visible',await page.locator('#version').innerText()==='v1.6.3');
  check('initial keyboard focus is restart',await page.locator('#restartButton').evaluate(el=>el===document.activeElement));
  await page.keyboard.press('Escape');
  check('Escape does not dismiss or unlock the gate',await page.locator('#gateTitle').isVisible()&&await page.evaluate(()=>window.fixture.closeCalls===0));
  await page.keyboard.press('Tab');check('keyboard can reach exit',await page.locator('#exitButton').evaluate(el=>el===document.activeElement));
  await page.keyboard.press('Shift+Tab');check('keyboard can return to restart',await page.locator('#restartButton').evaluate(el=>el===document.activeElement));
  await page.keyboard.press('Shift+Tab');check('keyboard can reach title close',await page.locator('#closeWindow').evaluate(el=>el===document.activeElement));
  await page.keyboard.press('Shift+Tab');check('keyboard can reach title minimize',await page.locator('#minimizeWindow').evaluate(el=>el===document.activeElement));
  for(const [width,height]of[[620,660],[430,660],[380,660]]){
    await page.setViewportSize({width,height});
    const metrics=await page.evaluate(()=>({width:document.documentElement.scrollWidth,viewport:innerWidth,buttons:[...document.querySelectorAll('button')].map(el=>{const r=el.getBoundingClientRect();return{left:r.left,right:r.right,width:r.width,height:r.height};})}));
    check(`${width}px: no horizontal overflow`,metrics.width<=width+1);
    check(`${width}px: all action hit targets are inside the window`,metrics.buttons.every(r=>r.left>=0&&r.right<=width+1&&r.width>=44&&r.height>=33));
    const screenshot=`admin-required-${width}.png`;await page.screenshot({path:path.join(output,screenshot),fullPage:true,animations:'disabled'});report.screenshots.push(screenshot);
  }
  await page.setViewportSize({width:620,height:660});
  await page.evaluate(()=>{window.fixture.holdRestart=true;});
  await page.locator('#restartButton').press('Enter');await page.waitForFunction(()=>window.fixture.restartCalls===1);
  await page.evaluate(()=>{for(let i=0;i<20;i++)document.querySelector('#restartButton').click();});
  check('pending restart cannot submit again',await page.evaluate(()=>window.fixture.restartCalls===1)&&await page.locator('#restartButton').isDisabled());
  check('pending operation is announced',await page.locator('.actions').getAttribute('aria-busy')==='true'&&/Windows/.test(await page.locator('#gateStatus').innerText()));
  await page.evaluate(()=>{window.fixture.holdRestart=false;window.fixture.releaseRestart();});await page.locator('#restartButton:not([disabled])').waitFor();
  check('canceling UAC leaves the gate locked and permits retry',/取消/.test(await page.locator('#gateError').innerText())&&await page.locator('#gateTitle').isVisible());
  check('canceled restart returns focus to retry',await page.locator('#restartButton').evaluate(el=>el===document.activeElement));
  await page.evaluate(()=>{window.fixture.result={started:false,errorCode:'PRIVATE_BACKEND_ERROR'};});await page.locator('#restartButton').click();
  await page.waitForFunction(()=>window.fixture.restartCalls===2&&!document.querySelector('#restartButton').disabled);
  check('explicit launch failure displays a readable error',/管理员启动未完成/.test(await page.locator('#gateError').innerText()));
  check('backend error identifiers are not exposed',!await page.locator('body').innerText().then(t=>t.includes('PRIVATE_BACKEND_ERROR')));
  await page.evaluate(()=>{window.fixture.throwRestart=true;});await page.locator('#restartButton').click();
  await page.waitForFunction(()=>window.fixture.restartCalls===3&&!document.querySelector('#restartButton').disabled);
  check('IPC rejection keeps retry available and never automatically exits',await page.locator('#gateError').isVisible()&&await page.evaluate(()=>window.fixture.closeCalls===0));
  check('IPC failure does not display raw error content',!await page.locator('body').innerText().then(t=>t.includes('private restart')));
  await page.locator('#minimizeWindow').click();check('title minimize uses the bridge',await page.evaluate(()=>window.fixture.minimizeCalls===1));
  await page.evaluate(()=>{window.fixture.throwClose=true;});await page.locator('#exitButton').click();
  await page.waitForFunction(()=>document.querySelector('#gateError').textContent.includes('暂时无法退出'));
  check('exit IPC failure remains visible without hiding the gate',await page.locator('#gateTitle').isVisible());
  await page.evaluate(()=>{window.fixture.throwClose=false;});await page.locator('#closeWindow').click();
  check('title close exits through the same bridge as exit',await page.evaluate(()=>window.fixture.closeCalls===2));
  await page.evaluate(()=>{window.fixture.throwRestart=false;window.fixture.result={started:true};});await page.locator('#restartButton').click();
  await page.waitForFunction(()=>document.querySelector('#gateStatus').textContent.includes('正在等待新窗口'));
  check('successful elevation keeps the gate pending until main process transitions',await page.locator('#restartButton').isDisabled()&&await page.locator('#gateTitle').isVisible());
  const screenshot='admin-required-pending.png';await page.screenshot({path:path.join(output,screenshot),animations:'disabled'});report.screenshots.push(screenshot);
  await page.reload();await page.evaluate(()=>{window.fixture.reason='check-failed';window.fixture.releaseInfo();});await page.locator('#restartButton:not([disabled])').waitFor();
  check('failed permission detection explains the problem and permits elevation retry',/无法确认当前管理员权限/.test(await page.locator('#gateError').innerText())&&await page.locator('#restartButton').isEnabled());
  await page.reload();await page.evaluate(()=>{window.fixture.reason='account-changed';window.fixture.releaseInfo();});await page.waitForFunction(()=>document.querySelector('#gateTitle').textContent==='请使用原来的 Windows 账户');
  check('cross-account elevation remains locked and focuses an enabled exit',await page.locator('#restartButton').isDisabled()&&await page.locator('#exitButton').isEnabled()&&await page.locator('#exitButton').evaluate(el=>el===document.activeElement)&&/为了保留原配置与授权/.test(await page.locator('#gateDescription').innerText())&&/回到原来的 Windows 账户/.test(await page.locator('#gateStatus').innerText())&&!/选择“是”/.test(await page.locator('#gateHelp').innerText()));
  await page.locator('#restartButton').evaluate(el=>el.dispatchEvent(new MouseEvent('click',{bubbles:true})));
  check('cross-account gate cannot invoke restart even through a dispatched click',await page.evaluate(()=>window.fixture.restartCalls===0));
  await page.reload();await page.evaluate(()=>{window.fixture.throwInfo=true;window.fixture.releaseInfo();});await page.waitForFunction(()=>document.querySelector('#gateStatus').textContent.includes('读取失败'));
  check('info IPC failure is fail closed and exits remain available',await page.locator('#restartButton').isDisabled()&&await page.locator('#exitButton').isEnabled());
  check('renderer has no unhandled exceptions',report.errors.length===0);
  check('renderer makes no network requests',blocked.length===0);
  report.passed=report.checks.length;report.failed=0;
}catch(cause){report.failed=1;report.failure=cause.stack;throw cause;}finally{
  await writeFile(path.join(output,'report.json'),`${JSON.stringify(report,null,2)}\n`);
  await context?.close();await browser?.close();
  process.stdout.write(`${path.join(output,'report.json')}\n`);
}
