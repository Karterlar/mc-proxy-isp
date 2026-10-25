// Exercise the real controller static allowlist and real workspace renderer.
// All application inventory is synthetic; all network traffic is loopback-only.
// Run: node desktop/test/application-icons-dom-acceptance.mjs
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { startController } from '../../backend/src/local-controller.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const require = createRequire(import.meta.url);
let playwright;
for (const candidate of [process.env.PLAYWRIGHT_MODULE, 'playwright'].filter(Boolean)) {
  try { playwright = require(candidate); break; } catch {}
}
assert.ok(playwright, 'An existing Playwright installation is required; nothing is downloaded');
let executablePath;
for (const candidate of [process.env.BROWSER_BIN, 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean)) {
  try { await access(candidate); executablePath = candidate; break; } catch {}
}
assert.ok(executablePath, 'An existing Chromium browser is required; nothing is downloaded');
await mkdir(path.join(root, '.cache', 'application-icons-review'), { recursive: true });
const output = await mkdtemp(path.join(root, '.cache', 'application-icons-review', 'run-'));
const controller = await startController({ mock: true, port: 0, runtimeRoot: path.join(output, 'isolated-runtime'), licenseConfig: { version: 1, mode: 'development' } });
const origin = new URL(controller.controlUrl()).origin;
const report = { kind: 'real controller HTTP/CSP and browser rendering; synthetic application inventory', network: 'loopback only', checks: [], images: [], screenshots: [], errors: [] };
let browser;
function check(name, pass) { report.checks.push({ name, pass }); assert.ok(pass, name); }
try {
  const brands = (await readdir(path.join(root, 'frontend/assets/brands'))).filter(name => /\.(png|svg)$/.test(name));
  for (const name of brands) {
    const response = await fetch(`${origin}/assets/brands/${name}`);
    check(`${name}: actual controller responds with the bundled image`, response.status === 200 && Buffer.from(await response.arrayBuffer()).equals(await readFile(path.join(root, 'frontend/assets/brands', name))));
  }
  browser = await playwright.chromium.launch({ executablePath, headless: true, args: ['--no-first-run', '--no-default-browser-check'] });
  for (const [width, height] of [[1080, 800], [380, 760]]) {
    const page = await browser.newPage({ viewport: { width, height }, reducedMotion: 'reduce', locale: 'zh-CN' });
    page.on('pageerror', cause => report.errors.push(cause.message));
    await page.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
    await page.addInitScript(() => {
      window.coworkCalls=[];
      window.coworkState={present:true,state:'running',startMode:'automatic',identity:'verified',systemAccount:true,mock:false,canRestore:false};
      window.mcDesktop = {
        getApplications: async () => ({ mock: true, processStatus: 'known', applications: ['claude-desktop', 'codex-desktop', 'claude-code', 'codex-cli', 'terminal'].map(id => ({ id, installed: true, launchable: true, running: 0 })) }),
        launchApplication: async () => ({ started: true, mock: true }),
        getClaudeBackground: async () => {coworkCalls.push('inspect');return structuredClone(coworkState);},
        openClaudeServices: async () => {coworkCalls.push('open');return {opened:true,mock:false};},
        disableClaudeStartup: async () => {coworkCalls.push('disable');coworkState={...coworkState,startMode:'disabled',canRestore:true,changed:true};return structuredClone(coworkState);},
        restoreClaudeStartup: async () => {coworkCalls.push('restore');coworkState={...coworkState,startMode:'automatic',canRestore:false,changed:true,persistedStartupDisabled:false,restartRequired:false};return structuredClone(coworkState);},
      };
    });
    await page.goto(controller.controlUrl());
    await page.waitForFunction(() => document.querySelector('#appFrame').dataset.currentScreen !== 'splash');
    // This invokes the production navigation and inventory handlers even on first run.
    await page.evaluate(() => document.querySelector('#workspaceApplicationButton').click());
    await page.waitForSelector('#applicationList .application-row');
    check(`${width}: all five real application rows render`, await page.locator('#applicationList .application-row').count() === 5);
    check(`${width}: Cowork is never inspected or changed automatically`, await page.evaluate(()=>coworkCalls.length===0));
    await page.locator('#claudeBackgroundPanel summary').click();
    await page.locator('#checkClaudeBackgroundButton').click();
    await page.waitForFunction(()=>document.querySelector('#claudeBackgroundStatus').textContent.includes('官方 Anthropic 签名有效'));
    check(`${width}: service report separates SYSTEM and automatic startup`, await page.locator('#claudeBackgroundStatus').textContent().then(text=>text.includes('系统权限运行')&&text.includes('开机自动启动')));
    check(`${width}: original settings cannot be restored before this app changes them`, await page.locator('#restoreClaudeStartupButton').isDisabled());
    await page.locator('#disableClaudeStartupButton').click();
    await page.waitForFunction(()=>document.querySelector('#claudeBackgroundStatus').textContent.includes('当前服务仍在运行'));
    check(`${width}: disable startup does not claim the running service stopped`, await page.locator('#claudeBackgroundStatus').textContent().then(text=>text.includes('没有中断任务')));
    await page.locator('#restoreClaudeStartupButton').click();
    await page.waitForFunction(()=>document.querySelector('#claudeBackgroundStatus').textContent.includes('原服务启动设置已恢复'));
    check(`${width}: no unsupported registry-write control is delivered`, await page.locator('#disableClaudeStartupCompatButton').count()===0);
    await page.evaluate(()=>{coworkState={present:false,state:'unknown',startMode:'unknown',identity:'unknown',code:'CLAUDE_BACKGROUND_CHECK_FAILED'};});
    await page.locator('#checkClaudeBackgroundButton').click();
    await page.waitForFunction(()=>document.querySelector('#claudeBackgroundStatus').textContent.includes('不能判断服务是否存在'));
    check(`${width}: service query failure remains unknown rather than not installed`, !await page.locator('#claudeBackgroundStatus').textContent().then(text=>text.includes('未发现')));
    check(`${width}: all service actions required explicit user clicks`, await page.evaluate(()=>coworkCalls.join(',')==='inspect,disable,restore,inspect'));
    const images = page.locator('#websiteShortcuts img, #applicationList img');
    check(`${width}: six website and four native-app brand images are present`, await images.count() === 10);
    for (let index = 0; index < await images.count(); index++) {
      const image = images.nth(index);
      await image.scrollIntoViewIfNeeded();
      await image.evaluate(node => node.decode());
      const state = await image.evaluate(node => {
        const rect = node.getBoundingClientRect(), style = getComputedStyle(node);
        return { src: new URL(node.currentSrc).pathname, complete: node.complete, naturalWidth: node.naturalWidth, naturalHeight: node.naturalHeight, width: rect.width, height: rect.height, display: style.display, visibility: style.visibility };
      });
      report.images.push({ viewport: width, ...state });
      check(`${width}: ${state.src} decodes and is visible`, state.complete && state.naturalWidth > 0 && state.naturalHeight > 0 && state.width >= 20 && state.height >= 20 && state.display !== 'none' && state.visibility === 'visible' && await image.isVisible());
    }
    for (const section of ['websiteShortcuts', 'applicationList']) {
      await page.locator(`#${section}`).scrollIntoViewIfNeeded();
      const name = `${width}-${section}.png`;
      await page.screenshot({ path: path.join(output, name), animations: 'disabled' });
      report.screenshots.push(name);
    }
    for (const selected of ['chrome', 'edge', 'fingerprint']) {
      await page.locator('#applicationBrowserChoice').selectOption(selected);
      const label = { chrome: 'Chrome', edge: 'Edge', fingerprint: '指纹浏览器' }[selected];
      check(`${width}: launch label identifies the selected ${selected} engine`, await page.locator('#safeAccessTitle').textContent() === `打开${label}`);
      if (selected === 'fingerprint') {
        check(`${width}: fingerprint choice displays its own symbol`, await page.locator('#applicationFingerprintIcon').isVisible() && !await page.locator('#applicationBrowserIcon').isVisible());
      } else {
        const icon = page.locator('#applicationBrowserIcon');
        await page.waitForFunction(name => {
          const node = document.querySelector('#applicationBrowserIcon');
          return node.complete && node.naturalWidth > 0 && node.currentSrc.endsWith(`/${name}.png`);
        }, selected);
        check(`${width}: ${selected} compatibility choice displays its local icon`, await icon.isVisible() && await icon.evaluate((node, name) => node.naturalWidth > 0 && node.currentSrc.endsWith(`/${name}.png`), selected));
      }
    }
    check(`${width}: no horizontal overflow`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
    await page.close();
  }
  check('no renderer errors', report.errors.length === 0);
} finally {
  await browser?.close();
  await controller.shutdown();
  await new Promise(resolve => controller.close(resolve));
  await writeFile(path.join(output, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ output, checks: report.checks.length, passed: report.checks.filter(item => item.pass).length, errors: report.errors }));
}
