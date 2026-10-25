// Real Chromium DOM, synthetic localhost-only measurements. No customer route or account.
// Run: node desktop/test/browser-observation-dom-acceptance.mjs
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, access } from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { normalizeBrowserObservation, OBSERVATION_SOURCES } from '../../backend/src/browser-observation.mjs';

const require = createRequire(import.meta.url), root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
let playwright, executablePath;
for (const candidate of [process.env.PLAYWRIGHT_MODULE, 'playwright'].filter(Boolean)) {
  try { playwright = require(candidate); break; } catch {}
}
for (const candidate of [process.env.BROWSER_BIN, 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean)) {
  try { await access(candidate); executablePath = candidate; break; } catch {}
}
assert.ok(playwright && executablePath, 'Existing Playwright and Chromium are required; this test downloads nothing');
const binding = { revision: 1, configHash: 'dom-fixture', exitBinding: 'dom-fixture' };
const session = { binding, expectedExitIps: ['203.0.113.8'], browser: 'chrome', language: 'en-US', timezone: 'Asia/Tokyo' };
let expiresAt = Date.now() + 30000, contextFailed = false;
const server = createServer(async (req, res) => {
  const respond = (code, data) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(data)); };
  try {
    if (req.url === '/context') return respond(contextFailed ? 410 : 200, { ...session, expiresAt: new Date(expiresAt).toISOString(), sources: OBSERVATION_SOURCES, measurementMs: 45000, dnsProbe: null });
    if (req.url === '/report') {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      return respond(200, { saved: true, report: normalizeBrowserObservation(JSON.parse(Buffer.concat(chunks)), session) });
    }
    const filename = req.url === '/' ? 'browser-observation.html' : req.url.slice(1);
    if (!['browser-observation.html', 'browser-observation.js', 'browser-observation.css', 'browser-identity-probe.js'].includes(filename)) return respond(404, {});
    res.writeHead(200, { 'content-type': filename.endsWith('.html') ? 'text/html' : filename.endsWith('.js') ? 'text/javascript' : 'text/css' });
    res.end(await readFile(path.join(root, 'frontend', filename)));
  } catch { respond(500, {}); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const output = path.join(root, '.cache', 'browser-observation-review', new Date().toISOString().replace(/[:.]/g, '-'));
await mkdir(output, { recursive: true });
const browser = await playwright.chromium.launch({ executablePath, headless: true, args: ['--no-first-run', '--no-default-browser-check'] });
const report = { mode: 'synthetic localhost-only DOM fixture; not public network evidence', checks: [], errors: [] };
const check = (name, passed) => { report.checks.push({ name, passed }); assert.ok(passed, name); };
try {
  const page = await browser.newPage({ locale: 'en-US', timezoneId: 'Asia/Tokyo', viewport: { width: 1080, height: 800 } });
  page.on('pageerror', error => report.errors.push(error.message));
  await page.addInitScript(() => {
    window.RTCPeerConnection = class {
      createDataChannel() {} async createOffer() { return {}; }
      async setLocalDescription() { queueMicrotask(() => this.onicecandidate?.({ candidate: null })); }
      close() {}
    };
  });
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    if (url.hostname === 'api4.ipify.org') return route.fulfill({ contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: '{"ip":"203.0.113.8"}' });
    if (url.hostname === 'www.cloudflare.com') return route.fulfill({ contentType: 'text/plain', headers: { 'access-control-allow-origin': '*' }, body: 'ip=203.0.113.8\n' });
    return route.abort();
  });
  await page.goto(origin);
  await page.waitForFunction(() => document.querySelector('#copyButton').disabled === false);
  check('normal result renders measured cards', await page.locator('#results .check[data-state="verified"]').count() > 0);
  contextFailed = true;
  await page.locator('#runButton').click();
  await page.waitForFunction(() => document.querySelector('#progress').dataset.error === 'true');
  check('failed rerun removes previous successful cards', await page.locator('#results .check').count() === 0);
  check('failed rerun cannot copy the prior report', await page.locator('#copyButton').isDisabled());
  contextFailed = false; expiresAt = Date.now() + 1800;
  await page.reload();
  await page.waitForFunction(() => document.querySelector('#copyButton').disabled === false);
  check('new session can measure again after failure while missing identity evidence stays unverified',
    await page.locator('#results .check').count() > 10 && await page.locator('#results .check').filter({ hasText: 'HTTP 请求头与页面一致性' }).getAttribute('data-state') === 'unverified');
  await page.waitForFunction(() => /检测页面已过期/.test(document.querySelector('#progress').textContent), { timeout: 5000 });
  check('expiry removes all previously measured cards', await page.locator('#results .check').count() === 0);
  check('expiry disables rerun and copying', await page.locator('#runButton').isDisabled() && await page.locator('#copyButton').isDisabled());
  check('expiry clears temporary raw readings', /临时读数已清除/.test(await page.locator('#rawReadings').textContent()));
  check('no renderer errors', report.errors.length === 0);
  await page.screenshot({ path: path.join(output, 'expired.png') });
} finally {
  await browser.close(); await new Promise(resolve => server.close(resolve));
  await writeFile(path.join(output, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ output, checks: report.checks.length, passed: report.checks.filter(row => row.passed).length, errors: report.errors }));
}
