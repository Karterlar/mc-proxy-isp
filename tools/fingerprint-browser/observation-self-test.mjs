// Real browser + production diagnostic server/CSP. External network readings are
// synthetic; this verifies probe execution, not a customer ISP or account.
import assert from 'node:assert/strict';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
import { access, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createBrowserObservation } from '../../backend/src/browser-observation.mjs';
import { requireFingerprintRuntime, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { resolveWindowsPlatformVersion } from '../../backend/src/browser-identity.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
let executablePath;
for (const candidate of [process.env.BROWSER_BIN, path.join(root, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY, 'chrome.exe'), 'C:/Program Files/Google/Chrome/Application/chrome.exe', 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].filter(Boolean)) {
  try { await access(candidate); executablePath = candidate; break; } catch {}
}
assert.ok(executablePath, 'an existing browser is required; no download');
const directory = path.join(root, '.cache', 'browser-observation-production', new Date().toISOString().replace(/[:.]/g, '-'));
await mkdir(directory, { recursive: true });
const report = { mode: 'real production observer + real browser APIs; synthetic external exits, no public network or accounts', checks: [], errors: [], localResponses: [], blockedProxyRequests: [] };
const check = (name, passed) => { report.checks.push({ name, passed }); assert.ok(passed, name); };
let valid = true;
const observation = createBrowserObservation({ isCurrent: () => valid });
const binding = { revision: 1, configHash: 'production-observer-local-fixture', exitBinding: 'production-observer-local-fixture' };
const fingerprintEngine = executablePath === path.join(root, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY, 'chrome.exe');
const engine = fingerprintEngine ? await requireFingerprintRuntime(path.dirname(executablePath)) : null;
const platformVersion = fingerprintEngine ? (await resolveWindowsPlatformVersion()).version : null;
report.engine = { executable: executablePath, version: engine?.version || null, verified: engine?.verified === true, platformVersion, sandboxEnabled: true, graphics: 'native' };
let browser, endpoint, session;
const proxy = http.createServer((request, response) => { report.blockedProxyRequests.push(request.url); response.writeHead(502).end(); });
proxy.on('connect', (request, socket) => { report.blockedProxyRequests.push(`CONNECT ${request.url}`); socket.end('HTTP/1.1 502 Local fixture only\r\nConnection: close\r\n\r\n'); });
try {
  endpoint = await observation.endpoint();
  session = await observation.createSession({ binding, browser: 'chrome', language: 'en-US', timezone: 'Asia/Tokyo', expectedExitIps: ['203.0.113.8'] });
  await new Promise((resolve, reject) => { proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve); });
  console.log('Starting sandboxed native-graphics browser against local-only fixtures.');
  browser = await chromium.launch({ executablePath, timeout: 20000, headless: false, chromiumSandbox: true, proxy: { server: `http://127.0.0.1:${proxy.address().port}` }, args: [
    // Ordering matters: Playwright appends <-loopback> after its bypass option,
    // which cancels an earlier loopback exception. Match the production order.
    `--proxy-bypass-list=<-loopback>;127.0.0.1:${endpoint.port}`,
    ...(fingerprintEngine ? [
    '--fingerprint=1024', '--fingerprint-platform=windows', `--fingerprint-platform-version=${platformVersion}`,
    '--fingerprint-brand=Chrome', `--fingerprint-brand-version=${engine.version}`, '--lang=en-US', '--accept-lang=en-US', '--timezone=Asia/Tokyo',
    '--disable-spoofing=font,audio,gpu,canvas,clientrects',
  ] : [])] });
  const context = await browser.newContext();
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    if (url.origin === endpoint.origin) return route.continue();
    if (url.hostname === 'api4.ipify.org') return route.fulfill({ contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: '{"ip":"203.0.113.8"}' });
    if (url.hostname === 'www.cloudflare.com') return route.fulfill({ contentType: 'text/plain', headers: { 'access-control-allow-origin': '*' }, body: 'ip=203.0.113.8\n' });
    return route.abort();
  });
  await context.addInitScript(() => {
    window.RTCPeerConnection = class {
      createDataChannel() {} async createOffer() { return {}; }
      async setLocalDescription() { queueMicrotask(() => this.onicecandidate?.({ candidate: null })); } close() {}
    };
  });
  const page = await context.newPage();
  page.on('pageerror', error => report.errors.push(error.message));
  page.on('response', response => { if (response.url().startsWith(endpoint.origin)) report.localResponses.push({ path: new URL(response.url()).pathname.split('/').slice(3).join('/'), status: response.status() }); });
  await page.goto(session.url);
  await page.waitForFunction(() => document.querySelector('#copyButton')?.disabled === false, { timeout: 20000 });
  const result = observation.snapshot().report;
  report.observation = result;
  check('production server received the real browser report', !!result);
  check('page device memory is measured as a positive native approximation', Number.isFinite(result.browser.deviceMemory) && result.browser.deviceMemory > 0);
  for (const name of ['iframe', 'dedicatedWorker', 'sharedWorker']) {
    check(`${name} really executes under production CSP`, result.measurements.consistency.contexts[name].status === 'measured');
    check(`${name} agrees with the real main document`, result.checks.find(item => item.id === `identity-${name}`).status === 'verified');
    check(`${name} device memory agrees with the real main document`, result.measurements.consistency.contexts[name].surface.deviceMemory === result.browser.deviceMemory);
  }
  check('HTTP headers agree with JS including device memory, platform version and full browser versions', result.checks.find(item => item.id === 'identity-http').status === 'verified');
  const memoryHeaders = ['device-memory', 'sec-ch-device-memory'].filter(name => typeof result.measurements.consistency.headers[name] === 'string');
  check('server directly observed opted-in device memory Client Hints', memoryHeaders.length > 0 && memoryHeaders.every(name => Number(result.measurements.consistency.headers[name]) === result.browser.deviceMemory));
  check('screen and DPR agree across the real frame', result.checks.find(item => item.id === 'identity-screen').status === 'verified');
  check('collecting UA does not claim fingerprint success', result.checks.find(item => item.id === 'ua-ch').status === 'measured');
  check('unknown managed target is not called verified', result.checks.find(item => item.id === 'identity-target').status === 'unverified');
  check('zero synthetic ICE never proves no WebRTC leak', result.checks.find(item => item.id === 'webrtc').status === 'unverified');
  check('no script errors', report.errors.length === 0);
  await page.screenshot({ path: path.join(directory, 'diagnostic.png'), fullPage: true });
  observation.invalidate();
  check('invalidated token immediately refuses requests', (await fetch(session.url)).status === 410);
  check('invalidating evidence retains the narrow observer port', (await observation.endpoint()).port === endpoint.port);
  valid = false;
} catch (error) {
  report.errors.push(error.stack || error.message); process.exitCode = 1;
} finally {
  await browser?.close().catch(error => report.errors.push(`Browser cleanup: ${error.message}`)); await observation.close();
  proxy.closeAllConnections(); if (proxy.listening) await new Promise(resolve => proxy.close(resolve));
  if (report.errors.length) process.exitCode = 1;
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ directory, checks: report.checks.length, passed: report.checks.filter(item => item.passed).length, errors: report.errors }));
}
