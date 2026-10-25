// Headed acceptance through the ordinary manager and a self-reporting page.
// No CDP/automation flags, remote accounts, certificate exceptions, host network
// changes, or process-ownership bypasses. All browser traffic stays in fixtures.
import assert from 'node:assert/strict';
import path from 'node:path';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createBrowserManager } from '../../backend/src/browser-session.mjs';
import { requireFingerprintRuntime, inspectFingerprintRuntime, FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_LEGACY_RELEASE, FINGERPRINT_BROWSER_PREVIOUS_SOURCE_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { readCandidateRuntime } from './native-engine/candidate-runtime.mjs';

const project = fileURLToPath(new URL('../../', import.meta.url));
const legacyInput = process.env.MC_FP_LEGACY_ROOT;
const legacyRoot = legacyInput ? path.resolve(legacyInput) : null;
const legacyChoices = [
  [path.join(project, '.cache/fingerprint-browser-canvas-r1'), FINGERPRINT_BROWSER_LEGACY_RELEASE],
  [path.join(project, '.cache/fingerprint-browser-source-150-r1'), FINGERPRINT_BROWSER_PREVIOUS_SOURCE_RELEASE],
];
const legacyRelease = legacyChoices.find(([directory]) => directory.toLowerCase() === legacyRoot?.toLowerCase())?.[1];
if (legacyInput !== undefined && (!legacyInput
  || !path.isAbsolute(legacyInput) || !legacyRelease)) {
  throw new Error('MC_FP_LEGACY_ROOT requires one of the two fixed verified previous component paths');
}
const sourceCandidate = process.env.MC_FP_SOURCE_CANDIDATE === '1' ? await readCandidateRuntime(process.argv[2]) : null;
const engineRoot = sourceCandidate?.root || process.argv[2] || path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY);
const release = sourceCandidate?.release || FINGERPRINT_BROWSER_RELEASE;
const readRuntime = (root, options) => inspectFingerprintRuntime(root, { ...options, release });
await mkdir(path.join(project, '.cache'), { recursive: true });
const directory = await mkdtemp(path.join(project, '.cache', 'fingerprint-engine-acceptance-'));
const runtimeRoot = path.join(directory, 'runtime');
const report = { startedAt: new Date().toISOString(), engine: null, network: 'localhost fixtures only; no customer ISP, VPN, account or host network settings', checks: [], observations: [], errors: [] };
const check = (name, passed, details) => { report.checks.push({ name, passed, ...(details ? { details } : {}) }); assert.ok(passed, name); };
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const sockets = new Set();
const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); };
const closeServer = server => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); });
const token = randomBytes(24).toString('base64url'), prefix = `/s/${token}/`;
const nativeOnly = process.env.MC_FP_NATIVE_ONLY === '1';
report.graphicsAcceptance = nativeOnly ? 'native-only diagnostic; seeded Canvas not asserted' : 'seeded and native graphics';
let currentSample, pending, observerRequests = 0, fixtureProxyRequests = 0, fixtureConnectRequests = 0, observerViaProxy = 0, blockedBackgroundRequests = 0;

async function browserFacts() {
  const high = await navigator.userAgentData?.getHighEntropyValues(['platformVersion', 'uaFullVersion', 'fullVersionList']);
  return { language: navigator.language, languages: [...navigator.languages], timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, platform: navigator.platform, cores: navigator.hardwareConcurrency, userAgent: navigator.userAgent, platformVersion: high?.platformVersion, browserVersion: high?.uaFullVersion, brands: navigator.userAgentData?.brands, fullVersionList: high?.fullVersionList };
}

async function browserProbe(sampleId, prefix, settleMs = 0) {
  const stage = value => fetch(prefix + 'progress', { method: 'POST', body: JSON.stringify({ sampleId, stage: value }) });
  try {
    await stage('start');
    const facts = await browserFacts();
    await stage('facts');
    if (settleMs) { await new Promise(resolve => setTimeout(resolve, settleMs)); await stage('renderer-settled'); }
    const canvas = document.createElement('canvas'); canvas.width = 280; canvas.height = 100;
    const ctx = canvas.getContext('2d'); await stage('canvas-context');
    ctx.fillStyle = '#acd7ed'; ctx.fillRect(0, 0, 280, 100); ctx.fillStyle = '#235'; ctx.font = '18px Arial'; ctx.fillText('MC Proxy Canvas ♥ 漢字 123', 12, 42); ctx.fillStyle = 'rgba(236,32,43,.3)'; ctx.fillRect(38, 22, 85, 46);
    await stage('canvas-drawn');
    const canvasData = canvas.toDataURL();
    await stage('canvas');
    const element = document.createElement('span'); element.textContent = 'MC Proxy ClientRects 漢字'; element.style.cssText = 'position:absolute;left:12.34px;top:110.12px;font:17px Arial;transform:rotate(.7deg);'; document.body.append(element);
    const range = document.createRange(); range.selectNodeContents(element);
    const rects = [...element.getClientRects(), ...range.getClientRects()].map(r => [r.x, r.y, r.width, r.height, r.top, r.right, r.bottom, r.left]); element.remove();
    const frame = document.createElement('iframe'); frame.srcdoc = '<!doctype html><title>Isolated child frame</title>';
    const iframeReady = new Promise(resolve => frame.onload = resolve); document.body.append(frame); await iframeReady;
    const iframe = await frame.contentWindow.eval(`(${browserFacts.toString()})()`); frame.remove();
    await stage('iframe');
    const worker = await new Promise((resolve, reject) => {
      const source = URL.createObjectURL(new Blob([`self.onmessage=async()=>{try{postMessage({facts:await (${browserFacts.toString()})()})}catch(error){postMessage({error:String(error)})}}`], { type: 'application/javascript' }));
      const instance = new Worker(source), timer = setTimeout(() => { instance.terminate(); URL.revokeObjectURL(source); reject(new Error('Worker timeout')); }, 5000);
      instance.onmessage = event => { clearTimeout(timer); instance.terminate(); URL.revokeObjectURL(source); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.facts); };
      instance.onerror = () => { clearTimeout(timer); instance.terminate(); URL.revokeObjectURL(source); reject(new Error('Worker failed')); }; instance.postMessage('collect');
    });
    await stage('worker');
    const cookieBefore = document.cookie.includes('mc_fixture=preserved'), localBefore = localStorage.getItem('mc_fixture') === 'preserved';
    document.cookie = 'mc_fixture=preserved; Path=/; SameSite=Lax; Max-Age=3600'; localStorage.setItem('mc_fixture', 'preserved');
    const indexedBefore = await new Promise((resolve, reject) => {
      const request = indexedDB.open('mc-fingerprint-fixture', 1); request.onupgradeneeded = () => request.result.createObjectStore('state'); request.onerror = () => reject(request.error);
      request.onsuccess = () => { const database = request.result, transaction = database.transaction('state', 'readwrite'), store = transaction.objectStore('state'); let present = false;
        const read = store.get('mc_fixture'); read.onsuccess = () => { present = read.result === 'preserved'; store.put('preserved', 'mc_fixture'); };
        transaction.oncomplete = () => { database.close(); resolve(present); }; transaction.onerror = () => { database.close(); reject(transaction.error); };
      };
    });
    await stage('storage');
    const serviceWorkerBefore = (await navigator.serviceWorker.getRegistrations()).length > 0;
    await navigator.serviceWorker.register(prefix + 'sw.js', { scope: prefix }); await navigator.serviceWorker.ready;
    await stage('serviceworker');
    const headers = await fetch(prefix + 'headers', { cache: 'no-store' }).then(response => response.json());
    const routed = await fetch('http://mc-proxy-fixture.invalid/ping', { cache: 'no-store', credentials: 'omit' }).then(response => response.json());
    const secureProbe = await fetch('https://mc-proxy-fixture.invalid/ping', { cache: 'no-store', credentials: 'omit' }).then(() => 'unexpected-success', () => 'controlled-connect-rejection');
    const geolocation = await navigator.permissions.query({ name: 'geolocation' });
    await fetch(prefix + 'report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sampleId, facts, iframe, worker, canvasData, rects, cookieBefore, localBefore, indexedBefore, serviceWorkerBefore, headers, routed, secureProbe, geolocation: geolocation.state }) });
    document.getElementById('status').textContent = 'Local verification completed. This disposable window will close automatically.';
  } catch (error) {
    await fetch(prefix + 'report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sampleId, error: String(error) }) });
    document.getElementById('status').textContent = 'Local verification failed; see the generated report.';
  }
}

const observer = http.createServer(async (request, response) => {
  if (request.url === prefix && request.method === 'GET' && currentSample) {
    observerRequests++;
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'accept-ch': 'Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List' });
    response.end(`<!doctype html><title>MC Proxy isolated engine verification</title><body><h1>MC Proxy local verification</h1><p id="status">Checking a disposable local browser environment. No accounts or public websites.</p><script>const browserFacts=${browserFacts.toString()};(${browserProbe.toString()})(${JSON.stringify(currentSample)},${JSON.stringify(prefix)},${Math.min(5000, Math.max(0, Number(process.env.MC_FP_RENDER_SETTLE_MS) || 0))});</script></body>`); return;
  }
  if (request.url === prefix + 'headers' && request.method === 'GET') { response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); response.end(JSON.stringify(request.headers)); return; }
  if (request.url === prefix + 'sw.js' && request.method === 'GET') { response.writeHead(200, { 'content-type': 'application/javascript', 'cache-control': 'no-store' }); response.end('self.addEventListener("install",()=>self.skipWaiting()); self.addEventListener("activate",event=>event.waitUntil(self.clients.claim()));'); return; }
  if (request.url === prefix + 'report' && request.method === 'POST') {
    try { let body = ''; for await (const chunk of request) { body += chunk; if (body.length > 65536) throw new Error('report too large'); } const data = JSON.parse(body); if (data.sampleId !== currentSample || !pending) throw new Error('stale report'); response.writeHead(200).end(); pending.resolve(data); pending = null; }
    catch { response.writeHead(400).end(); } return;
  }
  if (request.url === prefix + 'progress' && request.method === 'POST') { let body = ''; for await (const chunk of request) { body += chunk; if (body.length > 1024) { response.writeHead(400).end(); return; } } try { const value = JSON.parse(body); if (value.sampleId === currentSample) { (report.progress ||= []).push({ ...value, at: new Date().toISOString() }); console.log('Local browser fixture: ' + value.stage); } response.writeHead(200).end(); } catch { response.writeHead(400).end(); } return; }
  response.writeHead(404).end();
});
const proxy = http.createServer((request, response) => {
  if (request.url.includes(prefix)) observerViaProxy++;
  if (request.url === 'http://mc-proxy-fixture.invalid/ping') { fixtureProxyRequests++; response.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'cache-control': 'no-store' }); response.end('{"route":"fixture-http-proxy"}'); return; }
  blockedBackgroundRequests++; response.writeHead(502).end();
});
proxy.on('connect', (request, socket) => { if (request.url === 'mc-proxy-fixture.invalid:443') fixtureConnectRequests++; else blockedBackgroundRequests++; socket.end('HTTP/1.1 502 Local fixture controlled rejection\r\nConnection: close\r\n\r\n'); });
for (const server of [observer, proxy]) server.on('connection', track);
const observerPort = await listen(observer), proxyPort = await listen(proxy);
const observationUrl = `http://127.0.0.1:${observerPort}${prefix}`;
const managerOptions = { runtimeRoot, fingerprintRoot: engineRoot, ...(sourceCandidate ? { readFingerprintRuntime: readRuntime } : {}), closeTimeoutMs: 15000 };
let manager = createBrowserManager(managerOptions), expectedPlatformVersion;

async function sample({ workspaceId, nativeGraphics = nativeOnly, append = false, expectedSeed, legacy = false } = {}) {
  currentSample = randomUUID(); let timer;
  const received = new Promise((resolve, reject) => { timer = setTimeout(() => { pending = null; reject(new Error('Local browser observation timed out')); }, 30000); pending = { resolve: value => { clearTimeout(timer); resolve(value); } }; });
  // Attach a handler before native launch, so a failed launch cannot leave an
  // unhandled timer rejection while cleanup is still inspecting native state.
  received.catch(() => {});
  try {
    const planned = await manager.plan({ browser: 'fingerprint', service: 'observation', observationUrl, observationPort: observerPort, workspaceId, port: proxyPort, language: 'ja', timezone: 'Asia/Tokyo', nativeGraphics, ...(expectedSeed ? { seed: expectedSeed } : {}) });
    const before = await manager.status();
    const launched = append ? await manager.openObservation({ observationUrl, workspaceId, port: proxyPort }) : await manager.launch(planned);
    const observed = await received; if (observed.error) throw new Error(observed.error);
    const status = await manager.status();
    check('ordinary manager confirms native owned process without CDP flags', status.managed === true);
    if (append) check('observation reuses the same workspace without changing start time or seed', launched.reused && status.startedAt === before.startedAt && status.fingerprint.seed === before.fingerprint.seed && status.workspaceId === before.workspaceId);
    check('UA-CH uses independently read Universal API contract, not the NT build', observed.facts.platformVersion === expectedPlatformVersion);
    check('native UA-CH full browser version matches the verified component', observed.facts.browserVersion === report.engine.version && observed.facts.platform === 'Win32' && observed.facts.cores === planned.fingerprint.cores);
    for (const scope of ['iframe', 'worker']) {
      if (legacy && scope === 'worker') continue; // Legacy Worker identity is measured, not accepted as the candidate's repaired implementation.
      check(`${scope} agrees with the main document identity`, ['language', 'timezone', 'platform', 'cores', 'userAgent', 'platformVersion', 'browserVersion'].every(key => observed[scope][key] === observed.facts[key]));
    }
    check('request User-Agent and UA-CH match page platform and engine', observed.headers['user-agent'] === observed.facts.userAgent && observed.headers['sec-ch-ua-platform'] === '"Windows"' && observed.headers['sec-ch-ua-platform-version'] === `"${expectedPlatformVersion}"` && observed.headers['sec-ch-ua-full-version'] === `"${report.engine.version}"`);
    check('saved language and timezone are active', observed.facts.language === 'ja' && observed.facts.timezone === 'Asia/Tokyo');
    check('HTTP uses local proxy and HTTPS issues a controlled proxy CONNECT', observed.routed.route === 'fixture-http-proxy' && fixtureConnectRequests > 0 && observed.secureProbe === 'controlled-connect-rejection');
    check('only the reserved observer port bypasses proxy', observerRequests > 0 && observerViaProxy === 0);
    check('geolocation remains blocked', observed.geolocation === 'denied');
    const observation = { sampleId: currentSample, workspaceId: workspaceId || null, seed: planned.fingerprint.seed, nativeGraphics, ...(legacy ? { scope: 'legacy-storage-preparation; Worker identity not accepted' } : {}), facts: observed.facts, iframe: observed.iframe, worker: observed.worker, headers: observed.headers, canvasHash: createHash('sha256').update(observed.canvasData).digest('hex'), rectsHash: createHash('sha256').update(JSON.stringify(observed.rects)).digest('hex'), storage: { cookie: observed.cookieBefore, localStorage: observed.localBefore, indexedDB: observed.indexedBefore, serviceWorker: observed.serviceWorkerBefore } };
    report.observations.push(observation);
    const manifest = JSON.parse(await readFile(path.join(runtimeRoot, 'browser-session.json'), 'utf8'));
    return { observation, plan: planned, identity: manifest.identity };
  } finally { clearTimeout(timer); pending = null; }
}

async function safelyClose() { const result = await manager.close(); check('native normal-close verifies owned process and restores preferences', result.closed === true && (await manager.status()).running === false); }
const allStored = observation => Object.values(observation.storage).every(Boolean), noStored = observation => Object.values(observation.storage).every(value => !value);
try {
  const runtime = await requireFingerprintRuntime(engineRoot, { release });
  report.engine = { version: runtime.version, architecture: runtime.architecture, integrity: runtime.integrity, verified: runtime.verified, sourceCandidate: Boolean(sourceCandidate), ...(sourceCandidate ? { sourceManifestSha256: sourceCandidate.sourceManifestSha256, buildReceiptSha256: sourceCandidate.buildReceiptSha256 } : {}) };
  // Independent oracle: decode the registry DWORD here instead of asserting
  // that browser output merely equals the value from the production plan.
  const rawContract = await new Promise((resolve, reject) => execFile(path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'reg.exe'), ['query', 'HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\WellKnownContracts', '/v', 'Windows.Foundation.UniversalApiContract', '/reg:64'], { windowsHide: true, timeout: 5000 }, (cause, output) => cause ? reject(cause) : resolve(String(output))));
  const packed = Number.parseInt(rawContract.match(/REG_DWORD\s+0x([\da-f]+)/i)?.[1] || '', 16); assert.ok(Number.isInteger(packed) && packed >= 65536);
  expectedPlatformVersion = `${packed >>> 16}.${packed & 65535}.0`; report.expectedPlatformVersion = expectedPlatformVersion;
  if (legacyRoot) {
    const legacy = await requireFingerprintRuntime(legacyRoot, { release: legacyRelease });
    const workspaceId = randomUUID();
    report.legacyMigration = { legacyRoot, version: legacy.version, integrity: legacy.integrity,
      scope: 'disposable same-profile storage/seed/core compatibility; legacy Worker identity is measured only; new engine identity checks remain enabled',
      graphics: 'nativeGraphics=true for both migration launches; legacy Canvas safety/Blob protection is not claimed',
      canvasContinuity: 'not required: legitimate source fixes can change Canvas output', workspaceId };
    manager = createBrowserManager({ ...managerOptions, fingerprintRoot: legacyRoot,
      readFingerprintRuntime: (root, options) => inspectFingerprintRuntime(root, { ...options, release: legacyRelease }) });
    const before = await sample({ workspaceId, nativeGraphics: true, legacy: true });
    check('legacy preparation uses a new disposable workspace without existing website data', noStored(before.observation));
    await safelyClose();
    const identityFile = path.join(before.plan.profile, '.mc-fingerprint.json');
    const savedBytes = await readFile(identityFile), saved = JSON.parse(savedBytes.toString('utf8'));
    check('legacy profile saved its planned seed and core count', saved.seed === before.plan.fingerprint.seed && saved.cores === before.plan.fingerprint.cores);
    manager = createBrowserManager(managerOptions);
    const after = await sample({ workspaceId, nativeGraphics: true, expectedSeed: saved.seed });
    check('new engine reopens the exact legacy workspace/profile with saved seed and cores',
      after.plan.profile === before.plan.profile && after.observation.seed === saved.seed
      && after.plan.fingerprint.cores === saved.cores && after.observation.facts.cores === saved.cores);
    check('new engine preserves legacy Cookie/localStorage/IndexedDB/ServiceWorker', allStored(after.observation));
    check('new engine retains the legacy saved identity record byte for byte', (await readFile(identityFile)).equals(savedBytes));
    report.legacyMigration.result = { profile: after.plan.profile, seed: saved.seed, cores: saved.cores,
      storage: after.observation.storage, oldCanvasHash: before.observation.canvasHash, newCanvasHash: after.observation.canvasHash };
    await safelyClose(); manager = createBrowserManager(managerOptions);
  }
  const firstId = randomUUID(), secondId = randomUUID(), replacementId = randomUUID();
  const first = await sample({ workspaceId: firstId, ...(process.env.MC_FP_SEED ? { expectedSeed: Number(process.env.MC_FP_SEED) } : {}) }); check('new workspace has no Cookie, localStorage, IndexedDB or ServiceWorker', noStored(first.observation));
  if (process.env.MC_FP_ONE_SAMPLE === '1') { await safelyClose(); }
  else {
  const appended = await sample({ workspaceId: firstId, append: true });
  check('observation keeps the exact native process identity', JSON.stringify(first.identity) === JSON.stringify(appended.identity));
  check('current-workspace observation sees existing storage', allStored(appended.observation));
  await safelyClose(); manager = createBrowserManager(managerOptions);
  const repeated = await sample({ workspaceId: firstId, expectedSeed: first.plan.fingerprint.seed });
  check('workspace restart retains seed, Canvas, ClientRects and storage', repeated.observation.seed === first.observation.seed && repeated.observation.canvasHash === first.observation.canvasHash && repeated.observation.rectsHash === first.observation.rectsHash && allStored(repeated.observation));
  await safelyClose();
  const second = await sample({ workspaceId: secondId });
  check('second user has an independent profile, seed and website storage', second.plan.profile !== first.plan.profile && second.observation.seed !== first.observation.seed && noStored(second.observation));
  await safelyClose();
  const rotated = await manager.rotateFingerprint({ confirm: true, workspaceId: firstId });
  const changed = await sample({ workspaceId: firstId, expectedSeed: rotated.seed });
  check(nativeOnly ? 'same-profile rotation preserves storage with native graphics' : 'same-profile rotation changes Canvas/ClientRects and preserves storage', changed.observation.seed !== first.observation.seed && (nativeOnly || changed.observation.canvasHash !== first.observation.canvasHash && changed.observation.rectsHash !== first.observation.rectsHash) && allStored(changed.observation));
  await safelyClose();
  const replacement = await sample({ workspaceId: replacementId });
  check('replacement-style identity inherits no website storage', replacement.plan.profile !== first.plan.profile && replacement.observation.seed !== changed.observation.seed && noStored(replacement.observation));
  await safelyClose();
  const restored = await sample({ workspaceId: firstId, expectedSeed: rotated.seed });
  check('original environment remains recoverable with seed and storage', restored.observation.seed === changed.observation.seed && allStored(restored.observation));
  await safelyClose();
  const nativeBefore = await sample({ workspaceId: secondId, nativeGraphics: true }); await safelyClose();
  const nativeRotated = await manager.rotateFingerprint({ confirm: true, workspaceId: secondId });
  const nativeAfter = await sample({ workspaceId: secondId, nativeGraphics: true, expectedSeed: nativeRotated.seed });
  check('native graphics stay unchanged across seed rotation', nativeBefore.observation.canvasHash === nativeAfter.observation.canvasHash && nativeBefore.observation.rectsHash === nativeAfter.observation.rectsHash); await safelyClose();
  }
} catch (cause) {
  const lastStage = report.progress?.at(-1)?.stage;
  report.errors.push({ code: cause.code || (lastStage === 'canvas-drawn' && /timed out/.test(cause.message) ? 'FINGERPRINT_CANVAS_READBACK_TIMEOUT' : 'FINGERPRINT_ACCEPTANCE_FAILED'), message: cause.message, ...(lastStage ? { lastStage } : {}) }); process.exitCode = 1;
}
finally {
  try { if ((await manager.status()).running) await manager.close(); } catch (cause) { report.errors.push({ code: cause.code || 'FINGERPRINT_CLEANUP_FAILED', message: cause.message }); process.exitCode = 1; }
  for (const socket of sockets) socket.destroy(); await Promise.all([observer, proxy].map(closeServer));
  report.finishedAt = new Date().toISOString(); report.proxyEvidence = { fixtureProxyRequests, fixtureConnectRequests, observerRequests, observerViaProxy, blockedBackgroundRequests };
  const file = path.join(directory, 'report.json'); await writeFile(file, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ file, passed: report.checks.filter(value => value.passed).length, failed: report.checks.filter(value => !value.passed).length, errors: report.errors, engine: report.engine, proxyEvidence: report.proxyEvidence }, null, 2));
}
