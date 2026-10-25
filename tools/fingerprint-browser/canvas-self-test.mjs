// Headed Canvas memory-safety regression fixture. Disposable profiles and localhost
// only; the ordinary manager owns and closes every native process. No CDP,
// certificate exceptions, renderer-sandbox bypass, or machine network changes.
import http from 'node:http';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createBrowserManager } from '../../backend/src/browser-session.mjs';
import { requireFingerprintRuntime, inspectFingerprintRuntime, FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_UPSTREAM_RELEASE, FINGERPRINT_BROWSER_LEGACY_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { readCandidateRuntime } from './native-engine/candidate-runtime.mjs';

const project = fileURLToPath(new URL('../../', import.meta.url));
const sourceCandidate = process.env.MC_FP_SOURCE_CANDIDATE === '1' ? await readCandidateRuntime(process.argv[2]) : null;
// Diagnostic-only A/B pins. A writable receipt cannot authorize either variant.
// The production manager's default release remains independently source-pinned.
const variant = process.env.MC_CANVAS_VARIANT;
if (variant && !['upstream', 'fixed'].includes(variant)) throw new Error('Invalid pinned Canvas diagnostic variant');
if (sourceCandidate && variant) throw new Error('Source candidate cannot be combined with a binary diagnostic variant');
if (variant === 'upstream' && !process.argv[2]) throw new Error('The pinned upstream diagnostic requires an explicit old component directory');
const engineRoot = sourceCandidate?.root || process.argv[2] || path.join(project, '.cache', variant === 'fixed' ? 'fingerprint-browser-canvas-r1' : FINGERPRINT_BROWSER_CACHE_DIRECTORY);
const release = sourceCandidate?.release || (variant === 'upstream' ? FINGERPRINT_BROWSER_UPSTREAM_RELEASE : variant === 'fixed' ? FINGERPRINT_BROWSER_LEGACY_RELEASE : FINGERPRINT_BROWSER_RELEASE);
const readRuntime = (root, options) => inspectFingerprintRuntime(root, { ...options, release });
await mkdir(path.join(project, '.cache'), { recursive: true });
const directory = await mkdtemp(path.join(project, '.cache/canvas-regression-'));
const report = { startedAt: new Date().toISOString(), engineRoot, network: 'localhost-only fixture; no customer data or host network changes', samples: [], errors: [] };
// Native readback and worker timeout coverage follows Brave's own farbling
// regression cases (MustNotTimeout / FarbleGetImageData), without importing its
// code or bypassing this application's ordinary managed launch path:
// https://github.com/brave/brave-core/blob/7817378f3345f324d82e44dfc5da9d27226b540c/browser/farbling/brave_offscreencanvas_farbling_browsertest.cc#L93
const names = ['zero-url', 'one-url', 'blank-url', 'fill-url', 'text-url', 'small-image', 'drawn-image', 'blob', 'offscreen-blob', 'webgl-pixels',
  'worker-image', 'worker-blob', 'sharedworker-image', 'sharedworker-blob', 'iframe-image', 'iframe-url', 'jpeg-url', 'webp-url', 'odd-transparent-image', 'odd-transparent-url', 'webgl2-offset'];
// Empty / monochrome canvases may legitimately be excluded by low-entropy
// protection. GPU spoofing is intentionally disabled by the production policy.
const seededDrawingCases = new Set(['text-url', 'drawn-image', 'blob', 'offscreen-blob', 'worker-image', 'worker-blob', 'sharedworker-image', 'sharedworker-blob', 'iframe-image', 'iframe-url', 'jpeg-url', 'webp-url', 'odd-transparent-image', 'odd-transparent-url']);
const cases = (process.env.MC_CANVAS_CASES || names.join(',')).split(',');
if (cases.some(name => !names.includes(name))) throw new Error('Unknown Canvas case');
const seeds = (process.env.MC_CANVAS_SEEDS || '3324349380,1,4294967295').split(',').map(Number);
if (seeds.some(seed => !Number.isInteger(seed) || seed <= 0 || seed > 0xffffffff)) throw new Error('Invalid Canvas seed');
const repeats = Math.min(100, Math.max(1, Math.floor(Number(process.env.MC_CANVAS_REPEATS) || 10)));
const sampleTimeout = Math.min(60000, Math.max(5000, Number(process.env.MC_CANVAS_TIMEOUT_MS) || 15000));
const token = randomBytes(24).toString('base64url'), prefix = `/s/${token}/`;
let active, pending, manager;
const sockets = new Set();
const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); };

async function probe(sampleId, prefix, name, repeats) {
  const post = (type, value) => fetch(prefix + type, { method: 'POST', body: JSON.stringify({ sampleId, ...value }) });
  const stage = value => post('progress', { stage: value });
  // Self-contained so the exact drawing/readback also runs inside a native
  // DedicatedWorker, SharedWorker or same-origin iframe, without CDP injection.
  async function readCanvas(name, repeats, stage) {
    const offscreen = name.startsWith('offscreen-');
    const canvas = offscreen ? new OffscreenCanvas(280, 100) : document.createElement('canvas');
    const odd = name.startsWith('odd-transparent-');
    canvas.width = name === 'zero-url' ? 0 : name === 'one-url' ? 1 : ['blank-url', 'small-image'].includes(name) ? 2 : odd ? 17 : 280;
    canvas.height = name === 'zero-url' ? 0 : name === 'one-url' ? 1 : ['blank-url', 'small-image'].includes(name) ? 2 : odd ? 13 : 100;
    const gl = name === 'webgl-pixels' || name === 'webgl2-offset';
    const context = canvas.getContext(gl ? name === 'webgl2-offset' ? 'webgl2' : 'webgl' : '2d');
    if (!context) throw new Error('Required Canvas context unavailable: ' + name);
    if (gl) {
      context.clearColor(.2, .4, .6, 1); context.clear(context.COLOR_BUFFER_BIT);
      context.enable(context.SCISSOR_TEST); context.scissor(3, 2, 19, 17);
      context.clearColor(.8, .1, .3, .6); context.clear(context.COLOR_BUFFER_BIT); context.disable(context.SCISSOR_TEST);
    } else if (odd) {
      context.fillStyle = 'rgba(80,20,180,.4)'; context.fillRect(1, 1, 7, 5);
      context.fillStyle = 'rgba(13,190,27,.7)'; context.fillRect(8, 5, 8, 7);
      context.clearRect(3, 2, 2, 2);
    } else if (!['zero-url', 'one-url', 'blank-url'].includes(name)) {
      context.fillStyle = '#acd7ed'; context.fillRect(0, 0, canvas.width, canvas.height);
      if (!['fill-url', 'small-image'].includes(name)) { context.fillStyle = '#235'; context.font = '18px Arial'; context.fillText('MC Proxy Canvas ♥ 漢字 123', 12, 42); context.fillStyle = 'rgba(236,32,43,.3)'; context.fillRect(38, 22, 85, 46); }
    }
    await stage('drawn');
    const values = [];
    for (let iteration = 0; iteration < repeats; iteration++) {
      await stage('before-read-' + iteration);
      let bytes;
      if (name.endsWith('-url')) {
        const mime = name === 'jpeg-url' ? 'image/jpeg' : name === 'webp-url' ? 'image/webp' : 'image/png';
        const data = canvas.toDataURL(mime, .9);
        if (name === 'zero-url' ? data !== 'data:,' : !data.startsWith('data:' + mime + ';base64,')) throw new Error('Unexpected Canvas export type: ' + name);
        bytes = new TextEncoder().encode(data);
      } else if (name === 'blob') {
        const blob = await new Promise(resolve => canvas.toBlob(resolve));
        if (!blob || blob.type !== 'image/png') throw new Error('Invalid Canvas Blob');
        bytes = new Uint8Array(await blob.arrayBuffer());
      } else if (name === 'offscreen-blob') {
        const blob = await canvas.convertToBlob();
        if (blob.type !== 'image/png') throw new Error('Invalid OffscreenCanvas Blob');
        bytes = new Uint8Array(await blob.arrayBuffer());
      } else if (gl) {
        const length = canvas.width * canvas.height * 4, offset = name === 'webgl2-offset' ? 8 : 0;
        const destination = new Uint8Array(length + offset * 2); destination.fill(109);
        if (offset) context.readPixels(0, 0, canvas.width, canvas.height, context.RGBA, context.UNSIGNED_BYTE, destination, offset);
        else context.readPixels(0, 0, canvas.width, canvas.height, context.RGBA, context.UNSIGNED_BYTE, destination);
        if (context.getError() !== context.NO_ERROR) throw new Error('WebGL readPixels error');
        if (offset && (!destination.subarray(0, offset).every(value => value === 109) || !destination.subarray(offset + length).every(value => value === 109))) throw new Error('WebGL2 readPixels overwrote offset guards');
        bytes = destination.subarray(offset, offset + length);
      } else {
        bytes = context.getImageData(0, 0, canvas.width, canvas.height).data;
        if (odd && (bytes[3] !== 0 || !bytes.some((value, index) => index % 4 === 3 && value > 0 && value < 255))) throw new Error('Transparent Canvas alpha was not preserved');
      }
      if (!bytes.byteLength) throw new Error('Empty Canvas readback');
      await stage('after-read-' + iteration);
      values.push({ bytes: bytes.byteLength, hash: [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(value => value.toString(16).padStart(2, '0')).join('') });
    }
    return { values, width: canvas.width, height: canvas.height };
  }
  let timer, worker, canvasWorker, workerUrl, iframe;
  try {
    await stage('start');
    timer = setInterval(() => { void post('heartbeat', { scope: 'main' }); }, 500);
    const workerSource = URL.createObjectURL(new Blob([`setInterval(()=>fetch(${JSON.stringify(new URL(prefix + 'heartbeat', location.href).href)},{method:'POST',body:JSON.stringify({sampleId:${JSON.stringify(sampleId)},scope:'worker'})}),500);`], { type: 'application/javascript' }));
    worker = new Worker(workerSource); URL.revokeObjectURL(workerSource);
    let result;
    if (name.startsWith('worker-') || name.startsWith('sharedworker-')) {
      const shared = name.startsWith('sharedworker-'), method = name.endsWith('-image') ? 'offscreen-image' : 'offscreen-blob';
      const run = `const run=${readCanvas.toString()}; const start=async port=>{try{const result=await run(${JSON.stringify(method)},${repeats},stage=>{port.postMessage({stage});return Promise.resolve();});port.postMessage({result});}catch(error){port.postMessage({error:String(error)});}};`;
      workerUrl = URL.createObjectURL(new Blob([run + (shared ? 'onconnect=event=>{const port=event.ports[0];port.start();void start(port);};' : 'void start(self);')], { type: 'application/javascript' }));
      canvasWorker = shared ? new SharedWorker(workerUrl) : new Worker(workerUrl);
      const port = shared ? canvasWorker.port : canvasWorker;
      result = await new Promise((resolve, reject) => {
        port.onmessage = event => {
          if (event.data.stage) void stage(event.data.stage);
          else if (event.data.error) reject(new Error(event.data.error));
          else if (event.data.result) resolve(event.data.result);
        };
        canvasWorker.onerror = event => reject(new Error('Canvas worker error: ' + (event.message || 'unknown')));
        port.onmessageerror = () => reject(new Error('Canvas worker message error'));
        if (shared) port.start();
      });
    } else if (name.startsWith('iframe-')) {
      iframe = document.createElement('iframe');
      result = await new Promise((resolve, reject) => {
        const receive = event => {
          if (event.source !== iframe.contentWindow || event.data.sampleId !== sampleId) return;
          if (event.data.stage) void stage(event.data.stage);
          else { window.removeEventListener('message', receive); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); }
        };
        window.addEventListener('message', receive);
        const method = name.endsWith('-image') ? 'drawn-image' : 'text-url';
        iframe.srcdoc = '<!doctype html><script>const run=' + readCanvas.toString() + '; const send=value=>parent.postMessage({sampleId:' + JSON.stringify(sampleId) + ',...value},"*"); run(' + JSON.stringify(method) + ',' + repeats + ',stage=>{send({stage});return Promise.resolve();}).then(result=>send({result}),error=>send({error:String(error)}));<\/script>';
        document.body.append(iframe);
      });
    } else {
      result = await readCanvas(name, repeats, stage);
    }
    await post('report', result);
  } catch (error) { await post('report', { error: String(error) }); }
  finally { clearInterval(timer); worker?.terminate(); if (canvasWorker?.port) canvasWorker.port.close(); else canvasWorker?.terminate(); if (workerUrl) URL.revokeObjectURL(workerUrl); iframe?.remove(); }
}

const observer = http.createServer(async (request, response) => {
  if (request.url === prefix && request.method === 'GET' && active) {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(`<!doctype html><title>Disposable Canvas regression</title><p>MC Proxy local Canvas verification. No accounts or public websites.</p><script>(${probe.toString()})(${JSON.stringify(active.sampleId)},${JSON.stringify(prefix)},${JSON.stringify(active.name)},${repeats});</script>`); return;
  }
  if (request.method === 'POST' && ['progress', 'heartbeat', 'report'].some(type => request.url === prefix + type)) {
    try {
      let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 32768) throw new Error('Large report'); }
      const body = JSON.parse(raw); if (!active || body.sampleId !== active.sampleId) throw new Error('Stale report');
      if (request.url.endsWith('/progress')) { active.stages.push({ stage: body.stage, at: Date.now() }); if (!/-\d+$/.test(body.stage) || /-(?:0|99)$/.test(body.stage)) console.log(`${active.name} seed=${active.seed}: ${body.stage}`); }
      else if (request.url.endsWith('/heartbeat')) { active.heartbeats[body.scope] = Date.now(); }
      else if (pending) { pending(body); pending = null; }
      response.writeHead(200).end();
    } catch { response.writeHead(400).end(); } return;
  }
  response.writeHead(404).end();
});
const proxy = http.createServer((_request, response) => response.writeHead(502).end());
proxy.on('connect', (_request, socket) => socket.end('HTTP/1.1 502 Local fixture\r\nConnection: close\r\n\r\n'));
for (const server of [observer, proxy]) server.on('connection', track);
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const observerPort = await listen(observer), proxyPort = await listen(proxy);
const observationUrl = `http://127.0.0.1:${observerPort}${prefix}`;

try {
  const runtime = await requireFingerprintRuntime(engineRoot, { release }); report.engine = { version: runtime.version, integrity: runtime.integrity, verified: runtime.verified, variant: sourceCandidate ? 'source-candidate' : variant || 'production', inventorySha256: release.inventorySha256, ...(sourceCandidate ? { sourceManifestSha256: sourceCandidate.sourceManifestSha256, buildReceiptSha256: sourceCandidate.buildReceiptSha256 } : {}) };
  for (const seed of seeds) for (const name of cases) {
    active = { sampleId: randomUUID(), seed, name, stages: [], heartbeats: {} }; report.samples.push(active);
    manager = createBrowserManager({ runtimeRoot: path.join(directory, active.sampleId), fingerprintRoot: engineRoot, ...(sourceCandidate || variant ? { readFingerprintRuntime: readRuntime } : {}), closeTimeoutMs: 15000 });
    let timer;
    const received = new Promise((resolve, reject) => { pending = value => { clearTimeout(timer); resolve(value); }; timer = setTimeout(() => { pending = null; reject(new Error('Canvas report timed out')); }, sampleTimeout); }); received.catch(() => {});
    try {
      const planned = await manager.plan({ browser: 'fingerprint', service: 'observation', observationUrl, observationPort: observerPort, workspaceId: randomUUID(), port: proxyPort, language: 'ja', timezone: 'Asia/Tokyo', seed, nativeGraphics: process.env.MC_CANVAS_NATIVE === '1' });
      active.profile = planned.profile; active.args = planned.args; active.startedAt = new Date().toISOString();
      await manager.launch(planned); active.result = await received;
      active.readbackPassed = !active.result.error && !active.result.skipped && Array.isArray(active.result.values) && active.result.values.length === repeats;
      active.stable = active.readbackPassed && new Set(active.result.values.map(value => value.hash)).size === 1;
      active.passed = active.readbackPassed && active.stable;
      active.status = await manager.status();
      active.alivePassed = active.status.running === true;
      active.passed = active.passed && active.alivePassed;
    } catch (error) { active.passed = false; active.error = { code: error.code || 'CANVAS_READBACK_NO_REPORT', message: error.message }; active.timedOutAt = Date.now(); try { active.status = await manager.status(); } catch (error) { active.statusError = error.code || error.message; } }
    finally {
      clearTimeout(timer); pending = null;
      try { active.close = await manager.close(); active.closePassed = active.close.closed === true && active.close.running === false; } catch (error) { active.closePassed = false; active.closeError = error.code || error.message; }
      active.passed = active.passed === true && active.closePassed;
      console.log(JSON.stringify({ name, seed, passed: active.passed, stable: active.stable, error: active.error, closeError: active.closeError }));
      await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2));
    }
  }
} catch (error) { report.errors.push({ code: error.code, message: error.message }); }
finally {
  for (const socket of sockets) socket.destroy();
  await Promise.all([observer, proxy].map(server => new Promise(resolve => server.close(resolve))));
  report.finishedAt = new Date().toISOString();
  report.crossSeed = [];
  if (process.env.MC_CANVAS_NATIVE !== '1' && new Set(seeds).size > 1) for (const name of cases.filter(name => seededDrawingCases.has(name))) {
    const samples = report.samples.filter(sample => sample.name === name && sample.passed);
    const distinctSeeds = new Set(samples.map(sample => sample.seed)).size;
    const distinctHashes = new Set(samples.map(sample => sample.result.values[0].hash)).size;
    report.crossSeed.push({ name, distinctSeeds, distinctHashes, passed: distinctSeeds === new Set(seeds).size && distinctHashes === distinctSeeds });
  }
  report.summary = { readbackPassed: report.samples.filter(sample => sample.readbackPassed).length, readbackFailed: report.samples.filter(sample => !sample.readbackPassed).length,
    completedReadbacks: report.samples.reduce((sum, sample) => sum + (sample.result?.values?.length || 0), 0),
    passed: report.samples.filter(sample => sample.passed).length, failed: report.samples.filter(sample => !sample.passed).length, unstable: report.samples.filter(sample => sample.readbackPassed && !sample.stable).length,
    closeFailed: report.samples.filter(sample => !sample.closePassed).length, crossSeedPassed: report.crossSeed.filter(check => check.passed).length, crossSeedFailed: report.crossSeed.filter(check => !check.passed).length };
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ file: path.join(directory, 'report.json'), ...report.summary, errors: report.errors }));
  if (report.summary.failed || report.summary.crossSeedFailed || report.errors.length) process.exitCode = 1;
}
