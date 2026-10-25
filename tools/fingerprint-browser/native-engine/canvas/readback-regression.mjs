// Real headed, disposable-profile Canvas counterexamples. Ordinary manager,
// localhost-only observation, no CDP/shim/sandbox bypass or customer data.
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createBrowserManager } from '../../../../backend/src/browser-session.mjs';
import { inspectFingerprintRuntime, requireFingerprintRuntime, FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../../../backend/src/fingerprint-browser-runtime.mjs';
import { readCandidateRuntime } from '../candidate-runtime.mjs';

const project = fileURLToPath(new URL('../../../../', import.meta.url));
const candidate = process.env.MC_FP_SOURCE_CANDIDATE === '1' ? await readCandidateRuntime(process.argv[2]) : null;
const engineRoot = candidate?.root || process.argv[2] || path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY);
const release = candidate?.release || FINGERPRINT_BROWSER_RELEASE;
const runtime = await requireFingerprintRuntime(engineRoot, { release });
const directory = await mkdtemp(path.join(project, '.cache/canvas-readback-counterexamples-'));
const report = { startedAt: new Date().toISOString(), engineRoot, engine: { version: runtime.version, inventorySha256: release.inventorySha256, sourceCandidate: Boolean(candidate) }, samples: [], errors: [] };
const prefix = '/s/' + randomBytes(24).toString('base64url') + '/';
let active, receive, manager;
const sockets = new Set();
const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); };

async function pixels(scope) {
  const width = 128, height = 32;
  const create = () => { const canvas = typeof document === 'object' ? document.createElement('canvas') : new OffscreenCanvas(width, height); canvas.width = width; canvas.height = height; return canvas; };
  const canvas = create(), context = canvas.getContext('2d', { willReadFrequently: true });
  if (!context) throw new Error('2D context unavailable');
  const original = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    const at = (y * width + x) * 4;
    original[at] = (x * 17 + y * 3) & 255;
    original[at + 1] = (x * 11 + y * 13) & 255;
    original[at + 2] = (x * 5 + y * 29) & 255;
    original[at + 3] = 255;
  }
  context.putImageData(new ImageData(original, width, height), 0, 0);
  const read = target => target.getContext('2d').getImageData(0, 0, width, height).data;
  const distance = (a, b) => a.reduce((sum, value, index) => sum + (value !== b[index] ? 1 : 0), 0);
  const digest = async bytes => [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(value => value.toString(16).padStart(2, '0')).join('');
  const first = read(canvas), copy = create();
  copy.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(first), width, height), 0, 0);
  const second = read(copy), repeated = read(canvas);
  const floating = context.getImageData(0, 0, width, height, { pixelFormat: 'rgba-float16' });
  if (floating.pixelFormat !== 'rgba-float16' || floating.data.BYTES_PER_ELEMENT !== 2) throw new Error('Native float16 readback unavailable');
  const rounded = Uint8ClampedArray.from(floating.data, value => Math.round(Math.max(0, Math.min(1, value)) * 255));
  const blob = typeof canvas.convertToBlob === 'function' ? await canvas.convertToBlob() : await new Promise(resolve => canvas.toBlob(resolve));
  if (!blob || blob.type !== 'image/png') throw new Error('Native PNG Blob unavailable');
  const bitmap = await createImageBitmap(blob), decoded = create();
  decoded.getContext('2d').drawImage(bitmap, 0, 0); bitmap.close();
  const blobRead = read(decoded);
  // Copy an unread source at different integer coordinates, align the results,
  // then majority-vote each observed low bit. No observed pixels are written
  // back into these sources, so readback idempotence alone cannot pass this.
  const unread = create();
  unread.getContext('2d').putImageData(new ImageData(new Uint8ClampedArray(original), width, height), 0, 0);
  const votes = new Uint8Array(original.length), translationDifferences = [];
  for (let iteration = 0; iteration < 16; iteration++) {
    const dx = iteration * 131, translated = create(); translated.width = width + dx;
    const translatedContext = translated.getContext('2d', { willReadFrequently: true });
    translatedContext.drawImage(unread, dx, 0);
    const observed = translatedContext.getImageData(dx, 0, width, height).data;
    translationDifferences.push(distance(observed, first));
    observed.forEach((value, at) => { votes[at] += value & 1; });
  }
  const majority = Uint8ClampedArray.from(first, (value, at) => (value & 254) | (votes[at] > 8 ? 1 : 0));
  // A separate capability-limit diagnostic, NEVER counted as protected: a
  // low-bit-only scheme exposes the high seven bits of chosen color transforms.
  // Probe source, saturated +1 and abs(value-1); record actual native compositing
  // semantics before claiming this recovers the original. No API is disabled.
  const transform = operation => {
    const target = create(), targetContext = target.getContext('2d');
    targetContext.drawImage(unread, 0, 0); targetContext.globalCompositeOperation = operation;
    targetContext.fillStyle = 'rgb(1,1,1)'; targetContext.fillRect(0, 0, width, height);
    return read(target);
  };
  const plus = transform('lighter'), minus = transform('difference');
  let operationHighBitsMatch = true;
  const recovered = Uint8ClampedArray.from(first, (value, at) => {
    if (at % 4 === 3) return value;
    const a = value >> 1, b = plus[at] >> 1, c = minus[at] >> 1;
    operationHighBitsMatch &&= b === (Math.min(original[at] + 1, 255) >> 1) && c === (Math.abs(original[at] - 1) >> 1);
    return 2 * a + ((b > a || (a > 0 && c === a)) ? 1 : 0);
  });
  return {
    scope, firstDifferences: distance(first, original), writebackDifferences: distance(second, original),
    writebackChangedFromFirst: distance(second, first), repeatChangedFromFirst: distance(repeated, first),
    floatRoundedDifferences: distance(rounded, original), floatChangedFromFirst: distance(rounded, first),
    blobDifferences: distance(blobRead, original), blobChangedFromFirst: distance(blobRead, first),
    translationChangedFromFirst: translationDifferences, translationMajorityDifferences: distance(majority, original),
    chosenTransformDiagnostic: { status: 'not-claimed-protected', operationHighBitsMatch, recoveredDifferences: distance(recovered, original) },
    hashes: { original: await digest(original), first: await digest(first), writeback: await digest(second), float: await digest(rounded), blob: await digest(blobRead), translationMajority: await digest(majority) },
  };
}

async function page(sampleId, prefix, runPixels) {
  try {
    const results = [await runPixels('window')];
    for (const shared of [false, true]) {
      const scope = shared ? 'shared-worker' : 'dedicated-worker';
      const source = `const run=${runPixels.toString()};const start=async port=>{try{port.postMessage({result:await run(${JSON.stringify(scope)})});}catch(error){port.postMessage({error:String(error)});}};`;
      const workerUrl = URL.createObjectURL(new Blob([source + (shared ? 'onconnect=event=>{event.ports[0].start();void start(event.ports[0]);};' : 'void start(self);')], { type: 'application/javascript' }));
      const worker = shared ? new SharedWorker(workerUrl) : new Worker(workerUrl), port = shared ? worker.port : worker;
      try {
        results.push(await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(scope + ' timed out')), 15000);
          port.onmessage = event => { clearTimeout(timer); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); };
          worker.onerror = event => { clearTimeout(timer); reject(new Error(event.message || scope + ' failed')); };
          if (shared) port.start();
        }));
      } finally { shared ? port.close() : worker.terminate(); URL.revokeObjectURL(workerUrl); }
    }
    await fetch(prefix + 'report', { method: 'POST', body: JSON.stringify({ sampleId, results }) });
  } catch (error) { await fetch(prefix + 'report', { method: 'POST', body: JSON.stringify({ sampleId, error: String(error) }) }); }
}

const observer = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === prefix && active) {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(`<!doctype html><title>Local Canvas counterexamples</title><p>No accounts or public websites.</p><script>(${page.toString()})(${JSON.stringify(active.sampleId)},${JSON.stringify(prefix)},${pixels.toString()});</script>`); return;
  }
  if (request.method === 'POST' && request.url === prefix + 'report') {
    try {
      let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 32768) throw new Error('Report too large'); }
      const value = JSON.parse(raw); assert.equal(value.sampleId, active.sampleId);
      response.writeHead(200).end(); receive?.(value); receive = null;
    } catch { response.writeHead(400).end(); } return;
  }
  response.writeHead(404).end();
});
const proxy = http.createServer((_request, response) => response.writeHead(502).end());
proxy.on('connect', (_request, socket) => socket.end('HTTP/1.1 502 Local fixture\r\nConnection: close\r\n\r\n'));
for (const server of [observer, proxy]) server.on('connection', track);
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const observerPort = await listen(observer), proxyPort = await listen(proxy);
try {
  for (const seed of [123456789, 987654321]) {
    active = { sampleId: randomUUID(), seed }; report.samples.push(active);
    manager = createBrowserManager({ runtimeRoot: path.join(directory, active.sampleId), fingerprintRoot: engineRoot,
      ...(candidate ? { readFingerprintRuntime: (root, options) => inspectFingerprintRuntime(root, { ...options, release }) } : {}), closeTimeoutMs: 15000 });
    let timer;
    const received = new Promise((resolve, reject) => { receive = value => { clearTimeout(timer); resolve(value); }; timer = setTimeout(() => reject(new Error('Native report timed out')), 45000); }); received.catch(() => {});
    try {
      const plan = await manager.plan({ browser: 'fingerprint', service: 'observation', observationUrl: `http://127.0.0.1:${observerPort}${prefix}`, observationPort: observerPort, workspaceId: randomUUID(), port: proxyPort, language: 'ja', timezone: 'Asia/Tokyo', seed });
      active.args = plan.args; await manager.launch(plan); active.result = await received;
      active.passed = !active.result.error && active.result.results?.length === 3 && active.result.results.every(item =>
        item.firstDifferences > 0 && item.writebackDifferences > 0 && item.floatRoundedDifferences > 0 && item.blobDifferences > 0 &&
        item.writebackChangedFromFirst === 0 && item.repeatChangedFromFirst === 0 && item.floatChangedFromFirst === 0 && item.blobChangedFromFirst === 0 &&
        item.translationMajorityDifferences > 0 && item.translationChangedFromFirst?.length === 16 && item.translationChangedFromFirst.every(value => value === 0));
      active.crossContextPassed = new Set(active.result.results?.map(item => item.hashes.first)).size === 1;
      active.passed &&= active.crossContextPassed;
    } catch (error) { active.passed = false; active.error = error.message; }
    finally {
      clearTimeout(timer); receive = null;
      try { active.close = await manager.close(); active.passed &&= active.close.closed === true && active.close.running === false; }
      catch (error) { active.passed = false; active.closeError = error.message; }
      console.log(JSON.stringify({ seed, passed: active.passed, result: active.result, error: active.error }));
      await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
    }
  }
} catch (error) { report.errors.push(error.message); }
finally {
  for (const socket of sockets) socket.destroy();
  await Promise.all([observer, proxy].map(server => new Promise(resolve => server.close(resolve))));
  report.crossSeedPassed = report.samples.length === 2 && new Set(report.samples.map(item => item.result?.results?.[0]?.hashes.first)).size === 2;
  report.limitations = ['Chosen +1/-1 color-transform recovery is separately measured, NOT counted as protected. Low-bit perturbation is not complete anti-linkability or cryptographic anonymity.'];
  report.passed = report.errors.length === 0 && report.samples.length === 2 && report.samples.every(item => item.passed) && report.crossSeedPassed;
  report.finishedAt = new Date().toISOString();
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ report: path.join(directory, 'report.json'), passed: report.passed }));
  if (!report.passed) process.exitCode = 1;
}
