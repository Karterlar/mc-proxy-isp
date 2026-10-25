// Native, headed, localhost-only Canvas diagnosis. Use disposable profiles and
// the ordinary manager: no CDP, JS protection shim, sandbox exception, or change
// to customer profiles, the system proxy, or host network configuration.
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { availableParallelism } from 'node:os';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';
import { createBrowserManager } from '../../backend/src/browser-session.mjs';
import { requireFingerprintRuntime, inspectFingerprintRuntime, FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { readCandidateRuntime } from './native-engine/candidate-runtime.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const methodsForScope = scope => ['window', 'iframe', 'http-iframe'].includes(scope) ? ['image', 'url', 'blob', 'offscreen'] : ['image', 'blob'];
const identityFields = ['userAgent', 'platform', 'language', 'languages', 'hardwareConcurrency', 'timezone', 'uaCh'];
const identityHeaders = ['user-agent', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'sec-ch-ua-platform-version', 'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-model', 'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list', 'sec-ch-ua-wow64', 'sec-ch-ua-form-factors'];
const acceptIdentityHints = identityHeaders.filter(name => name.startsWith('sec-ch-')).join(', ');
const canonical = value => JSON.stringify(value, (_key, entry) => entry && !Array.isArray(entry) && typeof entry === 'object' ? Object.fromEntries(Object.keys(entry).sort().map(key => [key, entry[key]])) : entry);
const identitySurface = value => Object.fromEntries(identityFields.map(field => [field, value?.[field]]));
const quotedHeader = value => { try { const result = JSON.parse(value); return typeof result === 'string' ? result : null; } catch { return null; } };
function headerBrands(value) {
  if (typeof value !== 'string') return null;
  const matches = [...value.matchAll(/("(?:\\.|[^"\\])*");v=("[0-9.]+")/g)];
  if (!matches.length || value.replace(/("(?:\\.|[^"\\])*");v=("[0-9.]+")/g, '').replace(/[\s,]/g, '')) return null;
  try { return matches.map(match => ({ brand: JSON.parse(match[1]), version: JSON.parse(match[2]) })); } catch { return null; }
}
function evaluateIdentity(identity, observedHeaders, expected) {
  const checks = [], coverage = {};
  const add = (name, passed, detail) => checks.push({ name, passed: Boolean(passed), ...(detail ? { detail } : {}) });
  for (const phase of ['before', 'after']) {
    const surface = identity?.[phase], uaCh = surface?.uaCh, headers = observedHeaders?.[phase];
    const required = surface && ['userAgent', 'platform', 'language', 'timezone'].every(key => typeof surface[key] === 'string' && surface[key].length > 0)
      && Array.isArray(surface.languages) && surface.languages.length > 0 && surface.languages.every(value => typeof value === 'string' && value.length > 0)
      && Number.isInteger(surface.hardwareConcurrency) && surface.hardwareConcurrency > 0 && !surface.errors?.length
      && uaCh && ['platform', 'platformVersion', 'architecture', 'bitness', 'uaFullVersion'].every(key => typeof uaCh[key] === 'string' && uaCh[key].length > 0)
      && typeof uaCh.mobile === 'boolean' && typeof uaCh.wow64 === 'boolean' && typeof uaCh.model === 'string'
      && ['brands', 'fullVersionList'].every(key => Array.isArray(uaCh[key]) && uaCh[key].length > 0 && uaCh[key].every(value => typeof value.brand === 'string' && value.brand.length > 0 && typeof value.version === 'string' && value.version.length > 0))
      && Array.isArray(uaCh.formFactors) && uaCh.formFactors.length > 0 && uaCh.formFactors.every(value => typeof value === 'string' && value.length > 0);
    add(`${phase} identity complete native snapshot`, required, surface?.errors);
    add(`${phase} identity configured Windows/language/timezone/cores`, required && surface.platform === 'Win32' && /Windows NT 10\.0/.test(surface.userAgent)
      && surface.language === expected.language && surface.languages[0] === expected.language && surface.timezone === expected.timezone
      && surface.hardwareConcurrency === expected.cores && uaCh.platform === 'Windows' && uaCh.platformVersion === expected.platformVersion
      && uaCh.architecture === 'x86' && uaCh.bitness === '64' && uaCh.mobile === false && uaCh.wow64 === false && uaCh.model === '' && uaCh.formFactors.includes('Desktop'));
    const engineBrands = uaCh?.fullVersionList?.filter(value => ['Chromium', 'Google Chrome'].includes(value.brand));
    const majorBrands = uaCh?.brands?.filter(value => ['Chromium', 'Google Chrome'].includes(value.brand));
    add(`${phase} identity verified engine version`, required && /\b(?:Chrome|Chromium)\/(\d+)\./.exec(surface.userAgent)?.[1] === expected.engineVersion.split('.')[0]
      && uaCh.uaFullVersion === expected.engineVersion && engineBrands?.some(value => value.brand === 'Chromium') && engineBrands.every(value => value.version === expected.engineVersion)
      && majorBrands?.some(value => value.brand === 'Chromium') && majorBrands.every(value => value.version === expected.engineVersion.split('.')[0]));
    add(`${phase} HTTP identity echo was recorded independently`, headers && canonical(surface?.http?.headers) === canonical(headers)
      && surface.http.sampleId === expected.sampleId && surface.http.scope === expected.scope && surface.http.phase === phase);
    add(`${phase} HTTP identity User-Agent matches JavaScript`, typeof headers?.['user-agent'] === 'string' && headers['user-agent'] === surface?.userAgent);
    add(`${phase} HTTP identity Accept-Language matches JavaScript`, typeof headers?.['accept-language'] === 'string' && headers['accept-language'].split(',')[0].split(';')[0].trim() === surface?.language);
    const hintValues = {
      'sec-ch-ua': value => canonical(headerBrands(value)) === canonical(uaCh?.brands),
      'sec-ch-ua-mobile': value => value === (uaCh?.mobile ? '?1' : '?0'),
      'sec-ch-ua-platform': value => quotedHeader(value) === uaCh?.platform,
      'sec-ch-ua-platform-version': value => quotedHeader(value) === uaCh?.platformVersion,
      'sec-ch-ua-arch': value => quotedHeader(value) === uaCh?.architecture,
      'sec-ch-ua-bitness': value => quotedHeader(value) === uaCh?.bitness,
      'sec-ch-ua-model': value => quotedHeader(value) === uaCh?.model,
      'sec-ch-ua-full-version': value => quotedHeader(value) === uaCh?.uaFullVersion,
      'sec-ch-ua-full-version-list': value => canonical(headerBrands(value)) === canonical(uaCh?.fullVersionList),
      'sec-ch-ua-wow64': value => value === (uaCh?.wow64 ? '?1' : '?0'),
      'sec-ch-ua-form-factors': value => { try { return canonical(JSON.parse(`[${value}]`)) === canonical(uaCh?.formFactors); } catch { return false; } },
    };
    const present = Object.keys(hintValues).filter(name => typeof headers?.[name] === 'string');
    const missing = Object.keys(hintValues).filter(name => !present.includes(name));
    const completeRequired = ['window', 'http-iframe'].includes(expected.scope);
    coverage[phase] = { status: missing.length ? 'unverified-missing-headers' : 'measured', compared: present, missing, completeRequired };
    if (completeRequired) add(`${phase} HTTP identity all opted-in Client Hints observed`, missing.length === 0, { missing });
    // srcdoc has no HTTP opt-in, and the native Worker transport does not add
    // UA-CH. Their missing hints stay explicitly unverified; complete headers
    // are required only for the opted-in HTTP documents, never synthesized.
    for (const name of present) add(`${phase} HTTP identity ${name} matches JavaScript`, required && hintValues[name](headers[name]));
  }
  add('identity before/after snapshot stable', canonical(identitySurface(identity?.before)) === canonical(identitySurface(identity?.after)) && Boolean(identity?.before && identity?.after));
  return { checks, httpHintCoverage: coverage };
}
function categoryFor(name) {
  for (const [phrase, category] of [
    ['HTTP identity', 'httpIdentity'], ['identity before/after', 'identityStability'],
    ['cross-context identity', 'crossContextIdentity'], ['identity ', 'identityCoherence'],
    ['stable decoded pixels', 'pixelStability'], ['redraw restores', 'redrawRestoration'],
    ['drawing invalidates', 'contentInvalidation'], ['source bitmap', 'sourceImmutability'],
    ['alpha preserved', 'alphaSemantics'], ['API option semantics', 'optionSemantics'],
    ['cross-context/API', 'crossContextApiParity'], ['across seeds', 'crossSeedIdentity'],
    ['case coverage', 'caseCoverage'], ['still owned', 'processOwnership'],
    ['browser closes', 'processCleanup'], ['fixture completion', 'fixtureCompletion'],
  ]) if (name.includes(phrase)) return category;
  return 'other';
}
function checkSummary(checks) {
  const categories = {};
  for (const item of checks) {
    const key = item.category || categoryFor(item.name), category = categories[key] ||= { passed: 0, failed: 0 };
    category[item.passed ? 'passed' : 'failed']++;
  }
  return { passed: checks.filter(item => item.passed).length, failed: checks.filter(item => !item.passed).length, categories };
}
if (process.argv.includes('--summarize')) {
  const index = process.argv.indexOf('--summarize'), input = process.argv[index + 1];
  assert(input, '--summarize requires a report.json path');
  const existing = JSON.parse(await readFile(input, 'utf8'));
  assert(Array.isArray(existing.checks), 'Fixture report checks required');
  console.log(JSON.stringify({ file: path.resolve(input), ...checkSummary(existing.checks), errors: existing.errors?.length || 0 }, null, 2));
  process.exit(0);
}
// Decode outside Chromium so decoding a protected export cannot apply the
// browser's getImageData noise a second time. Only generated non-interlaced
// 8-bit PNGs are accepted; this is a fixture decoder, not a general image API.
function pngPixels(bytes) {
  assert(bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex')), 'PNG signature');
  let header, ended = false; const compressed = [];
  for (let cursor = 8; cursor + 12 <= bytes.length;) {
    const length = bytes.readUInt32BE(cursor), end = cursor + 12 + length;
    assert(end <= bytes.length && length <= 4 * 1024 * 1024, 'PNG chunk bounds');
    const type = bytes.toString('ascii', cursor + 4, cursor + 8), data = bytes.subarray(cursor + 8, end - 4);
    if (type === 'IHDR') { assert(!header && length === 13, 'PNG header'); header = data; }
    if (type === 'IDAT') compressed.push(data);
    cursor = end;
    if (type === 'IEND') { assert(length === 0 && cursor === bytes.length, 'PNG ending'); ended = true; break; }
  }
  assert(header && compressed.length && ended, 'Complete PNG');
  const width = header.readUInt32BE(0), height = header.readUInt32BE(4), channels = { 0: 1, 2: 3, 4: 2, 6: 4 }[header[9]];
  assert(width > 0 && height > 0 && width * height <= 1024 * 1024 && header[8] === 8 && channels && header[10] === 0 && header[11] === 0 && header[12] === 0, 'Supported PNG format');
  const stride = width * channels, raw = inflateSync(Buffer.concat(compressed), { maxOutputLength: (stride + 1) * height });
  assert.equal(raw.length, (stride + 1) * height, 'PNG raster size');
  const raster = Buffer.alloc(stride * height), pixels = Buffer.alloc(width * height * 4);
  const paeth = (a, b, c) => { const p = a + b - c, da = Math.abs(p - a), db = Math.abs(p - b), dc = Math.abs(p - c); return da <= db && da <= dc ? a : db <= dc ? b : c; };
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)]; assert(filter <= 4, 'PNG filter');
    for (let x = 0; x < stride; x++) {
      const at = y * stride + x, left = x >= channels ? raster[at - channels] : 0, above = y ? raster[at - stride] : 0, corner = y && x >= channels ? raster[at - stride - channels] : 0;
      const correction = [0, left, above, Math.floor((left + above) / 2), paeth(left, above, corner)][filter];
      raster[at] = (raw[y * (stride + 1) + x + 1] + correction) & 255;
    }
  }
  for (let index = 0; index < width * height; index++) {
    const source = index * channels, target = index * 4, gray = channels <= 2;
    pixels[target] = raster[source]; pixels[target + 1] = raster[source + (gray ? 0 : 1)]; pixels[target + 2] = raster[source + (gray ? 0 : 2)];
    pixels[target + 3] = channels === 2 ? raster[source + 1] : channels === 4 ? raster[source + 3] : 255;
  }
  return { width, height, pixels };
}

if (process.argv.includes('--self-check')) {
  // All five PNG filter forms over the same known RGBA raster. Chunk CRCs are
  // intentionally irrelevant to this local decoder; browser exports have CRCs.
  const row = Buffer.from([1, 12, 23, 255, 45, 56, 67, 128]);
  const chunk = (name, data) => { const output = Buffer.alloc(data.length + 12); output.writeUInt32BE(data.length); output.write(name, 4); data.copy(output, 8); return output; };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(2); ihdr.writeUInt32BE(5, 4); ihdr[8] = 8; ihdr[9] = 6;
  const raw = Buffer.alloc(45);
  for (let y = 0; y < 5; y++) for (let x = 0; x < 8; x++) {
    raw[y * 9] = y;
    const a = x >= 4 ? row[x - 4] : 0, b = y ? row[x] : 0, c = y && x >= 4 ? row[x - 4] : 0, p = a + b - c;
    const choice = Math.abs(p - a) <= Math.abs(p - b) && Math.abs(p - a) <= Math.abs(p - c) ? a : Math.abs(p - b) <= Math.abs(p - c) ? b : c;
    raw[y * 9 + x + 1] = (row[x] - [0, a, b, Math.floor((a + b) / 2), choice][y]) & 255;
  }
  const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
  assert(pngPixels(png).pixels.equals(Buffer.concat(Array(5).fill(row))));
  assert.throws(() => pngPixels(png.subarray(0, -1)));
  const expected = { sampleId: 'local-self-check', scope: 'dedicated', language: 'ja', timezone: 'Asia/Tokyo', cores: 12, platformVersion: '19.0.0', engineVersion: '150.0.7871.186' };
  const surface = { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/150.0.0.0 Safari/537.36', platform: 'Win32', language: 'ja', languages: ['ja'], hardwareConcurrency: 12, timezone: 'Asia/Tokyo', errors: [],
    uaCh: { platform: 'Windows', platformVersion: '19.0.0', architecture: 'x86', bitness: '64', model: '', mobile: false, wow64: false, uaFullVersion: expected.engineVersion, formFactors: ['Desktop'], brands: [{ brand: 'Chromium', version: '150' }], fullVersionList: [{ brand: 'Chromium', version: expected.engineVersion }] } };
  const headers = { 'user-agent': surface.userAgent, 'accept-language': 'ja', 'sec-ch-ua': '"Chromium";v="150"', 'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"', 'sec-ch-ua-platform-version': '"19.0.0"', 'sec-ch-ua-arch': '"x86"', 'sec-ch-ua-bitness': '"64"', 'sec-ch-ua-model': '""', 'sec-ch-ua-full-version': '"150.0.7871.186"', 'sec-ch-ua-full-version-list': '"Chromium";v="150.0.7871.186"', 'sec-ch-ua-wow64': '?0', 'sec-ch-ua-form-factors': '"Desktop"' };
  const identity = Object.fromEntries(['before', 'after'].map(phase => [phase, { ...structuredClone(surface), http: { ...expected, phase, headers: structuredClone(headers) } }]));
  const recorded = { before: headers, after: headers };
  const result = evaluateIdentity(identity, recorded, expected);
  assert(result.checks.every(item => item.passed)); assert.equal(result.httpHintCoverage.before.status, 'measured');
  const changedCores = structuredClone(identity); changedCores.after.hardwareConcurrency = 1;
  assert(evaluateIdentity(changedCores, recorded, expected).checks.some(item => !item.passed));
  const wrongHeaders = structuredClone(recorded); wrongHeaders.before['user-agent'] = 'Different native UA';
  assert(evaluateIdentity(identity, wrongHeaders, expected).checks.some(item => item.name.includes('User-Agent') && !item.passed));
  const missingEntropy = structuredClone(identity); delete missingEntropy.before.uaCh.architecture;
  assert(evaluateIdentity(missingEntropy, recorded, expected).checks.some(item => item.name.includes('complete native snapshot') && !item.passed));
  const missingHints = { before: { 'user-agent': surface.userAgent, 'accept-language': 'ja' }, after: headers };
  const sparseIdentity = structuredClone(identity); sparseIdentity.before.http.headers = missingHints.before;
  const sparse = evaluateIdentity(sparseIdentity, missingHints, expected); assert(sparse.checks.every(item => item.passed)); assert.equal(sparse.httpHintCoverage.before.status, 'unverified-missing-headers'); assert(sparse.httpHintCoverage.before.missing.includes('sec-ch-ua-arch'));
  const frameExpected = { ...expected, scope: 'http-iframe' }, frameIdentity = structuredClone(identity);
  for (const phase of ['before', 'after']) frameIdentity[phase].http.scope = frameExpected.scope;
  assert(evaluateIdentity(frameIdentity, recorded, frameExpected).checks.every(item => item.passed));
  const sparseFrame = structuredClone(frameIdentity); sparseFrame.before.http.headers = missingHints.before;
  assert(evaluateIdentity(sparseFrame, missingHints, frameExpected).checks.some(item => item.name.includes('all opted-in Client Hints observed') && !item.passed));
  const srcdocHeaders = Object.fromEntries(Object.entries(headers).filter(([name]) => ['user-agent', 'accept-language', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'].includes(name)));
  const srcdocExpected = { ...expected, scope: 'iframe' }, srcdocIdentity = structuredClone(identity);
  for (const phase of ['before', 'after']) srcdocIdentity[phase].http = { ...srcdocExpected, phase, headers: srcdocHeaders };
  const srcdoc = evaluateIdentity(srcdocIdentity, { before: srcdocHeaders, after: srcdocHeaders }, srcdocExpected);
  assert(srcdoc.checks.every(item => item.passed)); assert.equal(srcdoc.httpHintCoverage.before.missing.length, 8);
  assert(evaluateIdentity(null, {}, expected).checks.some(item => !item.passed));
  assert.equal(headerBrands('"Chromium";v="150", invalid'), null);
  assert.deepEqual(headerBrands('"A\\\\B\\\"C";v="150"'), [{ brand: 'A\\B"C', version: '150' }]);
  assert.equal(typeof new Function('return (' + measure.toString() + ')')(), 'function');
  assert.equal(typeof new Function('return (' + probe.toString() + ')')(), 'function');
  const frameHtml = iframeDocument(expected.sampleId, 'http-iframe', 4, 'http://127.0.0.1:12345/s/' + 'a'.repeat(32) + '/identity');
  assert(frameHtml.endsWith('</script>')); new Function(frameHtml.match(/<script>([\s\S]*)<\/script>/)[1]);
  console.log('PNG decoder and native identity evaluator: filters, truncation, complete snapshots, CPU/header conflicts, opted-in HTTP iframe hints, legal srcdoc/Worker omissions and iframe script serialization passed.');
  process.exit(0);
}

const project = fileURLToPath(new URL('../../', import.meta.url));
const sourceCandidate = process.env.MC_FP_SOURCE_CANDIDATE === '1' ? await readCandidateRuntime(process.argv[2]) : null;
const engineRoot = sourceCandidate?.root || process.argv[2] || path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY);
const release = sourceCandidate?.release || FINGERPRINT_BROWSER_RELEASE;
const readRuntime = (root, options) => inspectFingerprintRuntime(root, { ...options, release });
const seeds = (process.env.MC_BLOB_SEEDS || '3324349380,1,4294967295').split(',').map(Number);
assert(seeds.length <= 8 && new Set(seeds).size === seeds.length && seeds.every(seed => Number.isInteger(seed) && seed > 0 && seed <= 0xffffffff), 'Valid unique fixture seeds');
const repeats = Math.min(20, Math.max(3, Math.floor(Number(process.env.MC_BLOB_REPEATS) || 4)));
const timeoutMs = Math.min(60000, Math.max(10000, Number(process.env.MC_BLOB_TIMEOUT_MS) || 45000));
const scopes = (process.env.MC_BLOB_SCOPES || 'window,iframe,http-iframe,dedicated,shared').split(',');
assert(scopes.length <= 5 && new Set(scopes).size === scopes.length && scopes.every(scope => ['window', 'iframe', 'http-iframe', 'dedicated', 'shared'].includes(scope)), 'Valid unique scopes');
await mkdir(path.join(project, '.cache'), { recursive: true });
const directory = await mkdtemp(path.join(project, '.cache/blob-consistency-'));
const report = { fixtureVersion: 4, startedAt: new Date().toISOString(), engineRoot, seeds, scopes, repeats, hostConcurrency: availableParallelism(), network: 'localhost only, disposable browser profiles', identityScopes: { requested: scopes, completeFourContextMatrix: ['window', 'iframe', 'dedicated', 'shared'].every(scope => scopes.includes(scope)), httpIframeControlRequested: scopes.includes('http-iframe') }, samples: [], checks: [], errors: [] };
const check = (name, passed, detail) => report.checks.push({ name, category: categoryFor(name), passed, ...(detail ? { detail } : {}) });
const token = randomBytes(24).toString('base64url'), prefix = `/s/${token}/`;
let active, pending, manager;
const sockets = new Set();

// This exact function runs unchanged in all four contexts. No fonts, asynchronous
// resources, antialiasing, or timing-dependent animation influence the drawing.
async function measure(scope, repeats, progress, identityUrl, sampleId) {
  const width = 280, height = 100, results = [];
  const snapshot = async phase => {
    const observed = { errors: [] };
    try {
      Object.assign(observed, { userAgent: navigator.userAgent, platform: navigator.platform, language: navigator.language, languages: [...navigator.languages], hardwareConcurrency: navigator.hardwareConcurrency, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone });
      if (!navigator.userAgentData) throw new Error('Native User-Agent Client Hints unavailable');
      const data = navigator.userAgentData;
      observed.uaCh = { brands: data.brands.map(({ brand, version }) => ({ brand, version })), mobile: data.mobile, platform: data.platform };
      let timer;
      try {
        const values = await Promise.race([data.getHighEntropyValues(['architecture', 'bitness', 'fullVersionList', 'model', 'platformVersion', 'uaFullVersion', 'wow64', 'formFactors']), new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Native Client Hints timed out')), 5000); })]);
        Object.assign(observed.uaCh, values);
      } finally { clearTimeout(timer); }
    } catch (error) { observed.errors.push(String(error)); }
    try {
      const target = new URL(identityUrl);
      if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1' || !/^\/s\/[A-Za-z0-9_-]{32}\/identity$/.test(target.pathname) || target.username || target.password || target.search || target.hash) throw new Error('Non-loopback identity target refused');
      const response = await fetch(target.href, { method: 'POST', body: JSON.stringify({ sampleId, scope, phase }), cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok) throw new Error('Native identity header echo failed: ' + response.status);
      observed.http = await response.json();
    } catch (error) { observed.errors.push(String(error)); }
    return observed;
  };
  const before = await snapshot('before');
  const base64 = bytes => { let raw = ''; for (let offset = 0; offset < bytes.length; offset += 32768) raw += String.fromCharCode(...bytes.subarray(offset, offset + 32768)); return btoa(raw); };
  const methods = ['window', 'iframe', 'http-iframe'].includes(scope) ? ['image', 'url', 'blob', 'offscreen'] : ['image', 'blob'];
  for (const alpha of [false, true]) for (const frequent of [false, true]) for (const method of methods) {
    const offscreen = scope === 'dedicated' || scope === 'shared' || method === 'offscreen';
    const canvas = offscreen ? new OffscreenCanvas(width, height) : Object.assign(document.createElement('canvas'), { width, height });
    const context = canvas.getContext('2d', { willReadFrequently: frequent });
    if (!context) throw new Error('Canvas2D unavailable');
    const source = new Uint8ClampedArray(width * height * 4);
    for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
      const at = (y * width + x) * 4; source[at] = (x * 7 + y * 3) & 255; source[at + 1] = (x * 11 + y * 5) & 255; source[at + 2] = (x * 13 + y * 17) & 255;
      source[at + 3] = alpha ? [0, 64, 128, 192, 255][(x + y) % 5] : 255;
    }
    const draw = () => context.putImageData(new ImageData(new Uint8ClampedArray(source), width, height), 0, 0);
    const read = async () => {
      if (method === 'image') return { kind: 'rgba', base64: base64(context.getImageData(0, 0, width, height).data) };
      if (method === 'url') return { kind: 'png', base64: canvas.toDataURL('image/png').split(',')[1] };
      const blob = offscreen ? await canvas.convertToBlob({ type: 'image/png' }) : await new Promise(resolve => canvas.toBlob(resolve, 'image/png'));
      if (!blob || blob.type !== 'image/png') throw new Error('Expected PNG export');
      return { kind: 'png', base64: base64(new Uint8Array(await blob.arrayBuffer())) };
    };
    const copyPixels = () => { const copy = new OffscreenCanvas(width, height), copyContext = copy.getContext('2d', { willReadFrequently: true }); copyContext.drawImage(canvas, 0, 0); return { kind: 'rgba', base64: base64(copyContext.getImageData(0, 0, width, height).data) }; };
    draw(); const sourceBefore = copyPixels(), values = [];
    for (let iteration = 0; iteration < repeats; iteration++) { await progress(`${scope}/${alpha}/${frequent}/${method}/${iteration}`); values.push(await read()); }
    const sourceAfter = copyPixels();
    // Noise must not accumulate on the source bitmap or survive a new drawing.
    // Returning to the same known pixels must return to the same fingerprint.
    draw(); const redrawn = await read();
    context.fillStyle = '#173b69'; context.fillRect(17, 9, 31, 23); const modified = await read();
    draw(); const restored = await read();
    let semantics;
    if (method === 'image') {
      const negative = context.getImageData(width, height, -width, -height), explicit = context.getImageData(0, 0, width, height, { colorSpace: 'srgb' });
      semantics = { negativeDimensions: negative.width === width && negative.height === height, explicitSrgb: explicit.width === width && explicit.colorSpace === 'srgb' };
    } else {
      const fallback = offscreen ? await canvas.convertToBlob({ type: 'image/not-a-format', quality: .4 }) : await new Promise(resolve => canvas.toBlob(resolve, 'image/not-a-format', .4));
      semantics = { unsupportedMimePngFallback: fallback?.type === 'image/png' };
    }
    results.push({ scope, alpha, frequent, method, width, height, values, redrawn, modified, restored, sourceBefore, sourceAfter, semantics });
  }
  return { result: results, identity: { before, after: await snapshot('after') } };
}

function iframeDocument(sampleId, scope, repeats, identityUrl) {
  return '<!doctype html><script>const measure=' + measure.toString() + ';const send=value=>parent.postMessage({sampleId:' + JSON.stringify(sampleId) + ',...value},"*");measure(' + JSON.stringify(scope) + ',' + repeats + ',stage=>{send({stage});return Promise.resolve();},' + JSON.stringify(identityUrl) + ',' + JSON.stringify(sampleId) + ').then(result=>send({result}),error=>send({error:String(error)}));</scr' + 'ipt>';
}

async function probe(sampleId, prefix, scope, repeats) {
  const post = (type, value) => fetch(prefix + type, { method: 'POST', body: JSON.stringify({ sampleId, ...value }) });
  const progress = stage => post('progress', { stage });
  const identityUrl = new URL(prefix + 'identity', location.href).href;
  let worker, url, iframe, timer;
  try {
    let result;
    if (scope === 'window') result = await measure(scope, repeats, progress, identityUrl, sampleId);
    else if (scope === 'iframe' || scope === 'http-iframe') {
      iframe = document.createElement('iframe');
      result = await new Promise((resolve, reject) => {
        const receive = event => { if (event.source !== iframe.contentWindow || event.data?.sampleId !== sampleId) return; if (event.data.stage) void progress(event.data.stage); else { removeEventListener('message', receive); event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); } };
        addEventListener('message', receive);
        if (scope === 'iframe') iframe.srcdoc = iframeDocument(sampleId, scope, repeats, identityUrl);
        else iframe.src = prefix + 'http-iframe';
        document.body.append(iframe);
      });
    } else {
      const shared = scope === 'shared';
      url = URL.createObjectURL(new Blob(['const measure=' + measure.toString() + '; const run=port=>measure(' + JSON.stringify(scope) + ',' + repeats + ',stage=>{port.postMessage({stage});return Promise.resolve();},' + JSON.stringify(identityUrl) + ',' + JSON.stringify(sampleId) + ').then(result=>port.postMessage({result}),error=>port.postMessage({error:String(error)}));' + (shared ? 'onconnect=event=>{event.ports[0].start();run(event.ports[0]);};' : 'run(self);')], { type: 'application/javascript' }));
      worker = shared ? new SharedWorker(url) : new Worker(url); const port = shared ? worker.port : worker;
      result = await new Promise((resolve, reject) => { port.onmessage = event => { if (event.data.stage) void progress(event.data.stage); else event.data.error ? reject(new Error(event.data.error)) : resolve(event.data.result); }; worker.onerror = event => reject(new Error(event.message || 'Worker error')); port.onmessageerror = () => reject(new Error('Worker message decoding failed')); if (shared) port.start(); });
    }
    await post('report', result);
  } catch (error) { await post('report', { error: String(error) }); }
  finally { clearTimeout(timer); if (worker?.port) worker.port.close(); else worker?.terminate(); if (url) URL.revokeObjectURL(url); iframe?.remove(); }
}

function summarize(result) {
  assert(Array.isArray(result) && result.length === methodsForScope(active.scope).length * 4, 'Complete scope case matrix');
  const seen = new Set();
  return result.map(item => {
    assert(item.scope === active.scope && [false, true].includes(item.alpha) && [false, true].includes(item.frequent) && methodsForScope(active.scope).includes(item.method), 'Expected scope case');
    const caseKey = `${item.alpha}/${item.frequent}/${item.method}`;
    assert(!seen.has(caseKey), 'Unique scope case'); seen.add(caseKey);
    assert(item.width === 280 && item.height === 100 && Array.isArray(item.values) && item.values.length === repeats, 'Expected dimensions and repeat coverage');
    const decode = entry => {
      assert(entry && ['png', 'rgba'].includes(entry.kind) && typeof entry.base64 === 'string', 'Expected readback data');
      const bytes = Buffer.from(entry.base64, 'base64'), png = entry.kind === 'png' ? pngPixels(bytes) : null;
      if (png) assert(png.width === item.width && png.height === item.height, 'PNG dimensions match source');
      const pixels = png ? png.pixels : bytes;
      assert.equal(pixels.length, item.width * item.height * 4);
      const alphas = pixels.filter((_value, index) => index % 4 === 3), opaque = alphas.every(value => value === 255);
      const expectedAlpha = Buffer.from(Array.from({ length: item.width * item.height }, (_value, index) => item.alpha ? [0, 64, 128, 192, 255][(index % item.width + Math.floor(index / item.width)) % 5] : 255));
      return { kind: entry.kind, encodedHash: sha(bytes), pixelHash: sha(pixels), bytes: bytes.length, opaque, alphaHash: sha(alphas), expectedAlpha: alphas.equals(expectedAlpha) };
    };
    const values = item.values.map(decode), redrawn = decode(item.redrawn), modified = decode(item.modified), restored = decode(item.restored), sourceBefore = decode(item.sourceBefore), sourceAfter = decode(item.sourceAfter);
    const key = `${active.seed}/${item.scope}/alpha=${item.alpha}/frequent=${item.frequent}/${item.method}`;
    check(key + ' stable decoded pixels', new Set(values.map(value => value.pixelHash)).size === 1);
    check(key + ' redraw restores original fingerprint', redrawn.pixelHash === values[0].pixelHash && restored.pixelHash === values[0].pixelHash);
    check(key + ' drawing invalidates export', modified.pixelHash !== restored.pixelHash);
    check(key + ' readback preserves source bitmap through drawImage copies', sourceBefore.pixelHash === sourceAfter.pixelHash);
    check(key + ' alpha preserved', [...values, redrawn, restored].every(value => value.expectedAlpha) && (item.alpha || modified.opaque));
    check(key + ' API option semantics', Object.values(item.semantics).every(Boolean));
    const { values: _values, redrawn: _redrawn, modified: _modified, restored: _restored, sourceBefore: _before, sourceAfter: _after, ...meta } = item;
    return { ...meta, values, redrawn, modified, restored, sourceBefore, sourceAfter };
  });
}

const observer = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === prefix && active) { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'accept-ch': acceptIdentityHints }); response.end('<!doctype html><title>Disposable Blob consistency check</title><p>Local isolated Canvas fixture.</p><script>const measure=' + measure.toString() + ';const iframeDocument=' + iframeDocument.toString() + ';(' + probe.toString() + ')(' + JSON.stringify(active.sampleId) + ',' + JSON.stringify(prefix) + ',' + JSON.stringify(active.scope) + ',' + repeats + ');</script>'); return; }
  if (request.method === 'GET' && request.url === prefix + 'http-iframe' && active?.scope === 'http-iframe') { response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'accept-ch': acceptIdentityHints }); response.end(iframeDocument(active.sampleId, active.scope, repeats, `http://127.0.0.1:${observerPort}${prefix}identity`)); return; }
  if (request.method === 'POST' && request.url === prefix + 'identity') {
    try {
      const origin = `http://127.0.0.1:${observerPort}`;
      if (request.headers.host !== `127.0.0.1:${observerPort}` || request.headers.origin !== origin) throw new Error('Non-local identity echo origin');
      let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 4096) throw new Error('Large identity request'); }
      const body = JSON.parse(raw);
      if (!active || body.sampleId !== active.sampleId || body.scope !== active.scope || !['before', 'after'].includes(body.phase)
        || Object.keys(body).some(key => !['sampleId', 'scope', 'phase'].includes(key)) || active.headerObservations[body.phase]) throw new Error('Stale or duplicate identity request');
      const headers = Object.fromEntries(identityHeaders.filter(name => typeof request.headers[name] === 'string').map(name => [name, request.headers[name]]));
      active.headerObservations[body.phase] = headers;
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'accept-ch': acceptIdentityHints });
      response.end(JSON.stringify({ ...body, headers }));
    } catch { response.writeHead(400).end(); }
    return;
  }
  if (request.method === 'POST' && [prefix + 'report', prefix + 'progress'].includes(request.url)) {
    try { let raw = ''; for await (const chunk of request) { raw += chunk; if (raw.length > 32 * 1024 * 1024) throw new Error('Large fixture report'); } const body = JSON.parse(raw); if (!active || body.sampleId !== active.sampleId) throw new Error('Stale report'); if (request.url.endsWith('/progress')) { active.lastStage = body.stage; } else { pending?.(body); pending = null; } response.writeHead(200).end(); } catch { response.writeHead(400).end(); } return;
  }
  response.writeHead(404).end();
});
const proxy = http.createServer((_request, response) => response.writeHead(502).end());
proxy.on('connect', (_request, socket) => socket.end('HTTP/1.1 502 Local fixture\r\nConnection: close\r\n\r\n'));
for (const server of [observer, proxy]) server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const observerPort = await listen(observer), proxyPort = await listen(proxy), observationUrl = `http://127.0.0.1:${observerPort}${prefix}`;
try {
  const runtime = await requireFingerprintRuntime(engineRoot, { release }); report.engine = { version: runtime.version, integrity: runtime.integrity, verified: runtime.verified, sourceCandidate: Boolean(sourceCandidate), ...(sourceCandidate ? { sourceManifestSha256: sourceCandidate.sourceManifestSha256, buildReceiptSha256: sourceCandidate.buildReceiptSha256 } : {}) };
  for (const seed of seeds) for (const scope of scopes) {
    active = { sampleId: randomUUID(), seed, scope, headerObservations: {} }; report.samples.push(active); let timer;
    manager = createBrowserManager({ runtimeRoot: path.join(directory, active.sampleId), fingerprintRoot: engineRoot, ...(sourceCandidate ? { readFingerprintRuntime: readRuntime } : {}), closeTimeoutMs: 15000 });
    const received = new Promise((resolve, reject) => { pending = value => { clearTimeout(timer); resolve(value); }; timer = setTimeout(() => { pending = null; reject(new Error('Native Blob consistency report timed out')); }, timeoutMs); }); received.catch(() => {});
    try {
      const plan = await manager.plan({ browser: 'fingerprint', service: 'observation', observationUrl, observationPort: observerPort, workspaceId: randomUUID(), port: proxyPort, language: 'ja', timezone: 'Asia/Tokyo', seed, nativeGraphics: false });
      active.expectedIdentity = { sampleId: active.sampleId, scope, language: 'ja', timezone: 'Asia/Tokyo', cores: report.hostConcurrency, platformVersion: plan.fingerprint.platformVersion, engineVersion: runtime.version };
      active.profile = plan.profile; active.args = plan.args; await manager.launch(plan); const body = await received; if (body.error) throw new Error(body.error);
      active.identity = body.identity;
      const measured = evaluateIdentity(body.identity, active.headerObservations, active.expectedIdentity);
      active.httpHintCoverage = measured.httpHintCoverage;
      active.identityComplete = Object.fromEntries(['before', 'after'].map(phase => [phase, measured.checks.find(item => item.name === `${phase} identity complete native snapshot`).passed]));
      for (const item of measured.checks) check(`${seed}/${scope} ${item.name}`, item.passed, item.detail);
      active.result = summarize(body.result);
      check(`${seed}/${scope} browser still owned and running`, (await manager.status()).running === true);
    } catch (error) { active.error = { code: error.code, message: error.message }; check(`${seed}/${scope} native fixture completion`, false, active.error); }
    finally { clearTimeout(timer); pending = null; try { active.close = await manager.close(); check(`${seed}/${scope} exact owned browser closes`, active.close.closed === true && active.close.running === false); } catch (error) { active.closeError = error.code || error.message; check(`${seed}/${scope} exact owned browser closes`, false, active.closeError); } console.log(JSON.stringify({ seed, scope, error: active.error, lastStage: active.lastStage })); await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2)); }
  }
  for (const seed of seeds) for (const phase of ['before', 'after']) {
    const matching = report.samples.filter(sample => sample.seed === seed && scopes.includes(sample.scope));
    const complete = matching.length === scopes.length && scopes.every(scope => matching.some(sample => sample.scope === scope && sample.identityComplete?.[phase]));
    check(`${seed}/${phase} cross-context identity snapshots complete`, complete, { requested: scopes, measured: matching.filter(sample => sample.identityComplete?.[phase]).map(sample => sample.scope) });
    check(`${seed}/${phase} cross-context identity fields agree`, complete && new Set(matching.map(sample => canonical(identitySurface(sample.identity?.[phase])))).size === 1, matching.map(sample => ({ scope: sample.scope, surface: identitySurface(sample.identity?.[phase]) })));
  }
  const all = report.samples.flatMap(sample => (sample.result || []).map(item => ({ seed: sample.seed, ...item })));
  const expectedCaseKeys = scopes.flatMap(scope => methodsForScope(scope).map(method => `${scope}/${method}`));
  for (const seed of seeds) for (const alpha of [false, true]) for (const frequent of [false, true]) {
    const matching = all.filter(item => item.seed === seed && item.alpha === alpha && item.frequent === frequent);
    const actualKeys = matching.map(item => `${item.scope}/${item.method}`), complete = actualKeys.length === expectedCaseKeys.length && new Set(actualKeys).size === expectedCaseKeys.length && expectedCaseKeys.every(key => actualKeys.includes(key));
    check(`${seed}/alpha=${alpha}/frequent=${frequent} scope case coverage`, complete, { expected: expectedCaseKeys, actual: actualKeys });
    check(`${seed}/alpha=${alpha}/frequent=${frequent} cross-context/API decoded pixel parity`, complete && new Set(matching.map(item => item.values[0].pixelHash)).size === 1, matching.map(item => ({ scope: item.scope, method: item.method, hash: item.values[0].pixelHash })));
  }
  if (seeds.length > 1) for (const scope of scopes) for (const alpha of [false, true]) for (const frequent of [false, true]) for (const method of methodsForScope(scope)) {
    const matching = all.filter(item => item.scope === scope && item.alpha === alpha && item.frequent === frequent && item.method === method);
    const actualSeeds = matching.map(item => item.seed), complete = matching.length === seeds.length && new Set(actualSeeds).size === seeds.length && seeds.every(seed => actualSeeds.includes(seed));
    check(`${scope}/alpha=${alpha}/frequent=${frequent}/${method} seeded protection differs across seeds`, complete && new Set(matching.map(item => item.values[0].pixelHash)).size === seeds.length, { expectedSeeds: seeds, actualSeeds, hashes: matching.map(item => item.values[0].pixelHash) });
  }
} catch (error) { report.errors.push({ code: error.code, message: error.message }); }
finally {
  for (const socket of sockets) socket.destroy(); await Promise.all([observer, proxy].map(server => new Promise(resolve => server.close(resolve))));
  const identityHeaderPhases = report.samples.flatMap(sample => Object.values(sample.httpHintCoverage || {}));
  report.finishedAt = new Date().toISOString(); report.summary = { ...checkSummary(report.checks), errors: report.errors.length,
    identityHeaders: { measuredPhases: identityHeaderPhases.length, phasesWithUnverifiedHints: identityHeaderPhases.filter(value => value.missing.length > 0).length, missingHintObservations: identityHeaderPhases.reduce((sum, value) => sum + value.missing.length, 0) } };
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ file: path.join(directory, 'report.json'), ...report.summary })); if (report.summary.failed || report.errors.length) process.exitCode = 1;
}
