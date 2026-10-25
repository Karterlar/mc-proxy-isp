import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readdir, readFile, writeFile, rm, mkdir, symlink } from 'node:fs/promises';
import { createQualityReportStore } from '../src/quality-report.mjs';
import { CONNECTIVITY_SOURCES } from '../src/network-report.mjs';

const checks = [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }];
const options = { proxyPort: 17890, checks };
async function fixture(t, extra = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.quality-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const settings = { runtimeRoot: root, request: async () => ({ statusCode: 200 }), now: () => Date.parse('2026-10-02T10:00:00Z'), ...extra };
  return { root, settings, store: createQualityReportStore(settings) };
}

test('three fixed HTTPS HEAD probes run in parallel through the supplied loopback proxy', async t => {
  const calls = []; const waiting = [];
  const { store } = await fixture(t, { request: async (url, requestOptions) => {
    calls.push({ url: url.href, options: requestOptions });
    return new Promise(resolve => { waiting.push(resolve); if (waiting.length === 3) waiting.forEach(done => done({ statusCode: 200, body: 'ignored-response' })); });
  } });
  const report = await store.run(options);
  assert.deepEqual(calls.map(call => call.url), CONNECTIVITY_SOURCES.map(source => new URL(source.url).href));
  for (const call of calls) assert.deepEqual(call.options, { proxyPort: 17890, timeoutMs: 10000, method: 'HEAD', responseDetails: true });
  assert.equal(report.score, 100); assert.equal(report.maxScore, 100); assert.equal(report.kind, 'connectivity-quality');
  assert.equal(report.mock, false); assert.equal(report.results.length, 3);
  assert.ok(report.results.every(row => row.score === 100 && row.status === 'reachable' && row.exitIp === checks[0].ip));
  assert.match(report.summary, /不是.*官方 IP 信誉分/);
});

test('HTTP response classes and latency buckets yield transparent bounded scores', async t => {
  for (const [statusCode, delay, score, status] of [[200, 1500, 100, 'reachable'], [204, 1501, 90, 'reachable'], [301, 3000, 75, 'reachable'], [302, 3001, 65, 'reachable'], [403, 8000, 40, 'restricted'], [401, 8001, 35, 'restricted'], [429, 0, 60, 'restricted'], [500, 0, 50, 'failed']]) {
    let ticks = 0;
    const { store } = await fixture(t, { request: async () => ({ statusCode }), now: () => ticks++ < 3 ? 0 : delay });
    const report = await store.run(options);
    assert.equal(report.score, score, `HTTP ${statusCode} at ${delay}ms`);
    for (const row of report.results) {
      assert.equal(row.elapsedMs, delay); assert.equal(row.status, status); assert.equal(row.httpStatus, statusCode);
      assert.equal(row.score, row.scoring.availability + row.scoring.latency + row.scoring.consistency);
      assert.ok(row.score >= 0 && row.score <= 100);
    }
  }
});

test('network failure is zero rather than receiving consistency points and errors never leak', async t => {
  let calls = 0;
  const { root, store } = await fixture(t, { request: async () => {
    if (calls++ === 0) throw new Error('password=secret username=private');
    return { statusCode: 200, body: 'password=secret', headers: { authorization: 'never-store' } };
  } });
  const report = await store.run({ ...options, checks: checks.map(check => ({ ...check, credential: 'never-store' })) });
  assert.equal(report.score, 67); assert.equal(report.results[0].score, 0);
  assert.deepEqual(report.results[0].scoring, { availability: 0, latency: 0, consistency: 0 });
  assert.equal(report.results[0].httpStatus, null);
  const serialized = await readFile(path.join(root, '.quality', `${report.id}.json`), 'utf8');
  for (const sensitive of ['password', 'username', 'private', 'secret', 'authorization', 'never-store', 'credential']) assert.equal(serialized.includes(sensitive), false);
});

test('all unreachable or malformed HTTP responses produce zero-quality reports', async t => {
  const { store } = await fixture(t, { request: async () => ({ statusCode: 0 }) });
  const report = await store.run(options);
  assert.equal(report.score, 0); assert.ok(report.results.every(row => row.score === 0 && row.status === 'failed'));
  assert.ok(report.results.every(row => row.errorCode === 'QUALITY_SITE_UNREACHABLE'));
});

test('exit checks must identify exactly one agreeing result from each independent source', async t => {
  let calls = 0; const { store, root } = await fixture(t, { request: async () => { calls++; return { statusCode: 200 }; } });
  for (const invalid of [[], [checks[0]], [checks[0], checks[0]], [...checks, checks[0]], [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.9' }], checks.map(check => ({ ...check, ip: '<invalid>' }))]) await assert.rejects(store.run({ ...options, checks: invalid }), { code: 'QUALITY_EXIT_UNVERIFIED' });
  await assert.rejects(store.run({ ...options, proxyPort: 0 }), { code: 'QUALITY_PROXY_INVALID' });
  assert.equal(calls, 0); assert.deepEqual(await readdir(root), []);
});

test('equivalent IPv6 exit spellings count as consistent', async t => {
  const { store } = await fixture(t);
  const report = await store.run({ ...options, checks: [{ source: 'ipify', ip: '2001:db8::8' }, { source: 'cloudflare', ip: '2001:0db8:0:0:0:0:0:8' }] });
  assert.equal(report.score, 100); assert.equal(report.results[0].exitIp, '2001:db8::8');
});

test('private JSON survives process restart and each site has its own semantic HTML report', async t => {
  const { store, root, settings } = await fixture(t);
  const report = await store.run(options);
  assert.deepEqual((await readdir(path.join(root, '.quality'))).sort(), ['.gitignore', `${report.id}.json`].sort());
  const restarted = createQualityReportStore(settings);
  for (const row of report.results) {
    assert.equal(row.reportUrl, `/reports/quality/${report.id}/${row.id}`);
    const html = await restarted.read(report.id, row.id);
    assert.match(html, /^<!doctype html>/); assert.match(html, /name="viewport"/);
    assert.match(html, /href="\/quality-report.css"/); assert.match(html, /<main class="quality-document">/);
    assert.ok(html.includes(row.label)); assert.ok(html.includes(row.sourceUrl));
    assert.match(html, /50 分/); assert.match(html, /两家独立出口 IP 检测一致/);
    assert.match(html, /不是.*官方 IP 信誉分/); assert.match(html, /rel="noopener noreferrer"/);
  }
});

test('HTML escapes persisted descriptive text and uses only fixed trusted source links', async t => {
  const { store, root } = await fixture(t);
  const report = await store.run(options);
  const file = path.join(root, '.quality', `${report.id}.json`);
  report.summary = '<script>"unsafe" & \'quoted\'</script>';
  report.results[0].label = '<img src=x onerror=alert(1)>';
  await writeFile(file, JSON.stringify(report));
  const html = await store.read(report.id, 'cleanip');
  assert.equal(html.includes('<script>'), false); assert.equal(html.includes('<img'), false);
  assert.ok(html.includes('&lt;script&gt;&quot;unsafe&quot; &amp; &#39;quoted&#39;&lt;/script&gt;'));
  report.results[0].sourceUrl = 'javascript:alert(1)'; await writeFile(file, JSON.stringify(report));
  await assert.rejects(store.read(report.id, 'cleanip'), { code: 'QUALITY_REPORT_INVALID' });
});

test('unknown report and path attack requests return null without resolving attacker paths', async t => {
  const { store, root } = await fixture(t);
  for (const [id, siteId] of [['../../secrets', 'cleanip'], ['not-a-uuid', '../secrets'], ['00000000-0000-4000-8000-000000000000', '..'], ['00000000-0000-4000-8000-000000000000', 'cleanip'], [null, 'cleanip']]) assert.equal(await store.read(id, siteId), null);
  assert.deepEqual(await readdir(root), []);
});

test('linked report directories are refused and files outside the store remain untouched', async t => {
  const { root, store } = await fixture(t);
  const target = path.join(root, 'outside'); await mkdir(target);
  await symlink(target, path.join(root, '.quality'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(store.run(options), { code: 'QUALITY_PATH_INVALID' });
  await assert.rejects(store.read('00000000-0000-4000-8000-000000000000', 'cleanip'), { code: 'QUALITY_PATH_INVALID' });
  assert.deepEqual(await readdir(target), []);
});

test('mock report store never invokes requests or filesystem operations', async t => {
  const { root } = await fixture(t);
  const deny = () => { throw new Error('host access'); };
  const store = createQualityReportStore({ runtimeRoot: root, mock: true, request: deny, dependencies: { lstat: deny, realpath: deny, readFile: deny, open: deny, rename: deny, rm: deny, writePrivate: deny, createPrivateDirectory: deny } });
  const report = await store.run();
  assert.equal(report.mock, true); assert.match(report.summary, /模拟演示/);
  assert.ok(report.results.every(row => row.status === 'mocked' && row.exitIp === '203.0.113.8'));
  assert.match(await store.read(report.id, 'cleanip'), /未检查真实网络/);
  assert.equal(await store.read('00000000-0000-4000-8000-000000000000', 'cleanip'), null);
  assert.deepEqual(await readdir(root), []);
});

test('per-run mock requests are also memory-only and labeled as simulated', async t => {
  const { root, store } = await fixture(t, { request: () => { throw new Error('host request'); } });
  const report = await store.run({ mock: true });
  assert.equal(report.mock, true); assert.match(await store.read(report.id, 'ippure'), /模拟报告/);
  assert.deepEqual(await readdir(root), []);
});

test('concurrent real reports share safe directory initialization and persist unique files', async t => {
  const { root, store } = await fixture(t);
  const reports = await Promise.all([store.run(options), store.run(options)]);
  assert.notEqual(reports[0].id, reports[1].id);
  const files = await readdir(path.join(root, '.quality'));
  for (const report of reports) assert.ok(files.includes(`${report.id}.json`));
  assert.equal(files.filter(file => file.endsWith('.tmp')).length, 0);
});
