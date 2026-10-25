import path from 'node:path';
import { lstat, realpath, readFile, open, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { requestViaProxy } from './probe.mjs';
import { CONNECTIVITY_SOURCES, equalIp } from './network-report.mjs';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { UserError } from './config.mjs';

const idPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const clone = value => structuredClone(value);
const fail = (code, message) => { throw new UserError(code, message); };
const normalized = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const rules = '每站满分 100：可用性 50 分（HTTP 2xx：50；3xx：35；401/403/429：10；其他：0），延迟 30 分（≤1500ms：30；≤3000ms：20；≤8000ms：10；更慢：5），两家独立出口 IP 检测一致：20 分。网络请求完全失败时该站为 0 分；总分为三站平均值并四舍五入。';

export function createQualityReportStore({ runtimeRoot, mock = false, request = requestViaProxy, now = Date.now, dependencies = {} } = {}) {
  if (!mock && (!runtimeRoot || !path.isAbsolute(runtimeRoot))) fail('QUALITY_PATH_INVALID', '质量报告需要绝对运行目录');
  const root = path.resolve(runtimeRoot || '.mock-quality');
  const directory = path.join(root, '.quality');
  const fs = { lstat, realpath, readFile, open, rename, rm, createPrivateDirectory, writePrivate, ...dependencies };
  const memory = new Map();
  let preparing;
  async function safe(file) {
    const absolute = path.resolve(file);
    const relative = path.relative(root, absolute);
    if (relative.startsWith('..') || path.isAbsolute(relative)) fail('QUALITY_PATH_INVALID', '质量报告路径超出运行目录');
    let cursor = path.parse(absolute).root;
    for (const piece of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, piece);
      let info;
      try { info = await fs.lstat(cursor); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (info.isSymbolicLink() || normalized(await fs.realpath(cursor)) !== normalized(cursor)) fail('QUALITY_PATH_INVALID', '质量报告路径包含链接，操作已拒绝');
    }
  }
  async function ensureDirectory(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('QUALITY_PATH_INVALID', '质量报告存储位置不是目录'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (target !== root) await ensureDirectory(path.dirname(target));
      await fs.createPrivateDirectory(target);
    }
  }
  async function persist(report) {
    if (!preparing) preparing = ensureDirectory(directory).catch(error => { preparing = undefined; throw error; });
    await preparing;
    const temporary = path.join(directory, `${report.id}.tmp`);
    const destination = path.join(directory, `${report.id}.json`);
    try {
      await safe(temporary);
      await fs.writePrivate(temporary, `${JSON.stringify(report, null, 2)}\n`);
      const handle = await fs.open(temporary, 'r+');
      try { await handle.sync(); } finally { await handle.close(); }
      await safe(destination);
      await fs.rename(temporary, destination);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  function validate(report, id) {
    if (!report || report.id !== id || report.kind !== 'connectivity-quality' || report.maxScore !== 100 || !Number.isInteger(report.score) || report.score < 0 || report.score > 100 || !Number.isFinite(Date.parse(report.generatedAt)) || typeof report.mock !== 'boolean' || typeof report.summary !== 'string' || !Array.isArray(report.results) || report.results.length !== CONNECTIVITY_SOURCES.length) fail('QUALITY_REPORT_INVALID', '质量报告内容无效，请保留原文件后检查');
    for (const source of CONNECTIVITY_SOURCES) {
      const matches = report.results.filter(row => row?.id === source.id);
      const row = matches[0];
      if (matches.length !== 1 || row.sourceUrl !== source.url || row.reportUrl !== `/reports/quality/${id}/${source.id}` || !isIP(row.exitIp || '') || !Number.isInteger(row.score) || row.score < 0 || row.score > 100 || !Number.isInteger(row.elapsedMs) || row.elapsedMs < 0 || (row.httpStatus !== null && (!Number.isInteger(row.httpStatus) || row.httpStatus < 100 || row.httpStatus > 599)) || !['reachable', 'restricted', 'failed', 'mocked'].includes(row.status)) fail('QUALITY_REPORT_INVALID', '站点质量报告内容无效');
    }
    return report;
  }
  async function run({ proxyPort, checks = [], mock: requestedMock = false } = {}) {
    const simulated = mock || requestedMock === true;
    if (!simulated && (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535)) fail('QUALITY_PROXY_INVALID', '质量检查需要有效的本地代理端口');
    const first = Array.isArray(checks) ? checks.filter(row => row?.source === 'ipify') : [];
    const second = Array.isArray(checks) ? checks.filter(row => row?.source === 'cloudflare') : [];
    if (!simulated && (first.length !== 1 || second.length !== 1 || !equalIp(first[0]?.ip, second[0]?.ip))) fail('QUALITY_EXIT_UNVERIFIED', '质量检查需要两家独立检测站确认同一出口 IP');
    const exitIp = simulated ? '203.0.113.8' : first[0].ip;
    const id = randomUUID();
    const results = await Promise.all(CONNECTIVITY_SOURCES.map(async source => {
      const row = { id: source.id, label: source.label, sourceUrl: source.url, reportUrl: `/reports/quality/${id}/${source.id}`, exitIp };
      if (simulated) return { ...row, status: 'mocked', score: 100, elapsedMs: 0, httpStatus: null, scoring: { availability: 50, latency: 30, consistency: 20 } };
      const started = now();
      try {
        const response = await request(new URL(source.url), { proxyPort, timeoutMs: 10000, method: 'HEAD', responseDetails: true });
        const httpStatus = response?.statusCode;
        if (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599) throw new Error('invalid HTTP status');
        const elapsedMs = Math.max(0, Math.round(now() - started));
        const availability = httpStatus >= 200 && httpStatus < 300 ? 50 : httpStatus >= 300 && httpStatus < 400 ? 35 : [401, 403, 429].includes(httpStatus) ? 10 : 0;
        const latency = elapsedMs <= 1500 ? 30 : elapsedMs <= 3000 ? 20 : elapsedMs <= 8000 ? 10 : 5;
        return { ...row, status: httpStatus >= 200 && httpStatus < 400 ? 'reachable' : [401, 403, 429].includes(httpStatus) ? 'restricted' : 'failed', score: availability + latency + 20, elapsedMs, httpStatus, scoring: { availability, latency, consistency: 20 } };
      } catch {
        return { ...row, status: 'failed', score: 0, elapsedMs: Math.max(0, Math.round(now() - started)), httpStatus: null, errorCode: 'QUALITY_SITE_UNREACHABLE', scoring: { availability: 0, latency: 0, consistency: 0 } };
      }
    }));
    const score = Math.round(results.reduce((sum, row) => sum + row.score, 0) / results.length);
    const report = { id, score, maxScore: 100, kind: 'connectivity-quality', summary: `${simulated ? '模拟演示；未发出网络请求。' : ''}代理 HTTPS 连通质量 ${score}/100。评分反映三站响应、延迟和两源出口一致性，不是这些网站的官方 IP 信誉分，也不代表 Claude 账号或登录可用。`, results, generatedAt: new Date(now()).toISOString(), mock: simulated, scoringRules: rules };
    validate(report, id);
    if (simulated) { memory.set(id, clone(report)); if (memory.size > 128) memory.delete(memory.keys().next().value); }
    else await persist(report);
    return clone(report);
  }
  async function read(id, siteId) {
    if (typeof id !== 'string' || !idPattern.test(id) || !CONNECTIVITY_SOURCES.some(source => source.id === siteId)) return null;
    let report = memory.get(id);
    if (!report) {
      if (mock) return null;
      const file = path.join(directory, `${id}.json`);
      await safe(file);
      try {
        const info = await fs.lstat(file);
        if (!info.isFile() || info.size > 1024 * 1024) fail('QUALITY_REPORT_INVALID', '质量报告类型或大小无效');
        report = JSON.parse(await fs.readFile(file, 'utf8'));
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        if (error instanceof UserError) throw error;
        fail('QUALITY_REPORT_INVALID', '质量报告无法读取');
      }
    }
    validate(report, id);
    const row = report.results.find(result => result.id === siteId);
    const source = CONNECTIVITY_SOURCES.find(item => item.id === siteId);
    const status = { reachable: 'HTTPS 可达', restricted: '站点限制访问', failed: row.httpStatus ? 'HTTP 响应异常' : '网络请求失败', mocked: '模拟演示' }[row.status];
    return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(source.label)} · MC Proxy 连通报告</title><link rel="stylesheet" href="/quality-report.css"></head><body><main class="quality-document"><h1>${escape(source.label)} · MC Proxy 连通报告</h1><p>${escape(report.summary)}</p>${report.mock ? '<p><strong>模拟报告：所有分数和出口 IP 均为演示数据，未检查真实网络。</strong></p>' : ''}<dl><dt>站点评分</dt><dd>${row.score} / 100</dd><dt>检查结果</dt><dd>${escape(status)}</dd><dt>HTTP 状态</dt><dd>${row.httpStatus ?? '无 HTTP 响应'}</dd><dt>延迟</dt><dd>${row.elapsedMs} ms</dd><dt>出口 IP</dt><dd>${escape(row.exitIp)}</dd><dt>生成时间</dt><dd>${escape(report.generatedAt)}</dd></dl><h2>评分规则</h2><p>${escape(rules)}</p><p>仅向站点发出经本地代理的 HTTPS HEAD 请求，不读取或伪造站点的官方信誉评分；站点防护可能限制自动请求。</p><p><a href="${escape(source.url)}" target="_blank" rel="noopener noreferrer">打开 ${escape(source.label)} 原始网站</a></p><p><a href="/">返回 MC Proxy</a></p></main></body></html>`;
  }
  return { run, read };
}
