// Read-only network acceptance through an already running local HTTP proxy.
// Does not start/stop any proxy or mutate Windows settings, TUN or firewall.
import path from 'node:path';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { requestViaProxy } from '../src/probe.mjs';
import { IP_SOURCES, parseIpResponse, equalIp } from '../src/network-report.mjs';
import { createQualityReportStore } from '../src/quality-report.mjs';

const proxyPort = Number(process.argv[2]);
const output = process.argv[3] && path.resolve(process.argv[3]);
if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535 || !output) {
  throw new Error('Usage: node backend/tools/verify-current-proxy.mjs <loopback HTTP port> <new output directory>');
}
await mkdir(output, { recursive: false });
const observations = await Promise.all(IP_SOURCES.filter(source => ['ipify', 'cloudflare'].includes(source.id)).map(async source => {
  const started = Date.now();
  try {
    const body = await requestViaProxy(new URL(source.url), { proxyPort, timeoutMs: 20000 });
    return { source: source.id, ip: parseIpResponse(source, body).ip, elapsedMs: Date.now() - started };
  } catch (cause) { return { source: source.id, errorCode: cause.code || 'CHECK_FAILED', elapsedMs: Date.now() - started }; }
}));
await writeFile(path.join(output, 'exit-checks.json'), JSON.stringify(observations, null, 2), { flag: 'wx', mode: 0o600 });
if (observations.some(item => !item.ip) || !equalIp(observations[0].ip, observations[1].ip)) {
  process.stdout.write(JSON.stringify({ accepted: false, reason: 'Independent proxy exits were unavailable or inconsistent', observations, output }));
  process.exitCode = 1;
} else {
  const reports = createQualityReportStore({ runtimeRoot: output });
  const report = await reports.run({ proxyPort, checks: observations.map(({ source, ip }) => ({ source, ip })) });
  await writeFile(path.join(output, 'quality-report.css'), await readFile(new URL('../../frontend/quality-report.css', import.meta.url)), { flag: 'wx', mode: 0o600 });
  const files = [];
  for (const site of report.results) {
    const destination = path.join(output, `${site.id}.html`);
    const html = (await reports.read(report.id, site.id)).replace('href="/quality-report.css"', 'href="./quality-report.css"');
    await writeFile(destination, html, { flag: 'wx', mode: 0o600 });
    files.push({ id: site.id, path: destination });
  }
  await writeFile(path.join(output, 'result.json'), JSON.stringify(report, null, 2), { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ accepted: true, proxyPort, score: report.score, maxScore: report.maxScore, observations, results: report.results, files, output }, null, 2));
}
