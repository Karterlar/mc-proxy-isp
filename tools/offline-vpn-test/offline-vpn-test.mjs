import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { mkdir, readFile, writeFile, stat, rm } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { loadConfig, loadSecrets, buildSingBox, UserError } from '../../backend/src/config.mjs';
import { parseVpnConfig } from '../../backend/src/vpn-yaml.mjs';
import { createPrivateDirectory, writePrivate } from '../../backend/src/private-files.mjs';
import { allocateSetupPort } from '../../backend/src/setup-verification.mjs';
import { requestViaProxy } from '../../backend/src/probe.mjs';
import { IP_SOURCES, parseIpResponse, equalIp } from '../../backend/src/network-report.mjs';
import { listenerOwner, parseWindowsCommandLine } from '../../backend/src/windows-process.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const toolRoot = fileURLToPath(new URL('./', import.meta.url));
const defaultCore = path.join(root, 'backend/.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe');
const ipSources = IP_SOURCES.filter(source => ['ipify', 'cloudflare'].includes(source.id));
const sites = [
  { id: 'ping0', url: 'https://ping0.cc/' },
  { id: 'claude-api', url: 'https://api.anthropic.com/' },
  { id: 'codex-service', url: 'https://chatgpt.com/' },
];
const fail = code => { throw new UserError(code, code); };
const safeCode = error => /^[A-Z][A-Z0-9_]{1,70}$/.test(error?.code || '') ? error.code : 'TEST_FAILED';

// These are the only two outbounds. The VPN-only diagnostic listener is
// separate from the ISP listener; neither can silently fall back to direct.
export function buildTestConfig(config, secrets, vpnNode, { proxyPort, vpnPort, nodeIp } = {}) {
  const selected = structuredClone(config);
  delete selected.relay;
  selected.connectionMode = 'vpn-import';
  selected.listen.port = proxyPort;
  const credentials = { ISP_USERNAME: secrets.ISP_USERNAME || '', ISP_PASSWORD: secrets.ISP_PASSWORD || '' };
  const rendered = buildSingBox(selected, credentials, { mode: 'http', vpnNode, vpnNodeIp: nodeIp });
  rendered.inbounds.push({ type: 'http', tag: 'vpn-diagnostic', listen: '127.0.0.1', listen_port: vpnPort });
  rendered.route.rules = [{ inbound: ['vpn-diagnostic'], outbound: 'vpn-entry' }];
  return rendered;
}

export function classifyCoreOutput(chunk) {
  const patterns = [
    ['CORE_TLS_HANDSHAKE_FAILED', /(?:tls|x509|certificate|reality).{0,120}(?:fail|error|invalid|expired)|(?:fail|error).{0,120}(?:tls|x509|certificate|reality)/i],
    ['CORE_AUTH_REJECTED', /authentication|unauthorized|proxy authentication|status code: (?:401|407)/i],
    ['CORE_REMOTE_DNS_FAILED', /no such host|dns.{0,80}(?:fail|error)|lookup.{0,80}(?:fail|error)/i],
    ['CORE_CONNECTION_TIMEOUT', /timeout|timed out|deadline exceeded/i],
    ['CORE_CONNECTION_RESET', /reset by peer|forcibly closed|connection refused/i],
    ['CORE_NETWORK_UNREACHABLE', /network is unreachable|no route to host/i],
  ];
  return patterns.filter(([, pattern]) => pattern.test(chunk)).map(([code]) => code);
}

function cleanEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(?:https?_proxy|all_proxy|no_proxy|node_options|node_use_env_proxy)$/i.test(key)));
}

export async function checkCoreConfig(corePath, configPath, timeoutMs = 6000) {
  const checked = spawn(corePath, ['check', '-c', configPath], { windowsHide: true, stdio: 'pipe', env: cleanEnvironment() });
  let checkEnded = false;
  const checkResult = new Promise(resolve => {
    checked.once('error', () => { checkEnded = true; resolve(false); });
    checked.once('exit', code => { checkEnded = true; resolve(code === 0); });
    checked.stdout.resume(); checked.stderr.resume();
  });
  let checkTimer;
  const ok = await Promise.race([checkResult, new Promise(resolve => { checkTimer = setTimeout(() => resolve(false), timeoutMs); })]);
  clearTimeout(checkTimer);
  if (!checkEnded) {
    checked.kill();
    let stopTimer;
    const stopped = await Promise.race([checkResult.then(() => true), new Promise(resolve => { stopTimer = setTimeout(() => resolve(false), 4000); })]);
    clearTimeout(stopTimer);
    if (!stopped) fail('TEST_CORE_STOP_FAILED');
  }
  if (!ok) fail('CORE_CONFIG_CHECK_FAILED');
}

export async function startTestCore({ corePath, configPath, rendered, timeoutMs = 6000 }) {
  await writePrivate(configPath, JSON.stringify(rendered));
  await checkCoreConfig(corePath, configPath, timeoutMs);

  const child = spawn(corePath, ['run', '-c', configPath], { windowsHide: true, stdio: 'pipe', env: cleanEnvironment() });
  const diagnostics = new Set();
  let tail = '', ended = false;
  const exited = new Promise(resolve => {
    child.once('error', () => { ended = true; resolve(); });
    child.once('exit', () => { ended = true; resolve(); });
  });
  const observe = chunk => {
    tail = (tail + String(chunk)).slice(-8192);
    for (const code of classifyCoreOutput(tail)) diagnostics.add(code);
  };
  child.stdout.on('data', observe); child.stderr.on('data', observe);
  const stop = async () => {
    if (!ended) child.kill();
    let stopTimer;
    const stopped = await Promise.race([exited.then(() => true), new Promise(resolve => { stopTimer = setTimeout(() => resolve(false), 4000); })]);
    clearTimeout(stopTimer);
    if (!stopped) fail('TEST_CORE_STOP_FAILED');
  };
  try {
    const deadline = Date.now() + timeoutMs;
    while (!ended && Date.now() < deadline) {
      try { await tcpCheck('127.0.0.1', rendered.inbounds[0].listen_port, 300); }
      catch { await delay(100); continue; }
      if (process.platform === 'win32') {
        for (const inbound of rendered.inbounds) {
          const owner = await listenerOwner(inbound.listen_port);
          const args = owner ? parseWindowsCommandLine(owner.commandLine) : [];
          if (!owner || owner.pid !== child.pid || path.resolve(owner.executable).toLowerCase() !== path.resolve(corePath).toLowerCase()
            || args.length !== 4 || args[1] !== 'run' || args[2] !== '-c' || path.resolve(args[3]).toLowerCase() !== path.resolve(configPath).toLowerCase()) fail('TEST_LISTENER_OWNER_MISMATCH');
        }
      }
      if (ended) fail('TEST_CORE_EXITED');
      return { stop, diagnostics, alive: () => !ended };
    }
    fail('TEST_CORE_START_FAILED');
  } catch (error) { await stop(); error.coreDiagnostics = [...diagnostics]; throw error; }
}

export function tcpCheck(host, port, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => finish('NODE_TCP_TIMEOUT'), timeoutMs);
    const finish = code => {
      clearTimeout(timer); socket.removeAllListeners(); socket.destroy();
      if (code) reject(new UserError(code, code)); else resolve();
    };
    socket.once('connect', () => finish());
    socket.once('error', () => finish('NODE_TCP_FAILED'));
  });
}

export async function checkNodeTransport(nodeIp, outbound, { tcp = tcpCheck } = {}) {
  // QUIC nodes need their protocol handshake; an unrelated TCP listener is not
  // a prerequisite. Their HTTPS and ISP checks below remain mandatory.
  if (['hysteria2', 'tuic'].includes(outbound.type)) return 'not-applicable';
  await tcp(nodeIp, outbound.server_port);
  return 'pass';
}

export function assertExitChecks(checks, expectedExitIps) {
  if (checks.length !== 2 || checks.some(check => !net.isIP(check.ip || ''))) fail('ISP_EXIT_CHECK_FAILED');
  if (!equalIp(checks[0].ip, checks[1].ip)) fail('ISP_EXIT_INCONSISTENT');
  if (!expectedExitIps.length) fail('ISP_EXIT_PIN_REQUIRED');
  if (!expectedExitIps.some(ip => equalIp(ip, checks[0].ip))) fail('ISP_EXIT_PIN_MISMATCH');
}

async function resolveNode(host) {
  if (net.isIP(host)) return host;
  let timer;
  try {
    const addresses = await Promise.race([
      lookup(host, { all: true, verbatim: true }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new UserError('NODE_DNS_TIMEOUT', 'NODE_DNS_TIMEOUT')), 5000); }),
    ]);
    return (addresses.find(row => row.family === 4) || addresses[0])?.address || fail('NODE_DNS_FAILED');
  } catch (error) { throw new UserError(error.code === 'NODE_DNS_TIMEOUT' ? error.code : 'NODE_DNS_FAILED', 'Node bootstrap DNS failed'); }
  finally { clearTimeout(timer); }
}

export async function runNodeTest({ config, secrets, node, corePath, privateDir, cancelled = () => false, output = () => {} }) {
  const row = { nodeIndex: node.index, stages: {}, coreDiagnostics: [], success: false };
  const started = Date.now();
  let active, stage = 'node-dns', cleanupFailed = false;
  const configPath = path.join(privateDir, `node-${node.index}-${randomUUID()}.json`);
  const progress = next => {
    if (cancelled()) fail('TEST_CANCELLED');
    if (active && !active.alive()) fail('TEST_CORE_EXITED');
    stage = next; output(`Node ${node.index}: ${next}`);
  };
  const checkIp = async (source, proxyPort, timeoutMs) => {
    const body = await requestViaProxy(new URL(source.url), { proxyPort, timeoutMs });
    try { return { source: source.id, ip: parseIpResponse(source, body).ip }; }
    catch { fail('EXIT_RESPONSE_INVALID'); }
  };
  try {
    progress('node-dns');
    const nodeIp = await resolveNode(node.outbound.server);
    row.stages.nodeDns = 'pass';
    progress('node-transport'); row.stages.nodeTcp = await checkNodeTransport(nodeIp, node.outbound);
    progress('core-start');
    const proxyPort = await allocateSetupPort();
    let vpnPort = await allocateSetupPort();
    while (vpnPort === proxyPort) vpnPort = await allocateSetupPort();
    active = await startTestCore({ corePath, configPath, rendered: buildTestConfig(config, secrets, node.outbound, { proxyPort, vpnPort, nodeIp }) });
    progress('vpn-https');
    // Either IP endpoint may prove a working VPN handshake. ISP verification
    // below still requires BOTH independent endpoints to agree with the pin.
    const vpnChecks = await Promise.allSettled(ipSources.map(source => checkIp(source, vpnPort, 8000)));
    if (!vpnChecks.some(check => check.status === 'fulfilled')) fail('VPN_HTTPS_FAILED');
    row.stages.vpnHttps = 'pass';
    progress('isp-exit');
    const checks = await Promise.allSettled(ipSources.map(source => checkIp(source, proxyPort, 12000)));
    if (checks.some(check => check.status !== 'fulfilled')) fail('ISP_EXIT_CHECK_FAILED');
    row.exitChecks = checks.map(check => check.value);
    assertExitChecks(row.exitChecks, config.probe.expectedExitIps);
    row.stages.ispExit = 'verified';
    progress('target-sites');
    row.sites = await Promise.all(sites.map(async site => {
      try {
        const result = await requestViaProxy(new URL(site.url), { proxyPort, timeoutMs: 8000, method: 'HEAD', responseDetails: true });
        return { id: site.id, httpStatus: result.statusCode, reachable: result.statusCode >= 200 && result.statusCode < 400, httpsReached: true };
      } catch (error) { return { id: site.id, reachable: false, httpsReached: false, code: safeCode(error) }; }
    }));
    if (!row.sites.find(site => site.id === 'ping0')?.reachable) fail('TARGET_SITE_FAILED');
    progress('finished'); row.stages.targetSites = 'pass'; row.success = true;
  } catch (error) {
    if (error.code === 'TEST_CORE_STOP_FAILED') { cleanupFailed = true; throw error; }
    row.failureStage = stage; row.code = safeCode(error); row.coreDiagnostics = error.coreDiagnostics || [];
  }
  finally {
    if (active) {
      await active.stop();
      row.coreDiagnostics = [...active.diagnostics];
    }
    if (!cleanupFailed) await rm(configPath, { force: true });
    row.elapsedMs = Date.now() - started;
  }
  return row;
}

function reportText(report) {
  const explain = {
    NODE_DNS_FAILED: 'VPN 节点域名解析失败', NODE_DNS_TIMEOUT: 'VPN 节点域名解析超时',
    NODE_TCP_FAILED: '无法建立到 VPN 节点的 TCP 连接', NODE_TCP_TIMEOUT: '连接 VPN 节点超时',
    VPN_HTTPS_FAILED: 'VPN 协议握手或经过 VPN 的 HTTPS 请求失败；QUIC 节点不做 TCP 前置检查',
    ISP_EXIT_CHECK_FAILED: 'VPN 已通过检查，但经过 ISP 的两个出口检查未全部成功',
    ISP_EXIT_INCONSISTENT: '两个网站观察到不同 ISP 出口 IP',
    ISP_EXIT_PIN_MISMATCH: '实际出口与已保存的 ISP 出口不符；未自动更改出口白名单',
    ISP_EXIT_PIN_REQUIRED: '缺少已验证的 ISP 出口 IP；请先在客户端验证保存 ISP',
    TARGET_SITE_FAILED: 'ISP 出口已验证，但 Ping0 的 HTTPS 测试未通过',
    TEST_CORE_STOP_FAILED: '测试核心未确认停止；请保留私有目录并停止重试，不要上传私有目录',
    CONFIG_READ_FAILED: '无法读取已保存的 ISP 配置', SECRETS_READ_FAILED: '无法读取本机 ISP 凭据',
    NO_COMPLETE_CHAIN: '本次尝试未找到完整通过的链路，请查看各节点失败阶段',
    TEST_TIME_BUDGET_EXHAUSTED: '已达到本轮时间预算，未继续尝试剩余节点',
    TEST_CANCELLED: '用户中止了测试',
  };
  return [
    `MC Proxy VPN profile chain test: ${report.status}`,
    `结果：${report.status === 'pass' ? '完整链路通过' : report.status === 'prepared' ? '本机准备通过，尚未进行公网测试' : '测试未通过'}`,
    `Time: ${report.startedAt}`,
    `Supported nodes: ${report.supportedNodes ?? 0}/${report.totalNodes ?? 0}`,
    `External VPN closed: ${report.externalVpnOffConfirmed ? 'user confirmed; not independently proven' : 'not confirmed'}`,
    'Scope: temporary HTTP listeners only. System routes/DNS/proxy/firewall were not changed.',
    'PASS requires imported VPN + saved ISP + two matching pinned ISP exit checks + Ping0 HTTPS.',
    'Claude/Codex website HTTP status proves network reachability only, not application/login success.',
    ...(report.code ? [`Failure: ${report.code}${explain[report.code] ? ` — ${explain[report.code]}` : ''}`] : []),
    ...(report.unsupported || []).map(node => `Unsupported node ${node.index}: ${node.code}`),
    ...(report.nodes || []).map(node => `Node ${node.nodeIndex}: ${node.success ? 'PASS' : `${node.failureStage}: ${node.code}${explain[node.code] ? ` — ${explain[node.code]}` : ''}`} (${node.elapsedMs} ms)${node.coreDiagnostics.length ? `; ${node.coreDiagnostics.join(', ')}` : ''}`),
    ...(report.nodes || []).flatMap(node => (node.exitChecks || []).map(check => `  Node ${node.nodeIndex} ISP ${check.source}: ${check.ip}`)),
    ...(report.nodes || []).flatMap(node => (node.sites || []).map(site => `  Node ${node.nodeIndex} ${site.id}: ${site.httpStatus || site.code}`)),
    '',
    'Reconnect your normal VPN after testing. Share report.txt and summary.json, not the imported configuration or private directory.',
    '测试结束后重新开启原来的 VPN，分享 report.txt 和 summary.json；不要上传导入原文件或 .private 私有目录。',
  ].join('\r\n') + '\r\n';
}

export async function main(argv = process.argv.slice(2)) {
  let yamlPath, action = 'test', externalVpnOff = false;
  const seen = new Set();
  for (let i = 0; i < argv.length; i++) {
    const key = ['--test', '--prepare', '--self-test'].includes(argv[i]) ? 'action' : argv[i];
    if (seen.has(key)) fail('TEST_ARGUMENT_INVALID');
    seen.add(key);
    if (argv[i] === '--yaml') yamlPath = argv[++i];
    else if (argv[i] === '--prepare') action = 'prepare';
    else if (argv[i] === '--test') action = 'test';
    else if (argv[i] === '--external-vpn-off') externalVpnOff = true;
    else if (argv[i] === '--self-test') action = 'self-test';
    else fail('TEST_ARGUMENT_INVALID');
  }
  if (action === 'self-test') {
    // Tests contain loopback fixtures only, never the user's subscription.
    const child = spawn(process.execPath, ['--test', path.join(root, 'backend/test/vpn-yaml.test.mjs'), path.join(root, 'backend/test/offline-vpn-chain.test.mjs'), path.join(root, 'backend/test/offline-vpn-chain-native.test.mjs'), path.join(root, 'backend/test/vpn-protocol-core.test.mjs')], { windowsHide: true, stdio: 'inherit', env: cleanEnvironment() });
    return await new Promise(resolve => { child.once('exit', code => resolve(code === 0 ? 0 : code || 1)); child.once('error', () => resolve(1)); });
  }
  const runId = `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID().slice(0, 8)}`;
  const reportDir = path.join(toolRoot, 'logs', runId);
  await mkdir(reportDir, { recursive: true });
  const report = { version: 1, startedAt: new Date().toISOString(), action, status: 'failed', externalVpnOffConfirmed: externalVpnOff, nodes: [] };
  let privateDir, cancelled = false;
  const cancel = () => { cancelled = true; process.stdout.write('\nCancelling after the current bounded network operation...\n'); };
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    if (!yamlPath || (action === 'test' && !externalVpnOff)) fail(!yamlPath ? 'YAML_PATH_REQUIRED' : 'EXTERNAL_VPN_CONFIRMATION_REQUIRED');
    const info = await stat(yamlPath);
    if (!info.isFile() || info.size > 1048576) fail('YAML_FILE_INVALID');
    const parsed = parseVpnConfig(await readFile(yamlPath, 'utf8'));
    report.totalNodes = parsed.total; report.supportedNodes = parsed.nodes.length; report.unsupported = parsed.unsupported;
    if (!parsed.nodes.length) fail('VPN_NO_SUPPORTED_NODES');
    const config = await loadConfig(path.join(root, 'backend/runtime/config.json'));
    const secrets = await loadSecrets(path.join(root, 'backend/runtime/upstream.secrets.env'), config);
    if (!config.probe.expectedExitIps.length) fail('ISP_EXIT_PIN_REQUIRED');
    const core = await stat(defaultCore);
    if (!core.isFile()) fail('CORE_MISSING');
    privateDir = path.join(toolRoot, `.private-${runId}`);
    await createPrivateDirectory(privateDir);
    if (action === 'prepare') {
      // Native check does not open any network connection. The real hostname
      // is replaced for schema checking while TLS/Reality parameters are preserved.
      const checkPath = path.join(privateDir, 'prepare.json');
      const rendered = buildTestConfig(config, secrets, parsed.nodes[0].outbound, { proxyPort: 28991, vpnPort: 28992, nodeIp: '127.0.0.1' });
      await writePrivate(checkPath, JSON.stringify(rendered));
      await checkCoreConfig(defaultCore, checkPath, 8000);
      report.status = 'prepared';
      process.stdout.write(`PREPARED: ${parsed.nodes.length}/${parsed.total} nodes; saved ISP and exit pin; core schema valid. No network test was run.\n`);
    } else {
      const deadline = Date.now() + 10 * 60 * 1000;
      process.stdout.write(`Testing up to ${parsed.nodes.length} nodes, stopping at first complete success (about 10 minutes maximum, then finish the current bounded check).\n`);
      for (const node of parsed.nodes) {
        if (cancelled || Date.now() >= deadline) { report.code = cancelled ? 'TEST_CANCELLED' : 'TEST_TIME_BUDGET_EXHAUSTED'; break; }
        const row = await runNodeTest({ config, secrets, node, corePath: defaultCore, privateDir, cancelled: () => cancelled, output: line => process.stdout.write(`${line}\n`) });
        report.nodes.push(row);
        process.stdout.write(`Node ${node.index}: ${row.success ? 'PASS' : `${row.failureStage} / ${row.code}`}\n`);
        await writeFile(path.join(reportDir, 'summary.json'), JSON.stringify(report, null, 2));
        await writeFile(path.join(reportDir, 'report.txt'), reportText(report));
        if (row.success) { report.status = 'pass'; report.winningNodeIndex = node.index; break; }
      }
      if (report.status !== 'pass' && !report.code) report.code = 'NO_COMPLETE_CHAIN';
    }
  } catch (error) { report.code = safeCode(error); }
  finally {
    process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel);
    if (privateDir && report.code !== 'TEST_CORE_STOP_FAILED') await rm(privateDir, { recursive: true, force: true });
    report.finishedAt = new Date().toISOString();
    await writeFile(path.join(reportDir, 'summary.json'), JSON.stringify(report, null, 2));
    await writeFile(path.join(reportDir, 'report.txt'), reportText(report));
    await writeFile(path.join(toolRoot, 'LATEST-RESULT.txt'), `Status: ${report.status}\r\nReport: ${path.join(reportDir, 'report.txt')}\r\nJSON: ${path.join(reportDir, 'summary.json')}\r\n`);
    process.stdout.write(`\nResult: ${report.status}${report.code ? ` / ${report.code}` : ''}\nReport: ${path.join(reportDir, 'report.txt')}\n`);
  }
  return ['pass', 'prepared'].includes(report.status) ? 0 : cancelled ? 130 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = await main(); }
  catch { process.stderr.write('TEST_BOOTSTRAP_FAILED\n'); process.exitCode = 1; }
}
