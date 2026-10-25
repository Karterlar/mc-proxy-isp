import path from 'node:path';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import { lstat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { UserError, validateConfig, validateSecrets, validateVpnProxy } from './config.mjs';
import { createPrivateDirectory } from './private-files.mjs';
import { createProxyRuntime } from './proxy-runtime.mjs';
import { requestViaProxy, sanitizeProbeFailure } from './probe.mjs';
import { IP_SOURCES, parseIpResponse, equalIp } from './network-report.mjs';
import { validateVpnOutbound } from './vpn-yaml.mjs';
import { sanitizeSetupDiagnostic } from './setup-diagnostic.mjs';

const backendRoot = fileURLToPath(new URL('../', import.meta.url));
const sources = IP_SOURCES.filter(source => ['ipify', 'cloudflare'].includes(source.id));
const fail = (code, message, diagnostic) => { const cause = new UserError(code, message); if (diagnostic) cause.diagnostic = diagnostic; throw cause; };
const canonicalIp = ip => net.isIP(ip) === 6 ? new URL(`http://[${ip}]/`).hostname.slice(1, -1) : ip;

// The socket is closed before the core claims the chosen port. Runtime startup
// checks ownership both before and after spawn; a collision fails closed.
export function allocateSetupPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', () => reject(new UserError('SETUP_PORT_UNAVAILABLE', 'Cannot reserve a private setup port')));
    server.listen({ host: '127.0.0.1', port: 0, exclusive: true }, () => {
      const port = server.address()?.port;
      server.close(error => error || !Number.isInteger(port) || port < 1024
        ? reject(new UserError('SETUP_PORT_UNAVAILABLE', 'Cannot reserve a private setup port'))
        : resolve(port));
    });
  });
}

// Only the onboarding controller calls this after the user requests Save and
// Check. Discovery runs through a temporary HTTP core, never through TUN or a
// direct fallback, and returns a pin only after its owned process has stopped.
export function createSetupVerifier({ runtimeRoot = path.join(backendRoot, 'runtime'), corePath, mock = false, dependencies = {}, onProgress = () => {}, onDiagnostic } = {}) {
  const root = path.resolve(runtimeRoot);
  const setupRoot = path.join(root, '.setup-verification');
  const deps = { lstat, createPrivateDirectory, allocatePort: allocateSetupPort, createRuntime: createProxyRuntime, request: requestViaProxy, now: () => performance.now(), ...dependencies };
  let serial = Promise.resolve();
  const serialized = action => { const task = serial.then(action); serial = task.catch(() => {}); return task; };
  const progress = (stage, message) => { try { onProgress({ stage, message }); } catch {} };
  async function recoverAndStop() {
    if (mock) return { running: false, recovered: false, mock: true };
    for (const directory of [root, setupRoot]) {
      try {
        const info = await deps.lstat(directory);
        if (!info.isDirectory() || info.isSymbolicLink()) fail('RUNTIME_UNSAFE', 'Setup recovery path must be a private real directory');
      } catch (error) {
        if (error.code === 'ENOENT') return { running: false, recovered: false, mock: false };
        throw error;
      }
    }
    // Recovery uses only this isolated core's ownership manifest. In particular,
    // expired/missing main ISP settings or credentials must not prevent stop.
    const forbidden = async () => fail('SETUP_RECOVERY_INVALID', 'Setup recovery must not read current ISP configuration or credentials');
    const runtime = deps.createRuntime({ runtimeRoot: setupRoot, corePath, transportMode: 'http', setupDiscovery: true, onDiagnostic, dependencies: { loadConfig: forbidden, loadSecrets: forbidden } });
    try {
      const result = await runtime.stop();
      if (result?.running) fail('SETUP_PROXY_STOP_FAILED', 'The recovered setup proxy could not be stopped');
      return { running: false, recovered: true, mock: false };
    } finally { await runtime.dispose(); }
  }
  async function verify(input) {
    let stage = 'validating-input';
    const annotate = cause => {
      const failure = cause instanceof Error ? cause : new UserError('SETUP_VERIFICATION_FAILED', 'Temporary connection verification failed');
      failure.diagnostic = { ...failure.diagnostic,
        ...sanitizeSetupDiagnostic({ setupStage: stage, nativeCode: cause?.code, nativeError: cause?.name }),
        ...sanitizeSetupDiagnostic(failure.diagnostic) };
      return failure;
    };
    try { return await verifySteps(input, value => { stage = value; }, annotate); }
    catch (cause) { throw annotate(cause); }
  }
  async function verifySteps({ config, secrets, inspect, vpnProxy, vpnNode, signal } = {}, stage, annotate) {
    const checkCanceled = () => { if (signal?.aborted) fail('CONNECTION_CANCELED', 'Connection canceled; temporary proxy cleanup is required'); };
    checkCanceled();
    const selected = structuredClone(config);
    validateConfig(selected);
    if (vpnProxy !== undefined && selected.connectionMode !== 'vpn-compat') fail('VPN_PROXY_INVALID', 'A local VPN route requires VPN compatibility mode');
    const selectedVpnProxy = vpnProxy === undefined ? undefined : structuredClone(validateVpnProxy(vpnProxy, selected.listen.port));
    if (vpnNode !== undefined && selected.connectionMode !== 'vpn-import') fail('VPN_NODE_INVALID', 'An imported VPN node requires VPN import mode');
    if (selected.connectionMode === 'vpn-import' && vpnNode === undefined) fail('VPN_NODE_REQUIRED', 'An imported VPN node is required for verification');
    const selectedVpnNode = vpnNode === undefined ? undefined : validateVpnOutbound(vpnNode);
    if (inspect !== undefined && typeof inspect !== 'function') fail('SETUP_INSPECTION_INVALID', 'Setup inspection must be an internal callback');
    if (!secrets || typeof secrets !== 'object' || Array.isArray(secrets) || Object.entries(secrets).some(([key, value]) => !['ISP_USERNAME', 'ISP_PASSWORD', 'RELAY_USERNAME', 'RELAY_PASSWORD'].includes(key) || typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value))) fail('SECRETS_INVALID', 'ISP and relay credentials must be single-line strings');
    const credentials = structuredClone(validateSecrets(selected, secrets));
    const pinnedResult = (checks, mocked) => {
      const allowed = selected.probe.expectedExitIps;
      if (allowed.length && !allowed.some(ip => equalIp(ip, checks[0].ip))) fail('SETUP_EXIT_MISMATCH', 'The ISP exit does not match the configured IP allowlist; configuration was not saved');
      return { expectedExitIps: allowed.length ? [...allowed] : [checks[0].ip], checks, mock: mocked };
    };
    const inspectResult = async (result, proxyPort) => {
      if (inspect) {
        stage('inspecting-exit');
        const checkedConfig = structuredClone(selected);
        checkedConfig.probe.expectedExitIps = [...result.expectedExitIps];
        // The callback comes only from controller code. It receives no secrets
        // and no runtime object; its requests must use this verified proxy port.
        result.inspection = await inspect({ proxyPort, config: checkedConfig, checks: structuredClone(result.checks), mock: result.mock, mocked: result.mock });
      }
      return result;
    };
    if (mock) { const result = await inspectResult({ ...pinnedResult(sources.map(source => ({ source: source.id, ip: '203.0.113.8' })), true), ...(selectedVpnNode ? { latencyMs: null } : {}) }, null); checkCanceled(); return result; }

    stage('preparing-runtime');
    try {
      const info = await deps.lstat(root);
      if (!info.isDirectory() || info.isSymbolicLink()) fail('RUNTIME_UNSAFE', 'Setup runtime must be a private real directory');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await deps.createPrivateDirectory(root);
    }
    stage('creating-runtime');
    const runtime = deps.createRuntime({
      runtimeRoot: setupRoot, corePath, transportMode: 'http', setupDiscovery: true, onProgress, onDiagnostic,
      dependencies: { loadConfig: async () => structuredClone(selected), loadSecrets: async () => structuredClone(credentials) },
    });
    let result;
    try {
      // Recover only this verifier's previous owned process after a controller
      // crash. Main proxy state and any persistent firewall lock are separate.
      stage('recovering-proxy');
      await runtime.stop();
      stage('allocating-port');
      selected.listen.port = await deps.allocatePort();
      validateConfig(selected);
      if (selectedVpnProxy) validateVpnProxy(selectedVpnProxy, selected.listen.port);
      progress('checking-isp', '正在通过 ISP 独立检查两个出口 IP 站点');
      checkCanceled();
      stage('starting-proxy');
      const started = await runtime.start({ mode: 'http', config: selected, signal, ...(selectedVpnProxy ? { vpnProxy: selectedVpnProxy } : {}), ...(selectedVpnNode ? { vpnNode: selectedVpnNode } : {}) });
      checkCanceled();
      if (!started.running || !started.managed || started.mode !== 'http' || started.port !== selected.listen.port) fail('SETUP_PROXY_UNVERIFIED', 'The private setup proxy was not verified');
      const assertOwned = async () => {
        stage('checking-ownership');
        const live = await runtime.status();
        if (!live.running || !live.managed || live.mode !== 'http' || live.port !== selected.listen.port || live.configHash !== started.configHash || live.vpnNodeHash !== started.vpnNodeHash) fail('SETUP_PROXY_UNVERIFIED', 'The private setup proxy changed during verification');
      };
      stage('checking-exit');
      const observations = await Promise.allSettled(sources.map(async source => {
        const startedAt = deps.now();
        const body = await deps.request(new URL(source.url), { proxyPort: selected.listen.port, timeoutMs: Math.min(selected.probe.timeoutMs, 20000), signal });
        const latencyMs = Math.max(1, Math.round(deps.now() - startedAt));
        try { return { check: { source: source.id, ip: canonicalIp(parseIpResponse(source, body).ip) }, latencyMs }; }
        catch { fail('SETUP_IP_INVALID', 'An independent exit check did not return a valid IP address', { stage: 'target-response', targetHttpStatus: 200 }); }
      }));
      checkCanceled();
      if (observations.some(observation => observation.status !== 'fulfilled')) {
        const checks = observations.flatMap((observation, index) => {
          if (observation.status === 'fulfilled') return [];
          const safe = sanitizeProbeFailure(observation.reason);
          const invalidPayload = observation.reason?.code === 'SETUP_IP_INVALID';
          const diagnostic = safe?.diagnostic || (invalidPayload && observation.reason.diagnostic?.stage === 'target-response' && observation.reason.diagnostic.targetHttpStatus === 200 ? { stage: 'target-response', targetHttpStatus: 200 } : {});
          return [{ source: sources[index].id, code: safe?.code || (invalidPayload ? 'SETUP_IP_INVALID' : 'SETUP_CHECK_FAILED'), ...diagnostic }];
        });
        fail('SETUP_CHECK_FAILED', 'Both independent ISP exit checks must succeed before saving', { checks });
      }
      await assertOwned();
      stage('checking-exit');
      const checks = observations.map(observation => observation.value.check);
      if (!equalIp(checks[0].ip, checks[1].ip)) fail('SETUP_EXIT_MISMATCH', 'Independent ISP checks returned different exit IPs; configuration was not saved');
      const latencyMs = Math.round(observations.reduce((sum, observation) => sum + observation.value.latencyMs, 0) / observations.length);
      result = await inspectResult({ ...pinnedResult(checks, false), ...(selectedVpnNode ? { latencyMs } : {}) }, selected.listen.port);
      if (inspect) await assertOwned();
    } catch (cause) {
      // Capture before cleanup advances the stage; a successful stop must not
      // make an earlier startup/probe failure look like a cleanup failure.
      throw annotate(cause);
    } finally {
      try {
        stage('stopping-proxy');
        const stopped = await runtime.stop();
        if (stopped?.running) fail('SETUP_PROXY_STOP_FAILED', 'The setup proxy must stop before configuration can be saved');
      } catch (cause) {
        const failure = annotate(cause);
        fail('SETUP_PROXY_STOP_FAILED', 'The temporary setup proxy could not be safely stopped; configuration was not saved', failure.diagnostic);
      } finally { stage('disposing-runtime'); await runtime.dispose(); }
    }
    checkCanceled(); return result;
  }
  return { verify: input => serialized(() => verify(input)), recoverAndStop: () => serialized(recoverAndStop) };
}
