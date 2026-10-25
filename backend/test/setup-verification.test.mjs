import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createSetupVerifier } from '../src/setup-verification.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';
import { vpnOutbound } from './vpn-fixture.mjs';
import { createHash } from 'node:crypto';

const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: 'gateway.provider.test', port: 8080, auth: 'password' }, probe: { exitUrl: 'https://untrusted-config.test/', expectedExitIps: [], timeoutMs: 1000 } };
const secrets = { ISP_USERNAME: 'new-user', ISP_PASSWORD: 'new-password' };

function fixture(overrides = {}) {
  const calls = []; let runtimeOptions; let stops = 0; let vpnNodeHash;
  const runtime = {
    stop: async () => { calls.push('stop'); stops++; if (overrides.stop && stops === 2) throw new Error('private failure'); if (stops === 2) await overrides.stopAfter?.(); return { running: false }; },
    start: async request => { calls.push('start'); assert.equal(request.mode, 'http'); assert.equal(request.config.listen.port, 49160); overrides.inspectStart?.(request); if (overrides.start) throw new Error('failed'); vpnNodeHash = request.vpnNode && createHash('sha256').update(JSON.stringify(request.vpnNode)).digest('hex'); return { running: true, managed: true, mode: 'http', port: 49160, vpnNodeHash }; },
    status: async () => ({ running: !overrides.lostCore, managed: true, mode: 'http', port: 49160, vpnNodeHash: overrides.lostVpnNode ? '0'.repeat(64) : vpnNodeHash }),
    dispose: async () => { calls.push('dispose'); await overrides.dispose?.(); },
  };
  const verifier = createSetupVerifier({ runtimeRoot: path.resolve('.setup-test-root'), corePath: path.resolve('pinned-core.exe'), onDiagnostic: overrides.onDiagnostic, dependencies: {
    lstat: async () => ({ isDirectory: () => true, isSymbolicLink: () => false }),
    allocatePort: async () => { calls.push('port'); return 49160; },
    createRuntime: options => { runtimeOptions = options; return runtime; },
    ...(overrides.now ? { now: overrides.now } : {}),
    request: async (url, options) => {
      calls.push(url.hostname);
      assert.equal(options.proxyPort, 49160);
      if (overrides.request) return overrides.request(url, options);
      return url.hostname === 'api.ipify.org' ? '{"ip":"203.0.113.8"}' : 'fl=1\nip=203.0.113.8\n';
    },
    ...overrides.dependencies,
  } });
  return { verifier, calls, options: () => runtimeOptions };
}

test('onboarding discovers matching independent exits only through its stopped isolated HTTP proxy', async () => {
  const f = fixture();
  const result = await f.verifier.verify({ config, secrets });
  assert.deepEqual(result.expectedExitIps, ['203.0.113.8']);
  assert.deepEqual(result.checks.map(check => check.source), ['ipify', 'cloudflare']);
  assert.equal(result.mock, false);
  assert.deepEqual(f.calls, ['stop', 'port', 'start', 'api.ipify.org', 'www.cloudflare.com', 'stop', 'dispose']);
  assert.equal(f.options().setupDiscovery, true);
  assert.equal(f.options().transportMode, 'http');
  assert.ok(f.options().runtimeRoot.endsWith('.setup-verification'));
  assert.deepEqual(await f.options().dependencies.loadSecrets(), secrets);
  assert.equal(config.listen.port, 17890, 'ephemeral port is never persisted into caller configuration');
  assert.deepEqual(config.probe.expectedExitIps, []);
});

test('pre-aborted setup never creates or starts a temporary core', async () => {
  const controller = new AbortController(); controller.abort(); const f = fixture();
  await assert.rejects(f.verifier.verify({ config, secrets, signal: controller.signal }), { code: 'CONNECTION_CANCELED' });
  assert.deepEqual(f.calls, []);
});

test('cancellation during temporary startup always stops and disposes before rejecting', async () => {
  const controller = new AbortController();
  const f = fixture({ inspectStart: request => { assert.equal(request.signal, controller.signal); controller.abort(); } });
  await assert.rejects(f.verifier.verify({ config, secrets, signal: controller.signal }), { code: 'CONNECTION_CANCELED' });
  assert.deepEqual(f.calls, ['stop', 'port', 'start', 'stop', 'dispose']);
});

test('canceled parallel exit requests wait for stop and dispose before returning failure', async () => {
  const controller = new AbortController(); let requests = 0, notifyRequests, notifyStop, notifyDispose, releaseStop, releaseDispose, settled = false;
  const started = new Promise(resolve => { notifyRequests = resolve; }), stopped = new Promise(resolve => { notifyStop = resolve; }), disposing = new Promise(resolve => { notifyDispose = resolve; });
  const stopGate = new Promise(resolve => { releaseStop = resolve; }), disposeGate = new Promise(resolve => { releaseDispose = resolve; });
  const f = fixture({
    request: (_url, options) => {
      assert.equal(options.signal, controller.signal); if (++requests === 2) notifyRequests();
      return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('PRIVATE_CANCELED_REQUEST'), { code: 'CONNECTION_CANCELED' })), { once: true }));
    },
    stopAfter: () => { notifyStop(); return stopGate; }, dispose: () => { notifyDispose(); return disposeGate; },
  });
  const pending = f.verifier.verify({ config, secrets, signal: controller.signal });
  pending.then(() => { settled = true; }, () => { settled = true; });
  const rejection = assert.rejects(pending, { code: 'CONNECTION_CANCELED' });
  await started; controller.abort(); await stopped; assert.equal(settled, false);
  releaseStop(); await disposing; assert.equal(settled, false); releaseDispose(); await rejection;
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']); assert.equal(requests, 2);
});

test('canceling final inspection never returns a successful exit pin, including offline simulation', async () => {
  for (const mock of [false, true]) {
    const controller = new AbortController(), f = mock ? { verifier: createSetupVerifier({ mock: true }) } : fixture();
    await assert.rejects(f.verifier.verify({ config, secrets, signal: controller.signal, inspect: async () => { controller.abort(); return { ok: true }; } }), { code: 'CONNECTION_CANCELED' });
    if (!mock) assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
  }
});

test('imported node setup verifies both ISP exits through that node and stops on hash loss without exposing credentials', async () => {
  const selected = { ...config, connectionMode: 'vpn-import' }; const vpnNode = vpnOutbound();
  const f = fixture({ inspectStart: request => { assert.deepEqual(request.vpnNode, vpnNode); assert.equal(request.vpnProxy, undefined); assert.equal(request.config.relay, undefined); } });
  const result = await f.verifier.verify({ config: selected, secrets, vpnNode });
  assert.deepEqual(result.expectedExitIps, ['203.0.113.8']); assert.doesNotMatch(JSON.stringify(result), /11111111|private\.invalid|new-password/);
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
  const lost = fixture({ lostVpnNode: true });
  await assert.rejects(lost.verifier.verify({ config: selected, secrets, vpnNode }), { code: 'SETUP_PROXY_UNVERIFIED' });
  assert.deepEqual(lost.calls.slice(-2), ['stop', 'dispose']);
  const invalid = fixture();
  await assert.rejects(invalid.verifier.verify({ config: selected, secrets }), { code: 'VPN_NODE_REQUIRED' });
  await assert.rejects(invalid.verifier.verify({ config, secrets, vpnNode }), { code: 'VPN_NODE_INVALID' });
  assert.deepEqual(invalid.calls, []);
});

test('imported latency averages verified HTTPS request durations, excludes startup, and stays absent in offline simulation', async () => {
  const times = [0, 10, 90, 110];
  const f = fixture({ now: () => times.shift() });
  const selected = { ...config, connectionMode: 'vpn-import' };
  const result = await f.verifier.verify({ config: selected, secrets, vpnNode: vpnOutbound() });
  assert.equal(result.latencyMs, 95);
  assert.deepEqual(result.checks, [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }]);
  assert.equal(times.length, 0);
  const mock = createSetupVerifier({ mock: true, dependencies: { now: () => assert.fail('offline simulation must not measure a real request') } });
  assert.equal((await mock.verify({ config: selected, secrets, vpnNode: vpnOutbound() })).latencyMs, null);
});

test('setup passes private relay credentials only to its isolated core and preserves the encrypted chain', async () => {
  const f = fixture();
  const chained = { ...config, relay: relayFixture() };
  const credentials = { ...secrets, ...relaySecrets };
  const result = await f.verifier.verify({ config: chained, secrets: credentials });
  assert.deepEqual(result.expectedExitIps, ['203.0.113.8']);
  assert.deepEqual(await f.options().dependencies.loadSecrets(), credentials);
  assert.deepEqual((await f.options().dependencies.loadConfig()).relay, chained.relay);
  assert.equal(JSON.stringify(result).includes(relaySecrets.RELAY_PASSWORD), false);
});

test('different or malformed exits fail and still stop the temporary core', async () => {
  for (const response of ['ip=203.0.113.9\n', 'ip=not-an-ip\n']) {
    const f = fixture({ request: async url => url.hostname === 'api.ipify.org' ? '{"ip":"203.0.113.8"}' : response });
    await assert.rejects(f.verifier.verify({ config, secrets }), { code: response.includes('not-an-ip') ? 'SETUP_CHECK_FAILED' : 'SETUP_EXIT_MISMATCH' });
    assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
  }
});

test('failed checks wait for both requests before stopping and never expose raw request errors', async () => {
  let peerFinished = false;
  const f = fixture({ request: async url => {
    if (url.hostname === 'api.ipify.org') throw new Error('private credentials leaked by upstream');
    await new Promise(resolve => setImmediate(resolve)); peerFinished = true;
    return 'ip=203.0.113.8\n';
  } });
  await assert.rejects(f.verifier.verify({ config, secrets }), error => error.code === 'SETUP_CHECK_FAILED' && !error.message.includes('credentials'));
  assert.equal(peerFinished, true);
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});

test('failed setup retains at most two fixed source-layer diagnostics and still stops before returning failure', async () => {
  const f = fixture({ request: async url => {
    const code = url.hostname === 'api.ipify.org' ? 'PROXY_CONNECT_REJECTED' : 'PROBE_HTTP_STATUS';
    throw Object.assign(new Error('PRIVATE_ACCOUNT_URL_RESPONSE'), { code,
      diagnostic: code === 'PROXY_CONNECT_REJECTED' ? { httpStatus: 502, targetHttpStatus: 500, token: 'PRIVATE_CREDENTIAL' } : { stage: 'target-response', targetHttpStatus: 500, response: 'PRIVATE_BODY' } });
  } });
  await assert.rejects(f.verifier.verify({ config, secrets }), cause => {
    assert.equal(cause.code, 'SETUP_CHECK_FAILED');
    assert.deepEqual(cause.diagnostic, { setupStage: 'checking-exit', nativeError: 'Error', checks: [
      { source: 'ipify', code: 'PROXY_CONNECT_REJECTED', stage: 'proxy-connect', connectHttpStatus: 502 },
      { source: 'cloudflare', code: 'PROBE_HTTP_STATUS', stage: 'target-response', targetHttpStatus: 500 },
    ] });
    assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|https:|new-password/); return true;
  });
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});

test('setup distinguishes fixed TLS failures and malformed exit responses without exposing arbitrary error categories', async () => {
  for (const [reason, expected] of [
    [{ code: 'PROBE_TLS_OR_SOCKET_FAILED', diagnostic: { httpStatus: 502, stage: 'proxy-connect' } }, { code: 'PROBE_TLS_OR_SOCKET_FAILED', stage: 'tls' }],
    [{ code: 'PRIVATE_CUSTOM_ERROR', diagnostic: { targetHttpStatus: 500 } }, { code: 'SETUP_CHECK_FAILED' }],
  ]) {
    const f = fixture({ request: async url => {
      if (url.hostname === 'api.ipify.org') throw Object.assign(new Error('PRIVATE_NATIVE_DETAILS'), reason);
      return 'ip=not-an-ip\n';
    } });
    await assert.rejects(f.verifier.verify({ config, secrets }), cause => {
      assert.deepEqual(cause.diagnostic, { setupStage: 'checking-exit', nativeError: 'Error', checks: [{ source: 'ipify', ...expected }, { source: 'cloudflare', code: 'SETUP_IP_INVALID', stage: 'target-response', targetHttpStatus: 200 }] });
      assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_|not-an-ip/); return true;
    });
    assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
  }
});

test('equivalent IPv6 spellings yield a canonical saved pin', async () => {
  const f = fixture({ request: async url => url.hostname === 'api.ipify.org' ? '{"ip":"2001:db8:0:0:0:0:0:8"}' : 'ip=2001:db8::8\n' });
  assert.deepEqual((await f.verifier.verify({ config, secrets })).expectedExitIps, ['2001:db8::8']);
});

test('failed startup and failed stop never return discovered pins', async () => {
  const start = fixture({ start: true });
  await assert.rejects(start.verifier.verify({ config, secrets }));
  assert.deepEqual(start.calls.slice(-2), ['stop', 'dispose']);
  const stop = fixture({ stop: true });
  await assert.rejects(stop.verifier.verify({ config, secrets }), error => error.code === 'SETUP_PROXY_STOP_FAILED' && !error.message.includes('private failure'));
  assert.equal(stop.calls.at(-1), 'dispose');
});

test('local setup failures retain their exact step and fixed native category through successful cleanup', async () => {
  for (const mode of ['vpn-compat', 'vpn-import']) {
    const input = { config: { ...config, connectionMode: mode }, secrets, ...(mode === 'vpn-import' ? { vpnNode: vpnOutbound() } : {}) };
    const denied = fixture({ dependencies: { lstat: async () => { throw Object.assign(new Error('PRIVATE_PATH'), { code: 'EACCES', path: 'PRIVATE_PATH' }); } } });
    await assert.rejects(denied.verifier.verify(input), cause => {
      assert.deepEqual(cause.diagnostic, { setupStage: 'preparing-runtime', nativeCode: 'EACCES', nativeError: 'Error' });
      assert.doesNotMatch(JSON.stringify(cause.diagnostic), /PRIVATE_/); return true;
    });
    assert.deepEqual(denied.calls, []);
    const broken = fixture({ inspectStart: () => { throw new TypeError('PRIVATE_ARGUMENT'); } });
    await assert.rejects(broken.verifier.verify(input), cause => {
      assert.deepEqual(cause.diagnostic, { setupStage: 'starting-proxy', nativeError: 'TypeError' }); return true;
    });
    assert.deepEqual(broken.calls, ['stop', 'port', 'start', 'stop', 'dispose']);
    const cleanup = fixture({ inspectStart: () => { throw new TypeError('PRIVATE_ARGUMENT'); },
      stopAfter: () => { throw Object.assign(new Error('PRIVATE_PATH'), { code: 'EBUSY' }); } });
    await assert.rejects(cleanup.verifier.verify(input), cause => {
      assert.equal(cause.code, 'SETUP_PROXY_STOP_FAILED');
      assert.deepEqual(cause.diagnostic, { setupStage: 'stopping-proxy', nativeCode: 'EBUSY', nativeError: 'Error' });
      assert.doesNotMatch(JSON.stringify(cause), /PRIVATE_/); return true;
    });
    assert.equal(cleanup.calls.at(-1), 'dispose');
  }
});

test('loss of owned proxy after successful checks prevents saving another process exit', async () => {
  const f = fixture({ lostCore: true });
  await assert.rejects(f.verifier.verify({ config, secrets }), { code: 'SETUP_PROXY_UNVERIFIED' });
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});

test('mock onboarding validates input and remains offline even with injected native dependencies', async () => {
  const forbidden = () => { throw new Error('must remain offline'); };
  const verifier = createSetupVerifier({ mock: true, dependencies: Object.fromEntries(['lstat', 'createPrivateDirectory', 'allocatePort', 'createRuntime', 'request'].map(name => [name, forbidden])) });
  assert.deepEqual((await verifier.verify({ config, secrets })).expectedExitIps, ['203.0.113.8']);
  await assert.rejects(verifier.verify({ config, secrets: { ...secrets, ISP_PASSWORD: 'unsafe\nline' } }), { code: 'SECRETS_INVALID' });
});

test('concurrent onboarding attempts serialize process ownership and cleanup', async () => {
  const f = fixture();
  await Promise.all([f.verifier.verify({ config, secrets }), f.verifier.verify({ config, secrets })]);
  assert.equal(f.calls.filter(call => call === 'dispose').length, 2);
  assert.equal(f.calls.indexOf('dispose') < f.calls.lastIndexOf('port'), true);
});

test('provided IP pins must match the observed ISP and remain unchanged', async () => {
  const selected = structuredClone(config);
  selected.probe.expectedExitIps = ['203.0.113.9', '203.0.113.8'];
  const f = fixture();
  assert.deepEqual((await f.verifier.verify({ config: selected, secrets })).expectedExitIps, selected.probe.expectedExitIps);
  selected.probe.expectedExitIps = ['203.0.113.9'];
  let inspected = false;
  await assert.rejects(f.verifier.verify({ config: selected, secrets, inspect: () => { inspected = true; } }), { code: 'SETUP_EXIT_MISMATCH' });
  assert.equal(inspected, false);
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});

test('quality callback uses the verified temporary proxy before cleanup and returns its report', async () => {
  const f = fixture();
  const result = await f.verifier.verify({ config, secrets, inspect: async input => {
    assert.equal(input.proxyPort, 49160); assert.equal(input.mock, false); assert.equal(input.mocked, false);
    assert.deepEqual(input.config.probe.expectedExitIps, ['203.0.113.8']);
    assert.equal(input.checks.length, 2);
    assert.equal(JSON.stringify(input).includes('new-password'), false);
    assert.equal(f.calls.includes('dispose'), false);
    return { sites: ['cleanip', 'ippure', 'ping0'] };
  } });
  assert.deepEqual(result.inspection, { sites: ['cleanip', 'ippure', 'ping0'] });
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});

test('quality callback failure or core loss still stops and never returns a trusted report', async () => {
  const failed = fixture();
  await assert.rejects(failed.verifier.verify({ config, secrets, inspect: async () => { throw new Error('quality failed'); } }));
  assert.deepEqual(failed.calls.slice(-2), ['stop', 'dispose']);
  const changes = {};
  const lost = fixture(changes);
  await assert.rejects(lost.verifier.verify({ config, secrets, inspect: async () => { changes.lostCore = true; return { complete: true }; } }), { code: 'SETUP_PROXY_UNVERIFIED' });
  assert.deepEqual(lost.calls.slice(-2), ['stop', 'dispose']);
});

test('mock quality callback receives an explicit offline context without any native dependency', async () => {
  const forbidden = () => { throw new Error('must remain offline'); };
  const verifier = createSetupVerifier({ mock: true, dependencies: Object.fromEntries(['lstat', 'createPrivateDirectory', 'allocatePort', 'createRuntime', 'request'].map(name => [name, forbidden])) });
  const result = await verifier.verify({ config, secrets, inspect: async input => {
    assert.equal(input.mock, true); assert.equal(input.mocked, true); assert.equal(input.proxyPort, null);
    return { status: 'mocked' };
  } });
  assert.deepEqual(result.inspection, { status: 'mocked' });
});

test('recovery stops only the isolated runtime without loading current config or credentials', async () => {
  const f = fixture();
  const result = await f.verifier.recoverAndStop();
  assert.deepEqual(result, { running: false, recovered: true, mock: false });
  assert.deepEqual(f.calls, ['stop', 'dispose']);
  assert.ok(f.options().runtimeRoot.endsWith('.setup-verification'));
  assert.equal(f.options().setupDiscovery, true);
  await assert.rejects(f.options().dependencies.loadConfig(), { code: 'SETUP_RECOVERY_INVALID' });
  await assert.rejects(f.options().dependencies.loadSecrets(), { code: 'SETUP_RECOVERY_INVALID' });
});

test('missing recovery directory and mock recovery invoke no runtime or network dependency', async () => {
  const forbidden = () => { throw new Error('unexpected native call'); };
  const absent = createSetupVerifier({ dependencies: { lstat: async () => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); }, createRuntime: forbidden } });
  assert.equal((await absent.recoverAndStop()).recovered, false);
  const mocked = createSetupVerifier({ mock: true, dependencies: { lstat: forbidden, createRuntime: forbidden, request: forbidden } });
  assert.deepEqual(await mocked.recoverAndStop(), { running: false, recovered: false, mock: true });
});

test('recovery waits for in-progress verification to finish its own cleanup', async () => {
  const f = fixture();
  await Promise.all([f.verifier.verify({ config, secrets }), f.verifier.recoverAndStop()]);
  assert.deepEqual(f.calls.slice(-4), ['stop', 'dispose', 'stop', 'dispose']);
});

test('compatibility setup passes the selected local entry only to its isolated HTTP core', async () => {
  const selected = { ...config, connectionMode: 'vpn-compat' };
  const vpnProxy = { type: 'socks', host: '127.0.0.1', port: 17891 };
  const onDiagnostic = () => {};
  const f = fixture({ onDiagnostic, inspectStart: request => {
    assert.deepEqual(request.vpnProxy, vpnProxy); assert.equal(request.config.vpnProxy, undefined);
  } });
  await f.verifier.verify({ config: selected, secrets, vpnProxy });
  assert.equal(f.options().onDiagnostic, onDiagnostic);
  assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
  await f.verifier.recoverAndStop(); assert.equal(f.options().onDiagnostic, onDiagnostic);
});

test('setup refuses invalid, noncompatibility and temporary-listener colliding VPN entries before starting', async () => {
  const selected = { ...config, connectionMode: 'vpn-compat' };
  const f = fixture();
  await assert.rejects(f.verifier.verify({ config: selected, secrets, vpnProxy: null }), { code: 'VPN_PROXY_INVALID' });
  await assert.rejects(f.verifier.verify({ config, secrets, vpnProxy: { type: 'http', host: '127.0.0.1', port: 17891 } }), { code: 'VPN_PROXY_INVALID' });
  assert.equal(f.calls.length, 0);
  await assert.rejects(f.verifier.verify({ config: selected, secrets, vpnProxy: { type: 'http', host: '127.0.0.1', port: 49160 } }), { code: 'VPN_PROXY_INVALID' });
  assert.equal(f.calls.includes('start'), false); assert.deepEqual(f.calls.slice(-2), ['stop', 'dispose']);
});
