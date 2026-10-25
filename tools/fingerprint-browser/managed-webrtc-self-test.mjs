// Headed native WebRTC acceptance. Protection uses the unchanged production
// manager; only the disposable positive control omits its WebRTC defenses.
import assert from 'node:assert/strict';
import path from 'node:path';
import http from 'node:http';
import dgram from 'node:dgram';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { setTimeout as wait } from 'node:timers/promises';
import { createBrowserManager, commandUsesProfile, splitWindowsCommandLine } from '../../backend/src/browser-session.mjs';
import { closeBrowser, createWindowsProcessTools, inspectProcess, sameProcess } from '../../backend/src/windows-process.mjs';
import { requireFingerprintRuntime, inspectFingerprintRuntime, FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { readCandidateRuntime } from './native-engine/candidate-runtime.mjs';

// Same RFC 5389 loopback responder as webrtc-self-test.mjs. Documentation-only
// mapped address produces a native srflx candidate without an Internet server.
async function localStun() {
  const socket = dgram.createSocket('udp4'); let packets = 0;
  socket.on('message', (request, remote) => {
    if (request.length < 20 || request.readUInt16BE(0) !== 1 || request.readUInt32BE(4) !== 0x2112a442) return;
    packets++; const answer = Buffer.alloc(32); answer.writeUInt16BE(0x0101); answer.writeUInt16BE(12, 2); request.copy(answer, 4, 4, 20);
    answer.writeUInt16BE(0x20, 20); answer.writeUInt16BE(8, 22); answer[25] = 1; answer.writeUInt16BE(remote.port ^ 0x2112, 26); answer.writeUInt32BE((0xcb00714d ^ 0x2112a442) >>> 0, 28); socket.send(answer, remote.port, remote.address);
  });
  socket.bind(0, '127.0.0.1'); await once(socket, 'listening');
  return { port: socket.address().port, packets: () => packets, close: () => new Promise(resolve => socket.close(resolve)) };
}
const nativeComplete = value => value?.secureContext && value.nativeConstructor && value.nativeOffer && value.offerCreated && value.gathered === 'complete' && value.closed;
function outcome(control, protectedSample) {
  if (!nativeComplete(control) || !(control.udpPackets > 0) || !control.candidateTypes?.includes('srflx') || !nativeComplete(protectedSample) || !protectedSample.managed) return 'unverified';
  return protectedSample.udpPackets === 0 && protectedSample.candidateTypes?.length === 0 ? 'local-positive-control-and-policy-verified' : 'policy-failed';
}
async function browserProbe(stunPort, sampleId, prefix) {
  let peer, result;
  try {
    peer = new RTCPeerConnection({ iceServers: [{ urls: `stun:127.0.0.1:${stunPort}` }], iceCandidatePoolSize: 0 });
    const types = []; let timer;
    const gathered = new Promise(resolve => { const finish = () => { clearTimeout(timer); resolve(); }; peer.onicecandidate = event => event.candidate ? types.push(event.candidate.type) : finish(); peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === 'complete') finish(); }; timer = setTimeout(finish, 7000); });
    peer.createDataChannel('local-managed-fixture'); await peer.setLocalDescription(await peer.createOffer()); await gathered;
    result = { secureContext: isSecureContext, nativeConstructor: /\[native code\]/.test(Function.prototype.toString.call(RTCPeerConnection)), nativeOffer: /\[native code\]/.test(Function.prototype.toString.call(RTCPeerConnection.prototype.createOffer)), offerCreated: peer.localDescription?.type === 'offer', gathered: peer.iceGatheringState, candidateTypes: [...new Set(types)] };
  } catch (error) { result = { error: String(error) }; }
  finally { peer?.close(); }
  await fetch(prefix + 'report', { method: 'POST', body: JSON.stringify({ sampleId, ...result }) });
  document.body.textContent = 'Local native WebRTC observation completed. This disposable window will close automatically.';
}
async function main() {
  const project = fileURLToPath(new URL('../../', import.meta.url));
  const candidate = process.env.MC_FP_SOURCE_CANDIDATE === '1' ? await readCandidateRuntime(process.argv[2]) : null;
  const root = candidate?.root || process.argv[2] || path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY), release = candidate?.release || FINGERPRINT_BROWSER_RELEASE;
  const runtime = await requireFingerprintRuntime(root, { release }); // Verify proof/pin before any browser can launch.
  await mkdir(path.join(project, '.cache'), { recursive: true });
  const directory = await mkdtemp(path.join(project, '.cache/managed-webrtc-acceptance-'));
  const report = { startedAt: new Date().toISOString(), engine: { version: runtime.version, integrity: runtime.integrity, sourceCandidate: Boolean(candidate), ...(candidate ? { sourceManifestSha256: candidate.sourceManifestSha256, buildReceiptSha256: candidate.buildReceiptSha256 } : {}) }, scope: 'localhost HTTP observer, rejecting HTTP proxy and native UDP STUN; disposable profiles only; no CDP or host network changes', variants: [], errors: [], outcome: 'unverified' };
  const prefix = `/s/${randomBytes(24).toString('base64url')}/`; let active, pending, observerViaProxy = 0;
  const observer = http.createServer(async (request, response) => {
    if (request.url === prefix && request.method === 'GET' && active) { response.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' }).end(`<!doctype html><title>Local native WebRTC acceptance</title><body>Checking native WebRTC in a disposable profile.<script>(${browserProbe.toString()})(${active.stunPort},${JSON.stringify(active.id)},${JSON.stringify(prefix)})</script>`); return; }
    if (request.url === prefix + 'report' && request.method === 'POST') {
      try { let body = ''; for await (const chunk of request) { body += chunk; if (body.length > 4096) throw new Error('Report too large'); } const value = JSON.parse(body); if (!pending || value.sampleId !== active?.id) throw new Error('Stale report'); pending(value); pending = null; response.writeHead(200).end(); } catch { response.writeHead(400).end(); } return;
    }
    response.writeHead(404).end();
  });
  const proxy = http.createServer((request, response) => { if (request.url.includes(prefix)) observerViaProxy++; response.writeHead(502).end(); });
  proxy.on('connect', (_request, socket) => socket.end('HTTP/1.1 502 Local fixture\r\nConnection: close\r\n\r\n'));
  const sockets = new Set(); for (const server of [observer, proxy]) server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; };
  try {
    const observerPort = await listen(observer), proxyPort = await listen(proxy), observationUrl = `http://127.0.0.1:${observerPort}${prefix}`;
    const processes = createWindowsProcessTools();
    for (const protectedMode of [false, true]) {
      const name = protectedMode ? 'production-manager-policy' : 'positive-control', stun = await localStun(); let identity, child, timer;
      const manager = createBrowserManager({ runtimeRoot: path.join(directory, name), fingerprintRoot: root, ...(candidate ? { readFingerprintRuntime: (target, options) => inspectFingerprintRuntime(target, { ...options, release }) } : {}), closeTimeoutMs: 15000 });
      const result = { name, udpPackets: 0, closed: false }; report.variants.push(result); let controlProfile;
      const closeControl = async () => {
        if (!identity) { assert.ok(!child?.pid, 'Control ownership unresolved; disposable browser may still run'); return; }
        const owned = [identity];
        const retainDescendants = snapshot => { for (let index = 0; index < owned.length; index++) for (const value of snapshot) if (value.parentPid === owned[index].pid && !owned.some(item => item.pid === value.pid) && (value.unreadable || value.executable.toLowerCase() === identity.executable.toLowerCase())) owned.push(value); };
        retainDescendants(await processes.listProcessCandidates('chrome.exe'));
        await closeBrowser(identity, { timeoutMs: 15000 });
        for (let attempt = 0; attempt < 5; attempt++) {
          const snapshot = await processes.listProcessCandidates('chrome.exe'); retainDescendants(snapshot);
          const remaining = snapshot.filter(value => commandUsesProfile(value.commandLine, controlProfile) || owned.some(item => sameProcess(item, value) || item.pid === value.pid && (item.unreadable || value.unreadable) || value.parentPid === item.pid && (value.unreadable || value.executable.toLowerCase() === identity.executable.toLowerCase())));
          if (!remaining.length) { result.closed = true; delete result.unresolvedPids; return; } result.unresolvedPids = remaining.map(value => value.pid); await wait(200);
        }
        throw new Error('Control descendants/profile processes remain after normal close');
      };
      try {
        active = { id: randomUUID(), stunPort: stun.port };
        const plan = await manager.plan({ browser: 'fingerprint', service: 'observation', observationUrl, observationPort: observerPort, workspaceId: randomUUID(), port: proxyPort, nativeGraphics: true });
        controlProfile = plan.profile; const preferences = path.join(plan.profile, 'Default/Preferences'); await mkdir(path.dirname(preferences), { recursive: true });
        await writeFile(preferences, JSON.stringify({ webrtc: { ip_handling_policy: 'default' }, background_mode: { enabled: false } }));
        const received = new Promise((resolve, reject) => { pending = resolve; timer = setTimeout(() => reject(new Error('Local native WebRTC report timed out')), 30000); }); received.catch(() => {});
        if (protectedMode) { await manager.launch(plan); result.managed = (await manager.status()).managed === true; }
        else {
          const args = plan.args.filter(arg => !/^--(?:force-)?webrtc-ip-handling-policy=/.test(arg) && arg !== '--disable-non-proxied-udp');
          const env = { ...process.env }; for (const key of Object.keys(env)) if (/^(https?_proxy|all_proxy|no_proxy)$/i.test(key)) delete env[key];
          child = spawn(plan.executable, args, { detached: true, windowsHide: false, stdio: 'ignore', env }); await once(child, 'spawn'); child.unref();
          for (let attempt = 0; attempt < 10 && !identity; attempt++) { const value = await inspectProcess(child.pid); if (value && value.executable.toLowerCase() === plan.executable.toLowerCase() && commandUsesProfile(value.commandLine, plan.profile) && JSON.stringify(splitWindowsCommandLine(value.commandLine).slice(1)) === JSON.stringify(args)) identity = value; else await wait(100); }
          assert.ok(identity, 'Positive-control native process ownership must be independently verified');
        }
        Object.assign(result, await received); await wait(100); result.udpPackets = stun.packets();
        if (protectedMode) { assert.equal((await manager.close()).closed, true); result.closed = (await manager.status()).running === false; result.preferencesRestored = JSON.parse(await readFile(preferences, 'utf8')).webrtc?.ip_handling_policy === 'default'; assert.ok(result.preferencesRestored, 'Manager must restore the original disposable WebRTC preference'); }
        else await closeControl();
      } catch (error) { result.error = error.message; report.errors.push({ name, code: error.code, message: error.message }); }
      finally {
        clearTimeout(timer); pending = null; active = null; result.udpPackets = stun.packets();
        try { if (protectedMode && (await manager.status()).running) await manager.close(); else if (!protectedMode && !result.closed) await closeControl(); } catch (error) { report.errors.push({ name, cleanupError: error.message, pid: identity?.pid || child?.pid, profile: controlProfile }); }
        await stun.close();
      }
      if (!protectedMode && child?.pid && !result.closed) break; // Preserve unresolved ownership; do not open another browser.
    }
    report.outcome = report.errors.length || observerViaProxy ? 'unverified' : outcome(...report.variants);
  } catch (error) { report.errors.push({ code: error.code, message: error.message }); }
  finally {
    for (const socket of sockets) socket.destroy(); await Promise.all([observer, proxy].map(server => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); })));
    report.finishedAt = new Date().toISOString(); report.observerViaProxy = observerViaProxy;
    const file = path.join(directory, 'report.json'); await writeFile(file, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ file, ...report }, null, 2));
    if (report.outcome !== 'local-positive-control-and-policy-verified') process.exitCode = 1;
  }
}
if (process.argv[2] === '--self-check') {
  const stun = await localStun(), client = dgram.createSocket('udp4');
  try {
    const request = Buffer.alloc(20); request.writeUInt16BE(1); request.writeUInt32BE(0x2112a442, 4); randomBytes(12).copy(request, 8);
    const reply = once(client, 'message', { signal: AbortSignal.timeout(2000) }); client.send(request, stun.port, '127.0.0.1'); const [answer] = await reply;
    assert.equal(stun.packets(), 1); assert.equal(answer.readUInt16BE(0), 0x0101); assert.deepEqual(answer.subarray(4, 20), request.subarray(4, 20));
    const native = { secureContext: true, nativeConstructor: true, nativeOffer: true, offerCreated: true, gathered: 'complete', closed: true };
    const control = { ...native, udpPackets: 1, candidateTypes: ['srflx'] }, protectedSample = { ...native, managed: true, udpPackets: 0, candidateTypes: [] };
    assert.equal(outcome({ ...control, udpPackets: 0 }, protectedSample), 'unverified'); assert.equal(outcome(control, protectedSample), 'local-positive-control-and-policy-verified');
    assert.equal(outcome(control, { ...protectedSample, udpPackets: 1 }), 'policy-failed'); assert.equal(outcome(control, { ...protectedSample, gathered: 'gathering' }), 'unverified');
    console.log('Loopback STUN transaction and positive-control fail-closed checks passed; no browser launched.');
  } finally { client.close(); await stun.close(); }
} else await main();
