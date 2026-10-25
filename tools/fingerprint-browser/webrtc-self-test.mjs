// Local positive-control investigation only. These baseline profiles deliberately
// differ from production protection; no option here is added to MC launch args.
import path from 'node:path';
import http from 'node:http';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { setTimeout as wait } from 'node:timers/promises';
import { requireFingerprintRuntime, FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';

const project = fileURLToPath(new URL('../../', import.meta.url));
const engine = await requireFingerprintRuntime(process.argv[2] || path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY));
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const directory = await mkdtemp(path.join(project, '.cache/fingerprint-webrtc-acceptance-'));
const pageServer = http.createServer((_request, response) => response.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html><title>Loopback WebRTC fixture</title><p>Local fixture only.</p>'));
pageServer.listen(0, '127.0.0.1'); await once(pageServer, 'listening');
const origin = `http://127.0.0.1:${pageServer.address().port}`;
const proxyServer = http.createServer((_request, response) => response.writeHead(502).end());
proxyServer.on('connect', (_request, socket) => socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
proxyServer.listen(0, '127.0.0.1'); await once(proxyServer, 'listening');
const report = { engine: engine.version, scope: 'localhost secure-context page, local UDP STUN; no external network or accounts', variants: [], outcome: 'unverified' };

async function variant(name, { explicitDefault = false, customFalse = false, protectedPolicy = false, grantLocal = false } = {}) {
  const socket = dgram.createSocket('udp4'); let packets = 0;
  socket.on('message', (request, remote) => {
    if (request.length < 20 || request.readUInt16BE(0) !== 1 || request.readUInt32BE(4) !== 0x2112a442) return;
    packets++; const answer = Buffer.alloc(32); answer.writeUInt16BE(0x0101); answer.writeUInt16BE(12, 2); request.copy(answer, 4, 4, 20); answer.writeUInt16BE(0x20, 20); answer.writeUInt16BE(8, 22); answer[25] = 1; answer.writeUInt16BE(remote.port ^ 0x2112, 26); answer.writeUInt32BE((0xcb00714d ^ 0x2112a442) >>> 0, 28); socket.send(answer, remote.port, remote.address);
  });
  socket.bind(0, '127.0.0.1'); await once(socket, 'listening');
  const profile = path.join(directory, name); await mkdir(path.join(profile, 'Default'), { recursive: true });
  const policy = protectedPolicy ? 'disable_non_proxied_udp' : 'default';
  await writeFile(path.join(profile, 'Default/Preferences'), JSON.stringify({ webrtc: { ip_handling_policy: policy }, background_mode: { enabled: false } }));
  let context;
  try {
    context = await chromium.launchPersistentContext(profile, { executablePath: engine.executable, headless: false, args: [
      '--start-minimized', '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--no-first-run', '--disable-quic', `--log-file=${path.join(profile, 'engine.log')}`,
      `--proxy-server=http://127.0.0.1:${proxyServer.address().port}`, `--proxy-bypass-list=<-loopback>;127.0.0.1:${pageServer.address().port}`,
      ...(explicitDefault || protectedPolicy ? [`--force-webrtc-ip-handling-policy=${policy}`, `--webrtc-ip-handling-policy=${policy}`] : []),
      ...(customFalse ? ['--disable-non-proxied-udp=false'] : []), ...(protectedPolicy ? ['--disable-non-proxied-udp'] : []),
    ] });
    const page = context.pages()[0]; await page.goto(origin);
    const permissions = [];
    if (grantLocal) {
      const session = await context.newCDPSession(page);
      for (const name of ['local-network-access', 'local-network']) {
        try { await session.send('Browser.setPermission', { permission: { name }, setting: 'granted', origin }); permissions.push({ name, granted: true }); }
        catch (error) { permissions.push({ name, granted: false, reason: error.message.split('\n')[0] }); }
      }
    }
    const result = await page.evaluate(async stunPort => {
      const peer = new RTCPeerConnection({ iceServers: [{ urls: `stun:127.0.0.1:${stunPort}` }], iceCandidatePoolSize: 0 });
      const types = []; let completed = false;
      const gathered = new Promise(resolve => { const finish = () => { completed = true; resolve(); }; peer.onicecandidate = e => e.candidate ? types.push(e.candidate.type) : finish(); peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === 'complete') finish(); }; setTimeout(finish, 5000); });
      peer.createDataChannel('localhost-fixture'); await peer.setLocalDescription(await peer.createOffer()); await gathered;
      const output = { secureContext: isSecureContext, nativeConstructor: /\[native code\]/.test(Function.prototype.toString.call(RTCPeerConnection)), nativeOffer: /\[native code\]/.test(Function.prototype.toString.call(RTCPeerConnection.prototype.createOffer)), offerCreated: peer.localDescription?.type === 'offer', gathered: peer.iceGatheringState, completed, candidateTypes: [...new Set(types)] }; peer.close(); return output;
    }, socket.address().port);
    await wait(100);
    report.variants.push({ name, policy, customFalse, permissions, ...result, udpPackets: packets });
  } catch (error) { report.variants.push({ name, error: error.message.split('\n')[0], udpPackets: packets }); }
  finally { await context?.close(); await new Promise(resolve => socket.close(resolve)); }
}

try {
  await variant('secure-local-default');
  await variant('secure-local-explicit-default', { explicitDefault: true });
  await variant('secure-local-explicit-default-local-permission', { explicitDefault: true, grantLocal: true });
  await variant('secure-local-custom-false', { explicitDefault: true, customFalse: true, grantLocal: true });
  await variant('production-policy', { protectedPolicy: true, grantLocal: true });
  const positive = report.variants.slice(0, -1).filter(v => v.udpPackets > 0);
  const protectedBrowser = report.variants.at(-1);
  if (positive.length && protectedBrowser.udpPackets === 0 && protectedBrowser.nativeConstructor && protectedBrowser.nativeOffer && protectedBrowser.offerCreated && !protectedBrowser.candidateTypes.length) report.outcome = 'local-positive-control-and-policy-verified';
} finally {
  pageServer.closeAllConnections(); proxyServer.closeAllConnections(); await Promise.all([new Promise(resolve => pageServer.close(resolve)), new Promise(resolve => proxyServer.close(resolve))]);
  const file = path.join(directory, 'report.json'); await writeFile(file, JSON.stringify(report, null, 2));
  if (report.outcome !== 'local-positive-control-and-policy-verified') process.exitCode = 1;
  console.log(JSON.stringify({ file, ...report }, null, 2));
}
