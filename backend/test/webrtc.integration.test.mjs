import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createHash, createPublicKey } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { relayTlsFixture } from './relay-tls-fixture.mjs';

// Explicitly opt in with BROWSER_BIN. Every browser is a new headless process
// with a disposable profile; this never connects to an existing Chrome session.
const binary = process.env.BROWSER_BIN;
const headful = process.env.PROXYPILOT_BROWSER_HEADFUL === '1';
const cacheRoot = fileURLToPath(new URL('../.cache/', import.meta.url));
const policy = 'disable_non_proxied_udp';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function localStun() {
  const socket = dgram.createSocket('udp4');
  let packets = 0;
  socket.on('message', (request, remote) => {
    if (request.length < 20 || request.readUInt16BE(0) !== 0x0001 || request.readUInt32BE(4) !== 0x2112a442) return;
    packets++;
    // RFC 5389 Binding Success with a documentation-only XOR-MAPPED-ADDRESS.
    // This makes the native ICE agent complete gathering without any Internet STUN.
    const response = Buffer.alloc(32);
    response.writeUInt16BE(0x0101, 0); response.writeUInt16BE(12, 2);
    request.copy(response, 4, 4, 20);
    response.writeUInt16BE(0x0020, 20); response.writeUInt16BE(8, 22);
    response[25] = 1; response.writeUInt16BE(remote.port ^ 0x2112, 26);
    response.writeUInt32BE((0xcb00714d ^ 0x2112a442) >>> 0, 28);
    socket.send(response, remote.port, remote.address);
  });
  socket.bind(0, '127.0.0.1'); await once(socket, 'listening');
  return { port: socket.address().port, packets: () => packets, close: () => new Promise(resolve => socket.close(resolve)) };
}

async function denyProxy({ tlsPort } = {}) {
  // All browser HTTP/HTTPS traffic, including background requests, terminates
  // here. This fixture never resolves or forwards a requested destination.
  const server = http.createServer((_, response) => { response.writeHead(502); response.end('Local regression fixture'); });
  const tunnels = new Set();
  server.on('connect', (request, socket, head) => {
    if (!tlsPort || request.url !== `localhost:${tlsPort}`) return socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n');
    const upstream = net.connect(tlsPort, '127.0.0.1');
    for (const connection of [socket, upstream]) { tunnels.add(connection); connection.once('close', () => tunnels.delete(connection)); }
    socket.on('error', () => upstream.destroy()); upstream.on('error', () => socket.destroy());
    socket.once('close', () => upstream.destroy()); upstream.once('close', () => socket.destroy());
    upstream.once('connect', () => {
      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length) upstream.write(head);
      socket.pipe(upstream).pipe(socket);
    });
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { port: server.address().port, close: () => { for (const socket of tunnels) socket.destroy(); server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); } };
}

function debugPipe(child) {
  let sequence = 0; let pendingBytes = Buffer.alloc(0); const pending = new Map();
  child.stdio[4].on('data', data => {
    pendingBytes = Buffer.concat([pendingBytes, data]);
    let boundary;
    while ((boundary = pendingBytes.indexOf(0)) !== -1) {
      const raw = pendingBytes.subarray(0, boundary).toString('utf8');
      pendingBytes = pendingBytes.subarray(boundary + 1);
      if (!raw) continue;
      let message; try { message = JSON.parse(raw); } catch { continue; }
      const waiter = pending.get(message.id); if (!waiter) continue;
      pending.delete(message.id); clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(message.error.message)); else waiter.resolve(message.result);
    }
  });
  const abort = error => { for (const waiter of pending.values()) { clearTimeout(waiter.timer); waiter.reject(error); } pending.clear(); };
  child.once('error', abort); child.once('exit', () => abort(new Error('Disposable Chrome process exited')));
  child.stdio[3].on('error', abort); child.stdio[4].on('error', abort);
  return (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Chrome CDP timeout: ${method}`)); }, 15000);
    pending.set(id, { resolve, reject, timer });
    child.stdio[3].write(`${JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })}\0`, error => {
      if (error) { clearTimeout(timer); pending.delete(id); reject(error); }
    });
  });
}

async function stopBrowser(child, command) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit').catch(() => {});
  command('Browser.close').catch(() => {});
  await Promise.race([exited, delay(5000)]);
  if (child.exitCode === null && child.signalCode === null) { child.kill(); await exited; }
}

async function gather(profile, proxyPort, { flag, preference, chromeFlag = false, tlsUrl, certificatePin }) {
  const stun = await localStun();
  await mkdir(path.join(profile, 'Default'), { recursive: true });
  await writeFile(path.join(profile, 'Default', 'Preferences'), JSON.stringify({
    ...(preference ? { webrtc: { ip_handling_policy: policy } } : {}),
    net: { network_prediction_options: 2 },
    background_mode: { enabled: false },
  }));
  let child, command, stderr = '';
  try {
  child = spawn(binary, [
    // Headful checks exercise the production browser engine in a minimized,
    // disposable window; they never attach to the user's existing browser.
    ...(headful ? ['--start-minimized'] : ['--headless=new']), '--disable-gpu', '--remote-debugging-pipe', `--user-data-dir=${profile}`, '--profile-directory=Default',
    '--no-first-run', '--no-default-browser-check', '--disable-background-mode', '--disable-quic',
    '--disable-background-networking', '--disable-component-update', '--disable-default-apps', '--disable-sync',
    '--disable-domain-reliability', '--disable-client-side-phishing-detection', '--safebrowsing-disable-auto-update',
    '--metrics-recording-only', '--deny-permission-prompts', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
    `--proxy-server=http://127.0.0.1:${proxyPort}`, '--proxy-bypass-list=<-loopback>',
    ...(flag ? [`--force-webrtc-ip-handling-policy=${policy}`] : []),
    ...(chromeFlag ? [`--webrtc-ip-handling-policy=${policy}`] : []), 'about:blank',
    ...(certificatePin ? [`--ignore-certificate-errors-spki-list=${certificatePin}`] : []),
  ], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  child.stderr.on('data', data => { stderr = (stderr + data.toString()).slice(-4000); });
  command = debugPipe(child);
    const version = await command('Browser.getVersion');
    const { targetId } = await command('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await command('Target.attachToTarget', { targetId, flatten: true });
    if (tlsUrl) {
      await command('Page.enable', {}, sessionId);
      const navigation = await command('Page.navigate', { url: tlsUrl }, sessionId);
      if (navigation.errorText) throw new Error(navigation.errorText);
      const page = await command('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `(async () => { if (document.readyState === 'loading') await new Promise(resolve => addEventListener('DOMContentLoaded', resolve, { once: true })); return document.body?.textContent; })()` }, sessionId);
      return { version: version.product, body: page.result.value };
    }
    const result = await command('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `
      (async () => {
        const nativeConstructor = /\\[native code\\]/.test(Function.prototype.toString.call(RTCPeerConnection));
        const nativeOffer = /\\[native code\\]/.test(Function.prototype.toString.call(RTCPeerConnection.prototype.createOffer));
        const peer = new RTCPeerConnection({ iceServers: [{ urls: 'stun:127.0.0.1:${stun.port}' }], iceCandidatePoolSize: 0 });
        const types = [];
        const complete = new Promise(resolve => {
          let finished = false;
          const finish = () => { if (!finished) { finished = true; resolve(); } };
          peer.onicecandidate = event => { if (event.candidate) types.push(event.candidate.type); else finish(); };
          peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === 'complete') finish(); };
          setTimeout(finish, 5000);
        });
        peer.createDataChannel('local-regression');
        await peer.setLocalDescription(await peer.createOffer());
        await complete;
        const output = { nativeConstructor, nativeOffer, candidateTypes: [...new Set(types)], gathered: peer.iceGatheringState, offerCreated: peer.localDescription?.type === 'offer' };
        peer.close();
        return output;
      })()
    ` }, sessionId);
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || 'Native WebRTC evaluation failed');
    await delay(100);
    return { flag, chromeFlag, preference, version: version.product, ...result.result.value, udpPackets: stun.packets() };
  } catch (error) {
    // Only this disposable process's diagnostics are included; never read a user profile.
    throw new Error(`${error.message}${stderr ? `\nDisposable browser stderr: ${stderr}` : ''}`, { cause: error });
  } finally { await stopBrowser(child, command); await stun.close(); }
}

test('native Chrome WebRTC: local STUN baseline, legacy flag, profile preference, and Chrome policy switch', { skip: !binary, timeout: 120000 }, async t => {
  await mkdir(cacheRoot, { recursive: true });
  const directory = await mkdtemp(path.join(cacheRoot, 'webrtc-integration-'));
  const proxy = await denyProxy();
  try {
    const variants = [
      { name: 'unrestricted-baseline', flag: false, preference: false },
      { name: 'current-flag', flag: true, preference: false },
      { name: 'profile-preference', flag: false, preference: true },
      { name: 'flag-and-preference', flag: true, preference: true },
      { name: 'chrome-policy-switch', flag: false, preference: false, chromeFlag: true },
      { name: 'production-defense', flag: true, preference: true, chromeFlag: true },
    ];
    const results = [];
    for (const variant of variants) {
      const result = await gather(path.join(directory, variant.name), proxy.port, variant);
      results.push({ name: variant.name, mode: headful ? 'headful' : 'headless-new', ...result });
      t.diagnostic(JSON.stringify(results.at(-1)));
      assert.equal(result.nativeConstructor, true, 'The native RTCPeerConnection constructor must remain available');
      assert.equal(result.nativeOffer, true, 'The native createOffer implementation must be exercised');
      assert.equal(result.offerCreated, true, 'Native WebRTC must create a real local offer');
    }
    assert.ok(results[0].udpPackets > 0, 'Positive control must reach local STUN; otherwise zero packets cannot prove protection');
    assert.equal(results[2].udpPackets, 0, 'Profile policy must prevent non-proxied STUN UDP');
    assert.equal(results[3].udpPackets, 0, 'Production flag plus profile policy must prevent non-proxied STUN UDP');
    assert.equal(results[4].udpPackets, 0, 'Chrome policy switch must prevent non-proxied STUN UDP');
    assert.equal(results[5].udpPackets, 0, 'Production preference and both switches must prevent non-proxied STUN UDP');
    assert.deepEqual(results[5].candidateTypes, [], 'Production defense must not expose ICE candidates in this fixture');
    // Chromium's current ordinary Chrome path consumes the profile preference.
    // The force flag is also recorded for comparison; Chromium versions may
    // consume it only in the headless implementation, so this test does not
    // claim flag-only protection for a normal window unless the observed UDP
    // count demonstrates it.
  } finally {
    await proxy.close();
    assert.equal(path.dirname(directory), path.resolve(cacheRoot));
    assert.ok(path.basename(directory).startsWith('webrtc-integration-'));
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

// Browser versions may interpret individual Chrome-specific switches differently.
// This cross-browser check keeps the full production defense mandatory, with a
// positive control proving that the fixture really can send local STUN packets.
test('native Chromium production WebRTC policy blocks local STUN and ICE candidates in an isolated profile', { skip: !binary, timeout: 60000 }, async t => {
  await mkdir(cacheRoot, { recursive: true });
  const directory = await mkdtemp(path.join(cacheRoot, 'webrtc-integration-production-'));
  const proxy = await denyProxy();
  try {
    const baseline = await gather(path.join(directory, 'baseline'), proxy.port, { flag: false, preference: false });
    const protectedBrowser = await gather(path.join(directory, 'production'), proxy.port, { flag: true, preference: true, chromeFlag: true });
    for (const result of [baseline, protectedBrowser]) {
      assert.equal(result.nativeConstructor, true); assert.equal(result.nativeOffer, true); assert.equal(result.offerCreated, true);
    }
    assert.ok(baseline.udpPackets > 0, 'A working local STUN baseline is required to prove the policy');
    assert.equal(protectedBrowser.udpPackets, 0, 'The complete production defense must block non-proxied STUN');
    assert.deepEqual(protectedBrowser.candidateTypes, [], 'The complete production defense must not expose ICE candidates');
    t.diagnostic(JSON.stringify({ mode: headful ? 'headful' : 'headless-new', version: protectedBrowser.version, baselineUdpPackets: baseline.udpPackets, protectedUdpPackets: protectedBrowser.udpPackets, candidateTypes: protectedBrowser.candidateTypes }));
  } finally {
    await proxy.close();
    assert.equal(path.dirname(directory), path.resolve(cacheRoot)); assert.ok(path.basename(directory).startsWith('webrtc-integration-production-'));
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('native Chrome isolated profile opens only the loopback HTTPS fixture and rejects its untrusted certificate by default', { skip: !binary, timeout: 60000 }, async t => {
  await mkdir(cacheRoot, { recursive: true });
  const directory = await mkdtemp(path.join(cacheRoot, 'webrtc-integration-tls-'));
  let protocol;
  const server = https.createServer(relayTlsFixture.selfSignedLeaf, (request, response) => { protocol = request.socket.getProtocol(); response.end('local-chrome-tls-fixture'); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const proxy = await denyProxy({ tlsPort: server.address().port });
  try {
    const tlsUrl = `https://localhost:${server.address().port}/`;
    const defense = { flag: true, preference: true, chromeFlag: true, tlsUrl };
    await assert.rejects(gather(path.join(directory, 'untrusted'), proxy.port, defense), /ERR_CERT_AUTHORITY_INVALID/);
    // Trust this public test certificate's key only inside this disposable
    // process; no OS trust store, global ignore flag or user profile is changed.
    const certificatePin = createHash('sha256').update(createPublicKey(relayTlsFixture.selfSignedLeaf.cert).export({ type: 'spki', format: 'der' })).digest('base64');
    const result = await gather(path.join(directory, 'fixture-pin'), proxy.port, { ...defense, certificatePin });
    assert.equal(result.body, 'local-chrome-tls-fixture');
    assert.ok(['TLSv1.2', 'TLSv1.3'].includes(protocol));
    t.diagnostic(JSON.stringify({ version: result.version, protocol, loopbackHttpsOpened: true, untrustedCertificateRejected: true, trust: 'disposable-fixture-spki-only' }));
  } finally {
    await proxy.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    assert.equal(path.dirname(directory), path.resolve(cacheRoot)); assert.ok(path.basename(directory).startsWith('webrtc-integration-tls-'));
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
