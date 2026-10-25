import { collectIdentitySurface, collectIdentityContexts } from './browser-identity-probe.js';
const ipKey = value => { try { return value.includes(':') ? new URL(`http://[${value}]/`).hostname.toLowerCase() : value; } catch { return value; } };
const validIp = value => {
  if (typeof value !== 'string') return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) return value.split('.').every(part => +part <= 255);
  if (!value.includes(':') || !/^[a-f0-9:.]+$/i.test(value)) return false;
  try { return new URL(`http://[${value}]/`).hostname.startsWith('['); } catch { return false; }
};
const deadline = (task, ms, fallback) => new Promise(resolve => { const timer = setTimeout(() => resolve(fallback), ms); Promise.resolve(task).then(value => { clearTimeout(timer); resolve(value); }, () => { clearTimeout(timer); resolve(fallback); }); });
const fetchWithin = async (url, options = {}, ms = 6000) => {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), ms);
  try { return await fetch(url, { ...options, signal: controller.signal }); } finally { clearTimeout(timer); }
};
export function classifyIceCandidate(candidate, expectedExitIps = []) {
  const parts = String(candidate || '').trim().split(/\s+/);
  const address = parts[4] || '', type = parts[parts.indexOf('typ') + 1];
  if (!address) return null;
  if (/\.local\.?$/i.test(address)) return { kind: 'mdns', type, address, unexpected: false };
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  const v4Address = mapped || address;
  const v4 = /^\d+\.\d+\.\d+\.\d+$/.test(v4Address) && v4Address.split('.').every(value => +value <= 255);
  const v6 = address.includes(':') && /^[a-f0-9:.]+$/i.test(address);
  if (!v4 && !v6) return null;
  const octets = v4Address.split('.').map(Number);
  const privateAddress = v4 ? octets[0] === 10 || octets[0] === 127 || octets[0] === 0 || octets[0] === 169 && octets[1] === 254 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168 || octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127
    : /^(?:::1$|::$|f[cd][a-f0-9]{2}:|fe[89ab][a-f0-9]:)/i.test(address);
  return { kind: privateAddress ? 'private' : 'public', type, address, unexpected: !privateAddress && !expectedExitIps.some(ip => ipKey(ip) === ipKey(address)) };
}

export async function collectBrowserEnvironment({ navigator: nav = globalThis.navigator, window: win = globalThis.window } = {}) {
  const surface = await collectIdentitySurface({ navigator: nav, window: win });
  const permissions = await Promise.all(['geolocation', 'camera', 'microphone'].map(async name => {
    const state = await deadline(Promise.resolve().then(() => nav.permissions?.query({ name })).then(result => result?.state), 1500, 'unverified');
    return { name, state: ['granted', 'denied', 'prompt'].includes(state) ? state : 'unverified' };
  }));
  return { userAgent: surface.userAgent, language: surface.language, languages: surface.languages,
    timezone: surface.timezone, platform: surface.platform, hardwareConcurrency: surface.hardwareConcurrency, ...('deviceMemory' in surface ? { deviceMemory: surface.deviceMemory } : {}),
    viewport: { width: Math.min(win.innerWidth || 0, 100000), height: Math.min(win.innerHeight || 0, 100000), screenWidth: Math.min(win.screen?.width || 0, 100000), screenHeight: Math.min(win.screen?.height || 0, 100000), pixelRatio: Math.min(win.devicePixelRatio || 1, 100) }, permissions,
    uaCh: surface.uaCh };
}

export async function observeExit(source, { fetch: fetchApi = globalThis.fetch, signal, now = Date.now } = {}) {
  const started = now(), controller = new AbortController();
  const abort = () => controller.abort(); signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, 8000);
  try {
    const response = await fetchApi(source.url, { mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal });
    if (!response.ok) return { id: source.id, status: 'failed', elapsedMs: now() - started, errorCode: 'HTTP_RESPONSE_FAILED' };
    const body = await response.text();
    if (body.length > 16384) throw new Error('oversize');
    const ip = source.format === 'json' ? JSON.parse(body).ip : /^ip=([^\r\n]+)$/m.exec(body)?.[1];
    const v4 = typeof ip === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(ip) && ip.split('.').every(value => +value <= 255);
    const v6 = typeof ip === 'string' && ip.includes(':') && validIp(ip);
    if (!v4 && !v6 || source.family === 4 && !v4 || source.family === 6 && !v6) throw new Error('invalid IP');
    return { id: source.id, status: 'measured', ip, elapsedMs: now() - started };
  } catch { return { id: source.id, status: 'failed', elapsedMs: Math.min(now() - started, 45000), errorCode: controller.signal.aborted ? 'PROBE_TIMEOUT_OR_ABORTED' : 'NETWORK_CORS_OR_RESPONSE_FAILED' }; }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

export function observeWebRtc({ expectedExitIps = [], stun = 'stun:stun.cloudflare.com:3478', rtcFactory = options => new RTCPeerConnection(options), signal } = {}) {
  const counts = { public: 0, unexpectedPublic: 0, private: 0, mdns: 0, relay: 0 }, readings = [], seen = new Set();
  return new Promise(resolve => {
    let peer, finished = false, timer;
    const finish = (complete, errorCode) => {
      if (finished) return; finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      if (peer) { peer.onicecandidate = null; peer.onicegatheringstatechange = null; try { peer.close(); } catch {} }
      resolve({ report: { status: readings.length ? 'measured' : 'unverified', complete, counts, ...(errorCode ? { errorCode } : {}) }, readings });
    };
    const abort = () => finish(false, 'ICE_ABORTED');
    if (signal?.aborted) return finish(false, 'ICE_ABORTED');
    signal?.addEventListener('abort', abort, { once: true }); timer = setTimeout(() => finish(false, 'ICE_DEADLINE'), 7000);
    try {
      peer = rtcFactory({ iceServers: [{ urls: stun }], iceCandidatePoolSize: 0 });
      peer.createDataChannel('mc-observation');
      peer.onicecandidate = event => {
        if (!event.candidate) return finish(true);
        const row = classifyIceCandidate(event.candidate.candidate, expectedExitIps);
        if (!row || readings.length >= 100 || seen.has(`${row.address}:${row.type}`)) return;
        seen.add(`${row.address}:${row.type}`); readings.push(row); counts[row.kind]++;
        if (row.unexpected) counts.unexpectedPublic++; if (row.type === 'relay') counts.relay++;
      };
      peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === 'complete') finish(true); };
      Promise.resolve(peer.createOffer()).then(offer => peer.setLocalDescription(offer)).catch(() => finish(false, 'ICE_NOT_AVAILABLE'));
    } catch { finish(false, 'ICE_NOT_AVAILABLE'); }
  });
}

async function canvasReading(enabled) {
  if (!enabled) return { status: 'unverified', reason: 'OPTIONAL_TEST_NOT_SELECTED' };
  try {
    const canvas = document.createElement('canvas'); canvas.width = 260; canvas.height = 60;
    const context = canvas.getContext('2d'); if (!context) throw new Error('no context');
    context.fillStyle = '#087c63'; context.fillRect(0, 0, 260, 60); context.font = '18px sans-serif'; context.fillStyle = '#fff'; context.fillText('MC Proxy · Canvas 123', 10, 35);
    const readHash = async () => {
      const digest = await deadline(crypto.subtle.digest('SHA-256', new TextEncoder().encode(canvas.toDataURL())), 2000, null);
      if (!digest) throw new Error('timeout');
      return [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
    };
    return { status: 'measured', hash: await readHash(), repeatHash: await readHash() };
  } catch { return { status: 'failed', reason: 'CANVAS_NOT_AVAILABLE' }; }
}

// Resolve fresh names from this browser. The authority receipt, not a DoH setting,
// provides resolver evidence. No host-side DNS lookup is substituted for this path.
export async function observeDns(probe, { fetch: fetchApi = globalThis.fetch, signal, now = Date.now, wait = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  if (!probe) return { report: { status: 'unverified', reason: 'CONTROLLED_DNS_TEST_NOT_CONFIGURED' }, localReadings: null };
  const started = now(), controller = new AbortController(), abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true }); const timer = setTimeout(abort, 12000);
  const failed = reason => ({ report: { status: 'failed', probeId: probe.probeId, complete: false, queries: 0, resolverIps: [], reason }, localReadings: null });
  try {
    if (!/^[a-f0-9]{32}$/.test(probe.probeId) || !Array.isArray(probe.queryNames) || probe.queryNames.length !== 4
      || !probe.queryNames.every(name => typeof name === 'string' && name.startsWith(`${['a', 'b', 'c', 'd'][probe.queryNames.indexOf(name)]}-${probe.probeId}.`)) || !probe.receiptUrl?.startsWith('https://')) return failed('DNS_CONTEXT_INVALID');
    // The four URLs are supplied by the trusted local service, not user text.
    await Promise.all(probe.queryNames.map(name => fetchApi(`https://${name}/mc-dns-probe`, { mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal: controller.signal }).catch(() => null)));
    let latest = null;
    for (let attempt = 0; attempt < 6 && !controller.signal.aborted && now() - started < 12000; attempt++) {
      const response = await fetchApi(probe.receiptUrl, { mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (response.status === 404 || response.status === 202) { await wait(300); continue; }
      if (!response.ok) return failed('DNS_RECEIPT_HTTP_FAILED');
      const body = await response.text(); if (body.length > 16384) return failed('DNS_RECEIPT_INVALID');
      let receipt; try { receipt = JSON.parse(body); } catch { return failed('DNS_RECEIPT_INVALID'); }
      const validKeys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => allowed.includes(key));
      if (!validKeys(receipt, ['version', 'probeId', 'complete', 'queries']) || receipt.version !== 1 || receipt.probeId !== probe.probeId || typeof receipt.complete !== 'boolean'
        || !Array.isArray(receipt.queries) || receipt.queries.length > 4
        || !receipt.queries.every(query => validKeys(query, ['name', 'resolverIps']) && probe.queryNames.includes(query.name) && Array.isArray(query.resolverIps)
          && query.resolverIps.length <= 16 && query.resolverIps.every(validIp))) return failed('DNS_RECEIPT_INVALID');
      const names = new Set(receipt.queries.filter(query => query.resolverIps.length).map(query => query.name));
      const resolverIps = [...new Set(receipt.queries.flatMap(query => query.resolverIps))];
      if (resolverIps.length > 64) return failed('DNS_RECEIPT_INVALID');
      latest = { report: { status: resolverIps.length ? 'measured' : 'unverified', probeId: probe.probeId, complete: receipt.complete && names.size === 4, queries: names.size, resolverIps,
        ...(!resolverIps.length ? { reason: 'DNS_RECEIPT_EMPTY' } : {}) }, localReadings: receipt };
      if (latest.report.complete) return latest;
      await wait(300);
    }
    return latest || failed('DNS_RECEIPT_TIMEOUT');
  } catch { return failed(controller.signal.aborted ? 'DNS_RECEIPT_TIMEOUT' : 'DNS_NETWORK_CORS_OR_RESPONSE_FAILED'); }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}

export async function runBrowserObservation({ context, canvas = false, fetch: fetchApi = globalThis.fetch, navigator, window, rtcFactory, now = Date.now } = {}) {
  const started = now(), controller = new AbortController(), timer = setTimeout(() => controller.abort(), context.measurementMs);
  try {
    const sources = context.sources;
    const [browser, v4, cloudflare, ipv6, rtc, canvasResult, dnsResult, consistency, headers] = await Promise.all([
      collectBrowserEnvironment({ navigator, window }), observeExit(sources[0], { fetch: fetchApi, signal: controller.signal, now }),
      observeExit(sources[1], { fetch: fetchApi, signal: controller.signal, now }), observeExit(sources[2], { fetch: fetchApi, signal: controller.signal, now }),
      observeWebRtc({ expectedExitIps: context.expectedExitIps, stun: context.stun, rtcFactory, signal: controller.signal }), canvasReading(canvas),
      observeDns(context.dnsProbe, { fetch: fetchApi, signal: controller.signal, now }),
      context.identityChecks ? collectIdentityContexts() : null,
      context.identityChecks ? deadline(Promise.resolve().then(() => fetchApi('./headers', { credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', signal: controller.signal })).then(response => response.ok ? response.json() : null), 3000, null) : null,
    ]);
    return { report: { schemaVersion: 1, binding: context.binding, elapsedMs: Math.min(now() - started, context.measurementMs), browser,
      checks: { https: [v4, cloudflare], ipv6, webrtc: rtc.report, canvas: canvasResult, dns: dnsResult.report, ...(consistency ? { consistency } : {}) } },
      localReadings: { browser, https: [v4, cloudflare], ipv6, ice: rtc.readings, canvas: canvasResult, dns: dnsResult.localReadings, consistency, headers } };
  } finally { clearTimeout(timer); controller.abort(); }
}

if (typeof document !== 'undefined') {
  const find = id => document.getElementById(id), stateLabels = { verified: '本次匹配', measured: '已采集', mismatch: '发现不匹配', failed: '检测失败', unverified: '尚未验证', configured: '配置目标', mocked: '模拟数据' };
  let context, savedReport, busy = false, expiryTimer;
  const status = (message, error = false) => { find('progress').textContent = message; find('progress').dataset.error = String(error); };
  function acceptContext(value) {
    context = value; clearTimeout(expiryTimer);
    expiryTimer = setTimeout(() => {
      savedReport = null; find('copyButton').disabled = true; find('runButton').disabled = true;
      find('results').replaceChildren(); find('rawReadings').textContent = '本次检测页面已过期，临时读数已清除。';
      status('检测页面已过期，请从 MC Proxy 重新打开检测。', true);
    }, Math.max(0, Date.parse(context.expiresAt) - Date.now()));
  }
  function render(report) {
    find('results').replaceChildren();
    for (const row of report.checks) {
      const card = document.createElement('article'); card.className = 'check'; card.dataset.state = row.status;
      const heading = document.createElement('div'); heading.className = 'check-heading'; const title = document.createElement('h2'); title.textContent = row.label;
      const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = stateLabels[row.status] || row.status; heading.append(title, badge); card.append(heading);
      if (row.value) { const value = document.createElement('p'); value.className = 'value'; value.textContent = row.value; card.append(value); }
      const detail = document.createElement('p'); detail.className = 'detail'; detail.textContent = row.detail; card.append(detail); find('results').append(card);
    }
  }
  async function run() {
    if (busy || !context) return; busy = true; savedReport = null; find('runButton').disabled = true; find('copyButton').disabled = true; find('canvasEnabled').disabled = true;
    find('results').replaceChildren();
    find('rawReadings').textContent = '正在测量…'; status('正在测量当前浏览器环境、HTTPS / IPv6 出口与 WebRTC…');
    try {
      const fresh = await fetchWithin('./context', { credentials: 'same-origin', cache: 'no-store' });
      if (!fresh.ok) throw new Error('OBSERVATION_SESSION_EXPIRED'); acceptContext(await fresh.json());
      const result = await runBrowserObservation({ context, canvas: find('canvasEnabled').checked });
      if (Date.now() >= Date.parse(context.expiresAt)) throw new Error('OBSERVATION_SESSION_EXPIRED');
      find('rawReadings').textContent = JSON.stringify(result.localReadings, null, 2);
      const response = await fetchWithin('./report', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(result.report), credentials: 'same-origin', cache: 'no-store' });
      const receipt = await response.json(); if (!response.ok || !receipt.saved) throw new Error(receipt.error?.code || 'OBSERVATION_FAILED');
      if (Date.now() >= Date.parse(context.expiresAt)) throw new Error('OBSERVATION_SESSION_EXPIRED');
      savedReport = receipt.report; render(savedReport); find('copyButton').disabled = false;
      status(savedReport.source.kind === 'fixture' ? '模拟页结果；未作为真实网络通过。' : '检测已返回 MC Proxy。未测项目仍保留“尚未验证”，请逐项核对。');
    } catch (cause) { status(['OBSERVATION_SESSION_EXPIRED', 'OBSERVATION_SESSION_CHANGED'].includes(cause.message) ? '连接已变化或检测页面过期，请从 MC Proxy 重新打开检测。' : '本次结果未成功返回本机服务。请保持 MC Proxy 运行，并重新启动检测。', true); }
    finally { busy = false; find('runButton').disabled = Date.now() >= Date.parse(context.expiresAt); find('canvasEnabled').disabled = false; }
  }
  find('runButton').addEventListener('click', run);
  find('copyButton').addEventListener('click', async () => {
    if (!savedReport) return;
    const summary = { observedAt: savedReport.observedAt, source: savedReport.source.kind, configured: savedReport.configured, checks: savedReport.checks, scope: savedReport.scope };
    try { await navigator.clipboard.writeText(JSON.stringify(summary, null, 2)); status('已复制脱敏摘要；不包含访问令牌与 ICE 原始地址。'); } catch { status('复制失败，请在 MC Proxy 的诊断页查看结果。', true); }
  });
  fetchWithin('./context', { credentials: 'same-origin', cache: 'no-store' }).then(async response => {
    if (!response.ok) throw new Error('expired'); acceptContext(await response.json());
    find('target').textContent = `目标环境：${context.workspaceId ? context.workspaceId.slice(0, 8) : '默认浏览器环境'} · 出口 ${context.expectedExitIps.join(', ')} · ${context.language || '未设置语言目标'} · ${context.timezone || '未设置时区目标'} · 身份版本 ${context.identityRevision?.slice(0, 10) || '待绑定'} · DNS：${context.dnsProbe ? '已接入权威回执' : '未配置权威服务'} · 有效至 ${new Date(context.expiresAt).toLocaleTimeString()}`;
    void run();
  }).catch(() => status('本次检测地址已失效，或 MC Proxy 本机诊断服务未运行。请从软件重新打开。', true));
}

