const clean = (value, max = 256) => String(value || '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max);
const unavailable = reason => ({ status: 'unverified', reason });
const bounded = (task, ms, fallback) => new Promise(resolve => {
  const timer = setTimeout(() => resolve(fallback), ms);
  Promise.resolve(task).then(value => { clearTimeout(timer); resolve(value); }, () => { clearTimeout(timer); resolve(fallback); });
});

// This probe only reads public browser properties and a new local test page.
// It never opens customer documents, reads storage or requests media permissions.
export async function collectIdentitySurface({ navigator: nav = globalThis.navigator, window: win = globalThis.window } = {}) {
  const ua = nav.userAgentData;
  const high = ua?.getHighEntropyValues ? await bounded(Promise.resolve().then(() => ua.getHighEntropyValues(['architecture', 'bitness', 'platformVersion', 'fullVersionList'])), 1500, null) : null;
  return {
    userAgent: clean(nav.userAgent, 512), language: clean(nav.language, 64), languages: [...(nav.languages || [])].slice(0, 16).map(value => clean(value, 64)),
    timezone: clean(Intl.DateTimeFormat().resolvedOptions().timeZone, 100), platform: clean(nav.platform, 100),
    hardwareConcurrency: Number.isInteger(nav.hardwareConcurrency) && nav.hardwareConcurrency > 0 && nav.hardwareConcurrency <= 1024 ? nav.hardwareConcurrency : 0,
    ...(typeof nav.deviceMemory === 'number' && Number.isFinite(nav.deviceMemory) && nav.deviceMemory > 0 && nav.deviceMemory <= 1024 ? { deviceMemory: nav.deviceMemory } : {}),
    uaCh: ua ? { status: high ? 'measured' : 'unverified', platform: clean(ua.platform, 100), mobile: Boolean(ua.mobile),
      ...(high ? { architecture: clean(high.architecture, 100), bitness: clean(high.bitness, 100), platformVersion: clean(high.platformVersion, 100) } : {}),
      brands: (high?.fullVersionList || ua.brands || []).slice(0, 12).map(value => ({ brand: clean(value.brand, 100), version: clean(value.version, 64) })) } : { status: 'unverified' },
    ...(win?.screen && win.screen.width > 0 && win.screen.height > 0 ? { screen: { width: Math.min(win.screen.width, 100000), height: Math.min(win.screen.height, 100000), pixelRatio: Math.min(win.devicePixelRatio || 1, 100) } } : {}),
  };
}

async function readSurface() { try { return { status: 'measured', surface: await collectIdentitySurface() }; } catch { return unavailable('PROBE_READ_FAILED'); } }

function frameProbe() {
  if (typeof document === 'undefined' || typeof window === 'undefined') return Promise.resolve(unavailable('CONTEXT_API_UNSUPPORTED'));
  return new Promise(resolve => {
    const frame = document.createElement('iframe'); frame.hidden = true; frame.title = 'MC Proxy 本机身份检测';
    let timer;
    const finish = value => { clearTimeout(timer); window.removeEventListener('message', receive); frame.remove(); resolve(value); };
    const receive = event => { if (event.origin === location.origin && event.source === frame.contentWindow && event.data?.kind === 'mc-browser-identity-probe') finish(event.data.result); };
    window.addEventListener('message', receive); timer = setTimeout(() => finish(unavailable('CONTEXT_PROBE_TIMEOUT')), 4000);
    frame.addEventListener('error', () => finish(unavailable('CONTEXT_PROBE_FAILED')), { once: true });
    frame.src = './identity-frame'; document.body.append(frame);
  });
}

function workerProbe(shared) {
  const Constructor = shared ? globalThis.SharedWorker : globalThis.Worker;
  if (!Constructor) return Promise.resolve(unavailable('CONTEXT_API_UNSUPPORTED'));
  return new Promise(resolve => {
    let worker, channel, timer, done = false;
    const finish = value => {
      if (done) return; done = true; clearTimeout(timer);
      if (channel) { channel.onmessage = null; channel.onmessageerror = null; }
      if (worker) { worker.onerror = null; shared ? channel?.close() : worker.terminate(); }
      resolve(value);
    };
    try {
      worker = new Constructor(new URL('./browser-identity-probe.js', import.meta.url), { type: 'module' });
      channel = shared ? worker.port : worker;
      channel.onmessage = event => { if (event.data?.kind === 'mc-browser-identity-probe') finish(event.data.result); };
      channel.onmessageerror = () => finish(unavailable('CONTEXT_PROBE_FAILED'));
      worker.onerror = () => finish(unavailable('CONTEXT_PROBE_FAILED'));
      timer = setTimeout(() => finish(unavailable('CONTEXT_PROBE_TIMEOUT')), 4000); if (shared) channel.start();
    } catch { finish(unavailable('CONTEXT_API_UNSUPPORTED')); }
  });
}

export async function collectIdentityContexts() {
  const [iframe, dedicatedWorker, sharedWorker] = await Promise.all([frameProbe(), workerProbe(false), workerProbe(true)]);
  return { version: 1, contexts: { iframe, dedicatedWorker, sharedWorker } };
}

if (typeof WorkerGlobalScope !== 'undefined' && globalThis instanceof WorkerGlobalScope) {
  if (typeof globalThis.postMessage === 'function') {
    void readSurface().then(result => { globalThis.postMessage({ kind: 'mc-browser-identity-probe', result }); globalThis.close(); });
  } else {
    globalThis.addEventListener('connect', event => {
      const port = event.ports[0];
      void readSurface().then(result => { port.postMessage({ kind: 'mc-browser-identity-probe', result }); port.close(); setTimeout(() => globalThis.close(), 0); });
    });
  }
} else if (typeof document !== 'undefined' && window.parent !== window && document.body?.dataset.identityProbe === 'frame') {
  void readSurface().then(result => window.parent.postMessage({ kind: 'mc-browser-identity-probe', result }, location.origin));
}
