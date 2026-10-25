import { createHash } from 'node:crypto';
import { networkInterfaces as nativeInterfaces } from 'node:os';

export function createNetworkLifecycle({ mock = false, controller, powerMonitor, networkInterfaces = nativeInterfaces, onFailure,
  setInterval: interval = globalThis.setInterval, clearInterval: cancelInterval = globalThis.clearInterval,
  setTimeout: timeout = globalThis.setTimeout, clearTimeout: cancelTimeout = globalThis.clearTimeout } = {}) {
  let stopped = false, suspended = false, checking = false, pending = null, ready = false, debounce, poll, signature, observationFailed = false;
  let state = { enabled: !mock, phase: mock ? 'mock' : 'watching', errorCode: null };
  if (mock) return { stop: () => { stopped = true; state = { ...state, phase: 'stopped' }; }, status: () => ({ ...state }) };
  const failure = code => { state = { ...state, phase: 'failed', errorCode: code }; try { onFailure?.({ code, operation: 'network-lifecycle' }); } catch {} };
  function invalidate() {
    try { Promise.resolve(controller.suspendNetwork()).catch(() => { if (!stopped) failure('NETWORK_RECHECK_FAILED'); }); }
    catch { failure('NETWORK_RECHECK_FAILED'); }
  }
  async function drain() {
    if (stopped || suspended || checking || !ready || !pending) return;
    const reason = pending; pending = null; ready = false; checking = true;
    state = { ...state, phase: 'checking', errorCode: null };
    try {
      const result = await controller.networkChanged(reason);
      if (stopped || suspended || observationFailed) return;
      // A queued newer change must finish its own check. The controller returns
      // an unverified status on failure instead of necessarily rejecting.
      if (pending) state = { ...state, phase: 'checking', errorCode: null };
      else if (result?.networkLifecycle?.state === 'stable') state = { ...state, phase: 'watching', errorCode: null };
      else failure('NETWORK_RECHECK_FAILED');
    }
    catch { if (!stopped && !suspended && !observationFailed) failure('NETWORK_RECHECK_FAILED'); }
    finally { checking = false; if (!stopped && ready && pending) void drain(); }
  }
  function changed(reason) {
    if (stopped) return;
    invalidate(); pending = reason === 'resume' || pending === 'resume' ? 'resume' : 'adapter-change'; ready = false;
    cancelTimeout(debounce);
    if (!suspended) { debounce = timeout(() => { ready = true; void drain(); }, 2000); debounce?.unref?.(); }
  }
  const onSuspend = () => {
    if (stopped) return;
    suspended = true; pending = null; ready = false; cancelTimeout(debounce); invalidate();
    state = { ...state, phase: 'suspended', errorCode: null };
  };
  const onResume = () => { if (!stopped) { suspended = false; changed('resume'); } };
  function sample() {
    if (stopped) return;
    try {
      const interfaces = networkInterfaces();
      const values = Object.entries(interfaces).filter(([name]) => !/^ProxyPilot(?:\s+TUN)?$/i.test(name)).map(([name, entries]) => [name,
        (entries || []).filter(entry => !entry.internal && entry.address !== '::1' && !/^127\./.test(entry.address || '')).map(entry => [entry.family, entry.address, entry.cidr, entry.mac]).sort()])
        .filter(([, entries]) => entries.length).sort(([a], [b]) => a.localeCompare(b));
      const next = createHash('sha256').update(JSON.stringify(values)).digest('hex');
      if (observationFailed || signature !== undefined && signature !== next) changed('adapter-change');
      observationFailed = false;
      signature = next;
    } catch { if (!observationFailed) invalidate(); observationFailed = true; failure('NETWORK_OBSERVATION_FAILED'); }
  }
  powerMonitor?.on('suspend', onSuspend); powerMonitor?.on('resume', onResume);
  sample(); poll = interval(sample, 15_000); poll?.unref?.();
  return {
    status: () => ({ ...state }),
    stop: () => { if (stopped) return; stopped = true; cancelInterval(poll); cancelTimeout(debounce); pending = null;
      powerMonitor?.removeListener('suspend', onSuspend); powerMonitor?.removeListener('resume', onResume); state = { ...state, phase: 'stopped' }; },
  };
}
