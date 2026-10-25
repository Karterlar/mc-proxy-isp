// Local controller transport. A timed-out mutation is never retried: its result
// must be read from the controller before the user decides what to do next.
import { sanitizeEnvironmentFeedback } from './environment-feedback.js';
export function consumeControlToken({ location = globalThis.location, history = globalThis.history } = {}) {
  const fragment = new URLSearchParams(location?.hash?.slice(1) || '');
  const value = fragment.get('control_token');
  if (value !== null) {
    fragment.delete('control_token');
    history?.replaceState(null, '', `${location.pathname}${location.search}${fragment.size ? `#${fragment}` : ''}`);
  }
  return /^[a-f0-9]{64}$/i.test(value || '') ? value : '';
}

export function createControllerClient({ fetchImpl = globalThis.fetch, controlToken = consumeControlToken(), readTimeoutMs = 15000, operationTimeoutMs = 300000, progressTimeoutMs = 5000 } = {}) {
  let generation = 0;
  let statusRequest = null;

  async function request(endpoint, body, { signal, timeoutMs } = {}) {
    const profileRead = typeof endpoint === 'string' && body === undefined && /^\/api\/browser\/profiles\?browser=(?:chrome|edge|fingerprint)$/.test(endpoint);
    if (typeof endpoint !== 'string' || !/^\/api\/[a-z0-9/-]+$/.test(endpoint) && !profileRead) throw Object.assign(new Error('控制请求地址无效'), { code: 'CONTROLLER_ENDPOINT_INVALID' });
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(abort, timeoutMs ?? (endpoint === '/api/progress' ? progressTimeoutMs : body === undefined ? readTimeoutMs : operationTimeoutMs));
    try {
      const response = await fetchImpl(endpoint, {
        method: body === undefined ? 'GET' : 'POST', mode: 'same-origin', credentials: 'same-origin', cache: 'no-store',
        headers: { accept: 'application/json', ...(controlToken ? { 'x-mc-control-token': controlToken } : {}), ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: controller.signal,
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok || payload?.ok !== true || !payload.data || typeof payload.data !== 'object') {
        const error = new Error(payload?.error?.message || `本地服务请求失败（${response.status}）`);
        if (typeof payload?.error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(payload.error.code)) error.code = payload.error.code;
        if (error.code?.startsWith('ENVIRONMENT_')) {
          const diagnostic = sanitizeEnvironmentFeedback(payload?.error?.details);
          if (Object.keys(diagnostic).length) error.diagnostic = diagnostic;
        }
        if (Array.isArray(payload?.error?.details?.unsupportedNodes)) error.unsupportedNodes = payload.error.details.unsupportedNodes.slice(0, 256)
          .filter(item => Number.isInteger(item?.index) && item.index > 0 && item.index <= 256 && typeof item.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(item.code))
          .map(({ index, code }) => ({ index, code }));
        throw error;
      }
      return payload.data;
    } catch (error) {
      if (controller.signal.aborted) throw Object.assign(new Error(body === undefined ? '读取状态超时，请重新刷新。' : '操作等待超时，结果尚未确认。请先刷新状态，再决定是否重试。'), { code: 'CONTROLLER_REQUEST_TIMEOUT' });
      if (error instanceof TypeError) throw Object.assign(new Error('本地控制服务未连接，请检查启动器。'), { code: 'CONTROLLER_UNAVAILABLE' });
      throw error;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    }
  }

  function invalidateStatus() {
    generation++;
    statusRequest?.controller.abort();
    statusRequest = null;
  }

  function readStatus({ inspect = false } = {}) {
    if (inspect && statusRequest && !statusRequest.inspect) invalidateStatus();
    if (statusRequest) return statusRequest.promise;
    const version = generation;
    const entry = { controller: new AbortController(), promise: null, inspect };
    entry.promise = request(inspect ? '/api/status' : '/api/snapshot', undefined, { signal: entry.controller.signal })
      .then(data => version === generation ? data : null)
      .catch(error => { if (version === generation) throw error; return null; })
      .finally(() => { if (statusRequest === entry) statusRequest = null; });
    statusRequest = entry;
    return entry.promise;
  }

  return { request, readStatus, invalidateStatus };
}
