import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { validateCoreApi, UserError } from './config.mjs';

const error = code => new UserError(code, 'The private core connection observation is unavailable');
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const category = host => {
  if (typeof host !== 'string' || host.length > 253 || /[\s/@?#]/.test(host)) return 'unknown';
  const name = host.toLowerCase();
  if (['claude.ai', 'anthropic.com', 'openai.com', 'chatgpt.com'].some(domain => name === domain || name.endsWith(`.${domain}`))) return 'ai-service';
  if (['ipify.org', 'ipwho.is', 'ipwhois.app', 'ping0.cc', 'cleanip.net', 'ippure.com'].some(domain => name === domain || name.endsWith(`.${domain}`))) return 'exit-check';
  return net.isIP(name) ? 'ip-literal' : 'other-domain';
};
const application = processPath => {
  // sing-box may append the Windows user name to processPath. Never expose it,
  // nor infer that a generic node.exe process belongs to a particular AI CLI.
  const name = typeof processPath === 'string' ? processPath.replace(/ \([^)]*\)$/, '').split(/[\\/]/).at(-1)?.toLowerCase() : '';
  return ({ 'claude.exe': 'claude', 'codex.exe': 'codex', 'chrome.exe': 'chrome', 'msedge.exe': 'edge', 'node.exe': 'node', 'electron.exe': 'electron' })[name] || 'unknown';
};

export function allocateCoreApiPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', () => reject(error('CORE_API_UNAVAILABLE')));
    server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(cause => cause ? reject(error('CORE_API_UNAVAILABLE')) : resolve(port)); });
  });
}

export function requestCoreConnections(api) {
  validateCoreApi(api);
  return new Promise((resolve, reject) => {
    let bytes = 0; const chunks = []; let timer;
    const request = http.request({ hostname: '127.0.0.1', port: api.port, path: '/connections', method: 'GET', agent: false,
      headers: { authorization: `Bearer ${api.secret}`, accept: 'application/json', connection: 'close' } }, response => {
      if (response.statusCode !== 200) { response.resume(); request.destroy(error(response.statusCode === 401 || response.statusCode === 403 ? 'CORE_API_AUTH_FAILED' : 'CORE_API_UNAVAILABLE')); return; }
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) { response.destroy(error('CORE_API_RESPONSE_INVALID')); request.destroy(error('CORE_API_RESPONSE_INVALID')); return; }
        chunks.push(chunk);
      });
      response.once('error', () => { clearTimeout(timer); reject(error('CORE_API_RESPONSE_INVALID')); });
      response.once('end', () => {
        clearTimeout(timer);
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(error('CORE_API_RESPONSE_INVALID')); }
      });
    });
    request.once('error', cause => { clearTimeout(timer); reject(error(['CORE_API_AUTH_FAILED', 'CORE_API_RESPONSE_INVALID', 'CORE_API_TIMEOUT'].includes(cause.code) ? cause.code : 'CORE_API_UNAVAILABLE')); });
    timer = setTimeout(() => request.destroy(error('CORE_API_TIMEOUT')), 2000);
    request.end();
  });
}

// Fixed authenticated loopback operations only. Switching modes preserves the
// owned TUN; existing streams are drained only after the new rule is confirmed.
export async function setCoreTrafficBlocked(api, blocked) {
  validateCoreApi(api);
  if (typeof blocked !== 'boolean') throw error('CORE_TRAFFIC_GATE_FAILED');
  const mode = blocked ? 'mc-blocked' : 'mc-active';
  const call = (method, path, body) => new Promise((resolve, reject) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    let timer, settled = false, bytes = 0; const chunks = [];
    const finish = (cause, value) => { if (settled) return; settled = true; clearTimeout(timer); cause ? reject(error('CORE_TRAFFIC_GATE_FAILED')) : resolve(value); };
    const req = http.request({ hostname: '127.0.0.1', port: api.port, method, path, agent: false,
      headers: { authorization: `Bearer ${api.secret}`, accept: 'application/json', connection: 'close', ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}) } }, res => {
      if (![200, 204].includes(res.statusCode)) { res.resume(); finish(new Error()); req.destroy(); return; }
      res.on('data', chunk => { bytes += chunk.length; if (bytes > 4096) { finish(new Error()); res.destroy(); req.destroy(); } else chunks.push(chunk); });
      res.once('aborted', () => finish(new Error())); res.once('error', () => finish(new Error()));
      res.once('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
    });
    req.once('error', () => finish(new Error()));
    timer = setTimeout(() => { finish(new Error()); req.destroy(); }, 2000);
    req.end(payload);
  });
  await call('PATCH', '/configs', { mode });
  let observed; try { observed = JSON.parse(await call('GET', '/configs')); } catch { throw error('CORE_TRAFFIC_GATE_FAILED'); }
  if (observed?.mode !== mode) throw error('CORE_TRAFFIC_GATE_FAILED');
  if (blocked) await call('DELETE', '/connections');
  return { blocked, confirmed: true };
}

export function createCoreConnectionObserver({ request = requestCoreConnections, now = Date.now } = {}) {
  let currentSession = null; let history = new Map(); let reading = null;
  let summary = { status: 'unavailable', active: 0, observed: 0, observedAt: null, code: null };
  const reset = sessionId => {
    if (currentSession === sessionId) return;
    currentSession = sessionId; history = new Map(); reading = null;
    summary = { status: sessionId ? 'idle' : 'unavailable', active: 0, observed: 0, observedAt: null, code: null };
  };
  const snapshot = () => ({ ...summary, connections: [...history.values()].map(value => ({ ...value })) });
  function read({ api, sessionId, assertCurrent = async () => {} }) {
    validateCoreApi(api); reset(sessionId);
    if (reading?.sessionId === sessionId) return reading.promise;
    const selected = { sessionId };
    selected.promise = (async () => {
      try {
        await assertCurrent();
        const response = await request(api);
        await assertCurrent();
        if (currentSession !== sessionId) throw error('SESSION_CHANGED');
        if (!response || !Array.isArray(response.connections) || response.connections.length > 4096) throw error('CORE_API_RESPONSE_INVALID');
        const observedAt = new Date(now()).toISOString(), live = new Set();
        for (const connection of response.connections.slice(0, 256)) {
          if (!connection || typeof connection.id !== 'string' || !/^[a-zA-Z0-9-]{1,80}$/.test(connection.id)) continue;
          const metadata = connection.metadata || {}, chains = Array.isArray(connection.chains) ? connection.chains : [];
          const id = createHash('sha256').update(`${sessionId}:${connection.id}`).digest('hex').slice(0, 24);
          live.add(id);
          const literalFamily = net.isIP(typeof metadata.destinationIP === 'string' ? metadata.destinationIP : '');
          const destinationForm = literalFamily ? `ipv${literalFamily}-literal` : typeof metadata.host === 'string' && metadata.host ? 'domain' : 'unknown';
          const record = { id, application: application(metadata.processPath), target: category(metadata.host),
            inbound: metadata.type === 'tun/system-tun' ? 'tun' : metadata.type === 'http/ssh-http' ? 'explicit-proxy' : 'unknown',
            network: ['tcp', 'udp'].includes(metadata.network) ? metadata.network : 'unknown',
            route: chains.includes('isp-upstream') ? 'isp' : chains.includes('private-direct') ? 'private-direct' : 'unknown',
            destinationForm, domainAvailable: category(metadata.host) !== 'unknown' && typeof metadata.host === 'string' && !net.isIP(metadata.host),
            upload: count(connection.upload), download: count(connection.download), active: true, observedAt,
            ...(literalFamily === 6 ? { diagnostic: 'IP_LITERAL_REQUIRES_PROVIDER_SUPPORT' } : {}) };
          history.delete(id); history.set(id, record);
        }
        for (const [id, record] of history) {
          if (now() - Date.parse(record.observedAt) > 300_000) history.delete(id);
          else if (!live.has(id)) record.active = false;
        }
        while (history.size > 128) history.delete(history.keys().next().value);
        summary = { status: history.size ? 'observed' : 'idle', active: live.size, observed: history.size, observedAt, code: null };
        return snapshot();
      } catch (cause) {
        if (currentSession === sessionId) {
          for (const record of history.values()) record.active = false;
          summary = { ...summary, active: 0, status: 'failed', code: ['CORE_API_AUTH_FAILED', 'CORE_API_RESPONSE_INVALID', 'CORE_API_TIMEOUT', 'SESSION_CHANGED'].includes(cause.code) ? cause.code : 'CORE_API_UNAVAILABLE' };
        }
        throw error(cause.code === 'SESSION_CHANGED' ? 'SESSION_CHANGED' : summary.code || 'CORE_API_UNAVAILABLE');
      }
    })();
    reading = selected;
    void selected.promise.finally(() => { if (reading === selected) reading = null; }).catch(() => {});
    return selected.promise;
  }
  return { read, reset, snapshot, status: () => ({ ...summary }) };
}
