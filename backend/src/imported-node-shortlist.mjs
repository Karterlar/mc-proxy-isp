import net from 'node:net';
import dns from 'node:dns';
import { performance } from 'node:perf_hooks';
import { deduplicateVpnNodes, vpnOutboundIdentity } from './vpn-yaml.mjs';

const fail = code => { throw Object.assign(new Error('Imported node screening input is invalid'), { code }); };
function ownListener(host, port, listenPort) {
  if (port !== listenPort) return false;
  const canonical = net.isIP(host) === 6 ? new URL(`http://[${host}]/`).hostname.slice(1, -1) : host;
  return /^127\./.test(canonical) || ['0.0.0.0', '::', '::1'].includes(canonical) || /^::ffff:(?:127\.|7f[0-9a-f]{2}:|0\.0\.0\.0$|0:0$)/i.test(canonical);
}

// Only a bounded TCP connect is measured. No protocol credentials or ISP request
// are sent, and DNS time is excluded from a successful handshake observation.
export function probeTcpEndpoint({ host, port }, { timeoutMs = 750, signal, listenPort, connect = net.createConnection, lookup = dns.lookup, clock = () => performance.now() } = {}) {
  return new Promise(resolve => {
    let socket, timer, finished = false, tcpStarted = clock();
    const finish = status => {
      if (finished) return;
      finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      socket?.destroy();
      resolve({ status, tcpLatencyMs: status === 'reachable' ? Math.max(1, Math.round(clock() - tcpStarted)) : null });
    };
    const abort = () => finish('unknown');
    if (signal?.aborted) return finish('unknown');
    if (ownListener(host, port, listenPort)) return finish('blocked');
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => finish('unreachable'), Math.max(1, timeoutMs));
    try {
      socket = connect({ host, port, autoSelectFamily: true, lookup: (hostname, options, callback) => lookup(hostname, options, (cause, address, family) => {
        if (!cause && Array.isArray(address)) {
          const safe = address.filter(item => !ownListener(item.address, port, listenPort));
          if (safe.length) return callback(null, safe);
        }
        if (!cause && (Array.isArray(address) || ownListener(address, port, listenPort))) { finish('blocked'); callback(Object.assign(new Error('Own listener cannot be screened'), { code: 'VPN_NODE_INVALID' })); }
        else callback(cause, address, family);
      }) });
      socket.once('lookup', () => { tcpStarted = clock(); });
      socket.once('connect', () => finish('reachable'));
      socket.on('error', () => finish('unreachable'));
      if (finished) socket.destroy();
    } catch { finish('unreachable'); }
  });
}

export function createImportedNodeScreening({ now = Date.now } = {}) {
  const cache = new Map();
  const screen = (nodes, options = {}) => shortlistImportedNodes(nodes, { ...options, cache, now });
  screen.clear = () => cache.clear();
  return screen;
}

export async function shortlistImportedNodes(nodes, { probe = probeTcpEndpoint, listenPort, history = [], concurrency = 8, timeoutMs = 750, budgetMs = 6000, onProgress, cache, now = Date.now, force = false, signal } = {}) {
  if (!Array.isArray(nodes) || nodes.length > 256) fail('VPN_YAML_NODE_LIMIT');
  const indexes = new Set();
  for (const node of nodes) {
    if (!Number.isInteger(node?.index) || node.index < 1 || node.index > 256 || indexes.has(node.index) || !node.outbound || typeof node.outbound.server !== 'string' || !Number.isInteger(node.outbound.server_port)) fail('VPN_NODE_INVALID');
    indexes.add(node.index);
  }
  const inputCount = nodes.length, unique = deduplicateVpnNodes(nodes); nodes = unique.nodes;
  if (cache) for (const [key, entry] of cache) if (now() - entry.at >= 30_000 || now() < entry.at) cache.delete(key);
  concurrency = Math.max(1, Math.min(8, Number.isInteger(concurrency) ? concurrency : 8));
  timeoutMs = Math.max(1, Math.min(1000, Number.isFinite(timeoutMs) ? timeoutMs : 750));
  budgetMs = Math.max(1, Math.min(6000, Number.isFinite(budgetMs) ? budgetMs : 6000));
  const started = performance.now(), controller = new AbortController(), observations = new Map();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  if (signal?.aborted) cancel();
  let cursor = 0, reused = 0;
  const timer = setTimeout(() => controller.abort(), budgetMs);
  const screening = () => ({ scope: 'local-tcp-connect', durationMs: Math.max(0, Math.round(performance.now() - started)),
    screened: observations.size, total: nodes.length, inputCount, duplicates: unique.duplicates.length, reused,
    results: [...observations.values()].sort((a, b) => a.nodeIndex - b.nodeIndex) });
  const bounded = endpoint => new Promise(resolve => {
    const local = new AbortController(); let settled = false;
    const finish = value => {
      if (settled) return;
      settled = true; clearTimeout(timeout); controller.signal.removeEventListener('abort', abort); local.abort();
      resolve(value);
    };
    const abort = () => finish({ status: 'unknown', tcpLatencyMs: null });
    const remaining = Math.max(1, budgetMs - (performance.now() - started));
    const timeout = setTimeout(() => finish({ status: remaining < timeoutMs ? 'unknown' : 'unreachable', tcpLatencyMs: null }), Math.min(timeoutMs, remaining));
    controller.signal.addEventListener('abort', abort, { once: true });
    if (controller.signal.aborted) return abort();
    Promise.resolve().then(() => probe(endpoint, { timeoutMs, signal: local.signal, listenPort })).then(value => {
      const status = ['reachable', 'unreachable', 'blocked', 'unknown'].includes(value?.status) ? value.status : 'unknown';
      const latency = status === 'reachable' && Number.isFinite(value.tcpLatencyMs) && value.tcpLatencyMs >= 0 && value.tcpLatencyMs <= 1000 ? Math.max(1, Math.round(value.tcpLatencyMs)) : null;
      finish({ status, tcpLatencyMs: latency });
    }, () => finish({ status: 'unreachable', tcpLatencyMs: null }));
  });
  try {
    await Promise.all(Array.from({ length: Math.min(concurrency, nodes.length) }, async () => {
      while (cursor < nodes.length && !controller.signal.aborted && performance.now() - started < budgetMs) {
        const node = nodes[cursor++]; const outbound = node?.outbound;
        const key = vpnOutboundIdentity({ outbound, listenPort, timeoutMs }), previous = !force && cache?.get(key);
        const reusable = previous && now() >= previous.at && now() - previous.at < 30_000;
        const observation = ownListener(outbound.server, outbound.server_port, listenPort) ? { status: 'blocked', tcpLatencyMs: null }
          : ['hysteria2', 'tuic'].includes(outbound.type) ? { status: 'unknown', tcpLatencyMs: null }
          : reusable ? (reused++, previous.observation)
          : await bounded({ host: outbound.server, port: outbound.server_port });
        if (cache && observation.status === 'reachable' && !reusable) {
          if (cache.size >= 256) cache.delete(cache.keys().next().value);
          cache.set(key, { at: now(), observation: { ...observation } });
        }
        observations.set(node.index, { nodeIndex: node.index, ...observation });
        try { onProgress?.(screening()); } catch {}
      }
    }));
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); controller.abort(); }
  const completed = observations.size;
  for (const node of nodes) if (!observations.has(node.index)) observations.set(node.index, { nodeIndex: node.index, status: 'not-tested', tcpLatencyMs: null });
  const eligible = nodes.filter(node => !['blocked', 'unreachable'].includes(observations.get(node.index).status));
  eligible.sort((a, b) => {
    const left = observations.get(a.index), right = observations.get(b.index);
    const rank = (node, value) => value.status !== 'reachable' && history.includes(node.index) ? 0 : value.status === 'reachable' ? 1 : 2;
    return rank(a, left) - rank(b, right) || (left.tcpLatencyMs ?? Infinity) - (right.tcpLatencyMs ?? Infinity) || a.index - b.index;
  });
  return { nodes: eligible.slice(0, 3), duplicates: unique.duplicates, screening: { ...screening(), screened: completed, complete: completed === nodes.length } };
}
