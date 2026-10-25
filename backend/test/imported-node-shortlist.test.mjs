import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { performance } from 'node:perf_hooks';
import net from 'node:net';
import { shortlistImportedNodes, probeTcpEndpoint, createImportedNodeScreening } from '../src/imported-node-shortlist.mjs';

const node = (index, type = 'vless') => ({ index, name: `Fixture ${index}`, outbound: { type, server: `node-${index}.test`, server_port: 443, password: 'PRIVATE_UNUSED_CREDENTIAL' } });

test('duplicate aliases use one TCP probe and one of the three candidate positions', async () => {
  const original = node(1), probes = [];
  const result = await shortlistImportedNodes([original, { ...node(2), outbound: { ...original.outbound } }, { ...node(3), outbound: { ...original.outbound } }, node(4), node(5)], {
    probe: async endpoint => { probes.push(endpoint.host); return { status: 'reachable', tcpLatencyMs: 10 }; },
  });
  assert.equal(probes.length, 3); assert.deepEqual(result.nodes.map(item => item.index), [1, 4, 5]);
  assert.equal(result.screening.inputCount, 5); assert.equal(result.screening.total, 3); assert.equal(result.screening.duplicates, 2);
  assert.deepEqual(result.duplicates, [{ index: 2, duplicateOf: 1, code: 'VPN_NODE_DUPLICATE' }, { index: 3, duplicateOf: 1, code: 'VPN_NODE_DUPLICATE' }]);
});

test('ambiguous node indices cannot overwrite an observation or reach native screening', async () => {
  for (const nodes of [[node(0)], [node(257)], [node(1), { ...node(2), index: 1 }]]) {
    await assert.rejects(shortlistImportedNodes(nodes, { probe: () => assert.fail('invalid node must be rejected before screening') }), { code: 'VPN_NODE_INVALID' });
  }
});

test('private TCP observations reuse unchanged identity across reorder but expire or force fresh without granting ISP evidence', async () => {
  let now = 100, probes = 0;
  const screen = createImportedNodeScreening({ now: () => now });
  const options = { listenPort: 17890, probe: async () => { probes++; return { status: 'reachable', tcpLatencyMs: 7 }; } };
  await screen([node(1)], options);
  const reused = await screen([{ ...node(2), outbound: node(1).outbound }], options);
  assert.equal(probes, 1); assert.equal(reused.screening.reused, 1); assert.equal(reused.nodes[0].index, 2);
  assert.equal(reused.screening.scope, 'local-tcp-connect'); assert.doesNotMatch(JSON.stringify(reused.screening), /verified|PRIVATE_|node-1\.test|[a-f0-9]{64}/);
  await screen([node(1)], { ...options, force: true }); assert.equal(probes, 2);
  await screen([{ ...node(1), outbound: { ...node(1).outbound, password: 'changed' } }], options); assert.equal(probes, 3);
  await screen([node(1)], { ...options, listenPort: 17891 }); assert.equal(probes, 4);
  now += 30_000; await screen([node(1)], options); assert.equal(probes, 5);
  screen.clear(); await screen([node(1)], options); assert.equal(probes, 6);
});

test('native dual-stack localhost lookup reaches an isolated IPv4 socket without sending application data', async t => {
  let bytes = 0;
  const server = net.createServer(socket => socket.on('data', chunk => { bytes += chunk.length; }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const result = await probeTcpEndpoint({ host: 'localhost', port: server.address().port }, { listenPort: 17890 });
  assert.equal(result.status, 'reachable'); assert.ok(result.tcpLatencyMs >= 1 && result.tcpLatencyMs <= 750); assert.equal(bytes, 0);
});

test('parallel endpoint screening measures only TCP and returns at most three fastest candidates', async () => {
  let active = 0, maximum = 0, probes = 0;
  const nodes = Array.from({ length: 43 }, (_, index) => node(index + 1));
  const result = await shortlistImportedNodes(nodes, { probe: async endpoint => {
    assert.deepEqual(Object.keys(endpoint).sort(), ['host', 'port']); probes++; maximum = Math.max(maximum, ++active);
    await new Promise(resolve => setTimeout(resolve, 2)); active--;
    return { status: 'reachable', tcpLatencyMs: endpoint.host === 'node-40.test' ? 1 : endpoint.host === 'node-30.test' ? 2 : endpoint.host === 'node-20.test' ? 3 : 100 };
  } });
  assert.equal(probes, 43); assert.ok(maximum <= 8 && maximum > 1);
  assert.deepEqual(result.nodes.map(item => item.index), [40, 30, 20]);
  assert.equal(result.screening.scope, 'local-tcp-connect'); assert.equal(result.screening.screened, 43);
  assert.doesNotMatch(JSON.stringify(result.screening), /PRIVATE_|node-\d+\.test|outbound/);
});

test('QUIC remains unknown without bare TCP and historical verified unknown candidates remain eligible', async () => {
  const probed = [];
  const result = await shortlistImportedNodes([node(1), node(2, 'hysteria2'), node(3, 'tuic'), node(4)], { history: [3], probe: async endpoint => {
    probed.push(endpoint.host); return { status: 'reachable', tcpLatencyMs: endpoint.host === 'node-4.test' ? 5 : 10 };
  } });
  assert.deepEqual(probed.sort(), ['node-1.test', 'node-4.test']);
  assert.deepEqual(result.nodes.map(item => item.index), [3, 4, 1]);
  assert.deepEqual(result.screening.results.filter(item => [2, 3].includes(item.nodeIndex)).map(item => item.status), ['unknown', 'unknown']);
  const quicOnly = await shortlistImportedNodes(Array.from({ length: 20 }, (_, index) => node(index + 1, 'hysteria2')), { probe: () => assert.fail('QUIC cannot be screened with TCP') });
  assert.deepEqual(quicOnly.nodes.map(item => item.index), [1, 2, 3]);
});

test('deadline aborts all active probes, bounds DNS waits and retains untested nodes without claiming success', async () => {
  let active = 0, maximum = 0, aborted = 0;
  const started = performance.now();
  const result = await shortlistImportedNodes(Array.from({ length: 256 }, (_, index) => node(index + 1)), { budgetMs: 35, probe: async (endpoint, { signal }) => {
    maximum = Math.max(maximum, ++active);
    return new Promise(resolve => signal.addEventListener('abort', () => { active--; aborted++; resolve({ status: 'unknown', tcpLatencyMs: null }); }, { once: true }));
  } });
  assert.ok(performance.now() - started < 300); assert.ok(maximum <= 8);
  assert.equal(active, 0); assert.equal(aborted, maximum);
  assert.equal(result.screening.complete, false); assert.ok(result.screening.results.some(item => item.status === 'not-tested'));
  assert.ok(result.screening.results.every(item => item.tcpLatencyMs === null)); assert.ok(result.nodes.length <= 3);
  await assert.rejects(shortlistImportedNodes(Array.from({ length: 257 }, (_, index) => node(index))), { code: 'VPN_YAML_NODE_LIMIT' });
});

test('own listener is blocked before connection for IPv4, IPv6 and mapped addresses including DNS answers', async () => {
  for (const host of ['127.0.0.1', '127.4.3.2', '0.0.0.0', '::', '::1', '::ffff:127.0.0.1', '::ffff:0.0.0.0']) {
    assert.equal((await probeTcpEndpoint({ host, port: 17890 }, { listenPort: 17890, connect: () => assert.fail('own listener must not be dialed') })).status, 'blocked');
  }
  let destroyed = 0;
  const result = await probeTcpEndpoint({ host: 'own-listener.test', port: 17890 }, { listenPort: 17890,
    lookup: (host, options, callback) => callback(null, '127.0.0.1', 4),
    connect: options => {
      const socket = new EventEmitter(); socket.destroy = () => { destroyed++; };
      queueMicrotask(() => options.lookup(options.host, {}, cause => socket.emit('error', cause)));
      return socket;
    },
  });
  assert.equal(result.status, 'blocked'); assert.equal(destroyed, 1);
  const dual = await probeTcpEndpoint({ host: 'dual-stack.test', port: 17890 }, { listenPort: 17890,
    lookup: (host, options, callback) => callback(null, [{ address: '::1', family: 6 }, { address: '192.0.2.7', family: 4 }]),
    connect: options => {
      assert.equal(options.autoSelectFamily, true);
      const socket = new EventEmitter(); socket.destroy = () => {};
      queueMicrotask(() => options.lookup(options.host, { all: true }, (cause, addresses) => {
        assert.equal(cause, null); assert.deepEqual(addresses, [{ address: '192.0.2.7', family: 4 }]);
        socket.emit('lookup'); socket.emit('connect');
      }));
      return socket;
    },
  });
  assert.equal(dual.status, 'reachable');
});

test('native socket timeout and abort clean up, while handshake latency excludes DNS resolution', async () => {
  let destroyed = 0;
  const hanging = () => { const socket = new EventEmitter(); socket.destroy = () => { destroyed++; }; return socket; };
  assert.equal((await probeTcpEndpoint({ host: 'never-resolves.test', port: 443 }, { timeoutMs: 10, connect: hanging })).status, 'unreachable');
  const aborter = new AbortController();
  const pending = probeTcpEndpoint({ host: 'cancelled.test', port: 443 }, { signal: aborter.signal, connect: hanging });
  aborter.abort(); assert.equal((await pending).status, 'unknown'); assert.equal(destroyed, 2);
  let clock = 0;
  const observed = await probeTcpEndpoint({ host: 'fixture.test', port: 443 }, { clock: () => clock, connect: () => {
    const socket = hanging(); queueMicrotask(() => { clock = 100; socket.emit('lookup'); clock = 112; socket.emit('connect'); }); return socket;
  } });
  assert.deepEqual(observed, { status: 'reachable', tcpLatencyMs: 12 });
});

test('pre-aborted screening never probes any node and retains only explicitly untested candidates', async () => {
  const controller = new AbortController(); controller.abort();
  const result = await shortlistImportedNodes(Array.from({ length: 30 }, (_, index) => node(index + 1)), {
    signal: controller.signal, probe: () => assert.fail('pre-canceled node screening must stay offline'),
  });
  assert.equal(result.screening.screened, 0); assert.equal(result.screening.complete, false);
  assert.ok(result.screening.results.every(item => item.status === 'not-tested'));
});

test('external cancellation aborts the current batch and never proceeds through the remaining node list', async () => {
  const controller = new AbortController(); let entered, probes = 0, aborted = 0;
  const active = new Promise(resolve => { entered = resolve; });
  const pending = shortlistImportedNodes(Array.from({ length: 60 }, (_, index) => node(index + 1)), {
    concurrency: 2, signal: controller.signal, probe: (_endpoint, { signal }) => {
      if (++probes === 2) entered();
      return new Promise(resolve => signal.addEventListener('abort', () => { aborted++; resolve({ status: 'unknown', tcpLatencyMs: null }); }, { once: true }));
    },
  });
  await active; controller.abort(); const result = await pending;
  assert.equal(probes, 2); assert.equal(aborted, 2); assert.equal(result.screening.screened, 2);
  assert.equal(result.screening.complete, false);
  assert.equal(result.screening.results.filter(item => item.status === 'not-tested').length, 58);
});

test('a late rejected node probe after cancellation is consumed instead of causing an unhandled rejection', async () => {
  const controller = new AbortController(); let entered, rejectLate;
  const active = new Promise(resolve => { entered = resolve; });
  const pending = shortlistImportedNodes([node(1), node(2)], { concurrency: 1, signal: controller.signal,
    probe: () => new Promise((_resolve, reject) => { rejectLate = reject; entered(); }),
  });
  await active; controller.abort(); const result = await pending;
  assert.equal(result.screening.screened, 1); assert.equal(result.screening.results[1].status, 'not-tested');
  rejectLate(new Error('PRIVATE_LATE_PROBE_FAILURE')); await new Promise(resolve => setImmediate(resolve));
});
