import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildTunRoutingPolicy, validateRoutingApplicationPaths, ROUTING_FAKE_IP_NETWORK } from '../src/routing-policy.mjs';
import { FAKE_IP_NETWORK } from '../src/config.mjs';

function matches(rule, input) {
  const cidr = values => values.some(value => {
    const [address, prefix] = value.split('/'); const family = net.isIP(address);
    if (net.isIP(input.ip || '') !== family) return false;
    const block = new net.BlockList(); block.addSubnet(address, Number(prefix), family === 6 ? 'ipv6' : 'ipv4');
    return block.check(input.ip, family === 6 ? 'ipv6' : 'ipv4');
  });
  const result = rule.type === 'logical' ? rule.rules.every(child => matches(child, input))
    : (!rule.inbound || rule.inbound.includes(input.inbound)) && (!rule.network || rule.network === input.network)
      && (!rule.port || rule.port === input.port) && (!rule.ip_cidr || cidr(rule.ip_cidr))
      && (!rule.process_path || rule.process_path.includes(input.path))
      && (!rule.domain_suffix || rule.domain_suffix.some(domain => input.domain === domain || input.domain?.endsWith(`.${domain}`)));
  return rule.invert ? !result : result;
}
const selected = (policy, input) => {
  const rule = policy.rules.find(rule => matches(rule, { inbound: 'system-tun', network: 'tcp', port: 443, ...input }));
  return rule?.outbound || rule?.action || 'isp-upstream';
};

test('public traffic, unknown process and China-looking domains keep the ISP final policy', () => {
  const policy = buildTunRoutingPolicy();
  for (const input of [{ ip: '203.0.113.9' }, { ip: '2001:db8::3' }, { domain: 'service.cn' }, { domain: 'mcp.lan' }, { domain: 'public.local' }]) {
    assert.equal(selected(policy, input), 'isp-upstream');
  }
  assert.equal(policy.outbounds.length, 1); assert.equal(policy.outbounds[0].tag, 'private-direct');
  assert.doesNotMatch(JSON.stringify(policy), /geoip|geosite|\.cn|domain_keyword|process_name/);
  assert.equal(policy.summary.defaultPublic, 'isp-upstream');
});

test('DNS and unsupported UDP precede every private or application exception', () => {
  const policy = buildTunRoutingPolicy({ applicationPaths: ['C:\\Apps\\Claude.exe'] });
  assert.equal(selected(policy, { network: 'udp', port: 53, ip: '127.0.0.1' }), 'hijack-dns');
  assert.equal(selected(policy, { network: 'tcp', port: 53, ip: '10.0.0.1' }), 'hijack-dns');
  for (const ip of ['127.0.0.1', '10.0.0.1', 'fd00::1', '203.0.113.9']) assert.equal(selected(policy, { network: 'udp', ip }), 'reject');
});

test('TCP loopback callbacks remain local; protected domains and exact application paths precede LAN', () => {
  const applicationPath = 'C:\\Program Files\\Claude\\Claude.exe';
  const policy = buildTunRoutingPolicy({ applicationPaths: [applicationPath] });
  assert.equal(selected(policy, { ip: '127.0.0.1', path: applicationPath }), 'private-direct');
  assert.equal(selected(policy, { ip: '::1', domain: 'auth.openai.com' }), 'private-direct');
  assert.equal(selected(policy, { ip: '10.0.0.1', path: applicationPath }), 'isp-upstream');
  assert.equal(selected(policy, { ip: '192.168.1.1', domain: 'auth.openai.com' }), 'isp-upstream');
  assert.equal(selected(policy, { ip: '10.0.0.1', domain: 'notopenai.com' }), 'private-direct');
  assert.equal(selected(policy, { ip: '10.0.0.1', path: 'C:\\Other\\Claude.exe' }), 'private-direct');
});

test('LAN exceptions exclude the complete Fake-IP ranges and never affect explicit HTTP ingress', () => {
  assert.deepEqual(ROUTING_FAKE_IP_NETWORK, FAKE_IP_NETWORK);
  const policy = buildTunRoutingPolicy();
  for (const ip of ['10.255.255.255', '172.16.0.1', '172.31.255.255', '192.168.1.1', 'fc00:4000::1', 'fdff::1']) assert.equal(selected(policy, { ip }), 'private-direct');
  for (const ip of ['172.32.0.1', '192.169.1.1', '198.18.0.0', '198.19.255.255', 'fc00::1', 'fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff']) assert.equal(selected(policy, { ip }), 'isp-upstream');
  for (const ip of ['127.0.0.1', '10.0.0.1', 'fd00::1']) assert.equal(selected(policy, { ip, inbound: 'ssh-http' }), 'isp-upstream');
});

test('application paths are trusted absolute executable paths with bounded exact matching', () => {
  assert.deepEqual(validateRoutingApplicationPaths(['C:/Apps/Claude.exe', 'c:\\apps\\claude.exe']), ['C:\\Apps\\Claude.exe']);
  for (const values of ['C:\\Apps\\Claude.exe', Array(17).fill('C:\\Apps\\Claude.exe'), ['Claude.exe'], ['\\\\server\\share\\Claude.exe'],
    ['C:\\Apps\\*.exe'], ['C:\\Apps\\Claude.exe:stream.exe'], ['C:\\Apps\\Claude.exe\n'], ['C:\\Apps\\Claude.cmd'], [null]]) {
    assert.throws(() => buildTunRoutingPolicy({ applicationPaths: values }), { code: 'ROUTING_POLICY_INVALID' });
  }
  const policy = buildTunRoutingPolicy(); policy.rules[0].inbound.push('untrusted');
  assert.deepEqual(buildTunRoutingPolicy().rules[0].inbound, ['system-tun']);
});

test('global TUN routes LAN through ISP and retains only the TCP loopback callback exception', () => {
  const policy = buildTunRoutingPolicy({ routingMode: 'global' });
  assert.equal(policy.summary.mode, 'global'); assert.equal(policy.summary.localException, 'loopback-tcp');
  for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.1.1', 'fd00::1']) assert.equal(selected(policy, { ip }), 'isp-upstream');
  for (const ip of ['127.0.0.1', '::1']) assert.equal(selected(policy, { ip }), 'private-direct');
  assert.throws(() => buildTunRoutingPolicy({ routingMode: 'geoip-china' }), { code: 'ROUTING_POLICY_INVALID' });
});

test('pinned core accepts the private logical rule without opening TUN or connecting any target', { skip: !process.env.SING_BOX_BIN }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mc-routing-schema-'));
  try {
    const policy = buildTunRoutingPolicy({ applicationPaths: ['C:\\Apps\\Claude.exe'] });
    const file = join(directory, 'routing.json');
    await writeFile(file, JSON.stringify({
      inbounds: [{ type: 'http', tag: 'system-tun', listen: '127.0.0.1', listen_port: 17890 }],
      outbounds: [{ type: 'http', tag: 'isp-upstream', server: '127.0.0.1', server_port: 1080 }, ...policy.outbounds],
      dns: { servers: [{ type: 'https', tag: 'isp-doh', server: '1.1.1.1', detour: 'isp-upstream' }], final: 'isp-doh' },
      route: { final: 'isp-upstream', rules: policy.rules },
    }));
    const result = spawnSync(process.env.SING_BOX_BIN, ['check', '-c', file], { windowsHide: true, encoding: 'utf8', timeout: 6000 });
    assert.equal(result.status, 0, `Pinned schema check failed: ${result.error?.code || result.stderr}`);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
