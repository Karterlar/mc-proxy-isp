import test from 'node:test';
import assert from 'node:assert/strict';
import { compatibilityRoutes, readWindowsProxySettings } from '../src/compatibility-network.mjs';

test('automatic routes retain the system path and discover only configured local HTTP/SOCKS proxies', async () => {
  const routes = await compatibilityRoutes({ listenPort: 17890,
    readSystemProxy: async () => ({ enabled: true, server: 'https=127.0.0.1:7890;socks=[::1]:1080;http=127.0.0.1:7890' }),
    environment: { HTTPS_PROXY: 'http://localhost:7890', ALL_PROXY: 'socks5h://127.0.0.1:10808' } });
  assert.deepEqual(routes, [
    { strategy: 'system', source: 'system-network' },
    { strategy: 'http-proxy', source: 'windows-proxy', vpnProxy: { type: 'http', host: '127.0.0.1', port: 7890 } },
    { strategy: 'socks-proxy', source: 'windows-proxy', vpnProxy: { type: 'socks', host: '::1', port: 1080 } },
    { strategy: 'socks-proxy', source: 'proxy-environment', vpnProxy: { type: 'socks', host: '127.0.0.1', port: 10808 } },
  ]);
});

test('remote, credential-bearing, malformed, own-listener and PAC addresses are never used as proxy candidates', async () => {
  const routes = await compatibilityRoutes({ listenPort: 17890,
    readSystemProxy: async () => ({ enabled: true, server: 'http=192.0.2.25:8080;https=http://PRIVATE_TOKEN@127.0.0.1:7890;socks=127.0.0.1:17890', pacPresent: true }),
    environment: { HTTPS_PROXY: 'https://127.0.0.1:7890', ALL_PROXY: 'http://127.0.0.1:9000/private?secret=PRIVATE_TOKEN' } });
  assert.deepEqual(routes, [{ strategy: 'system', source: 'system-network' }]);
  assert.doesNotMatch(JSON.stringify(routes), /PRIVATE_TOKEN|192\.0\.2\.25/);
});

test('manual proxy selects only the explicit local route and validates before any discovery', async () => {
  const manualProxy = { type: 'socks', host: '127.0.0.1', port: 1080 };
  const routes = await compatibilityRoutes({ manualProxy, readSystemProxy: () => assert.fail('manual selection must not inspect system settings') });
  assert.deepEqual(routes, [{ strategy: 'socks-proxy', source: 'manual', vpnProxy: manualProxy }]);
  await assert.rejects(compatibilityRoutes({ manualProxy: { ...manualProxy, host: '192.0.2.25' } }), { code: 'VPN_PROXY_INVALID' });
});

test('Windows discovery is bounded, read-only and leaves an unavailable reader as an empty candidate set', async () => {
  let calls = 0;
  const result = await readWindowsProxySettings({ platform: 'win32', execFile: (file, args, options, callback) => {
    calls++; assert.equal(file, 'powershell.exe'); assert.equal(options.windowsHide, true); assert.equal(options.timeout, 5000);
    const script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    assert.match(script, /Get-ItemProperty/); assert.doesNotMatch(script, /Set-ItemProperty|Invoke-WebRequest|Invoke-Expression/);
    callback(null, '\uFEFF{"enabled":true,"server":"127.0.0.1:7890","pacPresent":false}');
  } });
  assert.equal(calls, 1); assert.equal(result.server, '127.0.0.1:7890');
  assert.deepEqual(await readWindowsProxySettings({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(new Error('PRIVATE_TOKEN')) }), {});
});
