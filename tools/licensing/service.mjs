import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { LicenseError } from '../../backend/src/license-format.mjs';
import { openStore } from './runtime.mjs';

const MESSAGES = {
  INVALID_REQUEST: 'Invalid activation request', INVALID_SIGNATURE: 'Invalid device signature', INVALID_KEY: 'Invalid device key',
  CARD_INVALID: 'Activation card is invalid', CARD_ALREADY_USED: 'Activation card was already used',
  RESOURCE_NOT_READY: 'Purchased network resources are awaiting fulfilment', RESOURCE_TERM_TOO_SHORT: 'Included ISP must cover the full purchased software term; this activation was not committed and the card remains available', INVALID_RESOURCE_MODE: 'Resource ownership must be included or customer', CARD_RESOURCE_MODE_FIXED: 'An unredeemed card retains its original order ISP supply mode', SERVER_CLOCK_INVALID: 'Licensing service clock is unavailable',
  REQUEST_CONFLICT: 'Request identifier was already used', DEVICE_MISMATCH: 'License belongs to another device',
  LICENSE_NOT_FOUND: 'License not found', LICENSE_REVOKED: 'License was revoked', REQUEST_TOO_LARGE: 'Request is too large',
  UNSUPPORTED_MEDIA_TYPE: 'Use application/json', NOT_FOUND: 'Endpoint not found', SERVICE_UNAVAILABLE: 'Licensing service is unavailable', RATE_LIMITED: 'Please retry later'
};
function respond(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
  response.end(JSON.stringify(body));
}
async function readRequest(request) {
  if (!/^application\/json(?:\s*;.*)?$/i.test(request.headers['content-type'] ?? '')) throw new LicenseError('UNSUPPORTED_MEDIA_TYPE', '');
  if (request.headers['content-encoding']) throw new LicenseError('INVALID_REQUEST', '');
  if (Number(request.headers['content-length'] ?? 0) > 8192) throw new LicenseError('REQUEST_TOO_LARGE', '');
  const body = await new Promise((resolve, reject) => {
    const chunks = []; let size = 0, tooLarge = false;
    request.on('data', chunk => {
      size += chunk.length;
      if (size > 8192) { if (!tooLarge) { tooLarge = true; chunks.length = 0; reject(new LicenseError('REQUEST_TOO_LARGE', '')); } }
      else if (!tooLarge) chunks.push(chunk);
    });
    request.once('end', () => { if (!tooLarge) resolve(Buffer.concat(chunks)); });
    request.once('error', () => reject(new LicenseError('INVALID_REQUEST', '')));
  });
  try { return JSON.parse(body.toString('utf8')); }
  catch { throw new LicenseError('INVALID_REQUEST', ''); }
}
export function createLicensingServer(store) {
  // ponytail: one loopback process and bounded global rate budget; add proxy per-IP limits when traffic grows.
  let windowStart = Date.now(), requestCount = 0;
  const server = createServer(async (request, response) => {
    try {
      if (request.method !== 'POST' || !['/v1/redeem', '/v1/refresh'].includes(request.url)) throw new LicenseError('NOT_FOUND', '');
      if (Date.now() - windowStart >= 60000) { windowStart = Date.now(); requestCount = 0; }
      if (++requestCount > 300) throw new LicenseError('RATE_LIMITED', '');
      const envelope = await readRequest(request);
      const license = request.url === '/v1/redeem' ? store.redeem(envelope) : store.refresh(envelope);
      respond(response, 200, { ok: true, data: { license } });
    } catch (error) {
      const code = error instanceof LicenseError && Object.hasOwn(MESSAGES, error.code) ? error.code : 'SERVICE_UNAVAILABLE';
      const status = code === 'NOT_FOUND' ? 404 : code === 'REQUEST_TOO_LARGE' ? 413 : code === 'UNSUPPORTED_MEDIA_TYPE' ? 415 : code === 'RATE_LIMITED' ? 429 : code === 'SERVICE_UNAVAILABLE' ? 503 : 400;
      respond(response, status, { ok: false, error: { code, message: MESSAGES[code] } });
    }
  });
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxConnections = 64;
  return server;
}
export async function startLicensingService(configPath, { host = '127.0.0.1', port = 8787 } = {}) {
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new LicenseError('INVALID_SERVER_CONFIG', 'Service must bind a loopback address');
  const { store } = await openStore(configPath);
  const server = createLicensingServer(store);
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }); }
  catch (error) { store.close(); throw error; }
  server.once('close', () => store.close());
  return server;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [configPath, portText = '8787'] = process.argv.slice(2);
  try {
    if (!configPath) throw new LicenseError('INVALID_SERVER_CONFIG', 'Usage: node tools/licensing/service.mjs <server-config.json> [port]');
    const server = await startLicensingService(configPath, { port: Number(portText) });
    process.stdout.write(`Licensing service listening on http://127.0.0.1:${server.address().port}\n`);
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close());
  } catch (error) { process.stderr.write(`${error instanceof LicenseError ? error.code + ': ' + error.message : 'SERVICE_UNAVAILABLE: Cannot start licensing service'}\n`); process.exitCode = 1; }
}
