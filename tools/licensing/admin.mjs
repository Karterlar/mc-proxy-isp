import { generateKeyPairSync } from 'node:crypto';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateDirectory, writePrivate } from '../../backend/src/private-files.mjs';
import { LicenseError, validateLicenseConfig } from '../../backend/src/license-format.mjs';
import { LicenseStore } from './store.mjs';
import { openStore } from './runtime.mjs';
import { readSafeText, safeDirectory, reserveSafeOutput } from './safe-files.mjs';

const JSON_TEXT = value => `${JSON.stringify(value, null, 2)}\n`;
function fail(message) { throw new LicenseError('INVALID_ARGUMENT', message); }
function parse(args) {
  const [command, ...rest] = args, options = {};
  for (let i = 0; i < rest.length; i++) {
    const name = rest[i];
    if (!/^--[a-z][a-z-]*$/.test(name) || Object.hasOwn(options, name.slice(2))) fail('Invalid or duplicate option');
    options[name.slice(2)] = ['--paid', '--resources-ready', '--pending', '--offline'].includes(name) ? true : rest[++i];
    if (options[name.slice(2)] === undefined || (typeof options[name.slice(2)] === 'string' && options[name.slice(2)].startsWith('--'))) fail(`Missing value for ${name}`);
  }
  return { command, options };
}
function requireValue(options, name) { if (!options[name]) fail(`--${name} is required`); return options[name]; }
function expiry(value, required = false) {
  if (value === undefined || value === 'none') { if (required) fail('--isp-expires is required'); return null; }
  const parsed = /^\d+$/.test(value) ? Number(value) : Date.parse(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail('Expiry must be epoch milliseconds or an ISO date');
  return parsed;
}
function payment(options) {
  return { orderId: requireValue(options, 'order-id'), paid: options.paid === true, resourcesReady: options['resources-ready'] === true,
    ispExpiresAt: expiry(options['isp-expires']), vpsExpiresAt: expiry(options['vps-expires']), offlineDays: offlineDays(options), resourcesMode: options['resources-mode'] };
}
function offlineDays(options) {
  if (options['offline-days'] === undefined) return undefined;
  const days = Number(options['offline-days']);
  if (![1, 3, 7, 15, 30].includes(days)) fail('--offline-days must be 1, 3, 7, 15 or 30');
  return days;
}
async function application(options) {
  try {
    const text = await readSafeText(requireValue(options, 'application'), 8192);
    return JSON.parse(text);
  } catch (error) { if (error instanceof LicenseError) throw error; fail('Cannot read offline application JSON'); }
}
export async function initializeLicensing(options) {
  const directory = resolve(requireValue(options, 'dir'));
  const keyId = options['key-id'] ?? 'license-1';
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  if (Boolean(options.offline) === Boolean(options['service-url'])) fail('Choose --offline or --service-url');
  const validatedConfig = validateLicenseConfig({ version: 1, mode: 'required', ...(options.offline ? {} : { serviceUrl: options['service-url'] }), publicKeys: { [keyId]: publicPem } });
  const clientConfig = options.offline ? { version: 1, mode: 'required', publicKeys: validatedConfig.publicKeys } : validatedConfig;
  await safeDirectory(resolve(directory, '..'));
  await createPrivateDirectory(directory);
  await writePrivate(join(directory, '.licensing-state'), 'ProxyPilot licensing private state v1\n');
  await writePrivate(join(directory, 'signing-private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await writePrivate(join(directory, 'signing-public.pem'), publicPem);
  await writePrivate(join(directory, 'server-config.json'), JSON_TEXT({ version: 1, keyId, privateKeyPath: 'signing-private.pem', databasePath: 'licenses.sqlite' }));
  await writePrivate(join(directory, 'client-config.template.json'), JSON_TEXT(clientConfig));
  const store = new LicenseStore(join(directory, 'licenses.sqlite'), { privateKey, keyId }); store.close();
  return { directory, serverConfig: join(directory, 'server-config.json'), clientConfigTemplate: join(directory, 'client-config.template.json') };
}
export async function runAdmin(args) {
  const { command, options } = parse(args);
  const common = ['config', 'out'];
  const allowed = {
    init: ['dir', 'service-url', 'offline', 'key-id'], 'issue-card': [...common, 'order-id', 'paid', 'resources-ready', 'isp-expires', 'vps-expires'],
    'activate-offline': [...common, 'application', 'card', 'order-id', 'paid', 'resources-ready', 'isp-expires', 'vps-expires', 'offline-days'],
    'trial-offline': [...common, 'application', 'resources-ready', 'isp-expires', 'vps-expires', 'offline-days'],
    'refresh-offline': [...common, 'application', 'license-id', 'offline-days'],
    renew: [...common, 'license-id', 'order-id', 'paid', 'resources-ready', 'isp-expires', 'vps-expires', 'offline-days'],
    'card-resources': [...common, 'order-id', 'resources-ready', 'isp-expires', 'vps-expires'], 'card-revoke': [...common, 'order-id'],
    resources: [...common, 'license-id', 'resources-ready', 'pending', 'isp-expires', 'vps-expires', 'offline-days'], rebind: [...common, 'license-id', 'application', 'offline-days'],
    revoke: [...common, 'license-id'], list: common, status: [...common, 'license-id']
  };
  for (const action of ['issue-card', 'activate-offline', 'trial-offline', 'renew', 'card-resources', 'resources']) allowed[action].push('resources-mode');
  if (!Object.hasOwn(allowed, command)) fail('Commands: init, issue-card, card-resources, card-revoke, trial-offline, activate-offline, refresh-offline, renew, resources, rebind, revoke, list, status');
  if (Object.keys(options).some(key => !allowed[command].includes(key))) fail('Unknown option for this command');
  let result;
  if (command === 'init') return initializeLicensing(options);
  const configPath = resolve(requireValue(options, 'config'));
  const output = options.out ? await reserveSafeOutput(options.out) : null;
  let store, delivered = false;
  try {
    ({ store } = await openStore(configPath, { deliver: output ? value => { output.write(JSON_TEXT(value)); delivered = true; } : undefined }));
    switch (command) {
      case 'issue-card': result = store.issueCard(payment(options)); break;
      case 'card-resources': result = store.cardResources(requireValue(options, 'order-id'), { resourcesReady: options['resources-ready'] === true, ispExpiresAt: expiry(options['isp-expires']), vpsExpiresAt: expiry(options['vps-expires']), resourcesMode: options['resources-mode'] }); break;
      case 'card-revoke': result = store.cardRevoke(requireValue(options, 'order-id')); break;
      case 'trial-offline': result = store.trialOffline(await application(options), { resourcesReady: options['resources-ready'] === true, ispExpiresAt: expiry(options['isp-expires']), vpsExpiresAt: expiry(options['vps-expires']), offlineDays: offlineDays(options), resourcesMode: options['resources-mode'] }); break;
      case 'activate-offline': result = store.activateOffline(await application(options), options.card ? { card: options.card, offlineDays: offlineDays(options) } : payment(options)); break;
      case 'refresh-offline': {
        if (Boolean(options.application) === Boolean(options['license-id'])) fail('Choose --application or --license-id');
        result = options.application ? store.refreshOffline(await application(options), { offlineDays: offlineDays(options) }) : store.refreshOfflineById(options['license-id'], { offlineDays: offlineDays(options) }); break;
      }
      case 'renew': result = store.renew(requireValue(options, 'license-id'), payment(options)); break;
      case 'resources': {
        if (options['resources-mode'] !== 'customer' && Boolean(options.pending) === Boolean(options['resources-ready'])) fail('Choose --resources-ready or --pending');
        result = store.resources(requireValue(options, 'license-id'), { resourcesReady: !options.pending, ispExpiresAt: expiry(options['isp-expires']), vpsExpiresAt: expiry(options['vps-expires']), offlineDays: offlineDays(options), resourcesMode: options['resources-mode'] }); break;
      }
      case 'rebind': result = store.rebind(requireValue(options, 'license-id'), await application(options), { offlineDays: offlineDays(options) }); break;
      case 'revoke': result = store.revoke(requireValue(options, 'license-id')); break;
      case 'list': result = store.list(); break;
      case 'status': result = store.status(requireValue(options, 'license-id')); break;
    }
    if (output && !delivered) output.write(JSON_TEXT(result));
    output?.close();
  } catch (error) { output?.cancel(); throw error; }
  finally { store?.close(); }
  if (options.out) return { output: resolve(options.out) };
  return result;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON_TEXT(await runAdmin(process.argv.slice(2)))); }
  catch (error) { process.stderr.write(`${error instanceof LicenseError ? error.code + ': ' + error.message : 'ADMIN_FAILED: Licensing operation failed'}\n`); process.exitCode = 1; }
}
