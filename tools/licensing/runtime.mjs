import { lstat } from 'node:fs/promises';
import { dirname, resolve, isAbsolute } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { LicenseError } from '../../backend/src/license-format.mjs';
import { LicenseStore } from './store.mjs';
import { checkSafeFile, readSafeText, safeDirectory } from './safe-files.mjs';

export async function openStore(configPath, { deliver, now = Date.now } = {}) {
  let config;
  try { config = JSON.parse(await readSafeText(configPath, 16384)); }
  catch { throw new LicenseError('INVALID_SERVER_CONFIG', 'Cannot read licensing server configuration'); }
  if (!config || config.version !== 1 || Object.keys(config).sort().join(',') !== 'databasePath,keyId,privateKeyPath,version' || typeof config.keyId !== 'string' || !/^[A-Za-z0-9_.-]{1,40}$/.test(config.keyId) || typeof config.databasePath !== 'string' || typeof config.privateKeyPath !== 'string' || !config.databasePath || !config.privateKeyPath || config.databasePath.length > 4096 || config.privateKeyPath.length > 4096) throw new LicenseError('INVALID_SERVER_CONFIG', 'Invalid licensing server configuration');
  const localPath = value => isAbsolute(value) ? resolve(value) : resolve(dirname(configPath), value);
  const directory = await safeDirectory(dirname(resolve(configPath)));
  if (await readSafeText(resolve(directory, '.licensing-state'), 128) !== 'ProxyPilot licensing private state v1\n') throw new LicenseError('INVALID_SERVER_CONFIG', 'Use the private directory created by licensing init');
  const keyPath = localPath(config.privateKeyPath), databasePath = localPath(config.databasePath);
  const sameDirectory = path => (process.platform === 'win32' ? dirname(path).toLowerCase() === directory.toLowerCase() : dirname(path) === directory);
  if (!sameDirectory(keyPath) || !sameDirectory(databasePath) || keyPath === databasePath) throw new LicenseError('INVALID_SERVER_CONFIG', 'Signing key and database must stay inside the initialized private directory');
  await checkSafeFile(databasePath, 128 * 1024 * 1024);
  for (const suffix of ['-wal', '-shm']) {
    try { await lstat(databasePath + suffix); await checkSafeFile(databasePath + suffix, 128 * 1024 * 1024); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  let privateKey;
  try { privateKey = createPrivateKey(await readSafeText(keyPath, 8192)); }
  catch { throw new LicenseError('SIGNING_KEY_UNAVAILABLE', 'Cannot read licensing signing key'); }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new LicenseError('SIGNING_KEY_UNAVAILABLE', 'Licensing requires an Ed25519 signing key');
  return { store: new LicenseStore(databasePath, { privateKey, keyId: config.keyId, deliver, now }), publicKey: createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }), keyId: config.keyId };
}
