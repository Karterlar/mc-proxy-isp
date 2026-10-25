import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareFingerprintBrowser } from '../../backend/src/fingerprint-browser-install.mjs';
import { FINGERPRINT_BROWSER_CACHE_DIRECTORY } from '../../backend/src/fingerprint-browser-runtime.mjs';
export { prepareFingerprintBrowser };

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const target = process.argv[2] || fileURLToPath(new URL(`../../.cache/${FINGERPRINT_BROWSER_CACHE_DIRECTORY}`, import.meta.url));
  try { console.log(JSON.stringify(await prepareFingerprintBrowser(path.resolve(target)), null, 2)); }
  catch (error) { console.error(error.code || 'BROWSER_FINGERPRINT_INSTALL_FAILED', error.message); process.exitCode = 1; }
}
