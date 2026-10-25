import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Node encodes an 8.3 path's '~' as %7E; Chromium retains the literal '~'.
// Compare the decoded local file identity, keeping the exact resource list.
export function matchesAdminFileUrl(value, file) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'file:' || url.host || url.username || url.password || url.port || url.search || url.hash || !path.isAbsolute(file)) return false;
    const actual = path.resolve(fileURLToPath(url)), expected = path.resolve(file);
    return process.platform === 'win32' ? actual.toLowerCase() === expected.toLowerCase() : actual === expected;
  } catch { return false; }
}
