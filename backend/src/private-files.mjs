import { mkdir, writeFile, rename as renameFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, win32 } from 'node:path';
import { UserError } from './config.mjs';

const executeFile = promisify(execFile);
const runPrivateCommand = (...args) => executeFile(...args).then(result => ({ ...result, status: 0 }));

export async function createPrivateDirectory(path, { platform = process.platform, run = runPrivateCommand, systemRoot = process.env.SystemRoot || 'C:\\Windows' } = {}) {
  try { await mkdir(path, { mode: 0o700 }); }
  catch (error) { throw new UserError('OUTPUT_UNAVAILABLE', error.code === 'EEXIST' ? 'Output directory already exists; choose a new directory to avoid overwriting secrets/configuration' : 'Cannot create output directory; its parent must exist'); }
  if (platform === 'win32') {
    const commandOptions = { encoding: 'utf8', windowsHide: true, timeout: 15000, maxBuffer: 65536 };
    const execute = async (file, args) => { try { return await run(file, args, commandOptions); } catch (error) { return { error }; } };
    const who = await execute(win32.join(systemRoot, 'System32', 'whoami.exe'), ['/user', '/fo', 'csv', '/nh']);
    const sid = who.stdout?.match(/S-1-5-(?:\d+-)*\d+/)?.[0];
    if (who.error || who.status !== 0 || !sid) throw new UserError('ACL_FAILED', 'Cannot identify Windows user; no secrets have been written');
    const acl = await execute(win32.join(systemRoot, 'System32', 'icacls.exe'), [path, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`, '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']);
    if (acl.error || acl.status !== 0) throw new UserError('ACL_FAILED', 'Cannot restrict Windows directory ACL; no secrets have been written');
  }
  await writeFile(join(path, '.gitignore'), '*\n', { flag: 'wx', mode: 0o600 });
}
export async function writePrivate(path, content) {
  await writeFile(path, content, { flag: 'wx', mode: 0o600 });
}

// Windows readers/virus scanners can briefly deny replacing an open journal.
// Retain the old file throughout; never unlink it to work around sharing locks.
export async function renamePrivate(source, target, { rename = renameFile, wait = delay, platform = process.platform } = {}) {
  for (let attempt = 0; ; attempt++) {
    try { return await rename(source, target); }
    catch (cause) {
      if (platform !== 'win32' || !['EPERM', 'EACCES', 'EBUSY'].includes(cause.code) || attempt >= 4) throw cause;
      await wait(25 * (attempt + 1));
    }
  }
}
