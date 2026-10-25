#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSingBox, loadConfig, loadSecrets, UserError } from './config.mjs';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { probe } from './probe.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const help = `ProxyPilot backend PoC (Node.js 20+, no dependencies)
  node src/cli.mjs init --dir runtime
  node src/cli.mjs validate --config runtime/config.json --secrets runtime/upstream.secrets.env
  node src/cli.mjs render --config runtime/config.json --secrets runtime/upstream.secrets.env --out runtime/deploy-01
  node src/cli.mjs probe --config runtime/config.json [--proxy-port 17890]

init/render require a NEW output directory. They never overwrite existing files.
probe exit 0 = pinned expected exit verified; 2 = IP discovered but not pinned; 1 = failure.
No VPS purchase, network deployment, system proxy changes, or direct fallback is performed.`;
function options(args, allowed) {
  const result = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index]; const value = args[index + 1];
    if (!allowed.includes(key) || !value || value.startsWith('--') || Object.hasOwn(result, key)) throw new UserError('ARGUMENTS_INVALID', 'Invalid, missing, duplicate, or unsupported command option');
    result[key] = value;
  }
  return result;
}
function required(opts, name) {
  if (!opts[name]) throw new UserError('ARGUMENTS_INVALID', `Required option: ${name}`);
  return opts[name];
}
async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ['help', '--help', '-h'].includes(command)) { console.log(help); return; }
  if (command === 'init') {
    const opts = options(args, ['--dir']); const dir = resolve(required(opts, '--dir'));
    await createPrivateDirectory(dir);
    await writePrivate(join(dir, 'config.json'), await readFile(join(root, 'examples', 'config.json')));
    await writePrivate(join(dir, 'upstream.secrets.env'), await readFile(join(root, 'examples', 'upstream.secrets.env.example')));
    console.log(JSON.stringify({ ok: true, message: 'Private runtime directory created. Edit config.json and upstream.secrets.env before validation.' }));
    return;
  }
  if (!['validate', 'render', 'probe'].includes(command)) throw new UserError('ARGUMENTS_INVALID', 'Unknown command; use help');
  const opts = options(args, command === 'probe' ? ['--config', '--proxy-port'] : command === 'render' ? ['--config', '--secrets', '--out'] : ['--config', '--secrets']);
  const config = await loadConfig(required(opts, '--config'));
  if (command === 'probe') {
    const port = opts['--proxy-port'] === undefined ? config.listen.port : Number(opts['--proxy-port']);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UserError('ARGUMENTS_INVALID', 'Proxy port must be between 1 and 65535');
    const result = await probe(config, port);
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 2;
    return;
  }
  const secrets = await loadSecrets(required(opts, '--secrets'), config);
  const generated = buildSingBox(config, secrets);
  if (command === 'validate') {
    console.log(JSON.stringify({ ok: true, upstreamType: config.upstream.type, upstreamTls: Boolean(config.upstream.tls), message: 'Configuration and credential shape valid. No network access tested.' }));
    return;
  }
  const dir = resolve(required(opts, '--out'));
  await createPrivateDirectory(dir);
  await writePrivate(join(dir, 'sing-box.json'), `${JSON.stringify(generated, null, 2)}\n`);
  for (const filename of ['install.sh', 'proxypilot.service']) await writePrivate(join(dir, filename), await readFile(join(root, 'deploy', filename)));
  console.log(JSON.stringify({ ok: true, message: 'Private deploy bundle created. Review install.sh; sing-box.json contains credentials. See backend README before SCP/install.' }));
}
main().catch(error => {
  // Never print raw parser/network errors: they may include credential values or remote response bodies.
  const safe = error instanceof UserError ? error : new UserError('OPERATION_FAILED', 'Operation failed; check paths, permissions, and the documented requirements');
  console.error(JSON.stringify({ ok: false, code: safe.code, message: safe.message }));
  process.exitCode = 1;
});
