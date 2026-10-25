import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { startController } from './local-controller.mjs';
const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath && invokedPath === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PROXYPILOT_CONTROL_PORT || 17654);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('PROXYPILOT_CONTROL_PORT must be between 1024 and 65535');
  const server = await startController({ host: '127.0.0.1', port,
    configPath: process.env.PROXYPILOT_CONFIG_PATH || undefined,
    secretsPath: process.env.PROXYPILOT_SECRETS_PATH || undefined,
    corePath: process.env.PROXYPILOT_CORE_PATH || undefined,
  });
  process.stdout.write(`MC Proxy owner-only control link: ${server.controlUrl()}\nKeep this temporary link private; it expires when this controller stops.\n`);
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    try { await server.shutdown(); process.exit(0); }
    catch { stopping = false; process.stderr.write('Safe shutdown is incomplete. Close the independent browser, then use End session or press Ctrl+C again.\n'); }
  };
  process.on('SIGINT', shutdown); process.on('SIGTERM', shutdown);
}

export { startController };
