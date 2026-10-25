import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { auditInputs, auditDelivery, signingEnvironment } from './audit.mjs';
import { prepareEdition, parseBuildArguments } from './edition.mjs';

export async function buildEdition(args, { root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..') } = {}) {
const options = parseBuildArguments(args);
const profile = await prepareEdition(root, options);
const expectations = { expectedEdition: profile.edition, expectedLicenseConfig: profile.distribution.licenseConfig };
console.log(JSON.stringify({ channel: 'unsigned-test', edition: profile.edition, stagingRoot: profile.stagingRoot, manifest: profile.manifestPath, signingEnvironmentPresent: signingEnvironment(process.env) }));
await auditInputs(profile.stagingRoot, expectations);
const require = createRequire(import.meta.url);
// Do not consume developer signing secrets, auto-discover certificates, or inherit Node preloads.
const environment = { ...process.env, CSC_IDENTITY_AUTO_DISCOVERY: 'false', ELECTRON_BUILDER_CACHE: path.join(root, '.cache/electron-builder') };
for (const name of Object.keys(environment)) {
  if (/^(?:NODE_OPTIONS|NODE_USE_ENV_PROXY|CSC_LINK|CSC_KEY_PASSWORD|CSC_NAME|WIN_CSC_LINK|WIN_CSC_KEY_PASSWORD|WIN_CSC_NAME|AZURE_CLIENT_SECRET|SIGNTOOL_PATH|ELECTRON_BUILDER_NSIS_DIR|ELECTRON_BUILDER_NSIS_RESOURCES_DIR|ELECTRON_BUILDER_RCEDIT_PATH|ELECTRON_BUILDER_BINARIES_.*)$/i.test(name)) delete environment[name];
}
const command = path.join(path.dirname(require.resolve('electron-builder/package.json')), 'cli.js');
const child = spawn(process.execPath, [command, '--win', ...options.targets, '--x64', '--publish', 'never'], { cwd: profile.stagingRoot, env: environment, stdio: 'inherit', windowsHide: true });
const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
if (code !== 0) return { code: code || 1, profile };
else {
  const report = await auditDelivery(profile.stagingRoot, expectations);
  console.log(JSON.stringify({ passed: report.passed, channel: report.channel, edition: profile.edition, report: report.reportPath, artifacts: report.artifacts.map(item => ({ name: item.name, bytes: item.bytes, sha256: item.sha256, signature: item.signature })) }));
  return { code: report.passed ? 0 : 1, profile, report };
}
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { process.exitCode = (await buildEdition(process.argv.slice(2))).code; }
  catch (error) { console.error(error.code || error.message); process.exitCode = 1; }
}
