import assert from 'node:assert/strict';
import { FINGERPRINT_BROWSER_RELEASE } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { createFingerprintSecurityCheck } from '../../backend/src/fingerprint-browser-security.mjs';
const args=process.argv.slice(2);assert.ok(args.length===0||args.length===1&&args[0]==='--check','Use no arguments for offline status, or --check for official release metadata');
const check=createFingerprintSecurityCheck({version:FINGERPRINT_BROWSER_RELEASE.version});
console.log(JSON.stringify(args.length?await check.check():check.snapshot(),null,2));
