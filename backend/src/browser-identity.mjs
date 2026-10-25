import path from 'node:path';
import { execFile as nodeExecFile } from 'node:child_process';

// Chromium reports the Windows Universal API contract, not the NT kernel build,
// in UA-CH platformVersion. In particular, 0x130000 is 19.0.0, not 10.0.26200.
export function windowsContractPlatformVersion(output) {
  const values = [...String(output).matchAll(/^\s*Windows\.Foundation\.UniversalApiContract\s+REG_DWORD\s+(0x[0-9a-f]{1,8})\s*$/gim)];
  if (values.length !== 1) return null;
  const packed = Number.parseInt(values[0][1], 16);
  const major = Math.floor(packed / 65536), minor = packed & 0xffff;
  return major > 0 ? `${major}.${minor}.0` : null;
}

export async function resolveWindowsPlatformVersion({ execFile = nodeExecFile, platform = process.platform, systemRoot = process.env.SystemRoot || 'C:\\Windows' } = {}) {
  const unavailable = () => Object.assign(new Error('无法读取 Windows UA-CH 平台版本，请重试；未使用内核构建号替代'), { code: 'BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE', status: 409 });
  if (platform !== 'win32') throw unavailable();
  try {
    const output = await new Promise((resolve, reject) => execFile(path.win32.join(systemRoot, 'System32', 'reg.exe'), [
      'query', 'HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\WellKnownContracts', '/v', 'Windows.Foundation.UniversalApiContract', '/reg:64',
    ], { windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 8192 }, (cause, stdout) => cause ? reject(cause) : resolve(stdout)));
    const version = windowsContractPlatformVersion(output);
    if (!version) throw unavailable();
    return { version, source: 'windows-universal-api-contract' };
  } catch { throw unavailable(); }
}
