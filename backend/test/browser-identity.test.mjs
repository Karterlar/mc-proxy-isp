import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveWindowsPlatformVersion, windowsContractPlatformVersion } from '../src/browser-identity.mjs';

test('Windows UA-CH decodes the Universal API contract DWORD, independently of the NT build', async () => {
  assert.equal(windowsContractPlatformVersion('    Windows.Foundation.UniversalApiContract    REG_DWORD    0x130000\r\n'), '19.0.0');
  assert.equal(windowsContractPlatformVersion(' Windows.Foundation.UniversalApiContract REG_DWORD 0x000a0002'), '10.2.0');
  for (const output of ['', 'Windows.Foundation.UniversalApiContract REG_SZ 10.0.26200', 'Windows.Foundation.UniversalApiContract REG_DWORD 0x00000000', 'Windows.Foundation.UniversalApiContract REG_DWORD 0x130000\nWindows.Foundation.UniversalApiContract REG_DWORD 0x130000', 'Other.Contract REG_DWORD 0x130000']) assert.equal(windowsContractPlatformVersion(output), null);
  let command;
  const result = await resolveWindowsPlatformVersion({ platform: 'win32', systemRoot: 'C:\\Windows', execFile: (file, args, options, done) => {
    command = { file, args, options }; done(null, 'Windows.Foundation.UniversalApiContract REG_DWORD 0x130000');
  } });
  assert.deepEqual(result, { version: '19.0.0', source: 'windows-universal-api-contract' });
  assert.equal(command.file, 'C:\\Windows\\System32\\reg.exe');
  assert.deepEqual(command.args, ['query', 'HKLM\\SOFTWARE\\Microsoft\\WindowsRuntime\\WellKnownContracts', '/v', 'Windows.Foundation.UniversalApiContract', '/reg:64']);
  assert.equal(command.options.windowsHide, true);
});

test('platform reads fail diagnostically without inventing a Windows version or modifying the registry', async () => {
  await assert.rejects(resolveWindowsPlatformVersion({ platform: 'linux', execFile: () => assert.fail('no command off Windows') }), { code: 'BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE' });
  for (const value of [null, 'Windows.Foundation.UniversalApiContract REG_DWORD 0xfffffffff']) await assert.rejects(resolveWindowsPlatformVersion({ platform: 'win32', execFile: (_file, _args, _options, done) => value === null ? done(new Error('denied private metadata')) : done(null, value) }), { code: 'BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE', message: '无法读取 Windows UA-CH 平台版本，请重试；未使用内核构建号替代' });
});
