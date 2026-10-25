const stages = new Set(['validating-input', 'preparing-runtime', 'creating-runtime', 'recovering-proxy', 'allocating-port',
  'starting-proxy', 'checking-exit', 'checking-ownership', 'inspecting-exit', 'stopping-proxy', 'disposing-runtime']);
const nativeCodes = new Set(['EACCES', 'EPERM', 'EBUSY', 'ENOENT', 'EEXIST', 'ENOSPC', 'ENOTDIR', 'EISDIR', 'EMFILE', 'ENFILE',
  'EIO', 'EROFS', 'ENAMETOOLONG', 'EINVAL', 'ENOMEM', 'ENOTEMPTY', 'ETIMEDOUT',
  'ERR_INVALID_ARG_TYPE', 'ERR_INVALID_ARG_VALUE', 'ERR_OUT_OF_RANGE', 'ERR_METHOD_NOT_IMPLEMENTED']);
const nativeErrors = new Set(['Error', 'TypeError', 'ReferenceError', 'SyntaxError', 'RangeError', 'AggregateError', 'EvalError', 'URIError']);

// Fixed categories only: native exception text can contain paths and credentials.
export function sanitizeSetupDiagnostic(value) {
  const result = {};
  if (stages.has(value?.setupStage)) result.setupStage = value.setupStage;
  if (nativeCodes.has(value?.nativeCode)) result.nativeCode = value.nativeCode;
  if (nativeErrors.has(value?.nativeError)) result.nativeError = value.nativeError;
  return Object.keys(result).length ? result : null;
}
