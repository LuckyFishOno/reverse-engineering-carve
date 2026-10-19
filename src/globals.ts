export const standardGlobals = new Set([
  'undefined', 'NaN', 'Infinity', 'Object', 'Array', 'String', 'Number', 'Boolean', 'BigInt',
  'Symbol', 'Math', 'JSON', 'RegExp', 'Date', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Promise',
  'Error', 'TypeError', 'RangeError', 'SyntaxError', 'URIError', 'ReferenceError', 'EvalError',
  'AggregateError', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Int8Array', 'Uint8Array',
  'Uint8ClampedArray', 'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array',
  'Float64Array', 'BigInt64Array', 'BigUint64Array', 'Intl', 'Reflect', 'Proxy',
  'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURI', 'encodeURIComponent',
  'decodeURI', 'decodeURIComponent', 'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams',
  'atob', 'btoa', 'structuredClone'
]);
