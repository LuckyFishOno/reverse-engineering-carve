// Independent bounded reconstruction of JDK Adler32 object state and libzip
// incremental adler32_z. The operation wrapper is a Carve API, not Java overloads.
let state = 1;
export function adler32Step(operation, ...parameters) {
  if (operation === 0 || operation === 2) {
    if (parameters.length !== 0) throw new TypeError('Read/reset take no byte argument.');
    if (operation === 2) state = 1;
    return state;
  }
  if (operation !== 1 || parameters.length !== 1 || !Array.isArray(parameters[0])) throw new TypeError('Use0 read,1 update with a byte array,2 reset.');
  const bytes = parameters[0];
  if (bytes.length > 65536) throw new TypeError('Update requires at most65536 integer bytes0–255.');
  for (const byte of bytes) if (!Number.isInteger(byte) || byte < 0 || byte > 255) throw new TypeError('Update requires at most65536 integer bytes0–255.');
  let a = state & 65535, b = state >>> 16;
  for (let i=0; i<bytes.length;) {
    const end = Math.min(i+5552,bytes.length);
    for (; i<end; ++i) { a += bytes[i]; b += a; }
    a %= 65521; b %= 65521;
  }
  state = b*65536+a;
  return state;
}
