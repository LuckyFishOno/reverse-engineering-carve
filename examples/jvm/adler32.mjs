// Independent reconstruction of the JDK java.util.zip.Adler32 whole-array checksum
// (shipped libzip adler32_z: modulus 65521, reduction every 5552 bytes).
// No JVM, JNI or native library dependency.
export function adler32(bytes) {
  if (!Array.isArray(bytes) || bytes.length > 1048576) throw new TypeError('Expected an array of at most1048576 integer bytes.');
  for (const byte of bytes) if (!Number.isInteger(byte) || byte < 0 || byte > 255) throw new TypeError('Expected integer bytes0–255.');
  const BASE = 65521, NMAX = 5552;
  let a = 1, b = 0;
  for (let i = 0; i < bytes.length;) {
    const end = Math.min(i + NMAX, bytes.length);
    for (; i < end; i++) { a += bytes[i]; b += a; }
    a %= BASE; b %= BASE;
  }
  // Unsigned 32-bit result, like Adler32.getValue().
  return b * 65536 + a;
}
