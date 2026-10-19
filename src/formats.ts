import path from 'node:path';
export interface Format { format: string; family: 'native' | 'managed' | 'javascript' | 'source' | 'container' | 'data'; architecture?: string; backend: string; identification: string; encrypted?: boolean }
const cpu = (value: number) => ({ 7: 'x86', 0x1000007: 'x86_64', 12: 'arm', 0x100000c: 'arm64', 18: 'ppc', 0x1000012: 'ppc64' } as Record<number, string>)[value] ?? `cpu-${value}`;
/** Header facts and extension hints only: this never executes the target. */
export function identifyFormat(header: Buffer, filename: string): Format {
  const ext = path.extname(filename).toLowerCase(); const magic = header.length >= 4 ? header.readUInt32BE(0) : 0;
  if (magic === 0x7f454c46 && header.length >= 20) {
    const machine = header[5] === 2 ? header.readUInt16BE(18) : header.readUInt16LE(18);
    return { format: 'elf', family: 'native', backend: 'ghidra', architecture: ({ 3: 'x86', 62: 'x86_64', 40: 'arm', 183: 'arm64', 243: 'riscv' } as Record<number, string>)[machine] ?? `elf-machine-${machine}`, identification: 'header' };
  }
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic) && header.length >= 28) {
    const little = magic === 0xcefaedfe || magic === 0xcffaedfe; const read = (offset: number) => little ? header.readUInt32LE(offset) : header.readUInt32BE(offset);
    const ncmds = read(16); let offset = [0xfeedfacf, 0xcffaedfe].includes(magic) ? 32 : 28; let encrypted: boolean | undefined;
    for (let i = 0; i < ncmds && i < 4096 && offset + 8 <= header.length; i++) {
      const cmd = read(offset); const size = read(offset + 4); if (size < 8 || offset + size > header.length) break;
      if ([0x21, 0x2c].includes(cmd & 0x7fffffff) && size >= 20) encrypted = read(offset + 16) !== 0;
      offset += size;
    }
    return { format: 'mach-o', family: 'native', backend: 'ghidra', architecture: cpu(read(4)), identification: 'header', ...(encrypted !== undefined ? { encrypted } : {}) };
  }
  if (magic === 0xcafebabe && header.length >= 8 && header.readUInt16BE(6) >= 45 && header.readUInt16BE(6) <= 100) return { format: 'java-class', family: 'managed', backend: 'jadx', identification: 'header' };
  if ([0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].includes(magic)) return { format: 'mach-o-fat', family: 'native', backend: 'ghidra', architecture: 'multiple-slices', identification: 'header' };
  if (header.length >= 64 && header.subarray(0, 2).toString() === 'MZ') {
    const offset = header.readUInt32LE(60);
    if (offset + 26 <= header.length && header.subarray(offset, offset + 4).equals(Buffer.from([80, 69, 0, 0]))) {
      const machine = header.readUInt16LE(offset + 4); const optional = offset + 24; const magic = header.readUInt16LE(optional);
      const directory = optional + (magic === 0x20b ? 112 : 96) + 14 * 8;
      const managed = directory + 8 <= header.length && header.readUInt32LE(directory) !== 0;
      return { format: managed ? 'pe-cli' : 'pe', family: managed ? 'managed' : 'native', backend: managed ? 'ilspy' : 'ghidra', architecture: ({ 0x14c: 'x86', 0x8664: 'x86_64', 0x1c4: 'arm', 0xaa64: 'arm64' } as Record<number, string>)[machine] ?? `pe-machine-${machine}`, identification: 'header' };
    }
    return { format: 'dos-mz-or-pe', family: 'native', backend: 'ghidra', identification: 'partial-header' };
  }
  if (/^dex\n\d{3}\0/.test(header.subarray(0, 8).toString('latin1'))) return { format: 'dex', family: 'managed', backend: 'jadx', identification: 'header' };
  if (magic === 0x0061736d) return { format: 'wasm', family: 'managed', backend: 'wasm', identification: 'header' };
  if ([0x504b0304, 0x504b0506, 0x504b0708].includes(magic)) {
    const kind = ({ '.apk': 'apk', '.aab': 'aab', '.ipa': 'ipa', '.jar': 'jar', '.aar': 'aar' } as Record<string, string>)[ext] ?? 'zip';
    return { format: kind, family: 'container', backend: ['apk', 'aab', 'jar', 'aar'].includes(kind) ? 'jadx' : 'container', identification: kind === 'zip' ? 'header' : 'zip-header-plus-extension-hint' };
  }
  if (['.js', '.mjs', '.cjs', '.jsx'].includes(ext)) return { format: 'javascript', family: 'javascript', backend: 'javascript', identification: 'extension-hint' };
  if (ext === '.asar') return { format: 'asar', family: 'container', backend: 'javascript', identification: 'extension-hint' };
  if (['.ts', '.tsx', '.py', '.c', '.cpp', '.cc', '.h', '.hpp', '.rs', '.go', '.swift', '.m', '.mm', '.java', '.cs'].includes(ext)) return { format: ext.slice(1) + '-source', family: 'source', backend: 'source', identification: 'extension-hint' };
  return { format: 'data', family: 'data', backend: 'none', identification: 'unknown' };
}
