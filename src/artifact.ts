import { createHash } from 'node:crypto';
import { readFile, realpath, stat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { extractFile, listPackage, statFile } from '@electron/asar';

export const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_FILES = 20_000;
const javascript = /\.(?:[cm]?js|jsx)$/i;
export const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

export interface Source {
  target: string;
  kind: 'javascript' | 'directory' | 'asar';
  module: string;
  code: string;
  sha256: string;
  bytes: number;
}

function modulePath(value: string): string {
  if (!value || value.includes('\\') || value.includes('\0') || path.posix.isAbsolute(value)
    || value.split('/').some(part => part === '..' || part === '.')) {
    throw new Error('Module must be a relative path inside the artifact, without .. or symlinks.');
  }
  return value;
}

export async function inventory(input: string) {
  const target = await realpath(input);
  const info = await stat(target);
  if (!info.isFile() && !info.isDirectory()) throw new Error('Target must be a regular file or directory.');
  if (info.isFile() && target.endsWith('.asar')) {
    const entries = listPackage(target, { isPack: false });
    if (entries.length > MAX_FILES) throw new Error(`ASAR exceeds the ${MAX_FILES} entry limit.`);
    const modules = entries.map(p => p.replace(/^\//, '')).filter(p => javascript.test(p)).sort();
    return { target, kind: 'asar' as const, modules, executesTarget: false };
  }
  if (info.isFile()) {
    if (!javascript.test(target)) throw new Error('Supported targets: JavaScript files, directories and ASAR archives.');
    return { target, kind: 'javascript' as const, modules: [path.basename(target)], executesTarget: false };
  }
  if (!info.isDirectory()) throw new Error('Target is not a regular file or directory.');
  const modules: string[] = [];
  let visited = 0;
  async function walk(folder: string) {
    for (const entry of await readdir(folder, { withFileTypes: true })) {
      if (++visited > MAX_FILES) throw new Error(`Directory exceeds the ${MAX_FILES} entry limit.`);
      if (entry.isSymbolicLink() || ['node_modules', '.git'].includes(entry.name)) continue;
      const item = path.join(folder, entry.name);
      if (entry.isDirectory()) await walk(item);
      else if (entry.isFile() && javascript.test(entry.name)) modules.push(path.relative(target, item).split(path.sep).join('/'));
    }
  }
  await walk(target);
  return { target, kind: 'directory' as const, modules: modules.sort(), executesTarget: false };
}

export async function loadSource(input: string, selectedModule?: string): Promise<Source> {
  const target = await realpath(input);
  const info = await stat(target);
  if (!info.isFile() && !info.isDirectory()) throw new Error('Target must be a regular file or directory.');
  let data: Buffer;
  let kind: Source['kind'];
  let module: string;
  if (info.isFile() && target.endsWith('.asar')) {
    kind = 'asar';
    if (!selectedModule) throw new Error('Choose an ASAR module with --file. Use inspect to list modules.');
    module = modulePath(selectedModule);
    const entry = statFile(target, module, false);
    if ('link' in entry || !('size' in entry) || entry.unpacked) throw new Error('Linked, unpacked or directory ASAR entries are unsupported.');
    if (entry.size > MAX_SOURCE_BYTES) throw new Error('Selected source exceeds 16 MiB.');
    data = extractFile(target, module);
  } else if (info.isDirectory()) {
    kind = 'directory';
    if (!selectedModule) throw new Error('Choose a directory module with --file. Use inspect to list modules.');
    module = modulePath(selectedModule);
    const candidate = path.join(target, module);
    const resolved = await realpath(candidate);
    if (resolved !== candidate || !resolved.startsWith(target + path.sep)) throw new Error('Module escapes artifact or follows a symlink.');
    if ((await stat(resolved)).size > MAX_SOURCE_BYTES) throw new Error('Selected source exceeds 16 MiB.');
    data = await readFile(resolved);
  } else {
    kind = 'javascript';
    module = path.basename(target);
    if (selectedModule && selectedModule !== module) throw new Error('Use --file only for a module inside a directory or ASAR.');
    if (info.size > MAX_SOURCE_BYTES) throw new Error('Selected source exceeds 16 MiB.');
    data = await readFile(target);
  }
  if (!javascript.test(module)) throw new Error('Selected module must be JavaScript.');
  if (data.length > MAX_SOURCE_BYTES) throw new Error('Selected source exceeds 16 MiB.');
  const code = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
  return { target, kind, module, code, sha256: digest(data), bytes: data.length };
}
