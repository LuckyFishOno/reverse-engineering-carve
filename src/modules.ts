import path from 'node:path';
import { readFile, realpath, stat, lstat } from 'node:fs/promises';
import { extractFile, listPackage, statFile } from '@electron/asar';
import { digest, MAX_SOURCE_BYTES, type Source } from './artifact.js';

export const portableBuiltins = new Set(['node:path', 'node:buffer', 'node:util', 'node:url', 'node:querystring', 'node:string_decoder', 'node:assert', 'node:assert/strict', 'node:crypto']);
const js = /\.(?:[cm]?js|jsx)$/i;
const missing = (name: string) => Object.assign(new Error(`Artifact file not found: ${name}`), { code: 'ENOENT' });
export const inside = (root: string, item: string) => {
  const relative = path.relative(root, item);
  return relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
};

export class Artifact {
  private cache = new Map<string, Buffer>();
  readonly inputs = new Map<string, { module: string; sha256: string; bytes: number }>();
  private total = 0;
  private entries?: Set<string>;
  private checkedPaths = new Set<string>();
  private constructor(readonly target: string, readonly root: string, readonly kind: Source['kind'], readonly defaultEntry?: string) {}
  static async open(input: string) {
    const target = await realpath(input);
    const info = await stat(target);
    if (!info.isFile() && !info.isDirectory()) throw new Error('Artifact must be a file or directory.');
    const kind = info.isDirectory() ? 'directory' : target.endsWith('.asar') ? 'asar' : 'javascript';
    const artifact = new Artifact(target, kind === 'javascript' ? path.dirname(target) : target, kind,
      kind === 'javascript' ? path.basename(target) : undefined);
    if (kind === 'asar') {
      const entries = listPackage(target, { isPack: false });
      if (entries.length > 20_000) throw new Error('ASAR exceeds 20000 entries.');
      artifact.entries = new Set(entries.map(p => p.replace(/^\//, '')));
    }
    return artifact;
  }
  normalize(module: string) {
    if (!module || module.includes('\\') || module.includes('\0') || module.startsWith('/')
      || module.split('/').includes('..')) throw new Error(`Module escapes artifact boundary: ${module}`);
    const normalized = path.posix.normalize(module);
    if (normalized === '.' || normalized.startsWith('../')) throw new Error('Invalid module path.');
    return normalized;
  }
  async read(module: string) {
    module = this.normalize(module);
    const cached = this.cache.get(module); if (cached) return cached;
    let data: Buffer;
    if (this.kind === 'asar') {
      if (!this.entries!.has(module)) throw missing(module);
      const info = statFile(this.target, module, false);
      if ('link' in info || !('size' in info) || info.unpacked) throw new Error(`Linked, unpacked or directory ASAR input is unsupported: ${module}`);
      if (info.size > MAX_SOURCE_BYTES) throw new Error(`Module exceeds 16 MiB: ${module}`);
      data = extractFile(this.target, module, false);
    } else {
      const candidate = path.join(this.root, module);
      const actual = await realpath(candidate);
      if (!inside(this.root, actual)) throw new Error(`Module follows a symlink or escapes artifact: ${module}`);
      let current = this.root;
      for (const component of module.split('/')) {
        current = path.join(current, component);
        if (!this.checkedPaths.has(current)) {
          if ((await lstat(current)).isSymbolicLink()) throw new Error(`Module follows a symlink: ${module}`);
          this.checkedPaths.add(current);
        }
      }
      const info = await stat(actual);
      if (!info.isFile()) throw missing(module);
      if (info.size > MAX_SOURCE_BYTES) throw new Error(`Module exceeds 16 MiB: ${module}`);
      data = await readFile(actual);
    }
    if (data.length > MAX_SOURCE_BYTES || this.total + data.length > 64 * 1024 * 1024) throw new Error('Artifact analysis exceeds the 16 MiB/module or 64 MiB total input limit.');
    this.total += data.length;
    this.cache.set(module, data);
    this.inputs.set(module, { module, sha256: digest(data), bytes: data.length });
    return data;
  }
  async text(module: string) { return new TextDecoder('utf-8', { fatal: true }).decode(await this.read(module)); }
  async optionalText(module: string) {
    try { return await this.text(module); } catch (error) {
      if (['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '')) return undefined;
      throw error;
    }
  }
  async source(module?: string): Promise<Source> {
    module ??= this.defaultEntry;
    if (!module) throw new Error('Choose an artifact module with --file.');
    module = this.normalize(module);
    if (!js.test(module)) throw new Error(`Unsupported JavaScript module: ${module}`);
    const data = await this.read(module);
    return { target: this.target, kind: this.kind, module, code: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data), sha256: digest(data), bytes: data.length };
  }
  async resolve(importer: string, specifier: string, mode: 'import' | 'require' = 'import'): Promise<string> {
    const canonicalBuiltin = specifier.startsWith('node:') ? specifier : 'node:' + specifier;
    if (portableBuiltins.has(canonicalBuiltin)) return canonicalBuiltin;
    if (!specifier || specifier.includes('\\') || specifier.includes('\0') || specifier.startsWith('/') || specifier.includes(':') || specifier.startsWith('#')) {
      throw new Error(`Unsupported module specifier: ${specifier}`);
    }
    if (specifier.startsWith('.')) {
      const candidate = path.posix.normalize(path.posix.join(path.posix.dirname(importer), specifier));
      return this.resolveFile(this.normalize(candidate), mode);
    }
    const parts = specifier.split('/');
    const packageName = parts.splice(0, specifier.startsWith('@') ? 2 : 1).join('/');
    if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(packageName) || parts.some(p => p === '..' || p === '.')) throw new Error(`Invalid package specifier: ${specifier}`);
    const subpath = parts.join('/');
    let directory = path.posix.dirname(importer);
    while (true) {
      const packageRoot = path.posix.join(directory, 'node_modules', packageName);
      const metadata = await this.optionalText(packageRoot + '/package.json');
      if (metadata !== undefined) {
        const pkg = JSON.parse(metadata);
        let entry: string | null | undefined;
        if (pkg.exports !== undefined) {
          const key = subpath ? './' + subpath : '.';
          const map = pkg.exports;
          let target: unknown;
          if (typeof map === 'string' || map === null || (typeof map === 'object' && !Array.isArray(map) && !Object.keys(map).some(k => k.startsWith('.')))) target = key === '.' ? map : undefined;
          else if (map && typeof map === 'object' && !Array.isArray(map)) {
            target = map[key];
            if (target === undefined) {
              const pattern = Object.keys(map).filter(k => k.includes('*') && key.startsWith(k.split('*')[0]!) && key.endsWith(k.split('*')[1]!)).sort((a, b) => b.indexOf('*') - a.indexOf('*') || b.length - a.length)[0];
              if (pattern) {
                const [prefix, suffix] = pattern.split('*');
                const match = key.slice(prefix!.length, key.length - suffix!.length);
                const selected = this.condition(map[pattern], mode);
                target = selected?.replaceAll('*', match);
              }
            }
          }
          entry = this.condition(target, mode);
          if (!entry || !entry.startsWith('./')) throw new Error(`Package export is unavailable or unsupported: ${specifier}`);
        } else entry = subpath || (mode === 'import' ? pkg.module : undefined) || pkg.main || 'index.js';
        const resolved = path.posix.normalize(path.posix.join(packageRoot, entry!));
        if (resolved !== packageRoot && !resolved.startsWith(packageRoot + '/')) throw new Error(`Package target escapes its package: ${specifier}`);
        return this.resolveFile(resolved, mode);
      }
      if (directory === '.') break;
      directory = path.posix.dirname(directory);
    }
    throw new Error(`Dependency is not present inside the selected artifact: ${specifier}. Select a root that contains its node_modules, or supply an independent implementation.`);
  }
  private condition(value: unknown, mode: 'import' | 'require'): string | null | undefined {
    if (value === null) return null;
    if (typeof value === 'string') return value;
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [name, target] of Object.entries(value)) if ([mode, 'node', 'default'].includes(name)) {
        const selected = this.condition(target, mode); if (selected !== undefined) return selected;
      }
    }
    return undefined;
  }
  private async resolveFile(candidate: string, mode: 'import' | 'require', seen = new Set<string>()): Promise<string> {
    if (seen.has(candidate)) throw new Error(`Circular package main: ${candidate}`);
    seen.add(candidate);
    const tryFiles = async (files: string[]) => {
      for (const file of files) {
        if (!js.test(file) && !file.endsWith('.json')) continue;
        try { await this.read(file); return file; } catch (error) {
          if (!['ENOENT', 'ENOTDIR'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
        }
      }
    };
    // Node resolves a file before attempting a directory's package main/index.
    const exact = await tryFiles([candidate, candidate + '.js', candidate + '.mjs', candidate + '.cjs', candidate + '.json']);
    if (exact) return exact;
    const metadata = await this.optionalText(candidate + '/package.json');
    if (metadata !== undefined) {
      const pkg = JSON.parse(metadata); const main = mode === 'import' ? pkg.module || pkg.main : pkg.main;
      if (typeof main === 'string') {
        const target = path.posix.normalize(path.posix.join(candidate, main));
        if (target !== candidate && !target.startsWith(candidate + '/')) throw new Error(`Package main escapes directory: ${candidate}`);
        if (target !== candidate) try { return await this.resolveFile(target, mode, seen); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
      }
    }
    const index = await tryFiles([candidate + '/index.js', candidate + '/index.mjs', candidate + '/index.cjs', candidate + '/index.json']);
    if (index) return index;
    throw missing(candidate);
  }
}
