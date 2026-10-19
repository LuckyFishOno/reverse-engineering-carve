import path from 'node:path';
import type { Artifact } from './modules.js';
import { digest } from './artifact.js';

export async function collectNotices(artifact: Artifact, modules: { module: string }[]) {
  const packages = new Map<string, { name: string; version: string | null; declaredLicense: unknown; packageFile: string; files: { source: string; output: string; sha256: string }[] }>();
  const files: Record<string, string> = {};
  for (const item of modules) {
    let directory = path.posix.dirname(item.module);
    while (true) {
      const prefix = directory === '.' ? '' : directory + '/';
      const metadata = await artifact.optionalText(prefix + 'package.json');
      if (metadata !== undefined) {
        if (!packages.has(directory)) {
          const pkg = JSON.parse(metadata);
          const entry = { name: typeof pkg.name === 'string' ? pkg.name : directory, version: typeof pkg.version === 'string' ? pkg.version : null,
            declaredLicense: pkg.license ?? null, packageFile: prefix + 'package.json', files: [] as { source: string; output: string; sha256: string }[] };
          const found = new Set<string>();
          for (const name of ['LICENSE', 'license', 'LICENSE.md', 'license.md', 'LICENSE.txt', 'license.txt', 'LICENCE', 'NOTICE', 'notice', 'NOTICE.md', 'NOTICE.txt']) {
            const group = name.toLowerCase().startsWith('not') ? 'notice' : 'license';
            if (found.has(group)) continue;
            const text = await artifact.optionalText(prefix + name); if (text === undefined) continue;
            found.add(group);
            if (Buffer.byteLength(text) > 1024 * 1024) throw new Error(`License/notice exceeds 1 MiB: ${prefix + name}`);
            const sha256 = digest(text); const slug = entry.name.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 100) || 'source';
            const output = `licenses/${slug}-${sha256.slice(0, 12)}.txt`;
            files[output] = text; entry.files.push({ source: prefix + name, output, sha256 });
            if (Object.keys(files).length > 512) throw new Error('More than 512 license/notice files are required.');
          }
          packages.set(directory, entry);
        }
        break;
      }
      if (directory === '.') break;
      directory = path.posix.dirname(directory);
    }
  }
  return { packages: [...packages.values()], files };
}
