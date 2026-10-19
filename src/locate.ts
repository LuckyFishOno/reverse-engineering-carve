import { realpath, stat, readdir } from 'node:fs/promises';
import path from 'node:path';
import { inventory } from './artifact.js';
import { Artifact } from './modules.js';

const js = /\.(?:[cm]?js|jsx)$/i;
export async function locate(input: string, options: { scanLimit?: number } = {}) {
  const limit = options.scanLimit ?? 20_000;
  if (!Number.isInteger(limit) || limit < 1 || limit > 50_000) throw new Error('Location scan limit must be 1–50000 entries.');
  const target = await realpath(input); const info = await stat(target);
  const candidates: { target: string; kind: string; moduleCount: number; entryHint: string | null; reason: string }[] = [];
  const errors: { path: string; error: string }[] = [];
  let visited = 0; let complete = true; let skippedLinks = 0;
  async function admit(file: string, reason: string) {
    try {
      const listed = await inventory(file);
      const artifact = await Artifact.open(file);
      let entryHint = artifact.defaultEntry ?? null;
      if (!entryHint) {
        const metadata = await artifact.optionalText('package.json');
        if (metadata !== undefined) {
          if (Buffer.byteLength(metadata) > 1024 * 1024) throw new Error('Package metadata exceeds 1 MiB.');
          const pkg = JSON.parse(metadata);
          const hints = [pkg.main, pkg.module].filter((s): s is string => typeof s === 'string');
          for (const hint of hints) {
            const normalized = hint.replace(/^\.\//, '');
            const exact = [normalized, normalized + '.js', normalized + '.cjs', normalized + '.mjs', normalized + '/index.js'].find(f => listed.modules.includes(f));
            if (exact) { entryHint = exact; break; }
          }
        }
      }
      candidates.push({ target: file, kind: listed.kind, moduleCount: listed.modules.length, entryHint, reason });
    } catch (error) { errors.push({ path: file, error: (error as Error).message }); }
  }
  const modules: string[] = []; const archives: string[] = [];
  async function walk(folder: string) {
    let entries;
    try { entries = await readdir(folder, { withFileTypes: true }); }
    catch (error) { errors.push({ path: folder, error: (error as Error).message }); complete = false; return; }
    entries.sort((a, b) => {
      const rank = (name: string) => ['Contents', 'Resources', 'resources', 'app.asar', 'app'].indexOf(name) < 0 ? 10 : ['Contents', 'Resources', 'resources', 'app.asar', 'app'].indexOf(name);
      return rank(a.name) - rank(b.name) || a.name.localeCompare(b.name);
    });
    for (const entry of entries) {
      if (++visited > limit) { complete = false; return; }
      if (entry.isSymbolicLink()) { skippedLinks++; continue; }
      if (['node_modules', '.git'].includes(entry.name) || entry.name.endsWith('.asar.unpacked')) continue;
      const file = path.join(folder, entry.name);
      if (entry.isDirectory()) await walk(file);
      else if (entry.isFile() && entry.name.toLowerCase().endsWith('.asar')) {
        if (archives.length >= 32) { complete = false; errors.push({ path: file, error: 'Archive candidate limit (32) reached; narrow the target.' }); return; }
        archives.push(file);
      }
      else if (entry.isFile() && js.test(entry.name)) modules.push(path.relative(target, file).split(path.sep).join('/'));
      if (visited > limit || archives.length >= 32 && errors.some(e => e.error.startsWith('Archive candidate limit'))) return;
    }
  }
  if (info.isFile()) {
    if (js.test(target) || target.toLowerCase().endsWith('.asar')) await admit(target, 'directly-selected-artifact');
  } else if (info.isDirectory()) {
    await walk(target);
    for (const archive of archives) await admit(archive, 'archive-found-inside-selected-application');
    if (!archives.length && modules.length) {
      // Do not repeat the full scan or silently discard the first scan's gaps.
      let entryHint: string | null = null;
      try {
        const metadata = await (await Artifact.open(target)).optionalText('package.json');
        if (metadata !== undefined && Buffer.byteLength(metadata) <= 1024 * 1024) {
          const pkg = JSON.parse(metadata);
          entryHint = [pkg.main, pkg.module].filter((s): s is string => typeof s === 'string').map(s => s.replace(/^\.\//, '')).find(s => modules.includes(s)) ?? null;
        }
      } catch (error) { errors.push({ path: path.join(target, 'package.json'), error: (error as Error).message }); }
      candidates.push({ target, kind: 'directory', moduleCount: modules.length, entryHint, reason: 'javascript-source-directory' });
    }
  } else throw new Error('Target must be a regular file or directory.');
  complete = complete && !errors.length;
  // An incomplete scan cannot establish that an archive is unique.
  const selected = complete && candidates.length === 1 ? candidates[0]! : null;
  const status = !complete ? 'incomplete-scan' : !candidates.length ? 'unsupported-target' : selected ? 'located' : 'needs-artifact-selection';
  return { schema: 'carve/location@1', target, status, executesTarget: false, selectedTarget: selected?.target ?? null,
    candidates, coverage: { complete, visitedEntries: Math.min(visited, limit), scanLimit: limit, skippedSymlinks: skippedLinks, errors },
    nextAction: selected ? 'Use selectedTarget for discovery/extraction. entryHint is a package entry hint, not a confirmed feature boundary.'
      : candidates.length ? 'Choose an explicit artifact from candidates or complete/narrow the scan. Do not choose a feature from package naming alone.'
      : 'No supported JavaScript or ASAR artifact was found. Native executables are outside automatic extraction; supply JavaScript sources or another supported artifact.',
    limitations: ['Location identifies containers, not the requested feature.', 'Symlinks, node_modules and ASAR-unpacked trees are skipped during discovery; dependencies can still be read inside an explicitly selected artifact.',
      ...(archives.length && modules.length ? ['Loose JavaScript outside archives was also found; select the source directory explicitly if the requested behavior lives there.'] : [])] };
}
