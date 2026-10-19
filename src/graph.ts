import { build } from 'esbuild';
import { analyze, type Selector, type Issue } from './analyze.js';
import { Artifact, portableBuiltins } from './modules.js';
import type { Source } from './artifact.js';

type Analysis = ReturnType<typeof analyze>;
interface ModuleNode {
  source: Source; overview: Analysis;
  bindings: Set<string>; fragments: Map<string, { start: number; end: number; text: string }>;
  exports: Map<string, { local?: string; from?: string; imported?: string }>;
  retained: Map<string, { name: string; start: number; end: number; line: number | null }>;
  capsule: boolean; json?: string;
}
export async function moduleGraph(input: string, file: string | undefined, selector: Selector) {
  const artifact = await Artifact.open(input);
  const entry = await artifact.source(file);
  const nodes = new Map<string, ModuleNode>();
  const issues: (Issue & { module: string })[] = [];
  const edges: { from: string; to: string; imported: string }[] = [];
  const resolved = new Map<string, string>();
  const warnings = new Set<string>();
  const builtins = new Set<string>();
  let requests = 0;
  const attempt = async (module: string, fn: () => Promise<void>) => {
    try { await fn(); } catch (error) { issues.push({ module, code: 'module-resolution', detail: (error as Error).message }); }
  };
  async function node(id: string) {
    const existing = nodes.get(id); if (existing) return existing;
    if (nodes.size >= 256) throw new Error('Module graph exceeds the 256-module limit.');
    let directory = id.includes('/') ? id.slice(0, id.lastIndexOf('/')) : '.';
    while (true) {
      await artifact.optionalText((directory === '.' ? '' : directory + '/') + 'package.json');
      if (directory === '.') break;
      directory = directory.includes('/') ? directory.slice(0, directory.lastIndexOf('/')) : '.';
    }
    let source: Source; let json: string | undefined;
    if (id.endsWith('.json')) {
      const text = await artifact.text(id); JSON.parse(text); json = text;
      source = { target: artifact.target, kind: artifact.kind, module: id, code: `const data=JSON.parse(${JSON.stringify(text)});export {data as default};`,
        sha256: artifact.inputs.get(id)!.sha256, bytes: artifact.inputs.get(id)!.bytes };
    } else source = await artifact.source(id);
    const result: ModuleNode = { source, overview: analyze(source), bindings: new Set(), fragments: new Map(), exports: new Map(), retained: new Map(), capsule: false, json };
    nodes.set(id, result); return result;
  }
  async function resolve(id: string, specifier: string, mode: 'import' | 'require' = 'import') {
    const key = id + '\0' + mode + '\0' + specifier;
    if (!resolved.has(key)) resolved.set(key, await artifact.resolve(id, specifier, mode));
    return resolved.get(key)!;
  }
  async function exportedNames(id: string, seen = new Set<string>()): Promise<string[]> {
    if (seen.has(id)) return []; seen.add(id);
    const item = await node(id);
    const names = new Set(item.overview.commonjs ? item.overview.commonjs.exports.map(e => e.name) : item.overview.exports.map(e => e.name));
    for (const link of item.overview.reexports) {
      if (link.exported !== '*') names.add(link.exported);
      else for (const name of await exportedNames(await resolve(id, link.source), seen)) if (name !== 'default') names.add(name);
    }
    return [...names].sort();
  }
  async function provider(id: string, name: string, seen = new Set<string>()): Promise<boolean> {
    if (seen.has(id)) return false; seen.add(id);
    const item = await node(id);
    if (item.overview.commonjs?.exports.some(e => e.name === name) || item.overview.exports.some(e => e.name === name) || item.overview.reexports.some(e => e.exported === name)) return true;
    if (name === 'default') return false;
    for (const link of item.overview.reexports.filter(e => e.exported === '*')) if (await provider(await resolve(id, link.source), name, new Set(seen))) return true;
    return false;
  }
  async function requestExport(id: string, name: string) {
    const item = await node(id);
    if (item.exports.has(name)) return;
    if (item.overview.commonjs) {
      const direct = item.overview.exports.find(e => e.name === name);
      if (!item.capsule && item.overview.commonjs.declarationExports && direct && !direct.local.startsWith('<commonjs:')) {
        const sliced = analyze(item.source, { kind: 'symbol', name: direct.local }, { imports: 'preserve', values: true, initialization: 'include' });
        if (sliced.plan?.status === 'extractable') {
          item.exports.set(name, { local: direct.local });
          await requestBinding(id, direct.local); return;
        }
      }
      if (!item.overview.commonjs.exports.some(e => e.name === name)) warnings.add(`CommonJS export ${name} in ${id} is a requested runtime property; its presence and callability require behavioral verification.`);
      item.exports.set(name, {});
      await requestCapsule(id); return;
    }
    // Reserve before following cycles; ESM linking will validate the result.
    item.exports.set(name, {});
    const direct = item.overview.exports.find(e => e.name === name);
    if (direct) {
      item.exports.set(name, { local: direct.local });
      await requestBinding(id, direct.local); return;
    }
    const explicit = item.overview.reexports.filter(e => e.exported === name);
    let links = explicit;
    if (!links.length && name !== 'default') {
      links = [];
      for (const link of item.overview.reexports.filter(e => e.exported === '*')) {
        const target = await resolve(id, link.source);
        if (await provider(target, name)) links.push({ ...link, imported: name, exported: name });
      }
    }
    if (links.length !== 1) throw new Error(links.length ? `Ambiguous re-export ${name} in ${id}.` : `Export ${name} does not exist in ${id}.`);
    const link = links[0]!;
    const target = await resolve(id, link.source);
    if (portableBuiltins.has(target)) throw new Error('Direct re-exports of Node builtins require an explicit local wrapper.');
    item.exports.set(name, { from: link.source, imported: link.imported });
    if (link.imported === '*') for (const exported of await exportedNames(target)) await requestExport(target, exported);
    else await requestExport(target, link.imported);
    edges.push({ from: id, to: target, imported: link.imported });
  }
  async function requestCapsule(id: string) {
    const item = await node(id);
    if (item.capsule) return;
    item.capsule = true; // Reserve before following CommonJS cycles.
    const cjs = item.overview.commonjs!;
    for (const issue of cjs.issues) issues.push({ module: id, ...issue });
    warnings.add(`CommonJS module ${id} is retained whole to preserve initialization, export mutation and require order; it is not a minimal declaration slice.`);
    item.retained.set('capsule', { name: '<commonjs-module>', start: 0, end: item.source.code.length, line: 1 });
    for (const dependency of cjs.dependencies) await attempt(id, async () => {
      const target = await resolve(id, dependency.source, 'require');
      edges.push({ from: id, to: target, imported: 'CommonJS require' });
      if (portableBuiltins.has(target)) { builtins.add(target); return; }
      const child = await node(target);
      if (child.overview.commonjs) await requestCapsule(target);
      else if (!target.endsWith('.json')) throw new Error(`CommonJS require() of ESM ${target} is not supported; supply an explicit ESM wrapper.`);
    });
  }
  async function requestBinding(id: string, name: string) {
    const item = await node(id);
    if (item.bindings.has(name)) return;
    if (++requests > 4096) throw new Error('Module graph exceeds 4096 binding requests.');
    item.bindings.add(name);
    const result = analyze(item.source, { kind: 'symbol', name }, { imports: 'preserve', values: true, initialization: 'include' });
    for (const fragment of result.fragments) item.fragments.set(`${fragment.start}:${fragment.end}`, fragment);
    for (const retained of result.plan!.retained) item.retained.set(`${retained.start}:${retained.end}`, retained);
    for (const issue of result.plan!.issues) issues.push({ module: id, ...issue });
    for (const warning of result.plan!.warnings) warnings.add(warning);
    if (item.overview.sideEffectImports.length) warnings.add(`Omitted side-effect imports in ${id}: ${item.overview.sideEffectImports.join(', ')}. Validate their effect on the chosen behavior.`);
    for (const dependency of result.plan!.imports) await attempt(id, async () => {
      const target = await resolve(id, dependency.source);
      edges.push({ from: id, to: target, imported: dependency.imported });
      if (portableBuiltins.has(target)) { builtins.add(target); return; }
      if (dependency.imported === '*') {
        const names = dependency.members ?? await exportedNames(target);
        for (const name of names) await requestExport(target, name);
      } else await requestExport(target, dependency.imported);
    });
  }
  await node(entry.module);
  if (selector.kind === 'symbol') {
    const item = nodes.get(entry.module)!;
    item.exports.set('__carve_selected', { local: selector.name });
    await attempt(entry.module, () => requestBinding(entry.module, selector.name));
  } else await attempt(entry.module, () => requestExport(entry.module, selector.name));
  const moduleList = [...nodes].sort(([a], [b]) => a.localeCompare(b)).map(([id, item]) => ({
    module: id, sha256: item.source.sha256, bytes: item.source.bytes,
    representation: id.endsWith('.json') ? 'json-data' : 'original-source',
    retention: item.capsule ? 'whole-commonjs-module' : 'declaration-closure',
    exports: [...item.exports.keys()], retained: id.endsWith('.json') ? [] : [...item.retained.values()]
  }));
  const issueList = [...new Map(issues.map(i => [JSON.stringify(i), i])).values()];
  const plan = { selector, status: issueList.length ? 'blocked' as const : 'extractable' as const,
    extractionKind: 'source-extraction' as const, modules: moduleList, dependencyEdges: edges,
    runtimeDependencies: [...builtins].sort(), issues: issueList, warnings: [...warnings],
    limits: { modules: 256, bindingRequests: 4096, moduleBytes: 16 * 1024 * 1024, totalInputBytes: 64 * 1024 * 1024 }, verification: { status: 'not-run' } };
  async function bundle() {
    if (plan.status !== 'extractable') throw new Error('Extraction blocked:\n' + issueList.map(i => `${i.module}: ${i.code}: ${i.detail}`).join('\n'));
    const result = await build({ entryPoints: ['carve:entry'], write: false, bundle: true, platform: 'node', format: 'esm',
      target: 'node22', treeShaking: true, charset: 'utf8', legalComments: 'inline', logLevel: 'silent',
      plugins: [{ name: 'carve-admitted-closure', setup(builder) {
        builder.onResolve({ filter: /.*/ }, args => {
          if (args.path === 'carve:entry') return { path: args.path, namespace: 'carve-entry' };
          if (args.namespace === 'carve-entry') return { path: entry.module, namespace: 'carve-module' };
          if (args.namespace === 'carve-builtin-require' && portableBuiltins.has(args.path)) return { path: args.path, external: true };
          const mode = args.kind === 'require-call' ? 'require' : 'import';
          const target = resolved.get(args.importer + '\0' + mode + '\0' + args.path);
          if (target && portableBuiltins.has(target) && mode === 'require') return { path: target, namespace: 'carve-builtin-require' };
          if (!target) return { errors: [{ text: `Unadmitted dependency: ${args.path}` }] };
          return portableBuiltins.has(target) ? { path: target, external: true } : { path: target, namespace: 'carve-module' };
        });
        builder.onLoad({ filter: /.*/, namespace: 'carve-builtin-require' }, args => ({ contents: `import value from ${JSON.stringify(args.path)}; export default value;`, loader: 'js' }));
        builder.onLoad({ filter: /.*/, namespace: 'carve-entry' }, () => ({ contents: `export { ${JSON.stringify(selector.kind === 'export' ? selector.name : '__carve_selected')} as capability } from 'carve:root';`, loader: 'js' }));
        builder.onLoad({ filter: /.*/, namespace: 'carve-module' }, args => {
          const item = nodes.get(args.path); if (!item) return { errors: [{ text: `Unadmitted module: ${args.path}` }] };
          if (item.capsule) {
            let contents = item.source.code;
            // The bundled ESM shim exposes native builtins through .default.
            for (const dependency of [...item.overview.commonjs!.dependencies].sort((a, b) => b.start - a.start)) {
              if (portableBuiltins.has(resolved.get(args.path + '\0require\0' + dependency.source)!)) contents = contents.slice(0, dependency.end) + '.default' + contents.slice(dependency.end);
            }
            return { contents, loader: 'js' };
          }
          if (item.json !== undefined) return { contents: `module.exports = JSON.parse(${JSON.stringify(item.json)});`, loader: 'js' };
          const admitted: { start: number; end: number; text: string }[] = [];
          for (const fragment of [...item.fragments.values()].sort((a, b) => a.start - b.start || b.end - a.end)) {
            if (!admitted.some(outer => outer.start <= fragment.start && outer.end >= fragment.end)) admitted.push(fragment);
          }
          const declarations = admitted.map(f => f.text).join('\n');
          const exports = [...item.exports].map(([name, value]) => value.local
            ? `export { ${value.local} as ${JSON.stringify(name)} };`
            : value.imported === '*' ? `export * as ${JSON.stringify(name)} from ${JSON.stringify(value.from)};`
            : `export { ${JSON.stringify(value.imported)} as ${JSON.stringify(name)} } from ${JSON.stringify(value.from)};`).join('\n');
          return { contents: item.overview.notices + '\n' + item.overview.directives + '\n' + declarations + '\n' + exports, loader: 'js' };
        });
      } }] });
    const code = result.outputFiles[0]!.text;
    const notices = [...new Set([...nodes.values()].map(n => n.overview.notices).filter(n => n && !code.includes(n)))].join('\n');
    return (notices ? notices + '\n' : '') + code;
  }
  return { artifact, source: entry, plan, bundle };
}
