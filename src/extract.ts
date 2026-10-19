import { mkdir, writeFile, rm, chmod } from 'node:fs/promises';
import path from 'node:path';
import { analyze, type Selector } from './analyze.js';
import { digest } from './artifact.js';
import { moduleGraph } from './graph.js';
import { readFeature } from './feature.js';
import { bindReaEvidence } from './evidence.js';
import { VERSION } from './version.js';
import { collectNotices } from './notices.js';

export const outputCli = `#!/usr/bin/env node
try {
  const options = process.argv.slice(2);
  if (options.includes('--help') || options.includes('-h')) {
    process.stdout.write("Usage: node cli.mjs [--raw] [--out FILE] '[ARGS...]'\\n\\nPass positional function arguments as a JSON array, or pipe the array to stdin.\\n--raw       Emit a returned string without JSON quotes or an extra newline.\\n--out FILE  Write to a new file; existing files are never overwritten.\\n--help      Show help without loading the extracted function.\\n");
  } else {
    let raw = false; let out; let input;
    for (let i = 0; i < options.length; i++) {
      const option = options[i];
      if (option === '--raw') raw = true;
      else if (option === '--out') { out = options[++i]; if (!out || out.startsWith('--')) throw new Error('--out needs a file path.'); }
      else if (option.startsWith('--')) throw new Error('Unknown option: ' + option);
      else if (input === undefined) input = option;
      else throw new Error('Pass exactly one JSON argument array.');
    }
    input ??= await new Promise((resolve, reject) => {
      let text = ''; process.stdin.setEncoding('utf8');
      process.stdin.on('data', chunk => { text += chunk; if (Buffer.byteLength(text) > 1048576) { reject(new Error('Input exceeds 1 MiB')); process.stdin.destroy(); } });
      process.stdin.on('end', () => resolve(text)); process.stdin.on('error', reject);
    });
    if (Buffer.byteLength(input) > 1048576) throw new Error('Input exceeds 1 MiB');
    const args = JSON.parse(input);
    if (!Array.isArray(args)) throw new TypeError('Pass function arguments as a JSON array.');
    const { capability } = await import('./index.mjs');
    const value = await capability(...args);
    const result = JSON.stringify(value, (_key, item) => {
      if (typeof item === 'number' && !Number.isFinite(item)) throw new TypeError('Function returned a non-finite number.');
      return item;
    });
    if (result === undefined) throw new TypeError('Function did not return a JSON value.');
    if (raw && typeof value !== 'string') throw new TypeError('--raw requires a string result.');
    const text = raw ? value : result + '\\n';
    if (out) { const { writeFile } = await import('node:fs/promises'); await writeFile(out, text, { flag: 'wx' }); process.stderr.write('Wrote ' + out + '\\n'); }
    else process.stdout.write(text);
  }
} catch (error) {
  process.stderr.write(JSON.stringify({ error: error.name, message: error.message }) + '\\n');
  process.exitCode = 1;
}
`;

export async function extract(input: string, options: { file?: string; selector: Selector; out: string; feature?: string; evidence?: string }) {
  const graph = await moduleGraph(input, options.file, options.selector);
  const { source, plan } = graph;
  if (plan.status !== 'extractable') throw new Error(`Extraction blocked:\n${plan.issues.map(i => `  ${i.module}: ${i.code}: ${i.detail}`).join('\n')}`);
  // Parse the result again before creating anything. This catches declaration
  // splitting/name collisions and verifies that the portable module is closed.
  const code = await graph.bundle();
  const portable = analyze({ ...source, code, module: 'index.mjs' }, { kind: 'export', name: 'capability' }, { imports: 'preserve', initialization: 'include', receivers: 'internal' });
  if (portable.plan?.status !== 'extractable') throw new Error('Generated module did not pass the dependency closure check: ' + portable.plan?.issues.map(i => i.code + ': ' + i.detail).join('; '));
  const out = path.resolve(options.out);
  const feature = options.feature ? await readFeature(options.feature) : undefined;
  const rea = options.evidence ? await bindReaEvidence(options.evidence, graph.artifact, plan.modules) : null;
  const notices = await collectNotices(graph.artifact, plan.modules);
  await mkdir(path.dirname(out), { recursive: true });
  await mkdir(out); // Exclusive destination: never merge or overwrite a package.
  const name = `carved-${options.selector.name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '') || 'capability'}`;
  const example = feature?.feature.examples.find(e => Object.hasOwn(e, 'expected'));
  const exampleArgs = example ? JSON.stringify(example.args).replaceAll("'", "'\"'\"'") : null;
  const usage = exampleArgs ? `\nExample from the supplied specification (not proof of untested behavior):\n\n\`node cli.mjs '${exampleArgs}'\`\n${typeof example?.expected === 'string' ? `\nRaw text: \`node cli.mjs --raw '${exampleArgs}'\`\n\nSave to a new file: \`node cli.mjs --raw --out result.txt '${exampleArgs}'\`\n` : ''}` : '\nNo argument example was supplied. Inspect the selected function signature before calling it.\n';
  const files: Record<string, string> = {
    'index.mjs': code,
    'cli.mjs': outputCli,
    'package.json': JSON.stringify({ name, version: '0.0.0', private: true, type: 'module', exports: './index.mjs',
      bin: { [name]: './cli.mjs' }, engines: { node: '>=22.19.0' }, license: 'UNLICENSED', dependencies: {} }, null, 2) + '\n',
    'README.md': `# ${name}\n\nExtracted from ${source.module} (${source.sha256}).\n\nRun: \`node cli.mjs '["argument"]'\` or pipe a JSON array to stdin. Use \`node cli.mjs --help\` for raw text and file output.\n${usage}\nWhen Carve is installed, run \`carve use /path/to/this/package\` for actual commands and MCP client configuration. \`carve serve-tool /path/to/this/package --execute\` exposes the capability over stdio MCP.\n\nImport \`capability\` from \`./index.mjs\`. No original application or npm dependencies are required by the generated package. Node.js is required.\n\nThis is source extraction, not an independent rewrite. Original code notices are retained when identified. The generated package is UNLICENSED: determine the input's applicable license before distributing it. Carve's MIT license does not relicense extracted code.\n\nStatic analysis is not behavioral verification. See carve.manifest.json and, after verification, carve.verification.json.\n`
  };
  if (feature) files['carve.feature.json'] = feature.text;
  Object.assign(files, notices.files);
  const manifest = {
    schema: 'carve/manifest@1', toolVersion: VERSION, createdAt: new Date().toISOString(),
    source: { target: source.target, kind: source.kind, module: source.module, sha256: source.sha256, bytes: source.bytes },
    selector: options.selector, extractionKind: plan.extractionKind,
    modules: plan.modules, inputs: [...graph.artifact.inputs.values()], dependencyEdges: plan.dependencyEdges,
    feature: feature ? { file: 'carve.feature.json', sha256: feature.sha256, status: feature.status, semanticMatch: 'unconfirmed' } : null,
    rea,
    licenses: notices.packages,
    output: { entry: 'index.mjs', export: 'capability', cli: 'cli.mjs', externalDependencies: [],
      runtimeDependencies: plan.runtimeDependencies,
      files: Object.entries(files).map(([file, contents]) => ({ file, sha256: digest(contents), bytes: Buffer.byteLength(contents) })) },
    warnings: plan.warnings, verification: { status: 'not-run' }
  };
  files['carve.manifest.json'] = JSON.stringify(manifest, null, 2) + '\n';
  try {
    for (const file of Object.keys(files)) await mkdir(path.dirname(path.join(out, file)), { recursive: true });
    await Promise.all(Object.entries(files).map(([file, contents]) => writeFile(path.join(out, file), contents, { flag: 'wx' })));
    await chmod(path.join(out, 'cli.mjs'), 0o755);
  } catch (error) {
    await rm(out, { recursive: true, force: true });
    throw error;
  }
  return { out, manifest, status: 'extracted', verification: 'not-run', nextAction: 'Run carve use on the output directory for recorded argument examples and MCP configuration.', helpArgv: [process.execPath, path.join(out, 'cli.mjs'), '--help'] };
}
