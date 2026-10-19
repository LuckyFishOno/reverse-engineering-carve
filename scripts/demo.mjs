import { mkdir, mkdtemp, writeFile, readFile, rename } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { createPackage } from '@electron/asar';
import { extract } from '../dist/extract.js';
import { verify } from '../dist/verify.js';
import { plan } from '../dist/mcp.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const run = await mkdtemp(path.join(root, 'artifacts', 'demo-'));
const application = path.join(run, 'desktop-app');
await mkdir(path.join(application, 'dist'), { recursive: true });
await build({ entryPoints: [path.join(root, 'examples/desktop-app/main.js')], bundle: true, minify: true,
  format: 'esm', platform: 'node', legalComments: 'inline', outfile: path.join(application, 'dist/main.mjs') });
await writeFile(path.join(application, 'package.json'), JSON.stringify({ name: 'desktop-fixture', type: 'module', main: 'dist/main.mjs' }));
const archive = path.join(run, 'app.asar');
await createPackage(application, archive);
const options = { file: 'dist/main.mjs', selector: { kind: 'export', name: 'formatSize' }, out: path.join(run, 'size-tool') };
const extractionPlan = await plan(archive, options.file, options.selector);
await writeFile(path.join(run, 'plan.json'), JSON.stringify(extractionPlan, null, 2));
await extract(archive, options);
const comparison = await verify(options.out, { cases: path.join(root, 'examples/size-cases.json'), execute: true });
if (comparison.status !== 'passed') throw new Error('Differential comparison failed.');
// Move both original artifacts away before a separate CLI smoke test. The
// generated package must run with no original application at the old paths.
await rename(application, application + '.removed');
await rename(archive, archive + '.removed');
const isolatedResult = execFileSync(process.execPath, [path.join(options.out, 'cli.mjs'), '[1536]'], { cwd: options.out, encoding: 'utf8' }).trim();
if (JSON.parse(isolatedResult) !== '1.5KB') throw new Error('Independent CLI failed.');
const originalBytes = (await readFile(path.join(application + '.removed', 'dist/main.mjs'))).length;
const outputBytes = (await readFile(path.join(options.out, 'index.mjs'))).length;
const report = { fixture: 'Source-owned desktop envelope with real bytes@3.1.2 formatter; not a third-party desktop app.',
  input: 'minified ESM inside ASAR', extractionKind: 'source-extraction', cases: { passed: comparison.passed, total: comparison.total },
  originalPathsRemoved: true, independentCliResult: JSON.parse(isolatedResult), originalBytes, outputBytes, output: options.out };
await writeFile(path.join(run, 'demo-result.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
