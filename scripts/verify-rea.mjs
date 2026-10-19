import { mkdir, mkdtemp, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPackage } from '@electron/asar';
import { analyzeWithRea } from '../dist/rea.js';
import { digest } from '../dist/artifact.js';
import { extract } from '../dist/extract.js';
import { verify } from '../dist/verify.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const run = await mkdtemp(path.join(root, 'artifacts', 'rea-'));
const source = path.join(run, 'application'); await mkdir(source);
await writeFile(path.join(source, 'package.json'), JSON.stringify({ name: 'carve-rea-fixture', type: 'module', main: 'main.mjs' }));
await writeFile(path.join(source, 'main.mjs'), 'const unit=1024;export function kilobytes(value){return value/unit}');
const archive = path.join(run, 'app.asar'); await createPackage(source, archive);
const evidence = path.join(run, 'evidence.json');
const result = await analyzeWithRea(archive, evidence, process.argv[2] ?? 'rea');
const contents = await readFile(evidence);
const record = JSON.parse(contents);
if (record.operation !== 'analyze_javascript_application' || !record.normalized_result?.graph || !record.evidence_id) {
  throw new Error('REA returned an unexpected evidence contract.');
}
const out = path.join(run, 'kilobytes-tool');
const extraction = await extract(archive, { file: 'main.mjs', selector: { kind: 'export', name: 'kilobytes' }, out, evidence });
const cases = path.join(run, 'cases.json');
await writeFile(cases, JSON.stringify([{ name: 'unit boundary', args: [1024], expected: 1 }, { name: 'fraction', args: [1536], expected: 1.5 }]));
const comparison = await verify(out, { cases, execute: true });
if (comparison.status !== 'passed') throw new Error('REA-backed extraction failed its comparison.');
const report = { fixture: 'source-owned ASAR', actualReaProcess: true, operation: record.operation,
  evidenceId: record.evidence_id, evidenceSha256: digest(contents), evidenceBytes: result.bytes,
  originalAsarSha256: digest(await readFile(archive)), recordedArtifactSha256: record.normalized_result.root_artifact_sha256,
  format: record.normalized_result.format, output: run,
  byteMatchedModules: extraction.manifest.rea.modules.filter(m => m.status === 'byte-matched').length,
  comparedCases: comparison.total,
  limitation: 'Byte-bound provider evidence and extraction smoke test; does not verify automatic semantic feature discovery.' };
if (report.originalAsarSha256 !== report.recordedArtifactSha256) throw new Error('REA evidence does not match the exact ASAR digest.');
await writeFile(path.join(run, 'integration-result.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
