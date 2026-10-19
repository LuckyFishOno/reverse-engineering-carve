import { isDeepStrictEqual } from 'node:util';
import { mkdtemp, readFile, writeFile, cp, rm, realpath, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { digest } from './artifact.js';
import { Artifact } from './modules.js';
import { readFeature } from './feature.js';
import { worker, run } from './execution.js';
import { readPackage } from './package.js';

interface Case { name: string; args: unknown[]; expected?: unknown; expectedError?: { name: string; message?: string } }

export async function verify(packagePath: string, options: { cases?: string; execute: boolean; reference?: string; referenceExport?: string; timeoutMs?: number }) {
  if (!options.execute) throw new Error('Verification executes both implementations. Pass --execute for a trusted target. A temporary directory is not a security sandbox.');
  const timeoutMs = options.timeoutMs ?? 3000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30_000) throw new Error('timeoutMs must be between 50 and 30000.');
  const { root: out, manifestText, manifest, files: expectedFiles } = await readPackage(packagePath);
  const feature = manifest.feature ? await readFeature(path.join(out, 'carve.feature.json')) : undefined;
  if (feature && feature.sha256 !== manifest.feature.sha256) throw new Error('Feature specification changed after extraction.');
  if (!options.cases && !feature) throw new Error('Supply --cases or extract with --feature.');
  const casesText = options.cases ? await readFile(options.cases, 'utf8') : JSON.stringify(feature!.feature.examples);
  if (Buffer.byteLength(casesText) > 1024 * 1024) throw new Error('Cases file exceeds 1 MiB.');
  const cases = JSON.parse(casesText) as Case[];
  if (!Array.isArray(cases) || !cases.length || cases.length > 200) throw new Error('Provide 1 to 200 named cases.');
  const names = new Set<string>();
  for (const item of cases) {
    if (!item || typeof item.name !== 'string' || !item.name || names.has(item.name) || !Array.isArray(item.args)) throw new Error('Each case needs a unique name and an args array.');
    if ('expected' in item && 'expectedError' in item) throw new Error('Use expected or expectedError, not both.');
    if (item.expectedError && (typeof item.expectedError.name !== 'string' || (item.expectedError.message !== undefined && typeof item.expectedError.message !== 'string'))) throw new Error('expectedError requires a string name and optional string message.');
    names.add(item.name);
  }
  const temp = await realpath(await mkdtemp(path.join(tmpdir(), 'carve-verify-')));
  try {
    const candidateRoot = path.join(temp, 'candidate');
    await mkdir(candidateRoot);
    // Only the emitted package is copied. No application files, node_modules,
    // or source checkout are mounted into the candidate working directory.
    for (const file of expectedFiles) await cp(path.join(out, file), path.join(candidateRoot, file), { recursive: false });
    const workerPath = path.join(temp, 'worker.mjs');
    await writeFile(workerPath, worker);
    let reference: string;
    let referenceHash: string;
    if (options.reference) {
      reference = await realpath(options.reference);
      referenceHash = digest(await readFile(reference));
    } else {
      const artifact = await Artifact.open(manifest.source.target);
      const source = await artifact.source(manifest.source.module);
      if (source.sha256 !== manifest.source.sha256) throw new Error('Original source changed after extraction. Extract again or provide an explicit reference harness.');
      for (const input of manifest.inputs ?? []) {
        if (digest(await artifact.read(input.module)) !== input.sha256) throw new Error(`Original source changed after extraction: ${input.module}.`);
      }
      referenceHash = source.sha256;
      if (source.kind === 'asar') {
        const root = path.join(temp, 'reference'); await mkdir(root);
        for (const input of manifest.inputs ?? [{ module: source.module }]) {
          const file = path.join(root, artifact.normalize(input.module));
          await mkdir(path.dirname(file), { recursive: true });
          await writeFile(file, await artifact.read(input.module));
        }
        reference = path.join(root, source.module);
      } else reference = source.kind === 'directory' ? path.join(source.target, source.module) : source.target;
    }
    const referenceExport = options.referenceExport ?? (manifest.selector.kind === 'export' ? manifest.selector.name : undefined);
    if (!referenceExport) throw new Error('A local symbol requires an explicit --reference-export on an exported reference harness.');
    const results = [];
    for (const item of cases) {
      const [original, candidate] = await Promise.all([
        run(workerPath, reference, referenceExport, item.args, path.dirname(reference), timeoutMs),
        run(workerPath, path.join(candidateRoot, 'index.mjs'), 'capability', item.args, candidateRoot, timeoutMs, true)
      ]);
      let passed = isDeepStrictEqual(original, candidate) && original.kind === 'return';
      if ('expected' in item) passed = passed && original.kind === 'return' && isDeepStrictEqual(original.value, item.expected);
      if (item.expectedError) passed = original.kind === 'throw' && candidate.kind === 'throw'
        && isDeepStrictEqual(original.error, candidate.error) && original.error.name === item.expectedError.name
        && (item.expectedError.message === undefined || original.error.message === item.expectedError.message);
      results.push({ name: item.name, args: item.args,
        ...('expected' in item ? { expected: item.expected } : {}),
        ...(item.expectedError ? { expectedError: item.expectedError } : {}), passed, original, candidate });
    }
    const report = {
      schema: 'carve/verification@1', status: results.every(r => r.passed) ? 'passed' : 'failed',
      checkedAt: new Date().toISOString(), manifestSha256: digest(manifestText), referenceSha256: referenceHash,
      referenceExport, casesSha256: digest(casesText), passed: results.filter(r => r.passed).length, total: results.length,
      featureSha256: feature?.sha256 ?? null, featureMatch: feature ? 'tested-examples-only' : 'not-specified',
      candidateEnvironment: { freshDirectory: true, copiedOriginalApplication: false, installedDependencies: false,
        nodePermissionModel: true, allowedReads: 'emitted-package-and-runner-only', securitySandbox: false },
      limitations: ['Only the supplied JSON-input/output cases were compared; equivalence outside these cases is unknown.',
        'The reference runs with user permissions. Candidate execution uses Node permissions for accidental resource dependencies, not a security sandbox for malicious code.',
        'Each case uses a fresh process; cross-call state and application integration are not verified.'], results
    };
    await writeFile(path.join(out, 'carve.verification.json'), JSON.stringify(report, null, 2) + '\n');
    return report;
  } finally { await rm(temp, { recursive: true, force: true }); }
}
