import { mkdtemp, rm, writeFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { discover } from './discover.js';
import { readFeature } from './feature.js';
import { extract } from './extract.js';
import { verify } from './verify.js';
import { Artifact } from './modules.js';
import { packageUsage } from './runtime.js';

export async function probe(input: string, options: { feature: string; execute: boolean; file?: string; evidence?: string; maxCandidates?: number; timeoutMs?: number }) {
  if (!options.execute) throw new Error('Probing executes trusted original and extracted implementations. Pass --execute.');
  const feature = await readFeature(options.feature);
  if (!feature.feature.examples.length) throw new Error('Supply concrete expected behavior in the feature examples before probing.');
  if (!feature.feature.examples.some(e => Object.hasOwn(e, 'expected'))) throw new Error('Supply at least one successful input/output example; errors alone cannot identify a capability.');
  const maxCandidates = options.maxCandidates ?? 5;
  if (!Number.isInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 10) throw new Error('Probe at most 1–10 candidates.');
  const discovery = await discover(input, { feature: options.feature, file: options.file, evidence: options.evidence, limit: maxCandidates });
  const temp = await mkdtemp(path.join(tmpdir(), 'carve-probe-'));
  const results = [];
  try {
    for (const candidate of discovery.candidates) {
      if (candidate.selector.kind === 'symbol') { results.push({ candidate, status: 'requires-reference-harness' as const }); continue; }
      const out = path.join(temp, candidate.id);
      try {
        const current = await (await Artifact.open(input)).source(candidate.module);
        if (current.sha256 !== candidate.sourceSha256) throw new Error('Candidate source changed after discovery.');
        await extract(input, { file: candidate.module, selector: candidate.selector, out, feature: options.feature, evidence: options.evidence });
        const verification = await verify(out, { execute: true, timeoutMs: options.timeoutMs });
        const status = verification.status === 'passed' ? 'matches-supplied-examples' as const
          : verification.results.some(r => r.original.kind === 'harness-error' || r.candidate.kind === 'harness-error') ? 'not-probeable' as const : 'behavior-mismatch' as const;
        results.push({ candidate, status, verification });
      } catch (error) { results.push({ candidate, status: 'blocked' as const, error: (error as Error).message }); }
    }
  } finally { await rm(temp, { recursive: true }); }
  const matches = results.filter(r => r.status === 'matches-supplied-examples').map(r => r.candidate.id);
  return { schema: 'carve/probe@1', target: discovery.target, featureSha256: feature.sha256,
    status: matches.length === 1 ? 'one-tested-match' : matches.length > 1 ? 'ambiguous' : 'no-tested-match',
    semanticMatch: 'tested-examples-only', matches, discovery, results,
    nextAction: matches.length > 1 ? 'Use recarve contrast TARGET --feature SPEC --execute to find a concrete distinguishing question, or gather UI/call evidence. Never choose arbitrarily.'
      : matches.length === 1 ? 'Run extraction and report the match as limited to the supplied examples and tested shortlist.'
      : 'Inspect blocked candidates, add observed technical terms or use REA/reference harnesses. A blocked candidate is not disproved.',
    limitations: ['Only the returned lexical shortlist was probed; other implementations may exist.',
      'Matching supplied examples does not prove the candidate is connected to the original UI action.',
      'Unexported or environment-dependent candidates need a reference harness; blocked candidates are not disproved.'] };
}

export async function runFeature(input: string, options: { feature: string; execute: boolean; out: string; file?: string; evidence?: string; maxCandidates?: number; timeoutMs?: number }) {
  try { await stat(options.out); throw new Error('Output directory already exists; choose a new destination.'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  const result = await probe(input, options);
  if (result.status !== 'one-tested-match') return { status: 'needs-disambiguation', probe: result, out: null };
  const selected = result.results.find(r => r.candidate.id === result.matches[0])!.candidate;
  const feature = await readFeature(options.feature);
  if (feature.sha256 !== result.featureSha256) throw new Error('Feature specification changed during probing.');
  const current = await (await Artifact.open(input)).source(selected.module);
  if (current.sha256 !== selected.sourceSha256) throw new Error('Selected source changed during probing.');
  const extracted = await extract(input, { file: selected.module, selector: selected.selector, out: options.out, feature: options.feature, evidence: options.evidence });
  const verification = await verify(extracted.out, { execute: true, timeoutMs: options.timeoutMs });
  await writeFile(path.join(extracted.out, 'carve.probe.json'), JSON.stringify(result, null, 2) + '\n');
  return { status: verification.status === 'passed' ? 'completed-for-supplied-examples' : 'verification-failed',
    out: extracted.out, selected, verification, probe: result, usage: await packageUsage(extracted.out) };
}
