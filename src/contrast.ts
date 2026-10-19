import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { probe } from './probe.js';
import { readFeature } from './feature.js';
import { extract } from './extract.js';
import { verify } from './verify.js';
import { digest } from './artifact.js';

type Input = { name: string; args: unknown[] };
/** Deterministic boundary mutations are questions, never expected behavior. */
export function contrastInputs(seeds: unknown[][], limit = 12): Input[] {
  const known = new Set(seeds.map(args => JSON.stringify(args)));
  const inputs: Input[] = [];
  const add = (args: unknown[], reason: string) => {
    const key = JSON.stringify(args);
    if (known.has(key) || inputs.length >= limit) return;
    known.add(key); inputs.push({ name: `contrast-${inputs.length + 1}: ${reason}`, args });
  };
  const replace = (args: unknown[], keys: (string | number)[], value: unknown, reason: string) => {
    const copy = structuredClone(args); let parent: any = copy;
    for (const key of keys.slice(0, -1)) parent = parent[key];
    // defineProperty also treats a JSON __proto__ field as data.
    Object.defineProperty(parent, keys.at(-1)!, { value, writable: true, configurable: true, enumerable: true });
    add(copy, reason);
  };
  const leaves: { args: unknown[]; keys: (string | number)[]; values: unknown[]; reason: string }[] = [];
  let visited = 0;
  const visit = (args: unknown[], value: unknown, keys: (string | number)[]) => {
    if (++visited > 200 || keys.length > 5) return;
    if (typeof value === 'string') leaves.push({ args, keys, values: ['', ' ', value + ',quoted', value + '"quote', value + '\nline', value.toUpperCase()], reason: 'text boundary' });
    else if (typeof value === 'number') leaves.push({ args, keys, values: [0, -1, 1, value + 1, value - 1, 0.5, 1024], reason: 'numeric boundary' });
    else if (typeof value === 'boolean') leaves.push({ args, keys, values: [!value], reason: 'boolean option' });
    else if (value === null) leaves.push({ args, keys, values: ['', 0], reason: 'null boundary' });
    else if (Array.isArray(value)) {
      for (let i = 0; i < Math.min(value.length, 8); i++) visit(args, value[i], [...keys, i]);
      leaves.push({ args, keys, values: [[], value.slice(0, 1), [...value, ...value.slice(0, 1)]], reason: 'collection boundary' });
    } else if (value && typeof value === 'object') {
      for (const key of Object.keys(value).slice(0, 12)) visit(args, (value as Record<string, unknown>)[key], [...keys, key]);
      leaves.push({ args, keys, values: [{}, null], reason: 'object boundary' });
    }
  };
  for (const args of seeds) for (let i = 0; i < args.length; i++) visit(args, args[i], [i]);
  // Round-robin across input fields/seeds so one string cannot consume the budget.
  for (let round = 0; round < 7 && inputs.length < limit; round++) for (const item of leaves) {
    if (round < item.values.length) replace(item.args, item.keys, item.values[round], item.reason);
  }
  return inputs;
}

export async function contrast(input: string, options: { feature: string; execute: boolean; file?: string; evidence?: string;
  maxCandidates?: number; timeoutMs?: number; maxProbes?: number; inputs?: Input[] }) {
  if (!options.execute) throw new Error('Contrast executes trusted code with additional inputs. Pass --execute.');
  const limit = options.maxProbes ?? 12;
  if (!Number.isInteger(limit) || limit < 1 || limit > 24) throw new Error('Contrast uses 1–24 additional inputs.');
  const supplied = options.inputs;
  if (supplied && (!Array.isArray(supplied) || supplied.length > limit || supplied.length < 1
    || supplied.some(i => !i || typeof i.name !== 'string' || !i.name || !Array.isArray(i.args))
    || new Set(supplied.map(i => i.name)).size !== supplied.length)) throw new Error('Supply 1–maxProbes uniquely named additional inputs with args arrays.');
  const feature = await readFeature(options.feature);
  const result = await probe(input, { ...options, maxCandidates: options.maxCandidates ?? 3 });
  if (result.featureSha256 !== feature.sha256) throw new Error('Feature changed during contrast.');
  const candidates = result.results.filter(r => r.status === 'matches-supplied-examples').map(r => r.candidate);
  const base = { schema: 'carve/contrast@1', target: result.target, featureSha256: feature.sha256,
    semanticMatch: 'unconfirmed', automaticSelection: false, probeStatus: result.status,
    candidateScope: 'passing-candidates-in-tested-lexical-shortlist', candidates };
  if (candidates.length < 2) return { ...base, status: 'not-ambiguous', questions: [], comparisons: [],
    nextAction: 'Use probe/run for the current result. Contrast requires at least two passing candidates.' };
  const inputs = supplied ?? contrastInputs(feature.feature.examples.map(e => e.args), limit);
  if (Buffer.byteLength(JSON.stringify(inputs)) > 1024 * 1024) throw new Error('Contrast inputs exceed 1 MiB.');
  const temp = await mkdtemp(path.join(tmpdir(), 'carve-contrast-'));
  const comparisons: { candidateId: string; status: string; error?: string; manifestSha256?: string; referenceSha256?: string;
    observations?: { name: string; args: unknown[]; outcome: unknown; consistentWithExtracted: boolean }[] }[] = [];
  try {
    const cases = path.join(temp, 'cases.json');
    const baseline = feature.feature.examples.map((e, i) => ({ ...e, name: `baseline-${i + 1}` }));
    const tests = inputs.map((i, n) => ({ name: `additional-${n + 1}`, args: i.args }));
    for (const candidate of candidates) {
      try {
        const out = path.join(temp, candidate.id);
        const extracted = await extract(input, { file: candidate.module, selector: candidate.selector, out, feature: options.feature, evidence: options.evidence });
        if (extracted.manifest.source.sha256 !== candidate.sourceSha256 || extracted.manifest.feature?.sha256 !== feature.sha256) throw new Error('Source or feature changed since discovery.');
        const allTests = [...baseline, ...tests];
        const reports = [];
        for (let offset = 0; offset < allTests.length; offset += 200) {
          await writeFile(cases, JSON.stringify(allTests.slice(offset, offset + 200)));
          reports.push(await verify(out, { execute: true, cases, timeoutMs: options.timeoutMs }));
        }
        const checked = reports[0]!;
        const results = reports.flatMap(r => r.results);
        if (results.slice(0, baseline.length).some(r => !r.passed)) throw new Error('Candidate no longer matches the baseline examples.');
        const observations = results.slice(baseline.length).map((r, i) => ({ name: inputs[i]!.name, args: r.args, outcome: r.original,
          consistentWithExtracted: r.original.kind !== 'harness-error' && isDeepStrictEqual(r.original, r.candidate) }));
        comparisons.push({ candidateId: candidate.id, status: 'observed', manifestSha256: checked.manifestSha256, referenceSha256: checked.referenceSha256, observations });
      } catch (error) { comparisons.push({ candidateId: candidate.id, status: 'unavailable', error: (error as Error).message }); }
    }
  } finally { await rm(temp, { recursive: true, force: true }); }
  const comparable = comparisons.length >= 2 && comparisons.every(c => c.status === 'observed');
  const questions = comparable ? inputs.flatMap((item, index) => {
    const groups: { outcome: unknown; candidateIds: string[] }[] = [];
    for (const candidate of comparisons) {
      const observation = candidate.observations![index]!;
      if (!observation.consistentWithExtracted) return [];
      let group = groups.find(g => isDeepStrictEqual(g.outcome, observation.outcome));
      if (!group) { group = { outcome: observation.outcome, candidateIds: [] }; groups.push(group); }
      group.candidateIds.push(candidate.candidateId);
    }
    if (groups.length < 2) return [];
    return [{ name: item.name, args: item.args, argsSha256: digest(JSON.stringify(item.args)),
      inputOrigin: supplied ? 'user-supplied-probe' : 'generated-boundary-probe', expected: 'unknown',
      question: 'Which result does the requested feature produce for this input? Observe the original product or confirm the intended behavior.',
      alternatives: groups, distinctOutcomes: groups.length,
      largestRemainingGroup: Math.max(...groups.map(g => g.candidateIds.length)) }];
  }).sort((a, b) => a.largestRemainingGroup - b.largestRemainingGroup || b.distinctOutcomes - a.distinctOutcomes).slice(0, 3) : [];
  return { ...base, status: !comparable ? 'incomplete-observations' : questions.length ? 'needs-observation' : 'no-difference-found',
    inputOrigin: supplied ? 'user-supplied-probe' : 'generated-boundary-probe', inputsTested: inputs.length,
    questions, comparisons,
    coverage: { additionalInputs: inputs.length, fullyComparableInputs: comparable ? inputs.filter((_i, n) => comparisons.every(c => c.observations![n]!.consistentWithExtracted)).length : 0 },
    nextAction: questions.length ? 'Ask about one concrete distinguishing input. Add the user-confirmed or actually observed result to the feature examples, then rerun. Do not select a candidate from generated observations alone.'
      : 'No distinguishing question was established within this bounded input set. Use additional real examples, explicit --inputs, UI/call evidence or a reference harness; do not infer equivalence.',
    limitations: ['Generated inputs may be invalid for the requested UI; observations of candidates are not observations of that UI.',
      'No expected behavior is invented or written into the feature. No candidate is selected automatically.',
      'Each case runs in a fresh process; this does not test stateful interactions.',
      'Only the passing lexical shortlist and bounded additional input set were compared.'] };
}
