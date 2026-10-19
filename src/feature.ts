import { z } from 'zod';
import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { digest } from './artifact.js';

export const exampleSchema = z.object({
  name: z.string().min(1).max(200), args: z.array(z.unknown()), expected: z.unknown().optional(),
  expectedError: z.object({ name: z.string().min(1), message: z.string().optional() }).optional(),
  origin: z.enum(['user-provided', 'observed-original', 'hypothesis']).default('user-provided'),
  evidence: z.string().optional()
}).superRefine((value, ctx) => {
  if (Object.hasOwn(value, 'expected') === Boolean(value.expectedError)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Specify exactly one expected value or expectedError.' });
  if (value.origin === 'observed-original' && !value.evidence) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'An original observation needs an evidence reference.' });
});
export const featureSchema = z.object({
  schema: z.literal('carve/feature@1'), title: z.string().min(1).max(160), description: z.string().min(1).max(8000),
  target: z.object({ path: z.string().min(1), file: z.string().optional() }).optional(),
  steps: z.array(z.string().min(1)).max(30).default([]),
  searchTerms: z.array(z.string().min(1).max(100)).max(40).default([]),
  acceptance: z.array(z.string().min(1)).max(40).default([]),
  exclusions: z.array(z.string().min(1)).max(40).default([]),
  examples: z.array(exampleSchema).max(200).default([])
}).superRefine((value, ctx) => {
  const names = value.examples.map(item => item.name);
  if (new Set(names).size !== names.length) ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Example names must be unique.' });
});
export type Feature = z.infer<typeof featureSchema>;

export function assessFeature(value: unknown) {
  const feature = featureSchema.parse(value);
  const missing = [];
  if (!feature.target) missing.push('target: locate the application or artifact');
  if (!feature.steps.length) missing.push('steps: describe where/how the original feature is used');
  if (!feature.examples.length) missing.push('examples: supply concrete arguments and expected results');
  if (!feature.acceptance.length) missing.push('acceptance: state which behavior must be retained');
  return { feature, status: missing.length ? 'draft' as const : 'ready-for-probe' as const, missing,
    semanticMatch: 'unconfirmed' as const, note: 'A complete specification defines a task; it does not prove that any implementation matches it.' };
}

export async function readFeature(file: string) {
  if ((await stat(file)).size > 1024 * 1024) throw new Error('Feature specification exceeds 1 MiB.');
  const text = await readFile(file, 'utf8');
  return { ...assessFeature(JSON.parse(text)), sha256: digest(text), text };
}

export function featurePrompt(feature: Feature, featurePath: string) {
  return `Use Carve to extract this local capability.\n\nGoal: ${feature.title}\n${feature.description}\n\nSpecification: ${featurePath}\nTarget: ${feature.target?.path ?? 'not yet located'}\nOriginal operations:\n${feature.steps.map(s => '- ' + s).join('\n') || '- not yet supplied'}\nAcceptance:\n${feature.acceptance.map(s => '- ' + s).join('\n') || '- not yet supplied'}\nExclusions:\n${feature.exclusions.map(s => '- ' + s).join('\n') || '- not yet supplied'}\n\nRead the specification and distinguish observed examples from hypotheses. Use carve_discover (or carve discover TARGET --feature SPEC) to find evidence-backed candidates; a ranking is not semantic confirmation. Use REA when lexical evidence is insufficient. If multiple candidates pass, use carve_contrast (or carve contrast TARGET --feature SPEC --execute) for concrete distinguishing inputs. Its candidate outputs are questions, not expected UI behavior; add an example only after user confirmation or observing the requested original operation. Inspect and plan candidate declarations before extraction. Compare against the original on the specified cases, including meaningful boundaries and errors. Do not treat function-name similarity, matching unexpected errors or a successful build as confirmation. Preserve unknowns. Report the independent output, its dependencies, the tested behavior and any unverified behavior.\n`;
}

export async function createFeature(description: string, out: string, target?: string) {
  const assessment = assessFeature({ schema: 'carve/feature@1', title: description.slice(0, 160), description,
    ...(target ? { target: { path: target } } : {}), steps: [], searchTerms: [], acceptance: [], exclusions: [], examples: [] });
  const destination = path.resolve(out);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, JSON.stringify(assessment.feature, null, 2) + '\n', { flag: 'wx' });
  return { path: destination, ...assessment, agentPrompt: featurePrompt(assessment.feature, destination) };
}
