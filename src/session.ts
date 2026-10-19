import path from 'node:path';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { locate } from './locate.js';
import { createFeature } from './feature.js';
import { shellCommand } from './runtime.js';

export async function startTask(input: string, options: { goal: string; out: string }) {
  if (!options.goal.trim() || options.goal.length > 8000) throw new Error('Supply a goal of 1–8000 characters.');
  const location = await locate(input);
  if (location.status === 'unsupported-target') return { status: 'unsupported-target', out: null, location,
    nextAction: location.nextAction };
  const out = path.resolve(options.out); const featureFile = path.join(out, 'feature.json');
  const cli = fileURLToPath(new URL('./cli.js', import.meta.url));
  const target = location.selectedTarget ?? location.target;
  const discover = shellCommand([process.execPath, cli, 'discover', target, '--feature', featureFile]);
  await mkdir(path.dirname(out), { recursive: true }); await mkdir(out);
  try {
    const brief = await createFeature(options.goal, featureFile, target);
    const task = `${brief.agentPrompt}\n## Artifact location\n\nStatus: ${location.status}.\n${location.candidates.map(c => `- ${c.target} (${c.kind}, ${c.moduleCount} JavaScript modules; entry hint: ${c.entryHint ?? 'unknown'})`).join('\n')}\n\nRead locate.json. If the scan is incomplete or artifacts are ambiguous, resolve that first. Entry hints do not identify the feature.\n\n## Agent workflow\n\n1. Inspect the actual operation and invocation boundary. Reuse the user's context. Map observed data to args only after inspecting the signature.\n2. Complete feature.json with actual operation steps, expectations, exclusions and successful/boundary examples. Leave unknowns unknown; do not invent observations.\n3. Discover and inspect candidates. Start with:\n\n\`\`\`sh\n${discover}\n\`\`\`\n\n4. Use probe/run only for trusted code within existing execution authorization. If multiple candidates pass, use contrast and obtain a real distinguishing observation.\n5. Extract into a new package directory and verify the supplied examples.\n6. Run carve use OUTPUT for actual example commands and optional MCP configuration. Deliver the independent package, actual test evidence and limits.\n\nCarve does not contain an LLM and does not automatically run an agent. Give this file to your existing agent.\n`;
    await writeFile(path.join(out, 'TASK.md'), task, { flag: 'wx' });
    await writeFile(path.join(out, 'locate.json'), JSON.stringify(location, null, 2) + '\n', { flag: 'wx' });
    return { schema: 'carve/task@1', status: location.status === 'located' ? 'draft-created' : 'needs-artifact-selection', out,
      task: path.join(out, 'TASK.md'), feature: featureFile, location, missing: brief.missing,
      agentInstruction: `Read ${path.join(out, 'TASK.md')} and complete the capability-extraction task.`,
      nextAction: 'Give TASK.md to your agent. It will investigate the operation, complete the feature specification, find and test candidates, and deliver an independently usable package.' };
  } catch (error) { await rm(out, { recursive: true, force: true }); throw error; }
}
