import { readFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { digest } from './artifact.js';
import type { Artifact } from './modules.js';

async function fileDigest(file: string) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
export async function bindReaEvidence(file: string, artifact: Artifact, modules: { module: string; sha256: string }[]) {
  if ((await stat(file)).size > 64 * 1024 * 1024) throw new Error('REA evidence exceeds 64 MiB. Investigate it directly with REA and omit --evidence, or analyze a smaller artifact.');
  const bytes = await readFile(file); const record = JSON.parse(bytes.toString('utf8'));
  const result = record.normalized_result;
  if (record.operation !== 'analyze_javascript_application' || typeof record.evidence_id !== 'string' || !Array.isArray(result?.graph?.nodes)) {
    throw new Error('Expected a REA analyze_javascript_application Evidence record.');
  }
  if (result.graph.nodes.length > 100_000) throw new Error('REA graph exceeds 100000 nodes.');
  let artifactMatch: 'exact-asar-bytes' | 'module-bytes-only' = 'module-bytes-only';
  if (artifact.kind === 'asar') {
    if (await fileDigest(artifact.target) !== result.root_artifact_sha256) throw new Error('REA evidence is stale or belongs to a different ASAR.');
    artifactMatch = 'exact-asar-bytes';
  }
  const byPath = new Map<string, { nodeId: string; sha256: string }[]>();
  for (const node of result.graph.nodes) {
    if (node.kind !== 'javascript-module') continue;
    for (const observation of node.observations ?? []) {
      const module = observation.properties?.path;
      const sha256 = observation.evidence?.artifact?.sha256 ?? node.identity?.artifact_sha256;
      if (typeof module === 'string' && typeof sha256 === 'string') {
        const values = byPath.get(module) ?? [];
        values.push({ nodeId: node.node_id, sha256 }); byPath.set(module, values);
      }
    }
  }
  const bindings = modules.map(module => {
    const candidates = byPath.get(module.module) ?? [];
    const matches = candidates.filter(c => c.sha256 === module.sha256);
    if (candidates.length && !matches.length) throw new Error(`REA module evidence is stale: ${module.module}.`);
    return { module: module.module, sha256: module.sha256, status: matches.length ? 'byte-matched' : 'not-covered', nodeIds: [...new Set(matches.map(m => m.nodeId))] };
  });
  if (!bindings.some(b => b.status === 'byte-matched')) throw new Error('REA evidence contains no byte-matching source modules for this operation.');
  return { provider: 'rea', evidenceId: record.evidence_id, evidenceSha256: digest(bytes), artifactMatch,
    modules: bindings, semanticMatch: 'unconfirmed',
    limitation: 'Content hashes bind recorded module bytes; Carve does not authenticate REA’s evidence ledger or infer that a candidate implements the requested behavior.' };
}
