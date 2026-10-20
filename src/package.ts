import {sequenceExampleSchema} from './sequence.js';
import path from 'node:path';
import { Artifact } from './modules.js';
import { digest } from './artifact.js';
import {z} from 'zod';

export const capabilityName=z.string().regex(/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/).max(63).refine(n=>!['con','prn','aux','nul','com1','com2','com3','com4','com5','com6','com7','com8','com9','lpt1','lpt2','lpt3','lpt4','lpt5','lpt6','lpt7','lpt8','lpt9'].includes(n),'Choose a portable capability name.');
export const capabilityMetadata=z.object({name:capabilityName,title:z.string().min(1).max(160),description:z.string().min(1).max(2000),tags:z.array(z.string().min(1).max(60)).max(20),sourceManifestSha256:z.string().regex(/^[a-f0-9]{64}$/),importedAt:z.string(),example:z.object({args:z.array(z.unknown()),expected:z.unknown().optional(),origin:z.string().optional(),scope:z.string().optional()}).nullable(),exampleSequence:sequenceExampleSchema.nullable().optional(),sourceVerification:z.unknown()}).strict();

/** Validate only the emitted package. The original app is never opened here. */
export async function readPackage(input: string) {
  const artifact = await Artifact.open(input);
  if (artifact.kind !== 'directory') throw new Error('Choose an extracted package directory.');
  const data = await artifact.read('carve.manifest.json');
  if (data.length > 1024 * 1024) throw new Error('Package manifest exceeds 1 MiB.');
  const manifestText = new TextDecoder('utf-8', { fatal: true }).decode(data);
  const manifest = JSON.parse(manifestText);
  const folder=manifest?.schema==='carve/manifest@2'&&manifest.output?.kind==='capability-folder';
  if ((!folder&&manifest?.schema !== 'carve/manifest@1') || manifest.output?.entry !== 'index.mjs' || manifest.output?.export !== 'capability') throw new Error('Unsupported RECarve manifest.');
  if(folder){capabilityMetadata.parse(manifest.library);if(manifest.output.cli!==null)throw new Error('A capability folder has no standalone CLI.');}
  const required = ['README.md', ...(folder?['SKILL.md']:['cli.mjs']), 'index.mjs', 'package.json', ...(manifest.feature ? ['carve.feature.json'] : [])];
  const optional=folder?['carve.source-verification.json']:[];
  if (!Array.isArray(manifest.output.files) || manifest.output.files.length > 1024) throw new Error('Invalid package file inventory.');
  const files: string[] = manifest.output.files.map((f: any) => f?.file);
  if (new Set(files).size !== files.length || required.some(f => !files.includes(f))
    || files.some(f => typeof f !== 'string' || (!required.includes(f) && !optional.includes(f) && !/^licenses\/[a-zA-Z0-9._-]+\.txt$/.test(f)))) throw new Error('Invalid package file inventory.');
  for (const file of manifest.output.files) {
    const contents = await artifact.read(file.file);
    if (digest(contents) !== file.sha256) throw new Error(`Package changed after extraction: ${file.file}. Extract again before using it.`);
  }
  if (manifest.feature && digest(await artifact.read('carve.feature.json')) !== manifest.feature.sha256) throw new Error('Feature specification changed after extraction.');
  return { root: artifact.target, manifest, manifestText, manifestSha256: digest(manifestText), files, artifact,folder,
    entry: path.join(artifact.target, 'index.mjs') };
}
