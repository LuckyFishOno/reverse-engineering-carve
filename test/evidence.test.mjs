import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {createPackage} from '@electron/asar';
import {Artifact} from '../dist/modules.js';
import {digest} from '../dist/artifact.js';
import {bindReaEvidence} from '../dist/evidence.js';

test('evidence content binding preserves its limited authority and rejects stale module/container bytes',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-evidence-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const app=path.join(root,'app');await mkdir(app);const code='export const double=x=>x*2;';await writeFile(path.join(app,'main.mjs'),code);
 const archive=path.join(root,'app.asar');await createPackage(app,archive);
 const artifact=await Artifact.open(archive);const source=await artifact.source('main.mjs');
 // A source-owned contract fixture. Actual provider integration is tested by
 // scripts/verify-rea.mjs; this test makes no claim of ledger authentication.
 const record={operation:'analyze_javascript_application',evidence_id:'fixture-evidence',normalized_result:{
   root_artifact_sha256:digest(await readFile(archive)),graph:{nodes:[{node_id:'fixture-module',kind:'javascript-module',
     identity:{artifact_sha256:source.sha256},observations:[{properties:{path:'main.mjs'}}]}]}}};
 const file=path.join(root,'evidence.json');await writeFile(file,JSON.stringify(record));
 const bound=await bindReaEvidence(file,artifact,[{module:'main.mjs',sha256:source.sha256}]);
 assert.equal(bound.artifactMatch,'exact-asar-bytes');assert.equal(bound.modules[0].status,'byte-matched');
 assert.equal(bound.semanticMatch,'unconfirmed');
 record.normalized_result.graph.nodes[0].identity.artifact_sha256='0'.repeat(64);await writeFile(file,JSON.stringify(record));
 await assert.rejects(()=>bindReaEvidence(file,artifact,[{module:'main.mjs',sha256:source.sha256}]),/module evidence is stale/);
 record.normalized_result.root_artifact_sha256='1'.repeat(64);await writeFile(file,JSON.stringify(record));
 await assert.rejects(()=>bindReaEvidence(file,artifact,[{module:'main.mjs',sha256:source.sha256}]),/different ASAR/);
});
