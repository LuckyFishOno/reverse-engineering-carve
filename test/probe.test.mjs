import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {probe,runFeature} from '../dist/probe.js';
import {analyze} from '../dist/analyze.js';
import {loadSource} from '../dist/artifact.js';

async function fixture(t,second='x*2'){
 const root=await mkdtemp(path.join(tmpdir(),'carve-probe-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const app=path.join(root,'app');await mkdir(app);
 await writeFile(path.join(app,'index.mjs'),`export function formatA(x){return x*2}export function formatB(x){return ${second}}`);
 const feature=path.join(root,'feature.json');await writeFile(feature,JSON.stringify({schema:'carve/feature@1',title:'format',description:'format a numeric input',target:{path:app},steps:['Use format'],acceptance:['Double the number'],searchTerms:['format'],examples:[{name:'three',args:[3],expected:6}]}));
 return {root,app,feature,out:path.join(root,'tool')};
}
test('export discovery never mistakes function parameters for public exports',async t=>{
 const {app}=await fixture(t);const result=analyze(await loadSource(path.join(app,'index.mjs')));
 assert.deepEqual(result.exports.map(e=>e.name),['formatA','formatB']);
});
test('two matching candidates remain ambiguous and produce no package',async t=>{
 const {app,feature,out}=await fixture(t);
 const result=await runFeature(app,{feature,out,execute:true});
 assert.equal(result.status,'needs-disambiguation');assert.equal(result.probe.status,'ambiguous');
 assert.equal(result.probe.matches.length,2);await assert.rejects(()=>access(out),/ENOENT/);
});
test('behavioral cases disambiguate an observed feature and drive the complete extraction',async t=>{
 const {app,feature,out}=await fixture(t,'x*3');
 const result=await runFeature(app,{feature,out,execute:true});
 assert.equal(result.status,'completed-for-supplied-examples');assert.equal(result.selected.selector.name,'formatA');
 assert.equal(result.probe.results.find(r=>r.candidate.selector.name==='formatB').status,'behavior-mismatch');
 assert.equal(result.verification.total,1);
});
test('probing requires execution opt-in and a positive example',async t=>{
 const {app,feature}=await fixture(t);
 await assert.rejects(()=>probe(app,{feature,execute:false}),/--execute/);
 await writeFile(feature,JSON.stringify({schema:'carve/feature@1',title:'format',description:'format',examples:[{name:'error',args:[],expectedError:{name:'TypeError'}}]}));
 await assert.rejects(()=>probe(app,{feature,execute:true}),/successful input\/output/);
});
