import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {contrast,contrastInputs} from '../dist/contrast.js';
async function fixture(t,code,args=[3],expected=6){
 const root=await mkdtemp(path.join(tmpdir(),'carve-contrast-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const app=path.join(root,'app');await mkdir(app);await writeFile(path.join(app,'index.mjs'),code);
 const feature=path.join(root,'feature.json');await writeFile(feature,JSON.stringify({schema:'carve/feature@1',title:'format',description:'format input',
  target:{path:app},steps:['Use format'],acceptance:['Expected result'],searchTerms:['format'],examples:[{name:'example',args,expected}]}));
 return {app,feature};
}
test('ambiguous candidates produce concrete questions without guessing an answer or changing the feature',async t=>{
 const {app,feature}=await fixture(t,'export const formatA=x=>x*2;export const formatB=x=>x+3;');
 const before=await readFile(feature,'utf8');
 const result=await contrast(app,{feature,execute:true,maxProbes:6});
 assert.equal(result.status,'needs-observation');assert.equal(result.automaticSelection,false);
 assert.ok(result.questions.length>0);assert.equal(result.questions[0].expected,'unknown');
 assert.equal(result.questions[0].alternatives.length,2);assert.equal(result.questions[0].inputOrigin,'generated-boundary-probe');
 assert.equal(await readFile(feature,'utf8'),before);assert.equal(result.comparisons.length,2);
 assert.ok(result.comparisons.every(c=>c.observations.every(o=>o.consistentWithExtracted)));
});
test('equivalent object outputs with different property orders do not create a false question',async t=>{
 const {app,feature}=await fixture(t,'export const formatA=x=>({a:x,b:2});export const formatB=x=>({b:2,a:x});',[3],{a:3,b:2});
 const result=await contrast(app,{feature,execute:true,maxProbes:2});
 assert.equal(result.status,'no-difference-found');assert.deepEqual(result.questions,[]);
});
test('explicit additional inputs can distinguish behavior outside generated boundaries',async t=>{
 const {app,feature}=await fixture(t,`export const formatA=x=>x==='magic'?'A':x;export const formatB=x=>x==='magic'?'B':x;`,['abc'],'abc');
 const result=await contrast(app,{feature,execute:true,inputs:[{name:'special word',args:['magic']}]});
 assert.equal(result.status,'needs-observation');assert.equal(result.questions[0].inputOrigin,'user-supplied-probe');
 assert.deepEqual(result.questions[0].args,['magic']);
 assert.deepEqual(result.questions[0].alternatives.map(a=>a.outcome.value),['A','B']);
});
test('contrast requires execution authorization and bounded input budgets',async t=>{
 const {app,feature}=await fixture(t,'export const formatA=x=>x*2;export const formatB=x=>x+3;');
 await assert.rejects(()=>contrast(app,{feature,execute:false}),/--execute/);
 await assert.rejects(()=>contrast(app,{feature,execute:true,maxProbes:25}),/1–24/);
});
test('boundary generation is deterministic, deduplicated, bounded and preserves seed objects',()=>{
 const seeds=[[{text:'A,B',rows:[{value:3}],enabled:true}],['hello']];const before=JSON.stringify(seeds);
 const result=contrastInputs(seeds,12);
 assert.deepEqual(result,contrastInputs(seeds,12));assert.equal(result.length,12);
 assert.equal(new Set(result.map(r=>JSON.stringify(r.args))).size,result.length);assert.equal(JSON.stringify(seeds),before);
 assert.ok(result.some(r=>r.args[0]===''));
});
