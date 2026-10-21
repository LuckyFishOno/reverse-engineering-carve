import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
import {survey} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';
import {readPeUi,inspectPeUi} from '../dist/pe-ui.js';
import {linkPeResourceReference,parsedPeResources} from '../dist/pe-resource-links.js';
import {reconstruct} from '../dist/reconstruction.js';

async function fixture(t){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-resource-links-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);const built=buildUiPe({imports:[]}),payload=built.resources.find(r=>r.keys[0]===6),offset=20;
 built.bytes.writeUInt32LE(0x40000040,0x40+24+224+36);await writeFile(path.join(input,'app.exe'),built.bytes);await survey(input,{workspace});
 const target='0x'+(0x400000+0x1000+payload.payloadOffset-0x200+offset).toString(16),fn=await importPeFunction(root,workspace,'app.exe',built.bytes,{address:'0x408010',dataReference:{target,read:true,write:false}});
 const graph=await readPeUi(path.join(input,'app.exe')),resources=parsedPeResources(graph.nodes),resource=resources.find(r=>r.resource[0]===6),prefix=built.bytes.subarray(payload.payloadOffset+offset,payload.payloadOffset+offset+8);
 const binding={observationId:fn.observationId,sourceAddress:'0x408010',targetAddress:target,handling:'embedded-readonly',description:'Reviewed synthetic string-table reference',bytes:{length:8,sha256:digest(prefix)},resource:{path:[6,63,1033],payloadSha256:resource.payloadSha256}};
 const raw={schema:'carve/reconstruction@2',goal:'Retain reviewed resource identity',primary:'app',artifacts:[{key:'app',file:'app.exe',evidenceIds:[fn.observationId],dataBindings:[binding]}],relationships:[],behavior:{description:'Synthetic resource validator',inputDomain:'JSON value',outputDomain:'JSON value'},dependencies:[],unknowns:[]};
 const implementation=path.join(root,'implementation.mjs');await writeFile(implementation,'export const value=x=>x;');
 const run=async(value=raw,out='package')=>{const contract=path.join(root,out+'.json');await writeFile(contract,JSON.stringify(value));return reconstruct(workspace,{contract,implementation,export:'value',out:path.join(root,out)});};
 return {root,workspace,resources,resource,target,fn,binding,raw,run};
}
test('typed direct resource references retain exact path, relative offset and original payload hash in immutable dependency evidence',async t=>{
 const f=await fixture(t),result=await inspectPeUi(f.workspace,{file:'app.exe',view:'dependencies',command:1001,functionIds:[f.fn.observationId],limit:100,budgetBytes:65536}),row=result.items.find(r=>r.kind==='data-reference');
 assert.equal(row.resourceAssociation.status,'inside-parsed-resource-payload');assert.equal(row.resourceAssociation.runtimeUse,'unverified');assert.deepEqual(row.resourceAssociation.matches[0].resource,[6,63,1033]);assert.equal(row.resourceAssociation.matches[0].offsetInPayload,20);assert.equal(row.resourceAssociation.matches[0].payloadSha256,f.resource.payloadSha256);assert.ok(row.nextSteps.some(s=>s.action==='review-resource'));
 const report=JSON.parse(await readFile(result.dependencyEvidence,'utf8'));assert.equal(report.resourceCatalogs[0].resources.length,5);assert.equal(report.resourceCatalogs[0].sourceSha256,result.sourceSha256);
});
test('resource pinning rejects wrong languages/hashes and byte prefixes crossing the payload boundary',async t=>{
 const f=await fixture(t),packaged=await f.run(),reference=packaged.artifacts[0].dataBindings[0].reference;assert.equal(reference.resourceAssociation.matches[0].payloadSha256,f.resource.payloadSha256);assert.equal(reference.bytes.length,8);
 for(const edit of [b=>b.resource.path[2]=1028,b=>b.resource.payloadSha256='0'.repeat(64),b=>b.bytes.length=39]){const raw=structuredClone(f.raw);edit(raw.artifacts[0].dataBindings[0]);await assert.rejects(f.run(raw,'bad'),/exact parsed payload|resource payload boundary/);}
});
test('payload containment keeps ambiguous languages and bounded alternatives without runtime language selection',async t=>{
 const f=await fixture(t),resources=Array.from({length:10},(_,i)=>({...f.resource,id:'language-'+i,resource:[6,63,1000+i]})),reference={sourceSection:{name:'.text'},status:'file-bytes-captured',targetRva:Number(f.resource.rva)+20};
 const r=linkPeResourceReference(reference,resources);assert.equal(r.status,'ambiguous-resource-payload');assert.equal(r.matchesTotal,10);assert.equal(r.matches.length,8);assert.equal(r.matchesTruncated,true);assert.equal(r.runtimeUse,'unverified');
 assert.equal(linkPeResourceReference({...reference,targetRva:Number(f.resource.rva)+Number(f.resource.bytes)},f.resources).status,'no-parsed-payload-match');
 assert.equal(linkPeResourceReference({...reference,status:'ambiguous-section-mapping'},f.resources).status,'unresolved-reference');
});
test('numeric IDs and UI command reuse never imply a resource reference',async t=>{
 const f=await fixture(t);for(const targetRva of [1001,63,0x8000])assert.equal(linkPeResourceReference({sourceSection:{name:'.text'},status:'file-bytes-captured',targetRva},f.resources).matchesTotal,0);
 assert.equal(linkPeResourceReference({targetRva:Number(f.resource.rva)},f.resources).status,'unresolved-reference');
});
