import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,readFile,writeFile,rm,symlink} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,openIndex} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';
import {buildPe} from './fixtures/pe-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
import {reconstructionContract,bindReconstruction,assertReconstructionBinding} from '../dist/reconstruction-contract.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {readPackage} from '../dist/package.js';
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
const seal=r=>{const {evidence_id,subject,...rest}=r;r.evidence_id='ev_'+digest(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));};
async function fixture(t,{plus=true}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-instruction-review-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const bytes=buildPe({plus,code:()=>Buffer.alloc(64,0xc3)});await writeFile(path.join(input,'app.dll'),bytes);await survey(input,{workspace});
 const fn=await importPeFunction(root,workspace,'app.dll',bytes,{address:plus?'0x140008010':'0x408010'});
 const db=openIndex(workspace,true);let row;try{row=db.prepare('SELECT * FROM observations WHERE id=?').get(fn.observationId);}finally{db.close();}
 const snapshot=JSON.parse(await readFile(row.evidence,'utf8')),info=JSON.parse(snapshot.records.find(r=>r.role==='info').json),p=info.normalized_result;
 const record=structuredClone(info);record.operation='read_function_instructions';record.normalized_result={procedure:{address:p.entrypoint,name:p.name,classification:p.classification,body:p.body},instructions:Array.from({length:16},(_,i)=>'0x'+(BigInt(p.entrypoint)+BigInt(i)).toString(16)+': RET'),limitations:['Synthetic validator fixture, not actual REA execution.']};record.raw_result={value:structuredClone(record.normalized_result),limitations:[]};seal(record);
 const instructionPath=path.join(workspace,'instructions.json');const save=async()=>{seal(record);await writeFile(instructionPath,JSON.stringify(record));};await save();
 const review={observationId:fn.observationId,instructions:{file:'instructions.json',sha256:digest(await readFile(instructionPath))},inferredSignature:p.signature,difference:'Synthetic declared return differs from the imported inferred prototype; no semantic proof.',abi:{convention:'windows-x64',parameters:[{name:'state',location:'rcx',type:'uint32',description:'Caller state'}],result:{location:'eax',type:'uint32'}},bytes:[{address:p.entrypoint,length:16,sha256:digest(Buffer.alloc(16,0xc3))}]};
 const raw={schema:'carve/reconstruction@2',goal:'Review original instructions and ABI declarations',primary:'app',artifacts:[{key:'app',file:'app.dll',evidenceIds:[fn.observationId],instructionReviews:[review]}],relationships:[],behavior:{description:'Synthetic example',inputDomain:'JSON integer',outputDomain:'JSON integer'},dependencies:[],unknowns:[]};
 await writeFile(path.join(root,'implementation.mjs'),'export const value=x=>x;');
 const run=async(value=raw,name='package')=>{const contract=path.join(root,name+'-contract.json');await writeFile(contract,JSON.stringify(value));return reconstruct(workspace,{contract,implementation:path.join(root,'implementation.mjs'),export:'value',out:path.join(root,name)});};
 return {root,workspace,input,record,review,raw,run,save,instructionPath};
}
test('instruction review pins original bytes, inferred prototype and declared ABI while remaining unverified',async t=>{
 const f=await fixture(t),result=await f.run(),pkg=await readPackage(result.out),r=pkg.manifest.reconstruction.artifacts[0].instructionReviews[0];
 assert.equal(result.status,'packaged-with-unknowns');assert.equal(result.unverifiedInstructionReviews.length,1);assert.equal(r.bytes[0].hex,'c3'.repeat(16));assert.equal(r.bytes[0].instructions.length,16);assert.equal(r.instructions.evidenceId,f.record.evidence_id);assert.equal(r.inferredSignature,f.review.inferredSignature);assert.equal(r.abi.result.location,'eax');assert.equal(r.verification,'not-run');assert.match(r.authority,/agent declarations/);
 const bound=await bindReconstruction(f.workspace,reconstructionContract.parse(f.raw));assertReconstructionBinding(pkg.manifest.reconstruction,bound);r.abi.result.type='pointer';assert.throws(()=>assertReconstructionBinding(pkg.manifest.reconstruction,bound),/bindings/);
 const legacy=structuredClone(f.raw);delete legacy.artifacts[0].instructionReviews;const old=await f.run(legacy,'legacy');assert.equal(Object.hasOwn(old.artifacts[0],'instructionReviews'),false);assert.equal(Object.hasOwn(old,'unverifiedInstructionReviews'),false);
});
test('instruction reviews reject guessed coordinates, wrong byte pins, stale signatures and undeclared observations',async t=>{
 const f=await fixture(t);for(const edit of [r=>r.inferredSignature='void guessed()',r=>r.observationId='0'.repeat(64),r=>r.bytes[0].sha256='0'.repeat(64),r=>r.bytes[0].address='0x140008000',r=>r.bytes[0].length=17]){
  const raw=structuredClone(f.raw);edit(raw.artifacts[0].instructionReviews[0]);await assert.rejects(f.run(raw,'bad'),/signature|declared complete|source SHA256|bounded by listed instructions/);
 }
 const duplicate=structuredClone(f.raw);duplicate.artifacts[0].instructionReviews.push(duplicate.artifacts[0].instructionReviews[0]);await assert.rejects(f.run(duplicate,'duplicate'),/Duplicate/);
});
test('instruction evidence content commitments and exact source/profile/body matches are rechecked',async t=>{
 for(const edit of [r=>r.evidence_id='ev_'+'0'.repeat(64),r=>r.subject.digest.sha256='0'.repeat(64),r=>r.parameters.procedure='0x140008011',r=>r.normalized_result.procedure.body.total_bytes=15,r=>{r.analysis_profile.parameters.analyzer_preset='other';r.analysis_profile.digest=digest(canonical({provider:r.analysis_profile.provider,parameters:r.analysis_profile.parameters}));}]){
  const f=await fixture(t);edit(f.record);if(!f.record.evidence_id.endsWith('0'.repeat(64)))seal(f.record);await writeFile(f.instructionPath,JSON.stringify(f.record));f.review.instructions.sha256=digest(await readFile(f.instructionPath));await assert.rejects(f.run(),/semantic ID|must match|matching function body/);
 }
 const f=await fixture(t);await writeFile(f.instructionPath,'{}');await assert.rejects(f.run(),/SHA256/);
});
test('review schema bounds ABI declarations and refuses external or redirected evidence paths',async t=>{
 const f=await fixture(t);for(const edit of [r=>r.instructions.file='../outside.json',r=>r.bytes[0].length=257,r=>r.abi.parameters.push(r.abi.parameters[0]),r=>r.abi.result={location:'eax',type:'pointer'}]){const raw=structuredClone(f.raw);edit(raw.artifacts[0].instructionReviews[0]);assert.equal(reconstructionContract.safeParse(raw).success,false);}
 const outside=path.join(f.root,'outside.json');await writeFile(outside,await readFile(f.instructionPath));await symlink(outside,path.join(f.workspace,'redirect.json'));f.review.instructions.file='redirect.json';await assert.rejects(f.run(),/without redirects/);
 const x86=await fixture(t,{plus:false});await assert.rejects(x86.run(),/AMD64 PE/);
});
test('fresh MCP uses the same review binding and later changed instruction evidence cannot be rebound',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.root,'contract.json'),JSON.stringify(f.raw));const client=new Client({name:'instruction-review-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve('dist/cli.js'),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const response=await client.callTool({name:'carve_reconstruct',arguments:{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'value',out:'mcp-package'}});assert.ok(!response.isError,response.content[0].text);const result=JSON.parse(response.content[0].text);assert.equal(result.artifacts[0].instructionReviews[0].instructions.sha256,f.review.instructions.sha256);
 await writeFile(f.instructionPath,'changed');await assert.rejects(bindReconstruction(f.workspace,reconstructionContract.parse(f.raw)),/SHA256/);
 await assert.rejects(verifyReconstruction(f.workspace,{package:result.out,cases:'unused',reference:'unused',execute:true}),/SHA256/);
});
