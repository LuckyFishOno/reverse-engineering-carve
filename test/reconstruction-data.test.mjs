import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {buildPe} from './fixtures/pe-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
import {survey} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';
import {reconstruct} from '../dist/reconstruction.js';
import {readPackage} from '../dist/package.js';
import {reconstructionContract,bindReconstruction,assertReconstructionBinding} from '../dist/reconstruction-contract.js';

async function fixture(t,{writable=false,extraWrite=false}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-reconstruction-data-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const bytes=buildPe({plus:false,code:()=>Buffer.alloc(64,0xc3)}),initial=Buffer.from([2,0,0,0,5,0,0,0,9,0,0,0]);initial.copy(bytes,0x2200);bytes.writeUInt32LE(writable?0xc0000040:0x40000040,0x40+24+224+36);await writeFile(path.join(input,'app.exe'),bytes);await survey(input,{workspace});
 const fn=await importPeFunction(root,workspace,'app.exe',bytes,{address:'0x408010',dataReference:true}),ids=[fn.observationId];
 if(extraWrite)ids.push((await importPeFunction(root,workspace,'app.exe',bytes,{address:'0x408030',dataReference:{target:'0x403000',read:false,write:true}})).observationId);
 const selection={observationId:fn.observationId,sourceAddress:'0x408010',targetAddress:'0x403000',handling:writable?'modeled-state':'embedded-readonly',description:'Reviewed synthetic initial data fixture; no runtime semantics claim.',bytes:{length:12,sha256:digest(initial)}};
 const raw={schema:'carve/reconstruction@2',goal:'Bind reviewed initial data',primary:'app',artifacts:[{key:'app',file:'app.exe',evidenceIds:ids,dataBindings:[selection]}],relationships:[],behavior:{description:'Synthetic validator example',inputDomain:'JSON integer',outputDomain:'JSON integer'},dependencies:[],unknowns:[]};
 const implementation=path.join(root,'implementation.mjs');await writeFile(implementation,'export const value=x=>x;');
 const run=async(value=raw,out='package')=>{const contract=path.join(root,out+'-contract.json');await writeFile(contract,JSON.stringify(value));return reconstruct(workspace,{contract,implementation,export:'value',out:path.join(root,out)});};
 return {root,input,workspace,raw,selection,run,implementation};
}
test('reviewed data prefixes bind exact code references and initial byte hashes into reconstruction provenance',async t=>{
 const f=await fixture(t),result=await f.run(),pkg=await readPackage(result.out),binding=pkg.manifest.reconstruction.artifacts[0].dataBindings[0];
 assert.equal(binding.reference.bytes.hex,'020000000500000009000000');assert.equal(binding.reference.bytes.length,12);assert.equal(binding.reference.bytes.fileOffset,0x2200);assert.equal(binding.reference.bytes.sha256,f.selection.bytes.sha256);assert.equal(binding.verification,'not-run');assert.equal(binding.reference.runtimeValue,'unverified');assert.equal(result.status,'packaged-unverified');
 const contract=reconstructionContract.parse(f.raw),bound=await bindReconstruction(f.workspace,contract);assertReconstructionBinding(pkg.manifest.reconstruction,bound);
 pkg.manifest.reconstruction.artifacts[0].dataBindings[0].handling='modeled-state';assert.throws(()=>assertReconstructionBinding(pkg.manifest.reconstruction,bound),/bindings/);
});
test('writable or selected-written data cannot be embedded as readonly; explicit state handling is retained',async t=>{
 const f=await fixture(t,{writable:true});assert.equal((await f.run()).artifacts[0].dataBindings[0].handling,'modeled-state');
 f.selection.handling='embedded-readonly';await assert.rejects(f.run(f.raw,'invalid'),/readonly/);
 const g=await fixture(t,{extraWrite:true});await assert.rejects(g.run(),/readonly/);
 const h=await fixture(t);h.selection.handling='modeled-state';await assert.rejects(h.run(),/writable target/);
});
test('unresolved selections remain explicit unknowns and legacy contracts gain no default bindings',async t=>{
 const f=await fixture(t);f.selection.handling='unresolved';delete f.selection.bytes;const result=await f.run();assert.equal(result.status,'packaged-with-unknowns');assert.equal(result.unresolvedDataBindings.length,1);assert.equal(result.artifacts[0].dataBindings[0].reference.bytes,null);
 delete f.raw.artifacts[0].dataBindings;const legacy=await f.run(f.raw,'legacy');assert.equal(Object.hasOwn(legacy.artifacts[0],'dataBindings'),false);assert.equal(Object.hasOwn(legacy,'unresolvedDataBindings'),false);
});
test('wrong byte pins, guessed references, duplicate selections and out-of-range extents fail before packaging',async t=>{
 const f=await fixture(t);
 for(const edit of [s=>s.bytes.sha256='0'.repeat(64),s=>s.sourceAddress='0x408011',s=>s.targetAddress='0x403004',s=>s.observationId='0'.repeat(64)]){
  const raw=structuredClone(f.raw);edit(raw.artifacts[0].dataBindings[0]);await assert.rejects(f.run(raw,'bad'),/SHA256|exact imported|declared complete/);
 }
 const duplicate=structuredClone(f.raw);duplicate.artifacts[0].dataBindings.push(duplicate.artifacts[0].dataBindings[0]);await assert.rejects(f.run(duplicate,'duplicate'),/Duplicate/);
 for(const length of [0,65]){const raw=structuredClone(f.raw);raw.artifacts[0].dataBindings[0].bytes.length=length;assert.equal(reconstructionContract.safeParse(raw).success,false);}
 const noBytes=structuredClone(f.raw);delete noBytes.artifacts[0].dataBindings[0].bytes;assert.equal(reconstructionContract.safeParse(noBytes).success,false);
});
test('fresh MCP packages the same data treatment and source changes prevent rebinding',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.root,'contract.json'),JSON.stringify(f.raw));const client=new Client({name:'data-contract-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve('dist/cli.js'),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const response=await client.callTool({name:'carve_reconstruct',arguments:{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'value',out:'mcp-package'}});assert.ok(!response.isError,response.content[0].text);assert.equal(JSON.parse(response.content[0].text).artifacts[0].dataBindings[0].reference.bytes.sha256,f.selection.bytes.sha256);
 const original=await readFile(path.join(f.input,'app.exe'));original[0x2200]^=1;await writeFile(path.join(f.input,'app.exe'),original);await assert.rejects(f.run(f.raw,'changed'),/changed|stale/);
});
