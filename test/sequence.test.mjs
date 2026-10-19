import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {extract} from '../dist/extract.js';
import {invoke,invokeSequence,packageUsage} from '../dist/runtime.js';
import {sequenceCalls,sequenceOutcome} from '../dist/sequence.js';
import {survey,queryIndex,openIndex,hashFile} from '../dist/survey.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {digest} from '../dist/artifact.js';
import {addCapability,getCapability} from '../dist/library.js';
import {verificationResponse,readVerificationArchive} from '../dist/verification-archive.js';
import {saveVerificationReport,readVerificationSummary} from '../dist/verification-receipt.js';
import {readPackage} from '../dist/package.js';
const cli=path.resolve('dist/cli.js'),ok=value=>({kind:'return',value});
const code=`let n=7;export async function counter(op,amount=0){if(op==='add')n=(n+amount)|0;if(op==='set')n=amount;if(op==='throw'){n++;throw new RangeError('after increment');}await Promise.resolve();return n;}`;
async function fixture(t,reconstruction=false,implementation=code){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-sequence-test-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const source=path.join(root,'implementation.mjs'),pkg=path.join(root,'package');await writeFile(source,implementation);
 if(!reconstruction){await extract(source,{selector:{kind:'export',name:'counter'},out:pkg});return{root,source,pkg};}
 const input=path.join(root,'test.dex'),workspace=path.join(root,'work');await writeFile(input,Buffer.from('dex\n035\0synthetic-sequence-fixture'));await survey(input,{workspace});
 const evidence=path.join(root,'evidence.txt');await writeFile(evidence,'Synthetic sequence validator fixture; not native decompilation or execution.');const id=digest('synthetic-sequence-test-row');
 const db=openIndex(workspace);db.exec('CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);CREATE VIRTUAL TABLE observation_search USING fts5(id UNINDEXED,content);');
 db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,'test.dex',(await queryIndex(workspace)).items[0].sha256,'java-class','Synthetic.java','Synthetic.java','unit counter',JSON.stringify({pseudocode:'synthetic test only',provider:{name:'synthetic-test-only'},pseudocodeTruncated:false}),evidence,(await hashFile(evidence)).sha256);db.prepare('INSERT INTO observation_search VALUES(?,?)').run(id,'unit counter');db.close();
 const contract=path.join(root,'contract.json');await writeFile(contract,JSON.stringify({schema:'carve/reconstruction@1',goal:'Synthetic stateful counter protocol test',file:'test.dex',evidenceIds:[id],behavior:{description:'Sequence protocol tests only',inputDomain:'counter operations',outputDomain:'int32'},dependencies:[],unknowns:['This fixture does not execute the original DEX.']}));
 await reconstruct(workspace,{contract,implementation:source,export:'counter',out:pkg});
 const harness=path.join(root,'reference.mjs');await writeFile(harness,`let s='';for await(const b of process.stdin)s+=b;${code.replace('export ','')}const results=[];for(const args of JSON.parse(s)){try{results.push({kind:'return',value:await counter(...args)});}catch(error){results.push({kind:'throw',error:{name:error.name,message:error.message}})}}console.log(JSON.stringify(results));`);
 const cases=path.join(root,'cases.json'),reference=path.join(root,'reference.json'),config={schema:'carve/reference@3',command:[process.execPath,harness],mode:'json-sequence-stdin',scope:'external-harness',description:'Synthetic Node stateful protocol fixture, does not execute the DEX',boundFiles:[harness]};
 const data={schema:'carve/sequence-cases@1',cases:[{name:'accumulate and throw',steps:[{args:['get'],expected:7},{args:['add',5],expected:12},{args:['throw']},{args:['get'],expected:13}]},{name:'fresh next sequence',steps:[{args:['get'],expected:7},{args:['set',-9],expected:-9},{args:['add',4],expected:-5}]}]};
 await writeFile(cases,JSON.stringify(data));await writeFile(reference,JSON.stringify(config));return{root,source,pkg,workspace,cases,reference,harness,config,data,options:{package:pkg,cases,reference,execute:true}};
}
test('sequence shares one module, awaits calls, snapshots returned objects and starts fresh next time',async t=>{
 const f=await fixture(t);const calls=[['get'],['add',5],['throw'],['get']];
 const expected=[ok(7),ok(12),{kind:'throw',error:{name:'RangeError',message:'after increment'}},ok(13)];
 for(let n=0;n<2;n++)assert.deepEqual(await invokeSequence(f.pkg,calls,{execute:true}),ok(expected));
 assert.deepEqual(await invoke(f.pkg,['get'],{execute:true}),ok(7));
 const g=await fixture(t,false,'const item={n:0};export function counter(){item.n++;return item}');assert.deepEqual(await invokeSequence(g.pkg,[[],[]],{execute:true}),ok([ok({n:1}),ok({n:2})]));
});
test('sequence validates finite bounded inputs and exact per-step protocol without fabricating target errors',async t=>{
 const f=await fixture(t);await assert.rejects(()=>invokeSequence(f.pkg,[[]],{execute:false}),/--execute/);
 for(const value of [[],new Array(65).fill([]),[1],[[NaN]],[[undefined]],[[{a:Infinity}]],[[1n]],[[()=>1]],[[Symbol('x')]],[["x".repeat(1048577)]]])assert.throws(()=>sequenceCalls(value));
 for(const value of [[ok(1)],Array(3).fill(ok(1)),[{},{}],[{kind:'return'},ok(1)],[{kind:'harness-error',detail:'bad'},ok(1)],[ok(NaN),ok(1)]])assert.equal(sequenceOutcome(ok(value),2).kind,'harness-error');
 assert.deepEqual(sequenceOutcome(ok([ok(null),{kind:'throw',error:{name:'TypeError',message:'x'}}]),2).value[0],ok(null));
});
test('whole-sequence deadlines, cancellation, serialization and output limits fail explicitly',async t=>{
 const f=await fixture(t,false,'export function counter(){while(true){}}');assert.match((await invokeSequence(f.pkg,[[]],{execute:true,timeoutMs:100})).detail,/timed out/);
 const controller=new AbortController(),pending=invokeSequence(f.pkg,[[]],{execute:true,timeoutMs:3000,signal:controller.signal});setTimeout(()=>controller.abort(),100);assert.match((await pending).detail,/cancelled/);
 const g=await fixture(t,false,'export const counter=()=>"x".repeat(1100000)');assert.match((await invokeSequence(g.pkg,[[]],{execute:true})).detail,/exceeded 1 MiB/);
 const h=await fixture(t,false,'export const counter=()=>undefined');assert.match((await invokeSequence(h.pkg,[[]],{execute:true})).detail,/serialization/);
 await writeFile(path.join(f.pkg,'index.mjs'),'tampered');await assert.rejects(()=>invokeSequence(f.pkg,[[]],{execute:true}),/Package changed/);
});
test('sequence CLI and both independent MCP modes preserve order and enforce workspace roots',async t=>{
 const f=await fixture(t);const calls=[['add',2],['add',3],['get']];assert.deepEqual(JSON.parse(execFileSync(process.execPath,[cli,'invoke-sequence',f.pkg,'--calls',JSON.stringify(calls),'--execute'],{encoding:'utf8'})),ok([ok(9),ok(12),ok(12)]));
 const client=new Client({name:'sequence-main',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 for(let i=0;i<2;i++){const r=await client.callTool({name:'carve_invoke_sequence',arguments:{package:'package',calls,execute:true}});assert.equal(r.isError,undefined);assert.deepEqual(r.structuredContent,{value:[ok(9),ok(12),ok(12)]});}
 const denied=await client.callTool({name:'carve_invoke_sequence',arguments:{package:path.dirname(f.root),calls:[[]],execute:true}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
 const standalone=new Client({name:'sequence-tool',version:'1'});await standalone.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve-tool',f.pkg,'--execute'],stderr:'pipe'}));t.after(()=>standalone.close());
 assert.deepEqual((await standalone.callTool({name:'capability_sequence',arguments:{calls}})).structuredContent,{value:[ok(9),ok(12),ok(12)]});
});
test('stateful verification compares all steps, archives details and preserves whole examples through library import',async t=>{
 const f=await fixture(t,true),r=await verifyReconstruction(f.workspace,f.options);assert.equal(r.status,'passed-supplied-cases');assert.equal(r.total,2);assert.equal(r.totalSteps,7);assert.equal(r.passedSteps,7);assert.equal(r.verifiedScope,'declared-external-harness-sequences');assert.equal(r.candidateEnvironment.stepsShareModuleInstance,true);assert.equal(r.results[0].steps[2].original.kind,'throw');
 const compact=await verificationResponse(f.workspace,r);assert.equal(compact.totalSteps,7);assert.equal(compact.comparisonMode,'stateful-sequences');const step=await readVerificationArchive(f.workspace,{id:compact.id,view:'case',caseIndex:0,field:'steps',item:3});assert.equal(JSON.parse(step.text).original.value,13);
 const usage=await packageUsage(f.pkg);assert.equal(usage.example,null);assert.deepEqual(usage.exampleSequence.calls,f.data.cases[0].steps.map(s=>s.args));assert.ok(usage.commands.sequence.includes('invoke-sequence'));
 const stored=await addCapability(f.pkg,{library:path.join(f.root,'functions'),name:'stateful-counter'});await rm(f.pkg,{recursive:true});await rm(f.source);await rm(f.harness);
 const got=await getCapability(path.join(f.root,'functions'),'stateful-counter');assert.equal(got.usage.example,null);assert.deepEqual(got.usage.exampleSequence,usage.exampleSequence);assert.equal(got.usage.verification.source.scope,'declared-external-harness-sequences');assert.deepEqual(await invokeSequence(stored.package,usage.exampleSequence.calls,{execute:true}),ok(usage.exampleSequence.outcomes));
});
test('sequence comparison catches reset-per-call implementations, wrong expectations and malformed original protocols',async t=>{
 const f=await fixture(t,true,'export function counter(op,amount=0){let n=7;if(op===\'add\')n+=amount;return n}');let r=await verifyReconstruction(f.workspace,f.options);assert.equal(r.status,'failed');assert.equal(r.results[0].steps[3].passed,false);
 const g=await fixture(t,true);g.data.cases[0].steps[1].expected=999;await writeFile(g.cases,JSON.stringify(g.data));r=await verifyReconstruction(g.workspace,g.options);assert.equal(r.results[0].steps[1].passed,false);
 for(const program of ['console.log(JSON.stringify([]))','console.log(JSON.stringify([1,2,3,4]))','console.log(1);process.exit(2)','process.stdout.write("1e999")']){await writeFile(g.harness,program);r=await verifyReconstruction(g.workspace,g.options);assert.equal(r.status,'failed');assert.equal(r.results[0].original.kind,'harness-error');assert.equal(r.passedSteps,0);}
});
test('sequence configuration rejects mixed modes, duplicate names, bounds and forged target-cli scope before execution',async t=>{
 const f=await fixture(t,true);await assert.rejects(()=>verifyReconstruction(f.workspace,{...f.options,execute:false}),/--execute/);
 await writeFile(f.cases,JSON.stringify([{name:'legacy',args:[]}]));await assert.rejects(()=>verifyReconstruction(f.workspace,f.options));
 for(const data of [{...f.data,cases:[f.data.cases[0],f.data.cases[0]]},{...f.data,cases:[{name:'too many',steps:Array(65).fill({args:[]})}]},{...f.data,cases:Array.from({length:16},(_,i)=>({name:String(i),steps:Array(64).fill({args:[]})}))}]){await writeFile(f.cases,JSON.stringify(data));await assert.rejects(()=>verifyReconstruction(f.workspace,f.options));}
 await writeFile(f.cases,JSON.stringify(f.data));await writeFile(f.reference,JSON.stringify({...f.config,scope:'target-cli'}));await assert.rejects(()=>verifyReconstruction(f.workspace,f.options),/selected indexed binary/);
});
test('sequence original-bound bytes changed during execution invalidate the comparison',async t=>{
 const f=await fixture(t,true),file=path.join(f.root,'bound.txt');await writeFile(file,'before');await writeFile(f.reference,JSON.stringify({...f.config,boundFiles:[f.harness,file]}));await writeFile(f.harness,`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(file)},'changed');console.log('[]');`);await assert.rejects(()=>verifyReconstruction(f.workspace,f.options),/bound bytes changed/);
});
test('large stateful receipts retain whole bounded sequences and no misleading independent example',async t=>{
 const f=await fixture(t,true),pkg=await readPackage(f.pkg),calls=[['get'],['add',1]],outcomes=[ok(7),ok(8)],large='x'.repeat(600000),report={schema:'carve/reconstruction-verification@1',manifestSha256:pkg.manifestSha256,status:'passed-supplied-cases',checkedAt:new Date().toISOString(),verifiedScope:'declared-external-harness-sequences',comparisonMode:'stateful-sequences',passed:2,total:2,totalSteps:3,passedSteps:3,results:[{name:'small',calls,passed:true,original:ok(outcomes),candidate:ok(outcomes)},{name:'large',calls:[[]],passed:true,original:ok([ok(large)]),candidate:ok([ok(large)])}]};
 await saveVerificationReport(f.pkg,report);const preview=await readVerificationSummary(f.pkg,pkg.manifestSha256);assert.equal(preview.example,undefined);assert.deepEqual(preview.exampleSequence.calls,calls);const usage=await packageUsage(f.pkg);assert.equal(usage.verification.totalSteps,3);assert.equal(usage.example,null);assert.ok(Buffer.byteLength(JSON.stringify(usage))<10000);
 const stored=await addCapability(f.pkg,{library:path.join(f.root,'functions'),name:'large-stateful'});assert.deepEqual((await packageUsage(stored.package)).exampleSequence.calls,calls);
});
