import test from 'node:test';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,readFile,writeFile,rm,chmod,symlink} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,openIndex} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';
import {buildPe} from './fixtures/pe-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {preparePeVerification,loadPeVerification,peVerificationSpec} from '../dist/pe-verification-task.js';
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
const seal=r=>{const {evidence_id,subject,...rest}=r;r.evidence_id='ev_'+digest(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));};
async function fixture(t,{plus=true,machineCode=Buffer.alloc(16,0xc3),extraCode=[]}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-instruction-review-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const bytes=buildPe({plus,code:()=>{const code=Buffer.alloc(256,0xc3);machineCode.copy(code,16);for(const part of extraCode)part.bytes.copy(code,part.offset);return code;}});await writeFile(path.join(input,'app.dll'),bytes);await survey(input,{workspace});
 const fn=await importPeFunction(root,workspace,'app.dll',bytes,{address:plus?'0x140008010':'0x408010',length:machineCode.length});
 const db=openIndex(workspace,true);let row;try{row=db.prepare('SELECT * FROM observations WHERE id=?').get(fn.observationId);}finally{db.close();}
 const snapshot=JSON.parse(await readFile(row.evidence,'utf8')),info=JSON.parse(snapshot.records.find(r=>r.role==='info').json),p=info.normalized_result;
 const record=structuredClone(info);record.operation='read_function_instructions';record.normalized_result={procedure:{address:p.entrypoint,name:p.name,classification:p.classification,body:p.body},instructions:Array.from({length:machineCode.length},(_,i)=>'0x'+(BigInt(p.entrypoint)+BigInt(i)).toString(16)+': RET'),limitations:['Synthetic validator fixture, not actual REA execution.']};record.raw_result={value:structuredClone(record.normalized_result),limitations:[]};seal(record);
 const instructionPath=path.join(workspace,'instructions.json');const save=async()=>{seal(record);await writeFile(instructionPath,JSON.stringify(record));};await save();
 const review={observationId:fn.observationId,instructions:{file:'instructions.json',sha256:digest(await readFile(instructionPath))},inferredSignature:p.signature,difference:'Synthetic declared return differs from the imported inferred prototype; no semantic proof.',abi:{convention:'windows-x64',parameters:[{name:'state',location:'rcx',type:'uint32',description:'Caller state'}],result:{location:'eax',type:'uint32'}},bytes:[{address:p.entrypoint,length:machineCode.length,sha256:digest(machineCode)}]};
 const raw={schema:'carve/reconstruction@2',goal:'Review original instructions and ABI declarations',primary:'app',artifacts:[{key:'app',file:'app.dll',evidenceIds:[fn.observationId],instructionReviews:[review]}],relationships:[],behavior:{description:'Synthetic example',inputDomain:'JSON integer',outputDomain:'JSON integer'},dependencies:[],unknowns:[]};
 await writeFile(path.join(root,'implementation.mjs'),'export const value=x=>x;');
 const run=async(value=raw,name='package')=>{const contract=path.join(root,name+'-contract.json');await writeFile(contract,JSON.stringify(value));return reconstruct(workspace,{contract,implementation:path.join(root,'implementation.mjs'),export:'value',out:path.join(root,name)});};
 return {root,workspace,input,bytes,record,review,raw,run,save,instructionPath};
}

async function prepared(t){const f=await fixture(t),pkg=await f.run();const spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:'/not-executed/python',bindings:[{parameter:'state',kind:'uint32',argument:0}]};const specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const out=path.join(f.root,'task'),options={package:pkg.out,spec:specPath,out};return {...f,pkg,spec,specPath,out,options};}
test('reviewed PE task preparation emits a pinned reference and runner without executing Python',async t=>{
 const f=await prepared(t),task=await preparePeVerification(f.workspace,f.options);assert.equal(task.status,'prepared-not-executed');const reference=JSON.parse(await readFile(task.reference)),descriptor=JSON.parse(await readFile(task.task));assert.equal(descriptor.entry,'0x140008010');assert.equal(descriptor.bindings[0].register,'rcx');assert.equal(descriptor.packageManifestSha256.length,64);const loaded=await loadPeVerification(f.workspace,f.pkg.out,reference,{});assert.equal(loaded.mode,'json-stdin');assert.equal(loaded.command[0],f.spec.python);assert.ok(loaded.boundFiles.includes(task.runner));
});
test('prepared tasks reject modified manifests, runner code and policy even with a new file pin',async t=>{
 const f=await prepared(t),task=await preparePeVerification(f.workspace,f.options),reference=JSON.parse(await readFile(task.reference)),original=await readFile(task.task);
 await writeFile(task.task,Buffer.concat([original,Buffer.from(' ')]));await assert.rejects(loadPeVerification(f.workspace,f.pkg.out,reference,{}),/SHA256/);await writeFile(task.task,original);
 const changed=JSON.parse(original);changed.bindings[0].register='r9';await writeFile(task.task,JSON.stringify(changed));reference.taskSha256=digest(await readFile(task.task));await assert.rejects(loadPeVerification(f.workspace,f.pkg.out,reference,{}),/execution policy/);await writeFile(task.task,original);reference.taskSha256=task.taskSha256;
 await writeFile(task.runner,'changed');await assert.rejects(loadPeVerification(f.workspace,f.pkg.out,reference,{}),/runner changed/);
});
test('bindings must match reviewed parameter types, contiguous inputs and declared length buffers',async t=>{
 for(const binding of [{parameter:'state',kind:'bytes',argument:0,maxLength:16},{parameter:'state',kind:'uint32',argument:1},{parameter:'unknown',kind:'uint32',argument:0},{parameter:'state',kind:'length',of:'missing'}]){
  const f=await prepared(t);f.spec.bindings=[binding];await writeFile(f.specPath,JSON.stringify(f.spec));await assert.rejects(preparePeVerification(f.workspace,f.options),/types differ|contiguous|names must match|byte buffer/);
 }
 assert.equal(peVerificationSpec.safeParse({schema:'carve/pe-verification-task@1'}).success,false);
});
test('partial byte reviews cannot become executable tasks and outputs cannot modify the package',async t=>{
 const f=await prepared(t);f.review.bytes[0].length=1;f.review.bytes[0].sha256=digest(Buffer.from([0xc3]));const pkg=await f.run(f.raw,'partial');await assert.rejects(preparePeVerification(f.workspace,{...f.options,package:pkg.out}),/every complete/);
 const g=await prepared(t);await assert.rejects(preparePeVerification(g.workspace,{...g.options,out:path.join(g.pkg.out,'nested')}),/outside the candidate/);
});
test('MCP reconstruction exposes optional PE task preparation through the existing tool',async t=>{
 const f=await prepared(t);await writeFile(path.join(f.root,'contract.json'),JSON.stringify(f.raw));const client=new Client({name:'prepare-pe-task',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve('dist/cli.js'),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const response=await client.callTool({name:'carve_reconstruct',arguments:{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'value',out:'mcp-package',verificationTask:{spec:'spec.json',out:'mcp-task'}}});assert.ok(!response.isError,response.content[0].text);assert.equal(JSON.parse(response.content[0].text).verificationTask.status,'prepared-not-executed');
});

test('generated references preserve interpreter alias invocation paths while hashing the actual file',async t=>{
 const f=await prepared(t),actual=path.join(f.root,'mock-python-real'),alias=path.join(f.root,'mock-python-alias');
 // This mock interpreter tests invocation-path semantics only, not original PE execution.
 await writeFile(actual,"#!/bin/sh\ncase ${0##*/} in mock-python-alias) echo 0;; *) exit 9;; esac\n");await chmod(actual,0o700);await symlink(actual,alias);
 f.spec.python=alias;await writeFile(f.specPath,JSON.stringify(f.spec));const task=await preparePeVerification(f.workspace,f.options),cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify([{name:'Mock interpreter invocation',args:[0],expected:0}]));
 const result=await verifyReconstruction(f.workspace,{package:f.pkg.out,cases,reference:task.reference,execute:true});assert.equal(result.status,'passed-supplied-cases');assert.equal(result.reference.command[0],alias);assert.ok(result.reference.boundFiles.some(f=>f.file===actual));
});

test('stateful preparation restricts initializer ABI and non-executable section memory',async t=>{
 const f=await prepared(t);f.spec.sequence={initializers:[[3],[5]],memory:[{address:'0x140001000',length:4,access:'read-write'}]};
 await writeFile(f.specPath,JSON.stringify(f.spec));const task=await preparePeVerification(f.workspace,f.options),reference=JSON.parse(await readFile(task.reference));
 const loaded=await loadPeVerification(f.workspace,f.pkg.out,reference,{});assert.equal(loaded.schema,'carve/reference@3');assert.equal(loaded.mode,'json-sequence-stdin');
 for(const sequence of [{initializers:[[]],memory:[]},{initializers:[],memory:[{address:'0x140008010',length:4,access:'read-write'}]},{initializers:[],memory:[{address:'0x140001000',length:4,access:'read'},{address:'0x140001002',length:4,access:'read-write'}]}]){
  await writeFile(f.specPath,JSON.stringify({...f.spec,sequence}));await assert.rejects(preparePeVerification(f.workspace,{...f.options,out:path.join(f.root,'invalid')}),/argument count|non-executable|overlap/);
 }
});
test('actual owned machine code initializes once, retains state and rejects undeclared writes',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // Actual machine-code execution; imported REA records remain synthetic validator fixtures.
 // mov rax,0x140001000; shl dword [rax],1; add [rax],ecx; mov eax,[rax]; ret
 const machineCode=Buffer.from('48b80010004001000000d12001088b00c3','hex');
 const f=await fixture(t,{machineCode});await writeFile(path.join(f.root,'implementation.mjs'),"let state=11;export const value=n=>state=(2*state+n)>>>0;");const pkg=await f.run();
 const spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'uint32',argument:0}],sequence:{initializers:[[3],[5]],memory:[{address:'0x140001000',length:4,access:'read-write'}]}};
 const specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const options={package:pkg.out,spec:specPath,out:path.join(f.root,'task')},task=await preparePeVerification(f.workspace,options);
 const invoke=(prepared,calls)=>JSON.parse(execFileSync(spec.python,[prepared.runner,prepared.task,prepared.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
 assert.deepEqual(invoke(task,[[1],[2],[0]]),[{kind:'return',value:23},{kind:'return',value:48},{kind:'return',value:96}]);assert.deepEqual(invoke(task,[[0]]),[{kind:'return',value:22}]);
 const reversed={...spec,sequence:{...spec.sequence,initializers:[[5],[3]]}};await writeFile(specPath,JSON.stringify(reversed));const reverseTask=await preparePeVerification(f.workspace,{...options,out:path.join(f.root,'reverse')});assert.deepEqual(invoke(reverseTask,[[0]]),[{kind:'return',value:26}]);await writeFile(specPath,JSON.stringify(spec));
 const cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify({schema:'carve/sequence-cases@1',cases:[{name:'Persistent state',steps:[{args:[1]},{args:[2]},{args:[0]}]},{name:'Independent fresh initialization',steps:[{args:[0]}]}]}));
 const report=await verifyReconstruction(f.workspace,{package:pkg.out,cases,reference:task.reference,execute:true});assert.equal(report.status,'passed-supplied-cases');
 await writeFile(path.join(f.root,'implementation.mjs'),"export const value=n=>22+n;");const mutant=await f.run(f.raw,'mutant');const mutantTask=await preparePeVerification(f.workspace,{...options,package:mutant.out,out:path.join(f.root,'mutant-task')});const failed=await verifyReconstruction(f.workspace,{package:mutant.out,cases,reference:mutantTask.reference,execute:true});assert.notEqual(failed.status,'passed-supplied-cases');
 for(const [label,memory] of [['undeclared',[]],['readonly',[{address:'0x140001000',length:4,access:'read'}]],['adjacent',[{address:'0x140001004',length:4,access:'read-write'}]]]){
  await writeFile(specPath,JSON.stringify({...spec,sequence:{initializers:[],memory}}));const invalid=await preparePeVerification(f.workspace,{...options,out:path.join(f.root,label)});assert.throws(()=>invoke(invalid,[[1]]));
 }
});

async function addReviewed(f,{offset,bytes,parameters=[],result={location:'none',type:'void'}}){
 const address='0x'+(0x140008000n+BigInt(offset)).toString(16),fn=await importPeFunction(f.root,f.workspace,'app.dll',f.bytes,{address,name:'owned_'+offset,length:bytes.length});
 const db=openIndex(f.workspace,true);let row;try{row=db.prepare('SELECT * FROM observations WHERE id=?').get(fn.observationId);}finally{db.close();}
 const snapshot=JSON.parse(await readFile(row.evidence,'utf8')),info=JSON.parse(snapshot.records.find(r=>r.role==='info').json),p=info.normalized_result,record=structuredClone(info);
 record.operation='read_function_instructions';record.normalized_result={procedure:{address:p.entrypoint,name:p.name,classification:p.classification,body:p.body},instructions:Array.from({length:bytes.length},(_,i)=>'0x'+(BigInt(address)+BigInt(i)).toString(16)+': RET'),limitations:['Synthetic validator fixture, not actual REA execution.']};record.raw_result={value:structuredClone(record.normalized_result),limitations:[]};seal(record);
 const file='instructions-'+offset+'.json';await writeFile(path.join(f.workspace,file),JSON.stringify(record));
 const review={observationId:fn.observationId,instructions:{file,sha256:digest(await readFile(path.join(f.workspace,file)))},inferredSignature:p.signature,difference:'Explicit owned fixture ABI, synthetic imported instructions are not semantic proof.',abi:{convention:'windows-x64',parameters,result},bytes:[{address,length:bytes.length,sha256:digest(bytes)}]};
 f.raw.artifacts[0].evidenceIds.push(fn.observationId);f.raw.artifacts[0].instructionReviews.push(review);return review;
}
test('separate void initializer and helper require complete selected instruction reviews',async t=>{
 const init=Buffer.from('48b800100040010000008910c3','hex'),helper=Buffer.from('48b800100040010000000108c3','hex');
 const main=Buffer.from('4883ec28e8470000004883c42848b800100040010000008b00c3','hex');
 const f=await fixture(t,{machineCode:main,extraCode:[{offset:64,bytes:init},{offset:96,bytes:helper}]}),initial=await addReviewed(f,{offset:64,bytes:init,parameters:[{name:'seed',location:'rdx',type:'uint32',description:'Initial counter'}]}),help=await addReviewed(f,{offset:96,bytes:helper,parameters:[{name:'amount',location:'rcx',type:'uint32',description:'Added amount'}]});
 await writeFile(path.join(f.root,'implementation.mjs'),'let state=5;export const value=n=>state=(state+n)>>>0;');const pkg=await f.run();
 const spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON??'/not-executed/python',bindings:[{parameter:'state',kind:'uint32',argument:0}],sequence:{initializers:[{observationId:initial.observationId,args:[3]},{observationId:initial.observationId,args:[5]}],helpers:[help.observationId],memory:[{address:'0x140001000',length:4,access:'read-write'}]}};
 const specPath=path.join(f.root,'spec.json');const prepare=async(value,label,packagePath=pkg.out)=>{await writeFile(specPath,JSON.stringify(value));return preparePeVerification(f.workspace,{package:packagePath,spec:specPath,out:path.join(f.root,label)});};
 const task=await prepare(spec,'separate'),descriptor=JSON.parse(await readFile(task.task));assert.equal(descriptor.initializers[0].bindings[0].register,'rdx');assert.equal(descriptor.initializers[0].abi.result.type,'void');assert.equal(descriptor.helpers[0].entry,'0x140008060');
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,initializers:[{observationId:'f'.repeat(64),args:[]}]}},'unreviewed'),/exact selected/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,initializers:[{observationId:initial.observationId,args:[]}]}},'wrong-arity'),/argument count/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,helpers:[help.observationId,help.observationId]}},'duplicate'),/Duplicate helper/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,helpers:['e'.repeat(64)]}},'missing-helper'),/exact selected/);
 const original=structuredClone(initial.bytes);initial.bytes=[{address:initial.bytes[0].address,length:1,sha256:digest(init.subarray(0,1))}];const partial=await f.run(f.raw,'partial-init');await assert.rejects(prepare(spec,'incomplete-init',partial.out),/every complete/);initial.bytes=original;
 const helperBytes=structuredClone(help.bytes);help.bytes=[{address:help.bytes[0].address,length:1,sha256:digest(helper.subarray(0,1))}];const partialHelper=await f.run(f.raw,'partial-helper');await assert.rejects(prepare(spec,'incomplete-helper',partialHelper.out),/every complete/);help.bytes=helperBytes;
 const oldResult=initial.abi.result;initial.abi.result={location:'rax',type:'pointer'};const pointerInit=await f.run(f.raw,'pointer-init');await assert.rejects(prepare(spec,'invalid-result',pointerInit.out),/void or EAX/);initial.abi.result=oldResult;
 if(process.env.CARVE_PE_PYTHON){
  const invoke=(prepared,calls)=>JSON.parse(execFileSync(spec.python,[prepared.runner,prepared.task,prepared.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
  assert.deepEqual(invoke(task,[[1],[2]]),[{kind:'return',value:6},{kind:'return',value:8}]);assert.deepEqual(invoke(task,[[0]]),[{kind:'return',value:5}]);
  const reverse=await prepare({...spec,sequence:{...spec.sequence,initializers:[...spec.sequence.initializers].reverse()}},'reversed');assert.deepEqual(invoke(reverse,[[1]]),[{kind:'return',value:4}]);
  const noHelpers=await prepare({...spec,sequence:{...spec.sequence,helpers:[]}},'no-helpers');assert.throws(()=>invoke(noHelpers,[[1]]),/Execution escaped/);
  const cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify({schema:'carve/sequence-cases@1',cases:[{name:'Initialized helper updates',steps:[{args:[1]},{args:[2]}]},{name:'Fresh initialization',steps:[{args:[0]}]}]}));const report=await verifyReconstruction(f.workspace,{package:pkg.out,cases,reference:task.reference,execute:true});assert.equal(report.status,'passed-supplied-cases');
  const changed=JSON.parse(await readFile(task.task));changed.initializers[0].entry=descriptor.entry;await writeFile(task.task,JSON.stringify(changed));const reference=JSON.parse(await readFile(task.reference));reference.taskSha256=digest(await readFile(task.task));await assert.rejects(loadPeVerification(f.workspace,pkg.out,reference,{}),/execution policy/);
 }
});

test('sequence buffers expire between calls and cannot be reused through retained image pointers',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // Owned AMD64 stores the first caller pointer in image state, then tries to reuse it.
 const machineCode=Buffer.from('48b80010004001000000488b104885d275074889080fb601c30fb602c3','hex'),f=await fixture(t,{machineCode});
 f.review.abi.parameters[0].type='pointer';const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'bytes',argument:0,maxLength:4}],sequence:{initializers:[],memory:[{address:'0x140001000',length:8,access:'read-write'}]}};
 const specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,'task')});
 const invoke=calls=>JSON.parse(execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
 assert.deepEqual(invoke([[[5]]]),[{kind:'return',value:5}]);assert.throws(()=>invoke([[[5]],[[9]]]),/Invalid memory read/);assert.throws(()=>invoke([[[1,2,3,4,5]]]),/Bounded byte array/);
});

test('predicate boundaries require reviewed identity, initializer-only scope and exact call counts',async t=>{
 // Original predicate returns99; the declared boundary substitutes1 during initialization.
 const boundaryCode=Buffer.from('b863000000c3','hex'),init=Buffer.from('4883ec28e8170000004883c42848ba00100040010000008902c3','hex');
 const main=Buffer.from('85c9750d48b800100040010000008b00c34883ec28e8360000004883c428c3','hex');
 const f=await fixture(t,{machineCode:main,extraCode:[{offset:64,bytes:init},{offset:96,bytes:boundaryCode}]}),initial=await addReviewed(f,{offset:64,bytes:init}),boundary=await addReviewed(f,{offset:96,bytes:boundaryCode,result:{location:'eax',type:'uint32'}}),pkg=await f.run();
 const initialized=Buffer.alloc(4);initialized.writeUInt32LE(1);
 const spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON??'/not-executed/python',bindings:[{parameter:'state',kind:'uint32',argument:0}],sequence:{initializers:[{observationId:initial.observationId,args:[]}],boundaries:[{observationId:boundary.observationId,result:1,phase:'initialization',expectedCalls:1,reason:'Owned synthetic predicate boundary; original return99is not executed.'}],memory:[{address:'0x140001000',length:4,access:'initialize-write',initializedSha256:digest(initialized)}]}};
 const specPath=path.join(f.root,'spec.json'),prepare=async(value,label)=>{await writeFile(specPath,JSON.stringify(value));return preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,label)});};
 const task=await prepare(spec,'predicate'),descriptor=JSON.parse(await readFile(task.task));assert.equal(descriptor.boundaries[0].originalExecution,'not-executed');assert.equal(descriptor.boundaries[0].entry,'0x140008060');
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,helpers:[boundary.observationId]}},'conflict'),/cannot also/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,boundaries:[{...spec.sequence.boundaries[0],observationId:f.review.observationId}]}},'wrong-abi'),/no-argument EAX/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,boundaries:[...spec.sequence.boundaries,...spec.sequence.boundaries]}},'duplicate'),/Duplicate predicate/);
 await assert.rejects(prepare({...spec,sequence:{...spec.sequence,boundaries:[{...spec.sequence.boundaries[0],observationId:'e'.repeat(64)}]}},'missing'),/exact selected/);
 assert.equal(peVerificationSpec.safeParse({...spec,sequence:{...spec.sequence,boundaries:[{...spec.sequence.boundaries[0],result:2}]}}).success,false);
 assert.equal(peVerificationSpec.safeParse({...spec,sequence:{...spec.sequence,boundaries:[{...spec.sequence.boundaries[0],phase:'compute'}]}}).success,false);
 if(process.env.CARVE_PE_PYTHON){
  const invoke=(prepared,calls)=>JSON.parse(execFileSync(spec.python,[prepared.runner,prepared.task,prepared.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
  assert.deepEqual(invoke(task,[[0],[0]]),[{kind:'return',value:1},{kind:'return',value:1}]);assert.throws(()=>invoke(task,[[1]]),/restricted to initialization/);
  for(const [label,changes,pattern] of [['count',{boundaries:[{...spec.sequence.boundaries[0],expectedCalls:2}]},/call count not observed/],['excess',{initializers:[...spec.sequence.initializers,...spec.sequence.initializers]},/call budget exceeded/],['hash',{boundaries:[{...spec.sequence.boundaries[0],result:0}]},/Initialized memory differs/],['missing-call',{initializers:[]},/call count not observed/]]){
   const invalid=await prepare({...spec,sequence:{...spec.sequence,...changes}},label);assert.throws(()=>invoke(invalid,[[0]]),pattern);
  }
  const changed=structuredClone(descriptor);changed.boundaries[0].result=0;await writeFile(task.task,JSON.stringify(changed));const reference=JSON.parse(await readFile(task.reference));reference.taskSha256=digest(await readFile(task.task));await assert.rejects(loadPeVerification(f.workspace,pkg.out,reference,{}),/execution policy/);
 }
});
test('initialization-only memory cannot be written by compared calls',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 const machineCode=Buffer.from('48b8001000400100000001088b00c390','hex'),f=await fixture(t,{machineCode}),pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'uint32',argument:0}],sequence:{initializers:[[3]],memory:[{address:'0x140001000',length:4,access:'initialize-write'}]}};
 const specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,'task')});
 assert.throws(()=>execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:'[[1]]',stdio:['pipe','pipe','pipe']}),/Undeclared memory write/);
});

test('declared caller byte alignment is honored independently of payload length',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // Owned machine code returns RCX modulo8, without reading the caller bytes.
 const f=await fixture(t,{machineCode:Buffer.from('4889c883e007c3','hex')});f.review.abi.parameters[0].type='pointer';const pkg=await f.run(),specPath=path.join(f.root,'spec.json');
 for(let alignment=0;alignment<8;alignment++){
  const spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'bytes',argument:0,maxLength:4096,alignment}],sequence:{initializers:[],memory:[]}};await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,'aligned-'+alignment)});
  const calls=[0,1,7,8,4096].map(length=>[Array(length).fill(0)]),result=JSON.parse(execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());assert.deepEqual(result,calls.map(()=>({kind:'return',value:alignment})));
 }
});

test('output buffers bind pointer ABI and derived capacity without weakening task pins',async t=>{
 const f=await fixture(t);f.review.abi.parameters=[{name:'target',location:'rcx',type:'pointer',description:'Owned output bytes'},{name:'capacity',location:'rdx',type:'uint32',description:'Output capacity'}];const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:'/not-executed/python',bindings:[{parameter:'target',kind:'output-bytes',argument:0,maxLength:16},{parameter:'capacity',kind:'length',of:'target'}]},specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,'task')}),descriptor=JSON.parse(await readFile(task.task));assert.equal(descriptor.policy,'single-function-output-buffers@1');assert.equal(descriptor.bindings[0].register,'rcx');
 descriptor.bindings[0].kind='bytes';await writeFile(task.task,JSON.stringify(descriptor));const reference=JSON.parse(await readFile(task.reference));reference.taskSha256=digest(await readFile(task.task));await assert.rejects(loadPeVerification(f.workspace,pkg.out,reference,{}),/execution policy/);
});
test('owned output writes compare actual bytes, preserve unwritten nulls and isolate calls',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // If capacity>0, write one byte42; return7 regardless of capacity.
 const machineCode=Buffer.from('85d27403c6012ab807000000c3','hex'),f=await fixture(t,{machineCode});f.review.abi.parameters=[{name:'target',location:'rcx',type:'pointer',description:'Output bytes'},{name:'capacity',location:'rdx',type:'uint32',description:'Derived capacity'}];
 await writeFile(path.join(f.root,'implementation.mjs'),"export const value=n=>({returnValue:7,outputs:{target:Array.from({length:n},(_,i)=>i===0?42:null)}});");const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'target',kind:'output-bytes',argument:0,maxLength:16,alignment:3},{parameter:'capacity',kind:'length',of:'target'}],sequence:{initializers:[],memory:[]}},specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const options={package:pkg.out,spec:specPath,out:path.join(f.root,'task')},task=await preparePeVerification(f.workspace,options),invoke=(prepared,calls)=>JSON.parse(execFileSync(spec.python,[prepared.runner,prepared.task,prepared.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
 assert.deepEqual(invoke(task,[[3],[0],[2]]),[{kind:'return',value:{returnValue:7,outputs:{target:[42,null,null]}}},{kind:'return',value:{returnValue:7,outputs:{target:[]}}},{kind:'return',value:{returnValue:7,outputs:{target:[42,null]}}}]);assert.throws(()=>invoke(task,[[17]]),/Bounded output capacity/);assert.throws(()=>invoke(task,[[true]]),/Bounded output capacity/);
 const cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify({schema:'carve/sequence-cases@1',cases:[{name:'Output state is invocation local',steps:[{args:[3]},{args:[0]},{args:[2]}]}]}));const report=await verifyReconstruction(f.workspace,{package:pkg.out,cases,reference:task.reference,execute:true});assert.equal(report.status,'passed-supplied-cases');
 await writeFile(path.join(f.root,'implementation.mjs'),"export const value=n=>({returnValue:7,outputs:{target:Array(n).fill(0)}});");const mutant=await f.run(f.raw,'mutant-output'),mutantTask=await preparePeVerification(f.workspace,{...options,package:mutant.out,out:path.join(f.root,'mutant-task')});const failed=await verifyReconstruction(f.workspace,{package:mutant.out,cases,reference:mutantTask.reference,execute:true});assert.notEqual(failed.status,'passed-supplied-cases');
});
test('output read-before-write and exact-range overrun fail even inside writable page slack',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 for(const [label,hex,pattern] of [['unwritten-read','0fb601c3',/uninitialized stack read/],['overrun','66c7012a00b807000000c3',/Undeclared memory write/],['underflow','c641ff2ab807000000c3',/Undeclared memory write/]]){
  const f=await fixture(t,{machineCode:Buffer.from(hex,'hex')});f.review.abi.parameters[0].type='pointer';const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'output-bytes',argument:0,maxLength:4,alignment:3}]},specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,label)});assert.throws(()=>execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:'[1]',stdio:['pipe','pipe','pipe']}),pattern);
 }
});

test('initialized inout bytes allow read-modify-write and preserve untouched caller bytes',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // Read the first caller byte, increment it, write it back, return the new byte.
 const f=await fixture(t,{machineCode:Buffer.from('0fb60104018801c3','hex')});f.review.abi.parameters=[{name:'target',location:'rcx',type:'pointer',description:'Initialized mutable caller bytes'}];
 await writeFile(path.join(f.root,'implementation.mjs'),"export const value=bytes=>{const target=bytes.slice();target[0]=(target[0]+1)&255;return {returnValue:target[0],outputs:{target}};};");const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'target',kind:'inout-bytes',argument:0,maxLength:16,alignment:3}],sequence:{initializers:[],memory:[]}},specPath=path.join(f.root,'spec.json'),prepare=async(value,label)=>{await writeFile(specPath,JSON.stringify(value));return preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,label)});};
 const task=await prepare(spec,'inout'),invoke=(prepared,calls)=>JSON.parse(execFileSync(spec.python,[prepared.runner,prepared.task,prepared.taskSha256],{input:JSON.stringify(calls),stdio:['pipe','pipe','pipe']}).toString());
 assert.deepEqual(invoke(task,[[[3,0,255]],[[7,8]],[[255,19]]]),[{kind:'return',value:{returnValue:4,outputs:{target:[4,0,255]}}},{kind:'return',value:{returnValue:8,outputs:{target:[8,8]}}},{kind:'return',value:{returnValue:0,outputs:{target:[0,19]}}}]);
 assert.throws(()=>invoke(task,[[[true]]]),/Bounded byte array/);assert.throws(()=>invoke(task,[[Array(17).fill(0)]]),/Bounded byte array/);
 const readonly=await prepare({...spec,bindings:[{...spec.bindings[0],kind:'bytes'}]},'readonly');assert.throws(()=>invoke(readonly,[[[3]]]),/Undeclared memory write|write-protected memory/);
 const pureOutput=await prepare({...spec,bindings:[{...spec.bindings[0],kind:'output-bytes'}]},'pure-output');assert.throws(()=>invoke(pureOutput,[[1]]),/uninitialized stack read/);
 const cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify({schema:'carve/sequence-cases@1',cases:[{name:'Caller initialized contents and fresh buffers',steps:[{args:[[3,0,255]]},{args:[[7,8]]},{args:[[255,19]]}]}]}));const report=await verifyReconstruction(f.workspace,{package:pkg.out,cases,reference:task.reference,execute:true});assert.equal(report.status,'passed-supplied-cases');
 const descriptor=JSON.parse(await readFile(task.task));descriptor.bindings[0].kind='output-bytes';await writeFile(task.task,JSON.stringify(descriptor));const reference=JSON.parse(await readFile(task.reference));reference.taskSha256=digest(await readFile(task.task));await assert.rejects(loadPeVerification(f.workspace,pkg.out,reference,{}),/execution policy/);
});
test('inout buffers retain exact read/write bounds inside mapped alignment slack',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 for(const [label,hex,pattern] of [['read-past','0fb64101c3',/Undeclared memory or uninitialized/],['write-past','c641012ab807000000c3',/Undeclared memory write/],['read-before','0fb641ffc3',/Undeclared memory or uninitialized/]]){
  const f=await fixture(t,{machineCode:Buffer.from(hex,'hex')});f.review.abi.parameters[0].type='pointer';const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'state',kind:'inout-bytes',argument:0,maxLength:4,alignment:3}]},specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,label)});assert.throws(()=>execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:'[[1]]',stdio:['pipe','pipe','pipe']}),pattern);
 }
});

test('one invocation preserves independent readonly, inout and pure-output permissions',{skip:!process.env.CARVE_PE_PYTHON},async t=>{
 // Add readonly source[0] to target[0], then copy the result into pure output[0].
 const f=await fixture(t,{machineCode:Buffer.from('0fb60100020fb602418801c3','hex')});f.review.abi.parameters=[{name:'source',location:'rcx',type:'pointer',description:'Readonly source'},{name:'target',location:'rdx',type:'pointer',description:'Initialized read/write target'},{name:'length',location:'r8',type:'uint64',description:'Derived target length'},{name:'result',location:'r9',type:'pointer',description:'Pure output'}];const pkg=await f.run(),spec={schema:'carve/pe-verification-task@1',artifact:'app',observationId:f.review.observationId,python:process.env.CARVE_PE_PYTHON,bindings:[{parameter:'source',kind:'bytes',argument:0,maxLength:4},{parameter:'target',kind:'inout-bytes',argument:1,maxLength:4},{parameter:'length',kind:'length',of:'target'},{parameter:'result',kind:'output-bytes',argument:2,maxLength:4}]},specPath=path.join(f.root,'spec.json');await writeFile(specPath,JSON.stringify(spec));const task=await preparePeVerification(f.workspace,{package:pkg.out,spec:specPath,out:path.join(f.root,'task')});
 const result=JSON.parse(execFileSync(spec.python,[task.runner,task.task,task.taskSha256],{input:'[[10],[2,3],2]',stdio:['pipe','pipe','pipe']}).toString());assert.deepEqual(result,{returnValue:12,outputs:{target:[12,3],result:[12,null]}});
});
