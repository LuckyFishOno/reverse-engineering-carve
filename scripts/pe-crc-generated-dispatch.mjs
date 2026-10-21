// Generated task integration; original CPU predicate bodies are explicitly replaced, never executed.
import assert from 'node:assert/strict';
import path from 'node:path';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {preparePeVerification} from '../dist/pe-verification-task.js';
const sha=b=>createHash('sha256').update(b).digest('hex');
export async function verifyGeneratedCrcDispatch({out,call,ids,python,expectedTableSha256,cases,save}){
 const contract=JSON.parse(await readFile(path.join(out,'contract.json'),'utf8'));
 contract.goal='Compare original initialized CRC dispatch through generated source-bound tasks';contract.behavior={description:'Unsigned CRC update after original table initialization with a declared CPU predicate',inputDomain:'uint32 state and readonly caller bytes up to4096bytes',outputDomain:'Updated uint32 CRC state; T4/T8 selection is constrained by each task helper allowlist'};
 await save('generated-contract.json',contract);
 await save('generated-reconstruction.json',await call('carve_reconstruct',{workspace:'work',contract:'generated-contract.json',implementation:'implementation.mjs',export:'crcValue',out:'generated-function'}));
 const pointer=value=>{const bytes=Buffer.alloc(8);bytes.writeBigUInt64LE(BigInt(value));return sha(bytes);};
 const specs=[],reports=[],directories=['generated-function'];let steps=0;
 for(const profile of [0,1])for(let alignment=0;alignment<8;alignment++){
  const label=`generated-${profile}-${alignment}`,memory=[{address:'0x6a5c6ba0',length:8192,access:'initialize-write',initializedSha256:expectedTableSha256},{address:'0x6a5c6b88',length:8,access:'initialize-write',initializedSha256:pointer(profile?'0x6a42c5c0':'0x6a42c680')},{address:'0x6a5c8ba0',length:8,access:'initialize-write',initializedSha256:pointer('0x6a42c5c0')},{address:'0x6a5c6b80',length:8,access:'initialize-write',initializedSha256:pointer('0x6a42c680')},{address:'0x6a571c10',length:8,access:'read',initializedSha256:pointer('0x6a42c5c0')},{address:'0x6a571c20',length:8,access:'read',initializedSha256:pointer('0x6a42c680')}];
  const spec={schema:'carve/pe-verification-task@1',artifact:'library',observationId:ids[1],python,bindings:[{parameter:'state',kind:'uint32',argument:0},{parameter:'data',kind:'bytes',argument:1,maxLength:4096,alignment},{parameter:'length',kind:'length',of:'data'}],sequence:{initializers:[{observationId:ids[0],args:[]}],helpers:[ids[profile?2:3]],boundaries:[{observationId:ids[4],result:profile,phase:'initialization',expectedCalls:1,reason:'CPU_Is_InOrder is a declared predicate outcome for this task; original CPU detection instructions are not executed.'}],memory}};
  await save(label+'-spec.json',spec);const task=await preparePeVerification(path.join(out,'work'),{package:path.join(out,'generated-function'),spec:path.join(out,label+'-spec.json'),out:path.join(out,label+'-task')});directories.push(label+'-task');
  const selected=cases.filter(c=>c.args[0]===profile&&c.args[3]===alignment).map(c=>({args:[c.args[1],c.args[2]],...(c.expected?{expected:c.expected.value}:{})}));steps+=selected.length;
  await save(label+'-cases.json',{schema:'carve/sequence-cases@1',cases:[{name:`Declared CPU=${profile}, caller alignment=${alignment}`,steps:selected}]});
  const report=await call('carve_verify_reconstruction',{workspace:'work',package:'generated-function',cases:label+'-cases.json',reference:path.relative(out,task.reference),execute:true,fullReport:true,timeoutMs:10000});await save(label+'-comparison.json',report);assert.equal(report.status,'passed-supplied-cases',JSON.stringify(report.results.find(r=>!r.passed)?.original??report.status).slice(0,4000));assert.equal(report.passed,1);specs.push({label,spec});reports.push({profile,alignment,steps:selected.length,verificationId:report.id});
 }
 // One original dispatcher sequence suffices for each boundary-policy failure.
 const base=specs[0],negative=[];
 const mutations=[['missing-boundary',{boundaries:[]}],['wrong-helper',{helpers:[ids[2]]}],['wrong-profile',{boundaries:[{...base.spec.sequence.boundaries[0],result:1}]}],['missing-init',{initializers:[]}],['wrong-call-count',{boundaries:[{...base.spec.sequence.boundaries[0],expectedCalls:2}]}],['wrong-table',{memory:base.spec.sequence.memory.map((r,i)=>i? r:{...r,initializedSha256:'0'.repeat(64)})}]];
 for(const [label,change] of mutations){
  const spec={...base.spec,sequence:{...base.spec.sequence,...change}};await save(label+'-spec.json',spec);const task=await preparePeVerification(path.join(out,'work'),{package:path.join(out,'generated-function'),spec:path.join(out,label+'-spec.json'),out:path.join(out,label+'-task')});directories.push(label+'-task');
  const report=await call('carve_verify_reconstruction',{workspace:'work',package:'generated-function',cases:base.label+'-cases.json',reference:path.relative(out,task.reference),execute:true,fullReport:true,timeoutMs:10000});await save(label+'-comparison.json',report);assert.notEqual(report.status,'passed-supplied-cases');assert.equal(report.results[0].original.kind,'harness-error');negative.push(label);
 }
 const summary={status:'passed',sequences:reports.length,steps,profiles:[0,1],alignments:[0,1,2,3,4,5,6,7],initializedTableCells:2048,initializedTableSha256:expectedTableSha256,originalCpuPredicateExecuted:false,cpuBoundary:'Reviewed no-argument entry, declared0or1, initialization only, exactly one call',computeMemory:'Initialization-only writable table and pointers; computation writes forbidden',negative,reports};await save('generated-summary.json',summary);
 const files=['generated-contract.json','generated-reconstruction.json','generated-summary.json',...specs.flatMap(({label})=>[label+'-spec.json',label+'-cases.json',label+'-comparison.json']),...negative.flatMap(label=>[label+'-spec.json',label+'-comparison.json'])];return {summary,directories,files};
}
