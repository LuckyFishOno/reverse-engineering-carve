// Real third-party internal table-driven CRC function, original instruction evidence and bounded ABI comparison.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtemp,mkdir,readFile,writeFile,copyFile,rename,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
import {runReference} from '../dist/reference.js';
import {parseProjectPlan,analyzeProjectPlan} from '../dist/project-plan.js';
import {createWorkPackage} from '../dist/work-package.js';
import {collectPeBehaviorEvidence} from './pe-behavior-rea.mjs';
import {peInstructionReview} from './pe-instruction-review.mjs';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
const {values:options}=parseArgs({options:{engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')},'rea-install':{type:'string',default:path.join(root,'artifacts/rea-local')},python:{type:'string',default:path.join(root,'artifacts/pe-behavior-venv/bin/python')}}});
const engines=await readEngineConfiguration(path.resolve(options.engines)),python=path.resolve(options.python);
assert.equal((await exec(python,['-c','import unicorn;print(unicorn.__version__)'])).stdout.trim(),'2.1.4');
const relative='Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll',source=path.join(engines.ghidra,relative);
const expectedSha='c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27';
assert.equal((await hashFile(source)).sha256,expectedSha,'This reviewed reconstruction requires the exact shipped DLL');
await mkdir(path.join(root,'artifacts'),{recursive:true});
const out=await mkdtemp(path.join(root,'artifacts/pe-crc-e2e-')),save=(name,data)=>writeFile(path.join(out,name),JSON.stringify(data,null,2)+'\n');
await mkdir(path.join(out,'input'));await copyFile(source,path.join(out,'input/lib7-Zip-JBinding.dll'));
const metadata=await readPeLoader(source);assert.equal(metadata.machine,0x8664);
const entry='0x6a42c4e0';
// Review pins both source bytes and the retained internal COFF symbol; this is not an export.
const symbols=(await exec('xcrun',['llvm-nm',source],{maxBuffer:8*1024*1024})).stdout;
assert.match(symbols,/^6a42c4e0 T CrcUpdateT1$/m);
await writeFile(path.join(out,'symbols.txt'),symbols);
const disassembly=(await exec('xcrun',['llvm-objdump','-d','--start-address='+entry,'--stop-address=0x6a42c509',source])).stdout;
await writeFile(path.join(out,'instructions.txt'),disassembly);
await save('images.json',{schema:'carve/third-party-pe-crc@1',sha256:expectedSha,metadata,entry});
await save('source.json',{path:source,distributionRelativePath:relative,sha256:expectedSha,windowsExecuted:false,jvmExecuted:false});
await copyFile(path.join(root,'examples/pe-crc/original.py'),path.join(out,'original.py'));
await copyFile(path.join(root,'examples/pe-crc/implementation.mjs'),path.join(out,'implementation.mjs'));
const producer=await collectPeBehaviorEvidence(out,{},engines,path.resolve(options['rea-install']),[['lib7-Zip-JBinding.dll',[['crc',entry]]]],{instructions:true});
assert.equal(producer.closed,true);
const client=new Client({name:'third-party-pe-crc',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],cwd:out,stderr:'pipe'});
let diagnostics='';transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-16000);});
const call=async(name,args)=>{const r=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(r.isError)throw Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return JSON.parse(r.content.find(c=>c.type==='text').text);};
const limitations='One internal CrcUpdateT1 function, explicit uint32 state, up to4096caller bytes and caller-provided256uint32table entries. Original AMD64 instructions run under a bounded Unicorn ABI harness. No DLL initialization, original table generation, runtime dispatch, Windows loader/OS/UI, JVM or compression/archive operations. Ghidra inferred a void return and elided computation; reviewed instruction evidence and executable comparisons are required.';
try{
 await client.connect(transport);assert.notEqual(transport.pid,producer.pid);
 await call('carve_reverse',{target:'input',goal:'Reuse one internal table-driven CRC helper with explicit caller inputs',out:'work'});
 const ids=[];for(const record of producer.records){
  const imported=await call('carve_import_rea_native',{workspace:'work',file:record.file,...Object.fromEntries(['code','info','callees','references'].map(role=>[role,path.relative(out,record[role])]))});ids.push(imported.observationId);
 }
 const dependencies=await call('carve_pe_ui',{workspace:'work',file:'lib7-Zip-JBinding.dll',view:'dependencies',entryMode:'selected-functions',functionIds:ids,limit:100,budgetBytes:65536});await save('dependency-boundary.json',dependencies);assert.equal(dependencies.visited,1);
 const pseudo=JSON.parse(await readFile(producer.records[0].code,'utf8'));assert.match(pseudo.normalized_result,/void CrcUpdateT1/);
 const instructionReview=await peInstructionReview(out,metadata,producer.records[0],ids[0],{convention:'windows-x64',parameters:[{name:'state',location:'rcx',type:'uint32',description:'Raw CRC state'},{name:'data',location:'rdx',type:'pointer',description:'Caller bytes'},{name:'length',location:'r8',type:'uint64',description:'Bounded byte count'},{name:'table',location:'r9',type:'pointer',description:'Caller256entry lookup table'}],result:{location:'eax',type:'uint32'}},'Imported inferred prototype/pseudocode omits return value and fourth argument. Reviewed original instructions use R9 table and return uint32 in EAX; semantic acceptance is separate.');
 await save('contract.json',{schema:'carve/reconstruction@2',goal:'Reuse internal table-driven CRC update from reviewed original instructions',primary:'library',artifacts:[{key:'library',file:'lib7-Zip-JBinding.dll',evidenceIds:ids,instructionReviews:[instructionReview]}],relationships:[],behavior:{description:'Unsigned32CRC state updated by each byte and an explicit256entry table',inputDomain:'uint32 state, array of0to4096bytes,256uint32table entries',outputDomain:'Unsigned32updated state; empty input preserves state; invalid inputs throw'},dependencies:[{name:'Input buffer and lookup table',status:'host-required',detail:'Caller provides both arrays. No table is inferred from original initialized memory.'}],unknowns:[limitations,'Caller pointers and dynamic table extent are declared harness inputs, not source-bound readonly data bindings.']});
 await save('pe-task-spec.json',{schema:'carve/pe-verification-task@1',artifact:'library',observationId:ids[0],python,bindings:[{parameter:'state',kind:'uint32',argument:0},{parameter:'data',kind:'bytes',argument:1,maxLength:4096},{parameter:'length',kind:'length',of:'data'},{parameter:'table',kind:'uint32-array',argument:2,length:256}]});
 const reconstruction=await call('carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'crcUpdate',out:'function',verificationTask:{spec:'pe-task-spec.json',out:'generated-task'}});await save('reconstruction.json',reconstruction);assert.equal(reconstruction.verificationTask.status,'prepared-not-executed');
 const table=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=((c>>>1)^((c&1)?0xedb88320:0))>>>0;return c;});
 const cases=[];for(let i=0;i<128;i++)cases.push({name:'Table indices '+i+' and '+(i+128),args:[0,[i,(table[i]^(i+128))&255],table]});
 const digits=Array.from(Buffer.from('123456789'));
 cases.push({name:'Standard CRC check vector in raw-state form',args:[0xffffffff,digits,table],expected:0x340bc6d9});
 for(const state of [0,1,0x7fffffff,0x80000000,0xffffffff])cases.push({name:'Empty state '+state,args:[state,[],table],expected:state});
 let seed=7171;const random=()=>seed=(Math.imul(seed,1664525)+1013904223)>>>0;
 while(cases.length<200){const t=cases.length%3===0?Array(256).fill(0):cases.length%3===1?Array.from({length:256},(_,i)=>i):Array.from({length:256},random),bytes=Array.from({length:cases.length===199?4096:random()%513},()=>random()&255);cases.push({name:'Caller table and bytes '+cases.length,args:[random(),bytes,t]});}
 const traces=[],indices=new Set();for(const row of cases.slice(0,128)){const result=await runReference([python,path.join(out,'original.py'),'--trace'],'json-stdin',row.args,out,3000);assert.equal(result.kind,'return',JSON.stringify(result));for(const index of result.value.trace.tableIndices)indices.add(index);traces.push({name:row.name,...result.value});}assert.equal(indices.size,256);
 const empty=await runReference([python,path.join(out,'original.py'),'--trace'],'json-stdin',[0x80000000,[],table],out,3000);assert.equal(empty.kind,'return');assert.equal(empty.value.trace.emptyBranch,1);assert.equal(empty.value.value,0x80000000);traces.push({name:'Empty branch',...empty.value});await save('original-traces.json',traces);
 const oracle=await runReference([python,'-c','import zlib,json;print((~zlib.crc32(b"123456789"))&0xffffffff)'],'json-stdin',[],out,3000);assert.equal(oracle.kind,'return');assert.equal(oracle.value,0x340bc6d9);await save('standard-vector.json',oracle);assert.deepEqual(JSON.parse(await readFile(path.join(out,'standard-vector.json'),'utf8')),oracle);
 const first=await runReference([python,path.join(out,'original.py')],'json-stdin',[0xffffffff,digits.slice(0,4),table],out,3000);assert.equal(first.kind,'return');const second=await runReference([python,path.join(out,'original.py')],'json-stdin',[first.value,digits.slice(4),table],out,3000);assert.equal(second.kind,'return');assert.equal(second.value,oracle.value);await save('incremental.json',{first,second,expected:oracle.value});
 await save('toolchain.json',{python,unicorn:'2.1.4',pythonExecutable:await hashFile(python)});
 await writeFile(path.join(out,'original.mjs'),`import {spawnSync} from 'node:child_process';import {readFileSync} from 'node:fs';import {fileURLToPath} from 'node:url';const config=JSON.parse(readFileSync(new URL('./toolchain.json',import.meta.url)));const r=spawnSync(config.python,[fileURLToPath(new URL('./original.py',import.meta.url))],{input:readFileSync(0,'utf8'),encoding:'utf8',timeout:3000});if(r.error||r.status!==0)throw Error(r.stderr||String(r.error));process.stdout.write(r.stdout);\n`);
 await writeFile(path.join(out,'candidate.mjs'),`import {readFileSync} from 'node:fs';import {capability} from './function/index.mjs';console.log(JSON.stringify(capability(...JSON.parse(readFileSync(0,'utf8')))));\n`);
 await writeFile(path.join(out,'mutant.mjs'),`import {readFileSync} from 'node:fs';import {capability} from './function/index.mjs';const [state,bytes]=JSON.parse(readFileSync(0,'utf8'));console.log(JSON.stringify(capability(state,bytes,${JSON.stringify(table)})));\n`);
 await writeFile(path.join(out,'cases.json'),JSON.stringify({schema:'carve/acceptance-cases@1',cases})+'\n');
 await writeFile(path.join(out,'pe-task-cases.json'),JSON.stringify(cases)+'\n');const generatedVerification=await call('carve_verify_reconstruction',{workspace:'work',package:'function',cases:'pe-task-cases.json',reference:'generated-task/reference.json',execute:true,fullReport:true,timeoutMs:5000});assert.equal(generatedVerification.status,'passed-supplied-cases');assert.equal(generatedVerification.passed,200);await save('generated-verification.json',generatedVerification);
 const runnerFile=path.join(out,'generated-task/runner.py'),runnerBytes=await readFile(runnerFile);try{await writeFile(runnerFile,Buffer.concat([runnerBytes,Buffer.from('\n# changed\n')]));const denied=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:'work',package:'function',cases:'pe-task-cases.json',reference:'generated-task/reference.json',execute:true}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/runner changed/);await save('generated-runner-rejection.json',denied);}finally{await writeFile(runnerFile,runnerBytes);}
 const plan={schema:'carve/project-plan@1',goal:'Reuse third-party PE CRC helper',target:{schema:'carve/target@1',platform:'macos',delivery:'module'},features:[{id:'crc',title:'Table-driven CRC update',contract:{input:'uint32 state, bounded bytes and explicit table',output:'Updated uint32 state',state:'Caller-managed incremental state',errors:'Invalid domain rejected'}}]},analysis=analyzeProjectPlan(parseProjectPlan(plan)),spec={schema:'carve/work-spec@1',planId:analysis.planId,assignments:[{feature:'crc',taskId:analysis.tasks[0].taskId,files:['candidate.mjs'],acceptance:[{name:'compare',criterion:'All200original machine-code cases match independent reconstruction'}]}]};
 await save('plan.json',plan);await save('work-spec.json',spec);const task=await createWorkPackage(plan,spec,'crc',path.join(out,'task'));
 const names=['pe-task-spec.json','pe-task-cases.json','generated-verification.json','generated-runner-rejection.json','images.json','source.json','symbols.txt','instructions.txt','standard-vector.json','incremental.json','original.py','original.mjs','candidate.mjs','mutant.mjs','toolchain.json','cases.json','contract.json','reconstruction.json','dependency-boundary.json','original-traces.json','input/lib7-Zip-JBinding.dll'];
 async function tree(directory){for(const e of await readdir(path.join(out,directory),{withFileTypes:true})){const p=directory+'/'+e.name;if(e.isDirectory())await tree(p);else if(e.isFile())names.push(p);else throw Error('Nonregular acceptance input');}}
 for(const directory of ['function','producer','generated-task','work/rea-native-evidence','work/ui-evidence','work/instruction-evidence'])await tree(directory);
 const files=await Promise.all(names.map(async p=>({path:p,sha256:(await hashFile(path.join(out,p))).sha256})));
 const command=file=>({runtime:'node',file,args:[]}),check={id:'compare',kind:'original-comparison',acceptance:['compare'],command:command('candidate.mjs'),comparison:{original:command('original.mjs'),cases:'cases.json',mode:'cases',scope:'declared-harness',limitations}},checks={schema:'carve/acceptance-spec@1',packageId:task.id,files,checks:[check]};
 await save('checks.json',checks);const request={package:'task',root:out,plan:'plan.json',spec:'work-spec.json'};
 const accepted=await call('carve_work_acceptance',{...request,action:'run',checks:'checks.json',out:'accepted',execute:true,timeoutMs:5000});await save('acceptance.json',accepted);assert.equal(accepted.status,'passed-declared-acceptance');
 await save('negative-checks.json',{...checks,checks:[{...check,command:command('mutant.mjs')}]});const rejected=await call('carve_work_acceptance',{...request,action:'run',checks:'negative-checks.json',out:'rejected',execute:true,timeoutMs:5000});assert.equal(rejected.categories['original-comparison'],'failed');
 const original=await readFile(path.join(out,'input/lib7-Zip-JBinding.dll'));try{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),Buffer.concat([original,Buffer.from([0])]));const stale=await client.callTool({name:'carve_work_acceptance',arguments:{...request,action:'read',directory:'accepted'}});assert.equal(stale.isError,true);await save('stale-rejection.json',stale);}finally{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),original);}
 const stored=await call('carve_library_add',{package:'function',library:'functions',name:'sevenzip-crc',title:'Reviewed third-party CRC update',description:limitations,tags:['pe','crc','table']});
 const fresh=new Client({name:'crc-library-only',version:'1'});await rename(path.join(out,'input'),path.join(out,'input-offline'));
 try{assert.equal((await runReference([python,path.join(out,'original.py')],'json-stdin',[0,[],table],out,3000)).kind,'harness-error');
  await fresh.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',path.join(out,'functions')],stderr:'pipe'}));
  const module=await import(pathToFileURL(path.join(stored.package,'index.mjs')));
  for(const row of [cases[0],cases[128],cases[129],cases[199]]){const expected=module.capability(...row.args),response=await fresh.callTool({name:'carve_invoke',arguments:{package:'sevenzip-crc',args:row.args,execute:true}});assert.ok(!response.isError);assert.equal(JSON.parse(response.content[0].text).value,expected);if(row.expected!==undefined)assert.equal(expected,row.expected);}
  const full=module.capability(0xffffffff,digits,table),prefix=module.capability(0xffffffff,digits.slice(0,4),table);assert.equal(module.capability(prefix,digits.slice(4),table),full);assert.equal(full,0x340bc6d9);
  assert.throws(()=>module.capability(-1,[],table),/uint32/);assert.throws(()=>module.capability(0,[256],table),/bytes/);assert.throws(()=>module.capability(0,[],[]),/256/);

 }finally{await fresh.close();await rename(path.join(out,'input-offline'),path.join(out,'input'));}
 assert.equal((await hashFile(source)).sha256,expectedSha);assert.equal((await hashFile(path.join(out,'input/lib7-Zip-JBinding.dll'))).sha256,expectedSha);
 assert.equal((await call('carve_work_acceptance',{...request,action:'read',directory:'accepted'})).reportSha256,accepted.reportSha256);
 const report={schema:'carve/third-party-pe-crc-e2e@1',status:'passed',out,sourceSha256:expectedSha,cases:cases.length,tableIndicesExercised:indices.size,instructionReviews:1,generatedTaskCases:200,generatedRunnerTamperRejected:true,incrementalOriginalCompared:true,decompilerPrototype:'void-return-inferred-computation-elided',visitedFunctions:dependencies.visited,scope:'declared-harness',windowsExecuted:false,jvmExecuted:false,archiveOperationsVerified:false,producerClosedBeforeImport:producer.closed,acceptanceReportSha256:accepted.reportSha256,negative:{fixedTableMutantRejected:true,staleOriginalRejected:true},independence:{originalCopyOffline:true,libraryOnlyMcp:true,directImport:true,originalsRestoredUnchanged:true},function:stored.package,limitations};await save('report.json',report);await writeFile(path.join(root,'artifacts/pe-crc-verification-summary.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}catch(error){await save('failure.json',{message:error.stack});throw error;}finally{await client.close();await writeFile(path.join(out,'carve-diagnostics.log'),diagnostics);}
