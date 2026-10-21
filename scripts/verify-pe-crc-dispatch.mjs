// Real CRC initializer and original indirect dispatch under declared CPU predicate outcomes.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtemp,mkdir,readFile,writeFile,copyFile,rename,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {generateCrcTables} from '../examples/pe-crc-dispatch/implementation.mjs';
import {createHash} from 'node:crypto';
import {readEngineConfiguration} from '../dist/engine-config.js';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
import {runReference} from '../dist/reference.js';
import {parseProjectPlan,analyzeProjectPlan} from '../dist/project-plan.js';
import {createWorkPackage} from '../dist/work-package.js';
import {collectPeBehaviorEvidence} from './pe-behavior-rea.mjs';
import {peInstructionReview} from './pe-instruction-review.mjs';
import {verifyGeneratedCrcDispatch} from './pe-crc-generated-dispatch.mjs';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
const {values:options}=parseArgs({options:{engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')},'rea-install':{type:'string',default:path.join(root,'artifacts/rea-local')},python:{type:'string',default:path.join(root,'artifacts/pe-behavior-venv/bin/python')}}});
const engines=await readEngineConfiguration(path.resolve(options.engines)),python=path.resolve(options.python);
assert.equal((await exec(python,['-c','import unicorn;print(unicorn.__version__)'])).stdout.trim(),'2.1.4');
const relative='Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll',source=path.join(engines.ghidra,relative);
const expectedSha='c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27';
assert.equal((await hashFile(source)).sha256,expectedSha,'This reviewed reconstruction requires the exact shipped DLL');
await mkdir(path.join(root,'artifacts'),{recursive:true});
const out=await mkdtemp(path.join(root,'artifacts/pe-crc-dispatch-e2e-')),save=(name,data)=>writeFile(path.join(out,name),JSON.stringify(data,null,2)+'\n');
await mkdir(path.join(out,'input'));await copyFile(source,path.join(out,'input/lib7-Zip-JBinding.dll'));
const metadata=await readPeLoader(source);assert.equal(metadata.machine,0x8664);
const entry='0x6a42c4a0',targets=[['initialize','0x6a42c510'],['update',entry],['t4','0x6a42c5c0'],['t8','0x6a42c680'],['cpu','0x6a41e6a0']];
// Review pins both source bytes and the retained internal COFF symbol; this is not an export.
const symbols=(await exec('xcrun',['llvm-nm',source],{maxBuffer:8*1024*1024})).stdout;
for(const [address,name] of [['6a42c510','CrcGenerateTable'],['6a42c4a0','CrcUpdate'],['6a42c5c0','CrcUpdateT4'],['6a42c680','CrcUpdateT8'],['6a41e6a0','CPU_Is_InOrder']])assert.ok(symbols.includes(address+' T '+name+'\n'));
await writeFile(path.join(out,'symbols.txt'),symbols);
const disassembly=(await exec('xcrun',['llvm-objdump','-d','--start-address='+entry,'--stop-address=0x6a42c800',source])).stdout;
await writeFile(path.join(out,'instructions.txt'),disassembly);
await save('images.json',{schema:'carve/third-party-pe-crc-dispatch@1',sha256:expectedSha,metadata,entry});
await save('source.json',{path:source,distributionRelativePath:relative,sha256:expectedSha,windowsExecuted:false,jvmExecuted:false});
await copyFile(path.join(root,'examples/pe-crc-dispatch/original.py'),path.join(out,'original.py'));
await writeFile(path.join(out,'implementation.mjs'),(await readFile(path.join(root,'examples/pe-crc-dispatch/implementation.mjs'),'utf8')).replace('../pe-crc/implementation.mjs','./crc-core.mjs'));await copyFile(path.join(root,'examples/pe-crc/implementation.mjs'),path.join(out,'crc-core.mjs'));
const producer=await collectPeBehaviorEvidence(out,{},engines,path.resolve(options['rea-install']),[['lib7-Zip-JBinding.dll',targets]],{instructions:true});
assert.equal(producer.closed,true);
const client=new Client({name:'third-party-pe-crc-dispatch',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],cwd:out,stderr:'pipe'});
let diagnostics='';transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-16000);});
const call=async(name,args)=>{const r=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(r.isError)throw Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return JSON.parse(r.content.find(c=>c.type==='text').text);};
const limitations='Original CRC table initializer and CrcUpdate indirect dispatch execute under a bounded Unicorn ABI harness. CPU_Is_InOrder is stubbed with declared0or1, not hardware detection. No Windows/DLL/JVM initialization, OS/UI, concurrency, loader rebasing or archive behavior. Portable code regenerates equivalent tables and computes the byte recurrence; it does not preserve original optimized instruction sequences.';
try{
 await client.connect(transport);assert.notEqual(transport.pid,producer.pid);
 await call('carve_reverse',{target:'input',goal:'Reconstruct original CRC table initialization and selected indirect dispatch',out:'work'});
 const ids=[];for(const record of producer.records){
  const imported=await call('carve_import_rea_native',{workspace:'work',file:record.file,...Object.fromEntries(['code','info','callees','references'].map(role=>[role,path.relative(out,record[role])]))});ids.push(imported.observationId);
 }
 const rootIds=ids.slice(0,2),dependencies=await call('carve_pe_ui',{workspace:'work',file:'lib7-Zip-JBinding.dll',view:'dependencies',entryMode:'selected-functions',functionIds:rootIds,dependencyIds:ids.slice(2),limit:100,budgetBytes:65536});await save('dependency-boundary.json',dependencies);
 assert.ok(dependencies.visited>=2);
 const full=JSON.parse(await readFile(dependencies.dependencyEvidence,'utf8')),runtimeTargets=new Set(['0x6a5c6ba0','0x6a5c6b88','0x6a5c8ba0','0x6a5c6b80']);
 const dataBindings=full.rows.filter(r=>r.kind==='data-reference'&&runtimeTargets.has(r.targetAddress)).map(row=>({observationId:row.from,sourceAddress:row.sourceAddress,targetAddress:row.targetAddress,handling:'unresolved',description:'Runtime initialized BSS table or dispatch pointer; no original file bytes or general lifetime proof are inferred'}));assert.ok(dataBindings.length>=2);
 const instructionReviews=[await peInstructionReview(out,metadata,producer.records[0],ids[0],{convention:'windows-x64',parameters:[],result:{location:'none',type:'void'}},'Reviewed original no-argument initializer writes BSS and calls an explicit CPU predicate boundary; no CPU/loader or semantic closure is inferred.'),await peInstructionReview(out,metadata,producer.records[1],ids[1],{convention:'windows-x64',parameters:[{name:'state',location:'rcx',type:'uint32',description:'Raw CRC state'},{name:'data',location:'rdx',type:'pointer',description:'Caller bytes'},{name:'length',location:'r8',type:'uint64',description:'Bounded byte count'}],result:{location:'eax',type:'uint32'}},'Reviewed dispatcher supplies original generated table through R9 and indirectly transfers to selected T4/T8. Return convention is agent-declared and separately compared.')];
 for(const index of [2,3,4])instructionReviews.push(await peInstructionReview(out,metadata,producer.records[index],ids[index],{convention:'windows-x64',parameters:index===4?[]:[{name:'state',location:'rcx',type:'uint32',description:'Raw CRC state'},{name:'data',location:'rdx',type:'pointer',description:'Caller bytes'},{name:'length',location:'r8',type:'uint64',description:'Bounded byte count'},{name:'table',location:'r9',type:'pointer',description:'Original initialized slicing table'}],result:{location:'eax',type:'uint32'}},index===4?'Source-bound CPU entry and body identify a declared constant predicate boundary. Original CPU detection is not executed.':'Reviewed optimized CRC helper body is an explicit executable dependency; outer behavior is separately compared.'));
 await save('contract.json',{schema:'carve/reconstruction@2',goal:'Reuse initialized CRC update semantics with a declared CPU predicate',primary:'library',artifacts:[{key:'library',file:'lib7-Zip-JBinding.dll',evidenceIds:ids,dataBindings,instructionReviews}],relationships:[],behavior:{description:'Regenerate CRC tables and model original T4/T8 selection with equivalent portable arithmetic',inputDomain:'CPU predicate0or1,uint32state,0to4096bytes,alignment0to7',outputDomain:'Object with updated uint32value and selected implementation T4orT8'},dependencies:[{name:'CPU_Is_InOrder result',status:'host-required',detail:'Caller declares0or1. Original CPU detection body is not executed.'},{name:'Runtime CRC tables and dispatch pointer',status:'reimplemented',detail:'Portable tables are regenerated from the reviewed recurrence; original initializer writes and selected target are separately compared.'}],unknowns:[limitations,'Uninitialized BSS and indirect static call destinations remain unresolved in the source-bound data/graph evidence.']});
 await save('reconstruction.json',await call('carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'crcDispatch',out:'function'}));
 const cases=[],lengths=[0,1,3,4,7,8,15,16,31,32,33,4096];let seed=7171;const random=()=>seed=(Math.imul(seed,1664525)+1013904223)>>>0;
 for(const profile of [0,1])for(let alignment=0;alignment<8;alignment++)for(const length of lengths){const state=[0,0xffffffff,0x80000000,random()][cases.length%4],bytes=Array.from({length},()=>random()>>>24);cases.push({name:`CPU=${profile} alignment=${alignment} bytes=${length}`,args:[profile,state,bytes,alignment]});}
 const digits=Array.from(Buffer.from('123456789'));for(const profile of [0,1])cases.push({name:'Standard vector CPU='+profile,args:[profile,0xffffffff,digits,3],expected:{value:0x340bc6d9,implementation:profile?'T4':'T8'}});
 const expectedTable=generateCrcTables(),tableBytes=Buffer.alloc(8192);expectedTable.forEach((n,i)=>tableBytes.writeUInt32LE(n,i*4));const expectedTableSha256=createHash('sha256').update(tableBytes).digest('hex');
 const traces=[];for(const profile of [0,1])for(const bytes of [[],digits]){const observed=await runReference([python,path.join(out,'original.py'),'--trace'],'json-stdin',[profile,0xffffffff,bytes,3],out,3000);assert.equal(observed.kind,'return',JSON.stringify(observed));assert.deepEqual(observed.value.trace.table,expectedTable);assert.equal(observed.value.trace.tableSha256,expectedTableSha256);assert.equal(observed.value.trace.tableWrites,2048);assert.equal(observed.value.trace.pointerWrites.length,profile?3:4);traces.push(observed.value);}await save('original-traces.json',traces);
 const uninitialized=await runReference([python,path.join(out,'original.py'),'--skip-init'],'json-stdin',[0,0xffffffff,digits,0],out,3000);assert.equal(uninitialized.kind,'harness-error');await save('uninitialized-rejection.json',uninitialized);
 const chunks=[];for(const profile of [0,1]){const first=await runReference([python,path.join(out,'original.py')],'json-stdin',[profile,0xffffffff,digits.slice(0,4),1],out,3000);assert.equal(first.kind,'return');const second=await runReference([python,path.join(out,'original.py')],'json-stdin',[profile,first.value.value,digits.slice(4),7],out,3000);assert.equal(second.kind,'return');assert.equal(second.value.value,0x340bc6d9);chunks.push({profile,first,second});}await save('incremental.json',chunks);
 await save('table-comparison.json',{cells:2048,sha256:expectedTableSha256,profiles:[0,1],originalCpuPredicateExecuted:false});
 const generated=await verifyGeneratedCrcDispatch({out,call,ids,python,expectedTableSha256,cases,save});
 await save('toolchain.json',{python,unicorn:'2.1.4',pythonExecutable:await hashFile(python)});
 await writeFile(path.join(out,'original.mjs'),`import {spawnSync} from 'node:child_process';import {readFileSync} from 'node:fs';import {fileURLToPath} from 'node:url';const config=JSON.parse(readFileSync(new URL('./toolchain.json',import.meta.url)));const r=spawnSync(config.python,[fileURLToPath(new URL('./original.py',import.meta.url))],{input:readFileSync(0,'utf8'),encoding:'utf8',timeout:3000});if(r.error||r.status!==0)throw Error(r.stderr||String(r.error));process.stdout.write(r.stdout);\n`);
 await writeFile(path.join(out,'candidate.mjs'),`import {readFileSync} from 'node:fs';import {capability} from './function/index.mjs';console.log(JSON.stringify(capability(...JSON.parse(readFileSync(0,'utf8')))));\n`);
 await writeFile(path.join(out,'mutant.mjs'),`import {readFileSync} from 'node:fs';import {capability} from './function/index.mjs';const [profile,...args]=JSON.parse(readFileSync(0,'utf8'));console.log(JSON.stringify(capability(1-profile,...args)));\n`);
 await writeFile(path.join(out,'cases.json'),JSON.stringify({schema:'carve/acceptance-cases@1',cases})+'\n');
 const plan={schema:'carve/project-plan@1',goal:'Reuse initialized third-party PE CRC',target:{schema:'carve/target@1',platform:'macos',delivery:'module'},features:[{id:'crc',title:'Initialized CRC dispatch',contract:{input:'CPU predicate, uint32state, bounded bytes and alignment',output:'Updated uint32state and selected T4/T8implementation',state:'Caller-managed incremental state',errors:'Invalid domain rejected'}}]},analysis=analyzeProjectPlan(parseProjectPlan(plan)),spec={schema:'carve/work-spec@1',planId:analysis.planId,assignments:[{feature:'crc',taskId:analysis.tasks[0].taskId,files:['candidate.mjs'],acceptance:[{name:'compare',criterion:'All194original initialized dispatch cases match independent reconstruction'}]}]};
 await save('plan.json',plan);await save('work-spec.json',spec);const task=await createWorkPackage(plan,spec,'crc',path.join(out,'task'));
 const names=['images.json','source.json','symbols.txt','instructions.txt','table-comparison.json','uninitialized-rejection.json','incremental.json','crc-core.mjs','original.py','original.mjs','candidate.mjs','mutant.mjs','toolchain.json','cases.json','contract.json','reconstruction.json','dependency-boundary.json','original-traces.json','input/lib7-Zip-JBinding.dll'];
 const snapshots=[];
 async function tree(directory,files){for(const e of await readdir(path.join(out,directory),{withFileTypes:true})){const p=directory+'/'+e.name;if(e.isDirectory())await tree(p,files);else if(e.isFile())files.push(p);else throw Error('Nonregular acceptance evidence input');}}
 snapshots.push(...generated.files);
 for(const directory of [...generated.directories,'producer','work/rea-native-evidence','work/ui-evidence','work/instruction-evidence'])await tree(directory,snapshots);
 const entries=[];for(const file of snapshots.sort()){const bytes=await readFile(path.join(out,file));entries.push({path:file,sha256:createHash('sha256').update(bytes).digest('hex'),encoding:'base64',content:bytes.toString('base64')});}
 await save('evidence-bundle.json',{schema:'carve/integration-evidence-bundle@1',authority:'Pinned immutable snapshot of integration evidence, not a live integrity claim about loose convenience files.',files:entries});
 const evidenceBundle={file:'evidence-bundle.json',files:entries.length,sha256:(await hashFile(path.join(out,'evidence-bundle.json'))).sha256};
 names.push('evidence-bundle.json');await tree('function',names);assert.ok(names.length<=64);
 const files=await Promise.all(names.map(async p=>({path:p,sha256:(await hashFile(path.join(out,p))).sha256})));
 const command=file=>({runtime:'node',file,args:[]}),check={id:'compare',kind:'original-comparison',acceptance:['compare'],command:command('candidate.mjs'),comparison:{original:command('original.mjs'),cases:'cases.json',mode:'cases',scope:'declared-harness',limitations}},checks={schema:'carve/acceptance-spec@1',packageId:task.id,files,checks:[check]};
 await save('checks.json',checks);const request={package:'task',root:out,plan:'plan.json',spec:'work-spec.json'};
 const accepted=await call('carve_work_acceptance',{...request,action:'run',checks:'checks.json',out:'accepted',execute:true,timeoutMs:5000});await save('acceptance.json',accepted);assert.equal(accepted.status,'passed-declared-acceptance');
 await save('negative-checks.json',{...checks,checks:[{...check,command:command('mutant.mjs')}]});const rejected=await call('carve_work_acceptance',{...request,action:'run',checks:'negative-checks.json',out:'rejected',execute:true,timeoutMs:5000});assert.equal(rejected.categories['original-comparison'],'failed');
 const bundleBytes=await readFile(path.join(out,'evidence-bundle.json'));try{await writeFile(path.join(out,'evidence-bundle.json'),Buffer.concat([bundleBytes,Buffer.from(' ')]));const stale=await client.callTool({name:'carve_work_acceptance',arguments:{...request,action:'read',directory:'accepted'}});assert.equal(stale.isError,true);await save('stale-bundle-rejection.json',stale);}finally{await writeFile(path.join(out,'evidence-bundle.json'),bundleBytes);}
 const original=await readFile(path.join(out,'input/lib7-Zip-JBinding.dll'));try{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),Buffer.concat([original,Buffer.from([0])]));const stale=await client.callTool({name:'carve_work_acceptance',arguments:{...request,action:'read',directory:'accepted'}});assert.equal(stale.isError,true);await save('stale-rejection.json',stale);}finally{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),original);}
 const stored=await call('carve_library_add',{package:'function',library:'functions',name:'sevenzip-crc-dispatch',title:'Reviewed third-party CRC update',description:limitations,tags:['pe','crc','initialize','dispatch']});
 const fresh=new Client({name:'crc-library-only',version:'1'});await rename(path.join(out,'input'),path.join(out,'input-offline'));
 try{assert.equal((await runReference([python,path.join(out,'original.py')],'json-stdin',[0,0,[],0],out,3000)).kind,'harness-error');
  await fresh.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',path.join(out,'functions')],stderr:'pipe'}));
  const module=await import(pathToFileURL(path.join(stored.package,'index.mjs')));
  for(const row of [cases[0],cases[11],cases[96],cases[107],cases[192],cases[193]]){const expected=module.capability(...row.args),response=await fresh.callTool({name:'carve_invoke',arguments:{package:'sevenzip-crc-dispatch',args:row.args,execute:true}});assert.ok(!response.isError);assert.deepEqual(JSON.parse(response.content[0].text).value,expected);if(row.expected!==undefined)assert.deepEqual(expected,row.expected);}
  for(const profile of [0,1]){const first=module.capability(profile,0xffffffff,digits.slice(0,4),1),second=module.capability(profile,first.value,digits.slice(4),7);assert.equal(second.value,0x340bc6d9);}
  assert.throws(()=>module.capability(2,0,[],0),/CPU predicate/);

 }finally{await fresh.close();await rename(path.join(out,'input-offline'),path.join(out,'input'));}
 assert.equal((await hashFile(source)).sha256,expectedSha);assert.equal((await hashFile(path.join(out,'input/lib7-Zip-JBinding.dll'))).sha256,expectedSha);
 assert.equal((await call('carve_work_acceptance',{...request,action:'read',directory:'accepted'})).reportSha256,accepted.reportSha256);
 const report={schema:'carve/third-party-pe-crc-dispatch-e2e@1',status:'passed',out,sourceSha256:expectedSha,cases:cases.length,generated:generated.summary,evidenceBundle,instructionReviews:instructionReviews.length,initializedTableCells:2048,initializedTableSha256:expectedTableSha256,profiles:[0,1],alignments:[0,1,2,3,4,5,6,7],originalCpuPredicateExecuted:false,incrementalOriginalCompared:true,visitedFunctions:dependencies.visited,scope:'declared-harness',windowsExecuted:false,jvmExecuted:false,archiveOperationsVerified:false,producerClosedBeforeImport:producer.closed,acceptanceReportSha256:accepted.reportSha256,negative:{wrongDispatchMutantRejected:true,uninitializedOriginalRejected:true,staleOriginalRejected:true,staleEvidenceBundleRejected:true},independence:{originalCopyOffline:true,libraryOnlyMcp:true,directImport:true,originalsRestoredUnchanged:true},function:stored.package,limitations};await save('report.json',report);await writeFile(path.join(root,'artifacts/pe-crc-dispatch-verification-summary.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}catch(error){await save('failure.json',{message:error.stack});throw error;}finally{await client.close();await writeFile(path.join(out,'carve-diagnostics.log'),diagnostics);}
