import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,rm,realpath} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {reverseTask} from '../dist/reverse.js';
import {nativeAnalysis,searchObservations,readObservation} from '../dist/native.js';
import {traceBoundary} from '../dist/trace.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {invoke} from '../dist/runtime.js';
import {readPackage} from '../dist/package.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('This fixture-specific native reconstruction is currently validated on macOS arm64.');
const configFile=await realpath(process.argv[2]??path.join(root,'artifacts/engines/config.json'));
const config=await readEngineConfiguration(configFile);
const r8=await realpath(process.argv[3]??path.join(root,'artifacts/engines/r8-9.5.26.jar'));
const run=promisify(execFile);const artifacts=path.join(root,'artifacts');await mkdir(artifacts,{recursive:true});
const out=await mkdtemp(path.join(artifacts,'native-e2e-'));const app=path.join(out,'app');await mkdir(app);
const binary=path.join(app,'parking');await run('xcrun',['clang','-O1','-g0',path.join(root,'examples/native-app/parking.c'),'-o',binary]);
await run('/usr/bin/strip',[binary]); // Analysis must follow strings/references even without the function's original name.
const workspace=path.join(out,'native-work');const task=await reverseTask(app,{goal:'Extract parking fee calculation from the shipped program',out:workspace});
assert.equal(task.status,'ready-for-analysis');
await nativeAnalysis(workspace,{file:'parking',ghidra:config.ghidra,javaHome:config.javaHome});
const text=(await searchObservations(workspace,'parking fee needs')).items.find(x=>x.kind==='string');assert.ok(text,'real string evidence');
const graph=await traceBoundary(workspace,text.id,{depth:2,maxNodes:50});
const entry=graph.nodes.find(n=>n.kind==='function'&&n.depth===1);assert.ok(entry,'string-to-function reference');
const candidate=graph.nodes.find(n=>n.kind==='function'&&n.depth===2&&!n.external&&!n.thunk);assert.ok(candidate,'entry-to-internal-function call excluding import thunks');
assert.ok(!/parking_fee/.test(candidate.name),'fixture stripped its original function symbol');
const client=new Client({name:'carve-native-e2e',version:'1.0.0'});
const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',configFile],stderr:'pipe'});
await client.connect(transport);
const call=async(name,args)=>{const result=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(result.isError)throw new Error(result.content[0].text);return JSON.parse(result.content[0].text);};
let nativeResult,managedResult;
try{
 nativeResult=await call('carve_native',{workspace:'native-work',file:'parking',function:candidate.address});assert.equal(nativeResult.status,'function-exported');assert.equal(nativeResult.reusedAnalysis,true);
 const decompiled=(await searchObservations(workspace,candidate.name)).items.filter(n=>n.kind==='function');
 let evidence;for(const row of decompiled){const detail=await readObservation(workspace,row.id);if(detail.decompilationStatus==='completed'){evidence=detail;break;}}
 assert.ok(evidence,'actual decompiled C body');assert.equal(evidence.truncated,false);assert.match(evidence.text,/0x19/);assert.match(evidence.text,/0xf/);assert.doesNotMatch(evidence.text,/Could not recover jumptable/);
 await nativeAnalysis(workspace,{file:'parking',ghidra:config.ghidra,javaHome:config.javaHome});
 assert.equal((await readObservation(workspace,evidence.id)).text,evidence.text,'later inventory must preserve deeper decompilation evidence');
 // Derived from the actual arm64 optimized pseudocode, including unsigned arithmetic.
 const nativeSource=path.join(out,'native-reimplementation.mjs');await writeFile(nativeSource,`export function fee(minutes,member){if(!Number.isInteger(minutes)||minutes<-2147483648||minutes>2147483647||!Number.isInteger(member)||member<-2147483648||member>2147483647)throw new RangeError('int32 args required');if(minutes<0)return -1;if(minutes<16)return 0;const blocks=Math.floor(((minutes+14)>>>0)/15);return Math.min(Math.imul(member!==0?20:25,blocks)>>>0,300);}\n`);
 const contract={schema:'carve/reconstruction@1',goal:'Parking fee',file:'parking',evidenceIds:[evidence.id],behavior:{description:'Fee returned by the selected stripped Mach-O CLI operation',inputDomain:'Two signed 32-bit integers: minutes and membership flag',outputDomain:'One JSON integer; negative minutes return -1'},dependencies:[],unknowns:['UI integration and inputs outside int32 are unverified.']};
 const contractFile=path.join(out,'native-contract.json');await writeFile(contractFile,JSON.stringify(contract,null,2));
 const nativePackage=path.join(out,'native-tool');await reconstruct(workspace,{contract:contractFile,implementation:nativeSource,export:'fee',out:nativePackage});
 const cases=[];for(const minutes of [-2147483648,-1,0,14,15,16,29,30,31,149,150,151,179,180,181,2147483633,2147483646,2147483647])for(const member of [0,1,-1])cases.push({name:`m=${minutes},member=${member}`,args:[minutes,member]});
 const casesFile=path.join(out,'cases.json');await writeFile(casesFile,JSON.stringify(cases,null,2));
 const refFile=path.join(out,'native-reference.json');await writeFile(refFile,JSON.stringify({schema:'carve/reference@1',command:[binary],mode:'argv-values',scope:'target-cli',description:'Actual stripped Mach-O executable CLI, signed-int32 decimal arguments',boundFiles:[]}));
 const nativeVerification=await verifyReconstruction(workspace,{package:nativePackage,cases:casesFile,reference:refFile,execute:true});assert.equal(nativeVerification.status,'passed-supplied-cases');
 console.log(`Stripped Mach-O: ${nativeVerification.passed}/${nativeVerification.total} actual executable cases passed.`);
 // Build a real DEX input from owned Java; JADX receives only the DEX, not the source.
 const classes=path.join(out,'java');const dex=path.join(out,'dex');await mkdir(classes);await mkdir(dex);
 const java=path.join(config.javaHome,'bin/java');const jar=path.join(out,'parking.jar');
 await run(path.join(config.javaHome,'bin/javac'),['--release','8','-d',classes,path.join(root,'examples/native-app/ParkingFeature.java')]);
 await run(path.join(config.javaHome,'bin/jar'),['--create','--file',jar,'-C',classes,'.']);
 await run(java,['-cp',r8,'com.android.tools.r8.D8','--min-api','21','--output',dex,jar]);
 const bundle=path.join(out,'payload.zip');await run(path.join(config.javaHome,'bin/jar'),['--create','--file',bundle,'-C',app,'.','-C',dex,'.']);
 await reverseTask(bundle,{goal:'Inspect native and DEX payloads in the packaged input',out:path.join(out,'container-work')});
 let container;do{container=await call('carve_unpack',{workspace:'container-work',file:'payload.zip',maxFiles:1});}while(container.status==='unpacking');
 assert.equal(container.status,'unpacked');
 const mobileWork=path.join(out,'android-work');await reverseTask(container.content,{goal:'Reconstruct the packaged DEX parking fee calculation',out:mobileWork});
 managedResult=await call('carve_managed',{workspace:'android-work',file:'classes.dex'});assert.equal(managedResult.status,'sources-exported');assert.equal(managedResult.container.sha256,container.original.sha256);
 const packagedNative=await call('carve_native',{workspace:'android-work',file:'parking',function:candidate.address});assert.equal(packagedNative.status,'function-exported');assert.equal(packagedNative.container.sha256,container.original.sha256);
 const mobileEvidence=(await searchObservations(mobileWork,'parkingFee')).items.find(n=>n.kind==='java-class');assert.ok(mobileEvidence);
 const mobileSource=path.join(out,'dex-reimplementation.mjs');await writeFile(mobileSource,`export function fee(minutes,member){if(!Number.isInteger(minutes)||minutes<-2147483648||minutes>2147483647||!Number.isInteger(member)||member<-2147483648||member>2147483647)throw new RangeError('int32 args required');if(minutes<0)return -1;if(minutes<=15)return 0;let value=Math.imul(Math.trunc(((minutes+14)|0)/15),25);if(member!==0)value=Math.trunc(Math.imul(value,8)/10);return Math.min(value,300);}\n`);
 const mobileContract={...contract,file:'classes.dex',evidenceIds:[mobileEvidence.id],behavior:{...contract.behavior,description:'DEX integer algorithm reimplemented from JADX output, compared to source-owned JVM harness'},unknowns:['Android runtime/device execution has not been performed.','JVM source-equivalent reference is not proof of DEX runtime equivalence.']};
 const mobileContractFile=path.join(out,'dex-contract.json');await writeFile(mobileContractFile,JSON.stringify(mobileContract,null,2));
 const mobilePackage=path.join(out,'dex-tool');await reconstruct(mobileWork,{contract:mobileContractFile,implementation:mobileSource,export:'fee',out:mobilePackage});
 const mobileReference=path.join(out,'dex-reference.json');await writeFile(mobileReference,JSON.stringify({schema:'carve/reference@1',command:[java,'-cp',classes,'example.ParkingFeature'],mode:'argv-values',scope:'external-harness',description:'Source-owned JVM class used to build DEX; no Android runtime is available',boundFiles:[path.join(classes,'example/ParkingFeature.class'),jar,r8]}));
 const mobileVerification=await verifyReconstruction(mobileWork,{package:mobilePackage,cases:casesFile,reference:mobileReference,execute:true});assert.equal(mobileVerification.status,'passed-supplied-cases');assert.equal(mobileVerification.verifiedScope,'declared-external-harness-cases');
 // Independence must survive removal of both original artifacts and reconstruction sources.
 await rm(app,{recursive:true});await rm(dex,{recursive:true});await rm(classes,{recursive:true});await rm(container.content,{recursive:true});await rm(bundle);await rm(nativeSource);await rm(mobileSource);
 assert.deepEqual(await invoke(nativePackage,[16,1],{execute:true}),{kind:'return',value:40});assert.deepEqual(await invoke(mobilePackage,[16,1],{execute:true}),{kind:'return',value:40});
 const standalone=await run(process.execPath,[path.join(nativePackage,'cli.mjs'),'[16,1]']);assert.equal(standalone.stdout.trim(),'40');
 const manifest=await readPackage(nativePackage);assert.equal(manifest.manifest.extractionKind,'behavior-reconstruction');
 const report={schema:'carve/native-e2e@1',status:'passed',checkedAt:new Date().toISOString(),node:process.version,platform:process.platform,arch:process.arch,out,
  native:{format:'stripped-mach-o',stringEvidence:text.id,graph,decompilation:nativeResult,verification:nativeVerification},
  container:{extraction:container,nativeDecompilation:packagedNative},android:{format:'dex',decompilation:managedResult,verification:mobileVerification,deviceExecution:false},independence:{originalsRemoved:true,reimplementationSourcesRemoved:true,cliPassed:true,invokePassed:true},
  limitations:['Own-source small fixtures, not large third-party app reconstruction.','The native case executes the actual compiled CLI. The mobile case decompiles real DEX but compares against an explicitly scoped JVM harness, not an Android device.','The fixture-specific implementations are authored by the agent; RECarve does not autonomously synthesize arbitrary features.']};
 const reportFile=path.join(out,'report.json');await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');await writeFile(path.join(artifacts,'native-verification-summary.json'),JSON.stringify({status:'passed',report:reportFile,out},null,2)+'\n');
 console.log(JSON.stringify({status:report.status,nativeCases:nativeVerification.total,dexJvmHarnessCases:mobileVerification.total,deviceExecution:false,independent:true,report:reportFile},null,2));
}finally{await client.close();}
