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
import {hashFile} from '../dist/survey.js';
import {queryLinks} from '../dist/linkage.js';
import {inspectLoader} from '../dist/loader.js';
import {analysisContext} from '../dist/context.js';
import {readPackage} from '../dist/package.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('This owned split-library case currently requires macOS arm64.');
const configFile=await realpath(process.argv[2]??path.join(root,'artifacts/engines/config.json'));const config=await readEngineConfiguration(configFile);
const out=await mkdtemp(path.join(root,'artifacts/multi-e2e-')),app=path.join(out,'app'),bin=path.join(app,'bin'),lib=path.join(app,'lib');await mkdir(bin,{recursive:true});await mkdir(lib);
const program=path.join(bin,'quote'),library=path.join(lib,'libcharge.dylib');
await exec('xcrun',['clang','-O1','-g0','-dynamiclib',path.join(root,'examples/native-app/split-charge.c'),'-Wl,-install_name,@rpath/libcharge.dylib','-o',library]);
await exec('xcrun',['clang','-O1','-g0',path.join(root,'examples/native-app/split-main.c'),'-L'+lib,'-lcharge','-Wl,-rpath,@loader_path/../lib','-o',program]);
await exec('xcrun',['clang','-O1','-g0','-dynamiclib',path.join(root,'examples/native-app/split-decoy.c'),'-Wl,-install_name,@rpath/libdecoy.dylib','-o',path.join(lib,'libdecoy.dylib')]);
await exec('/usr/bin/strip',[program]);await exec('/usr/bin/strip',['-x',library]);
const libraryIdentity=await hashFile(library),programIdentity=await hashFile(program);const loadCommands=await exec('/usr/bin/otool',['-L',program]);assert.match(loadCommands.stdout,/@rpath\/libcharge\.dylib/);
const loaded=await exec(program,['16','1','1'],{env:{PATH:process.env.PATH,DYLD_PRINT_LIBRARIES:'1'}});assert.equal(loaded.stdout.trim(),'47');assert.ok(loaded.stderr.includes(library),'actual dyld log names this library');
await writeFile(path.join(out,'runtime-library-load.log'),loaded.stderr);
const alternative=path.join(out,'alternate-quote');await exec('xcrun',['clang','-O1','-g0',path.join(root,'examples/native-app/split-main.c'),'-L'+lib,'-ldecoy','-Wl,-rpath,'+lib,'-o',alternative]);
const wrong=await exec(alternative,['16','1','1']);assert.equal(wrong.stdout.trim(),'1006');
const decoyCounterexample={args:[16,1,1],selectedTarget:47,alternateExecutable:1006,scope:'Owned alternate executable built against the same-name decoy library; this does not rebind the selected original executable.'};
const workspace=path.join(out,'work');await reverseTask(app,{goal:'Extract the complete parking quote including the shared library calculation and executable zone surcharge',out:workspace});
const loader=await inspectLoader(workspace,{file:'bin/quote'});
const loaderCharge=loader.dependencies.find(r=>r.name==='@rpath/libcharge.dylib');assert.ok(loaderCharge);assert.equal(loaderCharge.paths[0].candidate.file,'lib/libcharge.dylib');assert.equal(loaderCharge.runtimeLoading,'unverified');
const metadata=[];
for(const [file,kind] of [['bin/quote','imports'],['bin/quote','libraries'],['lib/libcharge.dylib','exports'],['lib/libdecoy.dylib','exports']]){
 let after;do{const r=await nativeAnalysis(workspace,{file,linkage:kind,ghidra:config.ghidra,javaHome:config.javaHome,limit:100,after});metadata.push(r);assert.equal(r.analysisStage,'loader-only');assert.equal(r.autoAnalysisPerformed,false);assert.doesNotMatch(await readFile(path.join(path.dirname(r.evidence),'engine.log'),'utf8'),/ANALYZING all memory and code/);after=r.nextCursor;}while(after);
}
const imported=(await queryLinks(workspace,{file:'bin/quote',kind:'imports',query:'carve_duration_charge'})).items[0];assert.ok(imported);
const candidates=await queryLinks(workspace,{from:imported.id});assert.equal(candidates.total,2);assert.ok(candidates.items.every(c=>c.semanticMatch==='unconfirmed'));assert.equal(candidates.items.filter(c=>c.libraryBasenameHint).length,1);
const selectedLibrary=candidates.items.find(c=>c.libraryBasenameHint);assert.equal(selectedLibrary.file,'lib/libcharge.dylib');
const full=await nativeAnalysis(workspace,{file:'bin/quote',ghidra:config.ghidra,javaHome:config.javaHome});assert.equal(full.analysisStage,'auto-analyzed-program');assert.equal(full.reusedAnalysis,false,'metadata cache must never replace full autoanalysis');
const text=(await searchObservations(workspace,'split quote needs')).items.find(r=>r.kind==='string');assert.ok(text);
const graph=await traceBoundary(workspace,text.id,{depth:2,maxNodes:50});let caller;
for(const row of graph.nodes.filter(n=>n.kind==='function'&&n.depth===2&&!n.external&&!n.thunk)){
 const analyzed=await nativeAnalysis(workspace,{file:'bin/quote',function:row.address,ghidra:config.ghidra,javaHome:config.javaHome});assert.equal(analyzed.status,'function-exported');
 for(const id of analyzed.observationIds){const evidence=await readObservation(workspace,id);if(evidence.text.includes('carve_duration_charge'))caller=evidence;}
}
assert.ok(caller,'actual caller pseudocode crosses the dynamic import');assert.equal(caller.truncated,false);assert.ok(caller.callees.some(c=>c.name.includes('carve_duration_charge')));assert.match(caller.text,/7/);
await nativeAnalysis(workspace,{file:'lib/libcharge.dylib',ghidra:config.ghidra,javaHome:config.javaHome});
const exported=(await searchObservations(workspace,'carve_duration_charge')).items.find(r=>r.artifact==='lib/libcharge.dylib'&&r.kind==='function');assert.ok(exported);
const analyzed=await nativeAnalysis(workspace,{file:'lib/libcharge.dylib',function:exported.address,ghidra:config.ghidra,javaHome:config.javaHome});assert.equal(analyzed.status,'function-exported');
const callee=await readObservation(workspace,analyzed.observationIds.find(id=>id!==exported.id)??analyzed.observationIds[0]);assert.equal(callee.truncated,false);assert.equal(callee.decompilationStatus,'completed');assert.match(callee.text,/0x12c|300/);
const context=await analysisContext(workspace,{ids:[caller.id,callee.id],view:'outline',budgetBytes:8192});assert.ok(context.items.some(r=>r.id===caller.id));assert.ok(context.items.some(r=>r.id===callee.id));assert.ok(context.items.every(r=>!Object.hasOwn(r,'text')));assert.equal(context.receipt.responseBytes,Buffer.byteLength(JSON.stringify(context)));const contextReuse=await analysisContext(workspace,{ids:[caller.id,callee.id],view:'outline',budgetBytes:8192,knownFingerprint:context.fingerprint});assert.equal(contextReuse.status,'unchanged-recorded-context');const contextAuto=await analysisContext(workspace,{ids:[caller.id,callee.id],budgetBytes:8192});for(const record of [caller,callee]){const item=contextAuto.items.find(r=>r.id===record.id);assert.ok(item);assert.equal(item.text?.value,record.text);assert.equal(item.text.complete,true);}assert.equal(contextAuto.receipt.responseBytes,Buffer.byteLength(JSON.stringify(contextAuto)));
const implementation=path.join(out,'rewrite.mjs');await writeFile(implementation,"export function quote(minutes,member,zone){for(const v of [minutes,member,zone])if(!Number.isInteger(v)||v<-2147483648||v>2147483647)throw new RangeError('int32 args required');if(minutes<0)return -1;const amount=minutes<=15?0:Math.min(Math.floor((minutes+14)/15)*(member!==0?20:25),300);return amount+(zone!==0?7:0);}\n");
const contract={schema:'carve/reconstruction@2',goal:'Complete split-library parking quote',primary:'app',artifacts:[{key:'app',file:'bin/quote',evidenceIds:[caller.id],supportingEvidenceIds:[text.id,imported.id,loader.observationId]},{key:'charge',file:selectedLibrary.file,evidenceIds:[callee.id],supportingEvidenceIds:[selectedLibrary.id]}],relationships:[{from:{artifact:'app',id:caller.id},to:{artifact:'charge',id:callee.id},kind:'calls',basis:'reviewed-static',description:'Caller decompilation invokes the external carve_duration_charge import; library export/code, executable load command and an actual dyld load log identify this owned library. These reviewed records do not prove arbitrary indirect-call closure.'}],behavior:{description:'Actual CLI total: shared duration/membership amount plus executable zone surcharge',inputDomain:'Three signed int32 values: minutes, membership flag, zone flag',outputDomain:'Integer quote; negative minutes return -1'},dependencies:[{name:'duration charge',status:'reimplemented',detail:'Independent implementation covers the separately analyzed library calculation.'}],unknowns:['Ghidra leaves imported-call argument types unresolved; the signed-int32 CLI boundary comes from reviewed invocation and actual comparisons, not an inferred C ABI.','Only the specified operation/int32 domain is covered. Other libraries, UI, hidden state and arbitrary third-party boundaries remain unverified.']};
const contractFile=path.join(out,'contract.json');await writeFile(contractFile,JSON.stringify(contract,null,2));const cases=[];
for(const minutes of [-2147483648,-1,0,14,15,16,29,30,31,149,150,151,179,180,181,2147483633,2147483646,2147483647])for(const member of [0,1,-1])for(const zone of [0,1,-1])cases.push({name:`${minutes}/${member}/${zone}`,args:[minutes,member,zone]});
assert.equal(cases.length,162);const casesFile=path.join(out,'cases.json');await writeFile(casesFile,JSON.stringify(cases));const reference=path.join(out,'reference.json');await writeFile(reference,JSON.stringify({schema:'carve/reference@1',command:[program],mode:'argv-values',scope:'target-cli',description:'Actual stripped executable using its separately analyzed dynamic library',boundFiles:[]}));
const client=new Client({name:'multi-artifact-e2e',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],stderr:'pipe'}));
const call=async(name,args)=>{const r=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(r.isError)throw new Error(r.content[0].text);return JSON.parse(r.content[0].text);};
try{
 const packaged=await call('carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'rewrite.mjs',export:'quote',out:'tool'});assert.equal(packaged.artifacts.length,2);assert.equal(packaged.evidence.filter(e=>e.role==='implementation-code').length,2);
 const verificationReceipt=await call('carve_verify_reconstruction',{workspace:'work',package:'tool',cases:'cases.json',reference:'reference.json',execute:true,budgetBytes:4096});assert.equal(verificationReceipt.schema,'carve/verification-read@1');assert.equal(Object.hasOwn(verificationReceipt,'results'),false);assert.equal(verificationReceipt.receipt.responseBytes,Buffer.byteLength(JSON.stringify(verificationReceipt)));assert.ok(verificationReceipt.receipt.responseBytes<=4096);const verified=JSON.parse(await readFile(path.join(workspace,'verification/reports',verificationReceipt.id,'report.json'),'utf8'));assert.equal(verified.status,'passed-supplied-cases');assert.equal(verified.total,162);assert.ok(verified.reference.boundFiles.some(f=>f.file===library&&f.sha256===libraryIdentity.sha256));
 await rm(app,{recursive:true});await rm(implementation);
 const recordedCase=await call('carve_verification',{workspace:'work',id:verificationReceipt.id,view:'case',caseIndex:0,field:'original',budgetBytes:4096});assert.deepEqual(JSON.parse(recordedCase.text),verified.results[0].original);const unknown=await call('carve_verification',{workspace:'work',id:verificationReceipt.id,view:'metadata',field:'unknowns',item:0});assert.equal(JSON.parse(unknown.text),verified.unknowns[0]);
 const independent=await exec(process.execPath,[path.join(out,'tool/cli.mjs'),'[16,1,1]']);assert.equal(independent.stdout.trim(),'47');const called=await call('carve_invoke',{package:'tool',args:[16,1,1],execute:true});assert.deepEqual(called,{value:47});
 const info=await call('carve_use',{package:'tool'});assert.equal(info.reconstruction.artifacts.length,2);assert.equal(info.verification.total,162);assert.deepEqual(info.example.args,cases[0].args);
 const standaloneClient=new Client({name:'multi-independent-capability',version:'1'});
 await standaloneClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve-tool',path.join(out,'tool'),'--execute'],stderr:'pipe'}));
 try{const infoReply=await standaloneClient.callTool({name:'capability_info',arguments:{}});assert.equal(JSON.parse(infoReply.content[0].text).reconstruction.artifacts.length,2);const value=await standaloneClient.callTool({name:'capability',arguments:{args:[16,1,1]}});assert.equal(value.structuredContent.value,47);}finally{await standaloneClient.close();}
 await readPackage(path.join(out,'tool'));
 const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
 const report={schema:'carve/multi-artifact-check@1',status:'passed',checkedAt:new Date().toISOString(),version,out,workspace,inputs:{program:{sha256:programIdentity.sha256},library:{sha256:libraryIdentity.sha256}},linkage:{loader,metadata,candidates,selectedLibrary,decoyCounterexample},boundary:{context,contextAuto,contextReuse,string:text.id,graph,caller,callee,loadCommands:loadCommands.stdout,actualLibraryLoadLog:path.join(out,'runtime-library-load.log')},packaged,verification:verified,verificationReceipt,recordedCase,independence:{originalExecutableAndLibraryRemoved:true,implementationSourceRemoved:true,cliPassed:true,mcpPassed:true},scope:'Owned small native executable/shared-library split feature. Real Ghidra analysis of both binaries, reviewed import/export/load evidence and162 original CLI comparisons. Relationships remain agent-declared, not automatic dependency resolution; no large third-party app or arbitrary behavior equivalence claim.'};
 await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/multi-verification-summary.json'),JSON.stringify({status:'passed',version,report:path.join(out,'report.json'),artifacts:2,cases:162,independent:true},null,2)+'\n');console.log(JSON.stringify({status:'passed',artifacts:2,cases:162,report:path.join(out,'report.json')}));
}finally{await client.close();}
