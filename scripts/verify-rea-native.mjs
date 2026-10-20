// A test client for two independent MCPs. It is neither a server nor a REA proxy.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtemp,mkdir,writeFile,readFile,rename,access} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
import {hashFile} from '../dist/survey.js';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile),{values}=parseArgs({options:{'rea-install':{type:'string'},engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')}}});
const out=await mkdtemp(path.join(root,'artifacts/rea-native-e2e-')),save=(file,value)=>writeFile(path.join(out,file),JSON.stringify(value,null,2)+'\n');
const engines=await readEngineConfiguration(path.resolve(values.engines));
let reaInstall=values['rea-install']?path.resolve(values['rea-install']):path.join(out,'rea-install');
if(!values['rea-install']){await mkdir(reaInstall);await writeFile(path.join(reaInstall,'package.json'),JSON.stringify({private:true,dependencies:{'rea-agents':'6.7.0'}}));const installed=await exec('npm',['install','--no-audit','--no-fund','--ignore-scripts'],{cwd:reaInstall,maxBuffer:1048576});await writeFile(path.join(out,'install.log'),installed.stdout+installed.stderr);}
const reaPackage=JSON.parse(await readFile(path.join(reaInstall,'node_modules/rea-agents/package.json'),'utf8'));
const reaBin=path.join(reaInstall,'node_modules/rea-agents',typeof reaPackage.bin==='string'?reaPackage.bin:reaPackage.bin.rea);
const input=path.join(out,'input'),producer=path.join(out,'producer'),temporary=path.join(out,'tmp');for(const dir of [input,producer,temporary])await mkdir(dir);
const binary=path.join(input,'parking');await exec('cc',['-O2','-fwrapv',path.join(root,'examples/native-app/parking.c'),'-o',binary]);
const original=await hashFile(binary),selector=process.platform==='darwin'?'_parking_fee':'parking_fee',other=process.platform==='darwin'?'_unrelated_editor':'unrelated_editor';
const common={PATH:process.env.PATH??'/usr/bin:/bin',LANG:'C.UTF-8'};
const reaTransport=new StdioClientTransport({command:process.execPath,args:[reaBin,'mcp'],cwd:out,stderr:'pipe',env:{...common,REA_ANALYSIS_PROVIDER:'ghidra',GHIDRA_INSTALL_DIR:engines.ghidra,JAVA_HOME:engines.javaHome,GHIDRA_HEADLESS_MAXMEM:'1024M',GHIDRA_MAXMEM:'1024M',TMPDIR:temporary}});
// Deliberately no --engines. RECarve consumes the files; only REA launches Ghidra.
const carveTransport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],cwd:out,stderr:'pipe',env:common});
const rea=new Client({name:'independent-rea-native-test',version:'1'}),carve=new Client({name:'independent-carve-native-test',version:'1'}),diagnostics={rea:'',carve:''};
for(const [key,t] of [['rea',reaTransport],['carve',carveTransport]])t.stderr?.on('data',b=>{diagnostics[key]=(diagnostics[key]+b.toString()).slice(-8000);});
const unwrap=r=>{if(r.isError)throw new Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return r.structuredContent??JSON.parse(r.content.find(c=>c.type==='text').text);};
const call=async(client,name,args)=>unwrap(await client.callTool({name,arguments:args},undefined,{timeout:600000}));
let reaClosed=false,reaPid,carvePid;
try{
 await rea.connect(reaTransport);await carve.connect(carveTransport);reaPid=reaTransport.pid;carvePid=carveTransport.pid;assert.ok(reaPid&&carvePid);assert.notEqual(reaPid,carvePid);
 const rTools=(await rea.listTools()).tools,cTools=(await carve.listTools()).tools;assert.ok(!cTools.some(t=>t.name==='procedure_pseudo_code'));assert.ok(!rTools.some(t=>t.name==='carve_import_rea_native'));
 const opened=await call(rea,'open_binary',{path:binary,provider_id:'ghidra'});await save('open.json',opened);
 const code=await call(rea,'procedure_pseudo_code',{procedure:selector}),info=await call(rea,'procedure_info',{procedure:selector}),otherInfo=await call(rea,'procedure_info',{procedure:other});
 assert.equal(code.subject.digest.sha256,original.sha256);assert.equal(info.subject.digest.sha256,original.sha256);
 for(const [name,record] of [['code',code],['info',info],['other-info',otherInfo]])await writeFile(path.join(producer,name+'.json'),JSON.stringify(record,null,2)+'\n');
 await call(rea,'close_binary',{});await rea.close();reaClosed=true;
 console.log(JSON.stringify({stage:'REA closed after real native code/info export',rea:reaPackage.version,provider:code.provider,bytes:original.bytes}));
 const reversed=await call(carve,'carve_reverse',{target:'input/parking',goal:'Extract the local parking fee arithmetic and preserve defined signed32-bit wrap behavior',out:'work'});assert.equal(reversed.status,'ready-for-analysis');
 const badSelector=await carve.callTool({name:'carve_import_rea_native',arguments:{workspace:'work',file:'parking',code:'producer/code.json',info:'producer/other-info.json'}});assert.equal(badSelector.isError,true);assert.match(badSelector.content.find(c=>c.type==='text').text,/exact selector/);
 const changed=structuredClone(code);changed.normalized_result+='\n/* edited after capture */';await writeFile(path.join(producer,'edited.json'),JSON.stringify(changed));
 const badId=await carve.callTool({name:'carve_import_rea_native',arguments:{workspace:'work',file:'parking',code:'producer/edited.json',info:'producer/info.json'}});assert.equal(badId.isError,true);assert.match(badId.content.find(c=>c.type==='text').text,/semantic ID/);await save('negative-imports.json',{differentSelector:badSelector,editedRecord:badId});
 const imported=await call(carve,'carve_import_rea_native',{workspace:'work',file:'parking',code:'producer/code.json',info:'producer/info.json'});assert.equal(imported.provider.name,'rea');assert.equal(imported.startsRea,false);assert.equal(imported.executesTarget,false);
 const observed=await call(carve,'carve_observation',{workspace:'work',id:imported.observationId});assert.equal(observed.externalEvidence.codeEvidenceId,code.evidence_id);assert.equal(observed.truncated,false);assert.match(observed.text,/0x19|25/);
 const context=await call(carve,'carve_context',{workspace:'work',ids:[imported.observationId]});assert.equal(context.calleeExpansionLimited,true);
 const graph=await call(carve,'carve_trace',{workspace:'work',id:imported.observationId});assert.equal(graph.relationshipsIncomplete,true);
 const menu=await call(carve,'carve_features',{workspace:'work',query:'parking_fee'});assert.equal(menu.items[0].basis,'recorded-code-lead');
 await save('import.json',imported);await save('context.json',context);await save('boundary.json',graph);await save('feature-menu.json',menu);
 // Preserve raw producer files at a different path; the importer must use its
 // owned snapshot after the original paths and REA process cease to exist.
 await rename(producer,path.join(out,'producer-archived'));await assert.rejects(()=>access(path.join(producer,'code.json')));
 const implementation=path.join(out,'fee.mjs');await writeFile(implementation,`export function fee(minutes,member){if(!Number.isInteger(minutes)||minutes<-2147483648||minutes>2147483647||!Number.isInteger(member)||member<-2147483648||member>2147483647)throw new RangeError('signed32 arguments required');if(minutes<0)return -1;if(minutes<16)return 0;const blocks=Math.trunc(((minutes+14)|0)/15);const amount=member!==0?Math.trunc(Math.imul(blocks,200)/10):Math.imul(blocks,25);return Math.min(amount,300);}\n`);
 await save('contract.json',{schema:'carve/reconstruction@1',goal:'Reuse the defined signed32 parking fee arithmetic from the selected compiled executable',file:'parking',evidenceIds:[imported.observationId],behavior:{description:'Agent reconstruction of one original arithmetic function based on complete REA Ghidra code/info Evidence; source was compiled with -fwrapv.',inputDomain:'Two signed32 integers: minutes and member flag.',outputDomain:'One JSON integer. Negative minutes return-1; up to15minutes returns0; intermediate integer overflow retains original compiled wrap behavior.'},dependencies:[],unknowns:['Source-owned CLI fixture only. Imported call/reference relationships are explicitly incomplete; no whole-app or general state/OS dependency claim.','Canonical Evidence/profile commitments bind local records, not a signed attestation of producer execution or all-input behavior.']});
 const packaged=await call(carve,'carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'fee.mjs',export:'fee',out:'fee-package'});await save('packaged.json',packaged);assert.equal(packaged.evidence[0].provider.codeEvidenceId,code.evidence_id);
 const cases=[];for(const minutes of [-2147483648,-1,0,14,15,16,29,30,31,149,150,151,179,180,181,2147483633,2147483646,2147483647])for(const member of [0,1,-1])cases.push({name:`minutes=${minutes},member=${member}`,args:[minutes,member]});
 let seed=99871;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed|0;};while(cases.length<160)cases.push({name:'signed32 boundary '+cases.length,args:[rand(),rand()]});await save('cases.json',cases);
 await save('reference.json',{schema:'carve/reference@1',command:[binary],mode:'argv-values',scope:'target-cli',description:'Actual source-owned compiled Mach-O/ELF executable; direct signed32 decimal argv values, no wrapper/interpreter/reference source code.',boundFiles:[]});
 const comparison=await call(carve,'carve_verify_reconstruction',{workspace:'work',package:'fee-package',cases:'cases.json',reference:'reference.json',execute:true,fullReport:true,timeoutMs:10000});await save('comparison.json',comparison);
 if(comparison.status!=='passed-supplied-cases')console.error(JSON.stringify(comparison.results.filter(r=>!r.passed).slice(0,3)));
 assert.equal(comparison.status,'passed-supplied-cases');assert.equal(comparison.total,160);assert.equal(comparison.verifiedScope,'selected-original-cli-cases');
 const stored=await call(carve,'carve_library_add',{package:'fee-package',library:'functions',name:'parking-fee',title:'REA native parking fee reconstruction',description:'One source-owned native arithmetic operation with160original executable comparisons; no whole-app/state/OS equivalence.',tags:['fee','native','rea']});
 const found=await call(carve,'carve_library_find',{library:'functions',query:'fee'});assert.equal(found.total,1);const current=await call(carve,'carve_library_get',{library:'functions',name:'parking-fee'});assert.equal(current.integrity,'matches-catalogued-manifest-and-files');
 const module=await import(pathToFileURL(path.join(stored.package,'index.mjs')));assert.equal(module.capability(16,1),40);
 const reused=new Client({name:'native-reuse-without-original-root',version:'1'});await reused.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',path.join(out,'functions')],env:common,stderr:'pipe'}));
 try{const value=await call(reused,'carve_invoke',{package:'parking-fee',args:[16,1],execute:true});assert.equal(value.value,40);}finally{await reused.close();}
 const after=await hashFile(binary);assert.equal(after.sha256,original.sha256);
 const report={schema:'carve/rea-native-e2e@1',status:'passed',checkedAt:new Date().toISOString(),version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,out,source:{...original,file:binary,compiledFrom:'examples/native-app/parking.c',flags:['-O2','-fwrapv'],unchangedAfter:true},rea:{packageVersion:reaPackage.version,tools:rTools.length,pid:reaPid,provider:code.provider,codeEvidenceId:code.evidence_id,infoEvidenceId:info.evidence_id,closedBeforeCarveImport:true},carve:{tools:cTools.length,pid:carvePid,engineConfiguration:false,startsRea:false,toolCatalogMerged:false},imported,negativeChecks:{differentRealProcedureInfoRejected:true,editedSemanticRecordRejected:true},producerPathsMovedToArchiveBeforeReconstruction:true,comparison:{passed:comparison.passed,total:comparison.total,scope:comparison.verifiedScope,report:path.join(out,'comparison.json')},reuse:{package:stored.package,libraryFindGet:true,directImport:true,libraryOnlyMcpRoot:true},context:{bytes:context.receipt.responseBytes,missingRelationshipsExplicit:graph.relationshipsIncomplete},limitations:['One source-owned native CLI, not third-party app or all-provider validation. Only the explicit REA Ghidra complete function/code profile is imported.','RECarve receives serialized files after the separate REA process closes; no shared/private session access, proxy, merged MCP or implicit provider installation.','Call/reference/OS/state boundaries are not imported as complete; no claim of generic cross-module closure or general equivalence. Canonical hashes do not authenticate the producer.']};
 await save('report.json',report);await writeFile(path.join(root,'artifacts/rea-native-verification-summary.json'),JSON.stringify({status:'passed',version:report.version,report:path.join(out,'report.json'),function:stored.package,cases:160},null,2)+'\n');
 console.log(JSON.stringify({status:'passed',rea:reaPackage.version,provider:code.provider.id,cases:160,scope:comparison.verifiedScope,carveStartsRea:false,report:path.join(out,'report.json')}));
}catch(error){await save('failure.json',{message:error.stack});throw error;}finally{if(!reaClosed)await rea.close();await carve.close();await save('diagnostics.json',diagnostics);}
