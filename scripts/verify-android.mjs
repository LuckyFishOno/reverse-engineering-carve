import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFile,writeFile,mkdir,mkdtemp,cp,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {reverseTask} from '../dist/reverse.js';
import {unpackContainer} from '../dist/container.js';
import {managedAnalysis} from '../dist/managed.js';
import {searchObservations,readObservation} from '../dist/native.js';
import {reconstruct} from '../dist/reconstruction.js';
import {hashFile} from '../dist/survey.js';
import {invoke} from '../dist/runtime.js';
import {readEngineConfiguration,readAndroidConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const {values}=parseArgs({options:{engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')},runtime:{type:'string',default:path.join(root,'artifacts/android/config.json')},serial:{type:'string'},port:{type:'string'}}});
const engines=await readEngineConfiguration(values.engines);const device=await readAndroidConfiguration(values.runtime);
const serial=values.serial??device.serial;if(!serial)throw new Error('Select an explicit Android --serial or configure serial in the runtime file.');
const serverPort=Number(values.port??device.serverPort??5037);
const version='5.0.1';const expected='764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536';
const url=`https://github.com/Genymobile/scrcpy/releases/download/v${version}/scrcpy-server-v${version}`;
const upstream=path.join(root,'artifacts/third-party',`scrcpy-${version}`);await mkdir(upstream,{recursive:true});
const cached=path.join(upstream,`scrcpy-server-v${version}`);
try{await readFile(cached);}catch(error){if(error.code!=='ENOENT')throw error;const response=await fetch(url);if(!response.ok)throw new Error('Upstream release download failed');await writeFile(cached,Buffer.from(await response.arrayBuffer()));}
assert.equal((await hashFile(cached)).sha256,expected,'pinned official release digest');
const license=path.join(upstream,'LICENSE');try{await readFile(license);}catch(error){if(error.code!=='ENOENT')throw error;const response=await fetch(`https://raw.githubusercontent.com/Genymobile/scrcpy/v${version}/LICENSE`);if(!response.ok)throw new Error('Upstream license download failed');await writeFile(license,await response.text());}
const out=await mkdtemp(path.join(root,'artifacts/android-e2e-'));const inputs=path.join(out,'inputs');await mkdir(inputs);const artifact=path.join(inputs,'scrcpy-server');await cp(cached,artifact);
const outer=await reverseTask(artifact,{goal:'Extract software-only video size constraints from the released Android server',out:path.join(out,'container-work')});
const unpacked=await unpackContainer(outer.workspace,{file:'scrcpy-server'});
const task=await reverseTask(unpacked.content,{goal:'Reconstruct Size.constrain with null encoder capabilities, preserving aspect/clamp/alignment and int32 arithmetic',out:path.join(out,'work')});
const analyses=[];
for(const [className,mode] of [['com.genymobile.scrcpy.model.Size','auto'],['com.genymobile.scrcpy.model.Size','fallback'],['com.genymobile.scrcpy.video.VideoConstraints','auto']]){
 const analysis=await managedAnalysis(task.workspace,{file:'classes.dex',jadx:engines.jadx,javaHome:engines.javaHome,class:className,mode});assert.equal(analysis.status,'sources-exported');analyses.push(analysis);
}
const evidenceIds=[];
for(const item of (await searchObservations(task.workspace,'constrain',100)).items){if(item.kind==='java-class'&&item.name.endsWith('/Size.java'))evidenceIds.push(item.id);}
for(const item of (await searchObservations(task.workspace,'class VideoConstraints',100)).items){if(item.kind==='java-class')evidenceIds.push(item.id);}
assert.ok(evidenceIds.length>=3,'separate class/mode evidence retained');
const evidence=[];for(const id of evidenceIds)evidence.push(await readObservation(task.workspace,id));assert.ok(evidence.some(e=>e.provider.analysisMode==='fallback'&&/goto L/.test(e.text)));
const source=path.join(out,'source');await mkdir(source);const implementation=path.join(source,'reimplementation.mjs');await cp(path.join(root,'examples/android/scrcpy-size.mjs'),implementation);await cp(license,path.join(source,'LICENSE'));
await writeFile(path.join(source,'package.json'),JSON.stringify({name:'scrcpy-size-reimplementation-input',version:'0.0.0',license:'Apache-2.0',private:true}));
const contract={schema:'carve/reconstruction@1',goal:'Independent scrcpy software video-size constraints',file:'classes.dex',evidenceIds,
 behavior:{description:'Reimplement the released Size.constrain(VideoConstraints, boolean) branch where encoderCapabilities is null; preserve aspect-ratio selection, max-size clamp, alignment and Java int32 overflow.',inputDomain:'width/height/alignment are positive signed-int32 values; maxSize is signed-int32 (<=0 disables limiting); preserveAspect is boolean.',outputDomain:'[width,height] JSON integer pair'},
 dependencies:[{name:'Java int32 arithmetic',status:'reimplemented',detail:'Math.imul and truncating integer division preserve the selected bytecode arithmetic.'}],
 unknowns:['The codec-capability branch, capture/encoding, UI integration, remote server behavior and non-int32 inputs are outside this selected boundary.','Only the identified Android runtime and supplied cases are compared; other devices and untested inputs remain unknown.']};
const contractFile=path.join(out,'contract.json');await writeFile(contractFile,JSON.stringify(contract,null,2));const pkg=path.join(out,'size-tool');await reconstruct(task.workspace,{contract:contractFile,implementation,export:'constrainVideoSize',out:pkg});
const firstCode=evidence.find(e=>e.name.endsWith('/Size.java')&&e.provider.analysisMode==='auto');assert.ok(firstCode);
const repeated=await managedAnalysis(task.workspace,{file:'classes.dex',jadx:engines.jadx,javaHome:engines.javaHome,class:'com.genymobile.scrcpy.model.Size'});analyses.push(repeated);
const stillBound=await readObservation(task.workspace,firstCode.id);assert.equal(stillBound.evidence,firstCode.evidence);assert.equal(stillBound.evidenceSha256,firstCode.evidenceSha256,'a repeated JADX export must preserve packaged evidence');
const classes=path.join(out,'harness-classes');const dex=path.join(out,'harness-dex');await mkdir(classes);await mkdir(dex);const exec=promisify(execFile);const java=path.join(engines.javaHome,'bin/java');
const r8=engines.r8??path.join(root,'artifacts/engines/r8-9.5.26.jar');
await exec(path.join(engines.javaHome,'bin/javac'),['--release','8','-Xlint:-options','-d',classes,path.join(root,'examples/android/ScrcpySizeHarness.java')]);
await exec(java,['-cp',r8,'com.android.tools.r8.D8','--min-api','21','--output',dex,path.join(classes,'carve/reference/ScrcpySizeHarness.class')]);
const harness=path.join(dex,'classes.dex');const reference=path.join(out,'reference.json');
await writeFile(reference,JSON.stringify({schema:'carve/android-reference@1',adb:device.adb,serial,serverPort,harness,entryClass:'carve.reference.ScrcpySizeHarness',dependencies:[],description:'RECarve-owned reflection harness calls original released scrcpy DEX Size.constrain with actual Android framework types and null codec capabilities. No copied or recompiled original algorithm.'},null,2));
const cases=[{name:'previously observed landscape resize',args:[1920,1080,1000,8,true],expected:[1000,560]}];
for(const [w,h] of [[1080,1920],[1920,1080],[1919,1079],[1,1],[7,2000],[4096,2160],[2147483647,1337],[65536,65536]])for(const max of [0,1000,2147483647])for(const aspect of [true,false])cases.push({name:`${w}x${h};max=${max};aspect=${aspect}`,args:[w,h,max,8,aspect]});
let seed=123456789;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
while(cases.length<160){const i=cases.length;cases.push({name:`deterministic boundary ${i}`,args:[1+rand()%100000,1+rand()%100000,[0,-1,1,7,1024,4097,2147483647][rand()%7],[1,7,8,16,256][rand()%5],Boolean(rand()%2)]});}
const caseFile=path.join(out,'cases.json');await writeFile(caseFile,JSON.stringify(cases,null,2));
const client=new Client({name:'carve-android-integration',version:'1.0.0'});const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],stderr:'pipe'});
let comparison;try{await client.connect(transport);const result=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:'work',package:'size-tool',cases:'cases.json',reference:'reference.json',execute:true,fullReport:true,timeoutMs:5000}},undefined,{timeout:300000});if(result.isError)throw new Error(result.content[0].text);comparison=JSON.parse(result.content[0].text);}finally{await client.close();}
if(comparison.status!=='passed-supplied-cases')console.error(JSON.stringify(comparison.results.filter(r=>!r.passed).slice(0,10),null,2));
assert.equal(comparison.status,'passed-supplied-cases');assert.equal(comparison.verifiedScope,'selected-dex-android-harness-cases');assert.equal(comparison.androidRuntime.selectedDexBytesVerified,true);assert.equal(comparison.androidRuntime.cleanup,'removed');
await rm(inputs,{recursive:true});await rm(unpacked.content,{recursive:true});await rm(source,{recursive:true});
assert.deepEqual(await invoke(pkg,[1920,1080,1000,8,true],{execute:true}),{kind:'return',value:[1000,560]});
const cli=await exec(process.execPath,[path.join(pkg,'cli.mjs'),'[1080,1920,1000,8,true]']);assert.deepEqual(JSON.parse(cli.stdout),[560,1000]);
const capabilityClient=new Client({name:'carve-independent-size-test',version:'1'});const capabilityTransport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve-tool',pkg,'--execute'],stderr:'pipe'});
try{
 await capabilityClient.connect(capabilityTransport);const info=await capabilityClient.callTool({name:'capability_info',arguments:{}});const usage=JSON.parse(info.content[0].text);assert.equal(usage.example.origin,'recorded-reference-comparison');assert.equal(usage.example.scope,'selected-dex-android-harness-cases');assert.ok(usage.reconstruction.unknowns.length);
 const called=await capabilityClient.callTool({name:'capability',arguments:{args:[1080,1920,1000,8,true]}});assert.deepEqual(called.structuredContent,{value:[560,1000]});
}finally{await capabilityClient.close();}
const report={schema:'carve/android-e2e@1',status:'passed',checkedAt:new Date().toISOString(),out,upstream:{project:'Genymobile/scrcpy',version,releaseUrl:url,sha256:expected,license:'Apache-2.0'},analyses,evidence:evidence.map(e=>({id:e.id,provider:e.provider,name:e.name})),comparison,
 independence:{originalInvocationPathsRemoved:true,implementationSourceRemoved:true,analysisSnapshotsRetained:true,cli:true,invoke:true,capabilityMcp:true,recordedUsageExample:true},
 limitations:['One bounded capability from a real third-party released Android server, not arbitrary app reconstruction.','Original DEX executes through a declared reflection harness on the identified Android runtime; UI/server/codec hardware behavior is excluded.','Agent-written reconstruction was prepared from static evidence and tested cases; no autonomous general synthesis engine is claimed.']};
const reportFile=path.join(out,'report.json');await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/android-verification-summary.json'),JSON.stringify({status:report.status,out,report:reportFile,passed:comparison.passed,total:comparison.total,androidApi:comparison.androidRuntime.api,upstream:report.upstream,independent:true},null,2)+'\n');
console.log(JSON.stringify({status:report.status,cases:comparison.total,api:comparison.androidRuntime.api,abi:comparison.androidRuntime.abi,upstream:report.upstream.project,independent:true,report:reportFile},null,2));
