import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,access,realpath} from 'node:fs/promises';
import {tmpdir,totalmem,availableParallelism} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {resolveEngineResources,heapExhausted,hostEngineLimits} from '../dist/engine-resources.js';
import {nativeAnalysis} from '../dist/native.js';
import {managedAnalysis} from '../dist/managed.js';
import {enqueueAnalysis,runAnalysisQueue,queryAnalysisJobs} from '../dist/analysis-queue.js';
import {readEngineConfiguration,readAndroidConfiguration} from '../dist/engine-config.js';
const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
const present=async file=>{try{await access(file);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};

test('engine resources default to the previous fixed launch budget and reject host-exceeding or malformed requests before any engine starts',async()=>{
 const host=hostEngineLimits();assert.equal(host.memoryMiB,Math.floor(totalmem()/1048576));assert.equal(host.parallelism,availableParallelism());
 const defaults=resolveEngineResources();assert.equal(defaults.heapMiB,1024);assert.equal(defaults.threads,2);assert.deepEqual(defaults.requested,{heapMiB:null,threads:null});
 assert.deepEqual(resolveEngineResources({heapMiB:host.heapLimitMiB,threads:host.parallelism}).requested,{heapMiB:host.heapLimitMiB,threads:host.parallelism});
 assert.throws(()=>resolveEngineResources({heapMiB:host.heapLimitMiB+1}),/host's engine heap limit/);
 assert.throws(()=>resolveEngineResources({threads:host.parallelism+1}),/available parallelism/);
 for(const bad of [{heapMiB:255},{heapMiB:1.5},{threads:0},{cpu:2}])assert.throws(()=>resolveEngineResources(bad));
 const base={file:'unused',ghidra:'unused',javaHome:'unused'};
 await assert.rejects(()=>nativeAnalysis('never-open-this-directory',{...base,resources:{threads:0}}),/threads/);
 await assert.rejects(()=>managedAnalysis('never-open-this-directory',{file:'unused',jadx:'unused',javaHome:'unused',resources:{heapMiB:host.heapLimitMiB+1}}),/heap limit/);
});

test('heap exhaustion scanning reads the whole log, including a marker split across stream chunks',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-heap-log-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const marker='java.lang.OutOfMemoryError';const split=path.join(root,'split.log'),clean=path.join(root,'clean.log');
 await writeFile(split,'x'.repeat(65536-10)+marker+'\n'+'y'.repeat(200000));await writeFile(clean,'java.lang.OutOfMemory but recovered\n'.repeat(5000));
 assert.equal(await heapExhausted(split),true);assert.equal(await heapExhausted(clean),false);
});

async function nativeFixture(t,{oom=false}={}){
 const root=await mkdtemp(path.join(tmpdir(),'carve-native-resources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'workspace'),ghidra=path.join(root,'ghidra'),javaHome=path.join(root,'jdk');
 await mkdir(input);await mkdir(path.join(ghidra,'Ghidra'),{recursive:true});await mkdir(path.join(ghidra,'support'));await mkdir(javaHome);
 await writeFile(path.join(ghidra,'Ghidra/application.properties'),'application.version=0.0-resource-fixture\n');
 const elf=Buffer.alloc(64);elf.writeUInt32BE(0x7f454c46);elf[4]=2;elf[5]=1;elf.writeUInt16LE(2,16);elf.writeUInt16LE(183,18);await writeFile(path.join(input,'tool'),elf);
 const sha=(await hashFile(path.join(input,'tool'))).sha256;const calls=path.join(root,'calls.jsonl'),oomFlag=path.join(root,'oom');if(oom)await writeFile(oomFlag,'');
 // Records the actual launch environment/arguments; emits only a minimal header/end export, not real analysis.
 await writeFile(path.join(ghidra,'support/analyzeHeadless'),`#!${process.execPath}
const fs=require('node:fs');const a=process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify({maxmem:process.env.GHIDRA_HEADLESS_MAXMEM,cpu:a[a.indexOf('-max-cpu')+1],reused:a.includes('-noanalysis')})+'\\n');
if(fs.existsSync(${JSON.stringify(oomFlag)}))console.error('Exception in analyzer thread: java.lang.OutOfMemoryError: Java heap space');
const evidence=a[a.indexOf('-postScript')+2];
fs.writeFileSync(evidence,JSON.stringify({kind:'header',programSha256:${JSON.stringify(sha)},language:'fixture'})+'\\n'+JSON.stringify({kind:'end',functions:0})+'\\n');
`,{mode:0o700});
 await survey(input,{workspace});
 const records=async()=>(await readFile(calls,'utf8')).trim().split('\n').map(line=>JSON.parse(line));
 return{root,workspace,ghidra,javaHome,oomFlag,records};
}

test('native analysis launches Ghidra with the requested heap/threads and records the budget of the completed cached analysis',async t=>{
 const f=await nativeFixture(t);const options={file:'tool',ghidra:f.ghidra,javaHome:f.javaHome};
 const first=await nativeAnalysis(f.workspace,{...options,resources:{heapMiB:512,threads:1}});
 assert.equal(first.reusedAnalysis,false);assert.equal(first.resources.heapMiB,512);assert.equal(first.resources.threads,1);assert.deepEqual(first.analysisResources,{heapMiB:512,threads:1});
 const second=await nativeAnalysis(f.workspace,options);
 assert.equal(second.reusedAnalysis,true);assert.equal(second.resources.heapMiB,1024);assert.equal(second.resources.threads,2);assert.deepEqual(second.analysisResources,{heapMiB:512,threads:1});
 assert.equal(second.provider.analysisProfile,first.provider.analysisProfile,'resources must not change analysis cache identity');
 assert.deepEqual(await f.records(),[{maxmem:'512M',cpu:'1',reused:false},{maxmem:'1024M',cpu:'2',reused:true}]);
});

test('a logged Ghidra OutOfMemoryError fails even with exit 0 and never marks the analysis cache completed',async t=>{
 const f=await nativeFixture(t,{oom:true});const options={file:'tool',ghidra:f.ghidra,javaHome:f.javaHome};
 await assert.rejects(()=>nativeAnalysis(f.workspace,{...options,resources:{heapMiB:256}}),/OutOfMemoryError with heapMiB 256.*not recorded as completed/);
 await rm(f.oomFlag);
 const retry=await nativeAnalysis(f.workspace,{...options,resources:{heapMiB:768}});
 assert.equal(retry.reusedAnalysis,false,'the heap-failed project must be re-imported');assert.deepEqual(retry.analysisResources,{heapMiB:768,threads:2});
 assert.deepEqual((await f.records()).map(r=>r.reused),[false,false]);
});

async function jadxFixture(t,{block=false}={}){
 const root=await mkdtemp(path.join(tmpdir(),'carve-jadx-resources-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'workspace');await mkdir(input);
 const engines={jadx:path.join(root,'engine/bin/jadx'),javaHome:path.join(root,'jdk')};
 await mkdir(path.dirname(engines.jadx),{recursive:true});await mkdir(path.join(root,'engine/lib'));await writeFile(path.join(root,'engine/lib/jadx-test.jar'),'resource fixture, not a real decompiler');
 await mkdir(path.join(engines.javaHome,'bin'),{recursive:true});await writeFile(path.join(engines.javaHome,'bin/java'),'resource fixture');
 const calls=path.join(root,'calls.jsonl'),oomFlag=path.join(root,'oom'),started=path.join(root,'started'),release=path.join(root,'release');
 await writeFile(engines.jadx,`#!${process.execPath}
const fs=require('node:fs');const path=require('node:path');const a=process.argv.slice(2);
if(a.includes('--version')){console.log('1.5.6');process.exit(0);}
fs.appendFileSync(${JSON.stringify(calls)},JSON.stringify({opts:process.env.JADX_OPTS,tool:process.env.JAVA_TOOL_OPTIONS.includes('-Xmx'),threads:a[a.indexOf('--threads-count')+1]})+'\\n');
if(fs.existsSync(${JSON.stringify(oomFlag)}))console.error('java.lang.OutOfMemoryError: Java heap space');
const finish=()=>{const out=a[a.indexOf('--output-dir')+1];fs.mkdirSync(path.join(out,'sources'),{recursive:true});fs.writeFileSync(path.join(out,'sources/Test.java'),'class Test {}');};
if(${block}){fs.writeFileSync(${JSON.stringify(started)},'');const timer=setInterval(()=>{if(fs.existsSync(${JSON.stringify(release)})){clearInterval(timer);finish();}},20);}else finish();
`,{mode:0o700});
 await writeFile(path.join(input,'classes.dex'),Buffer.from('dex\n035\0','latin1'));await writeFile(path.join(input,'module.js'),'export const x=1;\n');await survey(input,{workspace});
 const config=path.join(root,'engines.json');await writeFile(config,JSON.stringify(engines));
 const records=async()=>(await readFile(calls,'utf8')).trim().split('\n').map(line=>JSON.parse(line));
 return{root,workspace,engines,config,oomFlag,started,release,records};
}

test('JADX receives heap through its launcher options and threads through its CLI; a logged heap failure is not indexed',async t=>{
 const f=await jadxFixture(t);const options={file:'classes.dex',...f.engines};
 const report=await managedAnalysis(f.workspace,{...options,resources:{heapMiB:640,threads:1}});assert.equal(report.status,'sources-exported');assert.equal(report.resources.heapMiB,640);
 await writeFile(f.oomFlag,'');await assert.rejects(()=>managedAnalysis(f.workspace,options),/JADX reported java.lang.OutOfMemoryError with heapMiB 1024/);
 assert.deepEqual(await f.records(),[{opts:'-Xmx640m',tool:false,threads:'1'},{opts:'-Xmx1024m',tool:false,threads:'2'}]);
});

test('queued requests carry optional resources without changing older request identity and pass through host admission',async t=>{
 const f=await jadxFixture(t);
 await assert.rejects(()=>enqueueAnalysis(f.workspace,[{file:'module.js',resources:{heapMiB:512}}],f.engines),/apply only to Ghidra or JADX/);
 await assert.rejects(()=>enqueueAnalysis(f.workspace,[{file:'classes.dex',resources:{threads:availableParallelism()+1}}],f.engines),/available parallelism/);
 const plain=(await enqueueAnalysis(f.workspace,[{file:'classes.dex'}],f.engines)).items[0];
 const budgeted=(await enqueueAnalysis(f.workspace,[{file:'classes.dex',resources:{heapMiB:512,threads:1}}],f.engines)).items[0];
 assert.notEqual(plain.id,budgeted.id);
 const stored=(await queryAnalysisJobs(f.workspace,{id:plain.id})).items[0];assert.equal('resources' in stored.request,false);
 const admitted=[];let released=0;
 const batch=await runAnalysisQueue(f.workspace,{engines:f.engines,maxJobs:2,admit:resources=>{admitted.push([resources.heapMiB,resources.threads]);return()=>{released++;};}});
 assert.deepEqual(batch.items.map(item=>item.status),['completed','completed']);assert.equal(released,2);
 assert.deepEqual(admitted.sort(),[[1024,2],[512,1]].sort());
 assert.deepEqual((await f.records()).map(r=>r.opts).sort(),['-Xmx1024m','-Xmx512m']);
});

test('one MCP server refuses a concurrent engine call whose heap would exceed the shared host reservation',async t=>{
 const f=await jadxFixture(t,{block:true});const limit=hostEngineLimits().heapLimitMiB;const heapMiB=Math.floor(limit/2)+1;
 const client=new Client({name:'resource-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root,'--engines',f.config],stderr:'pipe'}));
 const first=client.callTool({name:'carve_managed',arguments:{workspace:'workspace',file:'classes.dex',heapMiB}});
 try{
 const deadline=Date.now()+15000;while(!await present(f.started)){if(Date.now()>deadline)assert.fail('First engine call did not start.');await new Promise(r=>setTimeout(r,20));}
 const second=await client.callTool({name:'carve_managed',arguments:{workspace:'workspace',file:'classes.dex',heapMiB}});
 assert.equal(second.isError,true);assert.match(second.content[0].text,/Engine heap budget busy/);
 await writeFile(f.release,'');const done=await first;assert.equal(done.isError,undefined,done.content[0].text);assert.equal(JSON.parse(done.content[0].text).resources.heapMiB,heapMiB);
 const after=await client.callTool({name:'carve_managed',arguments:{workspace:'workspace',file:'classes.dex',heapMiB}});assert.equal(after.isError,undefined,after.content[0].text);
 assert.equal((await f.records()).length,2,'the refused call must not launch JADX');
 }finally{await writeFile(f.release,'');await first.catch(()=>{});await client.close();}
});

test('engine configuration paths are resolved relative to the configuration file, so a moved installation keeps working through MCP',async t=>{
 const f=await jadxFixture(t);const moved=path.join(f.root,'conf');await mkdir(moved);
 const config=path.join(moved,'engines.json');await writeFile(config,JSON.stringify({jadx:'../engine/bin/jadx',javaHome:path.join(f.root,'jdk'),note:'kept'}));
 const resolved=await readEngineConfiguration(config);assert.equal(resolved.jadx,path.join(await realpath(f.root),'engine/bin/jadx'));assert.equal(resolved.javaHome,path.join(f.root,'jdk'));assert.equal(resolved.note,'kept');
 const android=path.join(moved,'android.json');await writeFile(android,JSON.stringify({sdkRoot:'sdk',adb:'sdk/platform-tools/adb',serial:'emulator-5580',serverPort:5039}));
 const device=await readAndroidConfiguration(android);assert.equal(device.adb,path.join(await realpath(moved),'sdk/platform-tools/adb'));assert.equal(device.serial,'emulator-5580');assert.equal(device.serverPort,5039);
 for(const bad of ['[]','{"jadx":""}','{"javaHome":3}']){await writeFile(path.join(moved,'bad.json'),bad);await assert.rejects(()=>readEngineConfiguration(path.join(moved,'bad.json')),/Configuration/);}
 // A different working directory proves the paths are not resolved against the server's cwd.
 const client=new Client({name:'relative-config-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root,'--engines',config],cwd:tmpdir(),stderr:'pipe'}));
 try{const result=await client.callTool({name:'carve_managed',arguments:{workspace:'workspace',file:'classes.dex'}});assert.equal(result.isError,undefined,result.content[0].text);assert.equal(JSON.parse(result.content[0].text).status,'sources-exported');}
 finally{await client.close();}
});
