import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,mkdtemp,readFile,writeFile,cp} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {survey,hashFile} from '../dist/survey.js';
import {nativeAnalysis} from '../dist/native.js';
import {managedAnalysis} from '../dist/managed.js';
import {hostEngineLimits} from '../dist/engine-resources.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const execute=promisify(execFile);
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const enginesFile=process.argv[2]??path.join(root,'artifacts/engines/config.json');const engines=await readEngineConfiguration(enginesFile);
const jq=path.join(root,'artifacts/third-party/jq-1.8.2/jq-macos-arm64'),dex=path.join(root,'artifacts/third-party/scrcpy-5.0.1/container-work/containers/764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536/content/classes.dex');
assert.equal((await hashFile(jq)).sha256,'2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e','pinned official jq release');
assert.equal((await hashFile(dex)).sha256,'a7e811763dc6352cfcc2e9d6f9e20724219b68af8e8a7a11271d8e00fe72ff8d','pinned scrcpy server classes.dex member');
const out=await mkdtemp(path.join(root,'artifacts/engine-resources-e2e-'));const input=path.join(out,'input'),workspace=path.join(out,'workspace');await mkdir(input);
await cp(jq,path.join(input,'jq'));await cp(dex,path.join(input,'classes.dex'));await survey(input,{workspace});

// Observes the actual launched JVM command line inside the registered engine process group.
function observer(){
 const seen=new Map();let timer;
 const sample=async group=>{try{const {stdout}=await execute('ps',['-ww','-A','-o','pid=,pgid=,args='],{maxBuffer:16*1024*1024,env:{PATH:process.env.PATH,LC_ALL:'C'}});
  for(const line of stdout.split('\n')){const match=/^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line);if(match&&Number(match[2])===group&&/\/bin\/java\s/.test(match[3]))seen.set(match[1],match[3]);}}catch{}};
 return{onProcess:guard=>{clearInterval(timer);timer=setInterval(()=>sample(guard.processGroup),100);},stop:()=>clearInterval(timer),javaArgs:()=>[...seen.values()]};
}
const mainJvm=(args,main)=>args.filter(a=>a.includes(main));
const lastHeap=args=>{const all=[...args.matchAll(/-Xmx(\d+[mMgG])/g)].map(m=>m[1]);return all.at(-1)??null;};
async function observed(run){const watch=observer();try{const result=await run(watch.onProcess);return{result,javaArgs:watch.javaArgs()};}finally{watch.stop();}}
const checks=[];
const ghidraOptions={file:'jq',ghidra:engines.ghidra,javaHome:engines.javaHome,limit:5,timeoutMs:1800000};
const first=await observed(onProcess=>nativeAnalysis(workspace,{...ghidraOptions,resources:{heapMiB:1536,threads:1},onProcess}));
assert.equal(first.result.reusedAnalysis,false);assert.equal(first.result.autoAnalysisPerformed,true);assert.equal(first.result.status,'inventory-page-exported');
assert.deepEqual(first.result.analysisResources,{heapMiB:1536,threads:1});
const ghidraMain='ghidra.app.util.headless.AnalyzeHeadless';const firstMain=mainJvm(first.javaArgs,ghidraMain);
assert.ok(firstMain.length,'actual Ghidra analysis JVM observed: '+JSON.stringify(first.javaArgs));assert.ok(firstMain.every(a=>lastHeap(a)==='1536M'&&/-max-cpu 1(\s|$)/.test(a)),'Ghidra analysis JVM effective -Xmx and -max-cpu');
const engineLog=await readFile(path.join(path.dirname(first.result.evidence),'engine.log'),'utf8');
checks.push({name:'ghidra-fresh-auto-analysis',heapArgument:'-Xmx1536M',maxCpuArgument:'1',analysisJvms:firstMain.length,observedJavaCommandLines:first.javaArgs,functions:first.result.functions,analysisResources:first.result.analysisResources,heapExhausted:engineLog.includes('java.lang.OutOfMemoryError')});
const second=await observed(onProcess=>nativeAnalysis(workspace,{...ghidraOptions,onProcess}));
assert.equal(second.result.reusedAnalysis,true);assert.equal(second.result.provider.analysisProfile,first.result.provider.analysisProfile);
assert.deepEqual(second.result.analysisResources,{heapMiB:1536,threads:1});assert.equal(second.result.resources.heapMiB,1024);
const secondMain=mainJvm(second.javaArgs,ghidraMain);assert.ok(secondMain.length&&secondMain.every(a=>lastHeap(a)==='1024M'&&/-max-cpu 2(\s|$)/.test(a)),'default Ghidra JVM heap on reused export: '+JSON.stringify(second.javaArgs));
checks.push({name:'ghidra-reused-export-defaults',heapArgument:'-Xmx1024M',analysisJvms:secondMain.length,observedJavaCommandLines:second.javaArgs,analysisResources:second.result.analysisResources});
const ready=JSON.parse(await readFile(path.join(workspace,'analysis-cache/ghidra',first.result.provider.analysisProfile,'ready.json'),'utf8'));assert.deepEqual(ready.analysisResources,{heapMiB:1536,threads:1});
const jadxOptions={file:'classes.dex',jadx:engines.jadx,javaHome:engines.javaHome,class:'com.genymobile.scrcpy.model.Size'};
const managed=await observed(onProcess=>managedAnalysis(workspace,{...jadxOptions,resources:{heapMiB:768,threads:1},onProcess}));
assert.equal(managed.result.status,'sources-exported');assert.equal(managed.result.resources.heapMiB,768);
const jadxMain=mainJvm(managed.javaArgs,'jadx.cli.JadxCLI');assert.ok(jadxMain.length,'actual JADX JVM observed: '+JSON.stringify(managed.javaArgs));
assert.ok(jadxMain.every(a=>lastHeap(a)==='768m'),'JADX JVMs effective -Xmx overrides MaxRAMPercentage default: '+JSON.stringify(jadxMain));
// The short --version launch carries the same heap; only the decompilation JVM carries worker threads.
const decompiler=jadxMain.filter(a=>!/JadxCLI --version$/.test(a));assert.ok(decompiler.length&&decompiler.every(a=>/--threads-count 1(\s|$)/.test(a)),'JADX decompilation JVM threads: '+JSON.stringify(jadxMain));
checks.push({name:'jadx-direct-api',heapArgument:'-Xmx768m',threadsArgument:'1',jadxJvms:jadxMain.length,observedJavaCommandLines:managed.javaArgs,sources:managed.result.sources});
const cli=await execute(process.execPath,[path.join(root,'dist/cli.js'),'managed',workspace,'--file','classes.dex','--jadx',engines.jadx,'--java-home',engines.javaHome,'--class','com.genymobile.scrcpy.model.Size','--heap-mib','640','--threads','1'],{maxBuffer:64*1024*1024});
const cliReport=JSON.parse(cli.stdout);assert.equal(cliReport.resources.heapMiB,640);assert.equal(cliReport.resources.threads,1);
const cliLog=await readFile(path.join(path.dirname(cliReport.output),'engine.log'),'utf8');
checks.push({name:'jadx-cli-flags',heapMiB:cliReport.resources.heapMiB,threads:cliReport.resources.threads,status:cliReport.status,heapExhausted:cliLog.includes('java.lang.OutOfMemoryError')});
const report={schema:'carve/engine-resources-e2e@1',status:'passed',checkedAt:new Date().toISOString(),node:process.version,host:hostEngineLimits(),
 inputs:{jq:{sha256:'2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e'},scrcpyClassesDex:{sha256:'a7e811763dc6352cfcc2e9d6f9e20724219b68af8e8a7a11271d8e00fe72ff8d'}},checks,
 scope:'Actual Ghidra/JADX JVM command lines carried the requested maximum heap and worker budgets, and completed-analysis resources were recorded and preserved on reuse. Peak memory, speed, a real engine heap exhaustion and large-binary recovery were not measured or established.'};
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({status:report.status,report:path.join(out,'report.json'),checks},null,2));
