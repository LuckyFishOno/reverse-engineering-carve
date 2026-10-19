import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile} from 'node:fs/promises';
import {execFile,spawn} from 'node:child_process';
import {once} from 'node:events';
import {promisify} from 'node:util';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {queryAnalysisJobs} from '../dist/analysis-queue.js';
import {processGroupMembers,processIsLive} from '../dist/process-lease.js';
import {readObservation} from '../dist/native.js';
const exec=promisify(execFile),root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('The pinned jq component is macOS arm64.');
const engines=path.resolve(process.argv[2]??path.join(root,'artifacts/engines/config.json'));
const out=await mkdtemp(path.join(root,'artifacts/queue-e2e-')),input=path.join(out,'input'),workspace=path.join(out,'workspace');await mkdir(input);
const originals=[
 {file:'jq',cache:'artifacts/third-party/jq-1.8.2/jq-macos-arm64',sha256:'2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e'},
 {file:'scrcpy-server.jar',cache:'artifacts/third-party/scrcpy-5.0.1/scrcpy-server-v5.0.1',sha256:'764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536'}
];
for(const source of originals){const from=path.join(root,source.cache);assert.equal((await hashFile(from)).sha256,source.sha256);await cp(from,path.join(input,source.file));}
await writeFile(path.join(input,'module.mjs'),'export const twice=x=>x*2;throw new Error("Static analysis must not execute this module");');await writeFile(path.join(input,'remote-logic.txt'),'Server implementation is unavailable in these client components.');
const inventory=await survey(input,{workspace});assert.equal(inventory.status,'indexed');assert.equal(inventory.files,4);
const requests=[{file:'jq',native:{strings:'utf8bytelength',limit:10}},{file:'jq',native:{function:'10000a8d8'}},{file:'scrcpy-server.jar',managed:{class:'com.genymobile.scrcpy.model.Size'}},{file:'module.mjs'},{file:'remote-logic.txt'}];
let sessions=0;const batches=[];
async function mcp(action){
 const client=new Client({name:'component-queue-check',version:'1'});const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',engines],stderr:'pipe'});await client.connect(transport);sessions++;
 const call=async(name,args)=>{const result=await client.callTool({name,arguments:args},undefined,{timeout:1200000});if(result.isError)throw new Error(result.content[0].text);return JSON.parse(result.content[0].text);};
 try{return await action(call);}finally{await client.close();}
}
const queued=await mcp(call=>call('carve_analysis_enqueue',{workspace:'workspace',requests}));assert.equal(queued.items.filter(i=>i.status==='queued').length,4);assert.equal(queued.items.at(-1).status,'unsupported');
// Cancel an actually analyzing Ghidra JVM, then retry in a separate CLI process.
const cliArgs=[path.join(root,'dist/cli.js'),'queue','run',workspace,'--engines',engines,'--max-jobs','1','--progress'];
const cancelling=spawn(process.execPath,cliArgs,{cwd:root,stdio:['ignore','pipe','pipe']});const stopped=once(cancelling,'close');let stdout='',stderr='';cancelling.stdout.on('data',d=>{stdout+=d;});cancelling.stderr.on('data',d=>{stderr+=d;});let observed;
try{
 for(let i=0;i<1500&&!observed;i++){
  if(cancelling.exitCode!==null||cancelling.signalCode!==null)throw new Error('CLI stopped before actual Ghidra cancellation: '+stderr);
  const active=(await queryAnalysisJobs(workspace,{status:'running',limit:1})).items[0];
  if(active?.backend==='ghidra'&&active.guard&&(await readFile(active.guard.log,'utf8')).includes('ANALYZING all memory and code')){
   const members=await processGroupMembers(active.guard.processGroup);
   if(members.length){
    const javaExecutable=path.join(active.provider.paths.javaHome,'bin/java');const ps=await exec('ps',['-ww','-p',members.join(','),'-o','pid=,args='],{maxBuffer:65536});
    for(const line of ps.stdout.split('\n')){const match=/^\s*(\d+)\s+(.+)$/.exec(line);if(!match||!match[2].startsWith(javaExecutable+' ')||!match[2].includes('ghidra.app.util.headless.AnalyzeHeadless'))continue;
     const actual=await exec('lsof',['-p',match[1],'-a','-d','txt','-Fn'],{maxBuffer:262144});if(actual.stdout.split('\n').includes('n'+javaExecutable))observed={job:active.id,guard:active.guard,actualJvm:line.trim(),actualExecutable:javaExecutable,analysisLog:active.guard.log};
    }
   }
  }
  if(!observed)await new Promise(r=>setTimeout(r,20));
 }
 assert.ok(observed,'actual Ghidra JVM and analysis phase observed');
}finally{cancelling.kill('SIGINT');await stopped;}
assert.equal(cancelling.exitCode,1,stderr);const cancelled=JSON.parse(stdout);assert.equal(cancelled.items[0].status,'interrupted');assert.equal(cancelled.cancelled,true);assert.equal(cancelled.items[0].id,observed.job);assert.equal(await processIsLive(observed.guard.supervisor),false);assert.deepEqual(await processGroupMembers(observed.guard.processGroup),[]);
const cli=await exec(process.execPath,[...cliArgs,'--retry'],{cwd:root,timeout:1200000,maxBuffer:2*1024*1024});batches.push(JSON.parse(cli.stdout));assert.match(cli.stderr,/job-started/);assert.equal(batches[0].items[0].id,observed.job);assert.equal(batches[0].items[0].attempt,2);
batches.push(await mcp(call=>call('carve_analysis_run',{workspace:'workspace',maxJobs:2})));
batches.push(await mcp(call=>call('carve_analysis_run',{workspace:'workspace',maxJobs:2})));
assert.equal(batches.flatMap(b=>b.items).length,4);assert.ok(batches.flatMap(b=>b.items).every(i=>i.status==='completed'));
const jobs=await mcp(call=>call('carve_analysis_jobs',{workspace:'workspace',limit:20}));assert.equal(jobs.total,5);assert.equal(jobs.items.filter(i=>i.status==='unsupported').length,1);
const results=[];
for(const job of jobs.items.filter(i=>i.status==='completed')){
 assert.equal(job.attempt,job.id===observed.job?2:1);assert.equal(job.matchesCurrentInventory,true);assert.equal((await hashFile(job.result.file)).sha256,job.result.sha256);const analyzed=JSON.parse(await readFile(job.result.file,'utf8'));results.push({id:job.id,file:job.file,backend:job.backend,status:analyzed.status,observationIds:analyzed.observationIds??[],guard:job.guard});
 if(job.guard){assert.equal(await processIsLive(job.guard.supervisor),false);assert.deepEqual(await processGroupMembers(job.guard.processGroup),[],'recorded actual engine group has stopped');}
 if(job.id===observed.job)assert.equal(analyzed.reusedAnalysis,false,'interrupted initial import restarts after actual process recovery');
 for(const id of analyzed.observationIds??[]){const observation=await readObservation(workspace,id);assert.equal(observation.sourceSha256,job.sha256);assert.equal(observation.matchesCurrentInventory,true);}
}
assert.ok(results.some(r=>r.backend==='ghidra'&&r.status==='function-exported'));assert.ok(results.some(r=>r.backend==='jadx'&&r.status==='sources-exported'));assert.ok(results.some(r=>r.backend==='javascript'&&r.status==='module-inspected'));
const repeated=await mcp(call=>call('carve_analysis_enqueue',{workspace:'workspace',requests:[requests[0]]}));assert.equal(repeated.items[0].status,'completed');assert.equal(repeated.items[0].id,queued.items[0].id);
assert.equal((await mcp(call=>call('carve_analysis_run',{workspace:'workspace'}))).items.length,0);
const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
const history=await queryAnalysisJobs(workspace,{id:observed.job});assert.deepEqual(history.attempts.map(a=>a.status),['completed','interrupted']);
const report={schema:'carve/component-queue-check@1',status:'passed',checkedAt:new Date().toISOString(),version,out,workspace,originals,componentFiles:4,completedAnalysisRequests:4,unsupportedRequests:1,freshMcpSessions:sessions,separateCliRunners:2,cancellation:{...observed,status:'interrupted-then-retried',previousGroupStopped:true},batchSizes:batches.map(b=>b.items.length),results,executesTarget:false,
 scope:'Real jq native analysis, real released scrcpy selected-class decompilation and static JS inspection across fresh CLI/MCP runners. The jq function selector comes from the previous source-hash-matched registration investigation. This check does not independently rediscover that boundary, reconstruct the whole project, prove cross-component dependencies or compare runtime behavior.'};
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/queue-verification-summary.json'),JSON.stringify({status:report.status,version,report:path.join(out,'report.json'),completedAnalysisRequests:4,freshMcpSessions:sessions},null,2)+'\n');console.log(JSON.stringify({status:'passed',completedAnalysisRequests:4,report:path.join(out,'report.json')},null,2));
