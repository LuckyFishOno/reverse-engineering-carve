import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {queryAnalysisJobs} from '../dist/analysis-queue.js';
import {queryAnalysisRuns,cancelAnalysisRun} from '../dist/analysis-background.js';
import {processGroupMembers,processIsLive} from '../dist/process-lease.js';
const exec=promisify(execFile),root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('The pinned jq component is macOS arm64.');
const engines=path.resolve(process.argv[2]??path.join(root,'artifacts/engines/config.json'));
const out=await mkdtemp(path.join(root,'artifacts/background-e2e-')),input=path.join(out,'input'),workspace=path.join(out,'workspace');await mkdir(input);
const originals=[
 {file:'jq',cache:'artifacts/third-party/jq-1.8.2/jq-macos-arm64',sha256:'2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e'},
 {file:'scrcpy-server.jar',cache:'artifacts/third-party/scrcpy-5.0.1/scrcpy-server-v5.0.1',sha256:'764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536'}
];
for(const source of originals){const from=path.join(root,source.cache);assert.equal((await hashFile(from)).sha256,source.sha256);await cp(from,path.join(input,source.file));}
await writeFile(path.join(input,'module.mjs'),'export const twice=x=>x*2;throw new Error("must never execute");');await survey(input,{workspace});
let sessions=0;const handles=[];
async function mcp(action){
 const client=new Client({name:'background-check',version:'1'});const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',engines],stderr:'pipe'});await client.connect(transport);sessions++;
 const call=async(name,args)=>{const result=await client.callTool({name,arguments:{workspace:'workspace',...args}},undefined,{timeout:15000});if(result.isError)throw new Error(result.content[0].text);return JSON.parse(result.content[0].text);};
 try{return await action(call);}finally{await client.close();}
}
async function cli(args){const result=await exec(process.execPath,[path.join(root,'dist/cli.js'),...args],{cwd:root,timeout:15000,maxBuffer:2*1024*1024});return JSON.parse(result.stdout);}
async function poll(check,ms=1200000){const end=Date.now()+ms;while(Date.now()<end){const result=await check();if(result)return result;await new Promise(r=>setTimeout(r,250));}throw new Error('Actual background condition was not reached.');}
async function run(id){return(await queryAnalysisRuns(workspace,{id})).items[0];}
const requests=[{file:'jq',native:{strings:'utf8bytelength',limit:10}},{file:'scrcpy-server.jar',managed:{class:'com.genymobile.scrcpy.model.Size'}},{file:'module.mjs'}];
try{
 const queued=await mcp(call=>call('carve_analysis_enqueue',{requests}));assert.equal(queued.items.length,3);
 const first=await cli(['queue','start',workspace,'--engines',engines]);handles.push(first.run.id);assert.equal(first.created,true);
 console.log(JSON.stringify({phase:'first-launcher-exited',run:first.run.id}));
 const observed=await poll(async()=>{
  const current=await run(first.run.id);if(!['starting','running'].includes(current.recordedStatus))throw new Error('Run stopped before actual Ghidra observation: '+JSON.stringify(current));
  if(current.liveness.launcher!=='gone'||current.liveness.owner!=='live'||!current.guard)return null;
  const log=await readFile(current.guard.log,'utf8');if(!log.includes('ANALYZING all memory and code'))return null;
  const job=(await queryAnalysisJobs(workspace,{status:'running',limit:1})).items[0];const members=await processGroupMembers(current.guard.processGroup);if(!members.length)return null;
  const executable=path.join(job.provider.paths.javaHome,'bin/java');const ps=await exec('ps',['-ww','-p',members.join(','),'-o','pid=,args='],{maxBuffer:65536});
  for(const line of ps.stdout.split('\n')){const match=/^\s*(\d+)\s+(.+)$/.exec(line);if(!match||!match[2].startsWith(executable+' ')||!match[2].includes('ghidra.app.util.headless.AnalyzeHeadless'))continue;
   const actual=await exec('lsof',['-p',match[1],'-a','-d','txt','-Fn'],{maxBuffer:262144});if(actual.stdout.split('\n').includes('n'+executable))return{owner:current.owner,launcher:current.launcher,guard:current.guard,job:job.id,actualJvm:line.trim(),actualExecutable:executable};
  }return null;
 },300000);
 const duplicate=await mcp(call=>call('carve_analysis_start',{maxJobs:3}));assert.equal(duplicate.created,false);assert.equal(duplicate.run.id,first.run.id);assert.equal(duplicate.run.options.maxJobs,1);
 const cancelling=await mcp(call=>call('carve_analysis_cancel',{id:first.run.id}));assert.equal(cancelling.run.cancelRequested,true);
 await poll(async()=>{const item=await run(first.run.id);return item.recordedStatus==='cancelled'&&item.liveness.owner==='gone'&&item.liveness.supervisor==='gone'&&item.liveness.processGroup==='gone';},30000);
 assert.equal((await queryAnalysisJobs(workspace,{id:observed.job})).items[0].status,'interrupted');console.log(JSON.stringify({phase:'real-ghidra-cancelled',run:first.run.id}));
 // Start from MCP, immediately close the session, then inspect from a separate CLI.
 const resumed=await mcp(call=>call('carve_analysis_start',{maxJobs:3,retry:true}));handles.push(resumed.run.id);assert.equal(resumed.created,true);
 await poll(async()=>!(await processIsLive(resumed.run.launcher)),15000);
 const outside=await cli(['queue','runs',workspace,'--id',resumed.run.id]);assert.equal(outside.total,1);
 await poll(async()=>{const item=await run(resumed.run.id);if(['failed','partial','deadline-exceeded','interrupted'].includes(item.observedStatus))throw new Error('Background batch did not complete: '+JSON.stringify(item));return item.recordedStatus==='completed'&&item.liveness.owner==='gone'&&['gone','unregistered'].includes(item.liveness.supervisor)&&['gone','unregistered'].includes(item.liveness.processGroup);});
 const finished=await mcp(call=>call('carve_analysis_runs',{id:resumed.run.id}));assert.equal(finished.items[0].observedStatus,'completed');
 assert.equal((await hashFile(finished.items[0].result.file)).sha256,finished.items[0].result.sha256);
 const jobs=await mcp(call=>call('carve_analysis_jobs',{limit:20}));assert.equal(jobs.total,3);assert.ok(jobs.items.every(job=>job.status==='completed'));
 const results=[];for(const job of jobs.items){assert.equal((await hashFile(job.result.file)).sha256,job.result.sha256);const result=JSON.parse(await readFile(job.result.file,'utf8'));assert.equal(job.attempt,job.id===observed.job?2:1);if(job.guard){assert.equal(await processIsLive(job.guard.supervisor),false);assert.deepEqual(await processGroupMembers(job.guard.processGroup),[]);}if(job.id===observed.job)assert.equal(result.reusedAnalysis,false);results.push({id:job.id,file:job.file,backend:job.backend,status:result.status,result:job.result,guard:job.guard});}
 assert.ok(results.some(r=>r.backend==='ghidra'&&r.status==='string-page-exported'));assert.ok(results.some(r=>r.backend==='jadx'&&r.status==='sources-exported'));assert.ok(results.some(r=>r.backend==='javascript'&&r.status==='module-inspected'));
 const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
 const report={schema:'carve/background-analysis-check@1',status:'passed',checkedAt:new Date().toISOString(),version,out,workspace,originals,freshMcpSessions:sessions,separateCliSessions:2,runs:handles,cancellation:{...observed,status:'interrupted-then-explicitly-retried',actualGroupStopped:true},results,scope:'Actual jq Ghidra analysis and released scrcpy selected-class JADX plus JS static inspection. CLI exit and normal MCP disconnect preserve the bounded worker. Fresh clients inspect/cancel; actual analyzing JVM identity, supervised cleanup and explicit retry are checked. Does not prove cross-binary boundaries, whole-app reconstruction or runtime equivalence.'};
 await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/background-verification-summary.json'),JSON.stringify({status:'passed',version,report:path.join(out,'report.json'),completedAnalysisRequests:3,freshMcpSessions:sessions},null,2)+'\n');console.log(JSON.stringify({status:'passed',completedAnalysisRequests:3,report:path.join(out,'report.json')}));
}catch(error){
 for(const id of handles){await cancelAnalysisRun(workspace,id);await poll(async()=>{const item=await run(id);return item.liveness.owner==='gone'&&['gone','unregistered'].includes(item.liveness.supervisor)&&['gone','unregistered'].includes(item.liveness.processGroup);},30000);}
 await writeFile(path.join(out,'failure.json'),JSON.stringify({status:'failed',error:error.message,handles},null,2)+'\n');throw error;
}
