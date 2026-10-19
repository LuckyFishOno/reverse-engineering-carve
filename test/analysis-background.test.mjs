import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,access} from 'node:fs/promises';
import {spawn,fork} from 'node:child_process';
import {once} from 'node:events';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {enqueueAnalysis,queryAnalysisJobs} from '../dist/analysis-queue.js';
import {startAnalysisRun,queryAnalysisRuns,cancelAnalysisRun} from '../dist/analysis-background.js';
import {acquireProcessLease,adoptProcessLease,processIdentity,processIsLive,processGroupMembers} from '../dist/process-lease.js';
import {openRuns,runOptions} from '../dist/analysis-run-state.js';
import {digest} from '../dist/artifact.js';
const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
async function eventually(check,ms=15000){
 const deadline=Date.now()+ms;while(Date.now()<deadline){const result=await check();if(result)return result;await new Promise(r=>setTimeout(r,30));}assert.fail('Actual process/run condition was not reached.');
}
const present=async file=>{try{await access(file);return true;}catch(e){if(e.code==='ENOENT')return false;throw e;}};
async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-background-')),input=path.join(root,'input'),workspace=path.join(root,'workspace');await mkdir(input);
 const engines={jadx:path.join(root,'engine/bin/jadx'),javaHome:path.join(root,'jdk')};
 await mkdir(path.dirname(engines.jadx),{recursive:true});await mkdir(path.join(root,'engine/lib'));await writeFile(path.join(root,'engine/lib/jadx-test.jar'),'process-lifecycle fixture, not a real decompiler');
 await mkdir(path.join(engines.javaHome,'bin'),{recursive:true});await writeFile(path.join(engines.javaHome,'bin/java'),'process-lifecycle fixture');
 const marker=path.join(root,'engine.json'),release=path.join(root,'release');
 const program=`#!${process.execPath}
const fs=require('node:fs');const path=require('node:path');
if(process.argv.includes('--version')){console.log('1.5.6');process.exit(0);}
fs.writeFileSync(${JSON.stringify(marker)},JSON.stringify({pid:process.pid}));
const timer=setInterval(()=>{if(!fs.existsSync(${JSON.stringify(release)}))return;clearInterval(timer);const out=process.argv[process.argv.indexOf('--output-dir')+1];fs.mkdirSync(path.join(out,'sources'),{recursive:true});fs.writeFileSync(path.join(out,'sources/Test.java'),'class Test {}');},20);
`;
 await writeFile(engines.jadx,program,{mode:0o700});await writeFile(path.join(input,'classes.dex'),Buffer.from('dex\n035\0','latin1'));await survey(input,{workspace});
 const config=path.join(root,'engines.json');await writeFile(config,JSON.stringify({...engines,nativeDecompilerSha256:'extra installation metadata'}));const job=(await enqueueAnalysis(workspace,[{file:'classes.dex'}],engines)).items[0];
 const run=async id=>(await queryAnalysisRuns(workspace,{id})).items[0];
 t.after(async()=>{
  const runs=(await queryAnalysisRuns(workspace)).items;
  for(const item of runs){await cancelAnalysisRun(workspace,item.id);if(item.owner&&await processIsLive(item.owner))process.kill(item.owner.pid,'SIGCONT');}
  await eventually(async()=>{
   for(const item of (await queryAnalysisRuns(workspace)).items){if(item.liveness.owner==='live'||item.liveness.supervisor==='live'||item.liveness.processGroup==='live')return false;}return true;
  });
  await rm(root,{recursive:true,force:true});
 });
 return{root,input,workspace,engines,config,marker,release,job,run};
}
async function callCli(args){
 const child=spawn(process.execPath,[cli,...args],{stdio:['ignore','pipe','pipe']});let out='',err='';child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>err+=d);const [code]=await once(child,'close');assert.equal(code,0,err);return JSON.parse(out);
}
async function mcp(f){
 const client=new Client({name:'background-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root,'--engines',f.config],stderr:'pipe'}));
 return{client,call:async(name,args)=>{const result=await client.callTool({name,arguments:{workspace:'workspace',...args}});assert.equal(result.isError,undefined,result.content[0].text);return JSON.parse(result.content[0].text);}};
}
async function engine(f,id){
 await eventually(()=>present(f.marker));return eventually(async()=>{const run=await f.run(id);return run.guard&&run.liveness.processGroup==='live'?run:null;});
}
async function stopped(f,id,status){
 return eventually(async()=>{const run=await f.run(id);return run.recordedStatus===status&&run.liveness.owner==='gone'&&['gone','unregistered'].includes(run.liveness.supervisor)&&['gone','unregistered'].includes(run.liveness.processGroup)?run:null;});
}
test('background CLI exits while work continues; concurrent starts reuse one run and fresh MCP cancels it',async t=>{
 const f=await fixture(t);const started=await callCli(['queue','start',f.workspace,'--engines',f.config]);assert.equal(started.created,true);const id=started.run.id;
 const active=await engine(f,id);assert.equal(active.liveness.launcher,'gone');assert.equal(active.liveness.owner,'live');
 const duplicates=await Promise.all(Array.from({length:4},()=>startAnalysisRun(f.workspace,{engines:f.engines,maxJobs:3})));assert.ok(duplicates.every(item=>item.created===false&&item.run.id===id));assert.equal(duplicates[0].run.options.maxJobs,1);
 const fresh=await mcp(f);try{
  const observed=await fresh.call('carve_analysis_runs',{id});assert.equal(observed.items[0].liveness.processGroup,'live');
  const cancelled=await fresh.call('carve_analysis_cancel',{id});assert.equal(cancelled.run.cancelRequested,true);assert.equal(cancelled.run.cancelReason,'user');
 }finally{await fresh.client.close();}
 const done=await stopped(f,id,'cancelled');assert.equal(done.cancelReason,'user');assert.equal((await queryAnalysisJobs(f.workspace,{id:f.job.id})).items[0].status,'interrupted');
 // Explicit retry creates another batch, preserving the previous interrupted attempt.
 await writeFile(f.release,'finish');const retry=await callCli(['queue','start',f.workspace,'--engines',f.config,'--retry']);assert.notEqual(retry.run.id,id);const completed=await stopped(f,retry.run.id,'completed');assert.equal((await hashFile(completed.result.file)).sha256,completed.result.sha256);
 const history=await queryAnalysisJobs(f.workspace,{id:f.job.id});assert.deepEqual(history.attempts.map(a=>a.status),['completed','interrupted']);assert.equal((await queryAnalysisRuns(f.workspace,{limit:1})).nextOffset,1);
 const alreadyDone=await cancelAnalysisRun(f.workspace,retry.run.id);assert.equal(alreadyDone.run.recordedStatus,'completed');assert.equal(alreadyDone.run.cancelRequested,false);assert.deepEqual(alreadyDone.run.result,completed.result);
});
test('normal MCP disconnect leaves background work alive; a fresh CLI reads its completion',async t=>{
 const f=await fixture(t);const first=await mcp(f);const started=await first.call('carve_analysis_start',{});await first.client.close();
 const active=await engine(f,started.run.id);await eventually(async()=>!(await processIsLive(active.launcher)));assert.equal(await processIsLive(active.owner),true);
 await writeFile(f.release,'finish');await stopped(f,started.run.id,'completed');const fresh=await callCli(['queue','runs',f.workspace,'--id',started.run.id]);assert.equal(fresh.items[0].observedStatus,'completed');assert.equal((await queryAnalysisJobs(f.workspace)).items[0].attempt,1);
});
test('execution deadline persists its reason and stops the actual engine group',async t=>{
 const f=await fixture(t);const started=await startAnalysisRun(f.workspace,{engines:f.engines,maxRunMs:5000});await engine(f,started.run.id);const done=await stopped(f,started.run.id,'deadline-exceeded');assert.equal(done.cancelRequested,true);assert.equal(done.cancelReason,'deadline');assert.ok(done.deadlineAt);assert.equal((await queryAnalysisJobs(f.workspace)).items[0].status,'interrupted');
});
test('SIGKILL of a background worker is interrupted, never completed, and supervised tools stop',async t=>{
 const f=await fixture(t);const started=await startAnalysisRun(f.workspace,{engines:f.engines});const active=await engine(f,started.run.id);assert.equal(await processIsLive(active.owner),true);process.kill(active.owner.pid,'SIGKILL');
 await eventually(async()=>{const run=await f.run(started.run.id);return run.observedStatus==='interrupted'&&run.liveness.supervisor==='gone'&&run.liveness.processGroup==='gone';});
 assert.equal((await queryAnalysisJobs(f.workspace)).items[0].status,'running');await writeFile(f.release,'finish');const retry=await startAnalysisRun(f.workspace,{engines:f.engines,retry:true});await stopped(f,retry.run.id,'completed');assert.deepEqual((await queryAnalysisJobs(f.workspace,{id:f.job.id})).attempts.map(a=>a.status),['completed','interrupted']);
});
test('a durable cancel while the worker is suspended cannot falsely report stopped',async t=>{
 const f=await fixture(t);const started=await startAnalysisRun(f.workspace,{engines:f.engines});const active=await engine(f,started.run.id);process.kill(active.owner.pid,'SIGSTOP');
 try{const cancel=await cancelAnalysisRun(f.workspace,started.run.id);assert.equal(cancel.run.observedStatus,'cancelling');assert.equal(cancel.run.liveness.owner,'live');assert.equal(cancel.run.liveness.processGroup,'live');}
 finally{process.kill(active.owner.pid,'SIGCONT');}
 await stopped(f,started.run.id,'cancelled');
});
test('lease adoption requires delegated identity; launcher disconnect after handoff starts the authorized batch',async t=>{
 const f=await fixture(t);const lease=await acquireProcessLease(f.workspace,'analysis-queue');const token=lease.token;const id=randomUUID();const folder=path.join(f.workspace,'analysis-runs',id);await mkdir(folder,{recursive:true});const log=path.join(folder,'runner.log');await writeFile(log,'');
 const child=fork(fileURLToPath(new URL('../dist/analysis-runner.js',import.meta.url)),[f.workspace,id],{execArgv:[],stdio:['ignore','ignore','ignore','ipc']});const closed=once(child,'exit');t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await closed;});
 const owner=await processIdentity(child.pid);const options=JSON.stringify(runOptions.parse({engines:f.engines}));const now=new Date().toISOString();const db=openRuns(f.workspace);
 db.prepare("INSERT INTO analysis_runs(id,status,created,updated,launcher,owner,lease_token,options,options_sha256,log) VALUES(?,'starting',?,?,?,?,?,?,?,?)").run(id,now,now,JSON.stringify(lease.owner),JSON.stringify(owner),token,options,digest(options),log);db.close();
 await lease.handoff(owner);lease.release();await assert.rejects(()=>adoptProcessLease(f.workspace,'analysis-queue',token),/not delegated/);await assert.rejects(()=>acquireProcessLease(f.workspace,'analysis-queue'),/still running/);
 child.disconnect();await engine(f,id);await cancelAnalysisRun(f.workspace,id);await stopped(f,id,'cancelled');await closed;
 const next=await acquireProcessLease(f.workspace,'analysis-queue');next.release();
});
test('invalid starts are rejected without launching work or changing queued jobs',async t=>{
 const f=await fixture(t);const abort=new AbortController();abort.abort();await assert.rejects(()=>startAnalysisRun(f.workspace,{engines:f.engines,signal:abort.signal}),/cancelled/);await assert.rejects(()=>startAnalysisRun(f.workspace,{maxRunMs:2}));await assert.rejects(()=>cancelAnalysisRun(f.workspace,'../../escape'),/returned analysis run ID/);assert.equal((await queryAnalysisRuns(f.workspace)).total,0);assert.equal((await queryAnalysisJobs(f.workspace)).items[0].status,'queued');
});
test('simultaneous initial starts share one durable batch and do not duplicate the engine',async t=>{
 const f=await fixture(t);const attempts=await Promise.all(Array.from({length:4},()=>startAnalysisRun(f.workspace,{engines:f.engines})));assert.equal(attempts.filter(a=>a.created).length,1);assert.equal(new Set(attempts.map(a=>a.run.id)).size,1);const id=attempts[0].run.id;await engine(f,id);assert.equal((await queryAnalysisJobs(f.workspace)).items[0].attempt,1);await cancelAnalysisRun(f.workspace,id);await stopped(f,id,'cancelled');
});
for(const delegated of [false,true])test(`actual launcher SIGKILL ${delegated?'after':'before'} lease delegation preserves the startup gate`,async t=>{
 const f=await fixture(t);const id=randomUUID(),folder=path.join(f.workspace,'analysis-runs',id);await mkdir(folder,{recursive:true});const log=path.join(folder,'runner.log');await writeFile(log,'');
 const code=`import {fork} from 'node:child_process';import {acquireProcessLease,processIdentity} from ${JSON.stringify(new URL('../dist/process-lease.js',import.meta.url).href)};import {openRuns,runOptions} from ${JSON.stringify(new URL('../dist/analysis-run-state.js',import.meta.url).href)};import {digest} from ${JSON.stringify(new URL('../dist/artifact.js',import.meta.url).href)};
 const workspace=${JSON.stringify(f.workspace)},id=${JSON.stringify(id)};const lease=await acquireProcessLease(workspace,'analysis-queue');const child=fork(${JSON.stringify(fileURLToPath(new URL('../dist/analysis-runner.js',import.meta.url)))},[workspace,id],{execArgv:[],stdio:['ignore','ignore','ignore','ipc']});const owner=await processIdentity(child.pid);const options=JSON.stringify(runOptions.parse({engines:${JSON.stringify(f.engines)}}));const now=new Date().toISOString();const db=openRuns(workspace);db.prepare("INSERT INTO analysis_runs(id,status,created,updated,launcher,owner,lease_token,options,options_sha256,log) VALUES(?,'starting',?,?,?,?,?,?,?,?)").run(id,now,now,JSON.stringify(lease.owner),JSON.stringify(owner),lease.token,options,digest(options),${JSON.stringify(log)});db.close();${delegated?'await lease.handoff(owner);':''}process.stdout.write('ready\\n');setInterval(()=>{},1000);`;
 const launcher=spawn(process.execPath,['--input-type=module','-e',code],{stdio:['ignore','pipe','pipe']});let text='',errors='';launcher.stdout.on('data',d=>text+=d);launcher.stderr.on('data',d=>errors+=d);const exited=once(launcher,'exit');
 t.after(async()=>{if(launcher.exitCode===null&&launcher.signalCode===null)launcher.kill('SIGKILL');await exited;});
 await eventually(()=>{if(launcher.exitCode!==null)assert.fail(errors);return text.includes('ready');});launcher.kill('SIGKILL');await exited;
 if(delegated){const active=await engine(f,id);assert.equal(active.liveness.launcher,'gone');await cancelAnalysisRun(f.workspace,id);await stopped(f,id,'cancelled');}
 else{const done=await stopped(f,id,'failed');assert.match(done.error,/not delegated/);assert.equal(await present(f.marker),false);assert.equal((await queryAnalysisJobs(f.workspace)).items[0].attempt,0);}
 const lease=await acquireProcessLease(f.workspace,'analysis-queue');lease.release();
});
test('a registered worker that dies during startup is interrupted even while its launcher stays alive',async t=>{
 const f=await fixture(t);const lease=await acquireProcessLease(f.workspace,'analysis-queue');const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});const exited=once(child,'exit');
 t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await exited;});
 const owner=await processIdentity(child.pid),id=randomUUID(),now=new Date().toISOString();const options=JSON.stringify(runOptions.parse({engines:f.engines}));
 const db=openRuns(f.workspace);db.prepare("INSERT INTO analysis_runs(id,status,created,updated,launcher,owner,lease_token,options,options_sha256,log) VALUES(?,'starting',?,?,?,?,?,?,?,?)").run(id,now,now,JSON.stringify(lease.owner),JSON.stringify(owner),lease.token,options,digest(options),path.join(f.workspace,'not-started.log'));db.close();
 await lease.handoff(owner);lease.release();child.kill('SIGKILL');await exited;
 const observed=await f.run(id);assert.equal(observed.liveness.launcher,'live');assert.equal(observed.liveness.owner,'gone');assert.equal(observed.observedStatus,'interrupted');
 await writeFile(f.release,'finish');const recovery=await startAnalysisRun(f.workspace,{engines:f.engines});assert.equal(recovery.created,true);assert.notEqual(recovery.run.id,id);await stopped(f,recovery.run.id,'completed');
});
