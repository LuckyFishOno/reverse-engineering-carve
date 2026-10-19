import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {mkdtemp,readFile,writeFile,access,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {acquireProcessLease,processIdentity,processIsLive,processGroupMembers,LeaseBusyError} from '../dist/process-lease.js';
import {runTool} from '../dist/tool-process.js';

async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),'carve-lease-'));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
async function eventually(check){for(let i=0;i<150;i++){if(await check())return;await new Promise(r=>setTimeout(r,20));}assert.fail('Actual process condition was not reached.');}
test('process identities and atomic leases reject live/concurrent owners and permit completed-owner reuse',async t=>{
 const root=await fixture(t);const owner=await processIdentity();assert.equal(await processIsLive(owner),true);assert.equal(await processIsLive({...owner,startedAt:'different start identity'}),false);
 for(let round=0;round<2;round++){
  const results=await Promise.allSettled(Array.from({length:4},()=>acquireProcessLease(root,'analysis')));const acquired=results.filter(r=>r.status==='fulfilled');assert.equal(acquired.length,1);for(const r of results)if(r.status==='rejected')assert.ok(r.reason instanceof LeaseBusyError);acquired[0].value.release();
 }
 await writeFile(path.join(root,'.analysis.lock'),JSON.stringify({pid:2147483647}));await assert.rejects(()=>acquireProcessLease(root,'analysis','.analysis.lock'),/Legacy analysis lock/);
});
test('tool launch waits for durable registration and does not execute after a rejected registration',async t=>{
 const root=await fixture(t);const marker=path.join(root,'ready');const executed=path.join(root,'executed');
 const code=`require('node:fs').readFileSync(${JSON.stringify(marker)});require('node:fs').writeFileSync(${JSON.stringify(executed)},'executed');`;
 const run=(log,onProcess)=>runTool(process.execPath,['-e',code],{cwd:root,env:{PATH:process.env.PATH},log:path.join(root,log),timeoutMs:3000,onProcess});
 await assert.rejects(()=>run('refused.log',()=>{throw new Error('registration refused');}),/registration refused/);await assert.rejects(()=>access(executed),/ENOENT/);
 const lease=await acquireProcessLease(root,'analysis');try{const result=await run('allowed.log',async guard=>{await lease.register(guard);await writeFile(marker,'durably registered');});assert.equal(result.exitCode,0);assert.equal(await readFile(executed,'utf8'),'executed');}finally{lease.release();}
});
async function liveRunner(t,root,waitBeforeLaunch=false){
 const leaseModule=new URL('../dist/process-lease.js',import.meta.url).href,toolModule=new URL('../dist/tool-process.js',import.meta.url).href;
 const marker=path.join(root,'engine.json');
 const code=`require('node:fs').writeFileSync(${JSON.stringify(marker)},JSON.stringify({pid:process.pid}));setInterval(()=>{},1000);`;
 const script=`import {acquireProcessLease} from ${JSON.stringify(leaseModule)};import {runTool} from ${JSON.stringify(toolModule)};const root=process.argv[1];const lease=await acquireProcessLease(root,'analysis');try{await runTool(process.execPath,['-e',${JSON.stringify(code)}],{cwd:root,env:{PATH:process.env.PATH},log:root+'/engine.log',timeoutMs:20000,onProcess:async guard=>{await lease.register(guard);process.stdout.write(JSON.stringify(guard)+'\\n');${waitBeforeLaunch?'await new Promise(r=>setTimeout(r,60000));':''}}});}finally{lease.release();}`;
 const child=spawn(process.execPath,['--input-type=module','-e',script,root],{stdio:['ignore','pipe','pipe']});let guard;let stderr='';child.stderr.on('data',d=>{stderr=(stderr+d).slice(-5000);});const closed=once(child,'close');
 t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await closed;if(guard){const members=await processGroupMembers(guard.processGroup);if(members.length)try{process.kill(-guard.processGroup,'SIGKILL');}catch{}}});
 let timer;try{guard=await new Promise((resolve,reject)=>{let text='';timer=setTimeout(()=>reject(new Error('No engine registration: '+stderr)),10000);child.stdout.on('data',d=>{text+=d;if(text.includes('\n'))resolve(JSON.parse(text.trim()));});child.once('error',reject);child.once('exit',()=>reject(new Error('Runner exited before registration: '+stderr)));});}finally{clearTimeout(timer);}
 return{child,closed,guard,marker};
}
test('parent SIGKILL before tool start closes the registered host group without executing the tool',async t=>{
 const root=await fixture(t);const run=await liveRunner(t,root,true);assert.ok((await processGroupMembers(run.guard.processGroup)).includes(run.guard.pid));run.child.kill('SIGKILL');await run.closed;
 await eventually(async()=>!(await processIsLive(run.guard.supervisor))&&!(await processGroupMembers(run.guard.processGroup)).length);await assert.rejects(()=>access(run.marker),/ENOENT/);
 const lease=await acquireProcessLease(root,'analysis');lease.release();
});
test('parent SIGKILL after tool start terminates its actual engine process group',async t=>{
 const root=await fixture(t);const run=await liveRunner(t,root);let engine;
 await eventually(async()=>{try{engine=JSON.parse(await readFile(run.marker,'utf8'));return true;}catch(error){if(error.code!=='ENOENT')throw error;return false;}});
 assert.ok((await processGroupMembers(run.guard.processGroup)).includes(engine.pid));run.child.kill('SIGKILL');await run.closed;
 await eventually(async()=>!(await processIsLive(run.guard.supervisor))&&!(await processGroupMembers(run.guard.processGroup)).length);const lease=await acquireProcessLease(root,'analysis');lease.release();
});
test('a surviving engine blocks recovery after both the runner and its host have died',async t=>{
 const root=await fixture(t);const run=await liveRunner(t,root);let engine;
 await eventually(async()=>{try{engine=JSON.parse(await readFile(run.marker,'utf8'));return true;}catch(error){if(error.code!=='ENOENT')throw error;return false;}});
 // Freeze each owned controller first so none can clean up on another controller's death.
 process.kill(run.child.pid,'SIGSTOP');process.kill(run.guard.supervisor.pid,'SIGSTOP');process.kill(run.guard.pid,'SIGSTOP');
 process.kill(run.guard.supervisor.pid,'SIGKILL');process.kill(run.guard.pid,'SIGKILL');run.child.kill('SIGKILL');await run.closed;
 assert.ok((await processGroupMembers(run.guard.processGroup)).includes(engine.pid));
 await assert.rejects(()=>acquireProcessLease(root,'analysis'),error=>error instanceof LeaseBusyError&&/process group is still alive/.test(error.message));
 // Only the group created by this test is stopped, after observing its actual member.
 process.kill(-run.guard.processGroup,'SIGKILL');await eventually(async()=>!(await processGroupMembers(run.guard.processGroup)).length);
 const lease=await acquireProcessLease(root,'analysis');lease.release();
});
test('the live parent cleans the engine group if its supervisor is killed externally',async t=>{
 const root=await fixture(t);const marker=path.join(root,'started');let guard;
 const pending=runTool(process.execPath,['-e',`require('node:fs').writeFileSync(${JSON.stringify(marker)},'ready');setInterval(()=>{},1000);`],{cwd:root,env:{PATH:process.env.PATH},log:path.join(root,'fallback.log'),timeoutMs:5000,onProcess:p=>{guard=p;}});
 await eventually(async()=>{try{await access(marker);return true;}catch{return false;}});process.kill(guard.supervisor.pid,'SIGKILL');await assert.rejects(()=>pending,/supervisor stopped unexpectedly/);assert.deepEqual(await processGroupMembers(guard.processGroup),[]);
});
test('parent death near tool startup leaves neither a supervisor nor a late engine child',async t=>{
 for(const delay of [0,5,15,30]){
  const root=await fixture(t);const run=await liveRunner(t,root);await new Promise(r=>setTimeout(r,delay));run.child.kill('SIGKILL');await run.closed;
  await eventually(async()=>!(await processIsLive(run.guard.supervisor))&&!(await processGroupMembers(run.guard.processGroup)).length);
 }
});
