import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {survey,openIndex,hashFile} from '../dist/survey.js';
import {enqueueAnalysis,queryAnalysisJobs,runAnalysisQueue} from '../dist/analysis-queue.js';

async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),'carve-queue-'));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input');await mkdir(input);const workspace=path.join(root,'workspace');return{root,input,workspace};}
test('disk jobs route selected components, deduplicate unchanged requests and preserve bounded results',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.input,'a.mjs'),'export const twice=x=>x*2;throw new Error("must never execute");');await writeFile(path.join(f.input,'b.mjs'),'export const three=3;');await writeFile(path.join(f.input,'unknown.wasm'),Buffer.from([0,97,115,109,1,0,0,0]));await survey(f.input,{workspace:f.workspace});
 assert.equal((await queryAnalysisJobs(f.workspace)).total,0);
 const added=await enqueueAnalysis(f.workspace,[{file:'a.mjs'},{file:'b.mjs'},{file:'unknown.wasm'}]);assert.deepEqual(added.items.map(i=>i.status),['queued','queued','unsupported']);
 const same=await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);assert.equal(same.items[0].id,added.items[0].id);assert.equal((await queryAnalysisJobs(f.workspace,{limit:1})).nextOffset,1);
 const first=await runAnalysisQueue(f.workspace);assert.equal(first.items.length,1);assert.equal(first.items[0].status,'completed');const second=await runAnalysisQueue(f.workspace);assert.equal(second.items[0].status,'completed');assert.equal((await runAnalysisQueue(f.workspace)).items.length,0);
 const output=JSON.parse(await readFile(first.items[0].result.file,'utf8'));assert.equal(output.status,'module-inspected');assert.equal((await hashFile(first.items[0].result.file)).sha256,first.items[0].result.sha256);assert.equal(output.executesTarget,false);
 const jobs=await queryAnalysisJobs(f.workspace,{id:first.items[0].id});assert.equal(jobs.items[0].attempt,1);assert.equal(jobs.attempts[0].status,'completed');assert.equal((await enqueueAnalysis(f.workspace,[{file:first.items[0].file}])).items[0].status,'completed');
});
test('failures are sticky without explicit retry and request/format errors never start an engine',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.input,'bad.mjs'),'export const = invalid syntax');await survey(f.input,{workspace:f.workspace});
 await assert.rejects(()=>enqueueAnalysis(f.workspace,[{file:'bad.mjs',native:{function:'x'}}]),/does not match/);
 await assert.rejects(()=>enqueueAnalysis(f.workspace,[{file:'bad.mjs',extra:'not supported'}]));
 await enqueueAnalysis(f.workspace,[{file:'bad.mjs'}]);const failed=await runAnalysisQueue(f.workspace);assert.equal(failed.items[0].status,'failed');assert.match(failed.items[0].error,/Unexpected token/);
 assert.equal((await runAnalysisQueue(f.workspace)).items.length,0);const retried=await runAnalysisQueue(f.workspace,{retry:true,maxJobs:10});assert.equal(retried.items.length,1);assert.equal(retried.items[0].attempt,2);assert.equal(retried.items[0].status,'failed');
 const job=await queryAnalysisJobs(f.workspace,{id:failed.items[0].id,limit:1});assert.equal(job.attemptTotal,2);assert.equal(job.nextAttemptOffset,1);const earlier=await queryAnalysisJobs(f.workspace,{id:failed.items[0].id,limit:1,offset:1});assert.equal(earlier.items[0].id,failed.items[0].id);assert.equal(earlier.attempts[0].attempt,1);assert.equal(earlier.nextAttemptOffset,null);
});
test('changed input/provider identity becomes stale and fresh enqueue creates a new immutable job',async t=>{
 const f=await fixture(t);const file=path.join(f.input,'a.mjs');await writeFile(file,'export const a=1;');await survey(f.input,{workspace:f.workspace});const first=await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);
 await writeFile(file,'export const changed=20;');assert.equal((await runAnalysisQueue(f.workspace)).items[0].status,'stale-input');await survey(f.input,{workspace:f.workspace,refresh:true});const second=await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);assert.notEqual(first.items[0].id,second.items[0].id);
 const db=openIndex(f.workspace);const provider=JSON.parse(db.prepare('SELECT provider FROM analysis_jobs WHERE id=?').get(second.items[0].id).provider);provider.sha256='test-only-altered-record';db.prepare('UPDATE analysis_jobs SET provider=? WHERE id=?').run(JSON.stringify(provider),second.items[0].id);db.close();
 assert.equal((await runAnalysisQueue(f.workspace)).items[0].status,'stale-provider');assert.equal((await runAnalysisQueue(f.workspace,{retry:true})).items.length,0);
 await writeFile(file,'export const a=1;');await survey(f.input,{workspace:f.workspace,refresh:true});const restored=await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);assert.equal(restored.items[0].id,first.items[0].id);assert.equal(restored.items[0].status,'queued');const again=await runAnalysisQueue(f.workspace);assert.equal(again.items[0].status,'completed');assert.equal(again.items[0].attempt,2);
});
test('cancellation preserves an interrupted attempt and requires explicit retry',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.input,'a.mjs'),'export const a=1;');await survey(f.input,{workspace:f.workspace});await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);const controller=new AbortController();
 const stopped=await runAnalysisQueue(f.workspace,{signal:controller.signal,onProgress:p=>{if(p.phase==='job-started')controller.abort();}});assert.equal(stopped.items[0].status,'interrupted');assert.equal(stopped.cancelled,true);assert.equal((await runAnalysisQueue(f.workspace)).items.length,0);
 const retried=await runAnalysisQueue(f.workspace,{retry:true});assert.equal(retried.items[0].attempt,2);assert.equal(retried.items[0].status,'completed');
});
test('a real killed queue runner is inspected as gone and its attempt can be explicitly resumed',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.input,'a.mjs'),'export const a=1;');await survey(f.input,{workspace:f.workspace});const added=await enqueueAnalysis(f.workspace,[{file:'a.mjs'}]);
 const script=`import {runAnalysisQueue} from ${JSON.stringify(new URL('../dist/analysis-queue.js',import.meta.url).href)};await runAnalysisQueue(process.argv[1],{onProgress:async p=>{if(p.phase==='job-started'){process.stdout.write(JSON.stringify(p)+'\\n');await new Promise(r=>setTimeout(r,60000));}}});`;
 const child=spawn(process.execPath,['--input-type=module','-e',script,f.workspace],{stdio:['ignore','pipe','pipe']});const closed=once(child,'close');let stderr='';child.stderr.on('data',d=>{stderr+=d;});t.after(async()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');await closed;});let timer;
 try{await new Promise((resolve,reject)=>{let text='';timer=setTimeout(()=>reject(new Error('No job checkpoint: '+stderr)),10000);child.stdout.on('data',d=>{text+=d;if(text.includes('\n'))resolve();});child.once('error',reject);});}finally{clearTimeout(timer);}
 const active=await queryAnalysisJobs(f.workspace,{id:added.items[0].id});assert.equal(active.items[0].liveness.owner,'live');
 child.kill('SIGKILL');await closed;const stopped=await queryAnalysisJobs(f.workspace,{id:added.items[0].id});assert.equal(stopped.items[0].status,'running');assert.equal(stopped.items[0].liveness.owner,'gone');
 const recovery=await runAnalysisQueue(f.workspace);assert.equal(recovery.items.length,0);assert.equal((await queryAnalysisJobs(f.workspace)).items[0].status,'interrupted');
 const resumed=await runAnalysisQueue(f.workspace,{retry:true});assert.equal(resumed.items[0].status,'completed');assert.equal(resumed.items[0].attempt,2);const history=await queryAnalysisJobs(f.workspace,{id:added.items[0].id});assert.deepEqual(history.attempts.map(a=>a.status),['completed','interrupted']);
});
