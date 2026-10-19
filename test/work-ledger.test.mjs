import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,readFile,writeFile,mkdir,readdir,rm,symlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createHash} from 'node:crypto';
import {createWorkPackage} from '../dist/work-package.js';
import {analyzeProjectPlan,parseProjectPlan} from '../dist/project-plan.js';
import {createWorkLedger,registerWork,claimWork,releaseWork,submitWork,requeueWork,queryWorkLedger,WORK_ATTEMPT_LIMIT,CLAIM_LIMIT} from '../dist/work-ledger.js';
import {existsSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
const proof=r=>{const {id,owner,attempt,claimId}=r.job;return{id,owner,attempt,claimId};};
async function setup(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ledger-')));t.after(()=>rm(root,{recursive:true,force:true}));const plan=JSON.parse(await readFile('examples/work-plan.json','utf8')),spec=JSON.parse(await readFile('examples/work-spec.json','utf8')),current={plan,spec},packages={};
 for(const feature of ['model','parser'])packages[feature]=await createWorkPackage(plan,spec,feature,path.join(root,feature));const ledger=path.join(root,'ledger');await createWorkLedger(ledger);for(const p of Object.values(packages))await registerWork(ledger,p.package,current);return{root,ledger,current,packages};}
async function record(ledger,id,attempt){let offset=0,text='';do{const page=await queryWorkLedger(ledger,{id,attempt,view:'result',offset,characters:12000,budgetBytes:2048});assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;}while(offset!==null);return JSON.parse(text);}
test('a ledger pins one plan/spec revision, registers idempotently and preserves current-check boundaries',async t=>{
 const {ledger,current,packages,root}=await setup(t);const first=await queryWorkLedger(ledger);assert.equal(first.total,2);assert.equal(first.revision,2);assert.equal(first.currentPlanCheck,'not-performed');assert.equal(first.startsAgents,false);
 assert.equal((await registerWork(ledger,packages.parser.package,current)).reused,true);assert.equal((await queryWorkLedger(ledger)).revision,2);
 const other=structuredClone(current);other.plan.goal+=' new revision';const graph=analyzeProjectPlan(parseProjectPlan(other.plan));other.spec.planId=graph.planId;for(const a of other.spec.assignments)a.taskId=graph.tasks.find(t=>t.id===a.feature).taskId;
 const packet=await createWorkPackage(other.plan,other.spec,'model',path.join(root,'new-model'));await assert.rejects(()=>registerWork(ledger,packet.package,other),/another plan\/spec/);await assert.rejects(()=>claimWork(ledger,packages.model.id,'agent',other),/Stale planId|stale/);assert.equal((await queryWorkLedger(ledger)).revision,2);
});
test('simultaneous claims have one winner; explicit release/failure/retry retain attempts and reject old owners',async t=>{
 const {ledger,current,packages}=await setup(t),id=packages.model.id;
 const attempts=await Promise.allSettled([claimWork(ledger,id,'Codex',current),claimWork(ledger,id,'Claude',current)]);assert.equal(attempts.filter(r=>r.status==='fulfilled').length,1);const first=proof(attempts.find(r=>r.status==='fulfilled').value);
 await assert.rejects(()=>releaseWork(ledger,{...first,owner:'someone else'},'released','wrong owner'),/mismatched/);await releaseWork(ledger,first,'released','Worker stopped editing; return to queue.');
 const second=proof(await claimWork(ledger,id,'worker-2',current));assert.equal(second.attempt,2);assert.notEqual(second.claimId,first.claimId);await assert.rejects(()=>submitWork(ledger,first,current,{kind:'proposal',summary:'old attempt'},undefined),/Stale/);
 await releaseWork(ledger,second,'failed','Owned fixture failure');await assert.rejects(()=>claimWork(ledger,id,'worker-3',current),/explicit retry/);const third=proof(await claimWork(ledger,id,'worker-3',current,{retry:true}));assert.equal(third.attempt,3);
 const history=await queryWorkLedger(ledger,{id,view:'attempts'});assert.deepEqual(history.items.map(r=>r.status),['released','failed','claimed']);assert.equal(history.items[0].claimId,first.claimId);
});
test('implementation handoff hashes every assigned file, distinguishes proposals and keeps checks explicitly self-reported',async t=>{
 const {ledger,current,packages,root}=await setup(t),id=packages.parser.id,identity=proof(await claimWork(ledger,id,'worker',current)),output=path.join(root,'output');await mkdir(output);
 await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'implementation',summary:'no files'},output),/ENOENT/);assert.equal((await queryWorkLedger(ledger,{id})).items[0].status,'claimed');
 const assignment=current.spec.assignments.find(a=>a.feature==='parser');for(const file of assignment.files){await mkdir(path.dirname(path.join(output,file)),{recursive:true});await writeFile(path.join(output,file),'// Owned synthetic file: '+file+'\n');}
 const sent=await submitWork(ledger,identity,current,{kind:'implementation',summary:'Synthetic files only; no target build',checks:[{name:'declared sample',status:'passed',detail:'Agent assertion, not authenticated execution.'}],unknowns:['Original behavior not observed.']},output);assert.equal(sent.job.status,'submitted');assert.equal(sent.artifactFiles,2);assert.equal(sent.verification,'not-run-by-ledger');assert.equal(sent.integration,'not-accepted-or-merged');
 const saved=await record(ledger,id,1);for(const artifact of saved.artifacts.files){const bytes=await readFile(path.join(output,artifact.file));assert.equal(artifact.sha256,createHash('sha256').update(bytes).digest('hex'));assert.equal(artifact.bytes,bytes.length);}assert.equal(saved.kind,'implementation');assert.match(saved.checksAuthority,/Agent-reported/);
 await writeFile(path.join(output,assignment.files[0]),'changed after submission');assert.deepEqual(await record(ledger,id,1),saved);await assert.rejects(()=>claimWork(ledger,id,'another',current),/cannot be taken over/);
 const proposed=proof(await claimWork(ledger,packages.model.id,'planner',current));await assert.rejects(()=>submitWork(ledger,proposed,current,{kind:'proposal',summary:'idea'},output),/must not/);await submitWork(ledger,proposed,current,{kind:'proposal',summary:'A design, no implementation files'},undefined);assert.equal((await queryWorkLedger(ledger,{id:packages.model.id})).items[0].status,'proposed');assert.equal((await record(ledger,packages.model.id,1)).artifacts,null);
});
test('changed interfaces, package bytes and redirected output cannot finish an active attempt',async t=>{
 const {ledger,current,packages,root}=await setup(t),id=packages.model.id,identity=proof(await claimWork(ledger,id,'worker',current));const other=structuredClone(current);other.plan.features[0].contract.errors+=' changed';
 await assert.rejects(()=>submitWork(ledger,identity,other,{kind:'proposal',summary:'stale'},undefined),/Stale planId/);const file=path.join(packages.model.package,'TASK.md'),original=await readFile(file);await writeFile(file,'tampered');await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'proposal',summary:'bad package'},undefined),/differ/);await writeFile(file,original);
 const output=path.join(root,'output');await mkdir(output);const assignment=current.spec.assignments.find(a=>a.feature==='model');for(const relative of assignment.files){await mkdir(path.dirname(path.join(output,relative)),{recursive:true});await writeFile(path.join(output,relative),'owned');}
 const target=path.join(output,assignment.files[0]);await rm(target);await symlink(path.join(root,'missing'),target);await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'implementation',summary:'redirect'},output));assert.equal((await queryWorkLedger(ledger,{id})).items[0].status,'claimed');
});
test('budget/cancellation failures roll back transitions; paged results preserve Unicode and revisions',async t=>{
 const {ledger,current,packages,root}=await setup(t),id=packages.model.id,initial=(await queryWorkLedger(ledger)).revision;
 await assert.rejects(()=>claimWork(ledger,id,'x'.repeat(100),current,{budgetBytes:1024}),/budget/i);await assert.rejects(()=>claimWork(ledger,id,'owner',current,{signal:AbortSignal.abort()}));assert.equal((await queryWorkLedger(ledger)).revision,initial);
 const identity=proof(await claimWork(ledger,id,'worker',current));await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'proposal',summary:'pending'},undefined,{budgetBytes:1024}),/budget/i);assert.equal((await queryWorkLedger(ledger,{id})).items[0].status,'claimed');
 const summary='😀\u4e2d\u6587'.repeat(300);await submitWork(ledger,identity,current,{kind:'proposal',summary},undefined);assert.equal((await record(ledger,id,1)).summary,summary);
 const first=await queryWorkLedger(ledger,{view:'result',id,attempt:1,characters:12000,budgetBytes:8192});await assert.rejects(()=>queryWorkLedger(ledger,{view:'result',id,attempt:1,offset:first.text.indexOf('😀')+1}),/surrogate/);
 const dir=path.join(root,'bad-budget');await assert.rejects(()=>createWorkLedger(dir,{budgetBytes:1023}));assert.ok(!(await readdir(root)).includes('bad-budget'));
});
test('a killed uncommitted SQLite writer recovers without releasing the external worker claim',async t=>{
 const {ledger,current,packages}=await setup(t),id=packages.model.id,identity=proof(await claimWork(ledger,id,'persistent-worker',current)),revision=(await queryWorkLedger(ledger)).revision;
 const script="const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.argv[1]);db.exec(\"PRAGMA cache_size=1; BEGIN IMMEDIATE; UPDATE control SET revision=999; UPDATE jobs SET status='failed';\");process.stdout.write('ready\\n');setInterval(()=>{},1000);";
 const child=spawn(process.execPath,['-e',script,path.join(ledger,'ledger.sqlite')],{stdio:['ignore','pipe','pipe']});t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(new Error('Writer did not become ready')),5000);child.stdout.once('data',()=>{clearTimeout(timeout);resolve();});child.once('error',reject);child.once('exit',()=>{clearTimeout(timeout);reject(new Error('Writer exited before ready'));});});const exited=once(child,'exit');child.kill('SIGKILL');await exited;
 const recovered=await queryWorkLedger(ledger,{id});assert.equal(recovered.revision,revision);assert.equal(recovered.items[0].status,'claimed');assert.equal(recovered.items[0].claimId,identity.claimId);await releaseWork(ledger,identity,'released','Worker explicitly stopped after recovery.');
});
test('review requeue binds the exact latest result, preserves it and starts a separate new attempt',async t=>{
 const {ledger,current,packages}=await setup(t),id=packages.model.id,first=proof(await claimWork(ledger,id,'planner',current)),sent=await submitWork(ledger,first,current,{kind:'proposal',summary:'Needs implementation'},undefined),saved=await record(ledger,id,1);
 await assert.rejects(()=>requeueWork(ledger,id,1,'a'.repeat(64),'reviewer','wrong result',current),/Stale review/);const again=await requeueWork(ledger,id,1,sent.submissionId,'reviewer','Proceed with implementation of this declared boundary',current);assert.equal(again.job.status,'queued');assert.deepEqual(await record(ledger,id,1),saved);
 const history=await queryWorkLedger(ledger,{id,view:'attempts'});assert.equal(history.items[0].reviewer,'reviewer');assert.equal(history.items[0].submissionId,sent.submissionId);assert.equal(history.items[0].status,'proposed');
 const next=proof(await claimWork(ledger,id,'implementer',current));assert.equal(next.attempt,2);await assert.rejects(()=>requeueWork(ledger,id,1,sent.submissionId,'reviewer','stale review',current),/Stale review/);await assert.rejects(()=>releaseWork(ledger,first,'released','old planner'),/Stale/);
});

test('plain releases do not consume the work-attempt budget; exhausted tasks are shown and refused',async t=>{
 const {ledger,current,packages}=await setup(t),id=packages.model.id,row=async target=>(await queryWorkLedger(ledger,{id:target})).items[0];
 assert.deepEqual([WORK_ATTEMPT_LIMIT,CLAIM_LIMIT],[100,1000]);
 for(let i=0;i<WORK_ATTEMPT_LIMIT+5;i++)await releaseWork(ledger,proof(await claimWork(ledger,id,'impatient',current)),'released','returned without work');
 let job=await row(id);assert.deepEqual([job.status,job.attempt,job.workAttempts,job.claimability],['queued',105,0,'available']);
 for(let i=0;i<WORK_ATTEMPT_LIMIT;i++)await releaseWork(ledger,proof(await claimWork(ledger,id,'worker',current,{retry:true})),'failed','owned failure fixture');
 job=await row(id);assert.deepEqual([job.status,job.attempt,job.workAttempts,job.claimability],['failed',205,100,'exhausted']);
 await assert.rejects(()=>claimWork(ledger,id,'worker',current,{retry:true}),/reached 100 work attempts \(failed, proposed or submitted\)/);
 // The total bound on claims, including releases, is reached through the same visible state.
 const other=packages.parser.id,db=new DatabaseSync(path.join(ledger,'ledger.sqlite'));try{db.prepare('UPDATE jobs SET attempt=? WHERE id=?').run(CLAIM_LIMIT-1,other);}finally{db.close();}
 assert.equal((await row(other)).claimability,'available');
 const last=proof(await claimWork(ledger,other,'worker',current));assert.equal(last.attempt,CLAIM_LIMIT);assert.equal((await row(other)).claimability,'held');
 await releaseWork(ledger,last,'released','last allowed claim');assert.equal((await row(other)).claimability,'exhausted');
 await assert.rejects(()=>claimWork(ledger,other,'worker',current),/reached 1000 claims in total, including releases/);
 assert.equal((await queryWorkLedger(ledger,{view:'attempts',id,offset:204,limit:1})).items[0].attempt,205,'attempt numbers above 100 are readable');
});

test('path errors name a real symlink, and a case-only difference is reported as such with the on-disk name',async t=>{
 const {root,ledger,current,packages}=await setup(t),id=packages.model.id;
 const alias=path.join(root,'alias-ledger');await symlink(ledger,alias);await assert.rejects(()=>queryWorkLedger(alias),/must not redirect through symlinks \(.*alias-ledger is a link\)/);
 const linked=path.join(root,'linked');await symlink(root,linked);
 await assert.rejects(()=>queryWorkLedger(path.join(linked,'ledger')),new RegExp('must not redirect through symlinks \\(.*linked is a link\\); use the canonical path '+ledger.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 await writeFile(path.join(root,'CaseProbe'),'');if(!existsSync(path.join(root,'caseprobe'))){t.skip('file system is case-sensitive');return;}
 const upper=path.join(root,'LEDGER');await assert.rejects(()=>queryWorkLedger(upper),/differs from its on-disk name only by letter case or Unicode normalization; use exactly .*\/ledger\./);
 const assignment=JSON.parse(await readFile(path.join(packages.model.package,'work.json'),'utf8')).assignment.files,output=path.join(root,'out');
 for(const file of assignment){const lower=path.join(output,file.toLowerCase());await mkdir(path.dirname(lower),{recursive:true});await writeFile(lower,'fixture\n');}
 const identity=proof(await claimWork(ledger,id,'case-worker',current));
 await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'implementation',summary:'wrong case'},output),new RegExp('Submitted artifact '+assignment[0].replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+' differs from its on-disk name only by letter case.*use exactly .*'+assignment[0].toLowerCase().replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
 await assert.rejects(()=>submitWork(ledger,identity,current,{kind:'implementation',summary:'wrong root case'},path.join(root,'OUT')),/Ledger\/output directory differs from its on-disk name only by letter case/);
 assert.equal((await queryWorkLedger(ledger,{id})).items[0].claimability,'held','refused submissions leave the claim in place');
});
