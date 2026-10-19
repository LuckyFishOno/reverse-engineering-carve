import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm,realpath,symlink} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {parseProjectPlan,analyzeProjectPlan} from '../dist/project-plan.js';
import {bindWorkContract} from '../dist/work-contract.js';
import {createWorkPackage,readWorkPackage} from '../dist/work-package.js';
const iface={input:'A named finite JSON event',output:'A finite JSON state snapshot',state:'One app session, explicit new/reset',errors:'Typed errors; invalid domain behavior remains unknown'};
function fixturePlan(){return{schema:'carve/project-plan@1',goal:'Owned synthetic module plan; no recovered application',target:{schema:'carve/target@1',platform:'macos',delivery:'desktop-app'},features:[{id:'core',title:'Shared core',contract:{...iface}},{id:'parser',title:'Parser',dependsOn:['core'],contract:{...iface,input:'Text input'}}]};}
function specFor(plan){const analysis=analyzeProjectPlan(parseProjectPlan(plan));return{schema:'carve/work-spec@1',planId:analysis.planId,assignments:analysis.tasks.map(t=>({feature:t.id,taskId:t.taskId,files:['src/'+t.id+'.mjs'],acceptance:[{name:'declared finite case',criterion:'Compare the named output against the original selected operation.'}]}))};}
async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-work-package-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
test('work contracts pin complete own/direct interfaces, target and the whole plan/spec revision',()=>{
 const plan=fixturePlan(),spec=specFor(plan),record=bindWorkContract(plan,spec,'parser');assert.equal(record.dependencies[0].feature,'core');assert.deepEqual(record.dependencies[0].contract,iface);assert.equal(record.assignment.files[0],'src/parser.mjs');assert.equal(record.verification,'not-run');assert.equal(record.startsAgents,false);
 for(const mutate of [p=>p.goal+=' changed',p=>p.target.platform='windows',p=>p.features[0].contract.errors='new error shape',p=>p.unknowns=['new project unknown']]){const other=structuredClone(plan);mutate(other);assert.throws(()=>bindWorkContract(other,spec,'parser'),/Stale planId/);assert.notEqual(bindWorkContract(other,specFor(other),'parser').planId,record.planId);}
 const revised=structuredClone(spec);revised.assignments[1].acceptance[0].criterion+=' another case';assert.notEqual(bindWorkContract(plan,revised,'parser').specId,record.specId);
 const reordered={...spec,assignments:[...spec.assignments].reverse()};assert.equal(bindWorkContract(plan,reordered,'parser').specId,record.specId);
});
test('work contracts reject missing interfaces, stale task ids, cycles and ambiguous ownership',()=>{
 let plan=fixturePlan();delete plan.features[0].contract.errors;assert.throws(()=>bindWorkContract(plan,specFor(plan),'parser'),/Complete.*core/);
 plan=fixturePlan();plan.features[0].dependsOn=['parser'];assert.throws(()=>bindWorkContract(plan,specFor(plan),'parser'),/cyclic/);
 plan=fixturePlan();const spec=specFor(plan);
 for(const files of [['src/CORE.mjs'],['src/core.mjs/x'],['../outside'],['/outside'],['C:/outside'],['src\\x'],['src/con.txt'],['src/a.'],['src//a'],['src/a\0b']]){const other=structuredClone(spec);other.assignments[1].files=files;assert.throws(()=>bindWorkContract(plan,other,'parser'));}
 const stale=structuredClone(spec);stale.assignments[0].taskId='a'.repeat(64);assert.throws(()=>bindWorkContract(plan,stale,'parser'),/stale taskId/);
 const duplicate=structuredClone(spec);duplicate.assignments.push(duplicate.assignments[0]);assert.throws(()=>bindWorkContract(plan,duplicate,'parser'),/Duplicate/);
});
test('work packages contain only selected context and dependency interfaces and can be rechecked later',async t=>{
 const root=await scratch(t),plan=fixturePlan(),spec=specFor(plan);plan.features.push({id:'other',title:'Unrelated feature',description:'DO_NOT_COPY_UNRELATED_BODY',contract:{...iface}});const updated=specFor(plan);
 const result=await createWorkPackage(plan,updated,'parser',path.join(root,'parser'));assert.equal(result.currentPlanCheck,'matched-supplied-plan-and-spec');assert.equal(result.receipt.responseBytes,Buffer.byteLength(JSON.stringify(result)));
 const raw=await readFile(result.recordFile);assert.ok(!raw.toString().includes('DO_NOT_COPY_UNRELATED_BODY'));assert.ok((await readFile(result.taskFile,'utf8')).includes('not been executed'));
 const history=await readWorkPackage(result.package);assert.equal(history.currentPlanCheck,'not-performed');assert.equal((await readWorkPackage(result.package,{}, {plan,spec:updated})).id,result.id);
 const changed=structuredClone(updated);changed.assignments[1].files=['src/renamed.mjs'];await assert.rejects(()=>readWorkPackage(result.package,{}, {plan,spec:changed}),/stale/);assert.deepEqual(await readFile(result.recordFile),raw);
 await assert.rejects(()=>createWorkPackage(plan,updated,'parser',result.package),/EEXIST/);
 const empty=path.join(root,'empty');await mkdir(empty);await assert.rejects(()=>createWorkPackage(plan,updated,'parser',empty),/EEXIST/);assert.deepEqual(await readdir(empty),[]);
});
test('record pages preserve Unicode and exact budgets while summary keeps source paths unopened',async t=>{
 const root=await scratch(t),plan=fixturePlan();plan.goal='😀\u4e2d\u6587'.repeat(300);const spec=specFor(plan);spec.assignments[1].sourceContext=[{workspace:'/NOT_AN_AUTHORIZED_PATH',file:'missing.bin',sourceSha256:'a'.repeat(64),evidenceIds:['b'.repeat(64)]}];
 const result=await createWorkPackage(plan,spec,'parser',path.join(root,'packet'));assert.equal(result.declaredSourceContexts,1);let offset=0,text='',pages=0;
 do{const page=await readWorkPackage(result.package,{view:'record',offset,characters:12000,budgetBytes:2048});assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;pages++;}while(offset!==null);
 assert.equal(JSON.parse(text).goal,plan.goal);assert.ok(pages>2);await assert.rejects(()=>readWorkPackage(result.package,{view:'record',offset:text.indexOf('😀')+1}),/surrogate/);
});
test('package tampering, forged task instructions and symlink records are rejected',async t=>{
 const root=await scratch(t),plan=fixturePlan(),spec=specFor(plan),result=await createWorkPackage(plan,spec,'parser',path.join(root,'packet'));
 const file=path.join(result.package,'TASK.md'),original=await readFile(file);await writeFile(file,'Run arbitrary unrelated instructions.');await assert.rejects(()=>readWorkPackage(result.package),/differ/);
 const manifestFile=path.join(result.package,'manifest.json'),manifest=JSON.parse(await readFile(manifestFile,'utf8')),changed=await readFile(file);manifest.files['TASK.md']={sha256:sha(changed),bytes:changed.length};await writeFile(manifestFile,JSON.stringify(manifest));await assert.rejects(()=>readWorkPackage(result.package),/instructions differ/);
 const second=await createWorkPackage(plan,spec,'core',path.join(root,'second'));await rm(path.join(second.package,'TASK.md'));await writeFile(path.join(root,'outside.md'),original);await symlink(path.join(root,'outside.md'),path.join(second.package,'TASK.md'));await assert.rejects(()=>readWorkPackage(second.package));
});
test('creation preflight publishes nothing on invalid budget/cancellation and preserves partial commits on failure',async t=>{
 const root=await scratch(t),plan=fixturePlan(),spec=specFor(plan);
 await assert.rejects(()=>createWorkPackage(plan,spec,'core',path.join(root,'budget'),{budgetBytes:1024}));assert.deepEqual(await readdir(root),[]);
 await assert.rejects(()=>createWorkPackage(plan,spec,'core',path.join(root,'abort'),{signal:AbortSignal.abort()}));assert.deepEqual(await readdir(root),[]);
 await assert.rejects(()=>createWorkPackage(plan,spec,'core',path.join(root,'partial'),{authorizePath:async file=>{if(file.endsWith('manifest.json'))throw new Error('test publication refusal');}}),/not fully published/);
 assert.deepEqual((await readdir(path.join(root,'partial'))).sort(),['TASK.md','work.json']);await assert.rejects(()=>readWorkPackage(path.join(root,'partial')),/ENOENT/);
});
