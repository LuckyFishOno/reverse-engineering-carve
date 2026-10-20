import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {readFile,mkdtemp,rm,realpath} from 'node:fs/promises';
import {assessBehavior,checkBehavior,behaviorAcceptance} from '../dist/behavior.js';
import {assessFeature,featurePrompt} from '../dist/feature.js';
import {featureScope} from '../dist/feature-scope.js';
import {survey} from '../dist/survey.js';
import {parseProjectPlan,analyzeProjectPlan} from '../dist/project-plan.js';
import {bindWorkContract,workRecordSchema} from '../dist/work-contract.js';
import {createWorkPackage,readWorkPackage} from '../dist/work-package.js';
const example=JSON.parse(await readFile('examples/behavior/interactive-console.json','utf8'));
const clone=()=>structuredClone(example);
function plan(behavior=clone()){return{schema:'carve/project-plan@1',goal:'Rebuild a synthetic console',target:{schema:'carve/target@1',platform:'macos',delivery:'desktop-app'},features:[{id:'console',title:'Console',contract:{input:'Keyboard and resize events',output:'Peer output bytes',state:'One shell per tab',errors:'Typed connection errors',behavior}}]};}
function specFor(p){const a=analyzeProjectPlan(parseProjectPlan(p));return{schema:'carve/work-spec@1',planId:a.planId,assignments:[{feature:'console',taskId:a.tasks[0].taskId,files:['Sources/console/Module.swift'],acceptance:[{name:'build',criterion:'Build the target; this alone is not behavior acceptance.'}]}]};}
async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-behavior-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test('an explicit interactive contract covers lifecycle, direct input, protocol, persistence and failure recovery without execution',()=>{
 const r=assessBehavior(clone());assert.equal(r.status,'declared-for-validation');assert.deepEqual(r.gaps,[]);assert.equal(r.verification,'not-run');assert.equal(r.executesTarget,false);
 assert.ok(r.requirements.some(r=>r.id==='interaction.action.interrupt'));assert.ok(r.requirements.some(r=>r.id==='protocol.ordering'));assert.equal(behaviorAcceptance(clone()).length,4);
 const page=checkBehavior(clone(),{view:'requirements',limit:3,budgetBytes:4096});assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));assert.equal(page.nextOffset,3);
});
test('independent calls cannot silently erase an interactive requirement or its pin',()=>{
 const interactive=assessBehavior(clone()),changed=clone();changed.protocol.mode='request-response';changed.lifecycle.lifetime='independent';
 assert.notEqual(assessBehavior(changed).sha256,interactive.sha256);
 const missing=clone();delete missing.lifecycle.close;delete missing.interaction.actions[1].expected;delete missing.errors.cases[0].recovery;
 const r=assessBehavior(missing);assert.equal(r.status,'needs-clarification');assert.ok(r.gaps.some(g=>g.id==='lifecycle.close'));assert.ok(r.gaps.some(g=>g.id==='interaction.action.interrupt'));assert.ok(r.gaps.some(g=>g.id==='errors.recovery.rejected-shell'));
 assert.throws(()=>behaviorAcceptance(missing),/needs clarification/);
});
test('build-only coverage, unknown facets, invented references and duplicate IDs do not become accepted behavior',()=>{
 const b=clone();b.scenarios=[];assert.ok(assessBehavior(b).gaps.some(g=>g.reason==='missing-scenario'));
 b.protocol.mode='unknown';assert.ok(assessBehavior(b).gaps.some(g=>g.id==='protocol.mode'));
 for(const change of [b=>b.scenarios[0].covers.push('invented.permission'),b=>b.interaction.actions.push(b.interaction.actions[0]),b=>b.scenarios.push(b.scenarios[0]),b=>b.scenarios[0].covers.push(b.scenarios[0].covers[0]),b=>b.interaction.mode='none']){const c=clone();change(c);assert.throws(()=>assessBehavior(c));}
});
test('stateful-sequence scenarios pin an existing comparison case without reading or executing it',()=>{
 const b=clone();b.scenarios.push({id:'sequence-state',title:'Retain state in one instance',validation:'stateful-sequence',covers:['lifecycle.lifetime'],steps:[{action:'Reuse the same instance',expected:'State remains available'}]});const sequence=b.scenarios.at(-1);assert.ok(assessBehavior(b).gaps.some(g=>g.reason==='missing-sequence-reference'));
 sequence.sequenceCase={casesSha256:'a'.repeat(64),name:'same-instance-cwd'};const r=assessBehavior(b);assert.equal(r.status,'declared-for-validation');assert.equal(r.verification,'not-run');
 const changed=structuredClone(b);changed.scenarios.at(-1).sequenceCase.casesSha256='b'.repeat(64);assert.notEqual(assessBehavior(changed).sha256,r.sha256);
});
test('behavior follows feature specifications and prompts while legacy features remain unchanged',()=>{
 const feature={schema:'carve/feature@1',title:'Console',description:'Direct input',target:{path:'synthetic'},steps:['Connect'],acceptance:['Run cases'],examples:[{name:'finite',args:[],expected:null}]};
 assert.equal(assessFeature(feature).status,'ready-for-probe');assert.equal('behavior' in assessFeature(feature),false);
 const b=clone();b.scenarios=[];const result=assessFeature({...feature,behavior:b});assert.equal(result.status,'draft');assert.ok(result.missing.some(m=>m.startsWith('behavior:')));
 assert.ok(featurePrompt(assessFeature({...feature,behavior:clone()}).feature,'feature.json').includes('do not replace continuous sessions with independent calls'));
});
test('work packages pin exact behavior, generate scenario acceptance, and reject stale or unresolved contracts',async t=>{
 const root=await scratch(t),p=plan(),spec=specFor(p),record=bindWorkContract(p,spec,'console');
 assert.equal(record.assignment.acceptance.length,5);assert.equal(record.assignment.acceptance[1].behaviorScenario,'live-input');assert.deepEqual(record.interface.contract.behavior,clone());
 const result=await createWorkPackage(p,spec,'console',path.join(root,'packet'));
 const acceptance=await readWorkPackage(result.package,{view:'acceptance'});assert.ok(acceptance.items.some(row=>row.behaviorScenario==='restart-metadata'));assert.equal(acceptance.verification,'not-run');
 const changed=plan();changed.features[0].contract.behavior.protocol.mode='request-response';assert.throws(()=>bindWorkContract(changed,spec,'console'),/Stale planId/);
 const incomplete=plan();incomplete.features[0].contract.behavior.scenarios=[];assert.throws(()=>bindWorkContract(incomplete,specFor(incomplete),'console'),/needs clarification/);
 const tampered=structuredClone(record);tampered.assignment.acceptance.pop();assert.throws(()=>workRecordSchema.parse(tampered),/Generated behavior acceptance/);
 const collision=structuredClone(spec);collision.assignments[0].acceptance[0].name='behavior:live-input';assert.throws(()=>bindWorkContract(p,collision,'console'),/collide/);
});
test('feature requests retain missing behavior questions and immutable revisions',async t=>{
 const root=await scratch(t),work=path.join(root,'work');await survey(path.resolve('examples/behavior/interactive-console.json'),{workspace:work});
 const request={schema:'carve/feature-request@1',goal:'Direct-input console',behavior:{trigger:'Connect',input:'Keys',output:'Peer bytes',state:'sequence'},boundary:{ui:'required',remote:'required',host:'required'},contract:clone()};
 request.contract.scenarios=[];const draft=await featureScope(work,{request});assert.equal(draft.behaviorContract.status,'needs-clarification');assert.ok(draft.questions.some(q=>q.id==='behavior-contract'));
 const complete=await featureScope(work,{request:{...request,contract:clone()},parentId:draft.id});assert.equal(complete.behaviorContract.status,'declared-for-validation');assert.equal(complete.status,'needs-evidence');assert.equal((await featureScope(work,{id:draft.id})).behaviorContract.status,'needs-clarification');
});

test('protocol-only checks cannot satisfy UI gestures or process restart requirements',()=>{
 const b=clone();b.scenarios=b.scenarios.filter(s=>s.validation!=='ui'&&s.validation!=='restart');
 const r=assessBehavior(b);assert.equal(r.status,'needs-clarification');assert.ok(r.gaps.some(g=>g.id==='interaction.surface'&&g.prompt.includes('ui')));assert.ok(r.gaps.some(g=>g.id==='persistence.restart'&&g.prompt.includes('restart')));
});
