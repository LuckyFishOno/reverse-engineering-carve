import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {assessBehavior,checkBehavior} from '../dist/behavior.js';
import {analyzeProjectPlan,parseProjectPlan} from '../dist/project-plan.js';
import {bindWorkContract} from '../dist/work-contract.js';
const example=JSON.parse(await readFile('examples/behavior/interactive-console.json','utf8'));
const hash='a'.repeat(64),ref={sourceSha256:hash,evidenceId:hash,locator:'Static resource node at offset 64'};
const claims=[
 {id:'resource',subject:'interaction.surface',statement:'The original resource declares a canvas.',kind:'original-evidence',references:[ref],limits:'Resource declaration only; runtime event handling unknown.'},
 {id:'guess',subject:'protocol.mode',statement:'A continuous shell is likely.',kind:'hypothesis',basis:[ref],uncertainty:'Protocol negotiation has not been observed.'},
 {id:'design',subject:'persistence.excluded',statement:'Do not persist live state.',kind:'target-design',rationale:'Chosen target privacy policy; not recovered.'},
 {id:'reported',subject:'lifecycle.reset',statement:'Reset matched the supplied cases.',kind:'verified-behavior',comparison:{reportSha256:hash,originalSha256:hash,candidateSha256:'b'.repeat(64),casesSha256:hash,scope:'Three reset sequences only',environment:'Source-owned local harness',limitations:'No UI, server or other device coverage'}}
];
const contract=()=>({...structuredClone(example),provenance:{schema:'carve/provenance@1',claims:structuredClone(claims)}});
test('classification never promotes static evidence or reported comparisons into authenticated behavior',()=>{
 const r=assessBehavior(contract());assert.equal(r.verification,'not-run');assert.equal(r.semanticMatch,'unconfirmed');
 const page=checkBehavior(contract(),{view:'provenance',limit:2,budgetBytes:8192});assert.equal(page.provenance.authenticated,false);assert.equal(page.nextOffset,2);assert.equal(page.provenance.counts['verified-behavior'],1);assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));
 const legacy=structuredClone(example);delete legacy.provenance;assert.equal(checkBehavior(legacy).provenance.status,'unclassified');assert.ok(checkBehavior(contract()).provenance.unclassifiedRequirements>0);
 assert.equal(r.requirements.find(r=>r.id==='protocol.mode').provenance[0].kind,'hypothesis');
});
test('fabricated classification shapes, missing report scope, duplicate IDs and unknown subjects are rejected',()=>{
 for(const mutate of [b=>delete b.provenance.claims[0].references,b=>delete b.provenance.claims[3].comparison.limitations,b=>b.provenance.claims[3].comparison.reportSha256='bad',b=>b.provenance.claims[1].id='resource',b=>b.provenance.claims[0].subject='invented.requirement',b=>b.provenance.claims[2].kind='original-evidence']){
  const b=contract();mutate(b);assert.throws(()=>assessBehavior(b));
 }
});
function plan(b){return{schema:'carve/project-plan@1',goal:'Synthetic console',target:{schema:'carve/target@1',platform:'macos',delivery:'desktop-app'},features:[{id:'console',title:'Console',contract:{input:'Keys',output:'Bytes',state:'Session',errors:'Failures',behavior:b}}]};}
function spec(p){const a=analyzeProjectPlan(parseProjectPlan(p));return{schema:'carve/work-spec@1',planId:a.planId,assignments:[{feature:'console',taskId:a.tasks[0].taskId,files:['console.ts'],acceptance:[{name:'build',criterion:'Readiness only'}]}]};}
test('provenance survives work binding and changed classification or comparison scope invalidates old assignments',()=>{
 const p=plan(contract()),s=spec(p),r=bindWorkContract(p,s,'console');assert.deepEqual(r.interface.contract.behavior.provenance.claims,claims);assert.equal(r.verification,'not-run');
 for(const mutate of [b=>b.provenance.claims[3].comparison.scope='Different coverage',b=>{b.provenance.claims[1]={id:'guess',subject:'protocol.mode',statement:'Choose a shell',kind:'target-design',rationale:'Target requirement'};}]){
  const b=contract();mutate(b);assert.notEqual(assessBehavior(b).sha256,assessBehavior(contract()).sha256);assert.throws(()=>bindWorkContract(plan(b),s,'console'),/Stale planId/);
 }
});
