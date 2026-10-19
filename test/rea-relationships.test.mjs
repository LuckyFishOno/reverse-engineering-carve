import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {mkdtemp,readFile,writeFile,rm,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {survey,openIndex} from '../dist/survey.js';
import {parseReaNativeEvidence,importReaNative} from '../dist/rea-native.js';
import {readObservation} from '../dist/native.js';
import {analysisContext} from '../dist/context.js';
import {traceBoundary} from '../dist/trace.js';
import {reconstruct} from '../dist/reconstruction.js';
import {relocateWorkspace} from '../dist/relocate.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';

const captured=JSON.parse(await readFile(new URL('./fixtures/rea-native-relationships.json',import.meta.url),'utf8')).records,exec=promisify(execFile);
const hash=value=>createHash('sha256').update(value).digest('hex');
function canonical(value){if(value===null||typeof value!=='object')return JSON.stringify(value);return Array.isArray(value)?'['+value.map(canonical).join(',')+']':'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';}
function seal(record){const {evidence_id,subject,...rest}=record;record.evidence_id='ev_'+hash(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));}
function reprofile(record){record.analysis_profile.digest=hash(canonical({provider:record.analysis_profile.provider,parameters:record.analysis_profile.parameters}));seal(record);}
function normalized(record,change){change(record.normalized_result);record.raw_result.value=structuredClone(record.normalized_result);seal(record);}
async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-rea-relationships-'));t.after(()=>rm(root,{recursive:true,force:true}));
 // Header-only synthetic validator input. Real native execution is tested separately.
 const bytes=Buffer.alloc(64);bytes.writeUInt32LE(0xfeedfacf,0);bytes.writeUInt32LE(0x100000c,4);bytes.writeUInt32LE(2,12);const input=path.join(root,'dependency.bin');await writeFile(input,bytes);const workspace=path.join(root,'work');await survey(input,{workspace});
 const records=structuredClone(captured);
 for(const group of Object.values(records))for(const record of Object.values(group)){record.subject.digest.sha256=hash(bytes);record.subject.name='Synthetic validator source; no execution claim';record.subject.local_path='/not/opened';seal(record);}
 const save=async name=>{const args={file:'dependency.bin'};for(const [role,record] of Object.entries(records[name])){const file=path.join(root,name+'-'+role+'.json');await writeFile(file,JSON.stringify(record));args[role]=file;}return args;};
 const run=async(name='feature_fee',omit=[])=>{const args=await save(name);for(const role of omit)delete args[role];return importReaNative(workspace,args);};
 const pack=async(ids,work=workspace)=>{const contract=path.join(root,'contract.json'),implementation=path.join(root,'implementation.mjs');await writeFile(implementation,'export const fee=()=>0;');await writeFile(contract,JSON.stringify({schema:'carve/reconstruction@1',goal:'Synthetic relationship binding test',file:'dependency.bin',evidenceIds:ids,behavior:{description:'Binding test only; no behavior comparison',inputDomain:'none',outputDomain:'zero'},dependencies:[],unknowns:['Synthetic input does not implement these captured instructions.']}));return reconstruct(work,{contract,implementation,export:'fee',out:path.join(root,'package-'+Math.random())});};
 return{root,input,workspace,records,save,run,pack};
}

test('checks captured REA typed references and partial call coverage using known semantic IDs',()=>{
 assert.equal(parseReaNativeEvidence(captured.feature_fee.callees,'procedure_callees').evidence_id,'ev_3be5c6d76293f80da1b8a4f0584e5738096ac775ce1dfc48b276cae72d95f06f');
 assert.equal(parseReaNativeEvidence(captured.feature_fee.references,'procedure_references').evidence_id,'ev_772e45600e1a1dd4e007b3567e227566600fbd1f5d83b4ca4f80860df63f7381');
 assert.equal(parseReaNativeEvidence(captured.fee_callback.callees,'procedure_callees').relationship_coverage.status,'partial');
});

test('traces only typed calls, keeps unindexed dependencies explicit, then links imported helper code',async t=>{
 const f=await fixture(t),seed=await f.run(),first=await traceBoundary(f.workspace,seed.observationId);assert.equal(first.edges.length,2);assert.ok(first.edges.every(e=>!e.indexed&&e.resolution==='missing-compatible-observation'));assert.equal(first.dependencyClosure,'not-established');
 assert.equal(seed.relationships.references,7);assert.equal(seed.relationships.callees,2);assert.equal(seed.relationships.calleesIncomplete,false);
 const a=await f.run('fee_blocks'),b=await f.run('fee_discount'),graph=await traceBoundary(f.workspace,seed.observationId);assert.equal(graph.nodes.length,3);assert.equal(graph.edges.length,2);assert.ok(graph.edges.every(e=>e.indexed&&e.callSiteCount===1&&e.callSites[0].kind==='UNCONDITIONAL_CALL'));assert.equal(graph.relationshipsIncomplete,false);assert.equal(graph.dependencyClosure,'not-established');
 assert.deepEqual(new Set(graph.edges.map(e=>e.toId)),new Set([a.observationId,b.observationId]));
 const context=await analysisContext(f.workspace,{ids:[seed.observationId],view:'outline',budgetBytes:16384});assert.equal(context.items.length,3);assert.ok(context.items.slice(1).every(i=>i.reason==='recorded-static-callee'));assert.equal(context.calleeExpansionLimited,false);
 const depth=await traceBoundary(f.workspace,seed.observationId,{depth:0});assert.equal(depth.truncated,true);assert.equal(depth.edges.length,0);
 const capped=await traceBoundary(f.workspace,seed.observationId,{maxNodes:1});assert.equal(capped.nodes.length,1);assert.equal(capped.truncated,true);
});

test('retains unresolved callback locations instead of inventing a callable target',async t=>{
 const f=await fixture(t),seed=await f.run('fee_callback'),view=await readObservation(f.workspace,seed.observationId);assert.equal(view.relationshipEvidence.coverageStatus,'partial');assert.equal(view.relationshipEvidence.unresolvedCallCount,1);assert.equal(view.linksTruncated.callees,true);assert.equal(view.callees.length,0);
 const graph=await traceBoundary(f.workspace,seed.observationId);assert.equal(graph.unresolvedCalls.length,1);assert.equal(graph.relationshipsIncomplete,true);assert.match(graph.unresolvedCalls[0].reason,/no call destination/);assert.equal(graph.edges.length,0);
 const context=await analysisContext(f.workspace,{ids:[seed.observationId]});assert.equal(context.calleeExpansionLimited,true);
});

test('preserves thunks, address spaces and data references without treating data as a call',async t=>{
 const f=await fixture(t),seed=await f.run('fee_notice'),view=await readObservation(f.workspace,seed.observationId);assert.equal(view.callees.length,1);assert.equal(view.callees[0].name,'_puts');assert.equal(view.callees[0].thunk,true);assert.equal(view.callees[0].thunkTarget,'EXTERNAL:0x3');assert.ok(view.references.some(r=>r.targetAddress.startsWith('stack:')));assert.ok(view.references.some(r=>r.kind.type==='PARAM'&&!r.kind.call));
 const graph=await traceBoundary(f.workspace,seed.observationId);assert.equal(graph.edges.length,1);assert.equal(graph.edges[0].thunkTarget,'EXTERNAL:0x3');assert.equal(graph.edges[0].indexed,false);
});

test('one optional relationship record never silently establishes complete graph coverage',async t=>{
 const f=await fixture(t),refs=await f.run('feature_fee',['callees']),calls=await f.run('feature_fee',['references']),legacy=await f.run('feature_fee',['callees','references']);
 assert.notEqual(refs.observationId,calls.observationId);assert.notEqual(refs.observationId,legacy.observationId);assert.equal(refs.relationships.callees,2);assert.equal(refs.relationships.calleesIncomplete,true);assert.equal(calls.relationships.referencesIncomplete,true);assert.equal(legacy.provider.adapter,'rea-ghidra-function@1');
 for(const r of [refs,calls,legacy])assert.equal((await traceBoundary(f.workspace,r.observationId)).relationshipsIncomplete,true);
});

test('trace and budgeted context refuse newer helper observations from another REA profile or provider',async t=>{
 const f=await fixture(t),seed=await f.run(),right=await f.run('fee_blocks');
 for(const r of Object.values(f.records.fee_blocks)){r.analysis_profile.parameters.analyzer_preset='synthetic other profile';reprofile(r);}
 const wrong=await f.run('fee_blocks');assert.notEqual(right.observationId,wrong.observationId);
 const db=openIndex(f.workspace),row=db.prepare('SELECT * FROM observations WHERE id=?').get(right.observationId),detail=JSON.parse(row.detail);detail.provider={name:'ghidra',version:'other'};const forged=hash('different internal provider');db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(forged,row.artifact,row.sha256,row.kind,row.name,row.address,row.content,JSON.stringify(detail),row.evidence,row.evidence_sha256);db.close();
 let graph=await traceBoundary(f.workspace,seed.observationId);assert.equal(graph.edges.find(e=>e.to===row.address).toId,right.observationId);
 let context=await analysisContext(f.workspace,{ids:[seed.observationId],view:'outline',budgetBytes:16384});assert.ok(context.items.some(i=>i.id===right.observationId));assert.ok(!context.items.some(i=>[wrong.observationId,forged].includes(i.id)));
 const edit=openIndex(f.workspace);edit.prepare('DELETE FROM observations WHERE id=?').run(right.observationId);edit.close();graph=await traceBoundary(f.workspace,seed.observationId);assert.equal(graph.edges.find(e=>e.to===row.address).toId,null);context=await analysisContext(f.workspace,{ids:[seed.observationId],view:'outline'});assert.equal(context.items.length,1);
});

test('rejects source/profile/selector/direction mismatches in optional records',async t=>{
 const variants=[
 r=>{r.references.subject.digest.sha256='0'.repeat(64);seal(r.references);},
 r=>{r.callees.parameters.procedure='_another';seal(r.callees);},
 r=>{r.references.analysis_profile.parameters.analyzer_preset='other';reprofile(r.references);},
 r=>{r.references.parameters.direction='incoming';normalized(r.references,x=>{x.direction='incoming';});},
 r=>{normalized(r.references,x=>{x.procedure.name='_wrong';});},
 r=>{r.callees.normalized_result.push(r.callees.normalized_result[0]);r.callees.raw_result.value=structuredClone(r.callees.normalized_result);seal(r.callees);}
 ];
 for(const change of variants){const f=await fixture(t);change(f.records.feature_fee);await assert.rejects(f.run());}
});

test('rejects out-of-body, contradictory typed endpoints and raw/coverage edits',async t=>{
 const variants=[
 r=>normalized(r.references,x=>{x.references[0].source_address='0x1';}),
 r=>normalized(r.references,x=>{x.references.find(r=>r.kind.call).target_procedure.body.total_bytes++;}),
 r=>normalized(r.references,x=>{x.references.find(r=>r.kind.call).kind.flow=false;}),
 r=>normalized(r.references,x=>{x.references[0].source_procedure.name='_wrong';}),
 r=>{r.callees.raw_result.relationship_coverage={status:'unknown',reason:'not checked'};seal(r.callees);},
 r=>{r.references.normalized_result.references=[];seal(r.references);},
 r=>{r.references.normalized_result.references=[];},
 r=>normalized(r.references,x=>{x.unresolved_calls=[{address:'0x1',reason:'synthetic impossible location'}];})
 ];for(const change of variants){const f=await fixture(t);change(f.records.feature_fee);await assert.rejects(f.run());}
});

test('keeps unknown/partial coverage, provider limitations and list disagreement visible',async t=>{
 const f=await fixture(t);f.records.feature_fee.callees.relationship_coverage={status:'unknown',reason:'synthetic unavailable inventory'};f.records.feature_fee.callees.raw_result.relationship_coverage=structuredClone(f.records.feature_fee.callees.relationship_coverage);seal(f.records.feature_fee.callees);
 let seed=await f.run();assert.equal(seed.relationships.calleesIncomplete,true);assert.equal((await readObservation(f.workspace,seed.observationId)).relationshipEvidence.coverageStatus,'unknown');
 f.records.feature_fee=structuredClone(captured.feature_fee);for(const r of Object.values(f.records.feature_fee)){r.subject.digest.sha256=hash(await readFile(f.input));seal(r);}
 normalized(f.records.feature_fee.callees,x=>x.pop());seed=await f.run();assert.equal(seed.relationships.callees,2);assert.equal(seed.relationships.calleesIncomplete,true);assert.equal((await readObservation(f.workspace,seed.observationId)).relationshipEvidence.calleeReferenceAgreement,false);
 f.records.feature_fee.references.raw_result.limitations=['Synthetic provider reports limited body coverage'];seal(f.records.feature_fee.references);seed=await f.run();assert.equal(seed.relationships.referencesIncomplete,true);assert.equal((await readObservation(f.workspace,seed.observationId)).relationshipEvidence.perResultLimitationCount,1);
});

test('owned graph snapshots rebind during packaging and survive external file removal and relocation',async t=>{
 const f=await fixture(t),seed=await f.run(),a=await f.run('fee_blocks'),b=await f.run('fee_discount'),ids=[seed.observationId,a.observationId,b.observationId];
 for(const role of ['code','info','callees','references'])await rm(path.join(f.root,'feature_fee-'+role+'.json'));
 const pack=await f.pack(ids);assert.equal(pack.evidence.length,3);assert.equal(pack.evidence[0].provider.adapter,'rea-ghidra-function@2');
 const db=openIndex(f.workspace),row=db.prepare('SELECT detail FROM observations WHERE id=?').get(seed.observationId),detail=JSON.parse(row.detail);detail.callees=[];db.prepare('UPDATE observations SET detail=? WHERE id=?').run(JSON.stringify(detail),seed.observationId);await assert.rejects(f.pack(ids),/captured complete/);db.prepare('UPDATE observations SET detail=? WHERE id=?').run(row.detail,seed.observationId);db.close();
 const moved=path.join(f.root,'moved');await rename(f.workspace,moved);await relocateWorkspace(moved);assert.equal((await traceBoundary(moved,seed.observationId)).nodes.length,3);await f.pack(ids,moved);
});

test('actual CLI and stdio MCP expose optional relationship inputs and confine both paths',async t=>{
 const f=await fixture(t),args=await f.save('feature_fee'),cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
 const result=await exec(process.execPath,[cli,'import-rea-native',f.workspace,'--file',args.file,'--code',args.code,'--info',args.info,'--callees',args.callees,'--references',args.references]);assert.equal(JSON.parse(result.stdout).relationships.callees,2);
 const client=new Client({name:'rea-relationships-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const local={workspace:'work',file:args.file,code:path.basename(args.code),info:path.basename(args.info),callees:path.basename(args.callees),references:path.basename(args.references)};
 const response=await client.callTool({name:'carve_import_rea_native',arguments:local});assert.ok(!response.isError);assert.equal(JSON.parse(response.content[0].text).relationships.references,7);
 for(const field of ['callees','references']){const bad=await client.callTool({name:'carve_import_rea_native',arguments:{...local,[field]:'../outside.json'}});assert.equal(bad.isError,true);}
});

test('bounds call-site and unresolved-reason output while preserving omission flags',async t=>{
 const f=await fixture(t);normalized(f.records.feature_fee.references,x=>{const call=x.references.find(r=>r.kind.call);x.references=Array.from({length:25},(_,i)=>({...structuredClone(call),source_address:'0x'+(BigInt(x.procedure.address)+BigInt(i)).toString(16)}));});
 const seed=await f.run(),view=await readObservation(f.workspace,seed.observationId),callee=view.callees.find(c=>c.callSiteCount===25);assert.equal(callee.callSites.length,20);assert.equal(callee.callSitesTruncated,true);
 normalized(f.records.fee_callback.references,x=>{x.unresolved_calls[0].reason='x'.repeat(8000);});const callback=await f.run('fee_callback'),graph=await traceBoundary(f.workspace,callback.observationId);assert.equal(graph.unresolvedCalls[0].reason.length,1000);assert.equal(graph.unresolvedCalls[0].reasonTruncated,true);assert.equal(graph.unresolvedCallsTruncated,true);
 const detail=await readObservation(f.workspace,callback.observationId);assert.equal(detail.unresolvedCalls[0].reasonTruncated,true);assert.equal(detail.unresolvedCallsTruncated,true);
});
