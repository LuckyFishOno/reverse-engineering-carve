import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {mkdtemp,readFile,writeFile,rm,rename,mkdir,symlink,truncate} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {survey,openIndex} from '../dist/survey.js';
import {parseReaNativeEvidence,importReaNative} from '../dist/rea-native.js';
import {readObservation} from '../dist/native.js';
import {analysisContext} from '../dist/context.js';
import {featureMenu} from '../dist/feature-menu.js';
import {traceBoundary} from '../dist/trace.js';
import {reconstruct} from '../dist/reconstruction.js';
import {relocateWorkspace} from '../dist/relocate.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';

const realCode=JSON.parse(await readFile(new URL('./fixtures/rea-native-code.json',import.meta.url),'utf8'));
const realInfo=JSON.parse(await readFile(new URL('./fixtures/rea-native-info.json',import.meta.url),'utf8'));
const hash=value=>createHash('sha256').update(value).digest('hex');
// Synthetic validator fixtures use commitments only to reach source/shape checks.
// Actual producer ID vectors below and the independent native integration exercise
// the protocol without constructing their expected IDs through this helper.
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
function seal(record){const {evidence_id,subject,...rest}=record;record.evidence_id='ev_'+hash(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));return record;}
function profile(record){const p=record.analysis_profile;p.digest=hash(canonical({provider:p.provider,parameters:p.parameters}));return seal(record);}
async function fixture(t,{encrypted=false,format='mach-o',architecture='arm64'}={}){
 const root=await mkdtemp(path.join(tmpdir(),'carve-rea-native-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const binary=Buffer.alloc(format==='pe'?512:64);
 if(format==='elf'){binary.set([0x7f,0x45,0x4c,0x46,architecture==='x86'||architecture==='arm'?1:2,1,1]);binary.writeUInt16LE(({x86:3,x86_64:62,arm:40,arm64:183})[architecture],18);}
 else if(format==='pe'){binary.write('MZ');binary.writeUInt32LE(128,60);binary.set([80,69,0,0],128);binary.writeUInt16LE(architecture==='x86'?0x14c:0x8664,132);binary.writeUInt16LE(architecture==='x86'?0x10b:0x20b,152);}
 else {binary.writeUInt32LE(0xfeedfacf,0);binary.writeUInt32LE(0x100000c,4);}
 if(encrypted){binary.writeUInt32LE(1,16);binary.writeUInt32LE(24,20);binary.writeUInt32LE(0x2c,32);binary.writeUInt32LE(24,36);binary.writeUInt32LE(1,48);}
 const input=path.join(root,'swipe.bin'),workspace=path.join(root,'work');await writeFile(input,binary);await survey(input,{workspace});
 const code=structuredClone(realCode),info=structuredClone(realInfo);
 for(const r of [code,info]){r.subject.digest.sha256=hash(binary);r.subject.local_path='/historical/unavailable/path';r.subject.name='Synthetic validator bytes, not a real decompilation';r.subject.format=format;r.subject.architecture=architecture;r.analysis_profile.parameters.target_format=format;r.analysis_profile.parameters.architecture=architecture;r.analysis_profile.parameters.available_architectures=[architecture];profile(r);}
 if(architecture==='x86'||architecture==='arm'){for(const result of [info.normalized_result,info.raw_result.value]){result.entrypoint='0x460';result.body.ranges=[{start:'0x460',end:'0x4d7'}];}seal(info);}
 const codeFile=path.join(root,'code.json'),infoFile=path.join(root,'info.json');
 const save=async()=>{await writeFile(codeFile,JSON.stringify(code));await writeFile(infoFile,JSON.stringify(info));};await save();
 const contract=path.join(root,'contract.json'),implementation=path.join(root,'implementation.mjs');await writeFile(implementation,'export const fee=()=>0;');
 const run=()=>importReaNative(workspace,{file:'swipe.bin',code:codeFile,info:infoFile});
 const pack=async(record,work=workspace)=>{await writeFile(contract,JSON.stringify({schema:'carve/reconstruction@1',goal:'Synthetic binding test',file:'swipe.bin',evidenceIds:[record.observationId],behavior:{description:'Validator fixture only; no binary behavior claim',inputDomain:'none',outputDomain:'zero'},dependencies:[],unknowns:['Synthetic bytes do not execute or implement this code.']}));return reconstruct(work,{contract,implementation,export:'fee',out:path.join(root,'package-'+Math.random())});};
 return{root,input,workspace,code,info,codeFile,infoFile,save,run,pack};
}

test('authenticates real REA6.7 Ghidra Evidence/profile commitment vectors',()=>{
 assert.equal(parseReaNativeEvidence(realCode,'procedure_pseudo_code').evidence_id,'ev_83d4b6a2ce4fb3ddf338867fe63f2c2a00e856c1d04fcdc6dd5ed76a386ebe9d');
 assert.equal(parseReaNativeEvidence(realInfo,'procedure_info').evidence_id,'ev_f6d8b079a445f06b9b9db021d33f76fa02e394fbe1a0aa458f4e9c5e38e8f45b');
 const changed=structuredClone(realCode);changed.normalized_result+='changed';assert.throws(()=>parseReaNativeEvidence(changed,'procedure_pseudo_code'),/semantic ID/);
 const p=structuredClone(realCode);p.analysis_profile.parameters.analyzer_preset='changed';assert.throws(()=>parseReaNativeEvidence(p,'procedure_pseudo_code'),/profile digest/);
 const display=structuredClone(realCode);display.subject.name='Moved';display.subject.local_path='/not/read';assert.equal(parseReaNativeEvidence(display,'procedure_pseudo_code').evidence_id,realCode.evidence_id);
});

test('imports idempotently, preserves producer identity and marks missing relationships',async t=>{
 const f=await fixture(t),first=await f.run(),again=await f.run();assert.equal(first.observationId,again.observationId);assert.equal(first.startsRea,false);assert.equal(first.executesTarget,false);
 const db=openIndex(f.workspace,true);assert.equal(db.prepare('SELECT count(*) n FROM observations').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM observation_search').get().n,1);db.close();
 const detail=await readObservation(f.workspace,first.observationId);assert.equal(detail.provider.name,'rea');assert.equal(detail.provider.analysisProvider.id,'ghidra');assert.equal(detail.externalEvidence.codeEvidenceId,f.code.evidence_id);assert.equal(detail.relationshipScope,'not-imported');assert.equal(detail.linksTruncated.callees,true);
 const context=await analysisContext(f.workspace,{ids:[first.observationId]});assert.equal(context.calleeExpansionLimited,true);
 const trace=await traceBoundary(f.workspace,first.observationId);assert.equal(trace.relationshipsIncomplete,true);assert.equal(trace.edges.length,0);
 const menu=await featureMenu(f.workspace,{choice:'swipe'});assert.equal(menu.items[0].basis,'recorded-code-lead');
});

test('owned snapshots survive removed producer files and workspace relocation',async t=>{
 const f=await fixture(t),record=await f.run();await rm(f.codeFile);await rm(f.infoFile);
 const packed=await f.pack(record);assert.equal(packed.evidence[0].provider.name,'rea');
 const moved=path.join(f.root,'moved');await rename(f.workspace,moved);await relocateWorkspace(moved);
 const again=await f.pack(record,moved);assert.equal(again.evidence[0].provider.codeEvidenceId,f.code.evidence_id);
});

test('preserves exact UTF8 BOM bytes and repairs derived search rows on repeat import',async t=>{
 const f=await fixture(t);await writeFile(f.codeFile,Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),await readFile(f.codeFile)]));const result=await f.run();
 const snapshot=JSON.parse(await readFile(result.evidence,'utf8'));assert.equal(snapshot.records[0].json.charCodeAt(0),0xfeff);assert.equal(snapshot.records[0].sha256,hash(await readFile(f.codeFile)));
 const db=openIndex(f.workspace);db.prepare('DELETE FROM observation_search WHERE id=?').run(result.observationId);db.close();await f.run();const restored=openIndex(f.workspace,true);assert.equal(restored.prepare('SELECT count(*) n FROM observation_search WHERE id=?').get(result.observationId).n,1);restored.close();
});

test('refuses edited snapshots and normalized SQL body/origin tampering during reconstruction',async t=>{
 const f=await fixture(t),record=await f.run(),snapshot=await readFile(record.evidence);
 await writeFile(record.evidence,Buffer.concat([snapshot,Buffer.from(' ')]));await assert.rejects(f.pack(record),/evidence changed|snapshot bytes changed/i);await writeFile(record.evidence,snapshot);
 const db=openIndex(f.workspace);const original=db.prepare('SELECT detail FROM observations WHERE id=?').get(record.observationId).detail;
 let changed=JSON.parse(original);changed.pseudocode='return fabricated_behavior;';db.prepare('UPDATE observations SET detail=? WHERE id=?').run(JSON.stringify(changed),record.observationId);await assert.rejects(f.pack(record),/differs from the captured/);
 changed=JSON.parse(original);delete changed.rea;changed.provider={name:'ghidra'};db.prepare('UPDATE observations SET detail=? WHERE id=?').run(JSON.stringify(changed),record.observationId);await assert.rejects(f.pack(record),/differs from the captured/);
 const rebased=path.join(f.root,'relabeled.json');await writeFile(rebased,snapshot);db.prepare('UPDATE observations SET evidence=? WHERE id=?').run(rebased,record.observationId);await assert.rejects(f.pack(record),/differs from the captured/);db.close();
});

test('rejects stale source, different subjects and mismatched exact selectors',async t=>{
 const f=await fixture(t);f.info.subject.digest.sha256='0'.repeat(64);seal(f.info);await f.save();await assert.rejects(f.run(),/different source bytes/);
 f.info.subject.digest.sha256=f.code.subject.digest.sha256;f.info.parameters.procedure='another';seal(f.info);await f.save();await assert.rejects(f.run(),/exact selector/);
 f.info.parameters.procedure=f.code.parameters.procedure;seal(f.info);await f.save();await writeFile(f.input,Buffer.from('changed source'));await assert.rejects(f.run(),/changed|stale|differs/i);
});

test('rejects null/partial/external/malformed function evidence instead of promoting metadata',async t=>{
 const changes=[
  (c,i)=>{c.normalized_result=null;c.raw_result.value=null;},
  (c,i)=>{c.raw_result.limitations=['truncated response'];},
  (c,i)=>{c.raw_result.partial=true;},
  (c,i)=>{c.raw_result.value='different result';},
  (c,i)=>{i.normalized_result.classification.external=true;i.raw_result.value.classification.external=true;},
  (c,i)=>{i.normalized_result.body.available=false;i.raw_result.value.body.available=false;},
  (c,i)=>{i.normalized_result.body.total_bytes++;i.raw_result.value.body.total_bytes++;},
  (c,i)=>{i.normalized_result.body.ranges[0].end='0x100000459';i.raw_result.value.body.ranges[0].end='0x100000459';},
  (c,i)=>{c.normalized_result='\ud800';c.raw_result.value='\ud800';}
 ];
 for(const change of changes){const f=await fixture(t);change(f.code,f.info);seal(f.code);seal(f.info);await f.save();await assert.rejects(f.run());}
});

test('rejects inconsistent profile/source format/architecture and declared encrypted input',async t=>{
 const f=await fixture(t);for(const record of [f.code,f.info]){record.subject.architecture='x86_64';record.analysis_profile.parameters.architecture='x86_64';profile(record);}await f.save();await assert.rejects(f.run(),/freshly hashed/);
 const encrypted=await fixture(t,{encrypted:true});await assert.rejects(encrypted.run(),/unencrypted supported/);
 const p=structuredClone(realCode);p.analysis_profile.parameters.architecture='x86';profile(p);assert.throws(()=>parseReaNativeEvidence(p,'procedure_pseudo_code'),/contradicts/);
});

test('validates declared ELF/PE/32-bit envelopes while refusing impossible 32-bit addresses',async t=>{
 for(const options of [{format:'elf',architecture:'x86_64'},{format:'elf',architecture:'arm'},{format:'pe',architecture:'x86_64'},{format:'pe',architecture:'x86'}]){const f=await fixture(t,options);const imported=await f.run();assert.equal(imported.status,'imported-static-function');}
 const f=await fixture(t,{format:'elf',architecture:'x86'});for(const result of [f.info.normalized_result,f.info.raw_result.value]){result.entrypoint='0x100000460';result.body.ranges=[{start:'0x100000460',end:'0x1000004d7'}];}seal(f.info);await f.save();await assert.rejects(f.run(),/architecture width/);
});

test('body coverage distinguishes adjacent ranges from a real gap',async t=>{
 const f=await fixture(t);for(const r of [f.info.normalized_result,f.info.raw_result.value])r.body.ranges=[{start:'0x100000460',end:'0x10000049b'},{start:'0x10000049c',end:'0x1000004d7'}];seal(f.info);await f.save();await f.run();
 for(const r of [f.info.normalized_result,f.info.raw_result.value]){r.body.ranges[1].start='0x10000049d';r.body.total_bytes=119;}seal(f.info);await f.save();await assert.rejects(f.run(),/coverage contradicts/);
});

test('bounds input bytes/JSON depth and refuses symlink snapshot storage',async t=>{
 const f=await fixture(t);await truncate(f.codeFile,16*1024*1024+1);await assert.rejects(f.run(),/byte budget/);
 await f.save();await writeFile(f.codeFile,'['.repeat(70)+'0'+']'.repeat(70));await assert.rejects(f.run(),/nesting/);
 await f.save();const outside=path.join(f.root,'outside');await mkdir(outside);await symlink(outside,path.join(f.workspace,'rea-native-evidence'));await assert.rejects(f.run(),/symlink/);
});

test('actual Carve MCP imports local records, confines all supplied paths and exposes REA provenance',async t=>{
 const f=await fixture(t),client=new Client({name:'rea-native-import-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('../dist/cli.js',import.meta.url)),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const call=async args=>client.callTool({name:'carve_import_rea_native',arguments:args});
 const result=await call({workspace:'work',file:'swipe.bin',code:'code.json',info:'info.json'});assert.ok(!result.isError);const row=JSON.parse(result.content[0].text);assert.equal(row.provider.name,'rea');
 const escaped=await call({workspace:'work',file:'swipe.bin',code:'../outside.json',info:'info.json'});assert.equal(escaped.isError,true);
 const observation=await client.callTool({name:'carve_observation',arguments:{workspace:'work',id:row.observationId}});assert.equal(JSON.parse(observation.content[0].text).externalEvidence.adapter,'rea-ghidra-function@1');
});
