import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,readFile,writeFile,rm,symlink,rename} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,openIndex} from '../dist/survey.js';
import {inspectPeUi} from '../dist/pe-ui.js';
import {importReaNative} from '../dist/rea-native.js';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
const codeTemplate=JSON.parse(await readFile(new URL('./fixtures/rea-native-code.json',import.meta.url),'utf8'));
const infoTemplate=JSON.parse(await readFile(new URL('./fixtures/rea-native-info.json',import.meta.url),'utf8'));
const hash=x=>createHash('sha256').update(x).digest('hex');
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
function seal(r){const {evidence_id,subject,...rest}=r;r.evidence_id='ev_'+hash(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));}
// Synthetic commitments exercise binding integrity only, not original executable behavior.
async function fixture(t,plus=false,splitHandlers=false){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ui-entries-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const file=path.join(root,'ui.exe'),built=buildUiPe({plus}),bytes=built.bytes,workspace=path.join(root,'work');if(splitHandlers)bytes.writeUInt32LE(0x408030,built.table+built.rowSize+20);await writeFile(file,bytes);await survey(file,{workspace});
 const address=plus?'0x140008010':'0x408010';
 const imported=async({entry=address,preset='default'}={})=>{
  const code=structuredClone(codeTemplate),info=structuredClone(infoTemplate);
  for(const r of [code,info]){r.subject.digest.sha256=hash(bytes);r.subject.format='pe';r.subject.architecture=plus?'x86_64':'x86';r.subject.name='Synthetic UI binding fixture';Object.assign(r.analysis_profile.parameters,{target_format:'pe',architecture:r.subject.architecture,available_architectures:[r.subject.architecture],analyzer_preset:preset});r.analysis_profile.digest=hash(canonical({provider:r.analysis_profile.provider,parameters:r.analysis_profile.parameters}));}
  for(const r of [info.raw_result.value,info.normalized_result]){r.name='ui_handler';r.entrypoint=entry;r.body.ranges=[{start:entry,end:'0x'+(BigInt(entry)+119n).toString(16)}];}
  seal(code);seal(info);
  const c=path.join(root,'code.json'),i=path.join(root,'info.json');await writeFile(c,JSON.stringify(code));await writeFile(i,JSON.stringify(info));
  return importReaNative(workspace,{file:'ui.exe',code:c,info:i});
 };
 const inspect=(options={})=>inspectPeUi(workspace,{file:'ui.exe',view:'entries',command:1001,...options});
 return{root,file,workspace,address,imported,inspect};
}
test('exact imported entries bind x86 and x64 UI candidates without confirming dispatch or semantics',async t=>{
 for(const plus of [false,true]){
  const f=await fixture(t,plus),record=await f.imported(),r=await f.inspect({functionIds:[record.observationId]});
  assert.equal(r.items.length,1);const entry=r.items[0];assert.equal(entry.status,'static-entry-matched');assert.equal(entry.dispatchConfirmed,false);assert.equal(entry.semanticMatch,'unconfirmed');assert.equal(entry.functions[0].observationId,record.observationId);assert.equal(entry.functions[0].relationshipsIncomplete,true);assert.equal(entry.functions[0].producerAuthentication,'not-established');assert.equal(entry.dispatch.length,2);
  const report=JSON.parse(await readFile(r.bindingEvidence,'utf8'));assert.equal(hash(await readFile(r.bindingEvidence)),r.bindingId);assert.equal(report.sourceSha256,record.sourceSha256);assert.equal(report.records[0].snapshotSha256,record.evidenceSha256);assert.equal(JSON.stringify(r).includes('pseudocode'),false);
  assert.equal((await f.inspect({functionIds:[record.observationId]})).bindingId,r.bindingId);
 }
});
test('missing evidence, containing bodies and absent handlers remain explicit without address guessing',async t=>{
 const f=await fixture(t),none=await f.inspect();assert.equal(none.items[0].status,'candidate-only');
 const inside=await f.imported({entry:'0x408000'});assert.equal((await f.inspect({functionIds:[inside.observationId]})).items[0].status,'candidate-only');
 const missing=await f.inspect({command:1003});assert.equal(missing.items[0].status,'missing-handler-candidate');assert.equal(missing.items[0].dispatchConfirmed,false);assert.equal((await f.inspect({command:9999})).items[0].status,'missing-ui-command');
 await assert.rejects(f.inspect({functionIds:['a'.repeat(64)]}),/missing/);
 await assert.rejects(f.inspect({functionIds:[inside.observationId,inside.observationId]}),/unique/);
 await assert.rejects(f.inspect({functionIds:Array.from({length:17},(_,i)=>i.toString(16).padStart(64,'0'))}),/up to16/);
 await assert.rejects(f.inspect({query:'Open'}),/does not accept query/);
});
test('conflicting profiles remain ambiguous and ordering does not change immutable binding identity',async t=>{
 const f=await fixture(t),a=await f.imported(),b=await f.imported({preset:'alternate'});
 const x=await f.inspect({functionIds:[a.observationId,b.observationId]}),y=await f.inspect({functionIds:[b.observationId,a.observationId]});
 assert.equal(x.items[0].status,'ambiguous-function-evidence');assert.equal(x.items[0].functions.length,2);assert.equal(x.bindingId,y.bindingId);assert.equal(x.items[0].dispatchConfirmed,false);
});
test('tampered snapshots, derived SQL rows, foreign artifacts and changed input cannot become entry matches',async t=>{
 const f=await fixture(t),r=await f.imported(),bytes=await readFile(r.evidence);await writeFile(r.evidence,Buffer.concat([bytes,Buffer.from(' ')]));await assert.rejects(f.inspect({functionIds:[r.observationId]}),/snapshot bytes changed/);await writeFile(r.evidence,bytes);
 const db=openIndex(f.workspace),original=db.prepare('SELECT * FROM observations WHERE id=?').get(r.observationId);
 db.prepare('UPDATE observations SET name=? WHERE id=?').run('forged',r.observationId);await assert.rejects(f.inspect({functionIds:[r.observationId]}),/differs from/);db.prepare('UPDATE observations SET name=?,artifact=? WHERE id=?').run(original.name,'other.exe',r.observationId);await assert.rejects(f.inspect({functionIds:[r.observationId]}),/same current/);db.prepare('UPDATE observations SET artifact=? WHERE id=?').run(original.artifact,r.observationId);db.close();
 await writeFile(f.file,Buffer.from('changed'));await assert.rejects(f.inspect({functionIds:[r.observationId]}),/changed|stale/);
});
test('redirected owned snapshots are refused before following evidence outside the workspace',async t=>{
 const f=await fixture(t),r=await f.imported(),folder=path.dirname(r.evidence),moved=path.join(f.root,'outside');await rename(folder,moved);await symlink(moved,folder);
 await assert.rejects(f.inspect({functionIds:[r.observationId]}),/owned REA snapshot/);
});
test('CLI and a fresh MCP expose identical entry binding receipts with explicit observation selection',async t=>{
 const f=await fixture(t),r=await f.imported(),cli=path.resolve('dist/cli.js');
 const {stdout}=await promisify(execFile)(process.execPath,[cli,'pe-ui',f.workspace,'--file','ui.exe','--view','entries','--command','1001','--function-ids',r.observationId]);const direct=JSON.parse(stdout);assert.equal(direct.receipt.responseBytes,Buffer.byteLength(stdout)-1);
 const c=new Client({name:'ui-entry-protocol-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>c.close());
 const reply=await c.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'ui.exe',view:'entries',command:1001,functionIds:[r.observationId]}});assert.ok(!reply.isError,reply.content[0].text);const remote=JSON.parse(reply.content[0].text);assert.equal(remote.bindingId,direct.bindingId);assert.equal(remote.items[0].status,'static-entry-matched');assert.equal(remote.receipt.responseBytes,Buffer.byteLength(reply.content[0].text));
 const denied=await c.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'ui.exe',view:'entries',functionIds:[r.observationId]}});assert.equal(denied.isError,true);
});

test('bounded pages retain one binding identity and immutable reports reject later edits',async t=>{
 const f=await fixture(t,false,true),a=await f.imported(),b=await f.imported({entry:'0x408030'}),options={functionIds:[a.observationId,b.observationId],limit:1,budgetBytes:4096};
 const first=await f.inspect(options);assert.equal(first.total,2);assert.equal(first.nextOffset,1);assert.equal(first.items.length,1);const second=await f.inspect({...options,offset:first.nextOffset});assert.equal(second.bindingId,first.bindingId);assert.equal(second.nextOffset,null);assert.notEqual(second.items[0].address,first.items[0].address);assert.equal(first.receipt.responseBytes,Buffer.byteLength(JSON.stringify(first)));
 const evidence=await readFile(first.bindingEvidence);await writeFile(first.bindingEvidence,Buffer.concat([evidence,Buffer.from(' ')]));await assert.rejects(f.inspect(options),/Existing evidence changed/);
});
