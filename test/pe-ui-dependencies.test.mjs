import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,writeFile,readFile,rm,truncate} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,openIndex} from '../dist/survey.js';
import {inspectPeUi} from '../dist/pe-ui.js';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
import {buildPe} from './fixtures/pe-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
async function fixture(t,{plus=false,invalidCall=false,forwarder=false,ordinal=false,delayImport=false,moduleName='helper.dll',duplicateSlot=false}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ui-dependencies-')));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const base=plus?0x140000000n:0x400000n,va=r=>'0x'+(base+BigInt(r)).toString(16);
 const importedModules=[{name:moduleName,entries:ordinal?[{ordinal:7}]:['ReadSettings']},...(duplicateSlot?[{name:'other.dll',entries:['OtherSettings']}]:[])];
 const bytes=buildUiPe({plus,imports:delayImport?[]:importedModules,delay:delayImport?importedModules:[],code:({slot,imageBase})=>{const b=Buffer.alloc(0x40,0xc3);b[0x10]=0xe8;b.writeInt32LE(0x8030-0x8015,0x11);b[0x16]=invalidCall?0x90:0xff;b[0x17]=0x15;const rva=slot(moduleName+(ordinal?'!#7':'!ReadSettings'));if(plus)b.writeInt32LE(rva-0x801c,0x18);else b.writeUInt32LE(Number(imageBase)+rva,0x18);return b;}}).bytes;
 if(duplicateSlot){const directory=0x40+24+(plus?112:96),table=bytes.readUInt32LE(directory+8)-0x1000+0x200;bytes.writeUInt32LE(bytes.readUInt32LE(table+16),table+20+16);}
 const library=buildPe({plus,dll:true,exports:{name:'helper.dll',base:ordinal?7:1,functions:[forwarder?{names:['ReadSettings'],forwarder:'other.ReadSettings'}:{names:['ReadSettings'],rva:0x8000}]},code:()=>Buffer.alloc(0x40,0xc3)});
 await writeFile(path.join(input,'program.exe'),bytes);await writeFile(path.join(input,'helper.dll'),library);await mkdir(path.join(input,'other'));await writeFile(path.join(input,'other/helper.dll'),library);await survey(input,{workspace});
 const imported=async(file,options)=>importPeFunction(root,workspace,file,file==='program.exe'?bytes:library,options);
 const rootOptions={address:va(0x8010),calls:[{site:va(0x8010),target:va(0x8030)},{site:va(0x8016),target:'EXTERNAL:0x1',indirect:true}],dataReference:true};
 const seed=await imported('program.exe',rootOptions),helper=await imported('program.exe',{address:va(0x8030),calls:[{site:va(0x8030),target:va(0x8010)}]}),dll=await imported('helper.dll',{address:va(0x8000)});
 const inspect=(options={})=>inspectPeUi(workspace,{file:'program.exe',view:'dependencies',command:1001,functionIds:[seed.observationId],dependencyIds:[helper.observationId,dll.observationId],limit:100,budgetBytes:65536,...options});
 return{root,input,workspace,seed,helper,dll,imported,inspect,va,rootOptions};
}
test('selected internal calls and byte-bound import/export candidates remain separate from runtime loading on x86 and x64',async t=>{
 for(const plus of [false,true]){
  const f=await fixture(t,{plus}),r=await f.inspect();assert.equal(r.visited,3);assert.equal(r.dependencyClosure,'not-established');assert.equal(r.rowLimitReached,false);
  const calls=r.items.filter(x=>x.kind==='call-dependency');assert.ok(calls.some(x=>x.status==='internal-code-match'&&x.from===f.seed.observationId));const link=calls.find(x=>x.status==='dll-export-candidate');assert.equal(link.importWitness.slot.module,'helper.dll');assert.equal(link.importWitness.slot.name,'ReadSettings');assert.equal(link.matches[0].observationId,f.dll.observationId);assert.equal(link.runtimeLoading,'unverified');assert.equal(calls.length,3);assert.equal(JSON.stringify(r).includes('pseudocode'),false);
  const report=JSON.parse(await readFile(r.dependencyEvidence,'utf8'));assert.equal(report.records.length,3);assert.equal(report.rows.filter(x=>x.kind==='function-coverage').length,3);assert.equal(r.startsRea,false);assert.equal(r.executesTarget,false);
 }
});
test('explicit function roots trace non-UI dependencies without inventing command dispatch',async t=>{
 const f=await fixture(t),options={command:undefined,entryMode:'selected-functions'};
 const selected=await f.inspect(options);assert.equal(selected.entryMode,'selected-functions');assert.equal(selected.visited,3);
 assert.equal(selected.counts.byKind['function-entry'],1);assert.equal(selected.counts.byKind['ui-entry'],undefined);
 const entry=selected.items.find(r=>r.kind==='function-entry');assert.equal(entry.status,'selected-function');assert.equal(entry.dispatchConfirmed,false);
 const first=await f.inspect({...options,limit:1}),second=await f.inspect({...options,limit:1,offset:1});assert.equal(first.dependencyId,second.dependencyId);
 assert.notEqual(selected.dependencyId,(await f.inspect()).dependencyId);
 const report=JSON.parse(await readFile(selected.dependencyEvidence,'utf8'));assert.equal(report.entryMode,'selected-functions');assert.equal(report.command,undefined);
 assert.equal(report.rows.filter(r=>r.kind==='function-coverage').length,3);
});
test('function-root mode rejects absent roots, command mixing, wrong images and invalid view modes',async t=>{
 const f=await fixture(t),options={command:undefined,entryMode:'selected-functions'};
 await assert.rejects(f.inspect({...options,functionIds:[]}),/requires function IDs/);
 await assert.rejects(f.inspect({entryMode:'selected-functions'}),/no command ID/);
 await assert.rejects(f.inspect({...options,functionIds:[f.dll.observationId]}),/same current indexed PE file/);
 await assert.rejects(f.inspect({...options,view:'entries'}),/only supported in dependencies/);
 await assert.rejects(f.inspect({...options,entryMode:'other'}),/Entry mode/);
 await assert.rejects(f.inspect({command:undefined}),/requires one command ID/);
});
test('CLI and MCP expose explicit function roots with the same immutable evidence identity',async t=>{
 const f=await fixture(t),cli=path.resolve('dist/cli.js'),{stdout}=await promisify(execFile)(process.execPath,[cli,'pe-ui',f.workspace,'--file','program.exe','--view','dependencies','--entry-mode','selected-functions','--function-ids',f.seed.observationId]);
 const direct=JSON.parse(stdout),client=new Client({name:'pe-function-roots',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const reply=await client.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'program.exe',view:'dependencies',entryMode:'selected-functions',functionIds:[f.seed.observationId]}});assert.ok(!reply.isError,reply.content[0].text);assert.equal(JSON.parse(reply.content[0].text).dependencyId,direct.dependencyId);assert.equal(direct.visited,1);
});
test('cycles terminate, depth bounds are explicit and pages retain immutable report identity',async t=>{
 const f=await fixture(t),a=await f.inspect({limit:1,budgetBytes:4096}),b=await f.inspect({limit:1,offset:1,budgetBytes:4096});assert.equal(a.nextOffset,1);assert.equal(a.dependencyId,b.dependencyId);assert.equal(a.receipt.responseBytes,Buffer.byteLength(JSON.stringify(a)));
 const zero=await f.inspect({dependencyDepth:0});assert.equal(zero.visited,1);assert.ok(zero.items.some(x=>x.expansion==='depth-limit'));
 const repeat=await f.inspect({dependencyIds:[f.dll.observationId,f.helper.observationId]});assert.equal(repeat.dependencyId,(await f.inspect()).dependencyId);
});
test('missing code and relationship coverage stay explicit; alternate profiles are never silently joined',async t=>{
 const f=await fixture(t),wrong=await f.imported('program.exe',{address:f.va(0x8030),preset:'other'}),r=await f.inspect({dependencyIds:[wrong.observationId]});assert.equal(r.visited,1);assert.ok(r.items.some(x=>x.status==='missing-function-code'));assert.ok(r.items.some(x=>x.status==='import-target-unresolved'));
 const old=await f.imported('program.exe',{...f.rootOptions,relationships:false}),missing=await f.inspect({functionIds:[old.observationId],dependencyIds:[]});assert.equal(missing.visited,1);assert.equal(missing.items.find(x=>x.kind==='function-coverage').relationshipsIncomplete,true);assert.ok(missing.counts.byNextAction['capture-relationships']>0);
 const unresolved=await f.imported('program.exe',{...f.rootOptions,unresolved:[{address:f.va(0x801e),reason:'Unknown computed destination'}]});assert.ok((await f.inspect({functionIds:[unresolved.observationId]})).items.some(x=>x.kind==='unresolved-call'&&x.nextSteps[0].action==='resolve-call'));
});
test('DLL filename/export matches without original import instructions cannot establish a cross-image edge',async t=>{
 const f=await fixture(t,{invalidCall:true}),r=await f.inspect();assert.ok(!r.items.some(x=>x.status==='dll-export-candidate'));assert.ok(r.items.some(x=>x.importDecodeIssue));
});
test('competing selected DLLs and forwarded exports remain unresolved alternatives',async t=>{
 const f=await fixture(t),other=await f.imported('other/helper.dll',{address:f.va(0x8000)}),r=await f.inspect({dependencyIds:[f.helper.observationId,f.dll.observationId,other.observationId]});assert.equal(r.visited,2);assert.ok(r.items.some(x=>x.status==='ambiguous-dll-export'&&x.matches.length===2&&x.nextSteps[0].action==='select-evidence'));
 const forwarded=await fixture(t,{forwarder:true}),forward=await forwarded.inspect();assert.ok(forward.items.some(x=>x.status==='import-target-unresolved'&&x.exportAlternatives.some(a=>a.status==='forwarded-export-unresolved')));
});
test('edited selected DLLs and snapshot rows are rejected even when the selected code is unreachable',async t=>{
 const f=await fixture(t);await writeFile(path.join(f.input,'helper.dll'),Buffer.from('changed'));await assert.rejects(f.inspect(),/changed|stale/);
 const g=await fixture(t),db=openIndex(g.workspace);db.prepare('UPDATE observations SET name=? WHERE id=?').run('edited',g.dll.observationId);db.close();await assert.rejects(g.inspect({functionIds:[]}),/differs from/);
});
test('CLI and fresh MCP share dependency reports and authorize every selected source',async t=>{
 const f=await fixture(t),cli=path.resolve('dist/cli.js'),{stdout}=await promisify(execFile)(process.execPath,[cli,'pe-ui',f.workspace,'--file','program.exe','--view','dependencies','--command','1001','--function-ids',f.seed.observationId,'--dependency-ids',f.helper.observationId,f.dll.observationId]);const direct=JSON.parse(stdout);
 const c=new Client({name:'pe-dependency-test',version:'1'});await c.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>c.close());
 const reply=await c.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'program.exe',view:'dependencies',command:1001,functionIds:[f.seed.observationId],dependencyIds:[f.helper.observationId,f.dll.observationId]}});assert.ok(!reply.isError,reply.content[0].text);assert.equal(JSON.parse(reply.content[0].text).dependencyId,direct.dependencyId);
 const db=openIndex(f.workspace),row=db.prepare('SELECT artifact FROM observations WHERE id=?').get(f.dll.observationId);db.prepare('UPDATE observations SET artifact=? WHERE id=?').run('../outside.dll',f.dll.observationId);db.close();const denied=await c.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'program.exe',view:'dependencies',command:1001,dependencyIds:[f.dll.observationId]}});assert.equal(denied.isError,true);assert.equal(row.artifact,'helper.dll');
});

test('import instruction extent must fit the captured caller body and selected source access is checked',async t=>{
 const f=await fixture(t),short=await f.imported('program.exe',{...f.rootOptions,length:8}),r=await f.inspect({functionIds:[short.observationId]});assert.ok(!r.items.some(x=>x.status==='dll-export-candidate'));assert.ok(r.items.some(x=>x.importDecodeIssue?.includes('outside the recorded body')));
 await assert.rejects(f.inspect({authorizePath:async file=>{if(file===path.join(f.input,'helper.dll'))throw new Error('Selected DLL is outside this authorization.');}}),/outside this authorization/);
});
test('ordinal and delay imports retain the original slot identity and never imply a loaded module',async t=>{
 for(const options of [{plus:true,ordinal:true},{delayImport:true}]){
  const f=await fixture(t,options),r=await f.inspect(),call=r.items.find(x=>x.status==='dll-export-candidate');assert.ok(call);assert.equal(call.runtimeLoading,'unverified');assert.equal(call.importWitness.slot.importKind,options.delayImport?'delay-import':'import');if(options.ordinal)assert.equal(call.importWitness.slot.ordinal,7);
 }
});

test('dependency input and snapshot byte bounds fail before reading oversized records',async t=>{
 const f=await fixture(t);await assert.rejects(f.inspect({dependencyDepth:9}),/depth/);await assert.rejects(f.inspect({dependencyIds:Array.from({length:33},(_,i)=>i.toString(16).padStart(64,'0'))}),/up to32/);await assert.rejects(f.inspect({view:'entries'}),/dependencies view only/);await assert.rejects(f.inspect({functionIds:[f.dll.observationId],dependencyIds:[]}),/same current/);
 await truncate(f.seed.evidence,64*1024*1024+1);await assert.rejects(f.inspect(),/64 MiB/);
});
test('a selected contract-named DLL cannot silently resolve an API-set import',async t=>{
 const f=await fixture(t,{moduleName:'api-ms-test.dll'}),bytes=await readFile(path.join(f.input,'helper.dll'));await writeFile(path.join(f.input,'api-ms-test.dll'),bytes);await survey(f.input,{workspace:f.workspace,refresh:true});
 const record=await f.imported('api-ms-test.dll',{address:f.va(0x8000)}),r=await f.inspect({dependencyIds:[record.observationId]});assert.ok(!r.items.some(x=>x.status==='dll-export-candidate'));assert.ok(r.items.some(x=>x.status==='import-target-unresolved'));
});

test('overlapping import-table declarations cannot assign one physical slot to a chosen DLL',async t=>{
 const f=await fixture(t,{duplicateSlot:true}),r=await f.inspect();assert.ok(!r.items.some(x=>x.status==='dll-export-candidate'));assert.ok(r.items.some(x=>x.importDecodeIssue?.includes('ambiguous overlapping declarations')&&x.importWitness===null));
});

test('next steps identify missing code, import identities and depth boundaries without implying closure',async t=>{
 const f=await fixture(t),missing=await f.inspect({dependencyIds:[]});
 const internal=missing.items.find(x=>x.status==='missing-function-code');
 assert.equal(internal.nextSteps[0].action,'import-function');assert.equal(internal.nextSteps[0].address,f.va(0x8030));
 const imported=missing.items.find(x=>x.status==='import-target-unresolved');
 assert.equal(imported.nextSteps[0].module,'helper.dll');assert.equal(imported.nextSteps[0].name,'ReadSettings');
 assert.equal(missing.counts.byNextAction['import-function'],1);
 const report=JSON.parse(await readFile(missing.dependencyEvidence,'utf8'));
 assert.deepEqual(report.rows.find(x=>x.status==='import-target-unresolved').nextSteps,imported.nextSteps);
 const zero=await f.inspect({dependencyDepth:0});assert.equal(zero.counts.byNextAction['expand-depth'],2);
 const complete=await f.inspect();assert.equal(complete.counts.byNextAction['expand-depth'],undefined);assert.ok(complete.counts.byNextAction['inspect-state-resources']>0);assert.equal(complete.dependencyClosure,'not-established');
 const candidate=await f.inspect({functionIds:[],dependencyIds:[]});assert.equal(candidate.items[0].nextSteps[0].action,'import-function');assert.equal(candidate.items[0].nextSteps[0].file,'program.exe');
});
