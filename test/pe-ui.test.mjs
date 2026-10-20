import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,writeFile,readFile,rm,mkdir,symlink} from 'node:fs/promises';
import {readPeUi,inspectPeUi} from '../dist/pe-ui.js';
import {survey} from '../dist/survey.js';
import {searchObservations} from '../dist/native.js';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
async function fixture(t,options={}){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-pe-ui-')));t.after(()=>rm(root,{recursive:true,force:true}));const file=path.join(root,'ui.exe'),built=buildUiPe(options);await writeFile(file,built.bytes);return{root,file,...built};}
for(const plus of [false,true])test(`PE UI resources retain exact standard/extended template fields and ${plus?'x64':'x86'} candidate rows`,async t=>{
 const f=await fixture(t,{plus,extended:plus}),g=await readPeUi(f.file);
 assert.equal(g.counts.parsedResources,5);assert.deepEqual(g.issues,[]);assert.equal(g.counts.handlerRows,2);
 assert.ok(g.nodes.some(n=>n.kind==='dialog-control'&&n.controlClass==='SysTreeView32'&&n.commandId===2000));
 assert.ok(g.nodes.some(n=>n.label==='Inspect \u{1f50e}'&&n.commandId===1003));
 assert.ok(g.nodes.some(n=>n.kind==='string'&&n.stringId===1001&&n.label==='Session label'));
 const handlers=g.nodes.filter(n=>n.kind==='handler-candidate');assert.equal(handlers.length,1);assert.equal(handlers[0].rva,0x8010);assert.equal(handlers[0].functionBoundary,'unverified');
 assert.deepEqual(g.nodes.filter(n=>n.kind==='dispatch-row-candidate').map(n=>n.notification),[0,2]);
 assert.equal(g.nodes.find(n=>n.kind==='dispatch-row-candidate').bytes,f.bytes.subarray(f.table,f.table+f.rowSize).toString('hex'));
 const ids=new Set(g.nodes.map(n=>n.id));assert.equal(ids.size,g.nodes.length);for(const e of g.edges){assert.ok(ids.has(e.from));assert.ok(ids.has(e.to));}
 assert.ok(g.edges.some(e=>e.from==='command:1001'&&e.kind==='dispatch-candidate'));
 assert.equal(g.edges.some(e=>e.from===handlers[0].id&&e.to.startsWith('import:')),false,'DLL declarations must not become handler dependencies');
 assert.deepEqual(await readFile(f.file),f.bytes);
});
test('unsupported architectures retain UI resources but do not guess a message-map layout',async t=>{
 const f=await fixture(t,{plus:true,machine:0xaa64}),g=await readPeUi(f.file);assert.equal(g.handlerScan,'unsupported-machine');assert.equal(g.counts.handlerRows,0);assert.equal(g.counts.parsedResources,5);
});
test('malformed templates are explicit issues and do not publish partial UI nodes',async t=>{
 const f=await fixture(t,{malformedMenu:true}),g=await readPeUi(f.file);assert.equal(g.issues.length,1);assert.equal(g.counts.parsedResources,4);assert.equal(g.nodes.some(n=>JSON.stringify(n.resource)===JSON.stringify([4,101,1033])),false);
});
test('resource cycles, invalid pointers and over-budget declarations fail before producing a graph',async t=>{
 const f=await fixture(t);let bytes=Buffer.from(f.bytes);bytes.writeUInt32LE(0x80000000,f.raw+20);await writeFile(f.file,bytes);await assert.rejects(()=>readPeUi(f.file),/cyclic/);
 bytes=Buffer.from(f.bytes);bytes.writeUInt32LE(0xfffffff0,f.raw+20);await writeFile(f.file,bytes);await assert.rejects(()=>readPeUi(f.file),/out of bounds/);
 bytes=Buffer.from(f.bytes);bytes.writeUInt32LE(0x1000001,f.directoryOptionalOffset+4);await writeFile(f.file,bytes);await assert.rejects(()=>readPeUi(f.file),/16 MiB/);
});
test('non-executable and out-of-image handler pointers are excluded',async t=>{
 const f=await fixture(t),bytes=Buffer.from(f.bytes);bytes.writeUInt32LE(0x401000,f.table+20);bytes.writeUInt32LE(0xffffffff,f.table+f.rowSize+20);await writeFile(f.file,bytes);assert.equal((await readPeUi(f.file)).counts.handlerRows,0);
});
test('workspace graph is source-pinned, indexed, immutable and supports byte-budgeted boundary pages',async t=>{
 const f=await fixture(t),workspace=path.join(f.root,'work');await survey(f.file,{workspace});
 const summary=await inspectPeUi(workspace,{file:'ui.exe'});assert.equal(summary.startsRea,false);assert.equal(summary.executesTarget,false);assert.equal(summary.receipt.responseBytes,Buffer.byteLength(JSON.stringify(summary)));
 const evidence=JSON.parse(await readFile(summary.evidence,'utf8'));assert.equal(evidence.sourceSha256,summary.sourceSha256);assert.equal(evidence.graph.counts.handlerRows,2);
 const all=[];let offset=0;do{const page=await inspectPeUi(workspace,{file:'ui.exe',view:'boundary',command:1001,limit:2,offset,budgetBytes:8192});assert.equal(page.observationId,summary.observationId);assert.ok(Buffer.byteLength(JSON.stringify(page))<=8192);all.push(...page.items);offset=page.nextOffset;}while(offset!==null);
 assert.ok(all.some(n=>n.kind==='handler-candidate'));assert.ok(all.some(n=>n.kind==='accelerator'));assert.ok(all.every(n=>Array.isArray(n.edges)));
 const found=await searchObservations(workspace,'folder');assert.ok(JSON.stringify(found).includes(summary.observationId));
 await writeFile(summary.evidence,'tampered');await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe'}),/Existing evidence changed/);
});
test('changed sources, invalid filters and redirected evidence directories are refused',async t=>{
 const f=await fixture(t),workspace=path.join(f.root,'work');await survey(f.file,{workspace});
 await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe',view:'boundary'}),/requires/);
 await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe',command:0}),/command1/);
 await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe',view:'summary',query:'x'}),/Summary/);
 await assert.rejects(()=>inspectPeUi(workspace,{file:'../ui.exe'}),/relative path/);
 const outside=path.join(f.root,'outside');await mkdir(outside);await symlink(outside,path.join(workspace,'ui-evidence'));
 await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe'}),/symlink/);
 await writeFile(f.file,Buffer.from('changed'));await assert.rejects(()=>inspectPeUi(workspace,{file:'ui.exe'}),/changed since inventory/);
});

test('resource-free images stay explicit and malformed resource issues are pageable',async t=>{
 const f=await fixture(t),bytes=Buffer.from(f.bytes);bytes.writeUInt32LE(0,f.directoryOptionalOffset);bytes.writeUInt32LE(0,f.directoryOptionalOffset+4);await writeFile(f.file,bytes);
 const empty=await readPeUi(f.file);assert.equal(empty.counts.resourceLeaves,0);assert.equal(empty.counts.commands,0);assert.equal(empty.counts.handlerRows,0);assert.ok(empty.nodes.some(n=>n.kind==='import-module'));
 const broken=await fixture(t,{malformedMenu:true}),work=path.join(broken.root,'work');await survey(broken.file,{workspace:work});
 const issues=await inspectPeUi(work,{file:'ui.exe',view:'issues'});assert.equal(issues.items.length,1);assert.deepEqual(issues.items[0].resource,[4,101,1033]);assert.match(issues.items[0].message,/truncated/);
});
test('malformed UTF16 labels are issues rather than replacement-character evidence',async t=>{
 const f=await fixture(t),bytes=Buffer.from(f.bytes),p=bytes.indexOf(Buffer.from('Sessions\0','utf16le'));bytes.writeUInt16LE(0xd800,p);await writeFile(f.file,bytes);
 const result=await readPeUi(f.file);assert.equal(result.issues.length,1);assert.match(result.issues[0].message,/UTF16/);
});

test('long labels have explicit bounded previews while immutable evidence retains complete values',async t=>{
 const f=await fixture(t),bytes=Buffer.from(f.bytes),entry=f.resources.find(r=>r.keys[0]===6),label='L'.repeat(3000),raw=Buffer.concat([Buffer.from([0xb8,0x0b]),Buffer.from(label,'utf16le'),Buffer.alloc(30)]);
 // Allocate a new string payload away from directory tables and original resource bytes.
 const target=0x3200;raw.copy(bytes,target);const oldRva=0x2000+entry.payloadOffset-f.raw;
 let descriptor=-1;for(let p=f.raw;p<f.raw+1000;p+=4)if(bytes.readUInt32LE(p)===oldRva&&bytes.readUInt32LE(p+4)===entry.bytes.length){descriptor=p;break;}
 assert.notEqual(descriptor,-1);bytes.writeUInt32LE(0x1000+target-0x200,descriptor);bytes.writeUInt32LE(raw.length,descriptor+4);await writeFile(f.file,bytes);
 const workspace=path.join(f.root,'work');await survey(f.file,{workspace});const page=await inspectPeUi(workspace,{file:'ui.exe',view:'nodes',query:'L'.repeat(100),budgetBytes:8192});
 assert.equal(page.items.length,1);assert.equal(page.items[0].label.length,512);assert.ok(page.items[0].previewFields.includes('label'));
 const saved=JSON.parse(await readFile(page.evidence,'utf8'));assert.equal(saved.graph.nodes.find(n=>n.id===page.items[0].id).label.length,3000);
});
