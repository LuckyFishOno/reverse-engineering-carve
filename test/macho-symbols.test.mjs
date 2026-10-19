import test from 'node:test';import assert from 'node:assert/strict';import path from 'node:path';import {tmpdir} from 'node:os';import {mkdtemp,writeFile,rm,symlink} from 'node:fs/promises';import {readMachOSymbol} from '../dist/macho-symbols.js';import {machoFixture} from './fixtures/macho-bridge.mjs';
async function fixture(t,options){const root=await mkdtemp(path.join(tmpdir(),'carve-macho-symbols-'));t.after(()=>rm(root,{recursive:true,force:true}));const built=machoFixture(options),file=path.join(root,'image');const save=()=>writeFile(file,built.bytes);await save();return{root,file,...built,save};}

test('selected ARM64 BL, stub indirect ordinal and defined export retain exact original byte coordinates',async t=>{
 const f=await fixture(t),a=await readMachOSymbol(f.file,{stub:f.stub,callSites:[f.call]});assert.equal(a.kind,'import-stub');assert.equal(a.libraryOrdinal,1);assert.equal(a.symbol.name,f.symbol);assert.equal(a.callSites[0].fileOffset,f.layout.call);assert.equal(a.callSites[0].target,f.stub);assert.equal(a.callSites[0].encoding,'aarch64-bl-immediate');assert.equal(a.stub.indirectFileOffset,0x840);
 const target=await fixture(t,{library:true}),b=await readMachOSymbol(target.file,{export:f.symbol});assert.equal(b.kind,'defined-export');assert.equal(b.symbol.value,'0x2d8');assert.equal(b.location.fileOffset,0x2d8);
});

test('decodes both signs of x86 E8 and ARM64 BL displacements without executing fixture bytes',async t=>{
 for(const cpu of [0x100000c,0x1000007])for(const options of [{},{textOffset:0x600,callOffset:0x620}]){const f=await fixture(t,{cpu,...options}),r=await readMachOSymbol(f.file,{stub:f.stub,callSites:[f.call]});assert.equal(r.callSites[0].target,f.stub);}
});

test('rejects malformed headers, table/section budgets and invalid file mappings',async t=>{
 const changes=[f=>f.bytes.writeUInt32LE(0xcafebabe),f=>f.bytes.writeUInt32LE(12,4),f=>f.bytes.writeUInt32LE(5000,16),f=>f.bytes.writeUInt32LE(600000,f.layout.symCommand+12),f=>f.bytes.writeUInt32LE(9*1024*1024,f.layout.symCommand+20),f=>f.bytes.writeUInt32LE(0xfffffff0,f.layout.symCommand+8),f=>f.bytes.writeUInt32LE(0x899,f.layout.textSection+48)];
 for(const change of changes){const f=await fixture(t);change(f);await f.save();await assert.rejects(readMachOSymbol(f.file,{stub:f.stub}));}
});

test('refuses weak/special/local/misaligned/out-of-table import stubs',async t=>{
 const changes=[f=>f.bytes.writeUInt16LE(0x140,0x806),f=>f.bytes.writeUInt16LE(0,0x806),f=>f.bytes.writeUInt16LE(0xfe00,0x806),f=>f.bytes.writeUInt32LE(0x80000000,0x840),f=>f.bytes.writeUInt32LE(9,0x840),f=>f.bytes.writeUInt32LE(0,f.layout.stubSection+72),f=>{f.bytes[0x804]=15;}];
 for(const change of changes){const f=await fixture(t);change(f);await f.save();await assert.rejects(readMachOSymbol(f.file,{stub:f.stub}));}
 const f=await fixture(t);await assert.rejects(readMachOSymbol(f.file,{stub:'0x'+(BigInt(f.stub)+4n).toString(16)}),/exact complete/);
});

test('rejects altered call opcodes, destinations, field bounds and excess call sites',async t=>{
 for(const change of [f=>f.bytes.writeUInt32LE(0xd503201f,f.layout.call),f=>f.bytes.writeUInt32LE(0x94000001,f.layout.call),f=>f.bytes.writeUInt32LE(10000,0x800)]){const f=await fixture(t);change(f);await f.save();await assert.rejects(readMachOSymbol(f.file,{stub:f.stub,callSites:[f.call]}));}
 const f=await fixture(t);await assert.rejects(readMachOSymbol(f.file,{stub:f.stub,callSites:Array(21).fill(f.call)}),/at most20/);const alias=path.join(f.root,'alias');await symlink(f.file,alias);await assert.rejects(readMachOSymbol(alias,{stub:f.stub}));
});

test('requires one exact strong instruction-section export, not weak/data/duplicate names',async t=>{
 const changes=[f=>f.bytes.writeUInt16LE(0x80,0x806),f=>{f.bytes[0x805]=0;},f=>f.bytes.writeUInt32LE(0,f.layout.textSection+64),f=>f.bytes.writeBigUInt64LE(0x1n,0x808),f=>{f.bytes.copy(f.bytes,0x810,0x800,0x810);f.bytes.writeUInt32LE(2,f.layout.symCommand+12);}];for(const change of changes){const f=await fixture(t,{library:true});change(f);await f.save();await assert.rejects(readMachOSymbol(f.file,{export:f.symbol}));}
 const f=await fixture(t,{library:true});await assert.rejects(readMachOSymbol(f.file,{export:'_missing'}),/one exact/);
});

test('original ARM64 B branch evidence handles both displacements without requiring an exported symbol name',async t=>{
 const {readMachOBranch}=await import('../dist/macho-symbols.js');for(const target of [0x480,0x4f0]){const f=await fixture(t);f.bytes.writeUInt32LE(0x14000000+(((target-f.layout.call)/4)&0x3ffffff),f.layout.call);await f.save();const r=await readMachOBranch(f.file,f.call,'0x'+(f.base+BigInt(target)).toString(16));assert.equal(r.fallthrough,false);assert.equal(r.encoding,'aarch64-b-immediate');assert.equal(r.fileOffset,f.layout.call);}
});
test('branch witnesses reject non-ARM64, non-code, unaligned, wrong-destination and symlink inputs',async t=>{
 const {readMachOBranch}=await import('../dist/macho-symbols.js'),f=await fixture(t);await assert.rejects(readMachOBranch(f.file,f.call,'0x100000480'),/B-immediate/);f.bytes.writeUInt32LE(0x17ffffee,f.layout.call);await f.save();for(const [source,target] of [[f.call,f.stub],['0x1000004c9','0x100000480'],[f.call,'0x100000481'],[f.call,'0x100000484']])await assert.rejects(readMachOBranch(f.file,source,target));const alias=path.join(f.root,'branch-alias');await symlink(f.file,alias);await assert.rejects(readMachOBranch(alias,f.call,'0x100000480'));const x=await fixture(t,{cpu:0x1000007});await assert.rejects(readMachOBranch(x.file,x.call,'0x100000480'),/ARM64/);
});
