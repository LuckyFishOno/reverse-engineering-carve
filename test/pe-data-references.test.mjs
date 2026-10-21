import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {buildPe} from './fixtures/pe-image.mjs';
import {readPeLoader} from '../dist/pe-loader.js';
import {inspectPeDataReference} from '../dist/pe-data-references.js';

async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-pe-data-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const file=path.join(root,'data.exe'),bytes=buildPe({code:()=>Buffer.alloc(32,0xc3)});
 bytes.write('settings\0',0x300,'ascii');bytes.write('status\0',0x340,'utf16le');bytes.writeUInt32LE(25,0x380);
 const section=0x40+24+240;bytes.writeUInt32LE(0x40000040,section+36);
 await writeFile(file,bytes);const metadata=await readPeLoader(file),base=BigInt(metadata.imageBase),va=n=>'0x'+(base+BigInt(n)).toString(16),body={ranges:[{start:va(0x8000),end:va(0x801f)}]};
 const ref=(rva,kind={read:true,write:false})=>({address:va(0x8001),targetAddress:va(rva),kind:{data:true,type:'READ',...kind}});
 const inspect=(reference,meta=metadata,knownWrite=false)=>inspectPeDataReference(file,meta,reference,body,knownWrite);
 return {file,bytes,metadata,ref,inspect,va};
}
test('data references bind source/target sections and bounded initial bytes without inferring types or runtime values',async t=>{
 const f=await fixture(t),r=await f.inspect(f.ref(0x1100));assert.equal(r.sourceAddress,f.va(0x8001));assert.equal(r.targetAddress,f.va(0x1100));assert.equal(r.section.name,'.data');assert.equal(r.access,'read');assert.equal(r.state,'read-only-data-candidate');assert.equal(r.bytes.fileOffset,0x300);assert.equal(r.bytes.length,64);assert.equal(r.bytes.objectExtent,'unknown');assert.equal(r.runtimeValue,'unverified');assert.equal(r.instructionSemantics,'not-decoded');assert.equal(r.stringCandidates[0].text,'settings');
 const wide=await f.inspect(f.ref(0x1140));assert.equal(wide.stringCandidates[0].encoding,'utf-16le');assert.equal(wide.stringCandidates[0].text,'status');
 assert.equal(r.sourceSection.name,'.text');assert.equal(r.sourceSection.executable,true);
 const scalar=await f.inspect(f.ref(0x1180));assert.equal(scalar.scalarPreview.value,25);assert.equal(scalar.scalarPreview.declaredType,'unknown');
});
test('writes and writable sections remain mutable even when their initial bytes look constant',async t=>{
 const f=await fixture(t),meta=structuredClone(f.metadata);meta.sections[0].characteristics|=0x80000000;
 for(const r of [await f.inspect(f.ref(0x1180),meta),await f.inspect(f.ref(0x1180),f.metadata,true),await f.inspect(f.ref(0x1180,{read:true,write:true}))])assert.equal(r.state,'mutable-state-candidate');
 assert.equal((await f.inspect(f.ref(0x1180,{read:false,write:false}))).access,'address-only');
});
test('external, virtual, overlapping, unmapped and out-of-body references preserve unknown locations without invented bytes',async t=>{
 const f=await fixture(t),overlap=structuredClone(f.metadata);overlap.sections.push({...overlap.sections[0],index:2});
 const virtual=structuredClone(f.metadata);virtual.sections[0].rawSize=0x100;
 const rows=[await f.inspect({...f.ref(0x1100),targetAddress:'EXTERNAL:0x1'}),await f.inspect({...f.ref(0x1100),address:f.va(0x9000)}),await f.inspect(f.ref(0x1100),overlap),await f.inspect(f.ref(0x1100),virtual),await f.inspect(f.ref(0x7000)),await f.inspect(f.ref(0x10000)),await f.inspect(f.ref(0x10))];
 assert.deepEqual(rows.map(r=>r.status),['non-image-target','source-outside-function-body','ambiguous-section-mapping','virtual-only-target','unmapped-target','target-outside-image','image-header-target']);for(const row of rows)assert.equal(row.bytes,null);
});
test('string recognition requires an observed terminator and complete code units; preview never crosses a section',async t=>{
 const f=await fixture(t);f.bytes.fill(65,0x300,0x340);await writeFile(f.file,f.bytes);assert.deepEqual((await f.inspect(f.ref(0x1100))).stringCandidates,[]);
 const meta=structuredClone(f.metadata);meta.sections[0].rawSize=0x107;const row=await f.inspect(f.ref(0x1100),meta);assert.equal(row.bytes.length,7);assert.deepEqual(row.stringCandidates,[]);
 const crossed=structuredClone(f.metadata);crossed.sections.push({...crossed.sections[0],index:2,virtualAddress:0x1120,virtualSize:16,rawSize:16});assert.equal((await f.inspect(f.ref(0x1100),crossed)).status,'ambiguous-section-mapping');
});
