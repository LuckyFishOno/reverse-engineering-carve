// Narrow source-owned COFF linker for rolling.c only.
import assert from 'node:assert/strict';
import path from 'node:path';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {coff,relocate} from './pe-behavior-fixture.mjs';
import {buildPe} from '../test/fixtures/pe-image.mjs';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
export async function buildPeSequenceFixture(root,out){
 await mkdir(path.join(out,'input'),{recursive:true});const object=path.join(out,'rolling.obj');
 await promisify(execFile)('clang',['-target','x86_64-pc-windows-msvc','-O1','-ffreestanding','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-optimize-sibling-calls','-c',path.join(root,'examples/pe-sequence/rolling.c'),'-o',object]);
 const parsed=coff(await readFile(object)),parts=parsed.parts.filter(p=>p.name==='.carves');assert.equal(parts.length,1);const data=parts[0];assert.equal(data.relocations,0);assert.equal(data.bytes.length,1028);
 const names=['session_init','session_byte','session_update','session_transform','session_inplace'],entries=names.map(name=>{const matches=[...parsed.symbols.values()].filter(s=>s.name===name&&s.section===parsed.section);assert.equal(matches.length,1);return {name,rva:0x8000+matches[0].value};});
 const mappings=new Map([[parsed.section,0x8000],[data.index,0xa000]]);
 const image=buildPe({dll:true,exports:{name:'rolling.dll',base:1,functions:entries.map(e=>({names:[e.name],rva:e.rva}))},code:()=>relocate(parsed,new Map(),mappings)});
 const bytes=Buffer.concat([image,Buffer.alloc(1536)]),section=0x40+24+240+80;bytes.writeUInt16LE(3,0x40+6);bytes.write('.carves',section);bytes.writeUInt32LE(data.bytes.length,section+8);bytes.writeUInt32LE(0xa000,section+12);bytes.writeUInt32LE(1536,section+16);bytes.writeUInt32LE(image.length,section+20);bytes.writeUInt32LE(0xc0000040,section+36);data.bytes.copy(bytes,image.length);
 const file=path.join(out,'input/rolling.dll');await writeFile(file,bytes);
 const manifest={schema:'carve/owned-pe-sequence@1',entries:entries.map(e=>({name:e.name,address:'0x'+(0x140000000n+BigInt(e.rva)).toString(16)})),memory:{address:'0x14000a000',length:data.bytes.length,access:'read-write'},sha256:(await hashFile(file)).sha256,metadata:await readPeLoader(file)};
 await writeFile(path.join(out,'images.json'),JSON.stringify(manifest,null,2)+'\n');return manifest;
}
