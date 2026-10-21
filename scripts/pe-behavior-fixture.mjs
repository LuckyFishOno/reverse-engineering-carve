// A deliberately narrow fixture builder for trusted Clang-produced COFF, not a general linker.
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {buildPe} from '../test/fixtures/pe-image.mjs';
import {buildUiPe} from '../test/fixtures/pe-ui-image.mjs';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
const exec=promisify(execFile),TEXT=0x8000;
export function coff(bytes){
 const machine=bytes.readUInt16LE(0);assert.ok(machine===0x8664||machine===0x14c);assert.equal(bytes.readUInt16LE(16),0);const n=bytes.readUInt16LE(2),symAt=bytes.readUInt32LE(8),count=bytes.readUInt32LE(12);assert.ok(n<32&&count<10000&&symAt+count*18+4<=bytes.length);
 const strings=bytes.subarray(symAt+count*18),name=p=>bytes.readUInt32LE(p)===0?strings.subarray(bytes.readUInt32LE(p+4)).toString().split('\0')[0]:bytes.subarray(p,p+8).toString().split('\0')[0];
 const symbols=new Map();for(let i=0;i<count;){const p=symAt+i*18;symbols.set(i,{name:name(p),value:bytes.readUInt32LE(p+8),section:bytes.readInt16LE(p+12)});i+=1+bytes[p+17];}
 let text;for(let i=0;i<n;i++){const p=20+i*40;if(bytes.subarray(p,p+8).toString().split('\0')[0]!=='.text')continue;assert.ok(!text);const size=bytes.readUInt32LE(p+16),raw=bytes.readUInt32LE(p+20),rel=bytes.readUInt32LE(p+24),relN=bytes.readUInt16LE(p+32);assert.ok(raw+size<=bytes.length&&rel+relN*10<=bytes.length);text={section:i+1,code:Buffer.from(bytes.subarray(raw,raw+size)),relocations:Array.from({length:relN},(_,j)=>({offset:bytes.readUInt32LE(rel+j*10),symbol:bytes.readUInt32LE(rel+j*10+4),type:bytes.readUInt16LE(rel+j*10+8)}))};}
 const parts=[];for(let i=0;i<n;i++){const p=20+i*40,name=bytes.subarray(p,p+8).toString().split('\0')[0],size=bytes.readUInt32LE(p+16),raw=bytes.readUInt32LE(p+20);assert.ok(size<=4096&&raw+size<=bytes.length);parts.push({index:i+1,name,bytes:Buffer.from(bytes.subarray(raw,raw+size)),relocations:bytes.readUInt16LE(p+32)});}
 assert.ok(text&&text.code.length<4096);return{...text,symbols,parts,machine};
}
export function relocate(object,imports,sectionRvas=new Map([[object.section,TEXT]])){
 assert.equal(object.machine,0x8664);const code=Buffer.from(object.code);
 for(const r of object.relocations){assert.ok(r.type>=4&&r.type<=9&&r.offset+4<=code.length,'Only AMD64 REL32 trusted fixture relocations are supported');const s=object.symbols.get(r.symbol);assert.ok(s);const section=sectionRvas.get(s.section),target=section===undefined?imports.get(s.name):section+s.value;assert.ok(target!==undefined,'Unresolved fixture symbol: '+s.name);const addend=code.readInt32LE(r.offset);code.writeInt32LE(target+addend-(TEXT+r.offset+4+r.type-4),r.offset);}
 return code;
}
const symbol=(o,n)=>{const entries=[...o.symbols.values()].filter(s=>s.name===n&&s.section===o.section);assert.equal(entries.length,1,'Expected one defined fixture symbol '+n);return TEXT+entries[0].value;};
export async function buildPeBehaviorFixture(root,out){
 const input=path.join(out,'input');await mkdir(input,{recursive:true});const flags=['-target','x86_64-pc-windows-msvc','-O1','-ffreestanding','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-optimize-sibling-calls','-c'];
 for(const source of ['quote','rate'])await exec('clang',[...flags,path.join(root,'examples/pe-feature',source+'.c'),'-o',path.join(out,source+'.obj')]);
 const quote=coff(await readFile(path.join(out,'quote.obj'))),rate=coff(await readFile(path.join(out,'rate.obj'))),quoteRva=symbol(quote,'quote_command'),blocksRva=symbol(quote,'billing_blocks'),rateRva=symbol(rate,'unit_rate');
 const ui=buildUiPe({plus:true,menuLabel:'Quote',menuTitle:'Quote actions',imports:[{name:'rate.dll',entries:['unit_rate']}],code:({slot})=>relocate(quote,new Map([['__imp_unit_rate',slot('rate.dll!unit_rate')]]))});
 ui.bytes.writeUInt32LE(quoteRva,0x40+24+16);for(let i=0;i<2;i++)ui.bytes.writeBigUInt64LE(0x140000000n+BigInt(quoteRva),ui.table+i*ui.rowSize+24);
 const library=buildPe({plus:true,dll:true,exports:{name:'rate.dll',base:1,functions:[{names:['unit_rate'],rva:rateRva}]},code:()=>relocate(rate,new Map())});library.writeBigUInt64LE(0x180000000n,0x40+24+24);
 const exe=path.join(input,'quote.exe'),dll=path.join(input,'rate.dll');await writeFile(exe,ui.bytes);await writeFile(dll,library);
 const manifest={schema:'carve/owned-pe-behavior@1',entry:'0x'+(0x140000000n+BigInt(quoteRva)).toString(16),blocks:'0x'+(0x140000000n+BigInt(blocksRva)).toString(16),rate:'0x'+(0x180000000n+BigInt(rateRva)).toString(16),command:1001,images:[]};
 for(const file of [exe,dll])manifest.images.push({file:path.relative(out,file).split(path.sep).join('/'),...await hashFile(file),metadata:await readPeLoader(file)});
 await writeFile(path.join(out,'images.json'),JSON.stringify(manifest,null,2)+'\n');return manifest;
}
