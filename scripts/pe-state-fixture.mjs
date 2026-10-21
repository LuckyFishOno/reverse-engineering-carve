// Narrow source-owned section linker; only trusted Clang output for state.c is supported.
import assert from 'node:assert/strict';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {coff,relocate} from './pe-behavior-fixture.mjs';
import {buildUiPe} from '../test/fixtures/pe-ui-image.mjs';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
export async function buildPeStateFixture(root,out){
 await mkdir(path.join(out,'input'),{recursive:true});const object=path.join(out,'state.obj');
 await promisify(execFile)('clang',['-target','x86_64-pc-windows-msvc','-O1','-fno-jump-tables','-ffreestanding','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-optimize-sibling-calls','-c',path.join(root,'examples/pe-feature/state.c'),'-o',object]);
 const parsed=coff(await readFile(object)),parts=['.carvec','.carves'].map(name=>{const list=parsed.parts.filter(p=>p.name===name);assert.equal(list.length,1);assert.equal(list[0].relocations,0);assert.ok(list[0].bytes.length>0&&list[0].bytes.length<=512);return list[0];});
 const mappings=new Map([[parsed.section,0x8000],...parts.map((p,i)=>[p.index,0xa000+i*0x1000])]);
 const ui=buildUiPe({plus:true,imports:[],menuLabel:'State',menuTitle:'State operations',code:()=>relocate(parsed,new Map(),mappings)});
 const entry=[...parsed.symbols.values()].find(s=>s.name==='state_command'&&s.section===parsed.section);assert.ok(entry);
 const result=Buffer.concat([ui.bytes,Buffer.alloc(1024)]),table=0x40+24+240;
 result.writeUInt16LE(4,0x40+6);result.writeUInt32LE(0x8000+entry.value,0x40+24+16);
 for(let i=0;i<2;i++)result.writeBigUInt64LE(0x140008000n+BigInt(entry.value),ui.table+i*ui.rowSize+24);
 parts.forEach((p,i)=>{const at=table+(i+2)*40;result.write(p.name,at,'ascii');result.writeUInt32LE(p.bytes.length,at+8);result.writeUInt32LE(0xa000+i*0x1000,at+12);result.writeUInt32LE(512,at+16);result.writeUInt32LE(ui.bytes.length+i*512,at+20);result.writeUInt32LE(i===0?0x40000040:0xc0000040,at+36);p.bytes.copy(result,ui.bytes.length+i*512);});
 // Point the existing string-table directory leaf at the compiled readonly array.
 const resourceSymbol=[...parsed.symbols.values()].find(s=>s.name==='resource_strings'&&s.section===parts[0].index);assert.ok(resourceSymbol);
 const strings=ui.resources.find(r=>r.keys[0]===6),oldRva=0x1000+strings.payloadOffset-0x200;let descriptor=-1;
 for(let p=ui.raw;p<ui.raw+1000;p+=4)if(result.readUInt32LE(p)===oldRva&&result.readUInt32LE(p+4)===strings.bytes.length){assert.equal(descriptor,-1);descriptor=p;}
 assert.ok(descriptor>=0);result.writeUInt32LE(0xa000+resourceSymbol.value,descriptor);result.writeUInt32LE(42,descriptor+4);
 const file=path.join(out,'input/state.exe');await writeFile(file,result);
 const manifest={schema:'carve/owned-pe-state@1',entry:'0x'+(0x140008000n+BigInt(entry.value)).toString(16),command:1001,stringResource:{path:[6,63,1033],rva:0xa000+resourceSymbol.value,bytes:42},images:[{file:'input/state.exe',...await hashFile(file),metadata:await readPeLoader(file)}]};
 await writeFile(path.join(out,'images.json'),JSON.stringify(manifest,null,2)+'\n');return manifest;
}

export async function buildPeResourceApiProbe(root,out,plus=true){
 const file=plus?'probe.exe':'probe32.exe';
 const object=path.join(out,plus?'resource-api.obj':'resource-api32.obj');
 await promisify(execFile)('clang',['-target',plus?'x86_64-pc-windows-msvc':'i686-pc-windows-msvc','-O1','-ffreestanding','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-optimize-sibling-calls','-c',path.join(root,'examples/pe-feature/resource-api.c'),'-o',object]);
 const parsed=coff(await readFile(object)),ui=buildUiPe({plus,imports:[{name:'user32.dll',entries:['LoadStringW']}],code:({slot,imageBase})=>{if(plus)return relocate(parsed,new Map([['__imp_LoadStringW',slot('user32.dll!LoadStringW')]]));const code=Buffer.from(parsed.code);for(const r of parsed.relocations){assert.equal(r.type,6);assert.ok(r.offset+4<=code.length);assert.equal(parsed.symbols.get(r.symbol).name,'__imp__LoadStringW@16');code.writeUInt32LE(Number(imageBase)+slot('user32.dll!LoadStringW')+code.readUInt32LE(r.offset),r.offset);}return code;}});
 const entry=[...parsed.symbols.values()].find(s=>s.name===(plus?'resource_api_probe':'_resource_api_probe')&&s.section===parsed.section);assert.ok(entry);
 ui.bytes.writeUInt32LE(0x8000+entry.value,0x40+24+16);for(let i=0;i<2;i++){if(plus)ui.bytes.writeBigUInt64LE(0x140008000n+BigInt(entry.value),ui.table+i*ui.rowSize+24);else ui.bytes.writeUInt32LE(0x408000+entry.value,ui.table+i*ui.rowSize+20);}
 await writeFile(path.join(out,'input',file),ui.bytes);return {file,entry:'0x'+((plus?0x140008000n:0x408000n)+BigInt(entry.value)).toString(16),executed:false};
}
