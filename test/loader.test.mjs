import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink} from 'node:fs/promises';import {tmpdir} from 'node:os';import path from 'node:path';
import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readMachOLoader,inspectLoader} from '../dist/loader.js';import {survey,hashFile,openIndex} from '../dist/survey.js';import {readObservation,searchObservations} from '../dist/native.js';
import {bindReconstruction,reconstructionContract} from '../dist/reconstruction-contract.js';
const exec=promisify(execFile);
function image({little=true,bits=64,cpuType=bits===64?0x100000c:12,cpuSubtype=0,fileType=2,commands=[]}={}){
 const list=commands.map(({command=0xc,name='@rpath/libfeature.dylib',useFlags})=>{const dylib=![0x8000001c,0x27].includes(command),minimum=dylib?(useFlags===undefined?24:28):12,bytes=Buffer.from(name),size=Math.ceil((minimum+bytes.length+1)/(bits/8))*(bits/8),b=Buffer.alloc(size);const put=(n,p)=>little?b.writeUInt32LE(n,p):b.writeUInt32BE(n,p);put(command,0);put(size,4);put(minimum,8);if(dylib){put(useFlags===undefined?0:0x1a741800,12);put(0x010203,16);put(0x010000,20);if(useFlags!==undefined)put(useFlags,24);}bytes.copy(b,minimum);return b;});
 const header=Buffer.alloc(bits===64?32:28),put=(n,p)=>little?header.writeUInt32LE(n,p):header.writeUInt32BE(n,p);put(bits===64?0xfeedfacf:0xfeedface,0);put(cpuType,4);put(cpuSubtype,8);put(fileType,12);put(list.length,16);put(list.reduce((n,b)=>n+b.length,0),20);return Buffer.concat([header,...list]);
}
function fat(images,{little=false,bits=32}={}){
 const width=bits===64?32:20,table=Buffer.alloc(8+width*images.length),parts=[table];const put=(n,p)=>little?table.writeUInt32LE(n,p):table.writeUInt32BE(n,p);put(bits===64?0xcafebabf:0xcafebabe,0);put(images.length,4);let offset=Math.ceil(table.length/8)*8;parts.push(Buffer.alloc(offset-table.length));
 images.forEach((b,i)=>{const p=8+i*width,le=b.readUInt32BE(0)===0xcffaedfe||b.readUInt32BE(0)===0xcefaedfe;put(le?b.readUInt32LE(4):b.readUInt32BE(4),p);put(le?b.readUInt32LE(8):b.readUInt32BE(8),p+4);if(bits===64){little?table.writeBigUInt64LE(BigInt(offset),p+8):table.writeBigUInt64BE(BigInt(offset),p+8);little?table.writeBigUInt64LE(BigInt(b.length),p+16):table.writeBigUInt64BE(BigInt(b.length),p+16);}else{put(offset,p+8);put(b.length,p+12);}put(3,p+(bits===64?24:16));parts.push(b);const padding=(8-b.length%8)%8;parts.push(Buffer.alloc(padding));offset+=b.length+padding;});return Buffer.concat(parts);
}
async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),'carve-loader-'));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test('Mach-O reader preserves ordered dependencies, install names, flags and exact file offsets in both byte orders',async t=>{
 const root=await fixture(t);
 for(const bits of [32,64])for(const little of [true,false]){
  const file=path.join(root,bits+'-'+little),b=image({bits,little,commands:[{command:0x8000001c,name:'@loader_path/../lib'},{command:0xc,name:'@rpath/libfeature.dylib'},{command:0x80000018,name:'/system/weak',useFlags:9},{command:0x8000001f,name:'/system/reexport'},{command:0xd,name:'@rpath/identity'},{command:0x27,name:'DYLD_LIBRARY_PATH=/untrusted'}]});await writeFile(file,b);const r=await readMachOLoader(file);
  assert.equal(r.bits,bits);assert.equal(r.endian,little?'little':'big');assert.equal(r.dependencies.length,3);assert.equal(r.dependencies[1].useFlags,9);assert.equal(r.dependencies[2].commandName,'LC_REEXPORT_DYLIB');assert.equal(r.dependencies[0].fileOffset,(bits===64?32:28)+r.rpaths[0].commandBytes);assert.equal(r.installNames[0].name,'@rpath/identity');assert.equal(r.dyldEnvironment[0].name,'DYLD_LIBRARY_PATH=/untrusted');assert.equal(r.dependencies[0].currentVersion,0x010203);
 }
});
test('universal32/64 and swapped tables require an explicit slice and preserve selected CPU/range identity',async t=>{
 const root=await fixture(t),arm=image({commands:[{name:'/arm64'}]}),x86=image({cpuType:0x1000007,cpuSubtype:3,commands:[{name:'/x86_64'}]});
 for(const bits of [32,64])for(const little of [true,false]){
  const file=path.join(root,bits+'-'+little);await writeFile(file,fat([arm,x86],{bits,little}));await assert.rejects(()=>readMachOLoader(file),/explicitly/);const r=await readMachOLoader(file,1);assert.equal(r.slice.cpuType,0x1000007);assert.equal(r.dependencies[0].name,'/x86_64');assert.ok(r.dependencies[0].fileOffset>r.slice.offset);await assert.rejects(()=>readMachOLoader(file,2),/absent/);
 }
});
test('malformed commands, unterminated or invalid strings and unsafe fat ranges fail before evidence ingestion',async t=>{
 const root=await fixture(t),valid=image({commands:[{name:'/library'}]}),cases=[];
 const changed=(mutate)=>{const b=Buffer.from(valid);mutate(b);cases.push(b);};
 changed(b=>b.writeUInt32LE(0,36));changed(b=>b.writeUInt32LE(9,36));changed(b=>b.writeUInt32LE(0xffffffff,20));changed(b=>b.writeUInt32LE(4097,16));changed(b=>b.writeUInt32LE(0,40));changed(b=>b.fill(65,56));changed(b=>{b[56]=255;});changed(b=>b.writeUInt32LE(0,16));cases.push(valid.subarray(0,30));cases.push(Buffer.from('not a mach-o binary'));
 const overlapping=fat([valid,valid]);overlapping.writeUInt32BE(overlapping.readUInt32BE(16),36);cases.push(overlapping);
 const mismatch=fat([valid]);mismatch.writeUInt32BE(0x1000007,8);cases.push(mismatch);
 const huge=fat([valid],{bits:64});huge.writeBigUInt64BE(2n**63n,16);cases.push(huge);
 const reserved=fat([valid],{bits:64});reserved.writeUInt32BE(1,36);cases.push(reserved);
 for(let i=0;i<cases.length;i++){const file=path.join(root,''+i);await writeFile(file,cases[i]);await assert.rejects(()=>readMachOLoader(file,0),'invalid binary case'+i);}
});
test('loader pages preserve immutable supporting evidence and retain every indexed rpath alternative without external reads',async t=>{
 const root=await fixture(t),input=path.join(root,'input'),workspace=path.join(root,'work');for(const dir of ['bin','lib','decoy'])await mkdir(path.join(input,dir),{recursive:true});
 await writeFile(path.join(input,'bin/app'),image({commands:[{command:0x8000001c,name:'@loader_path/../lib'},{command:0x8000001c,name:'@executable_path/../decoy'},{name:'@rpath/libfeature.dylib'},{name:'/never-open/secret.dylib'},{name:'@loader_path/missing'}]}));for(const dir of ['lib','decoy'])await writeFile(path.join(input,dir,'libfeature.dylib'),image({fileType:6}));await survey(input,{workspace});
 const a=await inspectLoader(workspace,{file:'bin/app',limit:1});assert.equal(a.total,3);assert.equal(a.nextOffset,1);assert.deepEqual(a.dependencies[0].paths.map(p=>p.candidate.file),['lib/libfeature.dylib','decoy/libfeature.dylib']);assert.ok(a.dependencies[0].paths.every(p=>p.candidate.freshBytesChecked===false));assert.equal(a.dependencies[0].runtimeLoading,'unverified');
 const second=await inspectLoader(workspace,{file:'bin/app',offset:1,limit:1});assert.equal(second.observationId,a.observationId);assert.equal(second.dependencies[0].paths[0].status,'outside-inventory');assert.equal(second.nextOffset,2);const o=await readObservation(workspace,a.observationId);assert.equal(o.kind,'native-loader');assert.equal(o.decompilationStatus,null);assert.equal(o.matchesCurrentInventory,true);assert.equal((await searchObservations(workspace,'libfeature')).items[0].id,a.observationId);assert.equal((await hashFile(a.evidence)).sha256,a.evidenceSha256);
 const asCode=reconstructionContract.parse({schema:'carve/reconstruction@1',goal:'test',file:'bin/app',evidenceIds:[a.observationId],behavior:{description:'test',inputDomain:'test',outputDomain:'test'},dependencies:[],unknowns:[]});await assert.rejects(()=>bindReconstruction(workspace,asCode),/complete decompiled/);
 await writeFile(a.evidence,'modified evidence');await assert.rejects(()=>inspectLoader(workspace,{file:'bin/app'}),/evidence changed/);
 await writeFile(path.join(input,'bin/app'),image());await assert.rejects(()=>inspectLoader(workspace,{file:'bin/app'}),/changed since inventory/);
});
test('a library does not invent an executable/inherited runpath context and path expansion has explicit bounds',async t=>{
 const root=await fixture(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 await writeFile(path.join(input,'library'),image({fileType:6,commands:[{command:0x8000001c,name:'@executable_path/lib'},...Array.from({length:40},(_,i)=>({command:0x8000001c,name:'@loader_path/path'+i})),...Array.from({length:10},()=>({name:'@rpath/feature'})),{name:'relative-name'}]}));await survey(input,{workspace});
 const r=await inspectLoader(workspace,{file:'library',limit:100});assert.equal(r.dependencies[0].paths[0].expandedPath,null);assert.equal(r.dependencies[0].pathsTruncated,true);assert.equal(r.dependencies.reduce((n,d)=>n+d.paths.length,0),256);assert.equal(r.dependencies.at(-1).pathsTruncated,true);
 for(const opts of [{limit:0},{limit:101},{offset:-1},{slice:-1}])await assert.rejects(()=>inspectLoader(workspace,{file:'library',...opts}));
});
test('actual CLI and stdio MCP inspect without engine configuration and confine selected sources',async t=>{
 const root=await fixture(t),input=path.join(root,'input');await mkdir(input);await writeFile(path.join(input,'app'),image({commands:[{name:'@loader_path/../library'}]}));await survey(input,{workspace:path.join(root,'work')});const cli=path.resolve('dist/cli.js');
 const stdout=(await exec(process.execPath,[cli,'loader',path.join(root,'work'),'--file','app'])).stdout;const info=JSON.parse(stdout);assert.equal(info.status,'loader-commands-inspected');assert.equal(info.executesTarget,false);
 const client=new Client({name:'loader-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));t.after(()=>client.close());const r=await client.callTool({name:'carve_loader',arguments:{workspace:'work',file:'app'}});assert.equal(r.isError,undefined);assert.equal(JSON.parse(r.content[0].text).observationId,info.observationId);
 const bad=await client.callTool({name:'carve_loader',arguments:{workspace:'work',file:'../outside'}});assert.equal(bad.isError,true);
 const outside=await mkdtemp(path.join(tmpdir(),'carve-loader-outside-'));t.after(()=>rm(outside,{recursive:true,force:true}));await writeFile(path.join(outside,'app'),image());await survey(outside,{workspace:path.join(root,'outside-work')});const denied=await client.callTool({name:'carve_loader',arguments:{workspace:'outside-work',file:'app'}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
 await symlink(path.join(outside,'app'),path.join(input,'linked'));const link=await client.callTool({name:'carve_loader',arguments:{workspace:'work',file:'linked'}});assert.equal(link.isError,true);
});
test('rpath suffixes stay relative to their declared base and unindexed candidate bytes are never assumed current',async t=>{
 const root=await fixture(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(path.join(input,'bin'),{recursive:true});await mkdir(path.join(input,'lib'));
 await writeFile(path.join(input,'bin/app'),image({commands:[{command:0x8000001c,name:'@loader_path/../lib'},{name:'@rpath//feature'},{name:'@unknown/feature'}]}));await writeFile(path.join(input,'lib/feature'),'old candidate');await survey(input,{workspace});const old=(await hashFile(path.join(input,'lib/feature'))).sha256;await writeFile(path.join(input,'lib/feature'),'new candidate');
 const r=await inspectLoader(workspace,{file:'bin/app'});assert.equal(r.dependencies[0].paths[0].candidate.file,'lib/feature');assert.equal(r.dependencies[0].paths[0].candidate.sourceSha256,old);assert.equal(r.dependencies[0].paths[0].candidate.freshBytesChecked,false);assert.equal(r.dependencies[1].paths[0].expandedPath,null);
});
test('concurrent large metadata pages publish one complete immutable evidence file and one searchable observation',async t=>{
 const root=await fixture(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);await writeFile(path.join(input,'app'),image({commands:Array.from({length:1000},(_,i)=>({name:'/'+i+'x'.repeat(3490)}))}));await survey(input,{workspace});
 const results=await Promise.all(Array.from({length:3},()=>inspectLoader(workspace,{file:'app',limit:1})));assert.equal(new Set(results.map(r=>r.observationId)).size,1);assert.equal((await hashFile(results[0].evidence)).sha256,results[0].evidenceSha256);assert.equal(JSON.parse(await readFile(results[0].evidence,'utf8')).metadata.dependencies.length,1000);
 const db=openIndex(workspace,true);try{assert.equal(db.prepare('SELECT count(*) n FROM observations').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM observation_search').get().n,1);}finally{db.close();}
});
