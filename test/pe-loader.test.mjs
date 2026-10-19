import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath,readdir} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {survey} from '../dist/survey.js';
import {readPeLoader,inspectPeLoader} from '../dist/pe-loader.js';
import {buildPe} from './fixtures/pe-image.mjs';

async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-pe-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
async function read(t,options){const root=await scratch(t),file=path.join(root,'image.bin');await writeFile(file,buildPe(options));return readPeLoader(file);}

test('PE32+ and PE32 import, delay-import and export tables are read exactly',async t=>{
 const app=await read(t,{imports:[{name:'KERNEL32.dll',entries:['CreateFileW',{ordinal:7},'ReadFile']},{name:'USER32.dll',entries:['MessageBoxW']}],
  delay:[{name:'helper.dll',entries:['Helper',{ordinal:3}]}],clr:true});
 assert.equal(app.format,'pe32+');assert.equal(app.machineName,'amd64');assert.equal(app.dll,false);assert.equal(app.managed,true);assert.equal(app.imageBase,'0x140000000');assert.equal(app.entryRva,0x1010);
 assert.deepEqual(app.imports.map(m=>[m.kind,m.name,m.status,m.lookupTable,m.entries.map(e=>e.name??'#'+e.ordinal)]),[
  ['import','KERNEL32.dll','entries-read','name-table',['CreateFileW','#7','ReadFile']],['import','USER32.dll','entries-read','name-table',['MessageBoxW']],
  ['delay-import','helper.dll','entries-read','name-table',['Helper','#3']]]);
 const kernel=app.imports[0];assert.deepEqual(kernel.entries.map(e=>e.hint??null),[100,null,102]);
 assert.deepEqual(kernel.entries.map(e=>e.thunkRva-kernel.addressTableRva),[0,8,16],'thunk RVAs index the 8-byte import address table');
 assert.deepEqual(app.dataDirectories.map(d=>d.name),['import','delay-import','clr-runtime']);
 const lib=await read(t,{plus:false,dll:true,imports:[{name:'msvcrt.dll',entries:['malloc',{ordinal:12}]}],legacyDelay:{name:'old.dll',entries:['Legacy']},
  exports:{name:'sample.dll',base:5,functions:[{rva:0x5010,names:['Open','OpenAlias']},{rva:0},{forwarder:'NTDLL.RtlFree',names:['Free']},{rva:0x5040}]}});
 assert.equal(lib.format,'pe32');assert.equal(lib.machineName,'i386');assert.equal(lib.dll,true);assert.equal(lib.imageBase,'0x400000');
 assert.deepEqual(lib.imports[0].entries.map(e=>e.thunkRva-lib.imports[0].addressTableRva),[0,4]);
 assert.deepEqual(lib.imports[1],{...lib.imports[1],kind:'delay-import',name:'old.dll',status:'legacy-va-descriptor-not-interpreted',entries:[]});
 assert.equal(lib.exports.name,'sample.dll');assert.equal(lib.exports.ordinalBase,5);
 assert.deepEqual(lib.exports.entries,[{ordinal:5,rva:0x5010,names:['Open','OpenAlias']},{ordinal:7,rva:lib.exports.entries[1].rva,names:['Free'],forwarder:'NTDLL.RtlFree'},{ordinal:8,rva:0x5040,names:[]}]);
 const bound=await read(t,{imports:[{name:'bound.dll',entries:['X']},{name:'free.dll',entries:['Y']}],boundFirst:true});
 assert.equal(bound.imports[0].status,'bound-address-table-without-lookup-table');assert.deepEqual(bound.imports[0].entries,[]);assert.equal(bound.imports[1].entries[0].name,'Y');
 assert.equal((await read(t,{machine:0xaa64,imports:[]})).machineName,'arm64');
});

test('malformed images are refused with the reason, never partially read',async t=>{
 const root=await scratch(t),file=path.join(root,'bad.bin');
 const reject=async(bytes,pattern)=>{await writeFile(file,bytes);await assert.rejects(()=>readPeLoader(file),pattern);};
 const good=buildPe({imports:[{name:'a.dll',entries:['f']}]});
 await reject(Buffer.from('not a PE file at all, just text that is long enough to read a DOS header'),/missing MZ header/);
 const lfanew=Buffer.from(good);lfanew.writeUInt32LE(0x7fffffff,60);await reject(lfanew,/invalid e_lfanew/);
 const signature=Buffer.from(good);signature.write('XX',0x40,'latin1');await reject(signature,/missing PE\\0\\0 signature/);
 await reject(buildPe({characteristics:0x20}),/does not mark an executable image/);
 await reject(buildPe({sections:0}),/section count must be 1–96/);await reject(buildPe({sections:97}),/section count must be 1–96/);
 await reject(buildPe({magic:0x107}),/unsupported optional header magic 0x107/);
 // Unreferenced bytes may be cut; a cut inside a referenced table must refuse.
 assert.equal((await (async()=>{await writeFile(file,good.subarray(0,0x300));return readPeLoader(file);})()).imports[0].entries[0].name,'f');
 await reject(good.subarray(0,0x210),/import descriptor at RVA 0x1000 is not backed by file data/);
 const unmapped=Buffer.from(good);unmapped.writeUInt32LE(0x900000,0x40+24+120);await reject(unmapped,/import descriptor at RVA 0x900000 is not backed by file data/);
 const longName=buildPe({imports:[{name:'x'.repeat(5000)+'.dll',entries:['f']}]});await reject(longName,/imported module name is unterminated or longer than 4096 bytes/);
 const badUtf8=Buffer.from(good),at=badUtf8.indexOf(Buffer.from('a.dll\0'));badUtf8[at]=0xff;await reject(badUtf8,/imported module name is not valid UTF-8/);
 await reject(buildPe({exports:{name:'e.dll',base:1,functions:[{rva:0x5000,names:['x']}],ordinalIndex:{x:9}}}),/export name refers to an ordinal outside the address table/);
 await reject(buildPe({exports:{name:'e.dll',base:1,functions:[],count:100001}}),/more than 100000 exports/);
 const raw=Buffer.from(good);raw.writeUInt32LE(0x7000000,0x40+24+240+20);await reject(raw,/raw data starts outside the file/);
 await reject(buildPe({plus:true,legacyDelay:{name:'old.dll',entries:['x']}}),/64-bit delay-import descriptor uses virtual addresses/);
});

test('workspace inspection records immutable evidence, pages tables and lists same-name DLL candidates',async t=>{
 const root=await scratch(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(path.join(input,'lib'),{recursive:true});
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'helper.dll',entries:Array.from({length:40},(_,i)=>`Function${i}`)},{name:'api-ms-win-core-file-l1-1-0.dll',entries:['CreateFileW']},{name:'missing_50%.dll',entries:[{ordinal:1}]}]}));
 await writeFile(path.join(input,'HELPER.DLL'),buildPe({dll:true,exports:{name:'helper.dll',base:1,functions:[{rva:0x5000,names:['Function0']}]}}));
 await writeFile(path.join(input,'lib','helper.dll'),buildPe({dll:true,exports:{name:'helper.dll',base:1,functions:[{rva:0x5000,names:['Function1']}]}}));
 await writeFile(path.join(input,'lib','missing_50x.dll'),'an unescaped % would match this file');
 await survey(input,{workspace});
 const summary=await inspectPeLoader(workspace,{file:'app.exe'});
 assert.equal(summary.schema,'carve/pe-loader@1');assert.equal(summary.executesTarget,false);assert.equal(summary.sourceFreshlyHashed,true);
 assert.deepEqual(summary.counts,{sections:1,modules:3,delayModules:0,imports:42,exports:0,forwarders:0});assert.equal(summary.total,0);
 assert.equal(summary.receipt.responseBytes,Buffer.byteLength(JSON.stringify(summary)));
 const evidence=JSON.parse(await readFile(summary.evidence,'utf8'));assert.equal(evidence.schema,'carve/pe-loader-evidence@1');assert.equal(evidence.metadata.imports[0].entries.length,40);
 const modules=await inspectPeLoader(workspace,{file:'app.exe',view:'modules'});assert.equal(modules.observationId,summary.observationId,'same bytes give the same observation');
 assert.deepEqual(modules.items.map(m=>[m.name,m.resolution,m.candidates.map(c=>c.file)]),[
  ['helper.dll','inventory-basename-candidates',['HELPER.DLL','lib/helper.dll']],['api-ms-win-core-file-l1-1-0.dll','api-set-contract',[]],['missing_50%.dll','not-in-inventory',[]]]);
 assert.ok(modules.items.every(m=>m.runtimeLoading==='unverified'&&m.semanticMatch==='unconfirmed'));
 const pages=[];let offset=0;
 for(;;){const page=await inspectPeLoader(workspace,{file:'app.exe',view:'imports',offset,limit:100,budgetBytes:2048});assert.ok(page.receipt.responseBytes<=2048);pages.push(...page.items);if(page.nextOffset===null)break;offset=page.nextOffset;}
 assert.equal(pages.length,42);assert.deepEqual(pages.at(-1),{module:'missing_50%.dll',kind:'import',ordinal:1,thunkRva:pages.at(-1).thunkRva});
 const helper=await inspectPeLoader(workspace,{file:'HELPER.DLL',view:'exports'});assert.deepEqual(helper.items.map(e=>e.names),[['Function0']]);
 assert.equal(helper.exportName,'helper.dll');
 const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});
 try{assert.equal(db.prepare("SELECT count(*) n FROM observations WHERE kind='native-loader'").get().n,2);}finally{db.close();}
 assert.equal((await readdir(path.join(workspace,'loader-evidence'))).filter(n=>n.endsWith('.json')).length,2);
 await assert.rejects(()=>inspectPeLoader(workspace,{file:'app.exe',view:'imports',offset:42}),/offset below 42/);
 await assert.rejects(()=>inspectPeLoader(workspace,{file:'app.exe',view:'resources'}),/Use view summary/);
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'other.dll',entries:['x']}]}));
 await assert.rejects(()=>inspectPeLoader(workspace,{file:'app.exe'}),/changed since inventory/);
});

// Real Windows images shipped inside the local Ghidra distribution, compared with LLVM's PE reader.
const ghidra=fileURLToPath(new URL('../artifacts/engines/ghidra/ghidra_12.1.4_PUBLIC/',import.meta.url));
const objdump='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump';
const realFiles=['GPL/DMG/data/os/win_x86_32/llio_amd64.dll','GPL/DMG/data/os/win_x86_32/llio_i386.dll','GPL/DMG/data/os/win_x86_64/llio_amd64.dll','GPL/DMG/data/os/win_x86_64/llio_i386.dll',
 'GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_24.exe','GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_41.exe','Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe','Ghidra/Features/Decompiler/os/win_x86_64/sleigh.exe',
 'Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll','Ghidra/Features/FileFormats/os/win_x86_64/lzfse.exe','Ghidra/Features/PDB/os/win_x86_64/pdb.exe',
 'docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceSrc.exe','docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceVersion2.exe','docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe'];
function llvmTables(file){
 const imports=[],exports=[];let section=null,module=null;
 for(const line of execFileSync(objdump,['-p',file],{encoding:'utf8',maxBuffer:64*1024*1024}).split('\n')){
  if(line.startsWith('The Import Tables:')){section='imports';continue;}if(line.startsWith('Export Table:')){section='exports';continue;}
  if(/^\S/.test(line))section=null;
  const name=/^\s+DLL Name: (.+)$/.exec(line);if(section==='imports'&&name){module=name[1].trim();continue;}
  const entry=section==='imports'&&module&&!line.includes('Hint/Ord')&&/^\s+(\d+)(?:\s+(\S.*))?$/.exec(line);if(entry)imports.push(`${module}|${entry[1]}|${(entry[2]??'').trim()}`);
  const exported=section==='exports'&&/^\s+(\d+)\s+(0x[0-9a-f]+)\s*(.*)$/.exec(line);if(exported)exports.push(`${exported[1]}|${parseInt(exported[2],16)}|${exported[3].trim()}`);
 }
 return{imports:imports.sort(),exports:exports.sort()};
}
test('fourteen real Windows images match llvm-objdump import and export tables; IA-64 imports match an independent decode',async t=>{
 if(!existsSync(ghidra)||!existsSync(objdump)){t.skip('local Ghidra distribution or Xcode llvm-objdump is not available');return;}
 let imports=0,exports=0;
 for(const relative of realFiles){
  const file=path.join(ghidra,relative),mine=await readPeLoader(file),reference=llvmTables(file);
  assert.deepEqual(mine.imports.flatMap(m=>m.entries.map(e=>`${m.name}|${e.name!==undefined?e.hint:e.ordinal}|${e.name??''}`)).sort(),reference.imports,relative+' imports');
  assert.deepEqual((mine.exports?.entries??[]).flatMap(e=>(e.names.length?e.names:['']).map(n=>`${e.ordinal}|${e.rva}|${n}`)).sort(),reference.exports,relative+' exports');
  imports+=reference.imports.length;exports+=reference.exports.length;
 }
 assert.deepEqual([imports,exports],[1167,71]);
 const jni=await readPeLoader(path.join(ghidra,'Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll'));
 assert.equal(jni.exports.entries.filter(e=>e.names.some(n=>n.startsWith('Java_'))).length,27);
 // Apple LLVM 21 llvm-objdump stops after the first IA-64 import; the 78 entries were confirmed by decoding the lookup table directly.
 for(const dir of ['win_x86_32','win_x86_64']){
  const ia64=await readPeLoader(path.join(ghidra,`GPL/DMG/data/os/${dir}/llio_ia64.dll`));
  assert.equal(ia64.machineName,'ia64');assert.equal(ia64.imports[0].entries.length,78);
  assert.deepEqual(ia64.imports[0].entries.slice(0,5).map(e=>e.name),['GetLastError','CreateFileW','MultiByteToWideChar','SetFilePointerEx','ReadFile']);
  assert.deepEqual((ia64.exports?.entries??[]).map(e=>e.ordinal).sort((a,b)=>a-b),llvmTables(path.join(ghidra,`GPL/DMG/data/os/${dir}/llio_ia64.dll`)).exports.map(e=>Number(e.split('|')[0])).sort((a,b)=>a-b));
 }
});
