import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {survey} from '../dist/survey.js';
import {readPeLoader} from '../dist/pe-loader.js';
import {readPeImportCalls,decodePeImportCall,inspectPeImportCalls,bridgePeImportCall} from '../dist/pe-calls.js';
import {buildPe} from './fixtures/pe-image.mjs';

async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-pe-calls-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
const imports=[{name:'KERNEL32.dll',entries:['CreateFileW','ReadFile','CloseHandle']},{name:'USER32.dll',entries:[{ordinal:7}]},{name:'helper.dll',entries:['Helper',{ordinal:3},'Moved']}];
// x86-64 code exercising every recognised form and the patterns that must not be reported.
function code64(marks){return({slot,textRva})=>{
 const b=[],at=()=>b.length,i32=v=>{const x=Buffer.alloc(4);x.writeInt32LE(v);b.push(...x);};
 const rip=(op,key,prefix=[])=>{const start=at();b.push(...prefix,0xff,op);i32(slot(key)-(textRva+at()+4));return start;};
 marks.call=rip(0x15,'KERNEL32.dll!CreateFileW');
 b.push(0x48,0x8d,0x48,0x48);marks.afterLea=rip(0x15,'KERNEL32.dll!CloseHandle');// lea rcx,[rax+0x48] ends in 0x48
 marks.ordinal=rip(0x15,'USER32.dll!#7');marks.delay=rip(0x15,'delay.dll!Delayed');marks.helper=rip(0x15,'helper.dll!Helper');
 marks.helperOrdinal=rip(0x15,'helper.dll!#3');marks.moved=rip(0x15,'helper.dll!Moved');
 marks.registerLoad=at();b.push(0x48,0x8b,0x05);i32(slot('KERNEL32.dll!ReadFile')-(textRva+at()+4));b.push(0xff,0xd0);// mov rax,[slot]; call rax
 marks.decoy=at();b.push(0xff,0x15);i32(0x1004-(textRva+at()+4));// reads data, not an import slot
 marks.viaRex=at();b.push(0xe8,0,0,0,0);marks.viaOpcode=at();b.push(0xe8,0,0,0,0);b.push(0xc3);
 marks.thunk=at();b.push(0x48,0xff,0x25);i32(slot('KERNEL32.dll!ReadFile')-(textRva+at()+4));
 const out=Buffer.from(b);out.writeInt32LE(marks.thunk-(marks.viaRex+5),marks.viaRex+1);out.writeInt32LE(marks.thunk+1-(marks.viaOpcode+5),marks.viaOpcode+1);
 marks.textRva=textRva;return out;
};}
const image64=(marks,extra={})=>buildPe({imports,delay:[{name:'delay.dll',entries:['Delayed']}],code:code64(marks),...extra});

test('x86-64 scanning finds call/jmp through import slots and calls into REX jump thunks, nothing else',async t=>{
 const root=await scratch(t),file=path.join(root,'app.exe'),m={};await writeFile(file,image64(m));
 const scan=await readPeImportCalls(file);assert.equal(scan.architecture,'x86-64');assert.equal(scan.status,'byte-pattern-candidates');
 const r=x=>m.textRva+x,sites=Object.fromEntries(scan.sites.map(s=>[s.instructionRva,s]));
 assert.deepEqual(scan.sites.map(s=>[s.instructionRva-m.textRva,s.form,s.slot.module+'!'+(s.slot.name??'#'+s.slot.ordinal)]),[
  [m.call,'call-indirect','KERNEL32.dll!CreateFileW'],[m.afterLea,'call-indirect','KERNEL32.dll!CloseHandle'],[m.ordinal,'call-indirect','USER32.dll!#7'],
  [m.delay,'call-indirect','delay.dll!Delayed'],[m.helper,'call-indirect','helper.dll!Helper'],[m.helperOrdinal,'call-indirect','helper.dll!#3'],[m.moved,'call-indirect','helper.dll!Moved'],
  [m.viaRex,'call-via-thunk','KERNEL32.dll!ReadFile'],[m.viaOpcode,'call-via-thunk','KERNEL32.dll!ReadFile'],[m.thunk+1,'jump-indirect','KERNEL32.dll!ReadFile']]);
 assert.equal(sites[r(m.afterLea)].precedingByteRexW,true,'a preceding 0x48 is reported, not guessed to be a prefix');
 assert.equal(sites[r(m.thunk+1)].precedingByteRexW,true);assert.equal(sites[r(m.call)].precedingByteRexW,undefined);
 assert.equal(sites[r(m.viaRex)].thunkRva,r(m.thunk));assert.equal(sites[r(m.viaOpcode)].thunkRva,r(m.thunk+1));
 assert.equal(sites[r(m.delay)].slot.importKind,'delay-import');assert.equal(sites[r(m.call)].instructionEndRva,r(m.call+6));
 assert.equal(sites[r(m.registerLoad)],undefined);assert.equal(sites[r(m.decoy)],undefined);
});

test('x86 absolute forms, exact decoding at evidence addresses, and refusals',async t=>{
 const root=await scratch(t),file=path.join(root,'app32.exe'),marks={};
 await writeFile(file,buildPe({plus:false,imports:[{name:'KERNEL32.dll',entries:['ExitProcess','GetTickCount']}],code:({slot,imageBase})=>{
  const b=Buffer.alloc(32,0x90),va=k=>Number(imageBase)+slot(k);
  b.set([0xff,0x15],0);b.writeUInt32LE(va('KERNEL32.dll!ExitProcess'),2);b.set([0xe8],6);b.writeInt32LE(16-11,7);b.set([0xff,0x25],16);b.writeUInt32LE(va('KERNEL32.dll!GetTickCount'),18);marks.base=0x8000;return b;}}));
 const scan=await readPeImportCalls(file);assert.equal(scan.architecture,'x86');
 assert.deepEqual(scan.sites.map(s=>[s.instructionRva-0x8000,s.form,s.slot.name]),[[0,'call-indirect','ExitProcess'],[6,'call-via-thunk','GetTickCount'],[16,'jump-indirect','GetTickCount']]);
 assert.equal((await decodePeImportCall(file,0x8006)).thunkRva,0x8010);
 const m={},file64=path.join(root,'app.exe');await writeFile(file64,image64(m));const r=x=>m.textRva+x;
 const rex=await decodePeImportCall(file64,r(m.thunk));assert.deepEqual([rex.form,rex.rexW,rex.instructionEndRva-rex.instructionRva,rex.slot.name],['jump-indirect',true,7,'ReadFile']);
 const plain=await decodePeImportCall(file64,r(m.thunk+1));assert.deepEqual([plain.form,plain.rexW,plain.instructionEndRva],['jump-indirect',undefined,rex.instructionEndRva]);
 assert.equal((await decodePeImportCall(file64,r(m.viaRex))).slot.name,'ReadFile');
 await assert.rejects(()=>decodePeImportCall(file64,r(m.decoy)),/reads 0x1004, which is not an import address table slot/);
 await assert.rejects(()=>decodePeImportCall(file64,r(m.registerLoad)),/is not call\/jmp through an import slot or call rel32/);
 await assert.rejects(()=>decodePeImportCall(file64,0x1000),/RVA 0x1000 is not in an executable section/);
 await assert.rejects(()=>decodePeImportCall(file64,-1),/instructionRva must be a 32-bit RVA/);
 const arm=path.join(root,'arm.exe');await writeFile(arm,buildPe({machine:0xaa64,imports}));
 assert.equal((await readPeImportCalls(arm)).status,'unsupported-machine');await assert.rejects(()=>decodePeImportCall(arm,0x8000),/machine arm64 is not supported/);
});

test('workspace views and the byte-bound bridge to a same-name library export',async t=>{
 const root=await scratch(t),input=path.join(root,'input'),workspace=path.join(root,'work'),m={};await mkdir(input);
 await writeFile(path.join(input,'app.exe'),image64(m));const r=x=>m.textRva+x;
 await writeFile(path.join(input,'HELPER.DLL'),buildPe({dll:true,exports:{name:'helper.dll',base:1,functions:[{rva:0x5010,names:['Helper']},{rva:0},{rva:0x5030},{forwarder:'core.Moved',names:['Moved']}]}}));
 await writeFile(path.join(input,'other.dll'),buildPe({dll:true,exports:{name:'other.dll',base:1,functions:[{rva:0x5010,names:['Helper']}]}}));
 await survey(input,{workspace});
 const summary=await inspectPeImportCalls(workspace,{file:'app.exe'});
 assert.deepEqual(summary.counts,{sites:10,'call-indirect':7,'jump-indirect':1,'call-via-thunk':2,imports:8,importsWithSites:8});
 assert.equal(summary.executesTarget,false);assert.equal(summary.receipt.responseBytes,Buffer.byteLength(JSON.stringify(summary)));
 const apis=await inspectPeImportCalls(workspace,{file:'app.exe',view:'apis',limit:100});
 assert.deepEqual(apis.items.map(a=>[a.module,a.name??'#'+a.ordinal,a.sites]),[['delay.dll','Delayed',1],['helper.dll','#3',1],['helper.dll','Helper',1],['helper.dll','Moved',1],['KERNEL32.dll','CloseHandle',1],['KERNEL32.dll','CreateFileW',1],['KERNEL32.dll','ReadFile',3],['USER32.dll','#7',1]]);
 const sites=[];let offset=0;for(;;){const page=await inspectPeImportCalls(workspace,{file:'app.exe',view:'sites',offset,budgetBytes:2200});assert.ok(page.receipt.responseBytes<=2200);sites.push(...page.items);if(page.nextOffset===null)break;offset=page.nextOffset;}
 assert.equal(sites.length,10);
 const bound=await bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.helper)},library:{file:'HELPER.DLL'}});
 assert.equal(bound.status,'byte-bound-static-import');assert.equal(bound.resolution,'same-name-inventory-file');assert.equal(bound.runtimeLoading,'unverified');
 assert.deepEqual(bound.witness.library.export,{ordinal:1,rva:0x5010,names:['Helper']});assert.equal(bound.witness.import.module,'helper.dll');
 assert.equal(bound.witness.caller.instruction.bytes.slice(0,4),'ff15');
 const byOrdinal=await bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.helperOrdinal)},library:{file:'HELPER.DLL'}});assert.deepEqual(byOrdinal.witness.library.export,{ordinal:3,rva:0x5030,names:[]});
 const forwarded=await bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.moved)},library:{file:'HELPER.DLL'}});
 assert.equal(forwarded.status,'byte-bound-static-import-forwarded');assert.equal(forwarded.witness.library.export.forwarder,'core.Moved');
 const open=await bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.call)}});assert.equal(open.status,'import-resolved-library-not-selected');assert.equal(open.witness.library,null);
 await assert.rejects(()=>bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.helper)},library:{file:'other.dll'}}),/does not have the imported module name helper.dll/);
 await assert.rejects(()=>bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.call)},library:{file:'HELPER.DLL'}}),/does not have the imported module name KERNEL32.dll/);
 await writeFile(path.join(input,'HELPER.DLL'),buildPe({dll:true,exports:{name:'helper.dll',base:1,functions:[{rva:0x5010,names:['Renamed']}]}}));
 await assert.rejects(()=>bridgePeImportCall(workspace,{caller:{file:'app.exe',instructionRva:r(m.helper)},library:{file:'HELPER.DLL'}}),/changed since inventory/);
 const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});
 try{assert.deepEqual(db.prepare("SELECT kind,count(*) n FROM observations GROUP BY kind ORDER BY kind").all().map(r=>[r.kind,r.n]),[['native-import-bridge',4],['native-import-calls',1]]);}finally{db.close();}
 const evidence=JSON.parse(await readFile(bound.evidence,'utf8'));assert.equal(evidence.schema,'carve/pe-import-bridge-evidence@1');assert.equal(evidence.witness.library.sourceSha256,bound.witness.library.sourceSha256);
});

// Real Windows images in the local Ghidra distribution, compared with LLVM's disassembler.
const ghidra=fileURLToPath(new URL('../artifacts/engines/ghidra/ghidra_12.1.4_PUBLIC/',import.meta.url));
const objdump='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump';
const realFiles=['GPL/DMG/data/os/win_x86_32/llio_amd64.dll','GPL/DMG/data/os/win_x86_32/llio_i386.dll','GPL/DMG/data/os/win_x86_64/llio_amd64.dll','GPL/DMG/data/os/win_x86_64/llio_i386.dll',
 'GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_24.exe','GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_41.exe','Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe','Ghidra/Features/Decompiler/os/win_x86_64/sleigh.exe',
 'Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll','Ghidra/Features/FileFormats/os/win_x86_64/lzfse.exe','Ghidra/Features/PDB/os/win_x86_64/pdb.exe',
 'docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceSrc.exe','docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceVersion2.exe','docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe'];
function llvmSites(file,metadata){
 const base=BigInt(metadata.imageBase),slots=new Set(metadata.imports.flatMap(m=>m.entries.map(e=>e.thunkRva))),sites=[],direct=[];
 for(const line of execFileSync(objdump,['-d',file],{encoding:'utf8',maxBuffer:512*1024*1024}).split('\n')){
  const m=/^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S+)\s+(.*)$/.exec(line);if(!m)continue;
  const start=Number(BigInt('0x'+m[1])-base),length=m[2].trim().split(' ').length,kind=/^call/.test(m[3])?'call':/^jmp/.test(m[3])?'jump':null;if(!kind)continue;
  const rip=/^\*0x[0-9a-f]+\(%rip\)\s+#\s+0x([0-9a-f]+)/.exec(m[4]),abs=/^\*0x([0-9a-f]+)$/.exec(m[4].trim()),slot=rip?Number(BigInt('0x'+rip[1])-base):abs?Number(BigInt('0x'+abs[1])-base):null;
  if(slot!==null&&slots.has(slot)){sites.push({start,end:start+length,form:kind==='call'?'call-indirect':'jump-indirect',slot});continue;}
  const target=kind==='call'&&length===5&&/^0x([0-9a-f]+)/.exec(m[4].trim());if(target)direct.push({start,end:start+5,target:Number(BigInt('0x'+target[1])-base)});
 }
 const thunks=new Map(sites.filter(s=>s.form==='jump-indirect').map(s=>[s.start,s.slot]));
 for(const d of direct)if(thunks.has(d.target))sites.push({start:d.start,end:d.end,form:'call-via-thunk',slot:thunks.get(d.target)});
 return sites;
}
test('fourteen real x86 / x86-64 Windows images match llvm-objdump call sites, and every LLVM site decodes exactly',async t=>{
 if(!existsSync(ghidra)||!existsSync(objdump)){t.skip('local Ghidra distribution or Xcode llvm-objdump is not available');return;}
 const key=s=>s.form==='call-via-thunk'?`${s.start}|${s.end}|${s.form}|${s.slot}`:`${s.end}|${s.form}|${s.slot}`;let total=0;
 for(const relative of realFiles){
  const file=path.join(ghidra,relative),scan=await readPeImportCalls(file),reference=llvmSites(file,scan.metadata);
  assert.deepEqual(scan.sites.map(s=>key({start:s.instructionRva,end:s.instructionEndRva,form:s.form,slot:s.slotRva})).sort(),reference.map(key).sort(),relative);
  for(const site of reference){const decoded=await decodePeImportCall(file,site.start,{metadata:scan.metadata});assert.deepEqual([decoded.form,decoded.slotRva,decoded.instructionEndRva],[site.form,site.slot,site.end],relative+' @'+site.start.toString(16));}
  total+=reference.length;
 }
 assert.equal(total,5116);
 assert.equal((await readPeImportCalls(path.join(ghidra,'GPL/DMG/data/os/win_x86_64/llio_ia64.dll'))).status,'unsupported-machine');
});
