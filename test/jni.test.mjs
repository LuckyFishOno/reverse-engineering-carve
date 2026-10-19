import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,openIndex,queryIndex} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';
import {linkageTables,saveLinkage,saveLinkagePage} from '../dist/linkage.js';
import {classNatives,dexNatives,decodeModifiedUtf8,jniMangle,jniNames,inspectJni} from '../dist/jni.js';
import {sampleClass,innerClass,sampleDex,expectedJniNames} from './fixtures/jni-sample.mjs';
const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
const selectedName=n=>n.overloaded?n.jniLongName:n.jniShortName;
const comparable=n=>[n.className,n.method,n.descriptor,n.static,n.overloaded,n.jniShortName,n.jniLongName].join(' ');

test('class and D8 DEX declarations agree and derive the exact names emitted by javac -h',()=>{
 const fromClasses=[...classNatives(sampleClass).natives,...classNatives(innerClass).natives],fromDex=dexNatives(sampleDex).natives;
 assert.equal(fromClasses.length,6);assert.deepEqual(fromDex.map(comparable).sort(),fromClasses.map(comparable).sort());
 assert.deepEqual(fromClasses.map(selectedName).sort(),expectedJniNames);
 const over=fromClasses.filter(n=>n.method==='over');assert.ok(over.every(n=>n.overloaded&&n.static));
 const handle=fromClasses.find(n=>n.method==='handle');assert.equal(handle.static,false);assert.equal(handle.descriptor,'(Ljava/lang/String;[[B)J');
 assert.equal(handle.jniLongName,'Java_carve_jni_1fixture_Sample_handle__Ljava_lang_String_2_3_3B');
 assert.equal(fromClasses.find(n=>n.className==='carve.jni_fixture.Sample$Inner').internalName,'carve/jni_fixture/Sample$Inner');
 assert.ok(fromClasses.some(n=>n.method==='näme_1'),'modified UTF-8 method name decoded');
 assert.equal(dexNatives(sampleDex).classes,2);
});

test('JNI mangling and modified UTF-8 follow their specifications, and malformed inputs fail without partial results',()=>{
 assert.equal(jniMangle('a/b_c;[$é𝄞'),'a_b_1c_2_3_00024_000e9_0d834_0dd1e');
 assert.deepEqual(jniNames('p/Q','m','()V'),{jniShortName:'Java_p_Q_m',jniLongName:'Java_p_Q_m__'});
 assert.throws(()=>jniNames('p/Q','m','V'),/descriptor/);
 assert.equal(decodeModifiedUtf8(Buffer.from([0x41,0xc0,0x80,0xed,0xa0,0xb4,0xed,0xb4,0x9e]),0,9),'A\0𝄞');
 for(const bytes of [[0],[0xf0,0x9d,0x84,0x9e],[0xc3],[0xe2,0x82]])assert.throws(()=>decodeModifiedUtf8(Buffer.from(bytes),0,bytes.length),/JNI declarations/);
 assert.throws(()=>classNatives(sampleClass.subarray(0,sampleClass.length-3)),/truncated/);
 assert.throws(()=>classNatives(Buffer.concat([sampleClass,Buffer.from([0])])),/trailing/);
 assert.throws(()=>classNatives(Buffer.from('not a class file')),/Java class/);
 const badSize=Buffer.from(sampleDex);badSize.writeUInt32LE(badSize.length+1,0x20);assert.throws(()=>dexNatives(badSize),/file size/);
 const badTable=Buffer.from(sampleDex);badTable.writeUInt32LE(0x7fffffff,0x60);assert.throws(()=>dexNatives(badTable),/outside/);
 assert.throws(()=>dexNatives(sampleDex.subarray(0,0x60)),/DEX/);
});

test('overlong modified UTF-8 is rejected like HotSpot and ART, except in class files of major version 47 or older',()=>{
 for(const bytes of [[0xc1,0xa4],[0xc0,0x81],[0xe0,0x81,0xa4],[0xe0,0x9f,0xbf]])assert.throws(()=>decodeModifiedUtf8(Buffer.from(bytes),0,bytes.length),/overlong/);
 assert.equal(decodeModifiedUtf8(Buffer.from([0xc1,0xa4]),0,2,{allowOverlong:true}),'d');
 assert.equal(decodeModifiedUtf8(Buffer.from([0xc2,0x80,0xe0,0xa0,0x80]),0,5),'\u0080\u0800');
 // Same-length substitution of "ä" (c3 a4) by the overlong "d" (c1 a4) in the method name näme_1.
 // Temurin 21 defineClass rejects the major-55 form with ClassFormatError and accepts it at major 45.
 const overlong=data=>{const out=Buffer.from(data),at=out.indexOf(Buffer.from([0x6e,0xc3,0xa4,0x6d,0x65,0x5f,0x31]));assert.ok(at>0);out[at+1]=0xc1;return out;};
 assert.throws(()=>classNatives(overlong(sampleClass)),/overlong two-byte/);
 const legacy=overlong(sampleClass);legacy.writeUInt16BE(45,6);assert.ok(classNatives(legacy).natives.some(n=>n.method==='ndme_1'));
 assert.throws(()=>dexNatives(overlong(sampleDex)),/overlong two-byte/);
});

const elf=()=>{const b=Buffer.alloc(64);b.writeUInt32BE(0x7f454c46);b[4]=2;b[5]=1;b.writeUInt16LE(3,16);b.writeUInt16LE(183,18);return b;};
const macho=()=>{const b=Buffer.alloc(32);b.writeUInt32LE(0xfeedfacf);b.writeUInt32LE(0x0100000c,4);b.writeUInt32LE(6,12);return b;};
async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-jni-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(path.join(input,'classes'),{recursive:true});await mkdir(path.join(input,'lib'));
 await writeFile(path.join(input,'classes/Sample.class'),sampleClass);await writeFile(path.join(input,'classes/Sample$Inner.class'),innerClass);await writeFile(path.join(input,'classes.dex'),sampleDex);
 for(const name of ['libsample.so','libother.so','libloader.so','libpartial.so','libunindexed.so'])await writeFile(path.join(input,'lib',name),Buffer.concat([elf(),Buffer.from(name)]));
 await writeFile(path.join(input,'lib/libsample.dylib'),Buffer.concat([macho(),Buffer.from('dylib')]));await writeFile(path.join(input,'notes.txt'),'not code');
 await survey(input,{workspace});const rows=(await queryIndex(workspace,{limit:100})).items;const db=openIndex(workspace);linkageTables(db);db.close();
 // Stand-in loader export pages in the shape Ghidra linkage export writes.
 const exports=(file,names,{format='elf',complete=true}={})=>{
  const source=rows.find(r=>r.path===file);const db=openIndex(workspace);
  try{names.forEach((name,i)=>saveLinkage(db,digest(JSON.stringify({file,name})),file,source.sha256,'profile1','AARCH64',format,{kind:'native-export',name,address:(0x1000+i).toString(16)}));
   saveLinkagePage(db,file,source.sha256,'profile1','exports',{linkageKind:'exports',offset:0,records:names.length,...(complete?{}:{nextOffset:names.length})});}finally{db.close();}
 };
 return{root,input,workspace,exports};
}
const all=['classes/Sample.class','classes/Sample$Inner.class','classes.dex'];

test('declarations match exact ELF and underscore Mach-O exports with coverage, overload and dynamic-registration limits',async t=>{
 const f=await fixture(t);
 f.exports('lib/libsample.so',['Java_carve_jni_1fixture_Sample_add','Java_carve_jni_1fixture_Sample_over__I','_Java_carve_jni_1fixture_Sample_handle','Java_carve_jni_1fixture_Sample_00024Inner_inner']);
 f.exports('lib/libsample.dylib',['_Java_carve_jni_1fixture_Sample_add'],{format:'mach-o'});
 f.exports('lib/libloader.so',['JNI_OnLoad']);
 const result=await inspectJni(f.workspace,{files:all,limit:100,budgetBytes:65536});
 assert.equal(result.status,'declarations-matched-to-indexed-exports');assert.equal(result.total,12);assert.equal(result.sources.length,3);
 const of=(file,method)=>result.items.filter(i=>i.file===file&&i.method===method);
 const add=of('classes/Sample.class','add')[0];assert.equal(add.status,'multiple-library-candidates');assert.deepEqual(add.candidates.map(c=>[c.file,c.form]).sort(),[['lib/libsample.dylib','short'],['lib/libsample.so','short']]);
 const handle=of('classes/Sample.class','handle')[0];assert.equal(handle.status,'no-indexed-static-export','an ELF symbol with a leading underscore is not a JNI name');assert.deepEqual(handle.dynamicRegistrationLeads,['lib/libloader.so']);
 const [overInt,overString]=['(I)V','(Ljava/lang/String;)V'].map(d=>of('classes/Sample.class','over').find(i=>i.descriptor===d));
 assert.equal(overInt.status,'static-export-candidate');assert.equal(overInt.candidates[0].form,'long');assert.match(overInt.note,/Overloaded/);assert.equal(overString.status,'no-indexed-static-export');
 assert.equal(of('classes/Sample$Inner.class','inner')[0].status,'static-export-candidate');
 assert.deepEqual(result.items.filter(i=>i.file==='classes.dex').map(i=>i.status).sort(),result.items.filter(i=>i.file!=='classes.dex').map(i=>i.status).sort(),'DEX and class declarations resolve alike');
 assert.equal(result.libraries.allSelectedExportsKnownComplete,true);assert.equal(result.libraries.nativeArtifactsWithoutExportIndex,3);
 assert.deepEqual(result.libraries.indexedExports.find(l=>l.file==='lib/libloader.so').jniOnLoad.map(e=>e.name),['JNI_OnLoad']);
 assert.equal(result.counts.declarations,12);assert.ok(result.receipt.responseBytes<=65536);
 const evidence=JSON.parse(await readFile(result.sources[0].evidence,'utf8'));assert.equal(evidence.schema,'carve/jni-declarations-evidence@1');assert.equal(evidence.metadata.natives.length,5);
 const again=await inspectJni(f.workspace,{files:all,limit:1});assert.equal(again.sources[0].observationId,result.sources[0].observationId,'identical declarations reuse immutable evidence');assert.equal(again.nextOffset,1);
 const db=openIndex(f.workspace,true);try{assert.equal(db.prepare("SELECT count(*) n FROM observations WHERE kind='jni-declarations'").get().n,3);}finally{db.close();}
});

test('library selection, incomplete pages and complete indexes keep missing matches explicit',async t=>{
 const f=await fixture(t);
 f.exports('lib/libpartial.so',['Java_carve_jni_1fixture_Sample_add'],{complete:false});f.exports('lib/libother.so',['unrelated']);
 const partial=await inspectJni(f.workspace,{files:['classes/Sample.class'],libraries:['lib/libpartial.so','lib/libunindexed.so'],limit:100});
 assert.deepEqual(partial.libraries.requestedWithoutExportIndex,['lib/libunindexed.so']);assert.equal(partial.libraries.allSelectedExportsKnownComplete,false);
 assert.equal(partial.libraries.indexedExports[0].exportsKnownComplete,false);assert.ok(partial.libraries.indexedExports[0].nextCursor);
 assert.equal(partial.items.find(i=>i.method==='add').status,'static-export-candidate');assert.ok(partial.items.filter(i=>i.method!=='add').every(i=>i.status==='no-indexed-static-export'));
 const complete=await inspectJni(f.workspace,{files:['classes/Sample.class'],libraries:['lib/libother.so'],query:'handle'});
 assert.equal(complete.total,1);assert.equal(complete.items[0].status,'no-static-export-in-complete-index');assert.equal(complete.items[0].dynamicRegistrationLeads,undefined);
 const none=await inspectJni(f.workspace,{files:['classes.dex'],libraries:['lib/libsample.dylib']});assert.deepEqual(none.libraries.requestedWithoutExportIndex,['lib/libsample.dylib']);assert.equal(none.libraries.allSelectedExportsKnownComplete,false);
});

test('JNI inspection rejects unsupported, changed or invalid selections before recording evidence',async t=>{
 const f=await fixture(t);
 await assert.rejects(()=>inspectJni(f.workspace,{files:['notes.txt']}),/choose an unpacked Java class or DEX/);
 await assert.rejects(()=>inspectJni(f.workspace,{files:[]}),/1–500/);await assert.rejects(()=>inspectJni(f.workspace,{files:['classes.dex','classes.dex']}),/distinct/);
 await assert.rejects(()=>inspectJni(f.workspace,{files:['classes.dex'],limit:0}),/limit/);
 await writeFile(path.join(f.input,'classes.dex'),Buffer.concat([sampleDex,Buffer.from([0])]));await assert.rejects(()=>inspectJni(f.workspace,{files:['classes.dex']}),/changed since inventory/);
 const db=openIndex(f.workspace,true);try{assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='observations'").get(),undefined);}finally{db.close();}
});

test('carve_jni and the jni CLI expose the same bounded result',async t=>{
 const f=await fixture(t);f.exports('lib/libsample.so',['Java_carve_jni_1fixture_Sample_add']);
 const client=new Client({name:'jni-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const reply=await client.callTool({name:'carve_jni',arguments:{workspace:'work',files:['classes/Sample.class'],query:'add'}});assert.equal(reply.isError,undefined,reply.content[0].text);
 const viaMcp=JSON.parse(reply.content[0].text);assert.equal(viaMcp.items[0].status,'static-export-candidate');
 const {execFile}=await import('node:child_process');const {promisify}=await import('node:util');
 const {stdout}=await promisify(execFile)(process.execPath,[cli,'jni',f.workspace,'--file','classes/Sample.class','--query','add']);
 const viaCli=JSON.parse(stdout);assert.deepEqual(viaCli.items,viaMcp.items);assert.equal(viaCli.sources[0].observationId,viaMcp.sources[0].observationId);
});
