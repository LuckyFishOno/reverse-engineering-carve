import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:net';
import {mkdtemp,rm,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {androidReferenceSchema,prepareAndroidReference,androidHarnessArguments} from '../dist/android.js';
import {runReference} from '../dist/reference.js';
test('Android reference needs an explicit transport/class and refuses non-DEX or absent servers without starting processes',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-android-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const server=createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;await new Promise(r=>server.close(r));
 const raw={schema:'carve/android-reference@1',adb:process.execPath,serial:'emulator-5580',serverPort:port,harness:'owned.dex',entryClass:'carve.Test',description:'Preflight validation only; no Android is simulated.'};
 const config=androidReferenceSchema.parse(raw);
 const target={path:'unopened-input',sha256:'0'.repeat(64),facts:{format:'dex'}};
 await assert.rejects(()=>prepareAndroidReference(root,target,config),/ADB server is not running/);
 await assert.rejects(()=>access(path.join(root,'verification')));
 await assert.rejects(()=>prepareAndroidReference(root,{...target,facts:{format:'java-class'}},config),/requires DEX/);
 await assert.rejects(()=>prepareAndroidReference(root,target,config,{signal:AbortSignal.abort()}),/cancelled/);
 for(const bad of [{...raw,serial:undefined},{...raw,serverPort:0},{...raw,entryClass:'bad; command'},{...raw,serial:'bad serial'}])assert.equal(androidReferenceSchema.safeParse(bad).success,false);
});
test('reference cancellation terminates a running host command without a success outcome',async()=>{
 const controller=new AbortController();const pending=runReference([process.execPath,'-e','setInterval(()=>{},1000)'],'argv-values',[],tmpdir(),30000,controller.signal);setTimeout(()=>controller.abort(),50);
 const result=await pending;assert.equal(result.kind,'harness-error');assert.match(result.detail,/cancelled/);
});
test('Android structured inputs stay off argv, preserve JSON data and reject unsupported/nonfinite/oversized values',()=>{
 const shared={x:1},json=[{values:[null,true,false,0,'\0😀\ufeff',shared,shared],injection:'$(touch marker);\n\'"'}];assert.deepEqual(androidHarnessArguments(json,'json-stdin'),[]);
 assert.deepEqual(androidHarnessArguments(['a',3,true],'argv-values'),['a','3','true']);
 for(const value of [[undefined],[NaN],[Infinity],[{x:undefined}],[new Date()],[()=>1],[1n],[Array(1)],['x'.repeat(1048576)]])assert.throws(()=>androidHarnessArguments(value,'json-stdin'));
 const cycle=[];cycle.push(cycle);assert.throws(()=>androidHarnessArguments(cycle,'json-stdin'));
 for(const value of [[{}],[null],[NaN],['\0'],Array(1)])assert.throws(()=>androidHarnessArguments(value,'argv-values'));
 const custom=[];custom.toJSON=()=>['substituted'];assert.throws(()=>androidHarnessArguments([custom],'json-stdin'));
 const raw={schema:'carve/android-reference@2',adb:'adb',serial:'emulator-5580',harness:'h.dex',entryClass:'carve.Test',mode:'json-stdin',description:'Structured protocol'};assert.equal(androidReferenceSchema.parse(raw).mode,'json-stdin');assert.equal(androidReferenceSchema.safeParse({...raw,mode:'json-argv'}).success,false);assert.equal(androidReferenceSchema.safeParse({...raw,schema:'carve/android-reference@1'}).success,false);
});

test('Android native references separate named libraries and reject traversal, aliases and old-schema misuse',()=>{
 const raw={schema:'carve/android-reference@3',adb:'adb',serial:'emulator-5580',harness:'h.dex',entryClass:'carve.Test',mode:'json-stdin',description:'Explicit native ELF test',nativeLibraries:[{file:'libnative.so',name:'libnative.so'}]};
 assert.equal(androidReferenceSchema.parse(raw).nativeLibraries[0].name,'libnative.so');
 for(const bad of [{...raw,nativeLibraries:[]},{...raw,nativeLibraries:[...raw.nativeLibraries,...raw.nativeLibraries]},{...raw,nativeLibraries:[{file:'x',name:'../x.so'}]},{...raw,nativeLibraries:[{file:'x',name:'libx.so;touch'}]},{...raw,nativeLibraries:[{file:'x',name:'libx.so',unknown:true}]},{...raw,schema:'carve/android-reference@2'},{...raw,schema:'carve/android-reference@1'}])assert.equal(androidReferenceSchema.safeParse(bad).success,false);
});

test('Android sequence mode is explicit, bounded and keeps nested finite data off argv',()=>{
 const raw={schema:'carve/android-reference@4',adb:'adb',serial:'emulator-5580',harness:'h.dex',entryClass:'carve.Test',mode:'json-sequence-stdin',description:'Sequence preflight only; no device execution.'};
 assert.equal(androidReferenceSchema.parse(raw).mode,'json-sequence-stdin');
 assert.deepEqual(androidHarnessArguments([['append',2147483647,32],['read'],[{text:'\0😀$(touch marker)',nested:[null,true]}]],'json-sequence-stdin'),[]);
 assert.deepEqual(androidHarnessArguments(Array.from({length:64},()=>[]),'json-sequence-stdin'),[]);
 for(const calls of [[],[1],[null],Array.from({length:65},()=>[]),[[undefined]],[[NaN]],[[new Date()]],[[{value:undefined}]],[[1n]],[['x'.repeat(1048576)]]])assert.throws(()=>androidHarnessArguments(calls,'json-sequence-stdin'));
 for(const bad of [{...raw,mode:'json-stdin'},{...raw,mode:'argv-values'},{...raw,schema:'carve/android-reference@3'},{...raw,schema:'carve/android-reference@2'},{...raw,nativeLibraries:[]},{...raw,nativeLibraries:[{file:'a',name:'../a.so'}]}])assert.equal(androidReferenceSchema.safeParse(bad).success,false);
 assert.equal(androidReferenceSchema.parse({...raw,nativeLibraries:[{file:'a',name:'liba.so'}]}).nativeLibraries.length,1);
});

test('Android native ELF preflight rejects executable, foreign ABI, endian and truncated headers',async()=>{
 const {androidNativeElf}=await import('../dist/android.js');
 const elf=Buffer.alloc(64);elf.set([0x7f,0x45,0x4c,0x46,2,1,1]);elf.writeUInt16LE(3,16);elf.writeUInt16LE(183,18);
 assert.equal(androidNativeElf(elf,'arm64-v8a').machine,183);
 for(const abi of ['armeabi-v7a','x86','x86_64','unknown'])assert.throws(()=>androidNativeElf(elf,abi));
 for(const [offset,value] of [[0,0],[4,1],[5,2],[6,0],[16,2]]){const bad=Buffer.from(elf);bad[offset]=value;assert.throws(()=>androidNativeElf(bad,'arm64-v8a'));}
 assert.throws(()=>androidNativeElf(elf.subarray(0,20),'arm64-v8a'));
 for(const [abi,klass,machine] of [['armeabi-v7a',1,40],['x86',1,3],['x86_64',2,62]]){const good=Buffer.from(elf);good[4]=klass;good.writeUInt16LE(machine,18);assert.equal(androidNativeElf(good,abi).abi,abi);}
});
