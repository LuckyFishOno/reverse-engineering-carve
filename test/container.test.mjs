import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {crc32} from 'node:zlib';
import {mkdtemp,writeFile,readFile,rm,lstat} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {unpackContainer,memberPath} from '../dist/container.js';
import {survey,queryIndex,indexedFile} from '../dist/survey.js';

// Minimal stored ZIP generator for malformed-path/CRC fixtures; no external process.
function zip(entries){
 const locals=[],central=[];let offset=0;
 for(const e of entries){const name=Buffer.from(e.name);const data=Buffer.from(e.data??'');const checksum=e.crc??crc32(data);const flags=e.flags??0;const stored=flags&1?Buffer.concat([Buffer.alloc(12),data]):data;
  const head=Buffer.alloc(30);head.writeUInt32LE(0x04034b50);head.writeUInt16LE(20,4);head.writeUInt16LE(flags,6);head.writeUInt32LE(checksum,14);head.writeUInt32LE(stored.length,18);head.writeUInt32LE(data.length,22);head.writeUInt16LE(name.length,26);
  const c=Buffer.alloc(46);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(3*256+20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(flags,8);c.writeUInt32LE(checksum,16);c.writeUInt32LE(stored.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(((e.mode??0o100644)<<16)>>>0,38);c.writeUInt32LE(offset,42);
  locals.push(head,name,stored);central.push(c,name);offset+=head.length+name.length+stored.length;
 }
 const directory=Buffer.concat(central);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);return Buffer.concat([...locals,directory,end]);
}
async function fixture(t,entries){const root=await mkdtemp(path.join(tmpdir(),'carve-container-'));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'app.ipa');await writeFile(input,zip(entries));const workspace=path.join(root,'work');await survey(input,{workspace});return{root,input,workspace};}
test('ZIP-family batches resume with exact member hashes and preserve container/member lineage',async t=>{
 const f=await fixture(t,[{name:'Payload/Test.app/main',data:'dex\n035\0owned fixture'},{name:'resource.txt',data:'text'},{name:'empty',data:''}]);
 let result=await unpackContainer(f.workspace,{file:'app.ipa',maxFiles:1});assert.equal(result.status,'unpacking');assert.equal(result.files,1);
 result=await unpackContainer(f.workspace,{file:'app.ipa',maxFiles:1});assert.equal(result.files,2);assert.equal(result.batch.cached,1);
 result=await unpackContainer(f.workspace,{file:'app.ipa',maxFiles:1});assert.equal(result.files,3);
 result=await unpackContainer(f.workspace,{file:'app.ipa',maxFiles:1});assert.equal(result.status,'unpacked');assert.equal(result.batch.processed,0);
 assert.equal(await readFile(path.join(result.content,'resource.txt'),'utf8'),'text');assert.equal((await lstat(path.join(result.content,'Payload/Test.app/main'))).mode&0o111,0);
 const inner=path.join(f.root,'inner-work');await survey(result.content,{workspace:inner});const selected=await indexedFile(inner,'Payload/Test.app/main');assert.equal(selected.facts.format,'dex');assert.equal(selected.container.sha256,result.original.sha256);assert.equal(selected.container.memberSha256,selected.sha256);
 // Simulate interruption after an output link, before its DB row was committed.
 const db=new DatabaseSync(result.memberIndex);db.prepare("DELETE FROM members WHERE path='empty'").run();db.close();result=await unpackContainer(f.workspace,{file:'app.ipa'});assert.equal(result.files,3);
 await writeFile(path.join(result.content,'resource.txt'),'changed');await assert.rejects(()=>unpackContainer(f.workspace,{file:'app.ipa'}),/member bytes changed/);
 await survey(result.content,{workspace:inner,refresh:true});await assert.rejects(()=>indexedFile(inner,'resource.txt'),/container extraction/);
});
test('unsafe paths, duplicate members, symlinks, encryption and bad CRC are refused',async t=>{
 for(const name of ['../escape','/absolute','C:/drive','a\\b','a//b','a/./b','a/../b','a\0b'])assert.throws(()=>memberPath(name),/Unsafe/);
 const cases=[{entries:[{name:'../escape',data:'x'}],pattern:/invalid relative path|Unsafe/},
  {entries:[{name:'link',data:'../elsewhere',mode:0o120777}],pattern:/symlinks/},
  {entries:[{name:'secret',data:'x',flags:1}],pattern:/Encrypted/},
  {entries:[{name:'duplicate',data:'one'},{name:'duplicate',data:'two'}],pattern:/Duplicate/},
  ...(process.platform==='darwin'?[{entries:[{name:'CASE',data:'same'},{name:'case',data:'same'}],pattern:/collide/}]:[]),
  {entries:[{name:'bad-checksum',data:'value',crc:1}],pattern:/CRC32/}];
 for(const item of cases){const f=await fixture(t,item.entries);await assert.rejects(()=>unpackContainer(f.workspace,{file:'app.ipa'}),item.pattern);}
});
test('file/total/entry budgets fail explicitly and completed batches can continue after raising a budget',async t=>{
 const f=await fixture(t,[{name:'one',data:'123'},{name:'two',data:'4567'}]);
 await assert.rejects(()=>unpackContainer(f.workspace,{file:'app.ipa',maxFileBytes:2}),/byte budgets/);
 await assert.rejects(()=>unpackContainer(f.workspace,{file:'app.ipa',maxEntries:1}),/maxEntries/);
 const result=await unpackContainer(f.workspace,{file:'app.ipa',maxEntries:2});assert.equal(result.status,'unpacked');assert.equal(result.files,2);assert.equal(result.batch.cached,1);
 await assert.rejects(()=>unpackContainer(f.workspace,{file:'app.ipa',maxBytes:2}),/input exceeds/);
});
