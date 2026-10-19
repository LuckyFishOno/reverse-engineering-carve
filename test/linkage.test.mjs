import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import path from 'node:path';
import {survey,openIndex,queryIndex} from '../dist/survey.js';import {digest} from '../dist/artifact.js';
import {linkageTables,saveLinkage,saveLinkagePage,linkageCoverage,linkageCursor,linkageOffset,queryLinks} from '../dist/linkage.js';
async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),'carve-links-'));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);for(const f of ['program','libcharge.dylib','decoy.dylib','otherarch','otherformat'])await writeFile(path.join(input,f),f);await survey(input,{workspace});const rows=(await queryIndex(workspace)).items;const db=openIndex(workspace);linkageTables(db);db.close();return{input,workspace,rows};}
function record(f,file,{kind='exports',name='_charge',library,profile='profile1',language='AARCH64',format='mach-o'}={}){const source=f.rows.find(r=>r.path===file);const db=openIndex(f.workspace);const id=digest(JSON.stringify({file,kind,name,profile}));saveLinkage(db,id,file,source.sha256,profile,language,format,{kind:({'imports':'native-import','exports':'native-export','libraries':'native-library'})[kind],name,library,address:'1000'});saveLinkagePage(db,file,source.sha256,profile,kind,{linkageKind:kind,offset:0,records:1});db.close();return id;}
test('current metadata pages expose bounded ambiguous candidates and explicit basename hints without resolving linkage',async t=>{
 const f=await fixture(t);assert.equal((await queryLinks(f.workspace)).total,0);const id=record(f,'program',{kind:'imports',library:'@rpath/libcharge.dylib'});record(f,'libcharge.dylib');record(f,'decoy.dylib');record(f,'otherarch',{language:'x86'});record(f,'otherformat',{format:'elf'});
 const first=await queryLinks(f.workspace,{from:id,limit:1});assert.equal(first.total,2);assert.equal(first.nextOffset,1);assert.equal(first.items[0].semanticMatch,'unconfirmed');assert.equal(first.items[0].freshBytesChecked,false);assert.equal(first.items[0].pageCoverage.knownComplete,true);
 const all=await queryLinks(f.workspace,{from:id});assert.equal(all.items.find(r=>r.file==='libcharge.dylib').libraryBasenameHint,true);assert.equal(all.items.find(r=>r.file==='decoy.dylib').libraryBasenameHint,false);assert.ok(all.items.every(r=>r.runtimeLoading==='unverified'));
 const list=await queryLinks(f.workspace,{kind:'imports',query:'@rpath/'});assert.equal(list.items[0].id,id);assert.equal((await queryLinks(f.workspace,{kind:'imports',query:'%'})).total,0);
});
test('leading underscore matching is explicit and stale source/profile records never enter current candidates',async t=>{
 const f=await fixture(t);const id=record(f,'program',{kind:'imports',name:'charge',library:'@rpath/libcharge.dylib'});record(f,'libcharge.dylib');assert.equal((await queryLinks(f.workspace,{from:id})).total,0);assert.equal((await queryLinks(f.workspace,{from:id,symbolMatch:'leading-underscore'})).total,1);
 record(f,'libcharge.dylib',{name:'different',profile:'profile2'});assert.equal((await queryLinks(f.workspace,{from:id,symbolMatch:'leading-underscore'})).total,0);
 await writeFile(path.join(f.input,'program'),'changed source');await survey(f.input,{workspace:f.workspace,refresh:true});await assert.rejects(()=>queryLinks(f.workspace,{from:id}),/no longer matches/);assert.equal((await queryLinks(f.workspace,{kind:'imports'})).total,0);
});
test('coverage detects gaps and overlapping pages and returns a source/profile-bound continuation',async t=>{
 const f=await fixture(t);const source=f.rows[0],db=openIndex(f.workspace),identity={file:source.path,sha256:source.sha256,profile:'p',kind:'imports'},item={artifact:source.path,sha256:source.sha256,profile:'p',kind:'imports'};
 const page=(offset,records,nextOffset)=>saveLinkagePage(db,source.path,source.sha256,'p','imports',{linkageKind:'imports',offset,records,...(nextOffset!==undefined?{nextOffset}:{})});
 page(0,2,2);page(4,1);let c=linkageCoverage(db,item);assert.equal(c.knownComplete,false);assert.equal(c.coveredFromStart,2);assert.equal(linkageOffset(c.nextCursor,identity),2);
 page(1,3,4);c=linkageCoverage(db,item);assert.equal(c.knownComplete,true);assert.equal(c.coveredFromStart,5);assert.equal(c.nextCursor,null);db.close();
});
test('opaque metadata cursors reject source, scope, profile and malformed offsets before an engine runs',()=>{
 const identity={file:'bin/app',sha256:'sha',profile:'profile',kind:'imports'},cursor=linkageCursor(identity,20);assert.equal(linkageOffset(cursor,identity),20);assert.equal(linkageOffset(undefined,identity),0);
 for(const key of ['file','sha256','profile','kind'])assert.throws(()=>linkageOffset(cursor,{...identity,[key]:'changed'}),/does not match/);
 for(const c of ['1000','!',linkageCursor(identity,-1),linkageCursor(identity,1000000001)])assert.throws(()=>linkageOffset(c,identity),/does not match/);
});
test('link queries reject conflicting modes, invalid IDs and unbounded requests',async t=>{
 const f=await fixture(t);for(const opts of [{limit:101},{offset:-1},{kind:'unknown'},{from:'not-an-id'},{symbolMatch:'leading-underscore'},{from:digest('x'),file:'program'},{query:'x'.repeat(1001)}])await assert.rejects(()=>queryLinks(f.workspace,opts));
});
