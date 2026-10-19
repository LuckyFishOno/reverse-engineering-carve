import assert from 'node:assert/strict';
import test from 'node:test';
import {queryBootstrapCatalog as query} from '../examples/android/termux-bootstrap-catalog.mjs';
const metadata={archiveBytes:7,archiveSha256:'recorded-only',totalEntries:3};
const entries=[{name:'bin/z',bytes:1},{name:'bin/a',bytes:2},{name:'bin-extra',bytes:3}];
test('bootstrap catalog preserves source order and exact prefix with bounded pages',()=>{
 assert.deepEqual(query(metadata,entries,{prefix:'bin/',limit:1}),{...metadata,matchedEntries:2,items:[entries[0]],nextOffset:1});
 assert.deepEqual(query(metadata,entries,{prefix:'bin/',offset:1,limit:100}),{...metadata,matchedEntries:2,items:[entries[1]],nextOffset:null});
 assert.deepEqual(query(metadata,entries,{prefix:'bin/',offset:1000000}),{...metadata,matchedEntries:2,items:[],nextOffset:null});
 assert.deepEqual(query(metadata,entries,{prefix:'\0'}).items,[]);assert.equal(query(metadata,entries).items.length,3);
});
test('bootstrap catalog input domain rejects coercion, unknown keys and invalid paging',()=>{
 for(const value of [null,[],new Date(),Object.create(null),{unexpected:true},{prefix:null},{prefix:'x'.repeat(257)},{offset:-1},{offset:1.5},{offset:1000001},{offset:NaN},{limit:0},{limit:101},{limit:'20'},{limit:Infinity}])assert.throws(()=>query(metadata,entries,value));
});
test('bootstrap catalog outputs cannot poison later direct-import queries',()=>{
 const first=query(metadata,entries);first.items[0].name='changed';first.items.push({name:'injected'});first.archiveBytes=0;
 const next=query(metadata,entries);assert.equal(next.items[0].name,'bin/z');assert.equal(next.items.length,3);assert.equal(next.archiveBytes,7);assert.equal(entries[0].name,'bin/z');
});
