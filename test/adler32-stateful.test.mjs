import test from 'node:test';
import assert from 'node:assert/strict';
import {adler32Step as step} from '../examples/jvm/adler32-stateful.mjs';
import {extract} from '../dist/extract.js';
import {invokeSequence} from '../dist/runtime.js';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
const bytes=s=>[...Buffer.from(s)];
test('incremental Adler32 preserves observed initialization, chunks, empty updates, reads and reset',()=>{
 assert.equal(step(2),1);assert.equal(step(0),1);assert.equal(step(1,bytes('Wiki')),64618901);assert.equal(step(1,[]),64618901);assert.equal(step(1,bytes('pedia')),300286872);assert.equal(step(0),300286872);assert.equal(step(2),1);assert.equal(step(1,bytes('abc')),38600999);assert.equal(step(2),1);assert.equal(step(2),1);
});
test('invalid Carve wrapper inputs are rejected without partially changing existing state',()=>{
 step(2);step(1,bytes('abc'));for(const args of [[3],[0,[]],[2,null],[1],[1,[1,256]],[1,Array(65537).fill(0)],[1,[NaN]],[1,Array(2)],[1,[null]],[1,[-1]]]){assert.throws(()=>step(...args),TypeError);assert.equal(step(0),38600999);}step(2);
});
test('extracted Adler32 folder runs ordered chunks and starts from its initial state on the next request',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-adler32-sequence-'));t.after(()=>rm(root,{recursive:true,force:true}));await extract(path.resolve('examples/jvm/adler32-stateful.mjs'),{selector:{kind:'export',name:'adler32Step'},out:root+'/tool'});
 const calls=[[0],[1,bytes('Wiki')],[1,bytes('pedia')],[0],[2],[0]],expected=[1,64618901,300286872,300286872,1,1].map(value=>({kind:'return',value}));
 for(let i=0;i<2;i++)assert.deepEqual(await invokeSequence(root+'/tool',calls,{execute:true}),{kind:'return',value:expected});
});
