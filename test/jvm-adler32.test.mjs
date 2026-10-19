import test from 'node:test';
import assert from 'node:assert/strict';
import {adler32} from '../examples/jvm/adler32.mjs';
// Published Adler-32 vectors (RFC 1950 definition; "Wikipedia" example) and block-reduction edges.
test('independent Adler-32 matches known vectors and reduces at the 5552-byte block edge',()=>{
 assert.equal(adler32([]),1);assert.equal(adler32([...Buffer.from('abc')]),0x024d0127);assert.equal(adler32([...Buffer.from('Wikipedia')]),0x11e60398);
 // Direct modular definition, independent of the block loop.
 const reference=bytes=>{let a=1,b=0;for(const x of bytes){a=(a+x)%65521;b=(b+a)%65521;}return b*65536+a;};
 for(const n of [5551,5552,5553,11104,11105])for(const fill of [0,1,255])assert.equal(adler32(Array(n).fill(fill)),reference(Array(n).fill(fill)),`${n}×${fill}`);
 assert.ok(adler32(Array(5553).fill(255))>2**31,'unsigned 32-bit result, not a signed int');
});
test('Adler-32 reconstruction rejects values outside its documented domain',()=>{
 for(const bad of [null,'abc',[256],[-1],[1.5],[Number.NaN]])assert.throws(()=>adler32(bad),TypeError);
 assert.throws(()=>adler32({length:1048577}),TypeError);
});
