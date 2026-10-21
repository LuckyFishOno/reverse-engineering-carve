import test from 'node:test';
import assert from 'node:assert/strict';
import {generateCrcTables,crcDispatch} from '../examples/pe-crc-dispatch/implementation.mjs';
test('portable CRC initialization produces all slicing tables without sharing caller mutations',()=>{
 const first=generateCrcTables(),second=generateCrcTables();assert.equal(first.length,2048);
 assert.equal(first[0],0);assert.equal(first[1],0x77073096);assert.equal(first[255],0x2d02ef8d);
 assert.deepEqual(first,second);first.fill(0);assert.equal(second[1],0x77073096);
});
test('declared CPU selection retains the CRC vector and alignment-independent byte semantics',()=>{
 const bytes=Array.from(Buffer.from('123456789'));
 for(const profile of [0,1])for(let alignment=0;alignment<8;alignment++){
  const expected={value:0x340bc6d9,implementation:profile?'T4':'T8'};assert.deepEqual(crcDispatch(profile,0xffffffff,bytes,alignment),expected);
  const first=crcDispatch(profile,0xffffffff,bytes.slice(0,4),alignment);assert.deepEqual(crcDispatch(profile,first.value,bytes.slice(4),alignment),expected);
  assert.equal(crcDispatch(profile,0x80000000,[],alignment).value,0x80000000);
 }
});
test('portable CRC dispatch rejects undeclared CPU predicates, alignments and input domains',()=>{
 for(const profile of [-1,2,true,'1',NaN])assert.throws(()=>crcDispatch(profile,0,[],0),/CPU predicate/);
 for(const alignment of [-1,8,0.5,undefined])assert.throws(()=>crcDispatch(0,0,[],alignment),/alignment/);
 assert.throws(()=>crcDispatch(0,-1,[],0),/uint32/);assert.throws(()=>crcDispatch(0,0,[256],0),/bytes/);
});
