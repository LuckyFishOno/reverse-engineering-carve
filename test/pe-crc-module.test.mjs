import test from 'node:test';
import assert from 'node:assert/strict';
import {crcUpdate} from '../examples/pe-crc/implementation.mjs';
const standard=Array.from({length:256},(_,index)=>{
 let state=index;for(let bit=0;bit<8;bit++)state=((state>>>1)^((state&1)?0xedb88320:0))>>>0;return state;
});
test('reviewed CRC module matches the standard check vector and preserves caller incremental state',()=>{
 const bytes=Array.from(Buffer.from('123456789'));
 assert.equal((crcUpdate(0xffffffff,bytes,standard)^0xffffffff)>>>0,0xcbf43926);
 const first=crcUpdate(0xffffffff,bytes.slice(0,4),standard);
 assert.equal(crcUpdate(first,bytes.slice(4),standard),0x340bc6d9);
 for(const state of [0,0x80000000,0xffffffff])assert.equal(crcUpdate(state,[],standard),state);
});
test('reviewed CRC module uses the supplied table and retains unsigned high-bit results',()=>{
 const table=Array(256).fill(0);table[255]=0x80000000;
 assert.equal(crcUpdate(0,[255],table),0x80000000);
 assert.equal(crcUpdate(0x80000000,[0],table),0x800000);
 assert.notEqual(crcUpdate(0,[255],table),crcUpdate(0,[255],standard));
 assert.equal(crcUpdate(0,Array(4096).fill(0),table),0);
});
test('reviewed CRC module rejects invalid domains and sparse caller arrays',()=>{
 for(const state of [-1,2**32,1.5,true,NaN])assert.throws(()=>crcUpdate(state,[],standard),/uint32/);
 for(const bytes of [[-1],[256],[0.5],Array(1),Array(4097).fill(0)])assert.throws(()=>crcUpdate(0,bytes,standard),/bytes/);
 for(const table of [[],Array(256),Array(256).fill(-1),Array(256).fill(2**32)])assert.throws(()=>crcUpdate(0,[],table),/256/);
});
