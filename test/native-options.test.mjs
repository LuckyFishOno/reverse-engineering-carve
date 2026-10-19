import test from 'node:test';
import assert from 'node:assert/strict';
import {nativeAnalysis} from '../dist/native.js';
import {addressKey,windowRange} from '../dist/addresses.js';
test('native inspection modes validate bounds and conflicting selectors before opening a project or executing an engine',async()=>{
 const base={file:'unused',ghidra:'unused',javaHome:'unused'};
 for(const [options,pattern] of [[{function:'f',strings:'x'},/Choose function/],[{function:'f',linkage:'imports'},/Choose function/],[{linkage:'bad'},/Invalid enum/],[{window:'1000',function:'f'},/Choose function/],[{bytes:1},/requires/],[{window:'1000',bytes:4097},/1–4096/],[{window:'1000',after:'1000'},/only for/],[{function:''},/empty/],[{strings:'x'.repeat(1001)},/1000/]])await assert.rejects(()=>nativeAnalysis('never-open-this-directory',{...base,...options}),pattern);
});
test('native window address keys preserve unsigned 64-bit precision and address-space boundaries',()=>{
 const a=addressKey('ram:0xfffffffffffff000');const b=addressKey('ram:fffffffffffff001');assert.ok(a.key<b.key);assert.equal(a.space,'ram');assert.equal(a.offset,0xfffffffffffff000n);
 assert.deepEqual(windowRange('1000',16),{space:'',start:'00000000000000000000000000001000',end:'0000000000000000000000000000100f'});
 assert.throws(()=>windowRange('ffffffffffffffffffffffffffffffff',2),/overflow/);assert.throws(()=>addressKey('invalid address'),/Invalid/);
});
