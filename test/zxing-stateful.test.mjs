import test from 'node:test';
import assert from 'node:assert/strict';
const fresh=async tag=>(await import('../examples/android/zxing-bitarray-stateful.mjs?'+tag)).bitArrayStep;
test('BitArray lifecycle preserves size on clear, starts empty on new, and snapshots earlier state',async()=>{
 const step=await fresh('lifecycle');assert.deepEqual(step('read'),{size:0,sizeInBytes:0,bits:''});
 const prior=step('append',5,3);assert.deepEqual(prior,{size:3,sizeInBytes:1,bits:'101'});
 assert.deepEqual(step('clear'),{size:3,sizeInBytes:1,bits:'000'});assert.equal(prior.bits,'101');
 assert.equal(step('append',3,2).bits,'00011');assert.equal(step('reverse').bits,'11000');
 assert.equal(step('flip',4).bits,'11001');assert.equal(step('set',2).bits,'11101');
 assert.deepEqual(step('new'),{size:0,sizeInBytes:0,bits:''});
});
test('BitArray signed32 appends cross word boundaries and new module instances start fresh',async()=>{
 const step=await fresh('words');assert.equal(step('append',-2147483648,32).bits,'1'+'0'.repeat(31));
 assert.equal(step('append',-1,1).bits,'1'+'0'.repeat(31)+'1');assert.equal(step('read').sizeInBytes,5);
 assert.equal(step('reverse').bits,'1'+'0'.repeat(31)+'1');assert.equal((await fresh('other'))('read').size,0);
});
test('BitArray invalid adapter-domain operations do not change prior state',async()=>{
 const step=await fresh('domain');step('append',5,3);const state=step('read');
 for(const args of [[],['unknown'],['read',1],['append',0,33],['append',0,-1],['append',2147483648,1],['append',NaN,1],['set',3],['flip',-1],['new',0]]){
  assert.throws(()=>step(...args),TypeError);assert.deepEqual(step('read'),state);
 }
 for(let i=0;i<127;i++)step('append',-1,32);
 step('append',0,29);assert.equal(step('read').size,4096);
 const full=step('read');assert.throws(()=>step('append',1,1),TypeError);assert.deepEqual(step('read'),full);
});
