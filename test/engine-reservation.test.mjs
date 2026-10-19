import test from 'node:test';
import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,rm,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {defaultReservationDirectory} from '../dist/engine-reservation.js';
import {hostEngineLimits} from '../dist/engine-resources.js';
const dist=fileURLToPath(new URL('../dist/',import.meta.url));

// Each child is a separate Carve process with its own TMPDIR, like an MCP host and an agent sandbox
// started by the same user. It reserves (or lists) and holds until told to release.
const child=`import {reserveEngineHeap,listEngineReservations} from ${JSON.stringify('file://'+dist+'engine-reservation.js')};
import {resolveEngineResources} from ${JSON.stringify('file://'+dist+'engine-resources.js')};
let held;process.on('message',async m=>{
 try{
  if(m.list){const listed=await listEngineReservations();process.send({ok:true,registry:listed.registry,ids:listed.items.map(i=>i.id)});return;}
  if(m.reserve){held=await reserveEngineHeap(resolveEngineResources({heapMiB:m.reserve}),{engine:'reservation-test',workspace:process.cwd()});process.send({ok:true,id:held.id,registry:held.registry,others:held.reservedByOthersMiB,reclaimed:held.reclaimedStale});return;}
  if(m.release){held?.release();process.send({ok:true});process.disconnect();}
 }catch(error){process.send({ok:false,error:error.message});}
});
process.send({ready:true});`;
async function harness(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-reservation-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const script=path.join(root,'child.mjs');await writeFile(script,child);const children=[];
 t.after(()=>{for(const c of children)if(c.exitCode===null&&c.signalCode===null)c.kill('SIGKILL');});
 const start=async(name,env={})=>{
  const tmp=path.join(root,name+'-tmp');await mkdir(tmp);const vars={...process.env,TMPDIR:tmp,...env};if(!('CARVE_ENGINE_RESERVATIONS' in env))delete vars.CARVE_ENGINE_RESERVATIONS;
  const c=fork(script,[],{env:vars,stdio:['ignore','ignore','pipe','ipc']});children.push(c);
  await new Promise((resolve,reject)=>{c.once('message',resolve);c.once('error',reject);});
  const ask=message=>new Promise(resolve=>{c.once('message',resolve);c.send(message);});
  return{process:c,tmp,ask};
 };
 return{root,start};
}

test('processes with different TMPDIR values share the default per-user heap registry',async t=>{
 const h=await harness(t);const first=await h.start('first'),second=await h.start('second');
 const held=await first.ask({reserve:256});assert.equal(held.ok,true,held.error);
 assert.equal(held.registry,path.join(await realpath(defaultReservationDirectory()),'heap.sqlite'));
 for(const tmp of [first.tmp,second.tmp])assert.ok(!held.registry.startsWith(await realpath(tmp)),'registry must not live under a per-process TMPDIR');
 const listed=await second.ask({list:true});assert.equal(listed.ok,true,listed.error);assert.equal(listed.registry,held.registry);assert.ok(listed.ids.includes(held.id));
 const also=await second.ask({reserve:256});assert.equal(also.ok,true,also.error);assert.equal(also.registry,held.registry);assert.ok(also.others>=256,'the first process reservation must be counted');
 assert.equal((await second.ask({release:true})).ok,true);assert.equal((await first.ask({release:true})).ok,true);
});

test('a second process is refused when the shared registry is full, and a killed owner is reclaimed',async t=>{
 const h=await harness(t);const registry=path.join(h.root,'registry');const env={CARVE_ENGINE_RESERVATIONS:registry};
 const limit=hostEngineLimits().heapLimitMiB;const first=await h.start('full',env),second=await h.start('refused',env);
 const held=await first.ask({reserve:limit});assert.equal(held.ok,true,held.error);
 const refused=await second.ask({reserve:256});assert.equal(refused.ok,false);assert.match(refused.error,new RegExp(`Engine heap budget busy: ${limit} MiB`));
 const exited=new Promise(resolve=>first.process.once('exit',resolve));first.process.kill('SIGKILL');await exited;
 const after=await second.ask({reserve:256});assert.equal(after.ok,true,after.error);assert.equal(after.others,0);assert.equal(after.reclaimed,1);
 assert.equal((await second.ask({release:true})).ok,true);
});
