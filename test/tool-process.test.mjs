import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {runTool} from '../dist/tool-process.js';
import {processIsLive,processGroupMembers} from '../dist/process-lease.js';
test('engine processes retain diagnostics, enforce deadlines/log budgets and honor cancellation',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-engine-test-'));t.after(()=>rm(root,{recursive:true,force:true}));let number=0;
 const run=(code,extra={})=>runTool(process.execPath,['-e',code],{cwd:root,env:{PATH:process.env.PATH},log:path.join(root,`${number++}.log`),timeoutMs:2000,...extra});
 const result=await run('console.log("actual process");console.error("diagnostic");process.exit(7)');assert.equal(result.exitCode,7);assert.match(result.diagnostic,/diagnostic/);assert.match(await readFile(path.join(root,'0.log'),'utf8'),/actual process/);
 await assert.rejects(()=>run('setInterval(()=>{},1000)',{timeoutMs:50}),/exceeded/);
 await assert.rejects(()=>run('console.log("x".repeat(10000))',{maxLogBytes:1000}),/byte budget/);
 const controller=new AbortController();const pending=run('setInterval(()=>{},1000)',{signal:controller.signal});setTimeout(()=>controller.abort(),50);await assert.rejects(()=>pending,/cancelled/);
 await assert.rejects(()=>run('console.log(1)',{signal:AbortSignal.abort()}),/cancelled/);
});
test('concurrent cancellation at different startup phases leaves no registered supervisor or engine group',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-engine-race-'));t.after(()=>rm(root,{recursive:true,force:true}));
 for(let round=0;round<4;round++)await Promise.all([15,45,80,130].map(async(delay,index)=>{
  const controller=new AbortController();let guard;const timer=setTimeout(()=>controller.abort(),delay);
  try{await assert.rejects(()=>runTool(process.execPath,['-e','setInterval(()=>{},1000)'],{cwd:root,env:{PATH:process.env.PATH},log:path.join(root,`${round}-${index}.log`),timeoutMs:5000,signal:controller.signal,onProcess:p=>{guard=p;}}),/cancelled/);}
  finally{clearTimeout(timer);}
  if(guard){assert.equal(await processIsLive(guard.supervisor),false);assert.deepEqual(await processGroupMembers(guard.processGroup),[]);}
 }));
});
