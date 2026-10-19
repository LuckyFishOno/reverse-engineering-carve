import test from 'node:test';import assert from 'node:assert/strict';import {tmpdir} from 'node:os';import path from 'node:path';import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {runReference} from '../dist/reference.js';
const echo='process.stdin.pipe(process.stdout)';
const run=(code,mode,args,output='json',timeout=2000,signal)=>runReference([process.execPath,'-e',code],mode,args,tmpdir(),timeout,signal,output);

test('raw bytes input/output preserves empty data, NUL, newlines and every byte without argv coercion',async()=>{
 for(const bytes of [[],[0,10,13,34,127,128,255],Array.from({length:256},(_,i)=>i)])assert.deepEqual(await run(echo,'bytes-stdin',[bytes],'bytes'),{kind:'return',value:bytes});
 assert.deepEqual(await run("process.stdin.resume();process.stdin.on('end',()=>process.stdout.write(String(process.argv.length)))",'bytes-stdin',[[1,2]],'utf8'),{kind:'return',value:'1'});
});
test('UTF8 text output preserves BOM, NUL, whitespace and multibyte characters split across pipe chunks',async()=>{
 const value='\ufeff\u6f22\u5b57😀\u0000\r\n ';
 const code="const chunks=[];process.stdin.on('data',x=>chunks.push(x));process.stdin.on('end',()=>{const b=Buffer.concat(chunks);process.stdout.write(b.subarray(0,5));setTimeout(()=>process.stdout.end(b.subarray(5)),10)})";
 assert.deepEqual(await run(code,'text-stdin',[value],'utf8'),{kind:'return',value});assert.deepEqual(await run(echo,'text-stdin',[''],'utf8'),{kind:'return',value:''});
 assert.equal((await run(echo,'text-stdin',[''])).kind,'harness-error');
});
test('raw input validation fails before starting a process and never silently drops extra arguments',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-reference-input-'));t.after(()=>rm(root,{recursive:true,force:true}));const marker=path.join(root,'ran');const code="require('node:fs').writeFileSync(process.argv[1],'ran')";
 const invalid=[['bytes-stdin',[]],['bytes-stdin',[[],123]],['bytes-stdin',['0']],['bytes-stdin',[[1.5]]],['bytes-stdin',[[-1]]],['bytes-stdin',[[256]]],['bytes-stdin',[[NaN]]],['bytes-stdin',[[,]]],['bytes-stdin',[Array(1048577).fill(0)]],['text-stdin',[1]],['text-stdin',['ok','extra']],['text-stdin',['\ud800']],['text-stdin',['\u6f22'.repeat(400000)]],['argv-values',['nul\u0000argv']],['argv-values',[Infinity]],['unknown',[]]];
 for(const [mode,args]of invalid){const r=await runReference([process.execPath,'-e',code,marker],mode,args,root,2000,undefined,'utf8');assert.equal(r.kind,'harness-error',mode);}
 await assert.rejects(()=>readFile(marker),/ENOENT/);
 const badOutput=await run(echo,'bytes-stdin',[[65]],'unknown');assert.equal(badOutput.kind,'harness-error');
});
test('invalid UTF8 cannot pass as replacement text or JSON while explicit byte output remains lossless',async()=>{
 const raw="process.stdout.write(Buffer.from([34,255,34]))";assert.equal((await run(raw,'argv-values',[],'utf8')).kind,'harness-error');assert.equal((await run(raw,'argv-values',[],'json')).kind,'harness-error');assert.deepEqual(await run(raw,'argv-values',[],'bytes'),{kind:'return',value:[34,255,34]});
 assert.equal((await run("process.stdout.write('1e999')",'argv-values',[])).kind,'harness-error');assert.deepEqual(await run("process.stdout.write('1e999')",'argv-values',[],'utf8'),{kind:'return',value:'1e999'});
});
test('raw references keep combined output limits, exit failures, deadlines and cancellation',async()=>{
 assert.match((await run("process.stdout.write(Buffer.alloc(1048577))",'text-stdin',[''],'bytes')).detail,/1 MiB/);
 assert.match((await run("process.stderr.write('failure');process.exit(7)",'bytes-stdin',[[]],'utf8')).detail,/exited 7/);
 assert.match((await run('setInterval(()=>{},1000)','bytes-stdin',[[]],'utf8',50)).detail,/timed out/);
 const aborted=new AbortController();aborted.abort();assert.match((await run(echo,'bytes-stdin',[[]],'bytes',1000,aborted.signal)).detail,/cancelled/);
 const active=new AbortController(),pending=run('setInterval(()=>{},1000)','text-stdin',[''],'utf8',2000,active.signal);setTimeout(()=>active.abort(),30);assert.match((await pending).detail,/cancelled/);
});
