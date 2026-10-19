import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,rename,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {extract} from '../dist/extract.js';
import {invoke,packageUsage} from '../dist/runtime.js';
import {digest} from '../dist/artifact.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
async function fixture(t,code='export const format=x=>x*2;'){
 const root=await mkdtemp(path.join(tmpdir(),'carve-runtime-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'app.mjs');await writeFile(input,code);const out=path.join(root,'tool');
 await extract(input,{selector:{kind:'export',name:'format'},out});return {root,input,out};
}
async function replaceEntry(out,code){
 await writeFile(path.join(out,'index.mjs'),code);const manifest=JSON.parse(await readFile(path.join(out,'carve.manifest.json'),'utf8'));
 const file=manifest.output.files.find(f=>f.file==='index.mjs');file.sha256=digest(code);file.bytes=Buffer.byteLength(code);
 await writeFile(path.join(out,'carve.manifest.json'),JSON.stringify(manifest));
}
test('invocation works after deleting the original and rejects unauthorized or changed packages',async t=>{
 const {input,out}=await fixture(t);await rm(input);
 assert.deepEqual(await invoke(out,[21],{execute:true}),{kind:'return',value:42});
 await assert.rejects(()=>invoke(out,[21],{execute:false}),/--execute/);
 await writeFile(path.join(out,'index.mjs'),'export const capability=x=>x*3;');
 await assert.rejects(()=>invoke(out,[21],{execute:true}),/Package changed/);
 await assert.rejects(()=>packageUsage(out),/Package changed/);
});
test('execution deadlines, cancellation and bounded output produce explicit failures',async t=>{
 const {out}=await fixture(t,'export function format(){while(true){}}');
 assert.match((await invoke(out,[],{execute:true,timeoutMs:100})).detail,/timed out/);
 const controller=new AbortController();const pending=invoke(out,[],{execute:true,timeoutMs:3000,signal:controller.signal});setTimeout(()=>controller.abort(),100);
 assert.match((await pending).detail,/cancelled/);
 await replaceEntry(out,'export const capability=()=>"x".repeat(2*1024*1024);');
 assert.match((await invoke(out,[],{execute:true})).detail,/exceeded 1 MiB/);
});
test('restricted calls cannot read the original file even with an intentionally rehashed package',async t=>{
 const {input,out}=await fixture(t);
 await replaceEntry(out,`import {readFileSync} from 'node:fs';export const capability=()=>readFileSync(${JSON.stringify(input)},'utf8');`);
 const outcome=await invoke(out,[],{execute:true});assert.equal(outcome.kind,'throw');assert.match(outcome.error.message,/denied|restricted|permission/i);
});
test('package files cannot be replaced by a same-byte symlink',async t=>{
 const {root,out}=await fixture(t);const entry=path.join(out,'index.mjs');const elsewhere=path.join(root,'copied.mjs');await rename(entry,elsewhere);await symlink(elsewhere,entry);
 await assert.rejects(()=>invoke(out,[],{execute:true}),/symlink/);
});
test('actual extracted-capability MCP calls independent output and starts fresh for each call',async t=>{
 const {input,out}=await fixture(t,'let n=0;export function format(){return ++n}');await rm(input);
 const transport=new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('../dist/cli.js',import.meta.url)),'serve-tool',out,'--execute'],stderr:'pipe'});
 const client=new Client({name:'carve-runtime-test',version:'1'});await client.connect(transport);t.after(()=>client.close());
 assert.deepEqual((await client.listTools()).tools.map(t=>t.name),['capability_info','capability','capability_sequence']);
 for(let i=0;i<2;i++) assert.deepEqual((await client.callTool({name:'capability',arguments:{args:[]}})).structuredContent,{value:1});
 const info=await client.callTool({name:'capability_info',arguments:{}});assert.equal(JSON.parse(info.content[0].text).package,await (await import('node:fs/promises')).realpath(out));
 await writeFile(path.join(out,'index.mjs'),'export const capability=()=>99;');
 const changed=await client.callTool({name:'capability',arguments:{args:[]}});assert.equal(changed.isError,true);assert.match(changed.content[0].text,/Package changed/);
});
