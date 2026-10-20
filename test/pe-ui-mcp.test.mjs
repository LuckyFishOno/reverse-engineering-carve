import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,writeFile,rm,symlink,mkdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey} from '../dist/survey.js';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
async function setup(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ui-protocol-')));t.after(()=>rm(root,{recursive:true,force:true}));const file=path.join(root,'ui.exe'),bytes=buildUiPe({plus:true,extended:true}).bytes;await writeFile(file,bytes);const workspace=path.join(root,'work');await survey(file,{workspace});return{root,file,workspace};}
async function connect(t,root){const client=new Client({name:'pe-ui-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));t.after(()=>client.close());return client;}
const call=(client,options={})=>client.callTool({name:'carve_pe_ui',arguments:{workspace:'work',file:'ui.exe',...options}});
function value(reply){assert.ok(!reply.isError,reply.content[0].text);const r=JSON.parse(reply.content[0].text);assert.equal(r.receipt.responseBytes,Buffer.byteLength(reply.content[0].text));return r;}
test('CLI and fresh independent MCP expose the same byte-bound UI graph and bounded command boundary',async t=>{
 const f=await setup(t),raw=(await exec(process.execPath,[cli,'pe-ui',f.workspace,'--file','ui.exe','--view','boundary','--command','1001','--limit','100','--budget-bytes','16384'])).stdout,result=JSON.parse(raw);
 assert.equal(result.receipt.responseBytes,Buffer.byteLength(raw)-1);assert.ok(result.items.some(n=>n.kind==='handler-candidate'));assert.ok(result.items.some(n=>n.edges.some(e=>e.kind==='dispatch-candidate')));
 const client=await connect(t,f.root);const summary=value(await call(client));assert.equal(summary.observationId,result.observationId);assert.equal(summary.sourceSha256,result.sourceSha256);assert.equal(summary.executesTarget,false);assert.equal(summary.startsRea,false);
 const first=value(await call(client,{view:'boundary',command:1001,limit:1}));assert.notEqual(first.nextOffset,null);const next=value(await call(client,{view:'boundary',command:1001,offset:first.nextOffset,limit:1}));assert.notEqual(first.items[0].id,next.items[0].id);
 const rows=value(await call(client,{view:'nodes',query:'Inspect'}));assert.equal(rows.items.length,1);assert.equal(rows.items[0].commandId,1003);
 assert.equal((await call(client,{view:'boundary'})).isError,true);assert.equal((await call(client,{command:0})).isError,true);
 await writeFile(f.file,Buffer.from('changed'));assert.equal((await call(client)).isError,true);
});
test('MCP refuses evidence-directory and current-source escapes before publishing graph records',async t=>{
 const f=await setup(t),outside=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ui-outside-')));t.after(()=>rm(outside,{recursive:true,force:true}));await mkdir(path.join(outside,'evidence'));await symlink(path.join(outside,'evidence'),path.join(f.workspace,'ui-evidence'));
 const client=await connect(t,f.root),denied=await call(client);assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
});
