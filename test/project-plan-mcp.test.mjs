import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,writeFile,readFile,rm,symlink} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
test('actual CLI and MCP page the same declared graph with exact compact budgets and no dispatch',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-plan-mcp-'));t.after(()=>rm(root,{recursive:true,force:true}));const plan=JSON.parse(await readFile('examples/project-plan.json','utf8'));
 await writeFile(path.join(root,'plan.json'),JSON.stringify(plan));const raw=(await exec(process.execPath,[cli,'project-plan',path.join(root,'plan.json'),'--limit','2','--budget-bytes','4096'])).stdout,first=JSON.parse(raw);
 assert.equal(first.summary.features,4);assert.equal(first.summary.phases,3);assert.equal(first.items.length,2);assert.equal(first.nextOffset,2);assert.equal(first.receipt.responseBytes,Buffer.byteLength(raw)-1);
 const client=new Client({name:'project-plan-protocol',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));t.after(()=>client.close());
 const tools=(await client.listTools()).tools,tool=tools.find(t=>t.name==='carve_project_plan');assert.equal(tool.annotations.readOnlyHint,true);
 const result=await client.callTool({name:'carve_project_plan',arguments:{plan:'plan.json',offset:2,limit:2,budgetBytes:4096}});assert.ok(!result.isError);const last=JSON.parse(result.content[0].text);assert.equal(last.planId,first.planId);assert.equal(last.nextOffset,null);assert.equal(last.receipt.responseBytes,Buffer.byteLength(result.content[0].text));assert.deepEqual([...first.items,...last.items].map(t=>t.id),['model','parser','storage','ui']);
 const after=JSON.parse(await readFile(path.join(root,'plan.json'),'utf8'));assert.deepEqual(after,plan);
});
test('MCP project-plan confines the input file and treats declared evidence as unopened data',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-plan-root-')),outside=await mkdtemp(path.join(tmpdir(),'carve-plan-outside-'));t.after(()=>Promise.all([rm(root,{recursive:true,force:true}),rm(outside,{recursive:true,force:true})]));
 const plan=JSON.parse(await readFile('examples/project-plan.json','utf8'));plan.features[0].description='$(touch NEVER_EXECUTE); source text only';plan.features[0].evidenceIds=['a'.repeat(64)];await writeFile(path.join(root,'plan.json'),JSON.stringify(plan));await writeFile(path.join(outside,'outside.json'),JSON.stringify(plan));await symlink(path.join(outside,'outside.json'),path.join(root,'foreign.json'));
 const client=new Client({name:'project-plan-root',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));t.after(()=>client.close());
 const valid=await client.callTool({name:'carve_project_plan',arguments:{plan:'plan.json'}});assert.ok(!valid.isError);assert.equal(JSON.parse(valid.content[0].text).items[0].declaredEvidenceIds,1);
 for(const input of ['foreign.json',path.join(outside,'outside.json')]){const denied=await client.callTool({name:'carve_project_plan',arguments:{plan:input}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);}
 await writeFile(path.join(root,'large.json'),' '.repeat(1048577));assert.equal((await client.callTool({name:'carve_project_plan',arguments:{plan:'large.json'}})).isError,true);
});
