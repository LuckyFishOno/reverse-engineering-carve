import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,writeFile,readFile,rm,symlink,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
async function setup(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-work-protocol-')));t.after(()=>rm(root,{recursive:true,force:true}));for(const [source,target] of [['work-plan.json','plan.json'],['work-spec.json','spec.json']])await writeFile(path.join(root,target),await readFile('examples/'+source));return root;}
async function connect(root){const peer=new Client({name:'work-package-test',version:'1'});await peer.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));return peer;}
const call=(peer,args)=>peer.callTool({name:'carve_work_package',arguments:args});
const value=r=>{assert.ok(!r.isError,r.content[0].text);const v=JSON.parse(r.content[0].text);assert.equal(v.receipt.responseBytes,Buffer.byteLength(r.content[0].text));return v;};
test('CLI-created work package survives a fresh MCP, checks pins and rejects stale declarations without rewriting history',async t=>{
 const root=await setup(t),folder=path.join(root,'parser'),raw=(await exec(process.execPath,[cli,'work-package','create',path.join(root,'plan.json'),path.join(root,'spec.json'),'--feature','parser','--out',folder,'--budget-bytes','4096'])).stdout,created=JSON.parse(raw);
 assert.equal(created.receipt.responseBytes,Buffer.byteLength(raw)-1);assert.equal(created.verification,'not-run');assert.equal(created.currentPlanCheck,'matched-supplied-plan-and-spec');const before=await readFile(path.join(folder,'work.json'));
 let peer=await connect(root);t.after(()=>peer.close());const inventory=(await peer.listTools()).tools;assert.equal(inventory.find(t=>t.name==='carve_work_package').annotations.destructiveHint,false);
 const read=value(await call(peer,{action:'read',package:'parser',view:'dependencies',budgetBytes:4096}));assert.equal(read.id,created.id);assert.equal(read.items[0].feature,'model');assert.equal(read.currentPlanCheck,'not-performed');
 await peer.close();peer=await connect(root);const checked=value(await call(peer,{action:'check',package:'parser',plan:'plan.json',spec:'spec.json'}));assert.equal(checked.currentPlanCheck,'matched-supplied-plan-and-spec');
 const spec=JSON.parse(await readFile(path.join(root,'spec.json'),'utf8'));spec.assignments[0].acceptance[0].criterion+=' changed';await writeFile(path.join(root,'spec.json'),JSON.stringify(spec));const stale=await call(peer,{action:'check',package:'parser',plan:'plan.json',spec:'spec.json'});assert.equal(stale.isError,true);assert.match(stale.content[0].text,/stale/);assert.deepEqual(await readFile(path.join(folder,'work.json')),before);
 value(await call(peer,{action:'create',plan:'plan.json',spec:'spec.json',feature:'storage',out:'storage'}));assert.equal((await call(peer,{action:'create',plan:'plan.json',spec:'spec.json',feature:'storage',out:'storage'})).isError,true);
});
test('MCP work packages reject escaped inputs/outputs, oversized files and mismatched action fields; unopened source references are data',async t=>{
 const root=await setup(t),outside=await realpath(await mkdtemp(path.join(tmpdir(),'carve-work-external-')));t.after(()=>rm(outside,{recursive:true,force:true}));await writeFile(path.join(outside,'plan.json'),await readFile(path.join(root,'plan.json')));await symlink(outside,path.join(root,'foreign'));const peer=await connect(root);t.after(()=>peer.close());
 const create={action:'create',plan:'plan.json',spec:'spec.json',feature:'parser',out:'parser'};
 for(const args of [{...create,plan:'foreign/plan.json'},{...create,out:'foreign/packet'},{...create,out:path.join(outside,'packet')},{...create,package:'parser'},{action:'read',package:'parser',plan:'plan.json'},{action:'check',package:'parser',plan:'plan.json'}])assert.equal((await call(peer,args)).isError,true);
 await writeFile(path.join(root,'large.json'),' '.repeat(1048577));assert.equal((await call(peer,{...create,plan:'large.json'})).isError,true);assert.deepEqual(await readdir(outside),['plan.json']);
 const spec=JSON.parse(await readFile(path.join(root,'spec.json'),'utf8'));spec.assignments.find(a=>a.feature==='parser').sourceContext=[{workspace:outside,file:'missing.exe',sourceSha256:'a'.repeat(64),evidenceIds:[]}];await writeFile(path.join(root,'spec.json'),JSON.stringify(spec));const created=value(await call(peer,create));assert.equal(created.declaredSourceContexts,1);assert.equal(created.startsAgents,false);
 let text='',offset=0;do{const page=value(await call(peer,{action:'read',package:'parser',view:'record',offset,characters:12000,budgetBytes:2048}));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;}while(offset!==null);assert.equal(JSON.parse(text).assignment.sourceContext[0].workspace,outside);
 await symlink(path.join(root,'parser'),path.join(root,'alias'));assert.equal((await call(peer,{action:'read',package:'alias'})).isError,true);
});
