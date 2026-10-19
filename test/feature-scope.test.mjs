import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm,realpath,symlink,rename} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {survey,queryIndex,openIndex} from '../dist/survey.js';
import {featureScope} from '../dist/feature-scope.js';
import {featureRequestSchema} from '../dist/feature-intent.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
async function fixture(t){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-feature-scope-')));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input');await mkdir(input);await writeFile(path.join(input,'swipe.mjs'),'export const direction=x=>x>0?1:-1;');await writeFile(path.join(input,'ui.mjs'),'export const render=x=>String(x);');
 const workspace=path.join(root,'work');await survey(input,{workspace});const file=(await queryIndex(workspace,{query:'swipe.mjs'})).items[0];
 const lead={file:file.path,sourceSha256:file.sha256},request={schema:'carve/feature-request@1',origin:'test-fixture',goal:'Select bounded swipe direction, not full app recovery',choice:'swipe',facet:'direction',behavior:{trigger:'One direction query',input:'A signed displacement',output:'An observed direction code',state:'stateless'},boundary:{ui:'excluded',remote:'excluded',host:'excluded'},leads:[lead]};return{root,input,workspace,lead,request};
}
test('incomplete intent survives sessions, revisions preserve prior bytes and readiness never means extraction',async t=>{
 const f=await fixture(t),first=await featureScope(f.workspace,{request:{schema:'carve/feature-request@1',goal:'Swipe and matching'}});assert.equal(first.status,'needs-clarification');assert.equal(first.sourceIdentityCheck,'no-selected-inputs');assert.equal(first.questions.filter(q=>q.audience==='user').length,7);assert.ok(first.questions.some(q=>q.audience==='agent'));
 const file=path.join(f.workspace,'feature-requests',first.id+'.json'),before=await readFile(file);assert.equal((await featureScope(f.workspace,{request:{schema:'carve/feature-request@1',goal:'Swipe and matching'}})).id,first.id);
 const second=await featureScope(f.workspace,{request:f.request,parentId:first.id});assert.equal(second.status,'ready-for-investigation');assert.equal(second.verification,'not-run');assert.equal(second.semanticMatch,'unconfirmed');assert.equal(second.parentId,first.id);assert.deepEqual(await readFile(file),before);assert.equal((await featureScope(f.workspace,{id:first.id})).status,'needs-clarification');assert.equal(second.executesTarget,false);
 const noLeads=await featureScope(f.workspace,{request:{...f.request,leads:[]}});assert.equal(noLeads.status,'needs-evidence');assert.deepEqual(noLeads.questions.map(q=>q.audience),['agent']);
});
test('multiple source workspaces retain explicit identities and only recorded code metadata',async t=>{
 const f=await fixture(t),otherInput=path.join(f.root,'metadata.mjs'),otherWork=path.join(f.root,'other-work');await writeFile(otherInput,'export const title="owned metadata";');await survey(otherInput,{workspace:otherWork});const other=(await queryIndex(otherWork)).items[0],db=openIndex(f.workspace);db.exec('CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,detail TEXT)');db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?)').run('a'.repeat(64),f.lead.file,f.lead.sourceSha256,'function','direction',JSON.stringify({pseudocode:'UNREAD_BODY_SENTINEL',pseudocodeTruncated:true}));db.close();
 const request={...f.request,leads:[{...f.lead,observationId:'a'.repeat(64)},{workspace:'../other-work',file:other.path,sourceSha256:other.sha256}]},saved=await featureScope(f.workspace,{request});assert.equal(saved.sourceCount,2);assert.equal(saved.items[1].workspace,'../other-work');assert.equal(saved.items[0].observation.recordedCompleteCode,false);assert.ok(!JSON.stringify(saved).includes('UNREAD_BODY_SENTINEL'));
 assert.equal(saved.receipt.responseBytes,Buffer.byteLength(JSON.stringify(saved)));assert.ok(saved.receipt.responseBytes<=8192);
});
test('historical reads do not recheck current files, while new scope writes reject stale or wrong observations',async t=>{
 const f=await fixture(t),saved=await featureScope(f.workspace,{request:f.request});await writeFile(path.join(f.input,'swipe.mjs'),'export const changed=2;');const read=await featureScope(f.workspace,{id:saved.id});assert.equal(read.sourceIdentityCheck,'recorded-only-no-current-source-check');await assert.rejects(()=>featureScope(f.workspace,{request:f.request}),/changed since inventory/);
 await survey(f.input,{workspace:f.workspace,refresh:true});await assert.rejects(()=>featureScope(f.workspace,{request:f.request}),/different source revision/);const fresh=(await queryIndex(f.workspace,{query:'swipe.mjs'})).items[0];await assert.rejects(()=>featureScope(f.workspace,{request:{...f.request,leads:[{file:fresh.path,sourceSha256:fresh.sha256,observationId:'b'.repeat(64)}]}}),/not recorded/);
});
test('scope record JSON paging keeps UTF16 boundaries, content identity and exact byte budgets',async t=>{
 const f=await fixture(t),request={...f.request,goal:'😀\u4e2d\u6587'.repeat(400),behavior:{...f.request.behavior,input:'😀data'.repeat(300),output:'\u4e2d\0\u6587'.repeat(400)}};const saved=await featureScope(f.workspace,{request});let offset=0,text='',pages=0;
 do{const page=await featureScope(f.workspace,{id:saved.id,view:'record',offset,characters:12000,budgetBytes:2048});assert.ok(page.text.length>0);assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;pages++;}while(offset!==null);
 assert.equal(JSON.parse(text).request.goal,request.goal);assert.ok(pages>2);const surrogate=text.indexOf('😀')+1;await assert.rejects(()=>featureScope(f.workspace,{id:saved.id,view:'record',offset:surrogate}),/surrogate/);
 const file=path.join(f.workspace,'feature-requests',saved.id+'.json'),bytes=await readFile(file);await writeFile(file,Buffer.concat([bytes,Buffer.from(' ')]));await assert.rejects(()=>featureScope(f.workspace,{id:saved.id}),/content identity/);
});
test('scope validation, cancellation and insufficient budgets publish no partial requests',async t=>{
 const f=await fixture(t);for(const bad of [{choice:'constructor'},{choice:'__proto__'},{facet:'other'},{choice:undefined,facet:'direction'},{boundary:{remote:'available'}},{leads:Array(17).fill(f.lead)}])assert.equal(featureRequestSchema.safeParse({...f.request,...bad}).success,false);
 for(const options of [{request:f.request,id:'a'.repeat(64)},{id:'../escape'},{request:f.request,parentId:'b'.repeat(64)},{request:f.request,offset:1},{request:f.request,budgetBytes:1024},{request:{...f.request,leads:[f.lead,f.lead]}},{request:f.request,signal:AbortSignal.abort()}])await assert.rejects(()=>featureScope(f.workspace,options));
 const files=await readdir(f.workspace);assert.equal(files.includes('feature-requests'),false);assert.equal(files.includes('.scan.lock'),false);
});
test('scope storage rejects symlinks and CLI/MCP round trips retain missing answers without executing sources',async t=>{
 const f=await fixture(t),requestFile=path.join(f.root,'request.json');await writeFile(requestFile,JSON.stringify(f.request));const raw=(await exec(process.execPath,[cli,'scope',f.workspace,'--request',requestFile])).stdout,result=JSON.parse(raw);assert.equal(result.status,'ready-for-investigation');assert.equal(result.receipt.responseBytes,Buffer.byteLength(raw)-1);
 const menuRaw=(await exec(process.execPath,[cli,'features',f.workspace,'--choice','swipe','--facet','direction'])).stdout,menu=JSON.parse(menuRaw);assert.equal(menu.refinement.selectedFacet,'direction');assert.equal(menu.receipt.responseBytes,Buffer.byteLength(menuRaw)-1);
 const client=new Client({name:'feature-scope-roundtrip',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());assert.ok((await client.listTools()).tools.some(t=>t.name==='carve_scope'));
 const read=await client.callTool({name:'carve_scope',arguments:{workspace:'work',id:result.id}});assert.ok(!read.isError);assert.equal(JSON.parse(read.content[0].text).sourceIdentityCheck,'recorded-only-no-current-source-check');
 const draft=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:{schema:'carve/feature-request@1',goal:'Unknown custom operation'}}});assert.ok(!draft.isError);assert.equal(JSON.parse(draft.content[0].text).status,'needs-clarification');
 const folder=path.join(f.workspace,'feature-requests');await rename(folder,folder+'-saved');await symlink(path.join(f.root,'input'),folder);await assert.rejects(()=>featureScope(f.workspace,{request:f.request}),/real directory/);
});
test('MCP scope rejects related workspace, input and storage paths outside the configured root',async t=>{
 const f=await fixture(t),outside=await fixture(t),client=new Client({name:'feature-scope-confinement',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const denied=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:{...f.request,leads:[{...outside.lead,workspace:outside.workspace}]}}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
 await symlink(outside.workspace,path.join(f.root,'foreign-work'));const alias=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:{...f.request,leads:[{...outside.lead,workspace:'../foreign-work'}]}}});assert.equal(alias.isError,true);assert.match(alias.content[0].text,/outside/);
 await symlink(outside.input,path.join(f.workspace,'feature-requests'));const storage=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:f.request}});assert.equal(storage.isError,true);assert.match(storage.content[0].text,/outside/);
});
