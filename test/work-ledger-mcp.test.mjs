import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,writeFile,readFile,mkdir,rm,symlink} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
const identity=job=>{const {id,owner,attempt,claimId}=job;return{id,owner,attempt,claimId};};
async function connect(root){const client=new Client({name:'work-ledger-protocol-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));return client;}
const call=(peer,request,extra={})=>peer.callTool({name:'carve_work_ledger',arguments:{ledger:'ledger',request,...extra}});
const value=r=>{assert.ok(!r.isError,r.content[0].text);const data=JSON.parse(r.content[0].text);assert.equal(data.receipt.responseBytes,Buffer.byteLength(r.content[0].text));return data;};
async function setup(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ledger-protocol-')));t.after(()=>rm(root,{recursive:true,force:true}));for(const name of ['plan','spec'])await writeFile(path.join(root,name+'.json'),await readFile('examples/work-'+name+'.json'));
 const raw=(await exec(process.execPath,[cli,'work-package','create',path.join(root,'plan.json'),path.join(root,'spec.json'),'--feature','parser','--out',path.join(root,'parser')])).stdout,packet=JSON.parse(raw);
 await exec(process.execPath,[cli,'work-ledger','create',path.join(root,'ledger')]);await exec(process.execPath,[cli,'work-ledger','register',path.join(root,'ledger'),'--package',packet.package,'--plan',path.join(root,'plan.json'),'--spec',path.join(root,'spec.json')]);return{root,packet};}
test('independent MCP clients race atomically, resume across restarts and submit through the installed CLI contract',async t=>{
 const {root,packet}=await setup(t);let first=await connect(root),second=await connect(root);t.after(()=>Promise.all([first.close(),second.close()]));
 const request={action:'claim',id:packet.id,owner:'first',plan:'plan.json',spec:'spec.json'},raced=await Promise.all([call(first,request),call(second,{...request,owner:'second'})]);assert.equal(raced.filter(r=>!r.isError).length,1);const won=value(raced.find(r=>!r.isError)),old=identity(won.job);
 await first.close();first=await connect(root);const resumed=value(await call(first,{action:'read',id:packet.id}));assert.equal(resumed.items[0].claimId,old.claimId);assert.equal(resumed.items[0].status,'claimed');
 value(await call(first,{action:'close',claim:old,outcome:'failed',reason:'Owned protocol failure fixture'}));assert.equal((await call(second,request)).isError,true);const retry=value(await call(second,{...request,retry:true}));assert.equal(retry.job.attempt,2);
 assert.equal((await call(first,{action:'close',claim:old,outcome:'released',reason:'stale attempt'})).isError,true);
 const changed=JSON.parse(await readFile(path.join(root,'plan.json'),'utf8'));changed.goal+=' changed';await writeFile(path.join(root,'changed-plan.json'),JSON.stringify(changed));await writeFile(path.join(root,'submission.json'),JSON.stringify({kind:'proposal',summary:'Not an implementation'}));
 assert.equal((await call(first,{action:'submit',claim:identity(retry.job),plan:'changed-plan.json',spec:'spec.json',submission:'submission.json'})).isError,true);assert.equal(value(await call(first,{action:'read',id:packet.id})).items[0].status,'claimed');
 const spec=JSON.parse(await readFile(path.join(root,'spec.json'),'utf8')),output=path.join(root,'output');for(const file of spec.assignments.find(a=>a.feature==='parser').files){await mkdir(path.dirname(path.join(output,file)),{recursive:true});await writeFile(path.join(output,file),'// Owned synthetic handoff fixture; no target build\n');}
 await writeFile(path.join(root,'claim.json'),JSON.stringify(retry));await writeFile(path.join(root,'submission.json'),JSON.stringify({kind:'implementation',summary:'Files supplied; original behavior and target build not verified',checks:[{name:'Not executed',status:'not-run',detail:'This test covers the coordinator, not a compiler.'}]}));
 const raw=(await exec(process.execPath,[cli,'work-ledger','submit',path.join(root,'ledger'),'--claim',path.join(root,'claim.json'),'--plan',path.join(root,'plan.json'),'--spec',path.join(root,'spec.json'),'--submission',path.join(root,'submission.json'),'--output-root',output])).stdout,sent=JSON.parse(raw);assert.equal(sent.receipt.responseBytes,Buffer.byteLength(raw)-1);assert.equal(sent.job.status,'submitted');assert.equal(sent.verification,'not-run-by-ledger');
 await second.close();second=await connect(root);const history=value(await call(second,{action:'read',view:'attempts',id:packet.id}));assert.deepEqual(history.items.map(a=>a.status),['failed','submitted']);let offset=0,text='';do{const page=value(await call(second,{action:'read',view:'result',id:packet.id,attempt:2,offset,characters:12000},{budgetBytes:2048}));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;}while(offset!==null);assert.equal(JSON.parse(text).artifacts.files.length,2);assert.equal(JSON.parse(text).integration,'not-accepted-or-merged');
});
test('MCP confines ledger, marker/SQLite sidecars, packages, current JSON and artifact outputs',async t=>{
 const {root,packet}=await setup(t),outside=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ledger-outside-')));t.after(()=>rm(outside,{recursive:true,force:true}));await writeFile(path.join(outside,'foreign.json'),'{}');await symlink(outside,path.join(root,'outside'));
 const peer=await connect(root);t.after(()=>peer.close());const claim=value(await call(peer,{action:'claim',id:packet.id,owner:'worker',plan:'plan.json',spec:'spec.json'})),proof=identity(claim.job);
 for(const request of [{action:'register',package:'outside',plan:'plan.json',spec:'spec.json'},{action:'claim',id:packet.id,owner:'worker',plan:'outside/foreign.json',spec:'spec.json'},{action:'submit',claim:proof,plan:'plan.json',spec:'spec.json',submission:'outside/foreign.json'}])assert.equal((await call(peer,request)).isError,true);
 await writeFile(path.join(root,'submission.json'),JSON.stringify({kind:'implementation',summary:'outside'}));assert.equal((await call(peer,{action:'submit',claim:proof,plan:'plan.json',spec:'spec.json',submission:'submission.json',outputRoot:'outside'})).isError,true);assert.equal(value(await call(peer,{action:'read',id:packet.id})).items[0].status,'claimed');
 assert.equal((await call(peer,{action:'read'},{ledger:'outside'})).isError,true);assert.equal((await call(peer,{action:'read'},{ledger:path.join(outside,'ledger')})).isError,true);
 const invalid=await call(peer,{action:'read',plan:'plan.json'}).catch(()=>({isError:true}));assert.equal(invalid.isError,true);
 await symlink(path.join(outside,'foreign.json'),path.join(root,'ledger/ledger.sqlite-wal'));assert.equal((await call(peer,{action:'read'})).isError,true);assert.equal(await readFile(path.join(outside,'foreign.json'),'utf8'),'{}');
});
