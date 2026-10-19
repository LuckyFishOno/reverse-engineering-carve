import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,readFile,rename,symlink,unlink,rm,realpath,cp} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {inspectLoader} from '../dist/loader.js';
const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
const metadata=work=>{const db=new DatabaseSync(path.join(work,'index.sqlite'),{readOnly:true});try{return{workspace:JSON.parse(db.prepare("SELECT value FROM meta WHERE key='workspace'").get().value),evidence:db.prepare('SELECT evidence FROM observations ORDER BY id').all().map(r=>r.evidence),relocations:db.prepare("SELECT count(*) n FROM events WHERE kind='relocate'").get().n};}finally{db.close();}};
async function fixture(t){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-relocate-mcp-'))),clients=[];
 t.after(async()=>{for(const c of clients)await c.close();await rm(root,{recursive:true,force:true});});
 const old=path.join(root,'old'),base=path.join(root,'current'),input=path.join(old,'input'),work=path.join(old,'work');await mkdir(input,{recursive:true});
 const header=Buffer.alloc(32);header.writeUInt32LE(0xfeedfacf);header.writeUInt32LE(0x0100000c,4);header.writeUInt32LE(2,12);await writeFile(path.join(input,'tool'),header);await writeFile(path.join(input,'module.mjs'),'export const x=1;');
 await survey(input,{workspace:work});const loader=await inspectLoader(work,{file:'tool'});await rename(old,base);
 const current=path.join(base,'work'),evidence=path.join(current,path.relative(work,loader.evidence));
 const client=new Client({name:'relocate-boundary-test',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',base],stderr:'pipe'});await client.connect(transport);clients.push(client);
 const call=(args)=>client.callTool({name:'carve_relocate',arguments:{workspace:'work',...args}});
 return{root,old,base,work:current,oldWork:work,evidence,loader,client,call,serverPid:transport.pid};
}
const value=reply=>{assert.equal(reply.isError,undefined,reply.content[0].text);return JSON.parse(reply.content[0].text);};
const denied=reply=>{assert.equal(reply.isError,true);assert.match(reply.content[0].text,/outside the MCP workspace root/);};

test('actual MCP repairs an automatically carried target and hashed loader evidence, retaining history and subsequent inspection',async t=>{
 const f=await fixture(t),before=metadata(f.work),bytes=await readFile(f.evidence);
 const unavailable=await f.client.callTool({name:'carve_loader',arguments:{workspace:'work',file:'tool'}});assert.equal(unavailable.isError,true);
 const repaired=value(await f.call({}));assert.equal(repaired.moved,true);assert.equal(repaired.from,f.oldWork);assert.equal(repaired.target.to,path.join(f.base,'input'));assert.equal(repaired.evidence.files,1);assert.equal(repaired.evidence.hashVerified,true);
 assert.deepEqual(await readFile(f.evidence),bytes);assert.equal(metadata(f.work).workspace,f.work);assert.deepEqual(metadata(f.work).evidence,[f.evidence]);assert.equal(metadata(f.work).relocations,before.relocations+1);
 const indexed=value(await f.client.callTool({name:'carve_index',arguments:{workspace:'work'}}));assert.equal(indexed.total,2);
 const observed=value(await f.client.callTool({name:'carve_observation',arguments:{workspace:'work',id:f.loader.observationId}}));assert.equal(observed.matchesCurrentInventory,true);assert.equal(observed.evidence,f.evidence);
 assert.equal(value(await f.call({})).moved,false);
});

test('MCP from is an old absolute mapping outside the new root, while an explicit target is root-relative',async t=>{
 const f=await fixture(t);await rename(path.join(f.base,'input'),path.join(f.base,'separately-moved'));
 // Emulate an old post-move survey report that lost its original workspace location.
 const db=new DatabaseSync(path.join(f.work,'index.sqlite'));db.prepare("UPDATE meta SET value=? WHERE key='workspace'").run(JSON.stringify(f.work));db.close();
 const bad=await f.call({from:'relative/old',target:'separately-moved'});assert.equal(bad.isError,true);
 const repaired=value(await f.call({from:f.oldWork,target:'separately-moved'}));assert.equal(repaired.from,f.oldWork);assert.equal(repaired.target.to,path.join(f.base,'separately-moved'));assert.equal(repaired.evidence.rows,1);
 assert.equal(value(await f.client.callTool({name:'carve_loader',arguments:{workspace:'work',file:'tool'}})).status,'loader-commands-inspected');
});

test('MCP rejects external workspace/explicit or inferred targets and symlink escapes before modifying live metadata',async t=>{
 const f=await fixture(t),before=metadata(f.work),outside=path.join(f.root,'outside');await cp(path.join(f.base,'input'),outside,{recursive:true});
 denied(await f.call({workspace:'../outside'}));denied(await f.call({target:outside}));await symlink(outside,path.join(f.base,'escape'));denied(await f.call({target:'escape'}));
 // The automatic target may still exist outside a newly selected server root.
 const db=new DatabaseSync(path.join(f.work,'index.sqlite'));db.prepare("UPDATE meta SET value=? WHERE key='target'").run(JSON.stringify(outside));db.close();
 denied(await f.call({}));assert.equal(metadata(f.work).workspace,before.workspace);assert.equal(metadata(f.work).relocations,0);
});

test('MCP rejects outside evidence and symlinked evidence without committing a relocation',async t=>{
 const f=await fixture(t),outside=path.join(f.root,'outside-evidence');await cp(f.evidence,outside);const saved=f.evidence+'.saved';await rename(f.evidence,saved);await symlink(outside,f.evidence);
 denied(await f.call({}));assert.equal(metadata(f.work).workspace,f.oldWork);assert.equal(metadata(f.work).relocations,0);
 await unlink(f.evidence);await rename(saved,f.evidence);
 const db=new DatabaseSync(path.join(f.work,'index.sqlite'));db.prepare('UPDATE observations SET evidence=?').run(outside);db.close();
 denied(await f.call({}));assert.equal(metadata(f.work).workspace,f.oldWork);assert.equal(metadata(f.work).relocations,0);
});

test('MCP checks the index and container/marker paths before they can reach outside the server root',async t=>{
 const f=await fixture(t),index=path.join(f.work,'index.sqlite'),saved=index+'.saved',outside=path.join(f.root,'outside.sqlite');await cp(index,outside);const before=(await hashFile(outside)).sha256;await rename(index,saved);await symlink(outside,index);
 denied(await f.call({}));assert.equal((await hashFile(outside)).sha256,before);await unlink(index);await rename(saved,index);
 const external=path.join(f.root,'outside-containers');await mkdir(external);await symlink(external,path.join(f.work,'containers'));denied(await f.call({}));assert.equal(metadata(f.work).workspace,f.oldWork);await unlink(path.join(f.work,'containers'));
 // A link at the temporary marker destination must also be caught before the SQL commit.
 assert.ok(f.serverPid);await symlink(outside,path.join(f.work,`.carve-workspace.json.${f.serverPid}.tmp`));denied(await f.call({}));assert.equal(metadata(f.work).workspace,f.oldWork);assert.equal(metadata(f.work).relocations,0);assert.equal((await hashFile(outside)).sha256,before);
});
