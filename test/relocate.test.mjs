import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {crc32} from 'node:zlib';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,writeFile,readFile,rm,rename,realpath} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,indexedFile,hashFile} from '../dist/survey.js';
import {unpackContainer} from '../dist/container.js';
import {relocateWorkspace} from '../dist/relocate.js';
const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));

// Minimal stored ZIP with regular members.
function zip(entries){
 const locals=[],central=[];let offset=0;
 for(const e of entries){const name=Buffer.from(e.name),data=Buffer.from(e.data),checksum=crc32(data);
  const head=Buffer.alloc(30);head.writeUInt32LE(0x04034b50);head.writeUInt16LE(20,4);head.writeUInt32LE(checksum,14);head.writeUInt32LE(data.length,18);head.writeUInt32LE(data.length,22);head.writeUInt16LE(name.length,26);
  const c=Buffer.alloc(46);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(3*256+20,4);c.writeUInt16LE(20,6);c.writeUInt32LE(checksum,16);c.writeUInt32LE(data.length,20);c.writeUInt32LE(data.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE((0o100644<<16)>>>0,38);c.writeUInt32LE(offset,42);
  locals.push(head,name,data);central.push(c,name);offset+=head.length+name.length+data.length;
 }
 const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(entries.length,8);end.writeUInt16LE(entries.length,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([...locals,directory,end]);
}
const elf=()=>{const b=Buffer.alloc(64);b.writeUInt32BE(0x7f454c46);b[4]=2;b[5]=1;b.writeUInt16LE(2,16);b.writeUInt16LE(183,18);return b;};
async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-relocate-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
// Records evidence the way analysis backends do: an absolute evidence file inside the workspace plus its hash.
async function recordEvidence(workspace,count){
 const dir=path.join(workspace,'analysis-cache/fixture/run-1');await mkdir(dir,{recursive:true});const evidence=path.join(dir,'evidence.jsonl');await writeFile(evidence,'{"kind":"fixture"}\n');
 const sha=(await hashFile(evidence)).sha256,db=new DatabaseSync(path.join(workspace,'index.sqlite'));
 try{db.exec('CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT)');
  for(let i=0;i<count;i++)db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run('id'+i,'tool','sha','string','n'+i,String(i),'c','{}',evidence,sha);}
 finally{db.close();}
 return evidence;
}
const meta=(workspace,key)=>{const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});try{const row=db.prepare('SELECT value FROM meta WHERE key=?').get(key);return row&&JSON.parse(row.value);}finally{db.close();}};
const evidencePaths=workspace=>{const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});try{return db.prepare('SELECT DISTINCT evidence FROM observations').all().map(r=>r.evidence);}finally{db.close();}};

test('a moved project folder is relocated: the target follows, evidence is rewritten after hash checks, and analysis selection works again',async t=>{
 const root=await scratch(t),project=path.join(root,'project'),input=path.join(project,'input'),work=path.join(project,'work');
 await mkdir(input,{recursive:true});await writeFile(path.join(input,'tool'),elf());await writeFile(path.join(input,'notes.txt'),'notes');
 await survey(input,{workspace:work});await recordEvidence(work,2);
 assert.equal(meta(work,'workspace'),work);
 // Workspaces from before 0.24 record their location only in survey.json.
 {const db=new DatabaseSync(path.join(work,'index.sqlite'));db.prepare("DELETE FROM meta WHERE key='workspace'").run();db.close();}

 const moved=path.join(root,'moved'),movedWork=path.join(moved,'work'),movedInput=path.join(moved,'input');await rename(project,moved);
 await assert.rejects(()=>indexedFile(movedWork,'tool'),/moved from .*project\/work.*carve relocate/);
 await assert.rejects(()=>survey(movedInput,{workspace:movedWork}),/moved from/);

 const result=await relocateWorkspace(movedWork);
 assert.equal(result.moved,true);assert.equal(result.from,work);assert.deepEqual(result.target,{from:input,to:movedInput,changed:true});
 assert.equal(result.inventory.files,2);assert.deepEqual(result.evidence,{files:1,rows:2,hashVerified:true,outsideWorkspace:0});
 assert.deepEqual(evidencePaths(movedWork),[path.join(movedWork,'analysis-cache/fixture/run-1/evidence.jsonl')]);
 assert.equal(meta(movedWork,'root'),movedInput);assert.equal(meta(movedWork,'workspace'),movedWork);
 assert.equal(JSON.parse(await readFile(path.join(movedWork,'.carve-workspace.json'),'utf8')).target,movedInput);
 assert.equal((await indexedFile(movedWork,'tool')).path,path.join(movedInput,'tool'));
 const again=await survey(movedInput,{workspace:movedWork,refresh:true});assert.equal(again.status,'indexed');assert.equal(again.batch.hashed,0,'moving does not change file metadata, so the inventory cache still applies');
 const repeat=await relocateWorkspace(movedWork);assert.equal(repeat.moved,false);assert.equal(repeat.target.changed,false);assert.equal(repeat.evidence.files,0);
 const db=new DatabaseSync(path.join(movedWork,'index.sqlite'),{readOnly:true});
 try{const events=db.prepare("SELECT detail FROM events WHERE kind='relocate' ORDER BY id").all().map(r=>JSON.parse(r.detail));assert.equal(events.length,2);assert.equal(events[0].evidenceRows,2);}finally{db.close();}
});

test('relocation refuses changed evidence or inventory and leaves the workspace unchanged',async t=>{
 const root=await scratch(t),project=path.join(root,'project'),input=path.join(project,'input'),work=path.join(project,'work');
 await mkdir(input,{recursive:true});await writeFile(path.join(input,'tool'),elf());await survey(input,{workspace:work});const evidence=await recordEvidence(work,1);
 const moved=path.join(root,'moved'),movedWork=path.join(moved,'work');await rename(project,moved);
 const movedEvidence=path.join(movedWork,path.relative(work,evidence));await writeFile(movedEvidence,'{"kind":"edited"}\n');
 await assert.rejects(()=>relocateWorkspace(movedWork),/does not match its recorded hash; nothing was changed/);
 assert.equal(meta(movedWork,'workspace'),work);assert.deepEqual(evidencePaths(movedWork),[evidence]);
 await assert.rejects(()=>indexedFile(movedWork,'tool'),/moved from/);
 await writeFile(movedEvidence,'{"kind":"fixture"}\n');await writeFile(path.join(moved,'input/tool'),Buffer.concat([elf(),Buffer.from('more')]));
 await assert.rejects(()=>relocateWorkspace(movedWork),/1 indexed file\(s\) are missing or differ at the new target \(first: tool\)/);
 assert.equal(meta(movedWork,'workspace'),work);
 // A pre-0.24 survey run after the move recorded the new path; evidence still names the old one.
 await writeFile(path.join(moved,'input/tool'),elf());
 {const db=new DatabaseSync(path.join(movedWork,'index.sqlite'));db.prepare("DELETE FROM meta WHERE key='workspace'").run();db.close();}
 const report=JSON.parse(await readFile(path.join(movedWork,'survey.json'),'utf8'));await writeFile(path.join(movedWork,'survey.json'),JSON.stringify({...report,workspace:movedWork}));
 await assert.rejects(()=>relocateWorkspace(movedWork),/or --from if this workspace moved/);
 await assert.rejects(()=>relocateWorkspace(movedWork,{target:path.join(moved,'input')}),/1 recorded evidence file\(s\) are not under the previous location .* Pass --from/);
 const repaired=await relocateWorkspace(movedWork,{from:work});assert.equal(repaired.evidence.rows,1);assert.deepEqual(evidencePaths(movedWork),[movedEvidence]);
});

test('an unpacked inventory waits for its container workspace, and a target that moved elsewhere needs --target',async t=>{
 const root=await scratch(t),project=path.join(root,'project');await mkdir(project);
 await writeFile(path.join(project,'app.apk'),zip([{name:'classes.dex',data:'dex\n035\0fixture'},{name:'res/a.txt',data:'a'}]));
 const containers=path.join(project,'container-work'),work=path.join(project,'work');await survey(path.join(project,'app.apk'),{workspace:containers});
 let unpacked;do{unpacked=await unpackContainer(containers,{file:'app.apk'});}while(unpacked.status!=='unpacked');
 await survey(unpacked.content,{workspace:work});assert.ok((await indexedFile(work,'classes.dex')).container);

 const moved=path.join(root,'moved');await rename(project,moved);const movedContainers=path.join(moved,'container-work'),movedWork=path.join(moved,'work');
 const client=new Client({name:'relocate-container-order',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',moved],stderr:'pipe'}));t.after(()=>client.close());
 const early=await client.callTool({name:'carve_relocate',arguments:{workspace:'work'}});assert.equal(early.isError,true);assert.match(early.content[0].text,/Relocate the container workspace that unpacked this inventory first/);
 const outer=JSON.parse((await promisify(execFile)(process.execPath,[cli,'relocate',movedContainers])).stdout);
 assert.equal(outer.containerCaches,1);assert.equal(outer.target.to,path.join(moved,'app.apk'));
 const repaired=await client.callTool({name:'carve_relocate',arguments:{workspace:'work'}});assert.equal(repaired.isError,undefined,repaired.content[0].text);const inner=JSON.parse(repaired.content[0].text);assert.equal(inner.containerLineage,true);
 const lineage=meta(movedWork,'container');assert.equal(lineage.workspace,movedContainers);assert.equal(lineage.memberIndex,path.join(path.dirname(inner.target.to),'members.sqlite'));
 const selected=await indexedFile(movedWork,'classes.dex');assert.equal(selected.container.workspace,movedContainers);assert.equal(selected.container.sha256,unpacked.original.sha256);

 // A file target that moved separately from its workspace.
 const elsewhere=path.join(root,'elsewhere');await mkdir(elsewhere);await writeFile(path.join(elsewhere,'tool'),elf());
 const single=path.join(root,'single-work');await survey(path.join(elsewhere,'tool'),{workspace:single});
 const later=path.join(root,'later');await rename(elsewhere,later);
 await assert.rejects(()=>relocateWorkspace(single),/Pass --target with its new location/);
 await writeFile(path.join(root,'other'),Buffer.concat([elf(),Buffer.from('x')]));
 await assert.rejects(()=>relocateWorkspace(single,{target:path.join(root,'other')}),/differ at the new target/);
 const retargeted=await relocateWorkspace(single,{target:path.join(later,'tool')});
 assert.equal(retargeted.moved,false);assert.equal(retargeted.target.changed,true);assert.equal((await indexedFile(single,'tool')).path,path.join(later,'tool'));
});
