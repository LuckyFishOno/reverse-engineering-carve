import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,open,symlink} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {survey,queryIndex,indexedFile,openIndex} from '../dist/survey.js';
import {identifyFormat} from '../dist/formats.js';
async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),'carve-survey-'));t.after(()=>rm(root,{recursive:true,force:true}));const app=path.join(root,'app');await mkdir(app);return {root,app,workspace:path.join(root,'work')};}
test('format detection distinguishes executable headers, JVM classes and archive hints',()=>{
 const elf=Buffer.alloc(64);elf.writeUInt32BE(0x7f454c46);elf[5]=1;elf.writeUInt16LE(183,18);assert.equal(identifyFormat(elf,'no-extension').architecture,'arm64');
 const java=Buffer.from([0xca,0xfe,0xba,0xbe,0,0,0,52]);assert.equal(identifyFormat(java,'app.bin').format,'java-class');
 const fat=Buffer.from([0xca,0xfe,0xba,0xbe,0,0,0,2]);assert.equal(identifyFormat(fat,'app.bin').format,'mach-o-fat');
 const dex=Buffer.from('dex\n035\0');assert.equal(identifyFormat(dex,'classes.dex').backend,'jadx');
 const zip=Buffer.from([80,75,3,4]);assert.equal(identifyFormat(zip,'app.apk').identification,'zip-header-plus-extension-hint');
 const pe=Buffer.alloc(512);pe.write('MZ');pe.writeUInt32LE(64,60);pe.write('PE\0\0',64);pe.writeUInt16LE(0x8664,68);pe.writeUInt16LE(0x20b,88);pe.writeUInt32LE(1234,88+112+14*8);
 assert.equal(identifyFormat(pe,'app.exe').format,'pe-cli');
});
test('bounded batches resume without a whole-project memory list and metadata refresh reuses hashes',async t=>{
 const {app,workspace}=await fixture(t);
 for(let i=0;i<7;i++)await writeFile(path.join(app,`${i}.js`),`export const value=${i};`);
 let result=await survey(app,{workspace,maxFiles:2});assert.equal(result.status,'indexing');let batches=1;
 while(result.status==='indexing'&&batches<10){result=await survey(app,{workspace,maxFiles:2});batches++;}
 assert.equal(result.status,'indexed');assert.equal(result.files,7);assert.ok(batches>1);
 const page=await queryIndex(workspace,{backend:'javascript',limit:2});assert.equal(page.items.length,2);assert.equal(page.total,7);assert.equal(page.nextOffset,2);
 result=await survey(app,{workspace,refresh:true});assert.equal(result.batch.cached,7);assert.equal(result.batch.hashed,0);
 await writeFile(path.join(app,'0.js'),'export const changed=42;');await assert.rejects(()=>indexedFile(workspace,'0.js'),/changed since inventory/);
 await rm(path.join(app,'1.js'));result=await survey(app,{workspace,refresh:true});assert.equal(result.files,6);assert.equal(result.batch.hashed,1);
});
test('a source larger than the JS slicer limit is hashed in a streaming inventory',async t=>{
 const {app,workspace}=await fixture(t);const file=path.join(app,'large.bin');const handle=await open(file,'w');await handle.truncate(20*1024*1024);await handle.close();
 const result=await survey(app,{workspace});assert.equal(result.status,'indexed');assert.equal((await queryIndex(workspace)).items[0].bytes,20*1024*1024);
});
test('survey skips symlinks and its own workspace, preserves foreign directories and refuses target drift',async t=>{
 const {root,app}=await fixture(t);await writeFile(path.join(app,'file.js'),'export const value=1;');await symlink(path.join(app,'file.js'),path.join(app,'link.js'));
 const workspace=path.join(app,'analysis');const result=await survey(app,{workspace});assert.equal(result.files,1);assert.ok(result.batch.skipped>=2);
 await assert.rejects(()=>indexedFile(workspace,'../outside'),/relative path/);
 const other=path.join(root,'other');await mkdir(other);await assert.rejects(()=>survey(other,{workspace}),/another target/);
 const foreign=path.join(root,'foreign');await mkdir(foreign);await writeFile(path.join(foreign,'index.sqlite'),'unrelated data');
 await assert.rejects(()=>survey(app,{workspace:foreign}),/existing files are preserved/);assert.equal(await readFile(path.join(foreign,'index.sqlite'),'utf8'),'unrelated data');
});
async function files(app,count){
 for(let i=0;i<count;i+=32)await Promise.all(Array.from({length:Math.min(32,count-i)},(_,j)=>writeFile(path.join(app,`${String(i+j).padStart(6,'0')}.mjs`),`export const n=${i+j};`)));
}
async function finish(app,workspace,maxFiles=31){
 let result,hashed=0,enumerated=0,listed=0,batches=0;
 do{result=await survey(app,{workspace,maxFiles});hashed+=result.batch.hashed;enumerated+=result.batch.enumeratedEntries;listed+=result.batch.listedDirectories;assert.ok(++batches<1000);}while(result.status==='indexing');
 return{result,hashed,enumerated,listed,batches};
}
test('flat-directory batches consume a disk queue without re-enumerating completed listings',async t=>{
 const {app,workspace}=await fixture(t);await files(app,73);
 const first=await survey(app,{workspace,maxFiles:7});assert.equal(first.pendingFiles,66);assert.equal(first.pendingDirectories,0);assert.equal(first.batch.enumeratedEntries,73);
 const remaining=await finish(app,workspace,7);assert.equal(remaining.result.status,'indexed');assert.equal(remaining.result.files,73);assert.equal(remaining.hashed,66);assert.equal(remaining.enumerated,0);assert.equal(remaining.listed,0);
 const unchanged=await survey(app,{workspace});assert.equal(unchanged.batch.processed,0);assert.equal(unchanged.batch.enumeratedEntries,0);
});
test('directory-only traversal is bounded and resumes even when no files were processed',async t=>{
 const {app,workspace}=await fixture(t);for(let i=0;i<9;i++)await mkdir(path.join(app,`dir-${i}`));
 let result=await survey(app,{workspace,maxDirectories:2});assert.equal(result.status,'indexing');assert.equal(result.batch.processed,0);assert.equal(result.batch.directoryAttempts,2);assert.equal(result.pendingDirectories,8);
 let listed=result.batch.listedDirectories,enumerated=result.batch.enumeratedEntries,batches=1;
 while(result.status==='indexing'){result=await survey(app,{workspace,maxDirectories:2});assert.ok(result.batch.directoryAttempts<=2);listed+=result.batch.listedDirectories;enumerated+=result.batch.enumeratedEntries;assert.ok(++batches<10);}
 assert.equal(result.status,'indexed');assert.equal(result.files,0);assert.equal(listed,10);assert.equal(enumerated,9);
});
test('cancelled listing keeps committed entries, releases ownership and resumes without duplicate file work',async t=>{
 const {app,workspace}=await fixture(t);await files(app,1105);const controller=new AbortController();
 await assert.rejects(()=>survey(app,{workspace,signal:controller.signal,onProgress:p=>{if(p.phase==='listing')controller.abort();}}),/Survey cancelled/);
 const db=openIndex(workspace,true);try{assert.equal(db.prepare('SELECT count(*) n FROM pending_files').get().n,1000);assert.equal(db.prepare("SELECT status FROM dirs WHERE path='.'").get().status,'queued');assert.equal(db.prepare("SELECT count(*) n FROM events WHERE kind='survey-interrupted'").get().n,1);}finally{db.close();}
 const resumed=await finish(app,workspace);assert.equal(resumed.result.status,'indexed');assert.equal(resumed.result.files,1105);assert.equal(resumed.hashed,1105);assert.equal(resumed.enumerated,1105);
});
async function killAtCheckpoint(t,app,workspace,phase){
 const child=spawn(process.execPath,['--input-type=module','-e',`import {survey} from ${JSON.stringify(new URL('../dist/survey.js',import.meta.url).href)};await survey(process.argv[1],{workspace:process.argv[2],onProgress:async p=>{if(p.phase===process.argv[3]){process.stdout.write(JSON.stringify(p)+'\\n');await new Promise(r=>setTimeout(r,60000));}}});`,app,workspace,phase],{stdio:['ignore','pipe','pipe']});
 t.after(()=>{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');});
 let stderr='';child.stderr.on('data',data=>{stderr=(stderr+data).slice(-10000);});const closed=once(child,'close');
 let timer;
 try{
  await new Promise((resolve,reject)=>{let text='';timer=setTimeout(()=>reject(new Error(`No checkpoint: ${stderr}`)),15000);
   child.stdout.on('data',data=>{text+=data;if(text.includes('\n')){assert.equal(JSON.parse(text.trim()).phase,phase);resolve();}});
   child.once('error',reject);child.once('exit',(code,signal)=>reject(new Error(`Exited before kill: ${code}/${signal}: ${stderr}`)));
  });
 }finally{clearTimeout(timer);child.kill('SIGKILL');await closed;}
 assert.equal(child.signalCode,'SIGKILL');
}
test('real killed process replays only its incomplete directory listing and preserves committed queue rows',async t=>{
 const {app,workspace}=await fixture(t);await files(app,1105);await killAtCheckpoint(t,app,workspace,'listing');
 const db=openIndex(workspace,true);try{assert.equal(db.prepare('SELECT count(*) n FROM pending_files').get().n,1000);assert.equal(db.prepare("SELECT status FROM dirs WHERE path='.'").get().status,'listing');}finally{db.close();}
 const resumed=await finish(app,workspace);assert.equal(resumed.result.status,'indexed');assert.equal(resumed.result.files,1105);assert.equal(resumed.hashed,1105);assert.equal(resumed.enumerated,1105);
});
test('real killed process does not replay a completed directory listing',async t=>{
 const {app,workspace}=await fixture(t);await files(app,43);await killAtCheckpoint(t,app,workspace,'directory-listed');
 const db=openIndex(workspace,true);try{assert.equal(db.prepare("SELECT status FROM dirs WHERE path='.'").get().status,'listed');}finally{db.close();}
 const resumed=await finish(app,workspace,7);assert.equal(resumed.result.status,'indexed');assert.equal(resumed.result.files,43);assert.equal(resumed.hashed,43);assert.equal(resumed.enumerated,0);
});
test('old inventories migrate with metadata cache reuse and remove deleted paths only on completed refresh',async t=>{
 const {app,workspace}=await fixture(t);await files(app,4);await survey(app,{workspace});
 const db=openIndex(workspace);db.exec("DELETE FROM meta WHERE key='inventoryVersion';DROP TABLE pending_files;UPDATE dirs SET status='done';");db.close();
 await rm(path.join(app,'000001.mjs'));
 const first=await survey(app,{workspace,maxFiles:1});assert.equal(first.inventoryVersion,2);assert.equal(first.status,'indexing');assert.equal(first.batch.cached,1);assert.equal(first.batch.hashed,0);
 const resumed=await finish(app,workspace);assert.equal(resumed.result.files,3);assert.equal(resumed.hashed,0);
 const check=openIndex(workspace,true);try{assert.equal(check.prepare('SELECT count(*) n FROM files').get().n,3);}finally{check.close();}
});
test('failed queued files do not starve later work and can be retried or refreshed after changes',async t=>{
 const {app,workspace}=await fixture(t);await files(app,4);
 const first=await survey(app,{workspace,maxFiles:1,onProgress:async p=>{if(p.phase==='directory-listed')await rm(path.join(app,'000000.mjs'));}});
 assert.equal(first.failed,1);assert.equal(first.status,'indexing');
 const rest=await survey(app,{workspace,maxFiles:10});assert.equal(rest.status,'partial');assert.equal(rest.batch.hashed,3);assert.equal(rest.batch.processed,3);
 await writeFile(path.join(app,'000000.mjs'),'export const recovered=true;');const retried=await survey(app,{workspace});assert.equal(retried.status,'indexed');assert.equal(retried.batch.hashed,1);assert.equal(retried.files,4);
 await rm(path.join(app,'000000.mjs'));const refreshed=await survey(app,{workspace,refresh:true});assert.equal(refreshed.files,3);assert.equal(refreshed.failed,0);
});
test('direct-file revisions still detect changes and failed-to-symlink retries remove stale file errors',async t=>{
 const {root,app,workspace}=await fixture(t);const selected=path.join(app,'single.mjs');await writeFile(selected,'export const a=1;');await survey(selected,{workspace});
 await writeFile(selected,'export const b=20;');const changed=await survey(selected,{workspace});assert.equal(changed.batch.hashed,1);assert.equal((await indexedFile(workspace,'single.mjs')).sha256,(await queryIndex(workspace)).items[0].sha256);
 const directoryWork=path.join(root,'directory-work');const broken=await survey(app,{workspace:directoryWork,onProgress:async p=>{if(p.phase==='directory-listed')await rm(selected);}});assert.equal(broken.status,'partial');
 await symlink(path.join(root,'directory-work/index.sqlite'),selected);const retried=await survey(app,{workspace:directoryWork});assert.equal(retried.status,'indexed');assert.equal(retried.files,0);
});
test('CLI inventory emits progress to stderr and retains a single JSON result on stdout',async t=>{
 const {app,workspace}=await fixture(t);await files(app,3);await mkdir(path.join(app,'empty'));
 const cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
 async function run(args){const child=spawn(process.execPath,[cli,...args],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',d=>{stdout+=d;});child.stderr.on('data',d=>{stderr+=d;});const [code]=await once(child,'close');assert.equal(code,0,stderr);return{result:JSON.parse(stdout),progress:stderr.split('\n').filter(l=>l.startsWith('{')).map(l=>JSON.parse(l))};}
 const first=await run(['survey',app,'--workspace',workspace,'--max-files','1','--max-directories','1','--progress']);assert.equal(first.result.status,'indexing');assert.equal(first.result.batch.processed,1);assert.equal(first.result.pendingDirectories,1);assert.equal(first.progress[0].schema,'carve/survey-progress@1');
 const resumed=await run(['survey',app,'--workspace',workspace,'--max-directories','1']);assert.equal(resumed.result.status,'indexed');assert.equal(resumed.result.files,3);assert.equal(resumed.result.batch.enumeratedEntries,0);
});
