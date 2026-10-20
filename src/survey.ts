import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { open, mkdir, realpath, lstat, opendir, readFile, writeFile, unlink, readdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { identifyFormat } from './formats.js';
import { inside } from './modules.js';

type Row = Record<string, any>;
export function openIndex(workspace: string, readOnly = false) {
  const db = new DatabaseSync(path.join(workspace, 'index.sqlite'), { readOnly });
  db.exec('PRAGMA busy_timeout=1500;');
  if (!readOnly) db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS dirs (path TEXT PRIMARY KEY,status TEXT NOT NULL,error TEXT);
    CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY,bytes REAL,mtime REAL,ctime REAL,sha256 TEXT,format TEXT,family TEXT,backend TEXT,facts TEXT,hash_mode TEXT,seen TEXT,error TEXT);
    CREATE INDEX IF NOT EXISTS files_backend ON files(backend,path);
    CREATE INDEX IF NOT EXISTS files_revision ON files(seen,format);
    CREATE INDEX IF NOT EXISTS dirs_status ON dirs(status,path);
    CREATE TABLE IF NOT EXISTS pending_files(path TEXT PRIMARY KEY,status TEXT NOT NULL,error TEXT);
    CREATE INDEX IF NOT EXISTS pending_files_status ON pending_files(status,path);
    CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY,time TEXT,kind TEXT,detail TEXT);`);
  return db;
}
const get = (db: DatabaseSync, key: string) => { const row = db.prepare('SELECT value FROM meta WHERE key=?').get(key) as Row | undefined; return row ? JSON.parse(row.value) : undefined; };
const put = (db: DatabaseSync, key: string, value: unknown) => db.prepare('INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)').run(key, JSON.stringify(value));
export { get as metaValue, put as setMetaValue };
// The directory a workspace was created in, or last relocated to. Workspaces made before 0.24
// recorded it only in their survey report.
export async function recordedWorkspace(db: DatabaseSync, workspace: string): Promise<string | undefined> {
  const stored = get(db, 'workspace'); if (typeof stored === 'string') return stored;
  try { const report = JSON.parse(await readFile(path.join(workspace, 'survey.json'), 'utf8')); return typeof report.workspace === 'string' ? report.workspace : undefined; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw error; }
}
// Evidence paths and container lineage are recorded as absolute paths, so a moved workspace must be
// relocated before new analysis mixes old and new locations.
export async function assertWorkspaceInPlace(workspace: string, db?: DatabaseSync) {
  let own: DatabaseSync | undefined;
  if (!db) { try { await lstat(path.join(workspace, 'index.sqlite')); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; } own = db = openIndex(workspace, true); }
  try {
    const recorded = await recordedWorkspace(db, workspace);
    if (recorded && recorded !== workspace) throw new Error(`Workspace was moved from ${recorded} to ${workspace}. Run "carve relocate ${workspace}" first; its recorded evidence and target paths still name the old location.`);
  } finally { own?.close(); }
}
export async function hashFile(input: string, signal?:AbortSignal) {
  const handle = await open(input, 'r');
  try {
    const before = await handle.stat(); if (!before.isFile()) throw new Error('Selected target is not a regular file.');
    const hash = createHash('sha256'); const buffer = Buffer.allocUnsafe(Math.max(1, Math.min(1024 * 1024, before.size))); const prefix = Buffer.alloc(Math.min(before.size, 65536));
    let position = 0;
    while (true) {
      if(signal?.aborted)throw new Error('File hashing cancelled.');
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position); if (!bytesRead) break;
      if (position < prefix.length) buffer.copy(prefix, position, 0, Math.min(bytesRead, prefix.length - position));
      hash.update(buffer.subarray(0, bytesRead)); position += bytesRead;
    }
    const after = await handle.stat();
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || position !== before.size) throw new Error('Target changed while hashing; retry after it stops changing.');
    return { sha256: hash.digest('hex'), bytes: position, mtime: before.mtimeMs, ctime: before.ctimeMs, facts: identifyFormat(prefix, input) };
  } finally { await handle.close(); }
}
export async function claim(workspace: string, filename = '.scan.lock') {
  if (!/^\.[a-zA-Z0-9-]+\.lock$/.test(filename)) throw new Error('Invalid lock name.');
  const lock = path.join(workspace, filename);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await open(lock, 'wx'); await handle.writeFile(JSON.stringify({ pid: process.pid })); await handle.close();
      return async () => { await unlink(lock).catch(() => {}); };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const previous = JSON.parse(await readFile(lock, 'utf8'));
      try { process.kill(previous.pid, 0); throw new Error('A scan is already running for this workspace.'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error; }
      await unlink(lock);
    }
  }
  throw new Error('Cannot acquire workspace scan lock.');
}
export interface SurveyProgress { phase:'listing'|'directory-listed'|'files';workspace:string;directory?:string;enumeratedEntries:number;processedFiles:number }
export interface SurveyOptions { workspace:string;maxFiles?:number;maxDirectories?:number;refresh?:boolean;signal?:AbortSignal;onProgress?:(progress:SurveyProgress)=>void|Promise<void> }
export async function survey(input:string,options:SurveyOptions){
  const maxFiles=options.maxFiles??10000,maxDirectories=options.maxDirectories??1000;
  if(!Number.isInteger(maxFiles)||maxFiles<1||maxFiles>1000000)throw new Error('maxFiles must be 1–1000000 per batch.');
  if(!Number.isInteger(maxDirectories)||maxDirectories<1||maxDirectories>1000000)throw new Error('maxDirectories must be 1–1000000 per batch.');
  const abort=()=>{if(options.signal?.aborted)throw new Error('Survey cancelled; committed directory/file checkpoints are retained.');};abort();
  const target=await realpath(input);const info=await lstat(target);
  if(!info.isFile()&&!info.isDirectory())throw new Error('Survey needs a regular file or directory.');
  await mkdir(options.workspace,{recursive:true});const workspace=await realpath(options.workspace);
  if(workspace===target)throw new Error('The analysis workspace must differ from the input directory.');
  const release=await claim(workspace);let db:DatabaseSync|undefined;
  let processed=0,hashed=0,cached=0,skipped=0,enumeratedEntries=0,listedDirectories=0,directoryAttempts=0;
  let progressFailed=false;
  const progress=async(phase:SurveyProgress['phase'],directory?:string)=>{
    try{if(options.onProgress)await options.onProgress({phase,workspace,directory,enumeratedEntries,processedFiles:processed});}
    catch(error){progressFailed=true;throw error;}abort();
  };
  try{
    const marker=path.join(workspace,'.carve-workspace.json');
    try{const identity=JSON.parse(await readFile(marker,'utf8'));if(identity.schema!=='carve/workspace@1')throw new Error('Workspace belongs to another target or is not a RECarve workspace.');await assertWorkspaceInPlace(workspace);if(identity.target!==target)throw new Error('Workspace belongs to another target or is not a RECarve workspace. If the same target moved, run carve relocate with --target.');}
    catch(error){
      if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
      if((await readdir(workspace)).some(name=>name!=='.scan.lock'))throw new Error('Use a new or empty analysis workspace; existing files are preserved.');
      await writeFile(marker,JSON.stringify({schema:'carve/workspace@1',target},null,2),{flag:'wx'});
    }
    db=openIndex(workspace);const indexDb=db;
    if(get(db,'target')&&get(db,'target')!==target)throw new Error('Workspace belongs to another target. Choose a new workspace.');
    const root=info.isDirectory()?target:path.dirname(target);
    put(db,'target',target);put(db,'root',root);put(db,'isDirectory',info.isDirectory());put(db,'workspace',workspace);
    try{
      const markerPath=path.join(path.dirname(root),'.carve-container.json');if((await lstat(markerPath)).size>1048576)throw new Error('Container lineage marker exceeds 1 MiB.');
      const container=JSON.parse(await readFile(markerPath,'utf8'));if(container.schema==='carve/container@1'&&container.content===root)put(db,'container',{...container,memberIndex:path.join(path.dirname(root),'members.sqlite')});
    }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    let epoch=get(db,'epoch') as string|undefined;const previousStatus=get(db,'status');
    if(!epoch||options.refresh||get(db,'inventoryVersion')!==2){
      epoch=randomUUID();db.exec('BEGIN');
      try{db.exec('DELETE FROM dirs;DELETE FROM pending_files;');put(db,'epoch',epoch);put(db,'inventoryVersion',2);put(db,'status','indexing');if(info.isDirectory())db.prepare("INSERT INTO dirs(path,status) VALUES('.','queued')").run();db.exec('COMMIT');}
      catch(error){db.exec('ROLLBACK');throw error;}
    }else{
      // Retry failed work only after other queued work finished, avoiding starvation.
      db.prepare("UPDATE pending_files SET status='queued' WHERE status='running'").run();
      db.prepare("UPDATE dirs SET status='queued' WHERE status IN ('running','listing')").run();
      if(previousStatus==='partial'){db.prepare("UPDATE pending_files SET status='queued' WHERE status='failed'").run();db.prepare("UPDATE dirs SET status='queued' WHERE status='failed'").run();}
    }
    put(db,'status','indexing');
    const upsert=db.prepare('INSERT OR REPLACE INTO files(path,bytes,mtime,ctime,sha256,format,family,backend,facts,hash_mode,seen,error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)');
    const enqueue=db.prepare("INSERT OR IGNORE INTO pending_files(path,status) SELECT ?,'queued' WHERE NOT EXISTS(SELECT 1 FROM files WHERE path=? AND seen=? AND error IS NULL)");
    const previousFile=db.prepare('SELECT * FROM files WHERE path=?');
    const cacheFile=db.prepare("UPDATE files SET seen=?,hash_mode='metadata-cache' WHERE path=?");
    const removeFile=db.prepare('DELETE FROM files WHERE path=?');
    const finishFile=db.prepare('DELETE FROM pending_files WHERE path=?');
    const failFile=db.prepare("UPDATE pending_files SET status='failed',error=? WHERE path=?");
    const addDirectory=db.prepare("INSERT OR IGNORE INTO dirs(path,status) VALUES(?,'queued')");
    const nextFile=db.prepare("SELECT path FROM pending_files WHERE status='queued' ORDER BY path LIMIT 1");
    const startFile=db.prepare("UPDATE pending_files SET status='running' WHERE path=?");
    const nextDirectory=db.prepare("SELECT path FROM dirs WHERE status='queued' ORDER BY path LIMIT 1");
    async function indexFile(relative:string,queued:boolean){
      abort();let stats:Awaited<ReturnType<typeof lstat>>|undefined;let result:Awaited<ReturnType<typeof hashFile>>|undefined;let old:Row|undefined;let errorText:string|null=null;let ignored=false;let unchanged=false;let metadataCache=false;
      try{
        const file=path.join(root,relative);const actual=await realpath(file);stats=await lstat(file);
        if(!inside(root,actual)||stats.isSymbolicLink()){ignored=true;skipped++;}
        else{
          if(!stats.isFile())throw new Error('Queued file changed type; refresh the inventory.');
          old=previousFile.get(relative) as Row|undefined;
          const metadataMatch=old?.sha256&&old.bytes===stats.size&&old.mtime===stats.mtimeMs&&old.ctime===stats.ctimeMs&&!old.error;
          if(metadataMatch){unchanged=old!.seen===epoch;metadataCache=!unchanged;}
          else result=await hashFile(file,options.signal);
        }
      }catch(error){if(options.signal?.aborted)throw error;errorText=(error as Error).message;}
      abort();
      indexDb.exec('BEGIN');
      try{
        if(errorText)upsert.run(relative,stats?.size??null,stats?.mtimeMs??null,stats?.ctimeMs??null,null,'unknown','data','none','{}','failed',epoch!,errorText);
        else if(result){upsert.run(relative,result.bytes,result.mtime,result.ctime,result.sha256,result.facts.format,result.facts.family,result.facts.backend,JSON.stringify(result.facts),'streamed-sha256',epoch!,null);hashed++;}
        else if(metadataCache){cacheFile.run(epoch!,relative);cached++;}
        else if(ignored)removeFile.run(relative);
        if(queued){if(errorText)failFile.run(errorText,relative);else finishFile.run(relative);}
        indexDb.exec('COMMIT');
      }catch(error){indexDb.exec('ROLLBACK');throw error;}
      if(queued||!unchanged||ignored||errorText)processed++;
      if(processed&&processed%1000===0)await progress('files');
    }
    async function listDirectory(relative:string){
      const folder=path.join(root,relative);directoryAttempts++;
      indexDb.prepare("UPDATE dirs SET status='listing',error=NULL WHERE path=?").run(relative);
      let transaction=false;let buffered=0;
      const begin=()=>{if(!transaction){indexDb.exec('BEGIN');transaction=true;}};
      const commit=()=>{if(transaction){indexDb.exec('COMMIT');transaction=false;}};
      try{
        const actual=await realpath(folder);if(!inside(root,actual)||(await lstat(folder)).isSymbolicLink())throw new Error('Directory follows a symlink or escapes the target.');
        for await(const entry of await opendir(folder)){
          abort();begin();enumeratedEntries++;buffered++;
          const child=path.posix.join(relative,entry.name),full=path.join(root,child);
          if(entry.isSymbolicLink()||entry.name==='.git'||full===workspace)skipped++;
          else if(entry.isDirectory())addDirectory.run(child);
          else if(entry.isFile())enqueue.run(child,child,epoch!);
          if(buffered>=1000){commit();buffered=0;await progress('listing',relative);}
        }
        begin();indexDb.prepare("UPDATE dirs SET status='listed',error=NULL WHERE path=?").run(relative);commit();listedDirectories++;await progress('directory-listed',relative);
      }catch(error){
        // Already enumerated entries survive cancellation/crash; only incomplete listings replay.
        commit();indexDb.prepare('UPDATE dirs SET status=?,error=? WHERE path=?').run(options.signal?.aborted||progressFailed?'queued':'failed',(error as Error).message,relative);
        if(options.signal?.aborted||progressFailed)throw error;
      }
    }
    if(info.isFile())await indexFile(path.basename(target),false);
    else while(processed<maxFiles){
      abort();const file=nextFile.get() as Row|undefined;
      if(file){startFile.run(file.path);await indexFile(file.path,true);continue;}
      if(directoryAttempts>=maxDirectories)break;
      const directory=nextDirectory.get() as Row|undefined;if(!directory)break;
      await listDirectory(directory.path);
    }
    const pendingDirectories=Number((db.prepare("SELECT count(*) n FROM dirs WHERE status IN ('queued','listing','running')").get() as Row).n);
    const pendingFiles=Number((db.prepare("SELECT count(*) n FROM pending_files WHERE status IN ('queued','running')").get() as Row).n);
    const failures=Number((db.prepare('SELECT count(*) n FROM files WHERE seen=? AND error IS NOT NULL').get(epoch) as Row).n)+Number((db.prepare("SELECT count(*) n FROM dirs WHERE status='failed'").get() as Row).n);
    const status=pendingDirectories||pendingFiles?'indexing':failures?'partial':'indexed';put(db,'status',status);
    if(status==='indexed')db.prepare('DELETE FROM files WHERE seen<>?').run(epoch);
    const batch={processed,hashed,cached,skipped,listedDirectories,directoryAttempts,enumeratedEntries};
    db.prepare('INSERT INTO events(time,kind,detail) VALUES(?,?,?)').run(new Date().toISOString(),'survey',JSON.stringify({status,...batch}));
    const count=Number((db.prepare('SELECT count(*) n FROM files WHERE seen=?').get(epoch) as Row).n);
    const formats=db.prepare('SELECT format,count(*) count,sum(bytes) bytes FROM files WHERE seen=? GROUP BY format ORDER BY count DESC').all(epoch);
    const result={schema:'carve/survey@1',workspace,target,status,revision:epoch,inventoryVersion:2,executesTarget:false,files:count,pendingDirectories,pendingFiles,failed:failures,batch,formats,
      cacheTrust:'Metadata cache accelerates inventory only. Every selected binary must be fully rehashed before analysis or reuse.',
      listingScope:'Each directory is listed once to a disk queue per revision. A single directory finishes as one unit; only interrupted listings may replay. Inventory is not an atomic filesystem snapshot.',
      nextAction:status==='indexing'?'Run the same survey command to resume queued files/directories.':status==='partial'?'Inspect errors; repeating retries failed work, or refresh after source changes.':'Query the index for components; analysis/reconstruction remain separate evidence-producing stages.'};
    const report=path.join(workspace,`.survey-${process.pid}.tmp`);await writeFile(report,JSON.stringify(result,null,2)+'\n');await rename(report,path.join(workspace,'survey.json'));return result;
  }catch(error){
    if(db&&options.signal?.aborted)db.prepare('INSERT INTO events(time,kind,detail) VALUES(?,?,?)').run(new Date().toISOString(),'survey-interrupted',JSON.stringify({processed,enumeratedEntries}));
    abort();throw error;
  }finally{db?.close();await release();}
}
export async function queryIndex(workspace: string, options: { query?: string; backend?: string; limit?: number; offset?: number } = {}) {
  const root = await realpath(workspace); const limit=options.limit??50;const offset=options.offset??0;
  if (!Number.isInteger(limit)||limit<1||limit>200||!Number.isInteger(offset)||offset<0) throw new Error('Use limit 1–200 and a nonnegative offset.');
  const db=openIndex(root,true);
  try {
    const clauses=['seen=?'];const args:(string|number)[]=[get(db,'epoch')];
    if(options.query){clauses.push("path LIKE ? ESCAPE '\\'");args.push('%'+options.query.replace(/[\\%_]/g,'\\$&')+'%');}
    if(options.backend){clauses.push('backend=?');args.push(options.backend);}
    const where=clauses.join(' AND ');const rows=db.prepare('SELECT * FROM files WHERE '+where+' ORDER BY path LIMIT ? OFFSET ?').all(...args,limit,offset) as Row[];
    const total=Number((db.prepare('SELECT count(*) n FROM files WHERE '+where).get(...args) as Row).n);
    return {schema:'carve/index-page@1',workspace:root,target:get(db,'target'),root:get(db,'root'),inventoryStatus:get(db,'status'),total,limit,offset,
      items:rows.map((row):Row=>({...row,facts:JSON.parse(row.facts)})),nextOffset:offset+rows.length<total?offset+rows.length:null};
  } finally {db.close();}
}
export async function indexedFile(workspace: string, relative: string, signal?:AbortSignal) {
  if (!relative || path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').includes('..')) throw new Error('Choose an indexed relative path.');
  const db=openIndex(await realpath(workspace),true);
  try {
    await assertWorkspaceInPlace(await realpath(workspace),db);
    const row=db.prepare('SELECT * FROM files WHERE path=? AND seen=?').get(relative,get(db,'epoch')) as Row|undefined;
    if (!row || !row.sha256 || row.error) throw new Error('File is not successfully indexed in the current survey.');
    const root=get(db,'root') as string;const file=await realpath(path.join(root,relative));
    if(!inside(root,file)||(await lstat(path.join(root,relative))).isSymbolicLink())throw new Error('Selected file escapes inventory or follows a symlink.');
    const current=await hashFile(file,signal);if(current.sha256!==row.sha256)throw new Error('Selected input changed since inventory. Refresh the survey before analysis.');
    const container=get(db,'container');
    if(container){
      const members=new DatabaseSync(container.memberIndex,{readOnly:true});
      try{const member=members.prepare("SELECT sha256 FROM members WHERE path=? AND kind='file'").get(relative) as Row|undefined;if(member?.sha256!==current.sha256)throw new Error('Selected member bytes do not match the recorded container extraction.');}finally{members.close();}
    }
    return {path:file,relative,sha256:current.sha256,bytes:current.bytes,facts:current.facts,...(container?{container:{workspace:container.workspace,file:container.original.file,sha256:container.original.sha256,member:relative,memberSha256:current.sha256}}:{})};
  }finally{db.close();}
}
