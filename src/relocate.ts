import {lstat,readFile,readdir,realpath,rename,writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {DatabaseSync} from 'node:sqlite';
import {claim,hashFile,metaValue,openIndex,recordedWorkspace,setMetaValue} from './survey.js';

// A workspace records absolute paths: its target binding, container lineage and the evidence files
// of every observation. Relocation rewrites exactly those live records after a move, verifies every
// rewritten evidence file against its recorded hash before committing, and leaves history (queue
// results, run logs, task reports, verification archives) as it was recorded.
export interface RelocateOptions {target?:string;from?:string;signal?:AbortSignal;authorizePath?:(file:string,newPath:boolean)=>Promise<unknown>}
type Row=Record<string,any>;
const missing=(error:unknown)=>(error as NodeJS.ErrnoException).code==='ENOENT';
async function exists(file:string){try{await lstat(file);return true;}catch(error){if(missing(error))return false;throw error;}}
const within=(root:string,item:string)=>item===root||item.startsWith(root+path.sep);
// Keeps a recorded path's position relative to the workspace, as when a project folder moves whole.
const carried=(from:string,to:string,item:string)=>path.join(to,path.relative(from,item));
const hasTable=(db:DatabaseSync,name:string)=>Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name));
async function replaceJson(file:string,value:unknown){const temporary=`${file}.${process.pid}.tmp`;await writeFile(temporary,JSON.stringify(value,null,2));await rename(temporary,file);}

export async function relocateWorkspace(input:string,options:RelocateOptions={}){
  const authorize=async(file:string,newPath=false)=>{options.signal?.throwIfAborted();await options.authorizePath?.(file,newPath);};
  const workspace=await realpath(input);await authorize(workspace);const markerFile=path.join(workspace,'.carve-workspace.json');
  // MCP checks every live path, including existing SQLite sidecars, before writes.
  for(const name of ['.carve-workspace.json','index.sqlite','index.sqlite-wal','index.sqlite-shm','survey.json','.scan.lock'])await authorize(path.join(workspace,name),name!=='.carve-workspace.json'&&name!=='index.sqlite');
  let marker:Row;try{marker=JSON.parse(await readFile(markerFile,'utf8'));}catch(error){if(missing(error))throw new Error('Not a Carve workspace: '+workspace);throw error;}
  if(marker.schema!=='carve/workspace@1'||typeof marker.target!=='string')throw new Error('Not a Carve workspace: '+workspace);
  const release=await claim(workspace);let db:DatabaseSync|undefined;
  try{
    db=openIndex(workspace);const index=db;
    const from=options.from?path.resolve(options.from):await recordedWorkspace(db,workspace);
    if(!from||!path.isAbsolute(from))throw new Error('This workspace does not record where it was created. Pass --from with its previous absolute path.');
    if((hasTable(db,'analysis_jobs')&&db.prepare("SELECT 1 FROM analysis_jobs WHERE status='running'").get())||(hasTable(db,'analysis_runs')&&db.prepare("SELECT 1 FROM analysis_runs WHERE status IN ('starting','running','cancelling')").get()))
      throw new Error('Analysis is running in this workspace. Relocate after queued and background work is terminal.');

    const oldTarget=(metaValue(db,'target') as string|undefined)??marker.target,isDirectory=Boolean(metaValue(db,'isDirectory'));
    let target:string;
    if(options.target)target=await realpath(options.target);
    else if(await exists(oldTarget))target=await realpath(oldTarget);
    else{
      const candidate=carried(from,workspace,oldTarget);
      if(!await exists(candidate))throw new Error(`Recorded target ${oldTarget} no longer exists and is not at ${candidate}, its position relative to the moved workspace. Pass --target with its new location${from===workspace?', or --from if this workspace moved and its recorded previous location is wrong':''}.`);
      target=await realpath(candidate);
    }
    await authorize(target);
    if(target===workspace)throw new Error('The analysis workspace must differ from the target.');
    if((await lstat(target)).isDirectory()!==isDirectory)throw new Error(`The new target must be a ${isDirectory?'directory':'regular file'}, like the surveyed one.`);
    const root=isDirectory?target:path.dirname(target);await authorize(root);

    // Sizes are checked for every indexed file; bytes are rehashed again whenever one is selected.
    const files=db.prepare('SELECT path,bytes,sha256 FROM files WHERE seen=? AND sha256 IS NOT NULL AND error IS NULL ORDER BY path').all(metaValue(db,'epoch')) as Row[];
    const changed:string[]=[];
    for(const row of files){
      if(options.signal?.aborted)throw new Error('Relocation cancelled; nothing was changed.');
      await authorize(path.join(root,row.path),true);
      try{const info=await lstat(path.join(root,row.path));if(!info.isFile()||info.size!==row.bytes)changed.push(row.path);}catch(error){if(!missing(error))throw error;changed.push(row.path);}
    }
    if(!isDirectory&&!changed.length&&files[0]&&(await hashFile(target,options.signal)).sha256!==files[0].sha256)changed.push(files[0].path);
    if(changed.length)throw new Error(`${changed.length} indexed file(s) are missing or differ at the new target (first: ${changed[0]}). Survey that location into a new workspace instead.`);

    let container=metaValue(db,'container') as Row|undefined;
    if(container){
      const lineageFile=path.join(path.dirname(root),'.carve-container.json');await authorize(lineageFile);let lineage:Row;
      try{lineage=JSON.parse(await readFile(lineageFile,'utf8'));}catch(error){if(missing(error))throw new Error(`Container lineage ${lineageFile} is missing at the new target.`);throw error;}
      if(lineage.schema!=='carve/container@1'||lineage.content!==root)throw new Error(`Relocate the container workspace that unpacked this inventory first: ${lineageFile} still names ${lineage.content}.`);
      container={...lineage,memberIndex:path.join(path.dirname(root),'members.sqlite')};
      await authorize(container.workspace);await authorize(container.memberIndex);
    }
    const caches:{file:string;value:Row}[]=[];
    await authorize(path.join(workspace,'containers'),true);
    let names:string[]=[];try{names=await readdir(path.join(workspace,'containers'));}catch(error){if(!missing(error))throw error;}
    for(const name of names.sort()){
      const file=path.join(workspace,'containers',name,'.carve-container.json');await authorize(file,true);if(!await exists(file))continue;
      const value=JSON.parse(await readFile(file,'utf8'));if(value.schema!=='carve/container@1'||value.original?.sha256!==name)throw new Error('Unrecognized container cache marker: '+file);
      const content=path.join(workspace,'containers',name,'content');if(value.workspace!==workspace||value.content!==content)caches.push({file,value:{...value,workspace,content}});
    }

    const moves:{from:string;to:string}[]=[];let outside=0;const lost:string[]=[];
    if(hasTable(db,'observations'))for(const row of db.prepare('SELECT DISTINCT evidence,evidence_sha256 FROM observations WHERE evidence IS NOT NULL ORDER BY evidence').all() as Row[]){
      // Evidence normally lives in this workspace. Anything else must still exist where it was recorded;
      // a pre-0.24 survey run after a move can leave the wrong previous location in survey.json.
      if(from===workspace||!within(from,row.evidence)){outside++;await authorize(row.evidence,true);if(!await exists(row.evidence))lost.push(row.evidence);continue;}
      const next=carried(from,workspace,row.evidence);await authorize(next);let current;
      try{current=await hashFile(next,options.signal);}catch(error){if(missing(error))throw new Error(`Recorded evidence ${row.evidence} is not at ${next}; nothing was changed.`);throw error;}
      if(current.sha256!==row.evidence_sha256)throw new Error(`Evidence ${next} does not match its recorded hash; nothing was changed.`);
      moves.push({from:row.evidence,to:next});
    }

    if(lost.length)throw new Error(`${lost.length} recorded evidence file(s) are not under the previous location ${from} and no longer exist (first: ${lost[0]}). Pass --from with the workspace's previous absolute path; nothing was changed.`);
    // Validate marker destinations and their temporary files before committing the index.
    for(const file of [...(marker.target!==target?[markerFile]:[]),...caches.map(c=>c.file)]){await authorize(file);await authorize(`${file}.${process.pid}.tmp`,true);}
    options.signal?.throwIfAborted();
    let rows=0;
    db.exec('BEGIN IMMEDIATE');
    try{
      if(moves.length){const update=index.prepare('UPDATE observations SET evidence=? WHERE evidence=?');for(const move of moves)rows+=Number(update.run(move.to,move.from).changes);}
      setMetaValue(index,'target',target);setMetaValue(index,'root',root);setMetaValue(index,'workspace',workspace);if(container)setMetaValue(index,'container',container);
      index.prepare('INSERT INTO events(time,kind,detail) VALUES(?,?,?)').run(new Date().toISOString(),'relocate',JSON.stringify({from,to:workspace,target:{from:oldTarget,to:target},evidenceFiles:moves.length,evidenceRows:rows,containerCaches:caches.length}));
      index.exec('COMMIT');
    }catch(error){index.exec('ROLLBACK');throw error;}
    // Files follow the committed index; rerunning relocation repairs them if this step is interrupted.
    if(marker.target!==target)await replaceJson(markerFile,{...marker,target});
    for(const cache of caches)await replaceJson(cache.file,cache.value);
    return{schema:'carve/relocation@1',workspace,from,moved:from!==workspace,target:{from:oldTarget,to:target,changed:oldTarget!==target},
      inventory:{files:files.length,check:'Every indexed file exists at the new target with its recorded size; a file target is rehashed. Selected files are still rehashed before analysis.'},
      evidence:{files:moves.length,rows,hashVerified:true,outsideWorkspace:outside},containerLineage:Boolean(container),containerCaches:caches.length,
      unchanged:'Historical queue results, run logs, task reports, engine logs and verification archives keep the paths recorded at the time.'};
  }finally{db?.close();await release();}
}
