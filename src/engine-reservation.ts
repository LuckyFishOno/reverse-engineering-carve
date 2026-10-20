import {randomUUID} from 'node:crypto';
import {mkdir,lstat,realpath} from 'node:fs/promises';
import {userInfo} from 'node:os';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';
import {processIdentity,processIsLive,type ProcessIdentity} from './process-inspection.js';
import type {ResolvedEngineResources} from './engine-resources.js';

// One per-user registry shared by every RECarve process on this host: CLI calls, MCP servers,
// queue runners and background workers. Rows belong to a live process identity; rows whose
// owner is verifiably gone are reclaimed, and uninspectable owners are kept conservatively.
// The default location comes from the account's home directory in the user database, not from
// TMPDIR/HOME/XDG variables, because launchers (agent sandboxes, MCP hosts, schedulers) give
// processes of the same user different environments and a per-environment registry would let
// each of them reserve the whole host budget. CARVE_ENGINE_RESERVATIONS is an explicit override
// that every cooperating process must share; the registry path is reported with each reservation.
export interface HeapReservation {id:string;registry:string;heapMiB:number;reservedByOthersMiB:number;hostLimitMiB:number;reclaimedStale:number;release:()=>void}
export function defaultReservationDirectory(){
  const home=userInfo().homedir;if(!home||!path.isAbsolute(home))throw new Error('Cannot determine this account\'s home directory for the engine reservation registry; set CARVE_ENGINE_RESERVATIONS.');
  return process.platform==='darwin'?path.join(home,'Library/Caches/carve/engine-reservations'):path.join(home,'.cache/carve/engine-reservations');
}
export async function reservationRegistry(){
  const directory=path.resolve(process.env.CARVE_ENGINE_RESERVATIONS??defaultReservationDirectory());
  await mkdir(directory,{recursive:true,mode:0o700});
  const info=await lstat(directory);
  if(!info.isDirectory()||info.isSymbolicLink()||(typeof process.getuid==='function'&&info.uid!==process.getuid())||(info.mode&0o077))throw new Error('Engine reservation directory must be a private directory owned by this user: '+directory);
  const file=path.join(await realpath(directory),'heap.sqlite');
  try{if((await lstat(file)).isSymbolicLink())throw new Error('Engine reservation database cannot be a symlink.');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  return file;
}
const open=(file:string)=>{const db=new DatabaseSync(file);db.exec('PRAGMA busy_timeout=5000;PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS reservations(id TEXT PRIMARY KEY,owner TEXT NOT NULL,heap INTEGER NOT NULL,engine TEXT NOT NULL,workspace TEXT NOT NULL,created TEXT NOT NULL);');return db;};
async function alive(owner:string){try{return await processIsLive(JSON.parse(owner) as ProcessIdentity);}catch{return true;}}
export async function reserveEngineHeap(resources:ResolvedEngineResources,context:{engine:string;workspace:string}):Promise<HeapReservation>{
  const registry=await reservationRegistry(),owner=await processIdentity();if(!owner)throw new Error('Cannot establish this process identity for an engine heap reservation.');
  const db=open(registry);let retained=false;
  try{
    // Liveness needs ps, so it is inspected before the short write transaction.
    const dead=new Set<string>();
    for(const row of db.prepare('SELECT id,owner FROM reservations').all() as {id:string;owner:string}[])if(!await alive(row.owner))dead.add(row.id);
    db.exec('BEGIN IMMEDIATE');let inTransaction=true;
    try{
      let reclaimed=0;for(const id of dead)reclaimed+=Number(db.prepare('DELETE FROM reservations WHERE id=?').run(id).changes);
      const others=Number((db.prepare('SELECT COALESCE(SUM(heap),0) n FROM reservations').get() as {n:number}).n);
      if(others+resources.heapMiB>resources.host.heapLimitMiB){
        db.exec('ROLLBACK');inTransaction=false;
        throw new Error(`Engine heap budget busy: ${others} MiB is reserved by running RECarve engine launches on this host; ${resources.heapMiB} MiB more exceeds the ${resources.host.heapLimitMiB} MiB host limit. Retry after they finish or request less heap.`);
      }
      const id=randomUUID();db.prepare('INSERT INTO reservations VALUES(?,?,?,?,?,?)').run(id,JSON.stringify(owner),resources.heapMiB,context.engine,context.workspace,new Date().toISOString());db.exec('COMMIT');inTransaction=false;
      let released=false;retained=true;
      return{id,registry,heapMiB:resources.heapMiB,reservedByOthersMiB:others,hostLimitMiB:resources.host.heapLimitMiB,reclaimedStale:reclaimed,
        release:()=>{if(released)return;released=true;try{db.prepare('DELETE FROM reservations WHERE id=?').run(id);}finally{db.close();}}};
    }catch(error){if(inTransaction)db.exec('ROLLBACK');throw error;}
  }finally{if(!retained)db.close();}
}
export async function listEngineReservations(){
  const registry=await reservationRegistry();const db=open(registry);
  try{return{registry,items:(db.prepare('SELECT * FROM reservations ORDER BY created,id').all() as Record<string,any>[]).map(r=>({...r,owner:JSON.parse(r.owner)}))};}finally{db.close();}
}
