import {randomUUID} from 'node:crypto';
import {lstat,realpath} from 'node:fs/promises';
import path from 'node:path';
import {DatabaseSync} from 'node:sqlite';

import {processIdentity,processIsLive,processGroupMembers,type ToolProcess,type ProcessIdentity} from './process-inspection.js';
export {processIdentity,processIsLive,processGroupMembers,type ToolProcess,type ProcessIdentity} from './process-inspection.js';
export class LeaseBusyError extends Error {}
export interface ProcessLease {
  token:string;owner:ProcessIdentity;directory:string;name:string;
  register:(guard:ToolProcess)=>Promise<void>;
  handoff:(owner:ProcessIdentity)=>Promise<void>;
  release:()=>void;
}
function leaseHandle(db:DatabaseSync,directory:string,name:string,token:string,owner:ProcessIdentity):ProcessLease{
  let closed=false;
  return{token,owner,directory,name,
    register:async guard=>{
      if(closed||guard.processGroup===null||guard.processGroup!==guard.pid||!guard.guardedStart)throw new Error('Invalid guarded engine process registration.');
      const old=db.prepare('SELECT guard FROM leases WHERE name=? AND token=?').get(name,token) as {guard:string|null}|undefined;
      if(old?.guard){const previous=JSON.parse(old.guard) as ToolProcess;if(previous.supervisor&&await processIsLive(previous.supervisor))throw new LeaseBusyError('Previous analysis supervisor is still alive.');if(previous.processGroup!==guard.processGroup&&previous.processGroup!==null&&(await processGroupMembers(previous.processGroup)).length)throw new LeaseBusyError('Previous engine process group is still alive.');}
      if(!db.prepare('UPDATE leases SET guard=? WHERE name=? AND token=? AND finished=0').run(JSON.stringify(guard),name,token).changes)throw new Error('Analysis lease ownership changed.');
    },
    handoff:async next=>{
      if(closed||!await processIsLive(next))throw new Error('Cannot hand off to an absent or uninspectable worker.');
      if(!db.prepare('UPDATE leases SET owner=? WHERE name=? AND token=? AND finished=0 AND guard IS NULL').run(JSON.stringify(next),name,token).changes)throw new Error('Only an unstarted owned lease can be handed off.');
      closed=true;db.close();
    },
    release:()=>{if(!closed){db.prepare('UPDATE leases SET finished=1 WHERE name=? AND token=?').run(name,token);closed=true;db.close();}}
  };
}
/** A forked runner can only adopt the lease already delegated to its actual process identity. */
export async function adoptProcessLease(directory:string,name:string,token:string):Promise<ProcessLease>{
  if(!/^[a-z-]{1,32}$/.test(name)||!/^[0-9a-f-]{36}$/.test(token))throw new Error('Invalid delegated process lease.');
  const root=await realpath(directory),file=path.join(root,'process-leases.sqlite');if((await lstat(file)).isSymbolicLink())throw new Error('Process lease database cannot be a symlink.');
  const owner=await processIdentity();if(!owner)throw new Error('Cannot establish this worker identity.');
  const db=new DatabaseSync(file);let retained=false;
  try{
    db.exec('PRAGMA busy_timeout=1500;');const row=db.prepare('SELECT owner,finished,guard FROM leases WHERE name=? AND token=?').get(name,token) as {owner:string;finished:number;guard:string|null}|undefined;
    if(!row||row.finished||row.guard!==null||row.owner!==JSON.stringify(owner))throw new LeaseBusyError('The unstarted lease was not delegated to this worker.');
    retained=true;return leaseHandle(db,root,name,token,owner);
  }finally{if(!retained)db.close();}
}
/** SQLite compare-and-swap serializes recovery; a recorded group must actually be gone. */
export async function acquireProcessLease(directory:string,name:string,legacyLock?:string){
  if(!/^[a-z-]{1,32}$/.test(name))throw new Error('Invalid process lease name.');
  const root=await realpath(directory);
  if(legacyLock){
    try{await lstat(path.join(root,legacyLock));throw new LeaseBusyError('Legacy analysis lock exists. Verify its actual engine processes before explicitly removing the old lock; it is not automatically reclaimed.');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
  const file=path.join(root,'process-leases.sqlite');
  try{if((await lstat(file)).isSymbolicLink())throw new Error('Process lease database cannot be a symlink.');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  const owner=await processIdentity();if(!owner)throw new Error('Cannot establish this process identity.');
  const db=new DatabaseSync(file);let retained=false;
  try{
    db.exec('PRAGMA busy_timeout=1500;PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS leases(name TEXT PRIMARY KEY,token TEXT NOT NULL,owner TEXT NOT NULL,guard TEXT,finished INTEGER NOT NULL);');
    for(let attempt=0;attempt<3;attempt++){
      const previous=db.prepare('SELECT * FROM leases WHERE name=?').get(name) as {token:string;owner:string;guard:string|null;finished:number}|undefined;
      if(previous){
        if(!previous.finished&&await processIsLive(JSON.parse(previous.owner)))throw new LeaseBusyError('Analysis lease owner is still running.');
        if(previous.guard){const guard=JSON.parse(previous.guard) as ToolProcess;if(guard.supervisor&&await processIsLive(guard.supervisor))throw new LeaseBusyError('Analysis supervisor is still alive.');if(guard.processGroup===null)throw new Error('Cannot recover an uninspectable engine process group.');
          const members=await processGroupMembers(guard.processGroup);if(members.length)throw new LeaseBusyError('Analysis engine process group is still alive: '+members.slice(0,10).join(', '));}
      }
      const token=randomUUID();
      const changed=previous?db.prepare('UPDATE leases SET token=?,owner=?,guard=NULL,finished=0 WHERE name=? AND token=?').run(token,JSON.stringify(owner),name,previous.token).changes:
        db.prepare('INSERT OR IGNORE INTO leases(name,token,owner,finished) VALUES(?,?,?,0)').run(name,token,JSON.stringify(owner)).changes;
      if(!changed)continue;
      retained=true;return leaseHandle(db,root,name,token,owner);
    }
    throw new LeaseBusyError('Analysis lease changed concurrently; inspect the current owner before retrying.');
  }finally{if(!retained)db.close();}
}
