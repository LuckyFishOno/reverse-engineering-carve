import path from 'node:path';
import {realpath,readFile,lstat} from 'node:fs/promises';
import {z} from 'zod';
import {openIndex,queryIndex} from './survey.js';
import {processIsLive,processGroupMembers,type ToolProcess} from './process-lease.js';

export const runOptions=z.object({
  engines:z.object({ghidra:z.string().max(4096).optional(),javaHome:z.string().max(4096).optional(),jadx:z.string().max(4096).optional()}).default({}),
  maxJobs:z.number().int().min(1).max(10).default(1),retry:z.boolean().default(false),maxRunMs:z.number().int().min(1000).max(86400000).default(86400000)
}).strict();
export type RunOptions=z.infer<typeof runOptions>;
export type RunRow=Record<string,any>;
export const terminalRunStates=new Set(['completed','partial','failed','cancelled','deadline-exceeded','launch-failed','interrupted']);
export function runId(id:string){if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id))throw new Error('Choose a returned analysis run ID.');return id;}
export async function runWorkspace(input:string){
  const root=await realpath(input),marker=path.join(root,'.carve-workspace.json');const info=await lstat(marker);
  if(!info.isFile()||info.isSymbolicLink()||info.size>1048576)throw new Error('Choose a RECarve analysis workspace.');
  const identity=JSON.parse(await readFile(marker,'utf8')),index=await queryIndex(root,{limit:1});
  if(identity.schema!=='carve/workspace@1'||typeof identity.target!=='string'||identity.target!==index.target)throw new Error('Workspace marker and inventory identity differ.');
  return root;
}
export function openRuns(root:string){
  const db=openIndex(root);db.exec(`CREATE TABLE IF NOT EXISTS analysis_runs(id TEXT PRIMARY KEY,status TEXT NOT NULL,created TEXT,updated TEXT,launcher TEXT,owner TEXT,lease_token TEXT,options TEXT,options_sha256 TEXT,log TEXT,guard TEXT,progress TEXT,result TEXT,error TEXT,cancel_requested INTEGER NOT NULL DEFAULT 0,cancel_reason TEXT,deadline_at TEXT);
    CREATE INDEX IF NOT EXISTS analysis_runs_status ON analysis_runs(status,created,id);`);return db;
}
export async function observeRun(row:RunRow){
  const owner=row.owner?JSON.parse(row.owner):null,launcher=row.launcher?JSON.parse(row.launcher):null,guard:ToolProcess|null=row.guard?JSON.parse(row.guard):null;
  let liveness:{owner:string;launcher:string;supervisor:string;processGroup:string;detail?:string};
  try{liveness={owner:owner?await processIsLive(owner)?'live':'gone':'unregistered',launcher:launcher?await processIsLive(launcher)?'live':'gone':'unregistered',supervisor:guard?.supervisor?await processIsLive(guard.supervisor)?'live':'gone':'unregistered',processGroup:guard?(await processGroupMembers(guard.processGroup!)).length?'live':'gone':'unregistered'};}
  catch(error){liveness={owner:'unknown',launcher:'unknown',supervisor:'unknown',processGroup:'unknown',detail:(error as Error).message};}
  let observedStatus=row.status;
  if(liveness.supervisor==='live'||liveness.processGroup==='live'){
    observedStatus=terminalRunStates.has(row.status)||liveness.owner!=='live'?'engine-cleanup-pending':row.cancel_requested?'cancelling':row.status;
  }else if(!terminalRunStates.has(row.status)){
    if(liveness.owner==='live')observedStatus=row.cancel_requested?'cancelling':row.status;
    else if(Object.values(liveness).includes('unknown'))observedStatus='unknown';
    else if(liveness.supervisor==='live'||liveness.processGroup==='live')observedStatus='engine-cleanup-pending';
    else if(row.status==='starting'&&!owner&&liveness.launcher==='live')observedStatus='starting';
    else observedStatus=row.cancel_requested?'cancelled-worker-stopped':'interrupted';
  }
  return{id:row.id,recordedStatus:row.status,observedStatus,created:row.created,updated:row.updated,owner,launcher,options:JSON.parse(row.options),log:row.log,guard,progress:row.progress?JSON.parse(row.progress):null,result:row.result?JSON.parse(row.result):null,error:row.error,cancelRequested:Boolean(row.cancel_requested),cancelReason:row.cancel_reason,deadlineAt:row.deadline_at,liveness};
}
