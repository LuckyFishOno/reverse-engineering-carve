import path from 'node:path';
import {fork} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {mkdir,open,realpath} from 'node:fs/promises';
import {openIndex} from './survey.js';
import {digest} from './artifact.js';
import {acquireProcessLease,processIdentity,type ProcessLease,LeaseBusyError} from './process-lease.js';
import {openRuns,observeRun,runOptions,runWorkspace,runId,terminalRunStates,type RunOptions,type RunRow} from './analysis-run-state.js';

export async function queryAnalysisRuns(workspace:string,options:{id?:string;limit?:number;offset?:number}={}){
  const root=await runWorkspace(workspace);const limit=options.limit??20,offset=options.offset??0;
  if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use run limit1–100 and a nonnegative offset.');if(options.id)runId(options.id);
  const db=openIndex(root,true);
  try{
    if(!db.prepare("SELECT name FROM sqlite_master WHERE name='analysis_runs'").get())return{schema:'carve/analysis-runs@1',workspace:root,total:0,items:[],nextOffset:null};
    const args=options.id?[options.id]:[],where=options.id?' WHERE id=?':'';
    const total=Number((db.prepare('SELECT count(*) n FROM analysis_runs'+where).get(...args) as RunRow).n);
    const rows=db.prepare('SELECT * FROM analysis_runs'+where+' ORDER BY created DESC,id DESC LIMIT ? OFFSET ?').all(...args,limit,offset) as RunRow[];
    const items=[];for(const row of rows)items.push(await observeRun(row));
    return{schema:'carve/analysis-runs@1',workspace:root,total,items,limit,offset,nextOffset:offset+rows.length<total?offset+rows.length:null,scope:'Recorded batch state plus actual process inspection. Missing/unknown workers are never assumed complete. Inspect component jobs and evidence separately.'};
  }finally{db.close();}
}
export async function cancelAnalysisRun(workspace:string,id:string){
  const root=await runWorkspace(workspace);runId(id);const db=openRuns(root);
  try{
    const row=db.prepare('SELECT * FROM analysis_runs WHERE id=?').get(id) as RunRow|undefined;if(!row)throw new Error('Analysis run not found.');
    if(!terminalRunStates.has(row.status))db.prepare("UPDATE analysis_runs SET cancel_requested=1,cancel_reason=COALESCE(cancel_reason,'user'),status='cancelling',updated=? WHERE id=? AND status IN ('starting','running','cancelling')").run(new Date().toISOString(),id);
    const current=db.prepare('SELECT * FROM analysis_runs WHERE id=?').get(id) as RunRow;
    return{schema:'carve/analysis-cancel@1',workspace:root,run:await observeRun(current),scope:'Durable cancellation request. The worker stops its owned tools; cancelling is not proof that processes have already stopped. No recorded PID is killed by this request.'};
  }finally{db.close();}
}
async function activeRun(root:string){
  const db=openRuns(root);let rows:RunRow[];
  try{rows=db.prepare("SELECT * FROM analysis_runs WHERE status IN ('starting','running','cancelling') ORDER BY created DESC LIMIT 20").all() as RunRow[];}finally{db.close();}
  for(const row of rows){const observed=await observeRun(row);if(['starting','running','cancelling','engine-cleanup-pending','unknown'].includes(observed.observedStatus))return observed;}
  return null;
}
export async function startAnalysisRun(workspace:string,input:Partial<RunOptions>&{signal?:AbortSignal}={}){
  const {signal,...supplied}=input;const options=runOptions.parse(supplied);const root=await runWorkspace(workspace);
  for(const key of ['ghidra','javaHome','jadx'] as const)if(options.engines[key])options.engines[key]=await realpath(options.engines[key]!);
  if(signal?.aborted)throw new Error('Background analysis start cancelled.');
  const active=await activeRun(root);if(active)return{schema:'carve/analysis-start@1',workspace:root,created:false,run:active};
  let lease:ProcessLease;
  try{lease=await acquireProcessLease(root,'analysis-queue');}
  catch(error){
    if(error instanceof LeaseBusyError){
      // The other launcher may hold the lease just before inserting its run.
      // Wait only for that handle; never acquire/retry an engine on a timeout.
      for(let n=0;n<20;n++){
        const running=await activeRun(root);if(running)return{schema:'carve/analysis-start@1',workspace:root,created:false,run:running};
        await new Promise(resolve=>setTimeout(resolve,20));
      }
    }throw error;
  }
  const id=randomUUID(),folder=path.join(root,'analysis-runs',id),log=path.join(folder,'runner.log');let db:ReturnType<typeof openRuns>|undefined;let delegated=false;
  try{
    await mkdir(folder,{recursive:true,mode:0o700});db=openRuns(root);const now=new Date().toISOString(),text=JSON.stringify(options);
    db.prepare("INSERT INTO analysis_runs(id,status,created,updated,launcher,lease_token,options,options_sha256,log) VALUES(?,'starting',?,?,?,?,?,?,?)").run(id,now,now,JSON.stringify(lease.owner),lease.token,text,digest(text),log);
    const output=await open(log,'wx',0o600);
    let child:ReturnType<typeof fork>;
    let finish:(state:string)=>void=()=>{};const accepted=new Promise<string>(resolve=>{finish=resolve;});
    let stopped:Promise<void>,timer:NodeJS.Timeout|undefined;
    try{
      child=fork(fileURLToPath(new URL('./analysis-runner.js',import.meta.url)),[root,id],{cwd:root,env:{PATH:process.env.PATH,TMPDIR:process.env.TMPDIR,LANG:'C.UTF-8'},execArgv:[],detached:true,stdio:['ignore',output.fd,output.fd,'ipc']});
      // Attach before the first await: even an immediate spawn failure must be observed.
      stopped=new Promise(resolve=>{child.once('error',()=>{finish('error');resolve();});child.once('exit',()=>{finish('exited');resolve();});});
      child.on('message',(message:any)=>{if(message?.kind==='accepted')finish('accepted');});
    }finally{await output.close();}
    let abortError:Error|undefined;
    const abort=()=>{
      try{db!.prepare("UPDATE analysis_runs SET cancel_requested=1,cancel_reason=COALESCE(cancel_reason,'start-cancelled'),status='cancelling',updated=? WHERE id=? AND status IN ('starting','running','cancelling')").run(new Date().toISOString(),id);}
      catch(error){abortError=error as Error;}
      // Before handoff this child has no authority to launch tools. After handoff,
      // its own controller consumes the durable request and stops owned tools.
      if(!delegated)child.kill('SIGTERM');
    };
    signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    try{
      const identity=child.pid?await processIdentity(child.pid):null;if(!identity)throw new Error('Background worker stopped before its identity could be established.');
      db.prepare('UPDATE analysis_runs SET owner=?,updated=? WHERE id=?').run(JSON.stringify(identity),new Date().toISOString(),id);
      if(abortError)throw abortError;if(signal?.aborted)throw new Error('Background analysis start cancelled.');
      await lease.handoff(identity);delegated=true;
      if(child.connected)child.send({kind:'start'},error=>{if(error)finish('channel-closed');});
      // A slow acknowledgement is not process death; return its inspectable handle.
      timer=setTimeout(()=>finish('starting'),5000);await accepted;
      child.unref();if(child.connected)child.disconnect();
      const row=db.prepare('SELECT * FROM analysis_runs WHERE id=?').get(id) as RunRow;
      return{schema:'carve/analysis-start@1',workspace:root,created:true,run:await observeRun(row),scope:'A bounded local background batch. It survives normal launcher/MCP disconnect. Query the run and component jobs; explicit cancel persists a request.'};
    }finally{if(timer)clearTimeout(timer);signal?.removeEventListener('abort',abort);if(!delegated){child.kill('SIGTERM');if(child.connected)child.disconnect();await stopped;}}
  }catch(error){
    if(db&&!delegated)db.prepare("UPDATE analysis_runs SET status='launch-failed',error=?,updated=? WHERE id=?").run((error as Error).message,new Date().toISOString(),id);
    throw error;
  }finally{db?.close();lease.release();}
}
