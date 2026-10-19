import path from 'node:path';
import {writeFile} from 'node:fs/promises';
import {digest} from './artifact.js';
import {adoptProcessLease,type ProcessLease,type ToolProcess} from './process-lease.js';
import {openRuns,runWorkspace,runOptions,runId,type RunRow} from './analysis-run-state.js';
import {runAnalysisQueue,type AnalysisQueueProgress} from './analysis-queue.js';

const workspace=process.argv[2]!,id=runId(process.argv[3]!);
let activating=false,reason:string|null=null,controlError:string|null=null;
const controller=new AbortController();
let db:ReturnType<typeof openRuns>|undefined;
function abort(why:string){
  reason??=why;controller.abort();
  try{db?.prepare("UPDATE analysis_runs SET cancel_requested=1,cancel_reason=COALESCE(cancel_reason,?),status='cancelling',updated=? WHERE id=? AND status IN ('starting','running','cancelling')").run(reason,new Date().toISOString(),id);}
  catch(error){controlError??=(error as Error).message;}
}
const signal=()=>abort('signal');process.on('SIGINT',signal);process.on('SIGTERM',signal);
function checkControl(){
  try{
    const current=db!.prepare('SELECT cancel_requested,cancel_reason FROM analysis_runs WHERE id=?').get(id) as RunRow|undefined;
    if(!current)throw new Error('Background control record disappeared.');
    if(current.cancel_requested){reason??=current.cancel_reason??'user';controller.abort();}
  }catch(error){controlError??=(error as Error).message;abort('control-failed');}
}
async function activate(){
  if(activating)return;activating=true;
  let lease:ProcessLease|undefined,ticker:NodeJS.Timeout|undefined,budget:NodeJS.Timeout|undefined,deadline=0;
  try{
    const root=await runWorkspace(workspace);db=openRuns(root);
    const row=db.prepare('SELECT * FROM analysis_runs WHERE id=?').get(id) as RunRow|undefined;
    if(!row)throw new Error('Background run not found.');
    if(digest(row.options)!==row.options_sha256)throw new Error('Background run options changed.');
    const options=runOptions.parse(JSON.parse(row.options));
    lease=await adoptProcessLease(root,'analysis-queue',row.lease_token);
    if(row.owner!==JSON.stringify(lease.owner))throw new Error('Background run owner differs from the delegated lease.');
    checkControl();if(controller.signal.aborted)abort(reason??'signal');
    deadline=Date.now()+options.maxRunMs;
    ticker=setInterval(checkControl,100);budget=setTimeout(()=>abort('deadline'),options.maxRunMs);
    db.prepare('UPDATE analysis_runs SET status=?,updated=?,deadline_at=? WHERE id=?').run(controller.signal.aborted?'cancelling':'running',new Date().toISOString(),new Date(deadline).toISOString(),id);
    if(process.connected)process.send?.({kind:'accepted',id},()=>{if(process.connected)process.disconnect();});
    const progress=(value:AnalysisQueueProgress)=>{db!.prepare('UPDATE analysis_runs SET progress=?,updated=? WHERE id=?').run(JSON.stringify(value),new Date().toISOString(),id);process.stdout.write(JSON.stringify(value)+'\n');};
    const onProcess=(guard:ToolProcess)=>{db!.prepare('UPDATE analysis_runs SET guard=?,updated=? WHERE id=?').run(JSON.stringify(guard),new Date().toISOString(),id);};
    const result=await runAnalysisQueue(root,{engines:options.engines,maxJobs:options.maxJobs,retry:options.retry,lease,signal:controller.signal,onProgress:progress,onProcess});
    const text=JSON.stringify(result,null,2)+'\n';if(Buffer.byteLength(text)>4*1024*1024)throw new Error('Background result exceeds4MiB.');
    const file=path.join(root,'analysis-runs',id,'result.json');await writeFile(file,text,{flag:'wx',mode:0o600});
    // Serialize completion with a fresh cancellation read, including requests
    // arriving while the result file was being written.
    db.exec('BEGIN IMMEDIATE');
    try{
      checkControl();if(Date.now()>=deadline)abort('deadline');
      const status=controlError?'failed':controller.signal.aborted?reason==='deadline'?'deadline-exceeded':'cancelled':result.items.some(item=>item.status==='partial')?'partial':result.items.some(item=>item.status!=='completed')?'failed':'completed';
      db.prepare('UPDATE analysis_runs SET status=?,updated=?,result=?,error=?,cancel_reason=COALESCE(cancel_reason,?) WHERE id=?').run(status,new Date().toISOString(),JSON.stringify({file,sha256:digest(text),bytes:Buffer.byteLength(text)}),controlError,reason,id);
      db.exec('COMMIT');
    }catch(error){db.exec('ROLLBACK');throw error;}
  }catch(error){
    if(db){
      try{
        db.exec('BEGIN IMMEDIATE');
        try{
          checkControl();if(deadline&&Date.now()>=deadline)abort('deadline');
          const status=controlError?'failed':controller.signal.aborted?reason==='deadline'?'deadline-exceeded':'cancelled':'failed';
          db.prepare('UPDATE analysis_runs SET status=?,error=?,updated=?,cancel_reason=COALESCE(cancel_reason,?) WHERE id=?').run(status,(error as Error).message.slice(0,16384),new Date().toISOString(),reason,id);
          db.exec('COMMIT');
        }catch(recordError){db.exec('ROLLBACK');throw recordError;}
      }catch(recordError){process.stderr.write('Cannot save terminal run state: '+(recordError as Error).message+'\n');}
    }
    process.stderr.write((error as Error).message.slice(0,16384)+'\n');
  }finally{
    if(ticker)clearInterval(ticker);if(budget)clearTimeout(budget);
    try{lease?.release();}finally{db?.close();db=undefined;if(process.connected)process.disconnect();}
  }
}
const launch=()=>{void activate().catch(error=>{process.stderr.write((error as Error).message+'\n');process.exitCode=1;});};
process.on('message',(message:any)=>{if(message?.kind==='start')launch();});
// A launcher may die after delegating but before sending start. Adoption still
// requires this exact live PID/start identity; an undelegated child cannot run.
process.on('disconnect',()=>{if(!activating)launch();});
if(!process.connected)launch();
