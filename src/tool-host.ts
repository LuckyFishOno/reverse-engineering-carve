// This supervisor stays outside the engine group so it can repeat cleanup across spawn races.
import {fork,type ChildProcess} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {processGroupMembers} from './process-inspection.js';
let worker:ChildProcess|undefined;let workerClosed=false;let configured=false;let stopping=false;let finishing=false;let done=false;let code:number|null=null;let killer:NodeJS.Timeout|undefined;
const killGroup=()=>{if(!worker?.pid)return;try{if(process.platform!=='win32')process.kill(-worker.pid,'SIGKILL');else worker.kill('SIGKILL');}catch{}};
const stop=()=>{if(done)return;stopping=true;killGroup();killer??=setInterval(killGroup,20);};
process.on('disconnect',stop);process.on('SIGINT',stop);process.on('SIGTERM',stop);
const waiting=setTimeout(stop,30000);
async function finish(){
  if(finishing||!workerClosed)return;finishing=true;clearTimeout(waiting);stop();
  // Reaping the worker closes its spawn window; then verify the actual remaining group.
  if(process.platform!=='win32')while(true){
    try{killGroup();if(!(await processGroupMembers(worker!.pid!)).length)break;}catch(error){process.stderr.write('Engine cleanup awaits process inspection: '+(error as Error).message+'\n');}
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  if(killer)clearInterval(killer);done=true;process.exitCode=code??1;
  if(process.connected)process.send?.({kind:'finished',exitCode:code},()=>{if(process.connected)process.disconnect();});
}
worker=fork(fileURLToPath(new URL('./tool-worker.js',import.meta.url)),[],{cwd:process.cwd(),env:process.env,execArgv:[],detached:process.platform!=='win32',stdio:['ignore','inherit','inherit','ipc']});
worker.on('spawn',()=>{if(stopping)killGroup();else process.send?.({kind:'ready',pid:worker!.pid});});
worker.on('message',message=>{if(process.connected)process.send?.(message);});
worker.on('error',error=>{process.stderr.write(error.message+'\n');if(process.connected)process.send?.({kind:'spawn-error',message:error.message});stop();});
worker.on('close',value=>{workerClosed=true;code=value;void finish();});
process.on('message',(input:any)=>{
  if(input?.kind==='cancel'){stop();return;}
  if(input?.kind!=='start'||stopping||configured)return;configured=true;clearTimeout(waiting);
  worker!.send(input,error=>{if(error){process.stderr.write(error.message+'\n');stop();}});
});
