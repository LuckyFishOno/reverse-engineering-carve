import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { open } from 'node:fs/promises';
import type {ToolProcess} from './process-lease.js';
import {processIdentity} from './process-inspection.js';
export async function runTool(command:string,args:string[],options:{cwd:string;env:NodeJS.ProcessEnv;log:string;timeoutMs:number;maxLogBytes?:number;signal?:AbortSignal;onProcess?:(process:ToolProcess)=>void|Promise<void>}) {
  if(options.signal?.aborted)throw new Error('Analysis cancelled.');
  const log=await open(options.log,'wx');let bytes=0;let tail='';
  try {
    return await new Promise<{exitCode:number|null;bytes:number;diagnostic:string;process:ToolProcess}>((resolve,reject)=>{
      const child=fork(fileURLToPath(new URL('./tool-host.js',import.meta.url)),[],{cwd:options.cwd,env:options.env,execArgv:[],detached:process.platform!=='win32',stdio:['ignore','pipe','pipe','ipc']});
      let identity:ToolProcess|undefined;
      let failure='';
      let registration=Promise.resolve();
      let fallback:NodeJS.Timeout|undefined;
      let controlledExit=false;
      const kill=()=>{if(!child.pid)return;try{child.kill('SIGTERM');}catch{}};
      const abort=()=>{failure='Analysis cancelled; the analysis is incomplete.';kill();};
      options.signal?.addEventListener('abort',abort,{once:true});if(options.signal?.aborted)abort();
      const detach=()=>options.signal?.removeEventListener('abort',abort);
      const timer=setTimeout(()=>{failure=`Tool exceeded ${options.timeoutMs} ms; the analysis is incomplete.`;kill();},options.timeoutMs);
      let writes=Promise.resolve();
      const collect=(data:Buffer)=>{
        bytes+=data.length;tail=(tail+data.toString('utf8')).slice(-8192);
        if(bytes>(options.maxLogBytes??32*1024*1024)){failure='Tool log exceeded its byte budget.';kill();return;}
        writes=writes.then(()=>log.write(data).then(()=>{})).catch(error=>{failure=error.message;kill();});
      };
      child.stdout!.on('data',collect);child.stderr!.on('data',collect);
      child.on('message',(message:any)=>{
        if(message?.kind==='finished'){controlledExit=true;return;}
        if(message?.kind==='spawn-error'){failure=String(message.message);return;}
        if(message?.kind!=='ready'||identity)return;
        if(failure){kill();return;}
        registration=Promise.resolve().then(async()=>{
          const supervisor=await processIdentity(child.pid);if(!supervisor)throw new Error('Tool supervisor stopped before registration.');
          identity={schema:'carve/tool-process@1',pid:message.pid,processGroup:process.platform==='win32'?null:message.pid,supervisor,guardedStart:true,command,log:options.log};
          await options.onProcess?.(identity);
        }).then(()=>{
          if(failure||!child.connected)return;
          child.send({kind:'start',command,args,cwd:options.cwd,env:options.env},error=>{if(error){failure||=error.message;kill();}});
        }).catch(error=>{failure||=error.message;kill();});
      });
      child.on('error',error=>{clearTimeout(timer);detach();reject(error);});
      child.on('exit',(code,signal)=>{
        if((signal||!controlledExit)&&identity?.processGroup){
          failure||='Tool supervisor stopped unexpectedly; analysis is incomplete.';
          const group=identity.processGroup;const cleanup=()=>{try{process.kill(-group,'SIGKILL');}catch{}};cleanup();fallback=setInterval(cleanup,20);
        }
      });
      child.on('close',async code=>{clearTimeout(timer);if(fallback)clearInterval(fallback);detach();await registration;await writes;if(failure)reject(new Error(failure));else if(!identity)reject(new Error('Tool supervisor stopped before establishing its process guard.'));else resolve({exitCode:code,bytes,diagnostic:tail,process:identity});});
    });
  }finally{await log.close();}
}
