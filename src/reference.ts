import { spawn,type ChildProcessWithoutNullStreams } from 'node:child_process';
import type { Outcome } from './execution.js';

export type ReferenceMode='argv-values'|'json-stdin'|'text-stdin'|'bytes-stdin';
export type ReferenceOutput='json'|'utf8'|'bytes';
const limit=1048576;
function input(mode:ReferenceMode,args:unknown[]){
 if(!Array.isArray(args))throw new Error('Reference arguments must be an array.');
 if(mode==='argv-values'){
  if(args.some(v=>!['string','boolean','number'].includes(typeof v)||typeof v==='number'&&!Number.isFinite(v)))throw new Error('argv-values accepts finite scalar string/boolean/number arguments only.');
  const argv=args.map(String);if(argv.some(s=>s.includes('\0')))throw new Error('argv-values cannot contain NUL.');
  if(argv.reduce((n,s)=>n+Buffer.byteLength(s)+1,0)>limit)throw new Error('Reference input exceeded 1 MiB.');return{argv,stdin:undefined};
 }
 let stdin:Buffer;
 if(mode==='json-stdin')stdin=Buffer.from(JSON.stringify(args));
 else if(mode==='text-stdin'){
  if(args.length!==1||typeof args[0]!=='string')throw new Error('text-stdin requires exactly one string argument.');stdin=Buffer.from(args[0],'utf8');if(stdin.toString('utf8')!==args[0])throw new Error('text-stdin requires well-formed Unicode.');
 }else if(mode==='bytes-stdin'){
  if(args.length!==1||!Array.isArray(args[0]))throw new Error('bytes-stdin requires exactly one JSON byte-array argument.');
  const values=args[0];if(values.length>limit)throw new Error('Reference input exceeded 1 MiB.');stdin=Buffer.alloc(values.length);
  for(let i=0;i<values.length;i++){const byte=values[i];if(!Number.isInteger(byte)||byte<0||byte>255)throw new Error('bytes-stdin accepts integer bytes0–255 only.');stdin[i]=byte;}
 }else throw new Error('Unknown reference input mode.');
 if(stdin.length>limit)throw new Error('Reference input exceeded 1 MiB.');return{argv:[],stdin};
}

export function runReference(command:string[],mode:ReferenceMode,args:unknown[],cwd:string,timeoutMs:number,signal?:AbortSignal,output:ReferenceOutput='json'):Promise<Outcome> {
  if(signal?.aborted)return Promise.resolve({kind:'harness-error',detail:'Reference execution cancelled.'});
  let prepared:ReturnType<typeof input>;
  try{if(!['json','utf8','bytes'].includes(output))throw new Error('Unknown reference output format.');if(!command.length||command.some(s=>typeof s!=='string'||s.includes('\0')))throw new Error('Invalid reference command.');prepared=input(mode,args);}
  catch(error){return Promise.resolve({kind:'harness-error',detail:(error as Error).message});}
  return new Promise(resolve=>{
    let child:ChildProcessWithoutNullStreams;
    try{child=spawn(command[0]!,[...command.slice(1),...prepared.argv],{shell:false,cwd,detached:process.platform!=='win32',stdio:['pipe','pipe','pipe'],env:{PATH:process.env.PATH,HOME:cwd,TMPDIR:cwd,TEMP:cwd,TMP:cwd,LANG:'C.UTF-8'}});}
    catch(error){resolve({kind:'harness-error',detail:(error as Error).message});return;}
    let bytes=0;let failure='';const stdout:Buffer[]=[];let stderr='';let finished=false;
    const kill=()=>{if(child.pid)try{if(process.platform!=='win32')process.kill(-child.pid,'SIGKILL');else child.kill('SIGKILL');}catch{}};
    const abort=()=>{failure='Reference execution cancelled.';kill();};signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
    const timer=setTimeout(()=>{failure=`Reference timed out after ${timeoutMs} ms`;kill();},timeoutMs);
    const finish=(value:Outcome)=>{if(finished)return;finished=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);kill();resolve(value);};
    const count=(data:Buffer)=>{bytes+=data.length;if(bytes>limit){failure='Reference output exceeded 1 MiB';kill();return false;}return true;};
    child.stdout.on('data',(data:Buffer)=>{if(count(data))stdout.push(data);});
    child.stderr.on('data',(data:Buffer)=>{count(data);if(stderr.length<2000)stderr+=data.toString().slice(0,2000-stderr.length);});
    child.once('error',e=>finish({kind:'harness-error',detail:e.message}));
    child.once('close',(code,signal)=>{
      if(failure)return finish({kind:'harness-error',detail:failure});
      if(code!==0)return finish({kind:'harness-error',detail:`Reference exited ${code??signal}: ${stderr}`});
      try{
        const raw=Buffer.concat(stdout);
        if(output==='bytes')return finish({kind:'return',value:[...raw]});
        const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw);
        if(output==='utf8')return finish({kind:'return',value:text});
        const value=JSON.parse(text);const validate=(v:unknown):void=>{if(typeof v==='number'&&!Number.isFinite(v))throw new Error('Non-finite JSON number');if(v&&typeof v==='object')for(const x of Object.values(v))validate(x);};validate(value);finish({kind:'return',value});
      }catch(error){finish({kind:'harness-error',detail:(output==='json'?'Reference did not emit one finite JSON value: ':'Reference did not emit valid UTF8: ')+(error as Error).message});}
    });
    child.stdin.on('error',()=>{});child.stdin.end(prepared.stdin);
  });
}
