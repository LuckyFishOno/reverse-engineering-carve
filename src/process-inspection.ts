import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const execute=promisify(execFile);
export interface ProcessIdentity {pid:number;startedAt:string}
export interface ToolProcess {schema:'carve/tool-process@1';pid:number;processGroup:number|null;supervisor:ProcessIdentity;guardedStart:true;command:string;log:string}
const exists=(pid:number)=>{try{process.kill(pid,0);return true;}catch(error){if((error as NodeJS.ErrnoException).code==='ESRCH')return false;throw error;}};
export async function processIdentity(pid=process.pid):Promise<ProcessIdentity|null>{
  if(!Number.isSafeInteger(pid)||pid<1)throw new Error('Invalid process identity.');
  if(!exists(pid))return null;
  if(process.platform==='win32')throw new Error('Durable analysis leases currently require POSIX process inspection.');
  try{
    const {stdout}=await execute('ps',['-p',String(pid),'-o','lstart='],{timeout:5000,maxBuffer:16384,env:{PATH:process.env.PATH,LC_ALL:'C',TZ:'UTC'}});
    const startedAt=stdout.trim();if(!startedAt)throw new Error('Missing process start identity.');return{pid,startedAt};
  }catch(error){if(!exists(pid))return null;throw new Error('Cannot establish live process identity: '+(error as Error).message);}
}
export async function processIsLive(identity:ProcessIdentity){const current=await processIdentity(identity.pid);return current?.startedAt===identity.startedAt;}
export async function processGroupMembers(group:number){
  if(!Number.isSafeInteger(group)||group<1)throw new Error('Invalid process group.');
  const {stdout}=await execute('ps',['-A','-o','pid=,pgid=,stat='],{timeout:5000,maxBuffer:8*1024*1024,env:{PATH:process.env.PATH,LC_ALL:'C',TZ:'UTC'}});
  const members:number[]=[];
  for(const line of stdout.split('\n')){
    if(!line.trim())continue;const match=/^\s*(\d+)\s+(\d+)\s+(\S+)\s*$/.exec(line);if(!match)throw new Error('Cannot parse process-group inspection; no recovery is attempted.');
    if(Number(match[2])===group&&!match[3]!.startsWith('Z'))members.push(Number(match[1]));
  }return members;
}
