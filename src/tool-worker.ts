// Wait for the parent to durably register this process group before starting a tool.
import {spawn,type ChildProcess} from 'node:child_process';
let child:ChildProcess|undefined;let configured=false;let done=false;
const kill=()=>{
  if(done)return;
  try{if(process.platform!=='win32')process.kill(-process.pid,'SIGKILL');else{child?.kill('SIGKILL');process.exit(1);}}catch{process.exit(1);}
};
process.on('disconnect',kill);process.on('SIGINT',kill);process.on('SIGTERM',kill);
const waiting=setTimeout(kill,30000);
process.on('message',(input:any)=>{
  if(configured)return;configured=true;clearTimeout(waiting);
  if(!input||typeof input.command!=='string'||!Array.isArray(input.args)||!input.args.every((a:unknown)=>typeof a==='string')){process.stderr.write('Invalid tool-host configuration.\n');kill();return;}
  try{
    child=spawn(input.command,input.args,{cwd:input.cwd,env:input.env,shell:false,stdio:['ignore','inherit','inherit']});
    child.once('error',error=>{process.stderr.write(error.message+'\n');process.send?.({kind:'spawn-error',message:error.message});});
    child.once('close',code=>{done=true;process.exitCode=code??1;if(process.connected)process.disconnect();});
  }catch(error){process.stderr.write((error as Error).message+'\n');kill();}
});
