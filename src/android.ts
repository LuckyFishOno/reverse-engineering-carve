import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, realpath, cp, writeFile, rm, open } from 'node:fs/promises';
import { z } from 'zod';
import { createConnection } from 'node:net';
import { hashFile } from './survey.js';
import { runTool } from './tool-process.js';
import { runReference } from './reference.js';
import { shellCommand } from './runtime.js';
import type { Outcome } from './execution.js';
import { sequenceCalls, sequenceOutcome } from './sequence.js';

const androidFields={
  adb:z.string().min(1),serial:z.string().regex(/^[A-Za-z0-9._:-]{1,200}$/),serverPort:z.number().int().min(1).max(65535).default(5037),
  harness:z.string().min(1),entryClass:z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*$/),
  dependencies:z.array(z.string().min(1)).max(20).default([]),description:z.string().trim().min(1).max(8000)};
const nativeLibraries=z.array(z.object({file:z.string().min(1),name:z.string().regex(/^lib[A-Za-z0-9_][A-Za-z0-9_.+-]{0,119}\.so$/)}).strict()).min(1).max(20).refine(items=>new Set(items.map(i=>i.name)).size===items.length,'Native library names must be unique.');
export const androidReferenceSchema=z.discriminatedUnion('schema',[
  z.object({schema:z.literal('carve/android-reference@1'),...androidFields}).strict(),
  z.object({schema:z.literal('carve/android-reference@2'),...androidFields,mode:z.enum(['argv-values','json-stdin'])}).strict(),
  z.object({schema:z.literal('carve/android-reference@3'),...androidFields,mode:z.enum(['argv-values','json-stdin']),nativeLibraries}).strict(),
  z.object({schema:z.literal('carve/android-reference@4'),...androidFields,mode:z.literal('json-sequence-stdin'),nativeLibraries:nativeLibraries.optional()}).strict()
]);
export type AndroidReference=z.infer<typeof androidReferenceSchema>;

/** ELF header compatibility only; dynamic dependencies and actual loading remain unproven. */
export function androidNativeElf(header:Buffer,abi:string){
 const expected=({ 'arm64-v8a':[2,183], 'armeabi-v7a':[1,40], x86:[1,3], x86_64:[2,62] } as Record<string,number[]>)[abi];
 if(!expected)throw new Error('Native reference does not support Android ABI '+abi+'.');
 if(header.length<64||!header.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46]))||header[5]!==1||header[6]!==1||header.readUInt16LE(16)!==3)throw new Error('Android native library requires a little-endian ELF shared object header.');
 if(header[4]!==expected[0]||header.readUInt16LE(18)!==expected[1])throw new Error('Android native library ELF class/machine does not match selected ABI '+abi+'.');
 return {format:'elf',elfClass:header[4]===2?'ELF64':'ELF32',machine:header.readUInt16LE(18),abi,scope:'Header compatibility only, not a dynamic-loader or dependency proof.'};
}

/** Preflight before any per-case process. JSON goes over stdin, never argv/shell. */
export function androidHarnessArguments(args:unknown[],mode:'argv-values'|'json-stdin'|'json-sequence-stdin'){
 if(!Array.isArray(args))throw new Error('Android reference arguments must be an array.');
 if(mode==='argv-values'){
  for(let i=0;i<args.length;i++){const a=args[i];if(!['string','number','boolean'].includes(typeof a)||typeof a==='number'&&!Number.isFinite(a))throw new Error('Android argv harness accepts finite scalar arguments only.');}
  const argv=args.map(String);if(argv.some(s=>s.includes('\0')))throw new Error('Android argv harness cannot contain NUL. Use json-stdin for structured data.');
  if(argv.reduce((n,s)=>n+Buffer.byteLength(s)+1,0)>1048576)throw new Error('Android reference input exceeded1MiB.');return argv;
 }
 if(mode!=='json-stdin'&&mode!=='json-sequence-stdin')throw new Error('Unknown Android reference input mode.');
 const pending:unknown[]=[args],seen=new Set<object>();
 while(pending.length){const value=pending.pop();if(value===null)continue;
  if(typeof value==='object'){
   if(seen.has(value))continue;seen.add(value);
   if((!Array.isArray(value)&&Object.getPrototypeOf(value)!==Object.prototype&&Object.getPrototypeOf(value)!==null)||Object.getOwnPropertySymbols(value).length||Object.hasOwn(value,'toJSON')&&typeof (value as any).toJSON==='function')throw new Error('Android json-stdin requires plain finite JSON data.');
   if(Array.isArray(value))for(let i=0;i<value.length;i++)pending.push(value[i]);else for(const item of Object.values(value))pending.push(item);
  }else if(!['string','number','boolean'].includes(typeof value)||typeof value==='number'&&!Number.isFinite(value))throw new Error('Android json-stdin requires plain finite JSON data.');
 }
 const json=JSON.stringify(args);if(Buffer.byteLength(json)>1048576)throw new Error('Android reference input exceeded1MiB.');
 if(mode==='json-sequence-stdin')sequenceCalls(args);
 return[] as string[];
}

async function requireServer(port:number){
  await new Promise<void>((resolve,reject)=>{
    const socket=createConnection({host:'127.0.0.1',port});
    socket.setTimeout(2000,()=>{socket.destroy();reject(new Error('Selected ADB server did not respond. Start it explicitly before verification.'));});
    socket.once('connect',()=>{socket.destroy();resolve();});
    socket.once('error',()=>reject(new Error('Selected ADB server is not running. Start it explicitly before verification.')));
  });
}

/** Stage exact byte snapshots on one explicitly selected device. Never starts/stops devices or ADB servers. */
export async function prepareAndroidReference(workspace:string,target:{path:string;sha256:string;facts:{format:string}},config:AndroidReference,options:{signal?:AbortSignal}={}){
  if(options.signal?.aborted)throw new Error('Android reference preparation cancelled.');
  config=androidReferenceSchema.parse(config);
  if(!['dex','apk','jar','zip','aab','aar'].includes(target.facts.format))throw new Error('Android runtime reference requires DEX or a DEX-bearing archive. Java class files need explicit D8 compilation first.');
  await requireServer(config.serverPort);
  const adb=await realpath(config.adb);const adbSha256=(await hashFile(adb)).sha256;
  const parent=path.join(workspace,'verification','android');await mkdir(parent,{recursive:true,mode:0o700});const run=await mkdtemp(path.join(parent,'run-'));
  const remote='/data/local/tmp/carve-'+randomBytes(16).toString('hex');
  const prefix=['-P',String(config.serverPort),'-s',config.serial];
  const env:NodeJS.ProcessEnv={PATH:process.env.PATH,HOME:run,TMPDIR:run,TMP:run,TEMP:run,LANG:'C.UTF-8',ADB_MDNS_AUTO_CONNECT:'0'};
  let number=0;let staged=false;const files:{file:string;sha256:string;bytes:number;remote:string;role:string;elf?:ReturnType<typeof androidNativeElf>}[]=[];
  const command=async(args:string[],allowFailure=false)=>{
    const result=await runTool(adb,[...prefix,...args],{cwd:run,env,log:path.join(run,`${number++}.log`),timeoutMs:30000,signal:options.signal,maxLogBytes:1048576});
    if(result.exitCode!==0&&!allowFailure)throw new Error('Android reference setup failed: '+result.diagnostic);
    return result;
  };
  const shell=(args:string[],allowFailure=false)=>command(['shell','-T',shellCommand(args)],allowFailure);
  async function cleanup(){
    let status='not-staged';
    if(staged){try{
      // A new cleanup call has its own deadline and must run even after cancellation.
      const result=await runTool(adb,[...prefix,'shell','-T',shellCommand(['rm','-rf','--',remote])],{cwd:run,env,log:path.join(run,`${number++}-cleanup.log`),timeoutMs:10000,maxLogBytes:1048576});
      status=result.exitCode===0?'removed':'failed';
    }catch{status='failed';}}
    await rm(path.join(run,'snapshots'),{recursive:true,force:true});
    await writeFile(path.join(run,'cleanup.json'),JSON.stringify({status,remote,serial:config.serial,serverPort:config.serverPort},null,2));return status;
  }
  try{
    const state=await command(['get-state']);if(state.diagnostic.trim()!=='device')throw new Error('Selected Android transport is not ready.');
    const fingerprint=(await shell(['getprop','ro.build.fingerprint'])).diagnostic.trim();
    const api=Number((await shell(['getprop','ro.build.version.sdk'])).diagnostic.trim());
    const abi=(await shell(['getprop','ro.product.cpu.abi'])).diagnostic.trim();
    if(!fingerprint||!Number.isInteger(api)||api<21||!abi)throw new Error('Cannot establish selected Android runtime identity.');
    let runtime='';let version='';
    for(const candidate of ['/apex/com.android.art/bin/dalvikvm64','/apex/com.android.art/bin/dalvikvm','/system/bin/dalvikvm64','/system/bin/dalvikvm']){
      const probe=await shell([candidate,'-showversion'],true);if(probe.exitCode===0&&/ART|Dalvik/i.test(probe.diagnostic)){runtime=candidate;version=probe.diagnostic.trim();break;}
    }
    if(!runtime)throw new Error('No directly executable ART/Dalvik VM found on selected device.');
    // Require the remote deadline utility before executing any target code.
    await shell(['timeout','-s','KILL','1','/system/bin/true']);
    staged=true;await shell(['mkdir','-m','700',remote]);
    const snapshots=path.join(run,'snapshots');await mkdir(snapshots);
    const libraries='nativeLibraries' in config?config.nativeLibraries??[]:[];
    const sources:{file:string;role:string;name?:string}[]=[{file:target.path,role:'selected-target'}, {file:config.harness,role:'reference-harness'},...config.dependencies.map(file=>({file,role:'declared-classpath-dependency'})),...libraries.map(item=>({...item,role:'declared-native-library'}))];
    const libraryDirectory=libraries.length?remote+'/lib':null;
    if(libraryDirectory)await shell(['mkdir','-m','700',libraryDirectory]);let nativeBytes=0;
    for(const [index,item] of sources.entries()){
      const file=await realpath(item.file);const recorded=await hashFile(file);
      if(index===0&&recorded.sha256!==target.sha256)throw new Error('Selected Android target bytes changed.');
      let elf:ReturnType<typeof androidNativeElf>|undefined;
      if(item.role==='declared-native-library'){nativeBytes+=recorded.bytes;if(recorded.bytes>64*1024*1024||nativeBytes>256*1024*1024)throw new Error('Native reference limits are64MiB/library and256MiB total.');}
      const local=path.join(snapshots,`${index}.input`);await cp(file,local);if((await hashFile(local)).sha256!==recorded.sha256)throw new Error('Android reference bytes changed while snapshotting.');
      if(item.role==='declared-native-library'){const handle=await open(local,'r');try{const header=Buffer.alloc(64);const read=await handle.read(header,0,64,0);elf=androidNativeElf(header.subarray(0,read.bytesRead),abi);}finally{await handle.close();}}
      const remoteFile=item.role==='declared-native-library'?libraryDirectory+'/'+item.name:remote+`/${index}.jar`;await command(['push','-q',local,remoteFile]);await shell(['chmod','444',remoteFile]);
      files.push({file,sha256:recorded.sha256,bytes:recorded.bytes,remote:remoteFile,role:item.role,...(elf?{elf}:{})});
    }
    const verifyRemote=async()=>{for(const file of files){const sum=(await shell(['sha256sum',file.remote])).diagnostic.trim().split(/\s/)[0];if(sum!==file.sha256)throw new Error('Android staged byte hash mismatch: '+file.role);}};
    await verifyRemote();
    const runtimeSha256=(await shell(['sha256sum',runtime])).diagnostic.trim().split(/\s/)[0];if(!/^[a-f0-9]{64}$/.test(runtimeSha256??''))throw new Error('Cannot hash the selected Android VM executable.');
    const inputMode=config.schema==='carve/android-reference@1'?'argv-values':config.mode;
    const sequenceMode=inputMode==='json-sequence-stdin';
    const identity={schema:sequenceMode?'carve/android-runtime@2':'carve/android-runtime@1',inputMode,adb,adbSha256,serial:config.serial,serverPort:config.serverPort,fingerprint,api,abi,runtime,runtimeVersion:version,runtimeSha256,
      ...(sequenceMode?{processLifetime:'one-sequence',freshVmPerSequence:true,crossSequenceVmState:false,objectLifetimeEvidence:'Defined by the reviewed harness, not independently instrumented.'}:{}),
      remote,entryClass:config.entryClass,files,...(libraryDirectory?{nativeLibraryDirectory:libraryDirectory,nativeLibraryBytesVerified:true,nativeLoadingEvidence:'Staged and hashed only. Actual load and JNI invocation depend on the reviewed harness; RegisterNatives/loader dependency closure are not established.'}:{}),selectedDexBytesVerified:true,executesDeclaredHarness:true,targetInvocationEvidence:'Defined by the declared harness; method execution is not independently instrumented.',scope:'declared-dex-classpath-harness',
      limitations:['Executes exact selected DEX/archive bytes through the declared harness; the harness invocation boundary must be reviewed.','This is a selected Android runtime, not proof of UI, server, codec hardware or all-device equivalence.','ADB transport, Android OS and boot/runtime libraries are identified but not comprehensively hashed.']};
    await writeFile(path.join(run,'runtime.json'),JSON.stringify(identity,null,2)+'\n');
    const classpath=files.filter(f=>f.role!=='declared-native-library').map(f=>f.remote).join(':');
    return{identity,logDirectory:run,
      run:async(args:unknown[],timeoutMs:number):Promise<Outcome>=>{
        let argv:string[];try{argv=androidHarnessArguments(args,inputMode);}catch(error){return{kind:'harness-error',detail:(error as Error).message};}
        const line=shellCommand(['timeout','-s','KILL',String(timeoutMs/1000),runtime,...(libraryDirectory?['-Djava.library.path='+libraryDirectory]:[]),'-cp',classpath,config.entryClass,...argv]);
        const result=await runReference([adb,...prefix,'shell','-T',line],inputMode==='argv-values'?'argv-values':'json-stdin',inputMode==='argv-values'?[]:args,run,timeoutMs+2000,options.signal);
        return sequenceMode?sequenceOutcome(result,args.length):result;
      },verifyRemote,cleanup};
  }catch(error){
    await writeFile(path.join(run,'failure.json'),JSON.stringify({status:'failed',message:(error as Error).message},null,2));await cleanup();throw error;
  }
}
