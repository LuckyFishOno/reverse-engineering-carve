import path from 'node:path';
import { realpath, mkdir, mkdtemp, cp, readFile, writeFile, rm, opendir, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { indexedFile, hashFile, openIndex } from './survey.js';
import { runTool } from './tool-process.js';
import { digest } from './artifact.js';
import type {ToolProcess} from './process-lease.js';
import {resolveEngineResources,heapExhausted,heapFailure,type EngineResources} from './engine-resources.js';
import {reserveEngineHeap,type HeapReservation} from './engine-reservation.js';

export async function managedAnalysis(workspace:string,options:{file:string;jadx:string;javaHome:string;class?:string;mode?:'auto'|'simple'|'fallback';timeoutMs?:number;resources?:EngineResources;signal?:AbortSignal;onProcess?:(process:ToolProcess)=>void|Promise<void>}) {
  if(process.platform==='win32')throw new Error('This JADX launcher is currently verified on POSIX hosts only.');
  const timeoutMs=options.timeoutMs??600000;if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>86400000)throw new Error('Use timeoutMs 1000–86400000.');
  const mode=options.mode??'auto';if(!['auto','simple','fallback'].includes(mode))throw new Error('Use JADX mode auto, simple or fallback.');
  const resources=resolveEngineResources(options.resources);
  const root=await realpath(workspace);const target=await indexedFile(root,options.file,options.signal);
  if(target.facts.backend!=='jadx')throw new Error(`Format ${target.facts.format} is not routed to JADX.`);
  const jadx=await realpath(options.jadx);const javaHome=await realpath(options.javaHome);
  const parent=path.join(root,'analysis-cache','jadx',target.sha256);await mkdir(parent,{recursive:true,mode:0o700});const run=await mkdtemp(path.join(parent,'run-'));
  const runtime=await realpath(await mkdtemp(path.join(tmpdir(),'carve-jadx-')));let db:ReturnType<typeof openIndex>|undefined;let reservation:HeapReservation|undefined;
  try {
    if(/\s/.test(runtime))throw new Error('JADX runtime temp path must not contain whitespace.');
    const snapshot=path.join(run,'input'+path.extname(target.path));await cp(target.path,snapshot);
    if((await hashFile(snapshot)).sha256!==target.sha256)throw new Error('Input changed while creating a JADX snapshot.');
    const env:NodeJS.ProcessEnv={PATH:process.env.PATH,JAVA_HOME:javaHome,JAVA_TOOL_OPTIONS:`-Duser.home=${runtime} -Djava.io.tmpdir=${runtime}`,JADX_OPTS:`-Xmx${resources.heapMiB}m`,LANG:'C.UTF-8'};
    // One reservation covers the short version JVM and the decompilation JVM, which run sequentially.
    reservation=await reserveEngineHeap(resources,{engine:'jadx',workspace:root});
    const versionResult=await runTool(jadx,['--version'],{cwd:run,env,log:path.join(run,'version.log'),timeoutMs:10000,signal:options.signal,onProcess:options.onProcess});
    const version=/^\d+\.\d+\.\d+[^\r\n]*/m.exec(versionResult.diagnostic)?.[0];if(versionResult.exitCode!==0||!version)throw new Error('Cannot verify the selected JADX version.');
    const output=path.join(run,'output');
    const args=['--no-res','--threads-count',String(resources.threads),'--decompilation-mode',mode,'--output-dir',output,...(options.class?['--single-class',options.class]:[]),snapshot];
    let result;try{result=await runTool(jadx,args,{cwd:run,env,log:path.join(run,'engine.log'),timeoutMs,signal:options.signal,onProcess:options.onProcess});}finally{reservation.release();}
    if(await heapExhausted(path.join(run,'engine.log')))throw new Error(heapFailure('JADX',resources)+` Partial source remains in ${output}.`);
    if(result.exitCode!==0)throw new Error(`JADX exited ${result.exitCode}; partial source remains in ${output}. ${result.diagnostic}`);
    db=openIndex(root);db.exec(`CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
      CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
      CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
    const save=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)');const remove=db.prepare('DELETE FROM observation_search WHERE id=?');const add=db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)');
    let sources=0;let truncated=0;const observationIds:string[]=[];
    async function walk(folder:string):Promise<void>{
      for await(const entry of await opendir(folder)){
        const file=path.join(folder,entry.name);if(entry.isSymbolicLink())throw new Error('Generated sources contain an unexpected symlink.');
        if(entry.isDirectory()){await walk(file);continue;}if(!entry.isFile()||!entry.name.endsWith('.java'))continue;
        const recorded=await hashFile(file);const name=path.relative(output,file).split(path.sep).join('/');
        const handle=await open(file,'r');const buffer=Buffer.alloc(Math.min(recorded.bytes,1024*1024));let bytes=0;
        try{while(bytes<buffer.length){const read=await handle.read(buffer,bytes,buffer.length-bytes,bytes);if(!read.bytesRead)break;bytes+=read.bytesRead;}}finally{await handle.close();}
        const code=new TextDecoder('utf-8').decode(buffer.subarray(0,bytes));const partial=recorded.bytes>buffer.length;if(partial)truncated++;
        const id=digest(JSON.stringify({artifact:options.file,sha256:target.sha256,provider:'jadx',version,mode,name,generatedSourceSha256:recorded.sha256}));
        const detail={kind:'java-class',name,pseudocode:code,pseudocodeTruncated:partial,generatedSource:file,generatedSourceSha256:recorded.sha256,provider:{name:'jadx',version,analysisMode:mode},limitation:'Decompiler output is analysis text, not original source or guaranteed compilable Java. Fallback mode exposes raw instructions. Missing server logic and behavior remain unknown.'};
        db!.exec('BEGIN');try{save.run(id,options.file,target.sha256,'java-class',name,name,code,JSON.stringify(detail),file,recorded.sha256);remove.run(id);add.run(id,code);db!.exec('COMMIT');}catch(error){db!.exec('ROLLBACK');throw error;}
        sources++;if(observationIds.length<100)observationIds.push(id);
      }
    }
    await walk(output);
    if(!sources)throw new Error('JADX produced no Java sources for the selected scope.');
    const report={schema:'carve/managed-analysis@1',status:truncated?'partial-index':'sources-exported',workspace:root,file:options.file,sourceSha256:target.sha256,container:target.container??null,provider:{name:'jadx',version,analysisMode:mode},scope:{class:options.class??null},resources,heapReservation:{registry:reservation.registry,heapMiB:reservation.heapMiB,reservedByOthersMiB:reservation.reservedByOthersMiB,hostLimitMiB:reservation.hostLimitMiB,reclaimedStale:reservation.reclaimedStale},executesTarget:false,sources,observationIds,observationIdsTruncated:sources>observationIds.length,truncatedSourcePreviews:truncated,output,
      limitation:'Only this input/scope was decompiled. Source previews above 1 MiB are explicitly truncated; full generated files remain on disk. No behavior or general equivalence is established.'};
    await writeFile(path.join(run,'result.json'),JSON.stringify(report,null,2)+'\n');return report;
  }catch(error){await writeFile(path.join(run,'failure.json'),JSON.stringify({status:'failed',message:(error as Error).message,sourceSha256:target.sha256,resources},null,2));throw error;}
  finally{reservation?.release();db?.close();await rm(runtime,{recursive:true,force:true});}
}
