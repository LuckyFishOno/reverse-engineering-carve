import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {realpath,readFile,readdir,mkdir,writeFile} from 'node:fs/promises';
import {z} from 'zod';
import {digest,loadSource} from './artifact.js';
import {analyze} from './analyze.js';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {nativeAnalysis} from './native.js';
import {managedAnalysis} from './managed.js';
import {acquireProcessLease,processIsLive,processGroupMembers,type ToolProcess,type ProcessLease} from './process-lease.js';
import {linkageKind} from './linkage.js';
import {engineResources,resolveEngineResources,type ResolvedEngineResources} from './engine-resources.js';
import {VERSION} from './version.js';

export interface EngineConfiguration {ghidra?:string;javaHome?:string;jadx?:string}
export const analysisRequest=z.object({
  file:z.string().min(1),timeoutMs:z.number().int().min(1000).max(86400000).default(600000),
  native:z.object({linkage:linkageKind.optional(),function:z.string().min(1).optional(),strings:z.string().max(1000).optional(),window:z.string().min(1).optional(),bytes:z.number().int().min(1).max(4096).optional(),after:z.string().optional(),limit:z.number().int().min(1).max(10000).optional()}).strict().optional(),
  managed:z.object({class:z.string().min(1).optional(),mode:z.enum(['auto','simple','fallback']).optional()}).strict().optional(),
  // Optional so requests recorded before 0.20 keep their exact job identity.
  resources:engineResources.optional()
}).strict();
type Request=z.infer<typeof analysisRequest>;
type Row=Record<string,any>;
function openQueue(workspace:string){
  const db=openIndex(workspace);db.exec(`CREATE TABLE IF NOT EXISTS analysis_jobs(id TEXT PRIMARY KEY,file TEXT,sha256 TEXT,backend TEXT,request TEXT,provider TEXT,status TEXT,attempt INTEGER NOT NULL,created TEXT,updated TEXT,result TEXT,error TEXT,owner TEXT,guard TEXT);
    CREATE INDEX IF NOT EXISTS analysis_jobs_status ON analysis_jobs(status,created,id);
    CREATE TABLE IF NOT EXISTS analysis_attempts(job TEXT,attempt INTEGER,status TEXT,started TEXT,finished TEXT,owner TEXT,guard TEXT,result TEXT,error TEXT,PRIMARY KEY(job,attempt));`);return db;
}
async function providerIdentity(backend:string,engines:EngineConfiguration,signal?:AbortSignal){
  const files:string[]=[];let paths:EngineConfiguration={};let version:string|null=null;
  if(backend==='ghidra'){
    if(!engines.ghidra||!engines.javaHome)throw new Error('Configure ghidra and javaHome before queueing native analysis.');
    paths={ghidra:await realpath(engines.ghidra),javaHome:await realpath(engines.javaHome)};
    files.push(path.join(paths.ghidra!,'Ghidra/application.properties'),path.join(paths.ghidra!,'support/analyzeHeadless'),path.join(paths.ghidra!,'support/launch.sh'),path.join(paths.javaHome!,'bin/java'),fileURLToPath(new URL('../engines/ghidra/CarveExport.java',import.meta.url)));
    version=/^application.version=(.+)$/m.exec(await readFile(files[0]!,'utf8'))?.[1]?.trim()??null;if(!version)throw new Error('Cannot identify queued Ghidra version.');
    const os=({darwin:{arm64:'mac_arm_64',x64:'mac_x86_64'},linux:{arm64:'linux_arm_64',x64:'linux_x86_64'}} as Record<string,Record<string,string>>)[process.platform]?.[process.arch];
    if(!os)throw new Error('Queued native analysis currently requires a supported POSIX host.');
    files.push(path.join(paths.ghidra!,'Ghidra/Features/Decompiler/os',os,'decompile'));
  }else if(backend==='jadx'){
    if(!engines.jadx||!engines.javaHome)throw new Error('Configure jadx and javaHome before queueing DEX/Java analysis.');
    paths={jadx:await realpath(engines.jadx),javaHome:await realpath(engines.javaHome)};files.push(paths.jadx!,path.join(paths.javaHome!,'bin/java'));
    const lib=path.resolve(paths.jadx!,'../../lib');const jars=(await readdir(lib)).filter(n=>/^jadx.*\.jar$/.test(n)).sort();
    if(!jars.length||jars.length>32)throw new Error('Configure a JADX distribution with identifiable main jars in its lib directory.');
    files.push(...jars.map(n=>path.join(lib,n)));
  }else if(backend==='javascript'){
    version=VERSION;for(const file of ['artifact.js','analyze.js','commonjs.js','globals.js'])files.push(fileURLToPath(new URL('./'+file,import.meta.url)));
  }else return null;
  const records=[];for(const file of files){const actual=await realpath(file);const current=await hashFile(actual,signal);records.push({path:actual,sha256:current.sha256,bytes:current.bytes});}
  const identity={backend,version,paths,files:records,scope:'Selected launchers, primary archives/scripts, native decompiler and JDK executable. Full tool installations, JDK libraries and local databases are not independently authenticated.'};
  return{...identity,sha256:digest(JSON.stringify(identity))};
}
function route(target:Awaited<ReturnType<typeof indexedFile>>,request:Request){
  const backend=target.facts.backend;
  if(request.native&&backend!=='ghidra'||request.managed&&backend!=='jadx')throw new Error('Analysis selector does not match the indexed backend.');
  const native=request.native??{};
  if([native.function,native.strings,native.window,native.linkage].filter(v=>v!==undefined).length>1||native.bytes!==undefined&&!native.window||native.after&&(native.function||native.window))throw new Error('Conflicting native analysis selectors.');
  return backend==='javascript'&&target.facts.format!=='javascript'?'existing-js-container-workflow':backend;
}
export async function enqueueAnalysis(workspace:string,requests:unknown,engines:EngineConfiguration={},signal?:AbortSignal){
  const selected=z.array(analysisRequest).min(1).max(100).parse(requests);const root=await realpath(workspace);const items=[];
  const providers=new Map<string,Awaited<ReturnType<typeof providerIdentity>>>();
  const db=openQueue(root);
  try{for(const request of selected){
    if(signal?.aborted)throw new Error('Analysis enqueue cancelled; already recorded jobs are retained.');
    const target=await indexedFile(root,request.file,signal);const backend=route(target,request);
    if(request.resources&&!['ghidra','jadx'].includes(backend))throw new Error('Engine resources apply only to Ghidra or JADX analysis requests.');
    if(request.resources)resolveEngineResources(request.resources);
    if(!providers.has(backend))providers.set(backend,await providerIdentity(backend,engines,signal));const provider=providers.get(backend)!;
    const id=digest(JSON.stringify({schema:'carve/analysis-job@1',file:request.file,sha256:target.sha256,backend,request,provider}));
    const status=provider?'queued':'unsupported';const now=new Date().toISOString();
    db.prepare('INSERT OR IGNORE INTO analysis_jobs(id,file,sha256,backend,request,provider,status,attempt,created,updated) VALUES(?,?,?,?,?,?,?,0,?,?)').run(id,request.file,target.sha256,backend,JSON.stringify(request),JSON.stringify(provider),status,now,now);
    const row=db.prepare('SELECT status,attempt,request,provider FROM analysis_jobs WHERE id=?').get(id) as Row;
    if(row.request!==JSON.stringify(request)||row.provider!==JSON.stringify(provider))throw new Error('Existing analysis job identity record changed; inspect the owned workspace before re-enqueueing.');
    if(['stale-input','stale-provider'].includes(row.status)){
      db.prepare("UPDATE analysis_jobs SET status='queued',error=NULL,result=NULL,updated=? WHERE id=? AND status IN ('stale-input','stale-provider')").run(now,id);row.status='queued';
    }
    items.push({id,file:request.file,sourceSha256:target.sha256,backend,status:row.status,attempts:row.attempt});
  }return{schema:'carve/analysis-enqueue@1',workspace:root,items,executesTarget:false,scope:'Analysis requests only. Unsupported formats stay unsupported; no capability match, reconstruction or behavior verification is inferred.'};}
  finally{db.close();}
}
async function liveness(row:Row){
  if(row.status!=='running')return null;
  try{const guard=row.guard?JSON.parse(row.guard):null;return{owner:row.owner&&await processIsLive(JSON.parse(row.owner))?'live':'gone',supervisor:guard?.supervisor?await processIsLive(guard.supervisor)?'live':'gone':'unregistered',processGroup:guard?(await processGroupMembers(guard.processGroup)).length?'live':'gone':'unregistered'};}
  catch(error){return{owner:'unknown',processGroup:'unknown',detail:(error as Error).message};}
}
export async function queryAnalysisJobs(workspace:string,options:{id?:string;status?:string;limit?:number;offset?:number}={}){
  const root=await realpath(workspace);const limit=options.limit??20,offset=options.offset??0;
  if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use job limit1–100 and a nonnegative offset.');
  const db=openIndex(root,true);
  try{
    if(!db.prepare("SELECT name FROM sqlite_master WHERE name='analysis_jobs'").get())return{schema:'carve/analysis-jobs@1',workspace:root,total:0,items:[],nextOffset:null};
    const clauses:string[]=[],args:string[]=[];if(options.id){clauses.push('id=?');args.push(options.id);}if(options.status){clauses.push('status=?');args.push(options.status);}
    const where=clauses.length?' WHERE '+clauses.join(' AND '):'';
    const total=Number((db.prepare('SELECT count(*) n FROM analysis_jobs'+where).get(...args) as Row).n);
    const rows=db.prepare('SELECT * FROM analysis_jobs'+where+' ORDER BY created,id LIMIT ? OFFSET ?').all(...args,limit,options.id?0:offset) as Row[];
    const items=[];for(const row of rows){
      const indexed=db.prepare("SELECT f.sha256 FROM files f JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') WHERE f.path=?").get(row.file) as Row|undefined;
      items.push({...row,matchesCurrentInventory:indexed?.sha256===row.sha256,request:JSON.parse(row.request),provider:JSON.parse(row.provider),result:row.result?JSON.parse(row.result):null,owner:row.owner?JSON.parse(row.owner):null,guard:row.guard?JSON.parse(row.guard):null,liveness:await liveness(row)});
    }
    const attempts=options.id?db.prepare('SELECT attempt,status,started,finished,guard,result,error FROM analysis_attempts WHERE job=? ORDER BY attempt DESC LIMIT ? OFFSET ?').all(options.id,limit,offset).map(row=>({...row,guard:row.guard?JSON.parse(String(row.guard)):null,result:row.result?JSON.parse(String(row.result)):null})):undefined;
    const attemptTotal=options.id?Number((db.prepare('SELECT count(*) n FROM analysis_attempts WHERE job=?').get(options.id) as Row).n):0;
    return{schema:'carve/analysis-jobs@1',workspace:root,total,items,limit,offset,nextOffset:!options.id&&offset+rows.length<total?offset+rows.length:null,...(attempts?{attempts,attemptTotal,nextAttemptOffset:offset+attempts.length<attemptTotal?offset+attempts.length:null}:{}),scope:'Persisted status plus actual process inspection for running rows. Completed means the bounded analysis request, not feature reconstruction.'};
  }finally{db.close();}
}
export interface AnalysisQueueProgress {phase:'job-started'|'job-finished';id:string;attempt:number;status:string}
export async function runAnalysisQueue(workspace:string,options:{engines?:EngineConfiguration;maxJobs?:number;retry?:boolean;signal?:AbortSignal;onProgress?:(progress:AnalysisQueueProgress)=>void|Promise<void>;onProcess?:(guard:ToolProcess)=>void|Promise<void>;lease?:ProcessLease;admit?:(resources:ResolvedEngineResources)=>()=>void}={}){
  const maxJobs=options.maxJobs??1;if(!Number.isInteger(maxJobs)||maxJobs<1||maxJobs>10)throw new Error('Use maxJobs1–10 per synchronous batch.');
  if(options.signal?.aborted)throw new Error('Analysis queue cancelled.');
  const root=await realpath(workspace);const lease=options.lease??await acquireProcessLease(root,'analysis-queue');let db:ReturnType<typeof openQueue>|undefined;const items=[];
  if(lease.owner.pid!==process.pid||lease.directory!==root||lease.name!=='analysis-queue')throw new Error('Analysis queue lease belongs to a different process or workspace.');
  try{
    db=openQueue(root);
    // The workspace lease first establishes that any prior recorded engine group is gone.
    for(const row of db.prepare("SELECT * FROM analysis_jobs WHERE status='running'").all() as Row[]){
      const current=await liveness(row);if(current?.owner!=='gone'||current.supervisor==='live'||current.processGroup==='live'||current.processGroup==='unknown')throw new Error('A prior analysis job still has a live or uninspectable process.');
      const message='Previous runner stopped; actual owner and any registered engine group are gone. Explicit retry can resume this job.';
      db.prepare("UPDATE analysis_jobs SET status='interrupted',error=?,updated=? WHERE id=? AND status='running'").run(message,new Date().toISOString(),row.id);
      db.prepare("UPDATE analysis_attempts SET status='interrupted',finished=?,error=? WHERE job=? AND attempt=? AND status='running'").run(new Date().toISOString(),message,row.id,row.attempt);
    }
    const states=options.retry?"('queued','failed','interrupted')":"('queued')";
    const attempted=new Set<string>();
    for(let n=0;n<maxJobs&&!options.signal?.aborted;n++){
      const rows=db.prepare(`SELECT * FROM analysis_jobs WHERE status IN ${states} ORDER BY created,id LIMIT 11`).all() as Row[];
      const job=rows.find(row=>!attempted.has(row.id));if(!job)break;attempted.add(job.id);
      const request=analysisRequest.parse(JSON.parse(job.request)),provider=JSON.parse(job.provider);let status='failed',error:string|null=null,result:Row|null=null;
      const attempt=job.attempt+1;const now=new Date().toISOString();const owner=JSON.stringify(lease.owner);
      db.exec('BEGIN');try{
        db.prepare("UPDATE analysis_jobs SET status='running',attempt=?,owner=?,guard=NULL,error=NULL,result=NULL,updated=? WHERE id=?").run(attempt,owner,now,job.id);
        db.prepare("INSERT INTO analysis_attempts(job,attempt,status,started,owner) VALUES(?,?,'running',?,?)").run(job.id,attempt,now,owner);db.exec('COMMIT');
      }catch(e){db.exec('ROLLBACK');throw e;}
      try{
        await options.onProgress?.({phase:'job-started',id:job.id,attempt,status:'running'});
        let target:Awaited<ReturnType<typeof indexedFile>>;
        try{target=await indexedFile(root,job.file,options.signal);if(target.sha256!==job.sha256)throw new Error('Queued source hash no longer matches.');}
        catch(e){status=options.signal?.aborted?'interrupted':'stale-input';throw e;}
        const current=await providerIdentity(job.backend,options.engines??{},options.signal);
        if(current?.sha256!==provider.sha256){status='stale-provider';throw new Error('Configured provider identity changed; enqueue a new job for the current provider.');}
        const onProcess=async(guard:ToolProcess)=>{
          await lease.register(guard);
          db!.exec('BEGIN');try{db!.prepare('UPDATE analysis_jobs SET guard=?,updated=? WHERE id=?').run(JSON.stringify(guard),new Date().toISOString(),job.id);db!.prepare('UPDATE analysis_attempts SET guard=? WHERE job=? AND attempt=?').run(JSON.stringify(guard),job.id,attempt);db!.exec('COMMIT');}catch(e){db!.exec('ROLLBACK');throw e;}
          await options.onProcess?.(guard);
        };
        let analyzed:Row;
        const resources=['ghidra','jadx'].includes(job.backend)?resolveEngineResources(request.resources):undefined;
        const releaseAdmission=resources?options.admit?.(resources):undefined;
        try{
          if(job.backend==='ghidra')analyzed=await nativeAnalysis(root,{file:job.file,...request.native,ghidra:current!.paths.ghidra!,javaHome:current!.paths.javaHome!,timeoutMs:request.timeoutMs,resources:request.resources,signal:options.signal,onProcess});
          else if(job.backend==='jadx')analyzed=await managedAnalysis(root,{file:job.file,...request.managed,jadx:current!.paths.jadx!,javaHome:current!.paths.javaHome!,timeoutMs:request.timeoutMs,resources:request.resources,signal:options.signal,onProcess});
          else if(job.backend==='javascript'){
            const source=await loadSource(target.path);if(source.sha256!==job.sha256)throw new Error('JavaScript source changed before analysis.');
            const summary=analyze(source);analyzed={schema:'carve/javascript-analysis@1',status:'module-inspected',source:summary.source,exports:summary.exports.slice(0,100),exportsTruncated:summary.exports.length>100,symbols:summary.symbols.slice(0,100),symbolsTruncated:summary.symbols.length>100,executesTarget:false,scope:'Bounded static module inspection. Existing discover/plan/probe/extract tools handle selected JS capabilities.'};
          }else throw new Error('Unsupported queued backend.');
        }finally{releaseAdmission?.();}
        const output=path.join(root,'analysis-jobs',job.id,`attempt-${attempt}`);await mkdir(output,{recursive:true});const resultFile=path.join(output,'result.json');const text=JSON.stringify(analyzed,null,2)+'\n';
        if(Buffer.byteLength(text)>32*1024*1024)throw new Error('Analysis result exceeds32MiB. Reduce the requested scope.');
        await writeFile(resultFile,text,{flag:'wx'});
        result={file:resultFile,sha256:digest(text),bytes:Buffer.byteLength(text),status:analyzed.status,observationIds:analyzed.observationIds??[],observationIdsTruncated:analyzed.observationIdsTruncated??false};
        const completedStatus=['linkage-page-exported','inventory-page-exported','string-page-exported','data-window-exported','function-exported','sources-exported','module-inspected'].includes(analyzed.status)?'completed':['partial-function','partial-index'].includes(analyzed.status)?'partial':'failed';
        try{const after=await indexedFile(root,job.file,options.signal);if(after.sha256!==job.sha256)throw new Error('Queued input changed during analysis.');}
        catch(e){status=options.signal?.aborted?'interrupted':'stale-input';throw e;}
        try{if((await providerIdentity(job.backend,options.engines??{},options.signal))?.sha256!==provider.sha256)throw new Error('Provider identity changed during analysis.');}
        catch(e){status='stale-provider';throw e;}
        status=completedStatus;if(status==='failed')error='Provider did not complete the selected analysis: '+analyzed.status;
      }catch(e){error=(e as Error).message;if(options.signal?.aborted)status='interrupted';}
      const finished=new Date().toISOString();db.exec('BEGIN');try{
        db.prepare('UPDATE analysis_jobs SET status=?,updated=?,result=?,error=? WHERE id=?').run(status,finished,result?JSON.stringify(result):null,error,job.id);
        db.prepare('UPDATE analysis_attempts SET status=?,finished=?,result=?,error=? WHERE job=? AND attempt=?').run(status,finished,result?JSON.stringify(result):null,error,job.id,attempt);db.exec('COMMIT');
      }catch(e){db.exec('ROLLBACK');throw e;}
      items.push({id:job.id,file:job.file,attempt,status,result,error});await options.onProgress?.({phase:'job-finished',id:job.id,attempt,status});
    }
    const counts=db.prepare('SELECT status,count(*) count FROM analysis_jobs GROUP BY status ORDER BY status').all();
    return{schema:'carve/analysis-batch@1',workspace:root,items,counts,cancelled:Boolean(options.signal?.aborted),executesTarget:false,scope:'Selected static analysis requests only. Failed/interrupted jobs require explicit retry. Source/provider changes require re-enqueue. No complete feature boundary or behavior equivalence is inferred.'};
  }finally{try{db?.close();}finally{lease.release();}}
}
