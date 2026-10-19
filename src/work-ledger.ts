import path from 'node:path';
import {constants} from 'node:fs';
import {open,realpath,lstat,mkdir,writeFile} from 'node:fs/promises';
import {randomUUID,createHash} from 'node:crypto';
import {DatabaseSync} from 'node:sqlite';
import {z} from 'zod';
import {loadWorkPackage} from './work-package.js';
import {canonicalWork} from './work-contract.js';
import {budgetItems,measured,responseBudget} from './context-budget.js';
import type {BridgePathAccess} from './rea-bridge.js';

const hash=z.string().regex(/^[a-f0-9]{64}$/),text=(n:number)=>z.string().trim().min(1).max(n);
export const WORK_STATES=['queued','claimed','failed','proposed','submitted'] as const;
// Work attempts (closed as failed, proposed or submitted) are limited per task. A plain release
// returns the task without consuming that budget; it only counts toward a larger bound on claims,
// which keeps each task's stored history finite.
export const WORK_ATTEMPT_LIMIT=100,CLAIM_LIMIT=1000;
const attemptNumber=z.number().int().min(1).max(CLAIM_LIMIT);
export const workClaimSchema=z.object({id:hash,owner:text(100),attempt:attemptNumber,claimId:z.string().uuid()}).strict();
type Claim=z.infer<typeof workClaimSchema>;
export const workSubmissionSchema=z.object({kind:z.enum(['proposal','implementation']),summary:text(2000),
 checks:z.array(z.object({name:text(100),status:z.enum(['passed','failed','not-run']),detail:text(2000)}).strict()).max(32).default([]),
 unknowns:z.array(text(500)).max(64).default([])}).strict();
const localPath=z.string().min(1).max(4096),currentFiles={plan:localPath,spec:localPath};
export const workLedgerRequestSchema=z.discriminatedUnion('action',[
 z.object({action:z.literal('create')}).strict(),
 z.object({action:z.literal('register'),package:localPath,...currentFiles}).strict(),
 z.object({action:z.literal('claim'),id:hash,owner:text(100),...currentFiles,retry:z.boolean().optional()}).strict(),
 z.object({action:z.literal('close'),claim:workClaimSchema,outcome:z.enum(['released','failed']),reason:text(2000)}).strict(),
 z.object({action:z.literal('submit'),claim:workClaimSchema,...currentFiles,submission:localPath,outputRoot:localPath.optional()}).strict(),
 z.object({action:z.literal('requeue'),id:hash,attempt:attemptNumber,submissionId:hash,reviewer:text(100),reason:text(2000),...currentFiles}).strict(),
 z.object({action:z.literal('read'),view:z.enum(['jobs','attempts','result']).optional(),id:hash.optional(),status:z.enum(WORK_STATES).optional(),attempt:attemptNumber.optional(),offset:z.number().int().nonnegative().optional(),limit:z.number().int().min(1).max(100).optional(),characters:z.number().int().min(1).max(12000).optional()}).strict()
]);
type Options={budgetBytes?:number;signal?:AbortSignal;authorizePath?:BridgePathAccess};
type Current={plan:unknown;spec:unknown};
type Row=Record<string,any>;
const markerSchema=z.object({schema:z.literal('carve/work-ledger@1'),id:z.string().uuid()}).strict();
const jobSchema=z.object({id:hash,feature:text(64),package:text(4096),planId:hash,specId:hash,taskId:hash,status:z.enum(WORK_STATES),attempt:z.number().int().min(0).max(CLAIM_LIMIT),owner:text(100).nullable(),claimId:z.string().uuid().nullable(),created:text(100),updated:text(100)}).strict();
const scope='Coordination records only. Owner labels and claim IDs are not authenticated identities. No agents started, dependency acceptance, test execution, target build or merge.';
const files=['ledger.sqlite','ledger.sqlite-journal','ledger.sqlite-wal','ledger.sqlite-shm'];
function check(options:Options){responseBudget(options.budgetBytes);options.signal?.throwIfAborted();}
function envelope(root:string,action:string,body:Row,options:Options){
 const result=measured({schema:'carve/work-ledger-view@1',ledger:root,action,...body,startsAgents:false,scope},responseBudget(options.budgetBytes));
 if(result.receipt.responseBytes>result.receipt.budgetBytes)throw new Error('Ledger response exceeds budgetBytes; increase the budget. No transition was committed.');return result;
}
async function boundedFile(file:string,max:number){const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{
 const before=await handle.stat();if(!before.isFile()||before.size>max)throw new Error('Ledger file must be regular and within its size bound.');
 const bytes=Buffer.alloc(before.size+1);let n=0;while(n<bytes.length){const r=await handle.read(bytes,n,bytes.length-n);if(!r.bytesRead)break;n+=r.bytesRead;}
 const after=await handle.stat();if(n!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw new Error('Ledger file changed while reading.');return bytes.subarray(0,n);
 }finally{await handle.close();}}
// realpath also canonicalizes letter case and Unicode normalization on case-insensitive or
// normalizing file systems (default APFS), so a mismatch is only called a symlink when one is found.
async function exactPath(file:string,base:string|null,what:string){
 const actual=await realpath(file);if(actual===file)return;
 let current=base??path.parse(file).root;
 for(const part of path.relative(current,file).split(path.sep).filter(Boolean)){current=path.join(current,part);if((await lstat(current)).isSymbolicLink())throw new Error(`${what} must not redirect through symlinks (${current} is a link); use the canonical path ${actual}.`);}
 throw new Error(`${what} differs from its on-disk name only by letter case or Unicode normalization; use exactly ${actual}.`);
}
async function canonicalDirectory(input:string){
 const root=path.resolve(input),info=await lstat(root);
 if(info.isSymbolicLink())throw new Error(`Ledger/output directory must not redirect through symlinks (${root} is a link).`);
 if(!info.isDirectory())throw new Error('Ledger/output directory must be a directory: '+root);
 await exactPath(root,null,'Ledger/output directory');return root;
}
async function connect(input:string,options:Options,readOnly=false){
 check(options);await options.authorizePath?.(input);const root=await canonicalDirectory(input);
 await options.authorizePath?.(path.join(root,'ledger.json'));const marker=markerSchema.parse(JSON.parse((await boundedFile(path.join(root,'ledger.json'),1024)).toString('utf8')));
 for(const name of files){const file=path.join(root,name);await options.authorizePath?.(file,true);try{const s=await lstat(file);if(!s.isFile()||s.size>134217728)throw new Error('Ledger database/sidecars must be regular, bounded and not redirected.');await exactPath(file,root,'Ledger file '+name);}catch(error){if(name==='ledger.sqlite'||(error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}}
 const db=new DatabaseSync(path.join(root,'ledger.sqlite'),{readOnly});try{
 db.exec('PRAGMA busy_timeout=1000; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;');
 if(!readOnly)db.exec('PRAGMA max_page_count=32768;');
 const meta=db.prepare('SELECT * FROM control WHERE singleton=1').get() as Row;
 if(meta?.identity!==marker.id||meta.schema!=='carve/work-ledger-db@1'||!Number.isSafeInteger(meta.revision)||meta.revision<0||meta.planId!==null&&!hash.safeParse(meta.planId).success||meta.specId!==null&&!hash.safeParse(meta.specId).success)throw new Error('Ledger marker/database identity or revision differs.');
 return{root,db};
 }catch(error){db.close();throw error;}
}
function control(db:DatabaseSync){const r=db.prepare('SELECT revision,planId,specId FROM control WHERE singleton=1').get() as Row;return{revision:Number(r.revision),planId:r.planId as string|null,specId:r.specId as string|null};}
function bump(db:DatabaseSync){db.prepare('UPDATE control SET revision=revision+1 WHERE singleton=1').run();return control(db);}
function job(db:DatabaseSync,id:string){hash.parse(id);const row=db.prepare('SELECT * FROM jobs WHERE id=?').get(id);if(!row)throw new Error('Unknown work package in this ledger.');return jobSchema.parse(row);}
function workAttempts(db:DatabaseSync,id:string){return Number((db.prepare("SELECT count(*) n FROM attempts WHERE job=? AND status<>'released'").get(id) as Row).n);}
// Whether a claim can start now, so an exhausted task is not shown as simply queued.
function claimability(row:ReturnType<typeof job>,work:number){
 if(row.status==='claimed')return'held';if(row.status==='proposed'||row.status==='submitted')return'awaiting-review';
 if(row.attempt>=CLAIM_LIMIT||work>=WORK_ATTEMPT_LIMIT)return'exhausted';return row.status==='failed'?'needs-explicit-retry':'available';
}
function owned(db:DatabaseSync,identity:Claim){const row=job(db,identity.id);if(row.status!=='claimed'||row.attempt!==identity.attempt||row.claimId!==identity.claimId||row.owner!==identity.owner)throw new Error('Stale or mismatched claim/attempt/owner; no transition committed.');return row;}
function transaction<T>(db:DatabaseSync,fn:()=>T){db.exec('BEGIN IMMEDIATE');try{const result=fn();db.exec('COMMIT');return result;}catch(error){db.exec('ROLLBACK');throw error;}}
async function checkedPackage(row:ReturnType<typeof job>,current:Current,options:Options){const loaded=await loadWorkPackage(row.package,options,current);if(loaded.id!==row.id||loaded.record.planId!==row.planId||loaded.record.specId!==row.specId||loaded.record.taskId!==row.taskId)throw new Error('Registered work package changed or differs from its ledger identity.');return loaded;}

export async function createWorkLedger(out:string,options:Options={}){
 check(options);await options.authorizePath?.(out,true);const resolved=path.resolve(out),root=path.join(await realpath(path.dirname(resolved)),path.basename(resolved)),id=randomUUID();await options.authorizePath?.(root,true);
 const result=envelope(root,'create',{id,revision:0,planId:null,specId:null},options);options.signal?.throwIfAborted();await mkdir(root,{mode:0o700});
 try{for(const name of [...files,'ledger.json'])await options.authorizePath?.(path.join(root,name),true);options.signal?.throwIfAborted();
 const db=new DatabaseSync(path.join(root,'ledger.sqlite'));try{db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=32768;
 CREATE TABLE control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema TEXT NOT NULL,identity TEXT NOT NULL,revision INTEGER NOT NULL,planId TEXT,specId TEXT);
 CREATE TABLE jobs(id TEXT PRIMARY KEY,feature TEXT UNIQUE NOT NULL,package TEXT NOT NULL,planId TEXT NOT NULL,specId TEXT NOT NULL,taskId TEXT NOT NULL,status TEXT NOT NULL,attempt INTEGER NOT NULL,owner TEXT,claimId TEXT,created TEXT NOT NULL,updated TEXT NOT NULL);
 CREATE TABLE attempts(job TEXT NOT NULL,attempt INTEGER NOT NULL,claimId TEXT UNIQUE NOT NULL,owner TEXT NOT NULL,status TEXT NOT NULL,started TEXT NOT NULL,finished TEXT,reason TEXT,result TEXT,PRIMARY KEY(job,attempt),FOREIGN KEY(job) REFERENCES jobs(id));
 CREATE TABLE reviews(job TEXT NOT NULL,attempt INTEGER NOT NULL,submissionId TEXT NOT NULL,reviewer TEXT NOT NULL,reason TEXT NOT NULL,created TEXT NOT NULL,PRIMARY KEY(job,attempt),FOREIGN KEY(job,attempt) REFERENCES attempts(job,attempt));
 CREATE INDEX jobs_order ON jobs(created,id);`);
 db.prepare("INSERT INTO control VALUES(1,'carve/work-ledger-db@1',?,0,NULL,NULL)").run(id);
 }finally{db.close();}
 options.signal?.throwIfAborted();await writeFile(path.join(root,'ledger.json'),JSON.stringify({schema:'carve/work-ledger@1',id})+'\n',{flag:'wx',mode:0o600});return result;
 }catch(error){throw new Error('Ledger creation did not finish; owned partial files retained at '+root+'. '+(error as Error).message);}
}
export async function registerWork(input:string,packagePath:string,current:Current,options:Options={}){
 check(options);const loaded=await loadWorkPackage(packagePath,options,current),{root,db}=await connect(input,options);
 try{return transaction(db,()=>{
  options.signal?.throwIfAborted();const meta=control(db);if(meta.planId!==null&&(meta.planId!==loaded.record.planId||meta.specId!==loaded.record.specId))throw new Error('Ledger belongs to another plan/spec revision. Create a new ledger; preserve the old attempts.');
  const existing=db.prepare('SELECT id FROM jobs WHERE id=?').get(loaded.id);if(existing){const row=job(db,loaded.id);if(row.package!==loaded.root)throw new Error('This package is already registered at another path; retain its recorded location.');return envelope(root,'register',{...control(db),job:row,reused:true,currentPlanCheck:'matched-supplied-plan-and-spec'},options);}
  if(Number((db.prepare('SELECT count(*) n FROM jobs').get() as Row).n)>=500)throw new Error('Use at most500 registered tasks per ledger.');
  const now=new Date().toISOString(),r=loaded.record;db.prepare('UPDATE control SET planId=?,specId=? WHERE singleton=1').run(r.planId,r.specId);
  db.prepare("INSERT INTO jobs VALUES(?,?,?,?,?,?,'queued',0,NULL,NULL,?,?)").run(loaded.id,r.feature.id,loaded.root,r.planId,r.specId,r.taskId,now,now);
  return envelope(root,'register',{...bump(db),job:job(db,loaded.id),reused:false,currentPlanCheck:'matched-supplied-plan-and-spec'},options);
 });}finally{db.close();}
}
export async function claimWork(input:string,id:string,owner:string,current:Current,options:Options&{retry?:boolean}={}){
 check(options);owner=text(100).parse(owner);const {root,db}=await connect(input,options);
 try{const row=job(db,id);await checkedPackage(row,current,options);return transaction(db,()=>{
  options.signal?.throwIfAborted();const latest=job(db,id);if(latest.status!=='queued'&&!(latest.status==='failed'&&options.retry===true))throw new Error('Task is not queued. Failed work needs explicit retry; claimed/submitted/proposed work cannot be taken over.');
  if(latest.attempt>=CLAIM_LIMIT)throw new Error(`Task reached ${CLAIM_LIMIT} claims in total, including releases. Create a new ledger for it; this one keeps the history.`);
  if(workAttempts(db,id)>=WORK_ATTEMPT_LIMIT)throw new Error(`Task reached ${WORK_ATTEMPT_LIMIT} work attempts (failed, proposed or submitted). Create a new ledger for it; this one keeps the history.`);
  const now=new Date().toISOString(),attempt=latest.attempt+1,claimId=randomUUID();db.prepare("UPDATE jobs SET status='claimed',attempt=?,owner=?,claimId=?,updated=? WHERE id=?").run(attempt,owner,claimId,now,id);
  db.prepare("INSERT INTO attempts(job,attempt,claimId,owner,status,started) VALUES(?,?,?,?,'claimed',?)").run(id,attempt,claimId,owner,now);
  return envelope(root,'claim',{...bump(db),job:job(db,id),currentPlanCheck:'matched-supplied-plan-and-spec',lease:'explicit-release; no timeout, PID inference or automatic takeover'},options);
 });}finally{db.close();}
}
export async function releaseWork(input:string,claim:unknown,outcome:'released'|'failed',reason:string,options:Options={}){
 check(options);const identity=workClaimSchema.parse(claim);reason=text(2000).parse(reason);if(!['released','failed'].includes(outcome))throw new Error('Use released or failed.');const {root,db}=await connect(input,options);
 try{return transaction(db,()=>{options.signal?.throwIfAborted();owned(db,identity);const now=new Date().toISOString();
  db.prepare('UPDATE jobs SET status=?,owner=NULL,claimId=NULL,updated=? WHERE id=?').run(outcome==='released'?'queued':'failed',now,identity.id);
  db.prepare('UPDATE attempts SET status=?,finished=?,reason=? WHERE job=? AND attempt=? AND claimId=?').run(outcome,now,reason,identity.id,identity.attempt,identity.claimId);
  return envelope(root,outcome,{...bump(db),job:job(db,identity.id),closedAttempt:identity.attempt},options);
 });}finally{db.close();}
}
async function artifactFiles(outputRoot:string,paths:string[],options:Options){
 await options.authorizePath?.(outputRoot);const root=await canonicalDirectory(outputRoot),files=[];let total=0;
 for(const relative of paths){options.signal?.throwIfAborted();const file=path.join(root,...relative.split('/'));await options.authorizePath?.(file);await exactPath(file,root,'Submitted artifact '+relative);
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{const before=await handle.stat();if(!before.isFile()||before.size>16777216||(total+=before.size)>67108864)throw new Error('Deliver regular artifacts <=16MiB each and64MiB total.');
   const hash=createHash('sha256'),buffer=Buffer.alloc(65536);let n=0;while(true){options.signal?.throwIfAborted();const read=await handle.read(buffer);if(!read.bytesRead)break;n+=read.bytesRead;if(n>before.size)throw new Error('Submitted artifact changed while hashing.');hash.update(buffer.subarray(0,read.bytesRead));}
   const after=await handle.stat();if(n!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw new Error('Submitted artifact changed while hashing.');files.push({file:relative,sha256:hash.digest('hex'),bytes:n});
  }finally{await handle.close();}
 }return{root,files};
}
export async function submitWork(input:string,claim:unknown,current:Current,submission:unknown,outputRoot:string|undefined,options:Options={}){
 check(options);const identity=workClaimSchema.parse(claim),data=workSubmissionSchema.parse(submission);if(data.kind==='implementation'?!outputRoot:outputRoot!==undefined)throw new Error('An implementation needs outputRoot; a proposal must not supply outputRoot.');
 const {root,db}=await connect(input,options);try{const row=owned(db,identity),loaded=await checkedPackage(row,current,options);
  const artifacts=data.kind==='implementation'?await artifactFiles(outputRoot!,loaded.record.assignment.files,options):null;
  // Recheck the package after artifact hashing; the current plan/spec are the caller-supplied revision.
  await checkedPackage(row,current,options);const result={schema:'carve/work-submission@1',packageId:identity.id,planId:row.planId,specId:row.specId,taskId:row.taskId,claim:identity,...data,artifacts,
   artifactScope:artifacts?'Per-file hashes captured during submission, not a locked snapshot. Files remain external and can change.':'No implementation files supplied.',checksAuthority:'Agent-reported; not executed or authenticated by the ledger.',verification:'not-run-by-ledger',targetAssessment:'not-performed',integration:'not-accepted-or-merged'};
  const serialized=canonicalWork(result);if(Buffer.byteLength(serialized)>131072)throw new Error('Submission record exceeds128KiB; reduce its declared checks/unknowns.');
  return transaction(db,()=>{options.signal?.throwIfAborted();owned(db,identity);const now=new Date().toISOString(),status=data.kind==='implementation'?'submitted':'proposed';
   db.prepare('UPDATE jobs SET status=?,owner=NULL,claimId=NULL,updated=? WHERE id=?').run(status,now,identity.id);
   db.prepare('UPDATE attempts SET status=?,finished=?,result=? WHERE job=? AND attempt=? AND claimId=?').run(status,now,serialized,identity.id,identity.attempt,identity.claimId);
   return envelope(root,'submit',{...bump(db),job:job(db,identity.id),closedAttempt:identity.attempt,submissionId:createHash('sha256').update(serialized).digest('hex'),currentPlanCheck:'matched-supplied-plan-and-spec',kind:data.kind,artifactFiles:artifacts?.files.length??0,checksAuthority:result.checksAuthority,verification:result.verification,integration:result.integration},options);
  });
 }finally{db.close();}
}
export async function requeueWork(input:string,id:string,attempt:number,submissionId:string,reviewer:string,reason:string,current:Current,options:Options={}){
 check(options);hash.parse(id);hash.parse(submissionId);reviewer=text(100).parse(reviewer);reason=text(2000).parse(reason);attemptNumber.parse(attempt);
 const {root,db}=await connect(input,options);try{await checkedPackage(job(db,id),current,options);return transaction(db,()=>{
  options.signal?.throwIfAborted();const row=job(db,id),old=db.prepare('SELECT result FROM attempts WHERE job=? AND attempt=?').get(id,attempt) as Row|undefined;
  if(row.attempt!==attempt||!['proposed','submitted'].includes(row.status)||typeof old?.result!=='string'||Buffer.byteLength(old.result)>131072||createHash('sha256').update(old.result).digest('hex')!==submissionId)throw new Error('Stale review: select the current proposed/submitted attempt and exact submissionId.');
  const now=new Date().toISOString();db.prepare('INSERT INTO reviews VALUES(?,?,?,?,?,?)').run(id,attempt,submissionId,reviewer,reason,now);db.prepare("UPDATE jobs SET status='queued',updated=? WHERE id=?").run(now,id);
  return envelope(root,'requeue',{...bump(db),job:job(db,id),currentPlanCheck:'matched-supplied-plan-and-spec',review:{attempt,submissionId,reviewer,reason,created:now},previousResult:'retained-unchanged',integration:'not-accepted-or-merged'},options);
 });}finally{db.close();}
}
export async function queryWorkLedger(input:string,options:Options&{view?:'jobs'|'attempts'|'result';id?:string;status?:typeof WORK_STATES[number];attempt?:number;offset?:number;limit?:number;characters?:number}={}){
 check(options);const {view='jobs',offset=0,limit=20,characters=2000}=options;
 if(!['jobs','attempts','result'].includes(view)||!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100||!Number.isInteger(characters)||characters<1||characters>12000)throw new Error('Use jobs/attempts/result, offset>=0, limit1–100 and characters1–12000.');
 if(options.id)hash.parse(options.id);if(options.status)z.enum(WORK_STATES).parse(options.status);if(view!=='jobs'&&!options.id||view==='result'&&(!Number.isInteger(options.attempt)||(options.attempt??0)<1||(options.attempt??0)>CLAIM_LIMIT))throw new Error(`Attempts need id; result also needs attempt1–${CLAIM_LIMIT}.`);
 if(options.status!==undefined&&view!=='jobs'||options.attempt!==undefined&&view!=='result')throw new Error('Status filters apply to jobs; attempt selection applies to result.');
 // A read may recover SQLite's own hot journal after a crashed writer. It never
 // releases an external worker's claim or changes its recorded transition.
 const {root,db}=await connect(input,options);try{
  db.exec('BEGIN');const base={schema:'carve/work-ledger-view@1',ledger:root,action:'read',view,...control(db),startsAgents:false,currentPlanCheck:'not-performed',scope};
  if(view==='result'){
   const r=db.prepare('SELECT result FROM attempts WHERE job=? AND attempt=?').get(options.id!,options.attempt!) as Row|undefined;if(!r?.result||typeof r.result!=='string'||Buffer.byteLength(r.result)>131072)throw new Error('No bounded submitted result for this attempt.');
   const text=r.result as string,high=(i:number)=>text.charCodeAt(i)>=0xd800&&text.charCodeAt(i)<=0xdbff,low=(i:number)=>text.charCodeAt(i)>=0xdc00&&text.charCodeAt(i)<=0xdfff;
   if(offset>text.length||low(offset)&&high(offset-1))throw new Error('Use an in-range UTF16 offset without splitting a surrogate pair.');
   const seal=(end:number)=>measured({...base,id:options.id,attempt:options.attempt,submissionId:createHash('sha256').update(text).digest('hex'),encoding:'JSON text excerpt; UTF16 offsets',offset,totalCharacters:text.length,text:text.slice(offset,end),nextOffset:end<text.length?end:null},responseBudget(options.budgetBytes));
   let end=Math.min(text.length,offset+characters);if(high(end-1)&&low(end))end--;let result=seal(end);while(result.receipt.responseBytes>result.receipt.budgetBytes&&end>offset){end=offset+Math.floor((end-offset)/2);if(high(end-1)&&low(end))end--;result=seal(end);}
   if(result.receipt.responseBytes>result.receipt.budgetBytes||end===offset&&offset<text.length)throw new Error('Budget cannot hold ledger result metadata and one character.');return result;
  }
  let rows:Row[],total:number;
  if(view==='attempts'){
   job(db,options.id!);total=Number((db.prepare('SELECT count(*) n FROM attempts WHERE job=?').get(options.id!) as Row).n);
   rows=db.prepare('SELECT a.attempt,a.claimId,a.owner,a.status,a.started,a.finished,a.reason,a.result,r.reviewer,r.reason reviewReason,r.created reviewedAt FROM attempts a LEFT JOIN reviews r ON r.job=a.job AND r.attempt=a.attempt WHERE a.job=? ORDER BY a.attempt LIMIT ? OFFSET ?').all(options.id!,limit,offset).map(row=>{
    const {result,...fields}=row;if(result!==null&&(typeof result!=='string'||Buffer.byteLength(result)>131072))throw new Error('Attempt result exceeds its bounded schema.');
    return{...fields,hasResult:result!==null,submissionId:result===null?null:createHash('sha256').update(result as string).digest('hex')};
   });
  }else{
   const conditions:string[]=[],args:string[]=[];if(options.id){conditions.push('id=?');args.push(options.id);}if(options.status){conditions.push('status=?');args.push(options.status);}const where=conditions.length?' WHERE '+conditions.join(' AND '):'';
   total=Number((db.prepare('SELECT count(*) n FROM jobs'+where).get(...args) as Row).n);rows=db.prepare('SELECT * FROM jobs'+where+' ORDER BY created,id LIMIT ? OFFSET ?').all(...args,limit,offset).map(r=>{const row=jobSchema.parse(r),work=workAttempts(db,row.id);return{...row,workAttempts:work,claimability:claimability(row,work)};});
  }
  if(offset>total)throw new Error('Ledger offset exceeds this view.');return budgetItems({...base,...(options.id?{id:options.id}:{}),total,offset},rows.map(value=>({value})),responseBudget(options.budgetBytes));
 }finally{db.close();}
}
