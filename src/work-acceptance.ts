import path from 'node:path';
import {createHash} from 'node:crypto';
import {provenanceSchema} from './provenance.js';
import {open,realpath,lstat,mkdir,writeFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {digest} from './artifact.js';
import {canonicalWork} from './work-contract.js';
import {loadWorkPackage} from './work-package.js';
import {runReference} from './reference.js';
import {sequenceCasesSchema,sequenceOutcome} from './sequence.js';
import {budgetItems,responseBudget,measured} from './context-budget.js';
import type {BridgePathAccess} from './rea-bridge.js';
const hash=z.string().regex(/^[a-f0-9]{64}$/),text=z.string().trim().min(1).max(1200);
const file=z.string().min(1).max(1024).refine(s=>!path.isAbsolute(s)&&!/[\\\x00-\x1f]/.test(s)&&s.split('/').every(p=>p!==''&&p!=='.'&&p!=='..'),'Use a relative path without traversal.');
const command=z.object({runtime:z.enum(['node','direct']),file,args:z.array(z.string().max(2048).refine(s=>!s.includes('\0'))).max(32)}).strict();
export const acceptanceSpecSchema=z.object({schema:z.literal('carve/acceptance-spec@1'),packageId:hash,
 files:z.array(z.object({path:file,sha256:hash}).strict()).min(1).max(64),
 checks:z.array(z.object({id:z.string().regex(/^[a-z][a-z0-9-]{0,47}$/),kind:z.enum(['build','unit','live','original-comparison']),acceptance:z.array(text).min(1).max(32),
  validation:z.enum(['manual','ui','protocol','restart','stateful-sequence']).optional(),command,expectedStdout:z.string().max(8192).optional(),
  comparison:z.object({original:command,cases:file,mode:z.enum(['cases','stateful-sequences']),scope:z.enum(['declared-harness','target-cli']),limitations:text}).strict().optional()
 }).strict()).min(1).max(32)
}).strict().superRefine((s,ctx)=>{
 if(new Set(s.files.map(f=>f.path)).size!==s.files.length||new Set(s.checks.map(c=>c.id)).size!==s.checks.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate file paths or check IDs.'});
 const files=new Set(s.files.map(f=>f.path));
 for(const c of s.checks){
  if(!files.has(c.command.file)||c.comparison&&(!files.has(c.comparison.original.file)||!files.has(c.comparison.cases)))ctx.addIssue({code:z.ZodIssueCode.custom,message:'All command and cases files need declared hashes.'});
  if(c.comparison&&c.command.file===c.comparison.original.file)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Original and candidate commands must use distinct pinned files.'});
  if((c.kind==='original-comparison')!==Boolean(c.comparison))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Only original-comparison checks require comparison settings.'});
  if(['unit','live'].includes(c.kind)&&c.expectedStdout===undefined)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Unit/live checks require exact expectedStdout, including empty output if intended.'});
  if(c.comparison&&c.expectedStdout!==undefined)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Comparison expectations belong in cases, not expectedStdout.'});
  if(new Set(c.acceptance).size!==c.acceptance.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate acceptance references.'});
 }
});
type Spec=z.infer<typeof acceptanceSpecSchema>;
type Options={execute?:boolean;timeoutMs?:number;budgetBytes?:number;signal?:AbortSignal;authorizePath?:BridgePathAccess};
async function bytes(file:string,max=1048576){const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{const a=await h.stat();if(!a.isFile()||a.size>max)throw new Error('Acceptance file must be regular and within its byte limit.');const b=Buffer.alloc(a.size+1);let n=0;while(n<b.length){const r=await h.read(b,n,b.length-n);if(!r.bytesRead)break;n+=r.bytesRead;}const z=await h.stat();if(n!==a.size||z.size!==a.size||z.mtimeMs!==a.mtimeMs||z.ctimeMs!==a.ctimeMs)throw new Error('Acceptance file changed while reading.');return b.subarray(0,n);}finally{await h.close();}}
async function fileHash(file:string){const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);try{const before=await h.stat();if(!before.isFile()||before.size>8*1024**3)throw new Error('Acceptance pinned files must be regular and at most8GiB.');const chunk=Buffer.alloc(1048576),hash=createHash('sha256');let total=0;while(true){const r=await h.read(chunk,0,chunk.length);if(!r.bytesRead)break;total+=r.bytesRead;if(total>before.size)throw new Error('Acceptance file grew while hashing.');hash.update(chunk.subarray(0,r.bytesRead));}const after=await h.stat();if(total!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw new Error('Acceptance file changed while hashing.');return hash.digest('hex');}finally{await h.close();}}
async function exact(input:string,authorize?:BridgePathAccess){const p=path.resolve(input);await authorize?.(p);if(await realpath(p)!==p)throw new Error('Acceptance paths must not redirect through symlinks.');return p;}
async function pinFiles(root:string,spec:Spec,authorize?:BridgePathAccess){for(const f of spec.files){const p=await exact(path.join(root,f.path),authorize);if(await fileHash(p)!==f.sha256)throw new Error('Acceptance input changed: '+f.path);}}
function invoke(root:string,c:z.infer<typeof command>){return c.runtime==='node'?[process.execPath,path.join(root,c.file),...c.args]:[path.join(root,c.file),...c.args];}
const casesSchema=z.object({schema:z.literal('carve/acceptance-cases@1'),cases:z.array(z.object({name:text,args:z.array(z.unknown()),expected:z.unknown().optional()}).strict()).min(1).max(200)}).strict();
function parseCases(data:Buffer,mode:string){const input=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));const rows=mode==='stateful-sequences'?sequenceCasesSchema.parse(input).cases:casesSchema.parse(input).cases;if(new Set(rows.map(c=>c.name)).size!==rows.length)throw new Error('Comparison case names must be unique.');return rows;}
const outcomeSchema=z.discriminatedUnion('kind',[z.object({kind:z.literal('return'),value:z.unknown()}).strict(),z.object({kind:z.literal('harness-error'),detail:z.string()}).strict()]).superRefine((o,ctx)=>{if(o.kind==='return'&&!Object.hasOwn(o,'value'))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Return observations require value.'});});
const resultSchema=z.object({id:z.string(),kind:z.enum(['build','unit','live','original-comparison']),acceptance:z.array(z.string()),validation:z.string().optional(),passed:z.boolean(),scope:z.string().optional(),limitations:z.string().optional(),observed:outcomeSchema.optional(),results:z.array(z.object({name:z.string(),passed:z.boolean(),original:outcomeSchema,candidate:outcomeSchema}).strict()).optional()}).strict();
const reportSchema=z.object({schema:z.literal('carve/acceptance-report@1'),packageId:hash,taskId:hash,planId:hash,specId:hash,checkedAt:z.string().datetime(),root:z.string(),spec:acceptanceSpecSchema,specSha256:hash,runtime:z.object({node:z.string(),executable:z.string(),sha256:hash,platform:z.string(),arch:z.string()}).strict(),inputIntegrity:z.enum(['matched-before-and-after','changed-during-execution']),status:z.enum(['passed-declared-acceptance','incomplete-or-failed']),categories:z.record(z.string()),acceptance:z.array(z.object({name:z.string(),status:z.enum(['not-run','failed','passed-declared-checks']),checks:z.array(z.string())}).strict()),results:z.array(resultSchema),authority:z.string()}).strict();
function score(criteria:string[],results:z.infer<typeof resultSchema>[],integrity:string){
 const acceptance=criteria.map(name=>{const checks=results.filter(r=>r.acceptance.includes(name));return{name,status:!checks.length?'not-run':integrity!=='matched-before-and-after'||checks.some(c=>!c.passed)?'failed':'passed-declared-checks',checks:checks.map(c=>c.id)};});
 const categories=Object.fromEntries(['build','unit','live','original-comparison'].map(kind=>{const rows=results.filter(r=>r.kind===kind);return[kind,!rows.length?'not-run':integrity!=='matched-before-and-after'||rows.some(r=>!r.passed)?'failed':kind==='original-comparison'?'passed-supplied-cases':'passed-declared-checks'];}));
 return{acceptance,categories,status:acceptance.every(a=>a.status==='passed-declared-checks')?'passed-declared-acceptance':'incomplete-or-failed'};
}
export async function runWorkAcceptance(packagePath:string,rootPath:string,specInput:unknown,out:string,current:{plan:unknown;spec:unknown},options:Options={}){
 if(options.execute!==true)throw new Error('Acceptance executes trusted commands with host permissions. Supply execute:true; this is not a security sandbox.');
 const timeout=options.timeoutMs??3000;if(!Number.isInteger(timeout)||timeout<50||timeout>30000)throw new Error('timeoutMs must be50–30000.');responseBudget(options.budgetBytes);options.signal?.throwIfAborted();
 if(Buffer.byteLength(JSON.stringify(specInput)??'')>1048576)throw new Error('Acceptance specification exceeds1MiB.');
 const executionSignal=AbortSignal.any([...(options.signal?[options.signal]:[]),AbortSignal.timeout(120000)]);
 const spec=acceptanceSpecSchema.parse(specInput),pkg=await loadWorkPackage(packagePath,{authorizePath:options.authorizePath},current),root=await exact(rootPath,options.authorizePath);
 if(!(await lstat(root)).isDirectory())throw new Error('Acceptance root must be a directory.');
 if(pkg.id!==spec.packageId)throw new Error('Acceptance spec references a different work package.');
 const criteria=new Map(pkg.record.assignment.acceptance.map(a=>[a.name,a])),scenarios=pkg.record.interface.contract.behavior?.scenarios??[];
 for(const c of spec.checks)for(const name of c.acceptance){const a=criteria.get(name);if(!a)throw new Error('Unknown acceptance criterion: '+name);if(a.behaviorScenario){const s=scenarios.find(s=>s.id===a.behaviorScenario)!;if(c.kind==='build'||c.validation!==s.validation)throw new Error('Behavior acceptance needs a matching validation kind and cannot use a build check.');if(s.validation==='stateful-sequence'&&(c.comparison?.mode!=='stateful-sequences'))throw new Error('Stateful acceptance requires ordered sequence comparison.');}}
 await pinFiles(root,spec,options.authorizePath);
 // Parse every comparison and validate pinned sequence references before any command starts.
 let caseCount=0;const prepared=new Map<string,ReturnType<typeof parseCases>>();
 for(const c of spec.checks)if(c.comparison){const data=await bytes(path.join(root,c.comparison.cases));const rows=parseCases(data,c.comparison.mode);caseCount+=rows.length;if(caseCount>200)throw new Error('Use at most200 comparison cases across the acceptance run.');prepared.set(c.id,rows);for(const name of c.acceptance){const a=criteria.get(name)!;const s=scenarios.find(s=>s.id===a.behaviorScenario);if(s?.sequenceCase&&(s.sequenceCase.casesSha256!==digest(data)||!rows.some(r=>r.name===s.sequenceCase!.name)))throw new Error('Sequence case hash/name differs from the pinned behavior contract.');}}
 const destination=path.resolve(out);await options.authorizePath?.(destination,true);const parent=await exact(path.dirname(destination),options.authorizePath);if(path.join(parent,path.basename(destination))!==destination||destination===root||root.startsWith(destination+path.sep))throw new Error('Use a new output directory outside input ancestors.');
 options.signal?.throwIfAborted();await mkdir(destination,{mode:0o700});
 const results:any[]=[];let inputIntegrity='matched-before-and-after';
 for(const c of spec.checks){
  executionSignal.throwIfAborted();await pinFiles(root,spec,options.authorizePath);
  if(c.comparison){const rows=prepared.get(c.id)!,details=[];
   for(const row of rows){executionSignal.throwIfAborted();const args='steps' in row?row.steps.map(s=>s.args):row.args;
    const original=await runReference(invoke(root,c.comparison.original),'json-stdin',args,root,timeout,executionSignal),candidate=await runReference(invoke(root,c.command),'json-stdin',args,root,timeout,executionSignal);
    const a='steps' in row?sequenceOutcome(original,row.steps.length):original,b='steps' in row?sequenceOutcome(candidate,row.steps.length):candidate;
    const expected='steps' in row?row.steps.every((step,i)=>!Object.hasOwn(step,'expected')||(a.kind==='return'&&Array.isArray(a.value)&&isDeepStrictEqual(a.value[i],{kind:'return',value:step.expected}))):!Object.hasOwn(row,'expected')||(a.kind==='return'&&isDeepStrictEqual(a.value,row.expected));
    const passed=a.kind==='return'&&b.kind==='return'&&isDeepStrictEqual(a.value,b.value)&&(!('steps' in row)||Array.isArray(a.value)&&a.value.every(step=>step?.kind==='return'))&&expected;
    details.push({name:row.name,passed,original:a,candidate:b});if(Buffer.byteLength(JSON.stringify([results,details]))>8388608)throw new Error('Acceptance observations exceed8MiB; partial owned output retained.');
   }
   results.push({id:c.id,kind:c.kind,acceptance:c.acceptance,validation:c.validation,passed:details.every(r=>r.passed),scope:c.comparison.scope,limitations:c.comparison.limitations,results:details});
  }else{const observed=await runReference(invoke(root,c.command),'text-stdin',[''],root,timeout,executionSignal,'utf8');results.push({id:c.id,kind:c.kind,acceptance:c.acceptance,validation:c.validation,passed:observed.kind==='return'&&(c.expectedStdout===undefined||observed.value===c.expectedStdout),observed});}
  if(Buffer.byteLength(JSON.stringify(results))>8388608)throw new Error('Acceptance observations exceed8MiB; partial owned output retained.');
  try{await pinFiles(root,spec,options.authorizePath);}catch{inputIntegrity='changed-during-execution';break;}
 }
 const afterPackage=await loadWorkPackage(packagePath,{authorizePath:options.authorizePath},current);if(afterPackage.id!==pkg.id)throw new Error('Work package changed during acceptance.');
 const {acceptance,categories,status}=score([...criteria.keys()],results,inputIntegrity);
 const report={schema:'carve/acceptance-report@1',packageId:pkg.id,taskId:pkg.record.taskId,planId:pkg.record.planId,specId:pkg.record.specId,checkedAt:new Date().toISOString(),root,spec,specSha256:digest(canonicalWork(spec)),runtime:{node:process.version,executable:process.execPath,sha256:await fileHash(process.execPath),platform:process.platform,arch:process.arch},inputIntegrity,status,categories,acceptance,results,authority:'Executed declared checks only. Command assertions, adapter invocation and scenario semantics are not independently proven. Output is a local integrity record, not a signed attestation or whole-feature equivalence. No automatic work-ledger acceptance or provenance promotion.'};
 const data=Buffer.from(canonicalWork(report)+'\n');if(data.length>16777216)throw new Error('Acceptance report exceeds16MiB; partial owned output retained.');
 for(const name of ['report.json','manifest.json'])await options.authorizePath?.(path.join(destination,name),true);
 await writeFile(path.join(destination,'report.json'),data,{flag:'wx',mode:0o600});await writeFile(path.join(destination,'manifest.json'),JSON.stringify({schema:'carve/acceptance-manifest@1',sha256:digest(data),bytes:data.length})+'\n',{flag:'wx',mode:0o600});
 return presentReport(report,digest(data),destination,options);
}
export async function readWorkAcceptance(directory:string,packagePath:string,rootPath:string,current:{plan:unknown;spec:unknown},options:Options&{offset?:number;limit?:number;claim?:unknown;checkId?:string}={}){
 const budget=responseBudget(options.budgetBytes),offset=options.offset??0,limit=options.limit??8;if(!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use offset>=0 and limit1–100.');
 const dir=await exact(directory,options.authorizePath);for(const f of ['manifest.json','report.json'])await options.authorizePath?.(path.join(dir,f));
 const manifest=z.object({schema:z.literal('carve/acceptance-manifest@1'),sha256:hash,bytes:z.number().int().min(1).max(16777216)}).strict().parse(JSON.parse((await bytes(path.join(dir,'manifest.json'))).toString()));
 const data=await bytes(path.join(dir,'report.json'),16777216);if(data.length!==manifest.bytes||digest(data)!==manifest.sha256)throw new Error('Acceptance report integrity mismatch.');const report=reportSchema.parse(JSON.parse(data.toString()));
 const spec=acceptanceSpecSchema.parse(report.spec);if(report.schema!=='carve/acceptance-report@1'||digest(canonicalWork(spec))!==report.specSha256)throw new Error('Invalid acceptance report/spec.');
 const pkg=await loadWorkPackage(packagePath,{authorizePath:options.authorizePath},current),root=await exact(rootPath,options.authorizePath);if(report.packageId!==pkg.id||spec.packageId!==pkg.id||report.root!==root||report.taskId!==pkg.record.taskId||report.planId!==pkg.record.planId||report.specId!==pkg.record.specId)throw new Error('Acceptance report belongs to another package/root/revision.');
 await pinFiles(root,spec,options.authorizePath);
 const derived=score(pkg.record.assignment.acceptance.map(a=>a.name),report.results,report.inputIntegrity);
 if(!isDeepStrictEqual(derived.acceptance,report.acceptance)||!isDeepStrictEqual(derived.categories,report.categories)||derived.status!==report.status)throw new Error('Acceptance report totals differ from its observations.');
 if(report.results.length>spec.checks.length||report.inputIntegrity==='matched-before-and-after'&&report.results.length!==spec.checks.length)throw new Error('Acceptance report check count differs from its specification.');
 for(const [i,r]of report.results.entries()){const c=spec.checks[i]!;if(r.id!==c.id||r.kind!==c.kind||!isDeepStrictEqual(r.acceptance,c.acceptance)||r.validation!==c.validation)throw new Error('Acceptance report check binding differs.');if(c.comparison){const rows=parseCases(await bytes(path.join(root,c.comparison.cases)),c.comparison.mode);if(!r.results||r.results.length!==rows.length||r.results.some((x,j)=>x.name!==rows[j]!.name)||r.passed!==r.results.every(x=>x.passed)||r.scope!==c.comparison.scope||r.limitations!==c.comparison.limitations)throw new Error('Comparison report case binding differs.');for(const [j,x]of r.results.entries()){const row=rows[j]!,a='steps' in row?sequenceOutcome(x.original.kind==='return'?{kind:'return',value:x.original.value}:x.original,row.steps.length):x.original,b='steps' in row?sequenceOutcome(x.candidate.kind==='return'?{kind:'return',value:x.candidate.value}:x.candidate,row.steps.length):x.candidate;const expected='steps' in row?row.steps.every((step,i)=>!Object.hasOwn(step,'expected')||(a.kind==='return'&&Array.isArray(a.value)&&isDeepStrictEqual(a.value[i],{kind:'return',value:step.expected}))):!Object.hasOwn(row,'expected')||(a.kind==='return'&&isDeepStrictEqual(a.value,row.expected));if(x.passed!==(a.kind==='return'&&b.kind==='return'&&isDeepStrictEqual(a.value,b.value)&&(!('steps' in row)||Array.isArray(a.value)&&a.value.every(step=>step?.kind==='return'))&&expected))throw new Error('Comparison report pass flag differs from observed values.');}}else if(!r.observed||r.passed!==(r.observed.kind==='return'&&(c.expectedStdout===undefined||r.observed.value===c.expectedStdout)))throw new Error('Command report outcome differs.');}
 await pinFiles(root,spec,options.authorizePath);if(report.runtime?.executable!==process.execPath||report.runtime?.sha256!==await fileHash(process.execPath))throw new Error('Acceptance runtime changed.');
 let claimBinding:unknown;
 if(options.claim!==undefined){const claim=provenanceSchema.parse({schema:'carve/provenance@1',claims:[options.claim]}).claims[0]!;if(claim.kind!=='verified-behavior'||!options.checkId)throw new Error('Claim check requires a verified-behavior claim and checkId.');const c=spec.checks.find(c=>c.id===options.checkId),r=report.results.find(r=>r.id===options.checkId);const pins=new Map(spec.files.map(f=>[f.path,f.sha256]));
  if(!c?.comparison||!r?.passed||report.inputIntegrity!=='matched-before-and-after'||claim.comparison.reportSha256!==manifest.sha256||claim.comparison.originalSha256!==pins.get(c.comparison.original.file)||claim.comparison.candidateSha256!==pins.get(c.command.file)||claim.comparison.casesSha256!==pins.get(c.comparison.cases))throw new Error('Verification claim differs from a passing pinned comparison.');
  claimBinding={claimId:claim.id,checkId:c.id,status:'content-pins-match-passing-local-comparison',semanticScope:'claim prose remains agent-declared; read report scope/limitations',authenticity:'unsigned-local-record'};
 }
 const response=presentReport(report,manifest.sha256,dir,options);if(claimBinding){const {receipt,...rest}=response;const result=measured({...rest,claimBinding},budget);if(result.receipt.responseBytes>budget)throw new Error('Increase response budget for claim binding.');return result;}return response;
}
function presentReport(report:any,sha256:string,dir:string,options:Options&{offset?:number;limit?:number}){
 const budget=responseBudget(options.budgetBytes),offset=options.offset??0,limit=options.limit??8;
 const rows=report.acceptance;if(!Array.isArray(rows)||offset>rows.length)throw new Error('Invalid acceptance report rows or offset.');
 return budgetItems({schema:'carve/acceptance-view@1',reportSha256:sha256,packageId:report.packageId,status:report.status,categories:report.categories,inputIntegrity:report.inputIntegrity,integrity:'local-report-content-pinned',authenticity:'unsigned-local-record',authority:report.authority,reportFile:path.join(dir,'report.json'),total:rows.length,offset},rows.slice(offset,offset+limit).map(value=>({value})),budget);
}
