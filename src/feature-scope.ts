import path from 'node:path';
import {behaviorSummary} from './behavior.js';
import {constants} from 'node:fs';
import {open,realpath,lstat,mkdir,writeFile,link,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {z} from 'zod';
import {digest} from './artifact.js';
import {openIndex,metaValue,indexedFile,assertWorkspaceInPlace,claim} from './survey.js';
import {budgetItems,measured,responseBudget} from './context-budget.js';
import {featureRequestSchema,featureQuestions,type FeatureRequest} from './feature-intent.js';
import type {BridgePathAccess} from './rea-bridge.js';

const id=z.string().regex(/^[a-f0-9]{64}$/),MAX=1048576;
const sourceSchema=z.object({workspace:z.string(),file:z.string(),sourceSha256:id,format:z.string(),encrypted:z.boolean(),inventoryStatus:z.string(),
 observation:z.object({id,kind:z.string(),name:z.string().max(240),nameTruncated:z.boolean(),recordedCompleteCode:z.boolean()}).strict().optional()}).strict();
const recordSchema=z.object({schema:z.literal('carve/feature-scope@1'),request:featureRequestSchema,parentId:id.optional(),sources:z.array(sourceSchema).max(16)}).strict();
type RecordValue=z.infer<typeof recordSchema>;
export type FeatureScopeOptions={request?:unknown;id?:string;parentId?:string;view?:'summary'|'record'|'sources';offset?:number;limit?:number;characters?:number;budgetBytes?:number;signal?:AbortSignal;authorizePath?:BridgePathAccess;authorizeWorkspace?:(workspace:string)=>Promise<string>};

async function readBytes(file:string){
 const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const before=await h.stat();if(!before.isFile()||before.size>MAX)throw new Error('Scope record must be a regular file <=1MiB.');
  const bytes=Buffer.alloc(before.size+1);let n=0;for(;;){const r=await h.read(bytes,n,bytes.length-n);if(!r.bytesRead)break;n+=r.bytesRead;if(n>before.size)throw new Error('Scope record changed while reading.');}
  const after=await h.stat();if(n!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw new Error('Scope record changed while reading.');return bytes.subarray(0,n);
 }finally{await h.close();}
}
async function directory(folder:string,access?:BridgePathAccess,create=false){
 await access?.(folder,create);if(create)await mkdir(folder,{recursive:true,mode:0o700});
 if(!(await lstat(folder)).isDirectory()||await realpath(folder)!==folder)throw new Error('Scope storage must be a real directory, without symlink redirection.');
}
async function retained(root:string,selected:string,access?:BridgePathAccess){
 id.parse(selected);const folder=path.join(root,'feature-requests');await directory(folder,access);const file=path.join(folder,selected+'.json');await access?.(file);
 const bytes=await readBytes(file);if(digest(bytes)!==selected)throw new Error('Scope record differs from its content identity.');
 const record=recordSchema.parse(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
 if(record.sources.length!==record.request.leads.length||record.sources.some((s,i)=>{const lead=record.request.leads[i]!;return s.workspace!==lead.workspace||s.file!==lead.file||s.sourceSha256!==lead.sourceSha256||s.observation?.id!==lead.observationId;}))throw new Error('Scope request and recorded source bindings differ.');
 return{record,file};
}
async function bindSources(root:string,request:FeatureRequest,options:FeatureScopeOptions){
 const sources:RecordValue['sources']=[],seen=new Set<string>();
 for(const lead of request.leads){
  options.signal?.throwIfAborted();const requested=path.resolve(root,lead.workspace);await options.authorizePath?.(requested);
  const workspace=await realpath(requested);
  for(const name of ['.carve-workspace.json','index.sqlite','index.sqlite-wal','index.sqlite-shm'])await options.authorizePath?.(path.join(workspace,name),name.endsWith('-wal')||name.endsWith('-shm'));
  if(options.authorizeWorkspace&&await realpath(await options.authorizeWorkspace(requested))!==workspace)throw new Error('Scope authorization must preserve the selected workspace identity.');
  await assertWorkspaceInPlace(workspace);const relative=path.relative(root,workspace).split(path.sep).join('/')||'.';
  const key=JSON.stringify([workspace,lead.file,lead.observationId??null]);if(seen.has(key))throw new Error('Do not duplicate a selected scope lead.');seen.add(key);
  const db=openIndex(workspace,true);let inventoryStatus:string;
  try{
   const inputRoot=metaValue(db,'root') as string,container=metaValue(db,'container') as any;
   await options.authorizePath?.(path.resolve(inputRoot,lead.file));if(container){await options.authorizePath?.(container.workspace);await options.authorizePath?.(container.memberIndex);}
   inventoryStatus=String(metaValue(db,'status')??'unknown');
  }finally{db.close();}
  const target=await indexedFile(workspace,lead.file,options.signal);if(target.sha256!==lead.sourceSha256)throw new Error('Scope lead belongs to a different source revision. Read current feature/index pages again.');
  let observation:z.infer<typeof sourceSchema>['observation'];
  if(lead.observationId){
   const index=openIndex(workspace,true);try{
    if(!index.prepare("SELECT 1 FROM sqlite_master WHERE name='observations'").get())throw new Error('Selected scope observation is not recorded in its workspace.');
    const row=index.prepare("SELECT id,artifact,sha256,name,kind,json_extract(detail,'$.decompilationStatus') status,json_extract(detail,'$.pseudocodeTruncated') truncated,json_type(detail,'$.pseudocode') code FROM observations WHERE id=?").get(lead.observationId) as any;
    if(!row||row.artifact!==lead.file||row.sha256!==target.sha256)throw new Error('Scope observation does not belong to the selected current source.');
    const name=String(row.name??'');observation={id:row.id,kind:row.kind,name:name.slice(0,240),nameTruncated:name.length>240,recordedCompleteCode:['function','java-class'].includes(row.kind)&&row.status!=='failed'&&!row.truncated&&row.code==='text'};
   }finally{index.close();}
  }
  sources.push({workspace:relative,file:lead.file,sourceSha256:target.sha256,format:target.facts.format,encrypted:Boolean(target.facts.encrypted),inventoryStatus,...(observation?{observation}:{})});
 }
 return sources;
}
function presentation(root:string,selected:string,record:RecordValue,options:FeatureScopeOptions,fresh:boolean){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??8,characters=options.characters??12000,budget=responseBudget(options.budgetBytes),questions=featureQuestions(record.request);
 const userQuestions=questions.filter(q=>q.audience==='user'),status=userQuestions.length?'needs-clarification':!record.sources.length?'needs-evidence':'ready-for-investigation';
 const base={schema:'carve/feature-scope-read@1',workspace:root,id:selected,view,parentId:record.parentId??null,status,sourceCount:record.sources.length,
  sourceIdentityCheck:fresh?(record.sources.length?'selected-input-hashes-checked-during-this-write':'no-selected-inputs'):'recorded-only-no-current-source-check',verification:'not-run',semanticMatch:'unconfirmed',executesTarget:false,startsRea:false,
  ...(record.request.target?{target:record.request.target,targetAssessment:'not-performed'}:{})};
 if(view==='record'){
  const text=JSON.stringify(record),low=(i:number)=>text.charCodeAt(i)>=0xdc00&&text.charCodeAt(i)<=0xdfff,high=(i:number)=>text.charCodeAt(i)>=0xd800&&text.charCodeAt(i)<=0xdbff;
  if(offset>text.length||low(offset)&&high(offset-1))throw new Error('Use an in-range UTF16 offset; do not split a surrogate pair.');
  const seal=(end:number)=>measured({...base,encoding:'JSON text excerpt; UTF16 offsets; complete only when complete=true',text:text.slice(offset,end),offset,totalCharacters:text.length,complete:offset===0&&end===text.length,nextOffset:end<text.length?end:null},budget);
  let end=Math.min(text.length,offset+characters);if(high(end-1)&&low(end))end--;let result=seal(end);
  while(result.receipt.responseBytes>budget&&end>offset){end=offset+Math.floor((end-offset)/2);if(high(end-1)&&low(end))end--;result=seal(end);}
  if(result.receipt.responseBytes>budget||end===offset&&offset<text.length)throw new Error('Scope page cannot hold metadata and a character; increase budgetBytes or characters.');return result;
 }
 if(offset>record.sources.length)throw new Error('Scope source offset exceeds the recorded source count.');
 const declarations=Object.entries(record.request.boundary).filter(([,v])=>v==='required').map(([name])=>name+'-required');
 return budgetItems({...base,total:record.sources.length,offset,...(view==='summary'?{origin:record.request.origin,goal:record.request.goal.slice(0,160),goalTruncated:record.request.goal.length>160,choice:record.request.choice??null,facet:record.request.facet??null,questions,declaredRequirements:declarations,...(record.request.contract?{behaviorContract:behaviorSummary(record.request.contract)}:{}),coverageIncomplete:record.sources.some(s=>s.inventoryStatus!=='indexed'),encryptedInputs:record.sources.filter(s=>s.encrypted).length,
  authority:'User/agent intent plus source identities and recorded name metadata; no complete code-evidence, runtime/dependency, availability or extraction claim.',nextAction:status==='ready-for-investigation'?'Investigate complete code/calls with the separate REA MCP and existing tools. Create/resume reverse with this request ID in the goal; do not copy intent into verified behavior.':'Ask the missing user questions and investigate missing source leads. Submit a complete revised request with parentId; earlier records remain unchanged.'}:{} )},record.sources.slice(offset,offset+limit).map(value=>({value})),budget);
}

/** Persist clarification progress, not implementation evidence or behavior verification. */
export async function featureScope(workspace:string,options:FeatureScopeOptions){
 const writing=options.request!==undefined;responseBudget(options.budgetBytes);
 if(writing===Boolean(options.id)||options.parentId&&!writing)throw new Error('Supply exactly one request or id; parentId is for a revised request.');
 if(options.view!==undefined&&!['summary','record','sources'].includes(options.view)||!Number.isSafeInteger(options.offset??0)||(options.offset??0)<0||!Number.isInteger(options.limit??8)||(options.limit??8)<1||(options.limit??8)>16||!Number.isInteger(options.characters??12000)||(options.characters??12000)<1||(options.characters??12000)>12000)throw new Error('Use summary/record/sources, nonnegative offset, limit1–16 and characters1–12000.');
 if(writing&&(options.offset??0)!==0)throw new Error('Write a scope from offset0; page its recorded ID afterward.');
 options.signal?.throwIfAborted();await options.authorizePath?.(workspace);const root=await realpath(workspace);
 for(const name of ['.carve-workspace.json','index.sqlite','index.sqlite-wal','index.sqlite-shm'])await options.authorizePath?.(path.join(root,name),name.endsWith('-wal')||name.endsWith('-shm'));
 await assertWorkspaceInPlace(root);
 if(!writing){const found=await retained(root,id.parse(options.id),options.authorizePath);return presentation(root,options.id!,found.record,options,false);}
 const request=featureRequestSchema.parse(options.request);if(Buffer.byteLength(JSON.stringify(request))>MAX)throw new Error('Scope request exceeds1MiB.');
 for(const name of ['index.sqlite','index.sqlite-wal','index.sqlite-shm','.scan.lock'])await options.authorizePath?.(path.join(root,name),name!=='index.sqlite');
 const release=await claim(root);
 try{
  if(options.parentId)await retained(root,options.parentId,options.authorizePath);
  const sources=await bindSources(root,request,options),normalized={...request,leads:request.leads.map((lead,i)=>({...lead,workspace:sources[i]!.workspace}))};
  const record:RecordValue={schema:'carve/feature-scope@1',request:normalized,...(options.parentId?{parentId:options.parentId}:{}),sources};
  const bytes=Buffer.from(JSON.stringify(record)+'\n');if(bytes.length>MAX)throw new Error('Scope record exceeds1MiB.');const selected=digest(bytes);
  // Validate the response before publishing; a too-small budget must not hide a successful write.
  const response=presentation(root,selected,record,options,true),folder=path.join(root,'feature-requests');await directory(folder,options.authorizePath,true);
  const file=path.join(folder,selected+'.json'),temporary=path.join(folder,'.incoming-'+randomUUID());await options.authorizePath?.(file,true);await options.authorizePath?.(temporary,true);options.signal?.throwIfAborted();
  await writeFile(temporary,bytes,{flag:'wx',mode:0o600});try{try{await link(temporary,file);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;if(!(await readBytes(file)).equals(bytes))throw new Error('Existing scope record differs from its content identity.');}}finally{await unlink(temporary);}
  return response;
 }finally{await release();}
}
