import path from 'node:path';
import {constants} from 'node:fs';
import {open,mkdir,lstat,realpath,writeFile,link,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {readMachOBranch} from './macho-symbols.js';
import {digest} from './artifact.js';
import {assertWorkspaceInPlace,claim,indexedFile,metaValue,openIndex} from './survey.js';

const maxJson=16*1024*1024,maxSnapshot=64*1024*1024,maxCode=4*1024*1024;
const sha=z.string().regex(/^[a-f0-9]{64}$/),ev=z.string().regex(/^ev_[a-f0-9]{64}$/);
const text=z.string().min(1).max(8192),providerSchema=z.object({id:text,name:text,version:text}).strict();
const profileSchema=z.object({provider:providerSchema,parameters:z.record(z.unknown()),digest:sha}).strict();
const evidenceSchema=z.object({
 evidence_id:ev,subject:z.object({name:text,digest:z.object({sha256:sha}).strict(),local_path:z.string().max(32768),format:z.enum(['mach-o','elf','pe']),architecture:text}).strict(),
 provider:providerSchema,analysis_profile:profileSchema,predicate_type:z.literal('rea.analysis'),operation:z.enum(['procedure_pseudo_code','procedure_info','procedure_callees','procedure_references']),
 parameters:z.object({procedure:text,document:text.optional(),direction:z.enum(['incoming','outgoing']).optional()}).strict(),raw_result:z.unknown(),normalized_result:z.unknown(),
 confidence:z.literal('observed'),authority:z.literal('shipped-artifact'),environment:z.unknown(),limitations:z.array(z.string().max(8192)).max(1000),
 relationship_coverage:z.unknown(),locations:z.array(z.unknown()).max(10000),evidence_links:z.array(ev).max(10000)
}).strict();
const address=z.string().regex(/^0x[0-9a-f]{1,16}$/);
const coordinate=z.string().max(1024).regex(/^(?:(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+:)?0x[0-9a-f]{1,16}$/);
const classification=z.object({external:z.boolean(),thunk:z.boolean(),thunk_target:coordinate.nullable(),provenance:z.literal('ghidra-function-manager')}).strict();
const bodySchema=z.object({available:z.literal(true),provenance:z.literal('ghidra-function-body-address-set'),ranges:z.array(z.object({start:coordinate,end:coordinate}).strict()).max(10000),total_bytes:z.number().int().nonnegative().safe(),span_bytes:z.number().int().nonnegative().safe().nullable(),non_contiguous:z.boolean(),contains_entry:z.boolean()}).strict();
const identity=z.object({address:coordinate,name:text,classification,body:bodySchema}).strict();
const referenceKind=z.object({available:z.literal(true),provenance:z.literal('ghidra-reference-manager'),type:z.string().min(1).max(160),flow:z.boolean(),call:z.boolean(),jump:z.boolean(),data:z.boolean(),read:z.boolean(),write:z.boolean(),indirect:z.boolean(),computed:z.boolean(),conditional:z.boolean(),terminal:z.boolean(),primary:z.boolean(),operand_index:z.number().int(),external:z.boolean()}).strict();
const referencesSchema=z.object({procedure:identity,direction:z.literal('outgoing'),reference_kinds_available:z.literal(true),unresolved_calls:z.array(z.object({address,reason:text}).strict()).max(10000),references:z.array(z.object({source_address:address,target_address:coordinate,source_procedure:identity.nullable(),target_procedure:identity.nullable(),kind:referenceKind}).strict()).max(10000)}).strict();
const directions=z.array(z.enum(['callers','callees'])).min(1).max(2).refine(a=>new Set(a).size===a.length);
const diagnostics=z.array(text).min(1).max(1000).optional();
const coverageSchema=z.discriminatedUnion('status',[
 z.object({status:z.literal('complete'),diagnostics}).strict(),
 z.object({status:z.literal('partial'),limitations:z.array(text).min(1).max(1000),limited_directions:directions.optional(),diagnostics}).strict(),
 z.object({status:z.literal('unknown'),reason:text,limited_directions:directions.optional(),diagnostics}).strict()
]);
const infoSchema=z.object({name:text,entrypoint:address,basicblock_count:z.number().int().nonnegative(),length:z.number().int().positive().safe(),signature:z.string().max(8192),locals:z.array(z.unknown()).max(100000),
 classification:z.object({external:z.literal(false),thunk:z.boolean(),thunk_target:z.string().nullable(),provenance:text}).strict(),
 body:z.object({available:z.literal(true),provenance:text,ranges:z.array(z.object({start:address,end:address}).strict()).min(1).max(10000),total_bytes:z.number().int().positive().safe(),span_bytes:z.number().int().positive().safe(),non_contiguous:z.boolean(),contains_entry:z.literal(true)}).strict()
}).strict();
type Evidence=z.infer<typeof evidenceSchema>;
type Access=(file:string,newPath?:boolean)=>Promise<unknown>;
type Selected=Awaited<ReturnType<typeof indexedFile>>;
type Role='code'|'info'|'callees'|'references';
type Snapshot={schema:'carve/rea-native-snapshot@1'|'carve/rea-native-snapshot@2'|'carve/rea-native-snapshot@3';adapter:'rea-ghidra-function@1'|'rea-ghidra-function@2'|'rea-ghidra-function@3';file:string;sourceSha256:string;records:{role:Role;sha256:string;bytes:number;json:string}[]};
const observationId=(file:string,sourceSha256:string,snapshotSha256:string,schema:Snapshot['schema']='carve/rea-native-snapshot@1')=>digest(JSON.stringify({schema,file,sourceSha256,snapshotSha256}));

export function isReaNativeObservation(row:Record<string,any>,detail:Record<string,any>){
 // The ID namespace still routes to revalidation if labels and snapshot paths
 // are edited while the original committed bytes/hash and observation ID remain.
 return Boolean(detail.rea||detail.provider?.name==='rea'||path.basename(path.dirname(row.evidence))==='rea-native-evidence'||['carve/rea-native-snapshot@1','carve/rea-native-snapshot@2','carve/rea-native-snapshot@3'].some(schema=>row.id===observationId(row.artifact,row.sha256,row.evidence_sha256,schema as Snapshot['schema'])));
}

function checked<S extends z.ZodTypeAny>(schema:S,value:unknown,label:string):z.infer<S>{
 const parsed=schema.safeParse(value);if(parsed.success)return parsed.data;
 throw new Error(label+': '+parsed.error.issues.slice(0,3).map(i=>(i.path.join('.')+': '+i.message).slice(0,300)).join('; ')+(parsed.error.issues.length>3?' (more issues omitted)':''));
}

function jsonLimits(value:unknown){
 const pending:{value:unknown;depth:number}[]=[{value,depth:0}];let nodes=0;
 while(pending.length){const item=pending.pop()!;if(++nodes>200000||item.depth>64)throw new Error('REA JSON exceeds nesting/node limits.');const v=item.value;
  if(typeof v==='number'&&!Number.isFinite(v)||typeof v==='string'&&/[\uD800-\uDFFF]/u.test(v))throw new Error('REA JSON requires finite numbers and well-formed Unicode.');
  if(v&&typeof v==='object')for(const [key,child] of Object.entries(v)){if(/[\uD800-\uDFFF]/u.test(key))throw new Error('REA JSON has an invalid Unicode key.');pending.push({value:child,depth:item.depth+1});}
 }
}
// RFC8785 ordering uses UTF16 code units, including numeric-looking object keys.
// Build JSON directly: constructing a sorted JS object would reorder integer keys.
function canonical(value:unknown):string{
 if(value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
 throw new Error('REA commitment contains a non-JSON value.');
}

/** Content commitment, not a signature or proof of who executed an analyzer. */
export function parseReaNativeEvidence(value:unknown,operation:Evidence['operation']){
 jsonLimits(value);const record=checked(evidenceSchema,value,'Unsupported or incomplete REA Evidence');
 for(const key of ['raw_result','normalized_result','environment','relationship_coverage'])if(!Object.hasOwn(value as object,key))throw new Error('Missing complete REA Evidence field: '+key);
 if(record.operation!==operation)throw new Error('Expected complete REA '+operation+' Evidence, not a summary or another operation.');
 if(operation!=='procedure_references'&&record.parameters.direction!==undefined)throw new Error('Only REA procedure_references admits a direction parameter.');
 const profile=record.analysis_profile;
 if(digest(canonical({provider:profile.provider,parameters:profile.parameters}))!==profile.digest)throw new Error('REA analysis profile digest does not match its parameters.');
 if(!isDeepStrictEqual(profile.provider,record.provider))throw new Error('REA Evidence provider differs from its analysis profile.');
 if(profile.parameters.target_format!==record.subject.format||profile.parameters.architecture!==record.subject.architecture)throw new Error('REA analysis profile target format/architecture contradicts its subject.');
 // Keep the producer's original semantic identity; display subject paths/names are excluded upstream.
 const {evidence_id,subject,...rest}=record;
 const projection={subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest};
 if('ev_'+digest(canonical(projection))!==evidence_id)throw new Error('REA Evidence semantic ID does not match its content.');
 return record;
}

function pair(codeValue:unknown,infoValue:unknown,allowBoundary=false){
 const code=parseReaNativeEvidence(codeValue,'procedure_pseudo_code'),info=parseReaNativeEvidence(infoValue,'procedure_info');
 if(code.subject.digest.sha256!==info.subject.digest.sha256||code.subject.format!==info.subject.format||code.subject.architecture!==info.subject.architecture)throw new Error('REA code and procedure info identify different source bytes/format/architecture.');
 if(!isDeepStrictEqual(code.analysis_profile,info.analysis_profile)||!isDeepStrictEqual(code.provider,info.provider)||!isDeepStrictEqual(code.parameters,info.parameters))throw new Error('REA code and procedure info require the same provider, profile and exact selector parameters.');
 if(code.provider.id!=='ghidra'||code.analysis_profile.parameters.function_body_evidence!=='complete-inclusive-ranges-v1')throw new Error('This native adapter currently supports the explicit REA Ghidra complete-body profile only.');
 if(typeof code.normalized_result!=='string'||!code.normalized_result.trim()||code.normalized_result.includes('\0')||Buffer.byteLength(code.normalized_result)>maxCode)throw new Error('REA needs nonempty complete pseudocode up to4MiB; null/metadata/preview is not implementation evidence.');
 const raw=z.object({value:z.unknown(),limitations:z.array(text).max(20)}).strict(),rawCode=checked(raw,code.raw_result,'Incomplete REA code result'),rawInfo=checked(raw,info.raw_result,'Incomplete REA info result');
 if(!isDeepStrictEqual(rawCode.value,code.normalized_result)||!isDeepStrictEqual(rawInfo.value,info.normalized_result))throw new Error('REA raw/normalized result mismatch; full unmodified results are required.');
 const boundaryDiagnostics:{message:string;address:string;target:string;targetName:string}[]=[];
 if(rawCode.limitations.length||rawInfo.limitations.length){
  if(!allowBoundary||code.analysis_profile.parameters.function_boundary_observations!=='ghidra-function-boundary-limitations-v4'||!isDeepStrictEqual(rawCode.limitations,rawInfo.limitations))throw new Error('Incomplete REA code/info diagnostics require the explicitly supported source-bound boundary profile and both relationship records.');
  const pattern=/^Ghidra Listing reports a terminal call at (0x[0-9a-f]{1,16}) to (0x[0-9a-f]{1,16}) (.+) \(external=false, thunk=false, hasNoReturn=false\); fallthrough is excluded by Ghidra's flow model\. The reason for the terminal flow is not established by this observation\.$/;
  for(const message of rawCode.limitations){const match=pattern.exec(message);if(!match||!code.limitations.includes(message)||!info.limitations.includes(message))throw new Error('Unsupported REA code/info limitation; incomplete or unknown diagnostics cannot become implementation evidence.');boundaryDiagnostics.push({message,address:match[1]!,target:match[2]!,targetName:match[3]!});}
 }
 const procedure=checked(infoSchema,info.normalized_result,'Incomplete REA procedure body'),ranges=procedure.body.ranges;
 let total=0n,previous=-1n,contains=false;const entry=BigInt(procedure.entrypoint);
 for(const range of ranges){const start=BigInt(range.start),end=BigInt(range.end);if(end<start||start<=previous)throw new Error('REA function body ranges overlap or are unordered.');total+=end-start+1n;previous=end;contains||=entry>=start&&entry<=end;}
 const span=BigInt(ranges.at(-1)!.end)-BigInt(ranges[0]!.start)+1n;
 if(!contains||total!==BigInt(procedure.body.total_bytes)||procedure.length!==procedure.body.total_bytes||span!==BigInt(procedure.body.span_bytes)||procedure.body.non_contiguous!==(span>total))throw new Error('REA function body coverage contradicts its entry/ranges/byte counts.');
 return{code,info,procedure,boundaryDiagnostics};
}

function point(value:string){const at=value.lastIndexOf(':');return{space:at<0?'':value.slice(0,at),offset:BigInt(value.slice(at+1))};}
function contains(body:{ranges:{start:string;end:string}[]},value:string){const p=point(value);return body.ranges.some(r=>{const a=point(r.start),b=point(r.end);return p.space===a.space&&p.offset>=a.offset&&p.offset<=b.offset;});}

/** Recorded REA graph traversal must not silently mix analysis profiles. */
export function reaObservationScope(provider:any,prefix:''|'o.'=''):{sql:string;values:string[]}{
 if(provider?.name!=='rea')return{sql:'',values:[]};
 const p=provider.analysisProvider,values=[provider.analysisProfileDigest,p?.id,p?.name,p?.version];
 if(values.some(v=>typeof v!=='string'||!v))return{sql:' AND 0',values:[]};
 return{sql:` AND json_extract(${prefix}detail,'$.provider.name')='rea'`+['analysisProfileDigest','analysisProvider.id','analysisProvider.name','analysisProvider.version'].map(k=>` AND json_extract(${prefix}detail,'$.provider.${k}')=?`).join(''),values};
}
function checkIdentity(value:z.infer<typeof identity>,bits:bigint){
 const bounds=new Map<string,{start:bigint;end:bigint}>();let total=0n;
 for(const r of value.body.ranges){const a=point(r.start),b=point(r.end),previous=bounds.get(a.space);if(a.space!==b.space||b.offset<a.offset||previous&&a.offset<=previous.end)throw new Error('REA reference identity has inconsistent body ranges.');bounds.set(a.space,{start:previous?.start??a.offset,end:b.offset});total+=b.offset-a.offset+1n;}
 const only=bounds.size===1?[...bounds.values()][0]:undefined,span=only?only.end-only.start+1n:bounds.size===0?0n:null;
 if(total!==BigInt(value.body.total_bytes)||(span===null?value.body.span_bytes!==null:span!==BigInt(value.body.span_bytes??-1))||value.body.non_contiguous!==(span===null||span>total)||value.body.contains_entry!==contains(value.body,value.address)||!value.classification.external&&!value.body.contains_entry)throw new Error('REA reference identity body coverage contradicts its entry/ranges.');
 for(const a of [value.address,...value.body.ranges.flatMap(r=>[r.start,r.end])])if(!point(a).space&&point(a).offset>=(1n<<bits))throw new Error('REA reference identity exceeds the selected architecture width.');
}

function relationshipRecords(decoded:Map<string,unknown>,code:Evidence,procedure:z.infer<typeof infoSchema>,bits:bigint){
 const selected={address:procedure.entrypoint,name:procedure.name,classification:procedure.classification,body:procedure.body};
 const records:Evidence[]=[],perResult:string[]=[];let refs:z.infer<typeof referencesSchema>|undefined,coverage:z.infer<typeof coverageSchema>|null=null,addresses:string[]|undefined;
 for(const [role,operation] of [['callees','procedure_callees'],['references','procedure_references']] as const){
  if(!decoded.has(role))continue;
  const r=parseReaNativeEvidence(decoded.get(role),operation),{direction,...selector}=r.parameters;
  if(r.subject.digest.sha256!==code.subject.digest.sha256||r.subject.format!==code.subject.format||r.subject.architecture!==code.subject.architecture||!isDeepStrictEqual(r.provider,code.provider)||!isDeepStrictEqual(r.analysis_profile,code.analysis_profile)||!isDeepStrictEqual(selector,code.parameters))throw new Error('REA relationship Evidence needs the same source, provider, profile and exact selector as code/info.');
  const raw=checked(z.object({value:z.unknown(),limitations:z.array(text).max(1000),...(role==='callees'?{relationship_coverage:coverageSchema.optional()}:{})}).strict(),r.raw_result,'Incomplete REA relationship result');
  if(!isDeepStrictEqual(raw.value,r.normalized_result))throw new Error('REA relationship raw/normalized results differ.');
  perResult.push(...raw.limitations);records.push(r);
  if(role==='callees'){
   if(code.analysis_profile.parameters.call_relationship_coverage!=='function-body-call-coverage-v5')throw new Error('Unsupported REA call relationship coverage profile.');
   coverage=r.relationship_coverage===null?null:checked(coverageSchema,r.relationship_coverage,'Invalid REA call relationship coverage');
   if(!isDeepStrictEqual(('relationship_coverage' in raw?raw.relationship_coverage:undefined)??null,coverage))throw new Error('REA raw/normalized relationship coverage differs.');
   addresses=checked(z.array(coordinate).max(10000),r.normalized_result,'Invalid REA callee addresses');if(new Set(addresses).size!==addresses.length)throw new Error('REA callee address list has duplicates.');
  }else{
   if(direction!=='outgoing'||r.relationship_coverage!==null||code.analysis_profile.parameters.function_references!=='complete-body-and-entry-reference-manager-v2')throw new Error('Only the explicit REA outgoing typed-reference profile is supported.');
   refs=checked(referencesSchema,r.normalized_result,'Invalid REA typed references');
   if(!isDeepStrictEqual(refs.procedure,selected))throw new Error('REA relationship procedure identity differs from code/info.');
  }
 }
 const calls=new Map<string,any>(),unresolved=refs?.unresolved_calls??[];
 const add=(address:string,endpoint:z.infer<typeof identity>|null,site?:{address:string;kind:string})=>{
  let call=calls.get(address);if(!call){call={address,name:endpoint?.name??null,external:endpoint?.classification.external??null,thunk:endpoint?.classification.thunk??null,thunkTarget:endpoint?.classification.thunk_target??null,callSites:[],callSiteCount:0,callSitesTruncated:false};calls.set(address,call);}
  if(site){call.callSiteCount++;if(call.callSites.length<20)call.callSites.push(site);else call.callSitesTruncated=true;}
 };
 const references=(refs?.references??[]).map(ref=>{
  if(!contains(procedure.body,ref.source_address))throw new Error('REA outgoing reference source lies outside the selected function body.');
  if(ref.source_procedure){checkIdentity(ref.source_procedure,bits);if(!isDeepStrictEqual(ref.source_procedure,selected))throw new Error('REA outgoing reference has a different source procedure.');}
  if(ref.target_procedure){checkIdentity(ref.target_procedure,bits);if(!contains(ref.target_procedure.body,ref.target_address)&&ref.target_procedure.address!==ref.target_address)throw new Error('REA reference target contradicts its containing procedure.');}
  if(!point(ref.target_address).space&&point(ref.target_address).offset>=(1n<<bits))throw new Error('REA reference target exceeds the selected architecture width.');
  if(ref.kind.call&&!ref.kind.flow)throw new Error('REA call reference must also be a flow reference.');
  if(ref.kind.call)add(ref.target_procedure?.address??ref.target_address,ref.target_procedure,{address:ref.source_address,kind:ref.kind.type});
  return{address:ref.source_address,targetAddress:ref.target_address,targetFunctionAddress:ref.target_procedure?.address??null,targetFunction:ref.target_procedure?.name??null,targetExternal:ref.target_procedure?.classification.external??null,targetThunk:ref.target_procedure?.classification.thunk??null,kind:ref.kind};
 });
 for(const call of unresolved)if(!contains(procedure.body,call.address))throw new Error('REA unresolved call lies outside the selected function body.');
 const typedTargets=new Set(calls.keys());for(const address of addresses??[]){if(!point(address).space&&point(address).offset>=(1n<<bits))throw new Error('REA callee exceeds the selected architecture width.');add(address,null);}
 const addressSet=new Set(addresses),disagree=addresses!==undefined&&refs!==undefined&&([...typedTargets].some(a=>!addressSet.has(a))||addresses.some(a=>!typedTargets.has(a)));
 return{callees:[...calls.values()],references,unresolvedCalls:unresolved,calleesTruncated:!addresses||!refs||coverage?.status!=='complete'||perResult.length>0||unresolved.length>0||disagree,referencesTruncated:!refs||perResult.length>0,
  relationshipScope:'rea-ghidra-outgoing@1',relationshipEvidence:{calleesEvidenceId:records.find(r=>r.operation==='procedure_callees')?.evidence_id??null,referencesEvidenceId:records.find(r=>r.operation==='procedure_references')?.evidence_id??null,coverage,unresolvedCallCount:refs?unresolved.length:null,perResultLimitations:perResult,calleeReferenceAgreement:addresses&&refs?!disagree:null},records};
}

function utf8(bytes:Buffer){return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}
function parseJson(bytes:Buffer){const value=JSON.parse(utf8(bytes).replace(/^\uFEFF/,''));jsonLimits(value);return value;}
async function boundedRead(file:string,limit:number){
 const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const before=await handle.stat();if(!before.isFile()||before.size>limit)throw new Error('REA Evidence must be a regular file within its byte budget.');
  const chunks:Buffer[]=[];let total=0;
  for(;;){const buffer=Buffer.allocUnsafe(Math.min(1024*1024,limit+1-total));const {bytesRead}=await handle.read(buffer);if(!bytesRead)break;total+=bytesRead;if(total>limit)throw new Error('REA Evidence exceeds its byte budget.');chunks.push(buffer.subarray(0,bytesRead));}
  const after=await handle.stat();if(before.size!==after.size||total!==before.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.ino!==after.ino)throw new Error('REA Evidence changed while reading.');return Buffer.concat(chunks,total);
 }finally{await handle.close();}
}
async function snapshotRecord(snapshot:Snapshot,target:Pick<Selected,'sha256'|'facts'|'path'>){
 const boundary=snapshot.schema==='carve/rea-native-snapshot@3'&&snapshot.adapter==='rea-ghidra-function@3';
 const graph=boundary||snapshot.schema==='carve/rea-native-snapshot@2'&&snapshot.adapter==='rea-ghidra-function@2';
 if(!(graph||snapshot.schema==='carve/rea-native-snapshot@1'&&snapshot.adapter==='rea-ghidra-function@1')||snapshot.sourceSha256!==target.sha256||!Array.isArray(snapshot.records)||(graph?snapshot.records.length<3||snapshot.records.length>4:snapshot.records.length!==2))throw new Error('REA snapshot source/adapter binding is invalid.');
 const roles=new Map(snapshot.records.map(r=>[r.role,r]));if(roles.size!==snapshot.records.length||!roles.has('code')||!roles.has('info')||[...roles.keys()].some(k=>!['code','info','callees','references'].includes(k)))throw new Error('REA snapshot needs one code/info record and unique supported roles.');
 const decoded=new Map<string,unknown>();
 for(const row of snapshot.records){if(typeof row.json!=='string'||Buffer.byteLength(row.json)>maxJson||row.bytes!==Buffer.byteLength(row.json)||row.sha256!==digest(row.json))throw new Error('REA snapshot record identity differs from its captured input bytes.');decoded.set(row.role,parseJson(Buffer.from(row.json)));}
 const {code,info,procedure,boundaryDiagnostics}=pair(decoded.get('code'),decoded.get('info'),boundary);
 if(boundary&&(!boundaryDiagnostics.length||snapshot.records.length!==4))throw new Error('REA boundary snapshot needs diagnostics and all four complete records.');
 if(target.facts.encrypted||target.facts.family!=='native'||!['mach-o','elf','pe'].includes(target.facts.format)||!['x86','x86_64','arm','arm64'].includes(target.facts.architecture??''))throw new Error('REA native handoff requires an unencrypted supported thin Mach-O/ELF/PE input and explicit architecture.');
 if(code.subject.digest.sha256!==target.sha256||code.subject.format!==target.facts.format||code.subject.architecture!==target.facts.architecture)throw new Error('REA Evidence does not match the freshly hashed selected input.');
 const bits=['x86','arm'].includes(target.facts.architecture!)?32n:64n,maxAddress=(1n<<bits)-1n;
 if(procedure.body.ranges.some(r=>BigInt(r.end)>maxAddress))throw new Error('REA function addresses exceed the selected architecture width.');
 const relationships=graph?relationshipRecords(decoded,code,procedure,bits):undefined;
 if(boundaryDiagnostics.length&&(!relationships||relationships.relationshipEvidence.coverage?.status!=='complete'||relationships.relationshipEvidence.calleeReferenceAgreement!==true||relationships.unresolvedCalls.length||relationships.records.length!==2||relationships.records.some(r=>!isDeepStrictEqual((r.raw_result as any).limitations,boundaryDiagnostics.map(d=>d.message)))))throw new Error('REA boundary policy needs complete agreeing callee/reference inventories, matching diagnostics and no unresolved calls.');
 const boundaryWarnings=[];
 for(const diagnostic of boundaryDiagnostics){
  const matched=relationships?.references.find(r=>r.address===diagnostic.address&&r.targetAddress===diagnostic.target&&r.targetFunctionAddress===diagnostic.target&&r.targetFunction===diagnostic.targetName&&r.targetExternal===false&&r.targetThunk===false&&r.kind.call&&r.kind.flow&&!r.kind.indirect&&!r.kind.computed&&!r.kind.external);
  if(target.facts.format!=='mach-o'||target.facts.architecture!=='arm64'||!matched||relationships?.relationshipEvidence.coverage?.status!=='complete'||!relationships.callees.some(c=>c.address===diagnostic.target)||!procedure.body.ranges.some(r=>BigInt(r.start)<=BigInt(diagnostic.address)&&BigInt(r.end)===BigInt(diagnostic.address)+3n))throw new Error('REA terminal boundary requires complete matching typed/callee records and a last ARM64 instruction in its body range.');
  const instruction=await readMachOBranch(target.path,diagnostic.address,diagnostic.target);
  boundaryWarnings.push({...diagnostic,kind:'terminal-direct-branch',instruction,reasonForProviderFlow:'not-established',semanticDependencyClosure:'not-established'});
 }
 const origin={schema:'carve/rea-native-origin@1',adapter:snapshot.adapter,codeEvidenceId:code.evidence_id,procedureEvidenceId:info.evidence_id,analysisProfileDigest:code.analysis_profile.digest,
  inputRecords:snapshot.records.map(r=>({role:r.role,sha256:r.sha256,bytes:r.bytes})),limitations:[...new Set([...code.limitations,...info.limitations])],
  authority:'External self-reported static Evidence. Canonical IDs and source bytes are checked, not producer identity or behavioral equivalence.',...(relationships?{relationshipEvidence:relationships.relationshipEvidence}:{})};
 const provider={name:'rea',adapter:origin.adapter,analysisProvider:code.provider,analysisProfileDigest:origin.analysisProfileDigest,codeEvidenceId:code.evidence_id,procedureEvidenceId:info.evidence_id,producerAuthentication:'not-established'};
 const detail:any={kind:'function',name:procedure.name,address:procedure.entrypoint,signature:procedure.signature,pseudocode:code.normalized_result as string,pseudocodeTruncated:false,decompilationStatus:boundaryWarnings.length?'completed-with-boundary-warnings':'completed',...(boundaryWarnings.length?{boundaryWarnings}:{}),external:false,thunk:procedure.classification.thunk,
  callees:[],calleesTruncated:true,references:[],referencesTruncated:true,relationshipScope:'not-imported',body:procedure.body,provider,rea:origin};
 if(relationships){const {records,...fields}=relationships;Object.assign(detail,fields);origin.limitations=[...new Set([...origin.limitations,...records.flatMap(r=>r.limitations)])];}
 return{detail,content:[detail.name,detail.signature,detail.pseudocode].join('\n')};
}

async function saveSnapshot(root:string,bytes:Buffer,access?:Access){
 const folder=path.join(root,'rea-native-evidence');await access?.(folder,true);
 try{await mkdir(folder,{mode:0o700});}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
 const info=await lstat(folder);if(!info.isDirectory()||info.isSymbolicLink()||await realpath(folder)!==folder)throw new Error('REA snapshot directory follows a symlink or is not owned in place.');
 const hash=digest(bytes),file=path.join(folder,hash+'.json'),temporary=path.join(folder,'.incoming-'+randomUUID()+'.json');await access?.(file,true);await access?.(temporary,true);
 await writeFile(temporary,bytes,{flag:'wx',mode:0o600});
 try{try{await link(temporary,file);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;const existing=await boundedRead(file,maxSnapshot);if(!existing.equals(bytes))throw new Error('Existing REA snapshot differs from its content identity.');}}finally{await unlink(temporary);}
 return{file,sha256:hash};
}

export async function importReaNative(workspace:string,options:{file:string;code:string;info:string;callees?:string;references?:string;signal?:AbortSignal;authorizePath?:Access}){
 const root=await realpath(workspace),access=options.authorizePath;options.signal?.throwIfAborted();
 for(const name of ['index.sqlite','index.sqlite-wal','index.sqlite-shm','.scan.lock'])await access?.(path.join(root,name),name!=='index.sqlite');
 await assertWorkspaceInPlace(root);for(const file of [options.code,options.info,options.callees,options.references])if(file!==undefined)await access?.(file);
 const release=await claim(root);
 try{
  const index=openIndex(root,true);let sourceRoot:string;try{sourceRoot=metaValue(index,'root') as string;if(typeof sourceRoot!=='string')throw new Error('Missing inventory source root.');}finally{index.close();}
  await access?.(path.resolve(sourceRoot,options.file));
  const target=await indexedFile(root,options.file,options.signal);
  // Store exact producer JSON bytes inside the immutable owned snapshot; no live
  // dependency on an external MCP process, evidence file or historical local_path.
  const graph=options.callees!==undefined||options.references!==undefined;
  const snapshot:Snapshot={schema:graph?'carve/rea-native-snapshot@2':'carve/rea-native-snapshot@1',adapter:graph?'rea-ghidra-function@2':'rea-ghidra-function@1',file:options.file,sourceSha256:target.sha256,records:[]};
  for(const role of ['code','info','callees','references'] as const){const file=options[role];if(file===undefined)continue;const raw=await boundedRead(file,maxJson);snapshot.records.push({role,sha256:digest(raw),bytes:raw.length,json:utf8(raw)});}
  const captured=snapshot.records.filter(r=>r.role==='code'||r.role==='info').map(r=>parseJson(Buffer.from(r.json)) as any);
  if(captured.some(r=>Array.isArray(r.raw_result?.limitations)&&r.raw_result.limitations.length)){
   if(!options.callees||!options.references)throw new Error('REA boundary warnings require both complete callee and outgoing-reference Evidence.');
   snapshot.schema='carve/rea-native-snapshot@3';snapshot.adapter='rea-ghidra-function@3';
  }
  const normalized=await snapshotRecord(snapshot,target),bytes=Buffer.from(JSON.stringify(snapshot)+'\n');if(bytes.length>maxSnapshot)throw new Error('REA snapshot exceeds64MiB.');
  const saved=await saveSnapshot(root,bytes,access);options.signal?.throwIfAborted();
  const current=await indexedFile(root,options.file,options.signal);if(current.sha256!==target.sha256)throw new Error('Selected source changed during REA import.');
  const id=observationId(options.file,target.sha256,saved.sha256,snapshot.schema),db=openIndex(root);
  try{
   db.exec(`CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
    CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
    CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
   db.exec('BEGIN IMMEDIATE');
   try{const d=normalized.detail,existing=db.prepare('SELECT * FROM observations WHERE id=?').get(id) as Record<string,any>|undefined;
    if(existing){if(existing.evidence!==saved.file||existing.evidence_sha256!==saved.sha256)throw new Error('Existing REA observation changed its owned snapshot binding.');await assertReaNativeObservation(existing,current);}else{db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,options.file,target.sha256,'function',d.name,d.address,normalized.content,JSON.stringify(d),saved.file,saved.sha256);}
    db.prepare('DELETE FROM observation_search WHERE id=?').run(id);db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(id,normalized.content);
    db.exec('COMMIT');
   }catch(error){db.exec('ROLLBACK');throw error;}
  }finally{db.close();}
  return{schema:'carve/rea-native-import@1',status:'imported-static-function',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,observationId:id,name:normalized.detail.name,address:normalized.detail.address,provider:normalized.detail.provider,evidence:saved.file,evidenceSha256:saved.sha256,executesTarget:false,startsRea:false,
   relationshipScope:normalized.detail.relationshipScope,...(normalized.detail.boundaryWarnings?.length?{decompilationStatus:normalized.detail.decompilationStatus,boundaryWarningCount:normalized.detail.boundaryWarnings.length}:{}),...(graph?{relationships:{callees:normalized.detail.callees.length,references:normalized.detail.references.length,unresolvedCalls:normalized.detail.unresolvedCalls.length,calleesIncomplete:normalized.detail.calleesTruncated,referencesIncomplete:normalized.detail.referencesTruncated,calleesEvidenceId:normalized.detail.relationshipEvidence.calleesEvidenceId,referencesEvidenceId:normalized.detail.relationshipEvidence.referencesEvidenceId}}:{}),
   limitations:['Only explicit REA Ghidra complete-body and optional typed outgoing-reference/callee profiles are supported. Recorded local relationships do not establish cross-module, state/OS or runtime dependency closure.','Canonical commitments establish record consistency, not trusted producer execution or behavior. Subject display paths are historical data and are never opened.'],nextAction:'Use observation/context/features/trace, import missing callee code via the separate REA MCP, then bind every selected implementation observation in a reconstruction contract and compare declared cases.'};
 }finally{await release();}
}

/** Rebind normalized code to immutable producer records before reconstruction. */
export async function assertReaNativeObservation(row:Record<string,any>,target:Pick<Selected,'sha256'|'facts'|'path'>){
 const bytes=await boundedRead(row.evidence,maxSnapshot);if(digest(bytes)!==row.evidence_sha256)throw new Error('REA snapshot bytes changed after import.');
 const snapshot=parseJson(bytes) as Snapshot;if(snapshot.file!==row.artifact)throw new Error('REA snapshot belongs to another indexed file.');
 const normalized=await snapshotRecord(snapshot,target),id=observationId(row.artifact,target.sha256,row.evidence_sha256,snapshot.schema);
 if(row.id!==id||row.sha256!==target.sha256||row.kind!=='function'||row.name!==normalized.detail.name||row.address!==normalized.detail.address||row.content!==normalized.content||!isDeepStrictEqual(JSON.parse(row.detail),normalized.detail))throw new Error('REA observation differs from the captured complete producer Evidence. Reimport intact records.');
}
