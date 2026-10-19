import path from 'node:path';
import {realpath,mkdir,mkdtemp,writeFile,readFile,lstat,rename,rm} from 'node:fs/promises';
import {z} from 'zod';
import {digest} from './artifact.js';
import {hashFile} from './survey.js';
import {responseBudget,measured,budgetItems} from './context-budget.js';

const MAX_REPORT=512*1024*1024,MAX_INDEX=4*1024*1024,MAX_CASE=16*1024*1024;
const sha=z.string().regex(/^[a-f0-9]{64}$/),scope=z.enum(['selected-original-cli-cases','declared-external-harness-cases','selected-dex-android-harness-cases','selected-original-cli-sequences','declared-external-harness-sequences','selected-dex-android-harness-sequences']);
const card=z.object({index:z.number().int().min(0).max(199),name:z.string().max(8000),passed:z.boolean(),originalKind:z.string().max(100),candidateKind:z.string().max(100),sha256:sha,bytes:z.number().int().min(1).max(MAX_CASE)}).strict();
const indexSchema=z.object({schema:z.literal('carve/verification-index@1'),reportSha256:sha,reportBytes:z.number().int().min(1).max(MAX_REPORT),metadata:z.record(z.unknown()),cases:z.array(card).min(1).max(200)}).strict();
const published=new WeakMap<object,string>();
function finite(value:unknown){JSON.stringify(value,(_key,v)=>{if(typeof v==='number'&&!Number.isFinite(v))throw new Error('Verification archive requires finite JSON.');return v;});}
async function directory(file:string){if(await realpath(file)!==file||(await lstat(file)).isSymbolicLink())throw new Error('Verification archive directory follows a symlink.');}
async function regular(file:string,max:number){const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink()||info.size>max)throw new Error('Invalid/oversized verification archive file.');return info;}
async function smallJson(file:string,max:number){await regular(file,max);const b=await readFile(file);if(b.length>max)throw new Error('Verification archive file exceeds its budget.');return{bytes:b,value:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b))};}

/** Keep complete historical reports/cases outside a disposable output package.
 * Directory identity is the SHA256 of an index binding metadata and all file
 * hashes. It detects changes to a pinned record; it is not authentication.
 */
export async function archiveVerificationReport(workspace:string,report:Record<string,any>){
 finite(report);if(report.schema!=='carve/reconstruction-verification@1'||!Array.isArray(report.results)||report.results.length<1||report.results.length>200)throw new Error('Expected a complete reconstruction verification report.');
 const {results,...metadata}=report,text=JSON.stringify(report,null,2)+'\n',bytes=Buffer.byteLength(text);if(bytes>MAX_REPORT)throw new Error('Verification report exceeds512MiB.');
 const texts=results.map((r:any)=>JSON.stringify(r,null,2)+'\n');
 const cases=results.map((r:any,i:number)=>card.parse({index:i,name:r.name,passed:r.passed,originalKind:r.original?.kind,candidateKind:r.candidate?.kind,sha256:digest(texts[i]!),bytes:Buffer.byteLength(texts[i]!)}));
 const record=indexSchema.parse({schema:'carve/verification-index@1',reportSha256:digest(text),reportBytes:bytes,metadata,cases});validateIndex(record);
 const indexText=JSON.stringify(record,null,2)+'\n';if(Buffer.byteLength(indexText)>MAX_INDEX)throw new Error('Verification metadata exceeds4MiB.');
 const id=digest(indexText),root=await realpath(workspace),journal=path.join(root,'verification'),parent=path.join(journal,'reports');await mkdir(journal,{recursive:true,mode:0o700});await directory(journal);await mkdir(parent,{recursive:true,mode:0o700});await directory(parent);const out=path.join(parent,id),temporary=await mkdtemp(path.join(parent,'.writing-'));
 try{
  await writeFile(path.join(temporary,'report.json'),text,{flag:'wx',mode:0o600});await mkdir(path.join(temporary,'cases'),{mode:0o700});
  for(let i=0;i<texts.length;i++)await writeFile(path.join(temporary,'cases',i+'.json'),texts[i]!,{flag:'wx',mode:0o600});
  await writeFile(path.join(temporary,'index.json'),indexText,{flag:'wx',mode:0o600});
  try{await rename(temporary,out);}catch(error){if(!['EEXIST','ENOTEMPTY'].includes((error as NodeJS.ErrnoException).code??''))throw error;
   const existing=await loadArchive(root,id);await directory(path.join(out,'cases'));for(const row of existing.record.cases){const file=path.join(out,'cases',row.index+'.json');await regular(file,MAX_CASE);const actual=await hashFile(file);if(actual.sha256!==row.sha256||actual.bytes!==row.bytes)throw new Error('Existing verification case changed.');}
  }
 }finally{await rm(temporary,{recursive:true,force:true});}
 published.set(report,id);return{id,workspace:root,reportSha256:record.reportSha256,reportBytes:bytes};
}
function validateIndex(record:z.infer<typeof indexSchema>){
 const m=record.metadata;scope.parse(m.verifiedScope);sha.parse(m.manifestSha256);
 if(m.schema!=='carve/reconstruction-verification@1'||typeof m.checkedAt!=='string'||m.checkedAt.length>100||m.total!==record.cases.length||m.passed!==record.cases.filter(c=>c.passed).length||!['passed-supplied-cases','failed'].includes(String(m.status))||(m.status==='passed-supplied-cases')!==(m.passed===m.total)||record.cases.some((c,i)=>c.index!==i))throw new Error('Inconsistent verification archive counters/schema.');
 if(m.analysisWarningCount!==undefined&&(!Number.isSafeInteger(m.analysisWarningCount)||Number(m.analysisWarningCount)<1||Number(m.analysisWarningCount)>8000||!Array.isArray(m.analysisWarnings)||(m.analysisWarnings as any[]).reduce((n,e)=>n+(Array.isArray(e.boundaryWarnings)?e.boundaryWarnings.length:0),0)!==m.analysisWarningCount))throw new Error('Inconsistent analysis-warning metadata.');
 const sequenceScope=String(m.verifiedScope).endsWith('-sequences');
 if(sequenceScope!==(m.comparisonMode==='stateful-sequences')||sequenceScope&&(!Number.isSafeInteger(m.totalSteps)||!Number.isSafeInteger(m.passedSteps)||Number(m.totalSteps)<record.cases.length||Number(m.totalSteps)>1000||Number(m.passedSteps)<0||Number(m.passedSteps)>Number(m.totalSteps)||(m.status==='passed-supplied-cases')!==(m.passedSteps===m.totalSteps)))throw new Error('Inconsistent sequence scope/counters.');
 finite(record);
}
async function loadArchive(workspace:string,id:string){
 sha.parse(id);const root=await realpath(workspace),parent=path.join(root,'verification','reports'),folder=path.join(parent,id);await directory(parent);await directory(folder);
 const index=await smallJson(path.join(folder,'index.json'),MAX_INDEX);if(digest(index.bytes)!==id)throw new Error('Verification index changed; use the original pinned report ID.');
 const record=indexSchema.parse(index.value);validateIndex(record);const report=path.join(folder,'report.json');await regular(report,MAX_REPORT);const current=await hashFile(report);if(current.sha256!==record.reportSha256||current.bytes!==record.reportBytes)throw new Error('Verification full report changed.');return{root,folder,record};
}
export const verificationViews=['summary','cases','case','metadata'] as const;
export type VerificationReadOptions={id:string;view?:typeof verificationViews[number];offset?:number;limit?:number;failedOnly?:boolean;caseIndex?:number;field?:string;item?:number;characters?:number;budgetBytes?:number};
export async function readVerificationArchive(workspace:string,options:VerificationReadOptions){
 const budget=responseBudget(options.budgetBytes),view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,characters=options.characters??2000;
 if(!verificationViews.includes(view)||!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100||!Number.isInteger(characters)||characters<1||characters>12000||options.caseIndex!==undefined&&(!Number.isInteger(options.caseIndex)||options.caseIndex<0||options.caseIndex>199)||options.item!==undefined&&(!Number.isInteger(options.item)||options.item<0)||options.field!==undefined&&(!options.field||options.field.length>100))throw new Error('Use valid verification view, offset, limit1–100, characters1–12000 and case/item indices.');
 const {root,folder,record}=await loadArchive(workspace,options.id),m=record.metadata;
 const base={schema:'carve/verification-read@1',workspace:root,id:options.id,view,reportSha256:record.reportSha256,reportBytes:record.reportBytes,manifestSha256:m.manifestSha256,status:m.status,checkedAt:m.checkedAt,verifiedScope:m.verifiedScope,passed:m.passed,total:m.total,...(m.analysisWarningCount?{analysisWarningCount:m.analysisWarningCount}:{}),...(m.comparisonMode==='stateful-sequences'?{comparisonMode:m.comparisonMode,totalSteps:m.totalSteps,passedSteps:m.passedSteps}:{}),
  provenance:'Recorded local result. Index/full-report checksums are freshly checked; case files are checked when read. Reading never executes a reference, checks current original inputs or establishes new equivalence. Hashes are not signatures or independently rederived counters.',unknownsCount:Array.isArray(m.unknowns)?m.unknowns.length:0,unresolvedDependenciesCount:Array.isArray(m.unresolvedDependencies)?m.unresolvedDependencies.length:0,limitationsCount:Array.isArray(m.limitations)?m.limitations.length:0};
 if(view==='summary'){
  const result=measured({...base,metadataFields:Object.keys(m),caseCount:record.cases.length,failedCases:record.cases.filter(c=>!c.passed).length,nextAction:'Use cases (failedOnly optional), case with caseIndex/field, or metadata with field/item to read complete recorded data under a budget. Unknowns/limitations remain on disk; counts do not imply they are resolved.'},budget);
  if(result.receipt.responseBytes>budget)throw new Error('Verification archived as '+options.id+'; metadata exceeds budgetBytes. Read this ID with a larger budget, without rerunning verification.');return result;
 }
 if(view==='cases'){
  const rows=record.cases.filter(c=>!options.failedOnly||!c.passed),{passed,total,...cardBase}=base;return budgetItems({...cardBase,total:rows.length,verificationPassed:passed,verificationTotal:total,failedOnly:Boolean(options.failedOnly),offset,limit},rows.slice(offset,offset+limit).map(value=>({value})),budget);
 }
 let container:Record<string,any>=m;
 if(view==='case'){
  const row=record.cases[options.caseIndex??-1];if(!row)throw new Error('Select an existing caseIndex.');await directory(path.join(folder,'cases'));const parsed=await smallJson(path.join(folder,'cases',row.index+'.json'),MAX_CASE);
  if(digest(parsed.bytes)!==row.sha256||parsed.bytes.length!==row.bytes)throw new Error('Verification case changed.');container=parsed.value;if(!container||typeof container!=='object'||Array.isArray(container))throw new Error('Invalid case record.');
 }
 const field=options.field??(view==='case'?'original':'unknowns');if(!Object.hasOwn(container,field)){
  const missing=measured({...base,caseIndex:options.caseIndex,field,present:false},budget);if(missing.receipt.responseBytes>budget)throw new Error('Verification metadata exceeds budgetBytes.');return missing;
 }
 let value=container[field];if(options.item!==undefined){if(!Array.isArray(value)||options.item>=value.length)throw new Error('Selected metadata/case field has no such array item.');value=value[options.item];}
 const text=JSON.stringify(value);if(text===undefined)throw new Error('Selected field has no JSON representation.');
 const low=(i:number)=>i>=0&&i<text.length&&text.charCodeAt(i)>=0xdc00&&text.charCodeAt(i)<=0xdfff,high=(i:number)=>i>=0&&i<text.length&&text.charCodeAt(i)>=0xd800&&text.charCodeAt(i)<=0xdbff;
 if(offset>text.length||low(offset)&&high(offset-1))throw new Error('Use an in-range UTF16 offset from nextOffset; do not split a surrogate pair.');
 const seal=(end:number)=>measured({...base,caseIndex:options.caseIndex,field,item:options.item,present:true,encoding:'JSON text excerpt; UTF16 offsets, not a complete value unless complete=true',offset,totalCharacters:text.length,text:text.slice(offset,end),complete:offset===0&&end===text.length,nextOffset:end<text.length?end:null,budgetLimited:end<Math.min(text.length,offset+characters)},budget);
 let end=Math.min(text.length,offset+characters);if(high(end-1)&&low(end))end--;let result=seal(end);
 while(result.receipt.responseBytes>budget&&end>offset){end=offset+Math.floor((end-offset)/2);if(high(end-1)&&low(end))end--;result=seal(end);}
 if(result.receipt.responseBytes>budget||end===offset&&offset<text.length)throw new Error('Verification page cannot hold metadata and one complete character; increase budgetBytes or characters.');return result;
}
export async function verificationResponse(workspace:string,report:Record<string,any>,budgetBytes?:number){
 const id=published.get(report);if(!id)throw new Error('Report has no published archive in this process.');return readVerificationArchive(workspace,{id,budgetBytes});
}
