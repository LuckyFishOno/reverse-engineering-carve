import path from 'node:path';
import {isDeepStrictEqual} from 'node:util';
import {hashFile} from './survey.js';
import {readPeLoader,type PeMetadata,type PeExport} from './pe-loader.js';
import {createPeImportCallDecoder,type PeCallSite} from './pe-calls.js';
import {loadPeUiFunctions,type PeUiFunction,type PeUiAccess} from './pe-ui-functions.js';
import {bindPeUiEntries} from './pe-ui-entries.js';
import {peUiNextSteps} from './pe-ui-next-steps.js';
import {inspectPeDataReference} from './pe-data-references.js';
import {parsedPeResources,linkPeResourceReference} from './pe-resource-links.js';
import {readPeUi,type UiNode,type UiEdge} from './pe-ui.js';
import {resourceApiKind,inspectPeResourceApi} from './pe-resource-api.js';
const numeric=(v:unknown):v is string=>typeof v==='string'&&/^0x[0-9a-f]+$/.test(v);
const equalAddress=(a:unknown,b:unknown)=>numeric(a)&&numeric(b)&&BigInt(a)===BigInt(b);
const sameProfile=(a:PeUiFunction,b:PeUiFunction)=>a.record.profile===b.record.profile&&isDeepStrictEqual(a.detail.provider.analysisProvider,b.detail.provider.analysisProvider);
const covers=(f:PeUiFunction,start:bigint,end=start)=>f.detail.body.ranges.some((r:any)=>BigInt(r.start)<=start&&BigInt(r.end)>=end);
const MAX_ROWS=5000;

export async function inspectPeUiDependencies(root:string,target:PeUiFunction['target'],file:string,graph:{nodes:UiNode[];edges:UiEdge[]},command:number,functionIds:string[],dependencyIds:string[],depth:number,signal?:AbortSignal,access?:PeUiAccess,entryMode:'ui-command'|'selected-functions'='ui-command'){
 const loaded=await loadPeUiFunctions(root,[...new Set([...functionIds,...dependencyIds])],signal,access),roots=loaded.filter(f=>functionIds.includes(f.record.observationId));
 if(entryMode==='selected-functions'&&roots.some(f=>f.record.file!==file||f.target.sha256!==target.sha256))throw new Error('Selected root functions must identify the same current indexed PE file.');
 const binding=entryMode==='selected-functions'?{entries:roots.map(f=>({status:'selected-function',address:f.record.address,functions:[f.record],dispatchConfirmed:false,semanticMatch:'unconfirmed',dependencyClosure:'not-established'})),limitations:['Explicit function seeds are agent selections, not evidence of UI dispatch, export invocation or runtime reachability.']}:await bindPeUiEntries(root,target,file,graph,command,functionIds,signal,roots),metadata=new Map<string,PeMetadata>(),slotCounts=new Map<string,Map<number,number>>();
 const exportIndexes=new Map<string,Map<string,PeExport[]>>(),exportMatches=new Map<string,Record<string,any>[]>(),decoders=new Map<string,Awaited<ReturnType<typeof createPeImportCallDecoder>>>();
 const meta=async(f:PeUiFunction)=>{let m=metadata.get(f.record.file);if(!m){m=await readPeLoader(f.target.path,{signal});metadata.set(f.record.file,m);const counts=new Map<number,number>();for(const module of m.imports)for(const entry of module.entries)counts.set(entry.thunkRva,(counts.get(entry.thunkRva)??0)+1);slotCounts.set(f.record.file,counts);}return m;};
 const rows:Record<string,any>[]=[],queue:{fn:PeUiFunction;depth:number}[]=[],visited=new Set<string>();let limited=false;
 const writes=new Set(loaded.flatMap(f=>(f.detail.references??[]).filter((r:any)=>r.kind.write).map((r:any)=>JSON.stringify([f.record.file,r.targetAddress]))));
 const resourceCatalogs=new Map<string,{file:string;sourceSha256:string;resources:UiNode[];issues:unknown[]}>();
 const resources=async(fn:PeUiFunction)=>{
  let catalog=resourceCatalogs.get(fn.record.file);if(!catalog){const selected=fn.record.file===file?graph:await readPeUi(fn.target.path,{signal});catalog={file:fn.record.file,sourceSha256:fn.target.sha256,resources:parsedPeResources(selected.nodes),issues:'issues' in selected?selected.issues as unknown[]:[]};resourceCatalogs.set(fn.record.file,catalog);}return catalog.resources;
 };
 const push=(row:Record<string,any>)=>{if(rows.length>=MAX_ROWS){limited=true;return false;}rows.push(row);return true;};
 for(const entry of binding.entries){
  push({kind:entryMode==='selected-functions'?'function-entry':'ui-entry',file,...entry});
  if(entry.status==='static-entry-matched'||entry.status==='selected-function'){
   const ids=(entry.functions as Record<string,any>[]).map(f=>f.observationId);for(const f of roots)if(ids.includes(f.record.observationId))queue.push({fn:f,depth:0});
  }
 }
 const exportCandidates=async(caller:PeUiFunction,site:PeCallSite)=>{
  const slot=site.slot,source=await meta(caller),candidates:Record<string,any>[]=[];
  if(/^(?:api|ext)-ms-/i.test(slot.module))return candidates;
  const cacheKey=JSON.stringify([caller.record.file,caller.detail.provider.analysisProvider,slot.module,slot.name,slot.ordinal]);const cached=exportMatches.get(cacheKey);if(cached)return cached;
  // An explicit selected image is only a candidate; Windows loader search is not simulated.
  for(const fn of loaded){
   if(fn.record.file===caller.record.file||path.posix.basename(fn.record.file).toLowerCase()!==slot.module.toLowerCase())continue;
   const m=await meta(fn);if(!m.dll||m.machine!==source.machine)continue;
   if(!isDeepStrictEqual(fn.detail.provider.analysisProvider,caller.detail.provider.analysisProvider))continue;
   let index=exportIndexes.get(fn.record.file);
   if(!index){index=new Map();for(const e of m.exports?.entries??[])for(const key of ['ordinal:'+e.ordinal,...e.names.map(n=>'name:'+n)]){const entries=index.get(key)??[];entries.push(e);index.set(key,entries);}exportIndexes.set(fn.record.file,index);}
   for(const e of index.get(slot.name!==undefined?'name:'+slot.name:'ordinal:'+slot.ordinal)??[]){
    if(e.forwarder){candidates.push({file:fn.record.file,status:'forwarded-export-unresolved',ordinal:e.ordinal,forwarder:e.forwarder});continue;}
    const address=BigInt(m.imageBase)+BigInt(e.rva);
    if(fn.record.thunk||!numeric(fn.record.address)||BigInt(fn.record.address)!==address)continue;
    if(!m.sections.some(s=>(s.characteristics&0x20000000)!==0&&e.rva>=s.virtualAddress&&e.rva<s.virtualAddress+s.rawSize))continue;
    candidates.push({file:fn.record.file,observationId:fn.record.observationId,address:fn.record.address,ordinal:e.ordinal,names:e.names,status:'dll-export-candidate',runtimeLoading:'unverified'});
   }
  }
  exportMatches.set(cacheKey,candidates);return candidates;
 };
 for(let q=0;q<queue.length&&!limited;q++){
  signal?.throwIfAborted();const {fn,depth:level}=queue[q]!,d=fn.detail,id=fn.record.observationId;if(visited.has(id))continue;visited.add(id);
  if(!push({kind:'function-coverage',from:id,file:fn.record.file,address:fn.record.address,depth:level,relationshipScope:d.relationshipScope,relationshipsIncomplete:fn.record.relationshipsIncomplete,relationshipEvidence:d.relationshipEvidence??null,nonCallReferences:(d.references??[]).filter((r:any)=>!r.kind.call).length,stateDependencies:'typed-references-inspected-semantics-unverified',resourceDependencies:'direct-payload-and-bounded-api-leads',limitations:d.rea.limitations,dependencyClosure:'not-established'}))break;
  for(const unresolved of d.unresolvedCalls??[]){
   const row:Record<string,any>={kind:'unresolved-call',from:id,file:fn.record.file,depth:level,...unresolved};
   if(numeric(unresolved.address)){
    const m=await meta(fn),rva=BigInt(unresolved.address)-BigInt(m.imageBase);
    if(rva>=0n&&rva<=0xffffffffn)try{
     let decode=decoders.get(fn.record.file);if(!decode){decode=await createPeImportCallDecoder(fn.target.path,{metadata:m,signal});decoders.set(fn.record.file,decode);}const witness=await decode(Number(rva));
     if(slotCounts.get(fn.record.file)?.get(witness.slotRva)===1&&witness.form!=='jump-indirect'&&covers(fn,BigInt(unresolved.address),BigInt(m.imageBase)+BigInt(witness.instructionEndRva)-1n)&&resourceApiKind(witness.slot)){
      row.importWitness=witness;row.relationshipBasis='recorded-unresolved-call-location';row.callSite=unresolved.address;row.resourceApi=await inspectPeResourceApi(fn.target.path,m,d,witness,await resources(fn),signal);
     }
    }catch(error){signal?.throwIfAborted();row.importDecodeIssue=(error as Error).message;}
   }
   if(!push(row))break;
  }
  for(const reference of d.references??[]){
   if(limited)break;if(reference.kind.call||!(reference.kind.data||reference.kind.read||reference.kind.write))continue;
   const data=await inspectPeDataReference(fn.target.path,await meta(fn),reference,d.body,writes.has(JSON.stringify([fn.record.file,reference.targetAddress])),signal);
   data.resourceAssociation=linkPeResourceReference(data,await resources(fn));
   if(!push({...data,from:id,file:fn.record.file,depth:level}))break;
  }
  for(const call of d.callees??[]){
   if(limited)break;
   const internal=loaded.filter(f=>f.record.file===fn.record.file&&call.external!==true&&equalAddress(f.record.address,call.address)&&sameProfile(fn,f)&&(call.thunk===null||call.thunk===undefined||call.thunk===f.record.thunk));
   const sites=call.callSites?.length?call.callSites:[null];
   for(const recordedSite of sites){
    if(limited)break;
    let witness:PeCallSite|null=null,decodeIssue:string|null=null;
    if(recordedSite){
     const typed=d.references?.find((r:any)=>r.address===recordedSite.address&&r.kind.call);
     if(typed&&numeric(typed.address)){
      const m=await meta(fn),rva=BigInt(typed.address)-BigInt(m.imageBase);
      if(rva>=0n&&rva<=0xffffffffn){
       try{let decode=decoders.get(fn.record.file);if(!decode){decode=await createPeImportCallDecoder(fn.target.path,{metadata:m,signal});decoders.set(fn.record.file,decode);}const decoded=await decode(Number(rva));
        if(slotCounts.get(fn.record.file)?.get(decoded.slotRva)!==1)decodeIssue='Import slot has ambiguous overlapping declarations.';else if(covers(fn,BigInt(typed.address),BigInt(m.imageBase)+BigInt(decoded.instructionEndRva)-1n)&&decoded.form!=='jump-indirect')witness=decoded;else decodeIssue='Decoded import instruction is outside the recorded body or is a jump, not a call.';
       }catch(error){decodeIssue=(error as Error).message;}
      }else decodeIssue='Recorded call site is outside preferred-image RVA coordinates.';
     }else decodeIssue='No matching imported typed call reference.';
    }
    const exported=witness?await exportCandidates(fn,witness):[];
    const matches=witness?exported.filter(c=>c.status==='dll-export-candidate'):internal.map(f=>({observationId:f.record.observationId,file:f.record.file,address:f.record.address,status:'internal-code-match'}));
    const status=witness?(matches.length===1?'dll-export-candidate':matches.length>1?'ambiguous-dll-export':'import-target-unresolved'):(internal.length===1?'internal-code-match':internal.length>1?'ambiguous-function-evidence':'missing-function-code');
    const row:Record<string,any>={kind:'call-dependency',from:id,file:fn.record.file,depth:level,address:call.address,name:call.name,external:call.external,thunk:call.thunk,thunkTarget:call.thunkTarget,callSite:recordedSite?.address??null,callSitesTotal:call.callSiteCount,callSitesTruncated:call.callSitesTruncated,status,matches,exportAlternatives:exported,importWitness:witness,importDecodeIssue:decodeIssue,relationshipBasis:recordedSite?'recorded-typed-call':'callee-inventory-only',runtimeLoading:'unverified',dependencyClosure:'not-established'};
    if(witness&&resourceApiKind(witness.slot))row.resourceApi=await inspectPeResourceApi(fn.target.path,await meta(fn),d,witness,await resources(fn),signal);
    if(!push(row))break;
    if(matches.length===1){
     const next=loaded.find(f=>f.record.observationId===matches[0]!.observationId)!;
     if(visited.has(next.record.observationId))row.expansion='already-visited';else if(level<depth)queue.push({fn:next,depth:level+1});else row.expansion='depth-limit';
    }
   }
  }
 }
 for(const selected of new Map(loaded.map(f=>[f.record.file,f.target])).values())if((await hashFile(selected.path,signal)).sha256!==selected.sha256)throw new Error('Selected dependency source changed during PE UI inspection.');
 const counts={byKind:{} as Record<string,number>,byStatus:{} as Record<string,number>,byResourceStatus:{} as Record<string,number>,byResourceApiStatus:{} as Record<string,number>,byNextAction:{} as Record<string,number>};for(const row of rows){if(row.resourceApi){const status=row.resourceApi.status;counts.byResourceApiStatus[status]=(counts.byResourceApiStatus[status]??0)+1;}if(row.resourceAssociation){const status=row.resourceAssociation.status;counts.byResourceStatus[status]=(counts.byResourceStatus[status]??0)+1;}row.nextSteps=peUiNextSteps(row,visited);for(const step of row.nextSteps)counts.byNextAction[step.action]=(counts.byNextAction[step.action]??0)+1;counts.byKind[row.kind]=(counts.byKind[row.kind]??0)+1;if(row.status)counts.byStatus[row.status]=(counts.byStatus[row.status]??0)+1;}
 return {rows,counts,resourceCatalogs:[...resourceCatalogs.values()].sort((a,b)=>a.file.localeCompare(b.file)),records:loaded.map(f=>f.record),entries:binding.entries,visited:visited.size,depth,rowLimit:MAX_ROWS,rowLimitReached:limited,dependencyClosure:'not-established',scope:'Explicit selected observations only. Internal expansion requires matching source/profile; cross-image candidates require original call-to-IAT bytes and an exact selected defined DLL export. No Windows loader resolution or runtime binding.',limitations:[...binding.limitations,'Imported typed call sites are self-reported static evidence, not observed execution.','Only supported x86/x64 import-call encodings are decoded. Forwarders, API-set routing, dynamic loading, other instruction encodings, data/resource semantics and unselected code remain unresolved.']};
}
