import path from 'node:path';
import {realpath} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {indexedFile,openIndex,hashFile} from './survey.js';
import {assertReaNativeObservation,isReaNativeObservation} from './rea-native.js';
import {assertReaBridgeObservation,isReaBridgeObservation,type BridgePathAccess} from './rea-bridge.js';

export const contractText=z.string().trim().min(1).max(8000);
const id=z.string().regex(/^[a-f0-9]{64}$/),key=z.string().regex(/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/);
const evidenceFields={file:z.string().min(1).max(4096),evidenceIds:z.array(id).min(1).max(100),supportingEvidenceIds:z.array(id).max(100).default([])};
const shared={goal:contractText,behavior:z.object({description:contractText,inputDomain:contractText,outputDomain:contractText}).strict(),
  dependencies:z.array(z.object({name:contractText,status:z.enum(['available','reimplemented','host-required','remote-required','unknown']),detail:contractText}).strict()).max(100),unknowns:z.array(contractText).max(100)};
const endpoint=z.object({artifact:key,id}).strict();
const artifactContract=z.object({key,workspace:z.string().min(1).max(4096).default('.'),file:evidenceFields.file,
 role:z.enum(['implementation','boundary-support']).optional(),evidenceIds:z.array(id).max(100),supportingEvidenceIds:evidenceFields.supportingEvidenceIds}).strict().superRefine((item,ctx)=>{
 if(item.role==='boundary-support'){
  if(item.evidenceIds.length||!item.supportingEvidenceIds.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Boundary-support artifacts require zero implementation evidenceIds and at least one supportingEvidenceId.'});
 }else if(!item.evidenceIds.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Implementation artifacts require complete code evidenceIds.'});
});
export const reconstructionContract=z.discriminatedUnion('schema',[
  z.object({schema:z.literal('carve/reconstruction@1'),...shared,...evidenceFields}).strict(),
  z.object({schema:z.literal('carve/reconstruction@2'),...shared,primary:key,
    artifacts:z.array(artifactContract).min(1).max(32),
    relationships:z.array(z.object({from:endpoint,to:endpoint,kind:z.enum(['calls','loads','data','other']),basis:z.enum(['hypothesis','reviewed-static']).default('hypothesis'),description:contractText,bridgeEvidenceId:id.optional()}).strict()).max(128)
  }).strict()
]);
export type ReconstructionContract=z.infer<typeof reconstructionContract>;
export type WorkspaceAccess=(workspace:string)=>Promise<string>;
export async function bindReconstruction(workspace:string,contract:ReconstructionContract,authorizeWorkspace?:WorkspaceAccess,signal?:AbortSignal,authorizePath?:BridgePathAccess){
  const root=await realpath(workspace),multi=contract.schema==='carve/reconstruction@2';
  const selected=multi?contract.artifacts:[{key:'primary',workspace:'.',file:contract.file,evidenceIds:contract.evidenceIds,supportingEvidenceIds:contract.supportingEvidenceIds}];
  const primary=multi?contract.primary:'primary',keys=new Set(selected.map(a=>a.key));
  if(keys.size!==selected.length||!keys.has(primary))throw new Error('Artifact keys must be unique and include the selected primary.');
  if(multi&&contract.artifacts.find(a=>a.key===primary)?.role==='boundary-support')throw new Error('The primary artifact requires complete implementation code, not boundary support.');
  if(selected.reduce((n,a)=>n+new Set([...a.evidenceIds,...a.supportingEvidenceIds]).size,0)>400)throw new Error('Use at most400 distinct artifact/evidence bindings per reconstruction.');
  if(multi){
    const ids=new Map(selected.map(a=>[a.key,new Set([...a.evidenceIds,...a.supportingEvidenceIds])]));const reached=new Set([primary]);
    for(const link of contract.relationships){if(link.from.artifact===link.to.artifact||!ids.get(link.from.artifact)?.has(link.from.id)||!ids.get(link.to.artifact)?.has(link.to.id))throw new Error('Each cross-artifact relationship must reference declared evidence on two different artifacts.');}
    let changed=true;while(changed){changed=false;for(const link of contract.relationships)if(reached.has(link.from.artifact)&&!reached.has(link.to.artifact)){reached.add(link.to.artifact);changed=true;}}
    if(reached.size!==keys.size)throw new Error('Every secondary artifact needs a directed relationship path from the primary. Declared paths are not semantic proof.');
  }
  // Authorize every declared workspace before a retained bridge can read another index.
  // A snapshot cannot introduce an undeclared third workspace into the contract.
  const workspaces=new Map<string,string>();
  for(const item of selected){
    const requested=path.resolve(root,item.workspace);await authorizePath?.(requested);
    for(const name of ['.carve-workspace.json','index.sqlite','index.sqlite-wal','index.sqlite-shm'])await authorizePath?.(path.join(requested,name),name.endsWith('-wal')||name.endsWith('-shm'));
    const resolved=await realpath(requested),current=authorizeWorkspace?await realpath(await authorizeWorkspace(resolved)):resolved;
    if(current!==resolved)throw new Error('Workspace authorization must preserve the declared workspace identity.');workspaces.set(item.key,current);
  }
  const declaredWorkspaces=new Set(workspaces.values()),bridgeWorkspace=async(input:string)=>{
    const actual=await realpath(input);if(!declaredWorkspaces.has(actual))throw new Error('Every bridge endpoint workspace must be explicitly declared by a selected contract artifact.');
    return authorizeWorkspace?await authorizeWorkspace(actual):actual;
  };
  const artifacts:{key:string;workspace:string;file:string;sha256:string;format:string;bytes:number;container:unknown;evidenceIds:string[];supportingEvidenceIds:string[];role?:string}[]=[];const evidence=[],targets=[],bridges:{key:string;workspace:string;id:string;witness:Awaited<ReturnType<typeof assertReaBridgeObservation>>}[]=[];const checked=new Map<string,string>(),paths=new Set<string>();
  for(const item of selected){
    const current=workspaces.get(item.key)!;
    const preflight=openIndex(current,true);try{
      const meta=preflight.prepare("SELECT key,value FROM meta WHERE key IN ('root','container')").all() as {key:string;value:string}[];
      for(const entry of meta){const value=JSON.parse(entry.value);if(entry.key==='root')await authorizePath?.(path.resolve(value,item.file));else if(value){await authorizePath?.(value.workspace);await authorizePath?.(value.memberIndex);}}
    }finally{preflight.close();}
    const target=await indexedFile(current,item.file,signal);if(paths.has(target.path))throw new Error('Two artifact keys select the same actual input path.');paths.add(target.path);
    const original={file:item.file,sha256:target.sha256,format:target.facts.format,bytes:target.bytes,container:target.container??null};
    artifacts.push({key:item.key,workspace:current,...('role' in item&&item.role?{role:item.role}:{}),...original,evidenceIds:[...new Set(item.evidenceIds)],supportingEvidenceIds:[...new Set(item.supportingEvidenceIds)]});targets.push({key:item.key,target});
    const db=openIndex(current,true);
    try{
      for(const observationId of new Set([...item.evidenceIds,...item.supportingEvidenceIds])){
        const row=db.prepare('SELECT * FROM observations WHERE id=?').get(observationId) as any;
        if(!row||row.artifact!==item.file||row.sha256!==target.sha256)throw new Error('Evidence does not match the current selected input: '+item.key+'.');
        const detail=JSON.parse(row.detail),implementation=item.evidenceIds.includes(observationId);
        if(implementation&&(!detail.pseudocode||detail.pseudocodeTruncated||detail.decompilationStatus==='failed'))throw new Error('Reconstruction needs complete decompiled function/class evidence, not only an inventory name or a truncated preview.');
        await authorizePath?.(row.evidence);let hash=checked.get(row.evidence);if(!hash){hash=(await hashFile(row.evidence,signal)).sha256;checked.set(row.evidence,hash);}
        if(hash!==row.evidence_sha256)throw new Error('Recorded decompilation evidence changed on disk. Rerun analysis.');
        if(isReaNativeObservation(row,detail))await assertReaNativeObservation(row,target);
        if(isReaBridgeObservation(row,detail))bridges.push({key:item.key,workspace:current,id:observationId,witness:await assertReaBridgeObservation(row,current,signal,{authorizePath,authorizeWorkspace:bridgeWorkspace})});
        evidence.push({...(multi?{artifact:item.key,workspace:current,file:item.file,sourceSha256:target.sha256}:{}),id:observationId,role:implementation?'implementation-code':'boundary-support',kind:row.kind,name:row.name,address:row.address,truncated:Boolean(detail.pseudocodeTruncated??detail.truncated),...(detail.provider===undefined?{}:{provider:detail.provider}),...(detail.boundaryWarnings?.length?{decompilationStatus:detail.decompilationStatus,boundaryWarnings:detail.boundaryWarnings}:{}),evidence:row.evidence,evidenceSha256:hash});
      }
    }finally{db.close();}
  }
  const target=targets.find(t=>t.key===primary)!.target,original={file:selected.find(a=>a.key===primary)!.file,sha256:target.sha256,format:target.facts.format,bytes:target.bytes,container:target.container??null};
  const used=new Set<string>();
  const relationships=multi?contract.relationships.map(link=>{
    if(!link.bridgeEvidenceId)return{...link,semanticMatch:'unconfirmed',authority:'Agent-declared relationship anchored to static evidence; no automatic cross-artifact resolution or runtime-load proof.'};
    const bridge=bridges.find(b=>b.key===link.from.artifact&&b.id===link.bridgeEvidenceId),from=artifacts.find(a=>a.key===link.from.artifact)!,to=artifacts.find(a=>a.key===link.to.artifact)!;
    if(!bridge||link.kind!=='calls'||link.basis!=='reviewed-static'||bridge.workspace!==from.workspace||path.resolve(bridge.workspace,bridge.witness.to.workspace??'.')!==to.workspace||bridge.witness.from.id!==link.from.id||bridge.witness.to.id!==link.to.id||bridge.witness.from.file!==from.file||bridge.witness.to.file!==to.file||bridge.witness.from.sha256!==from.sha256||bridge.witness.to.sha256!==to.sha256||!selected.find(a=>a.key===link.from.artifact)!.supportingEvidenceIds.includes(bridge.id)||!selected.find(a=>a.key===link.from.artifact)!.evidenceIds.includes(link.from.id)||!selected.find(a=>a.key===link.to.artifact)!.evidenceIds.includes(link.to.id))throw new Error('A bridgeEvidenceId requires its exact declared caller/callee implementation endpoints and caller supportingEvidenceIds in their declared workspaces, with reviewed-static calls basis.');
    used.add(bridge.key+':'+bridge.id);return{...link,semanticMatch:'unconfirmed',authority:'Original direct-call instruction, import stub/symbol ordinal, local loader path and defined export are byte-bound. Runtime loading, ABI and semantic dependency closure remain unverified.',staticBridge:{policy:bridge.witness.policy,symbol:bridge.witness.import.symbol.name,runtimeLoading:'unverified'}};
  }):[];
  if(bridges.some(b=>!used.has(b.key+':'+b.id)))throw new Error('Every REA bridge supporting observation must be used by an explicit multi-artifact relationship with both complete implementation endpoints.');
  return{target,original,artifacts,evidence,relationships,targets,unresolvedRelationships:relationships.filter(link=>link.basis==='hypothesis')};
}
export function assertReconstructionBinding(provenance:any,bound:Awaited<ReturnType<typeof bindReconstruction>>){
  if(!isDeepStrictEqual(provenance.original,bound.original))throw new Error('Reconstruction was packaged for different original bytes or provenance.');
  if(!isDeepStrictEqual(provenance.evidence,bound.evidence))throw new Error('Packaged evidence no longer matches the analysis record.');
  if(provenance.schema==='carve/reconstruction-provenance@2'&&(!isDeepStrictEqual(provenance.artifacts,bound.artifacts)||!isDeepStrictEqual(provenance.relationships,bound.relationships)))throw new Error('Packaged artifact bindings or relationship records changed.');
}
