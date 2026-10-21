import {z} from 'zod';
import {digest} from './artifact.js';
import {readPeLoader} from './pe-loader.js';
import {inspectPeDataReference} from './pe-data-references.js';
import {loadPeUiFunctions,type PeUiAccess} from './pe-ui-functions.js';
import {isDeepStrictEqual} from 'node:util';
import {readPeUi} from './pe-ui.js';
import {parsedPeResources,linkPeResourceReference} from './pe-resource-links.js';

export const reconstructionDataBinding=z.object({
 observationId:z.string().regex(/^[a-f0-9]{64}$/),sourceAddress:z.string().regex(/^0x[0-9a-f]{1,16}$/),targetAddress:z.string().min(1).max(1024),
 handling:z.enum(['embedded-readonly','modeled-state','unresolved']),description:z.string().trim().min(1).max(2000),
 bytes:z.object({length:z.number().int().min(1).max(64),sha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict().optional(),
 resource:z.object({path:z.array(z.union([z.number().int().min(0).max(0x7fffffff),z.string().min(1).max(8192)])).length(3),payloadSha256:z.string().regex(/^[a-f0-9]{64}$/)}).strict().optional()
}).strict().superRefine((item,ctx)=>{if(item.handling!=='unresolved'&&!item.bytes)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Resolved data handling requires an explicit initial byte length and SHA256.'});});

export async function bindReconstructionData(root:string,file:string,implementationIds:string[],selections:z.infer<typeof reconstructionDataBinding>[],signal?:AbortSignal,access?:PeUiAccess){
 const loaded=await loadPeUiFunctions(root,implementationIds,signal,access,file),metadata=await readPeLoader(loaded[0]!.target.path,{signal}),seen=new Set<string>();
 const writes=new Set(loaded.flatMap(f=>(f.detail.references??[]).filter((r:any)=>r.kind.write).map((r:any)=>r.targetAddress)));
 const resources=selections.some(s=>s.resource)?parsedPeResources((await readPeUi(loaded[0]!.target.path,{signal})).nodes):[];
 const results=[];
 for(const selection of selections){
  signal?.throwIfAborted();const identity=JSON.stringify([selection.observationId,selection.sourceAddress,selection.targetAddress]);
  if(seen.has(identity))throw new Error('Duplicate reconstruction data reference selection.');seen.add(identity);
  const fn=loaded.find(f=>f.record.observationId===selection.observationId);if(!fn)throw new Error('Data binding requires a declared complete implementation observation.');
  const refs=(fn.detail.references??[]).filter((r:any)=>r.address===selection.sourceAddress&&r.targetAddress===selection.targetAddress&&!r.kind.call&&(r.kind.data||r.kind.read||r.kind.write));
  if(refs.length!==1)throw new Error('Data binding requires one exact imported typed reference, not a guessed target.');
  const reference=await inspectPeDataReference(fn.target.path,metadata,refs[0],fn.detail.body,writes.has(selection.targetAddress),signal);
  if(selection.resource){
   const association=linkPeResourceReference(reference,resources),match=association.matches[0];
   if(association.matchesTotal!==1||!match||!isDeepStrictEqual(match.resource,selection.resource.path)||match.payloadSha256!==selection.resource.payloadSha256)throw new Error('Resource binding requires one exact parsed payload path/hash at the selected data target.');
   if(selection.bytes&&selection.bytes.length>Number(match.payloadBytes)-match.offsetInPayload)throw new Error('Selected data prefix crosses the resource payload boundary.');
   reference.resourceAssociation=association;
  }
  if(selection.handling==='embedded-readonly'&&reference.state!=='read-only-data-candidate')throw new Error('Embedded readonly data requires a readonly non-executable target with no exact selected write.');
  if(selection.handling==='modeled-state'&&reference.state!=='mutable-state-candidate')throw new Error('Modeled state requires a writable target or exact selected write.');
  let bytes=null;
  if(selection.bytes){
   if(!reference.bytes||reference.bytes.length<selection.bytes.length)throw new Error('Selected data byte extent is not backed by captured original bytes.');
   const prefix=Buffer.from(reference.bytes.hex,'hex').subarray(0,selection.bytes.length),sha256=digest(prefix);
   if(sha256!==selection.bytes.sha256)throw new Error('Selected reconstruction data bytes differ from their declared SHA256.');
   bytes={fileOffset:reference.bytes.fileOffset,length:prefix.length,hex:prefix.toString('hex'),sha256,scope:'explicit-reviewed-initial-prefix',objectExtent:'not-established'};
  }
  results.push({...selection,sourceSha256:fn.target.sha256,snapshotSha256:fn.record.snapshotSha256,reference:{...reference,bytes},verification:'not-run',handlingAuthority:'Agent-declared treatment; byte matching does not prove implementation use, state semantics or immutability.'});
 }
 return results;
}
