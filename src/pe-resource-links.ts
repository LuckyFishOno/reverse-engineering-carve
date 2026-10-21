import type {UiNode} from './pe-ui.js';

export function parsedPeResources(nodes:UiNode[]){return nodes.filter(n=>n.kind==='resource'&&Array.isArray(n.resource)&&Number.isSafeInteger(n.rva)&&Number.isSafeInteger(n.bytes)&&Number(n.bytes)>0&&typeof n.payloadSha256==='string');}

// Payload containment only: no resource-ID argument tracking or Windows language selection.
export function linkPeResourceReference(reference:Record<string,any>,resources:UiNode[]){
 if(!Number.isSafeInteger(reference.targetRva)||!reference.sourceSection||reference.status!=='file-bytes-captured')return {status:'unresolved-reference',matches:[],matchesTotal:0,matchesTruncated:false,runtimeUse:'unverified'};
 const matches=resources.filter(r=>reference.targetRva>=Number(r.rva)&&reference.targetRva<Number(r.rva)+Number(r.bytes));
 return {status:matches.length===1?'inside-parsed-resource-payload':matches.length>1?'ambiguous-resource-payload':'no-parsed-payload-match',matches:matches.slice(0,8).map(r=>({resourceId:r.id,resource:r.resource,payloadRva:r.rva,payloadBytes:r.bytes,payloadSha256:r.payloadSha256,fileOffset:r.fileOffset,offsetInPayload:reference.targetRva-Number(r.rva)})),matchesTotal:matches.length,matchesTruncated:matches.length>8,runtimeUse:'unverified'};
}
