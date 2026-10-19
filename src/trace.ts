import { realpath } from 'node:fs/promises';
import { openIndex, indexedFile } from './survey.js';
import { addressKey } from './addresses.js';
import { reaObservationScope } from './rea-native.js';

export async function traceBoundary(workspace:string,id:string,options:{depth?:number;maxNodes?:number}={}){
  const depth=options.depth??2;const maxNodes=options.maxNodes??50;
  if(!/^[a-f0-9]{64}$/.test(id)||!Number.isInteger(depth)||depth<0||depth>8||!Number.isInteger(maxNodes)||maxNodes<1||maxNodes>200)throw new Error('Use a valid observation ID, depth 0–8 and maxNodes 1–200.');
  const root=await realpath(workspace);const db=openIndex(root,true);
  try{
    const seed=db.prepare('SELECT * FROM observations WHERE id=?').get(id) as any;if(!seed)throw new Error('Observation not found.');
    const target=await indexedFile(root,seed.artifact);if(target.sha256!==seed.sha256)throw new Error('Trace observation belongs to a previous input revision.');
    const queue=[{row:seed,level:0}];const visited=new Set<string>();const nodes=[];const edges=[];const unresolvedCalls:any[]=[];let truncated=false,relationshipsIncomplete=false,unresolvedCallsTruncated=false;
    const windows=db.prepare("SELECT name FROM sqlite_master WHERE name='native_windows'").get()?db.prepare('SELECT o.* FROM native_windows w JOIN observations o ON o.id=w.id WHERE w.artifact=? AND w.sha256=? AND w.space=? AND w.start<=? AND w.end>=? ORDER BY o.rowid DESC LIMIT 1'):undefined;
    while(queue.length){
      const current=queue.shift()!;const row=current.row;const nodeKey=row.kind+':'+row.address;if(visited.has(nodeKey))continue;
      if(nodes.length>=maxNodes){truncated=true;break;}visited.add(nodeKey);
      const detail=JSON.parse(row.detail);if(detail.calleesTruncated||detail.referencesTruncated)relationshipsIncomplete=true;nodes.push({id:row.id,kind:row.kind,address:row.address,name:row.name,depth:current.level,external:Boolean(detail.external),thunk:Boolean(detail.thunk),decompiled:Boolean(detail.pseudocode),...(detail.boundaryWarnings?.length?{boundaryWarningCount:detail.boundaryWarnings.length,decompilationStatus:detail.decompilationStatus}:{}),calleesTruncated:Boolean(detail.calleesTruncated),referencesTruncated:Boolean(detail.referencesTruncated),...(detail.relationshipScope?{relationshipScope:detail.relationshipScope}:{})});
      for(const call of detail.unresolvedCalls??[]){relationshipsIncomplete=true;const reason=String(call.reason);if(reason.length>1000)unresolvedCallsTruncated=true;if(unresolvedCalls.length<maxNodes*20)unresolvedCalls.push({fromId:row.id,functionAddress:row.address,address:call.address,reason:reason.slice(0,1000),reasonTruncated:reason.length>1000});else unresolvedCallsTruncated=true;}
      const scope=reaObservationScope(detail.provider),select=db.prepare("SELECT * FROM observations WHERE artifact=? AND sha256=? AND kind='function' AND address=?"+scope.sql+" ORDER BY json_extract(detail,'$.pseudocode') IS NULL, rowid DESC LIMIT 1");
      const next=row.kind==='string'?(detail.references??[]).map((r:any)=>({address:r.functionAddress??r.address,name:r.function,external:r.functionExternal,thunk:r.functionThunk,kind:r.functionAddress?'function':'data-window',relation:r.functionAddress?'string-reference':'data-reference-to-string'}))
        :row.kind==='data-window'?[...(detail.references??[]).filter((r:any)=>r.targetFunctionAddress).map((r:any)=>({address:r.targetFunctionAddress,name:r.targetFunction,external:r.targetExternal,thunk:r.targetThunk,kind:'function',relation:'analyzer-reference'})),...(detail.pointers??[]).filter((r:any)=>r.targetFunctionAddress).map((r:any)=>({address:r.targetFunctionAddress,name:r.targetFunction,external:r.external,thunk:r.thunk,kind:'function',relation:'raw-pointer-interpretation'}))]
        :(detail.callees??[]).map((r:any)=>({...r,kind:'function',relation:'static-call'}));
      if(current.level>=depth){if(next.length)truncated=true;continue;}
      for(const child of next){
        if(edges.length>=maxNodes*20){truncated=true;break;}
        const location=child.kind==='data-window'?addressKey(child.address):undefined;
        const found=(child.kind==='function'?select.get(row.artifact,row.sha256,child.address,...scope.values):windows?windows.get(row.artifact,row.sha256,location!.space,location!.key,location!.key):db.prepare("SELECT * FROM observations WHERE artifact=? AND sha256=? AND kind='data-window' AND address=? ORDER BY rowid DESC LIMIT 1").get(row.artifact,row.sha256,child.address)) as any;
        edges.push({from:row.address,to:found?.address??child.address,fromId:row.id,toId:found?.id??null,referenceAddress:child.address,kind:child.kind,name:child.name,relation:child.relation,external:child.external==null?null:Boolean(child.external),thunk:child.thunk==null?null:Boolean(child.thunk),indexed:Boolean(found),...(scope.sql?{resolution:found?'matching-rea-profile':'missing-compatible-observation'}:{}),...(child.thunkTarget?{thunkTarget:child.thunkTarget}:{}),...(child.callSites?{callSites:child.callSites.slice(0,20),callSiteCount:child.callSiteCount,callSitesTruncated:child.callSitesTruncated}:{})});
        if(found&&!visited.has(found.kind+':'+found.address)){if(queue.length<maxNodes)queue.push({row:found,level:current.level+1});else truncated=true;}
      }
    }
    return{schema:'carve/static-boundary@1',artifact:seed.artifact,sourceSha256:seed.sha256,nodes,edges,truncated,relationshipsIncomplete,unresolvedCalls,unresolvedCallsTruncated,dependencyClosure:'not-established',semanticMatch:'unconfirmed',
      limitations:['Only observed references/calls and bounded data windows in the selected binary are followed. REA function edges require matching source/provider/profile observations; missing compatible code is explicit. Indirect calls, uninspected data, other binaries and remote logic remain unknown.','Raw pointer interpretations and neighboring table functions are leads, not proof of registration structure or semantic linkage. Read a data window at unindexed data-reference sources.','The graph is a bounded investigation aid, not a complete dependency closure or proof that the requested feature was selected.']};
  }finally{db.close();}
}
