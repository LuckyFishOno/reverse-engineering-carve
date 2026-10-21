import {indexedFile} from './survey.js';
import type {UiNode,UiEdge} from './pe-ui.js';
import {loadPeUiFunctions,type PeUiFunction} from './pe-ui-functions.js';

// Exact preferred-image addresses bind static function records, never runtime dispatch.
export async function bindPeUiEntries(root:string,target:Awaited<ReturnType<typeof indexedFile>>,file:string,graph:{nodes:UiNode[];edges:UiEdge[]},command:number,ids:string[],signal?:AbortSignal,loaded?:PeUiFunction[]){
 const functions=loaded??await loadPeUiFunctions(root,ids,signal,undefined,file);
 if(functions.some(f=>f.record.file!==file||f.target.sha256!==target.sha256))throw new Error('PE UI function evidence must identify the same current indexed PE file.');
 const records=functions.map(f=>f.record);
 const rows=graph.edges.filter(e=>e.from==='command:'+command&&e.kind==='dispatch-candidate');
 const selected=new Map(rows.map(r=>[r.to,r])),dispatchByHandler=new Map<string,{rowId:string;notification:unknown;ownership:string}[]>();
 for(const e of graph.edges){
  const row=selected.get(e.from);if(e.kind!=='points-to'||!row)continue;
  const dispatch=dispatchByHandler.get(e.to)??[];dispatch.push({rowId:row.to,notification:row.notification,ownership:'unverified'});dispatchByHandler.set(e.to,dispatch);
 }
 const entries:Record<string,unknown>[]=graph.nodes.filter(n=>dispatchByHandler.has(n.id)).map(n=>{
  const matches=records.filter(r=>BigInt(r.address)===BigInt(String(n.address)));
  return {handlerId:n.id,address:n.address,command,status:matches.length===1?'static-entry-matched':matches.length>1?'ambiguous-function-evidence':'candidate-only',dispatch:dispatchByHandler.get(n.id)!,functions:matches,dispatchConfirmed:false,semanticMatch:'unconfirmed',dependencyClosure:'not-established'};
 });
 if(!entries.length)entries.push({command,status:graph.nodes.some(n=>n.id==='command:'+command)?'missing-handler-candidate':'missing-ui-command',dispatch:[],functions:[],dispatchConfirmed:false,semanticMatch:'unconfirmed',dependencyClosure:'not-established'});
 return {entries,records,scope:'Explicitly selected REA observations only; no automatic inventory or profile selection. Exact preferred-image VA matching only; no rebase, containing-function, thunk-target or semantic inference.',limitations:['Function entry matches are source-bound self-reported static evidence, not authenticated producer execution.','UI dispatch, class ownership, notification selection, feature behavior and dependency closure remain unverified.','Missing matches cover only supplied observation IDs, not all possible functions.']};
}
