import {realpath} from 'node:fs/promises';
import {openIndex} from './survey.js';
import {digest} from './artifact.js';
import {measured,responseBudget} from './context-budget.js';
import {reaObservationScope} from './rea-native.js';

type Row=Record<string,any>;
type View='auto'|'outline'|'excerpt';
type Candidate={row:Row;reason:string;inline:boolean};
const active=" JOIN files f ON f.path=o.artifact AND f.sha256=o.sha256 JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') AND f.error IS NULL";
const text="COALESCE(json_extract(o.detail,'$.pseudocode'),o.content)";
// Bound text transferred out of SQLite even for very large class records.
function fields(view:View){return `o.id,o.artifact,o.sha256,o.kind,o.name,o.address,json_extract(o.detail,'$.signature') signature,json_extract(o.detail,'$.provider') provider,json_extract(o.detail,'$.pseudocode') IS NOT NULL has_code,COALESCE(json_extract(o.detail,'$.pseudocodeTruncated'),json_extract(o.detail,'$.truncated'),0) record_truncated,json_extract(o.detail,'$.decompilationStatus') decompilation_status,COALESCE(json_array_length(o.detail,'$.boundaryWarnings'),0) boundary_warning_count,json_extract(o.detail,'$.calleesTruncated') callees_truncated,json_extract(o.detail,'$.external') external,json_extract(o.detail,'$.thunk') thunk,length(CAST(${text} AS BLOB)) text_bytes,${view==='outline'?'NULL':`substr(CAST(${text} AS BLOB),1,4804)`} excerpt`;}

function excerpt(row:Row){
 // SQLite length/substr(TEXT) stop at NUL. Read a bounded UTF8 byte prefix
 // instead, then count Unicode scalars in JS without cutting a multibyte char.
 const bytes=row.excerpt as Uint8Array;
 const prefix=new TextDecoder('utf-8',{fatal:true}).decode(bytes,{stream:bytes.length<Number(row.text_bytes)});
 const value=[...prefix].slice(0,1200).join(''),complete=Buffer.byteLength(value)===Number(row.text_bytes);
 return{source:row.has_code?'pseudocode':'record-content',value,complete,nextOffset:complete?null:value.length};
}

export async function analysisContext(workspace:string,options:{query?:string;ids?:string[];file?:string;view?:View;code?:boolean;offset?:number;budgetBytes?:number;knownFingerprint?:string}={}){
 const budget=responseBudget(options.budgetBytes),offset=options.offset??0,query=options.query?.trim(),ids=options.ids&&[...new Set(options.ids)];
 const view=options.view??(options.code===true?'excerpt':options.code===false?'outline':'auto');
 if(!['auto','outline','excerpt'].includes(view)||options.view!==undefined&&options.code!==undefined&&view!==(options.code?'excerpt':'outline'))throw new Error('Choose view auto, outline or excerpt; code is an alias for excerpt (false: outline).');
 if(Boolean(query)===Boolean(ids?.length)||query&&query.length>1000||ids&&((options.ids?.length??0)>20||ids.some(id=>!/^[a-f0-9]{64}$/.test(id)))||!Number.isSafeInteger(offset)||offset<0||options.knownFingerprint!==undefined&&!/^[a-f0-9]{64}$/.test(options.knownFingerprint))throw new Error('Choose query1–1000 characters or1–20 observation IDs, a nonnegative offset and an optional returned fingerprint.');
 const root=await realpath(workspace),db=openIndex(root,true);
 db.exec('BEGIN');
 try{
  const epoch=JSON.parse((db.prepare("SELECT value FROM meta WHERE key='epoch'").get() as Row).value);
  const base={schema:'carve/analysis-context@2',workspace:root,view,sourceInventoryRevision:epoch,freshBytesChecked:false,scope:'Bounded recorded static context; incomplete dependency closure. Recheck source/evidence bytes before reconstruction.'};
  const request={query:query??null,ids:ids??null,file:options.file??null,view,offset,budgetBytes:budget};
  const exists=Boolean(db.prepare("SELECT name FROM sqlite_master WHERE name='observations'").get());
  let seeds:Row[]=[],matching=0,scanLimited=false,termsLimited=false;
  if(exists&&ids?.length){
   const select=db.prepare('SELECT '+fields(view)+' FROM observations o'+active+' WHERE o.id=?'+(options.file?' AND o.artifact=?':''));
   seeds=ids.map(id=>{const row=select.get(id,...(options.file?[options.file]:[])) as Row|undefined;if(!row)throw new Error('Focus observation is absent or no longer matches this inventory/file.');return row;});matching=seeds.length;
  }else if(exists){
   const allTerms=query!.replace(/([a-z0-9])([A-Z])/g,'$1 $2').match(/[\p{L}\p{N}_]+/gu)??[];termsLimited=allTerms.length>12;const terms=allTerms.slice(0,12);if(!terms.length)throw new Error('Query needs at least one identifier or word.');
   const words=[...new Set(terms.map(s=>s.toLowerCase()))],phrase=words.map(s=>'"'+s.replaceAll('"','""')+'"').join(' OR ');
   const nameHits=words.map(()=>'(instr(lower(o.name),?)>0)'),params=[...words,phrase,...(options.file?[options.file]:[])];
   const join=' FROM observations o'+active+' WHERE ('+nameHits.join(' OR ')+" OR o.id IN (SELECT id FROM observation_search WHERE observation_search MATCH ?))"+(options.file?' AND o.artifact=?':'');
   matching=Number((db.prepare('SELECT count(*) n'+join).get(...params) as Row).n);
   seeds=db.prepare('SELECT '+fields(view)+','+nameHits.join('+')+' name_score'+join+' ORDER BY name_score DESC,has_code DESC,o.artifact,o.address,o.id LIMIT 64').all(...words,...params) as Row[];scanLimited=matching>seeds.length;
  }
  const rows=new Map<string,{row:Row;reason:string}>(),locations=new Set<string>();
  function add(row:Row,reason:string){if(rows.has(row.id))return;const key=JSON.stringify([row.artifact,row.kind,row.address]);if(locations.has(key)&&!ids?.includes(row.id))return;locations.add(key);rows.set(row.id,{row,reason});}
  for(const seed of seeds)add(seed,ids?.includes(seed.id)?'explicit-focus':'lexical-match');
  const edges=new Map<string,Row[]>();let edgeLimited=seeds.length>4||seeds.slice(0,4).some(r=>Boolean(r.callees_truncated));
  if(exists){
   const calls=db.prepare("SELECT value FROM json_each((SELECT detail FROM observations WHERE id=?),'$.callees') LIMIT 13");
   for(const seed of seeds.slice(0,4)){
    const scope=reaObservationScope(seed.provider?JSON.parse(seed.provider):null,'o.');
    const select=db.prepare('SELECT '+fields(view)+' FROM observations o'+active+" WHERE o.artifact=? AND o.sha256=? AND o.kind='function' AND o.address=?"+scope.sql+" ORDER BY json_extract(o.detail,'$.pseudocode') IS NULL,o.rowid DESC LIMIT 1");
    const references=calls.all(seed.id);if(references.length>12)edgeLimited=true;const links=[];
    for(const value of references.slice(0,12)){
     const call=JSON.parse(String(value.value));if(typeof call.address!=='string')continue;const found=select.get(seed.artifact,seed.sha256,call.address,...scope.values) as Row|undefined;
     links.push({name:String(call.name??'').slice(0,160),address:call.address,id:found?.id??null,external:call.external??null,thunk:call.thunk??null});if(found)add(found,'recorded-static-callee');
    }edges.set(seed.id,links);
   }
  }
  const groups=new Map<string,{row:Row;reason:string}[]>();for(const row of rows.values()){const bucket=groups.get(row.row.artifact)??[];bucket.push(row);groups.set(row.row.artifact,bucket);}
  const ranked:{row:Row;reason:string}[]=[];for(let depth=0;;depth++){let added=false;for(const group of groups.values())if(group[depth]){ranked.push(group[depth]!);added=true;}if(!added)break;}
  const candidates=ranked.slice(offset).map(({row,reason})=>({row,reason,inline:view==='excerpt'||view==='auto'&&Boolean(row.has_code)&&!row.record_truncated&&(row.decompilation_status===null||row.decompilation_status==='completed')&&row.text_bytes<=1024}));
  const selected:Candidate[]=[];
  // Rebuild dictionaries and page-local edge references after every fit check.
  const seal=()=>{
   const sources:Row[]=[],providers:any[]=[],sourceIndex=new Map<string,number>(),providerIndex=new Map<string,number>(),itemIndex=new Map(selected.map((c,i)=>[c.row.id,i]));
   const items=selected.map(({row:r,reason,inline})=>{
    const sourceKey=JSON.stringify([r.artifact,r.sha256]);let source=sourceIndex.get(sourceKey);if(source===undefined){source=sources.length;sourceIndex.set(sourceKey,source);sources.push({file:r.artifact,sha256:r.sha256});}
    let provider:number|null=null;if(r.provider){const value=JSON.parse(r.provider),key=JSON.stringify(value);let index=providerIndex.get(key);if(index===undefined){index=providers.length;providerIndex.set(key,index);providers.push(value);}provider=index;}
    const callees=(edges.get(r.id)??[]).map(link=>{const target=link.id?itemIndex.get(link.id):undefined;return{...(target===undefined?{id:link.id,name:link.name,address:link.address}:{item:target,...(link.name!==String(selected[target]!.row.name??'')?{name:link.name}:{})}),external:link.external,thunk:link.thunk};});
    return{id:r.id,source,provider,kind:r.kind,name:String(r.name??'').slice(0,200),address:r.address,reason,...(r.signature?{signature:String(r.signature).slice(0,240)}:{}),hasCode:Boolean(r.has_code),external:r.external===null?null:Boolean(r.external),thunk:r.thunk===null?null:Boolean(r.thunk),recordTruncated:Boolean(r.record_truncated),decompilationStatus:r.decompilation_status??null,...(r.boundary_warning_count?{boundaryWarningCount:r.boundary_warning_count}:{}),...(callees.length?{callees}:{}),...(inline?{text:excerpt(r)}:{})};
   });
   return measured({...base,status:exists?'context-packet':'no-observations',fingerprint:'0'.repeat(64),total:ranked.length,offset,seedMatches:matching,queryTermsLimited:termsLimited,candidateScanLimited:scanLimited,calleeExpansionLimited:edgeLimited,sources,providers,items,nextOffset:offset+selected.length<ranked.length?offset+selected.length:null,budgetLimited:selected.length<candidates.length},budget,selected.reduce((n,c)=>n+Number(c.row.text_bytes),0));
  };
  let packet=seal();if(packet.receipt.responseBytes>budget)throw new Error('Response metadata exceeds budgetBytes; increase the budget.');
  for(const candidate of candidates){
   selected.push(candidate);let next=seal();
   if(next.receipt.responseBytes>budget&&view==='auto'&&candidate.inline){candidate.inline=false;next=seal();}
   if(next.receipt.responseBytes>budget){selected.pop();if(!selected.length)throw new Error('Budget cannot hold one complete result; use at least'+next.receipt.responseBytes+' bytes.');packet=seal();break;}
   packet=next;
  }
  const fingerprint=digest(JSON.stringify({request,packet}));
  if(options.knownFingerprint===fingerprint){const unchanged=measured({schema:base.schema,status:'unchanged-recorded-context',fingerprint,freshBytesChecked:false,items:[],nextOffset:packet.nextOffset},budget);if(unchanged.receipt.responseBytes>budget)throw new Error('Response metadata exceeds budgetBytes.');return unchanged;}
  return{...packet,fingerprint};
 }finally{db.exec('ROLLBACK');db.close();}
}
