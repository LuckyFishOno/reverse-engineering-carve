import {realpath} from 'node:fs/promises';
import {openIndex,metaValue,assertWorkspaceInPlace} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {featureFacet,featureFacets} from './feature-intent.js';

// These labels classify recorded leads, never semantic confidence or extraction success.
const rules=[
 {id:'swipe',title:'Swipe and drag interactions',terms:['draggable','swipe','\u6ed1\u5361','\u62d6\u66f3'],goal:'Extract local swipe direction and drag interactions; confirm thresholds and dependencies, and retain server matching as unknown.',boundary:'Confirm gesture entry points, geometry, direction settings and animation dependencies; a swipe component does not establish matching rules.'},
 {id:'contact',title:'Contact and vCard conversion',terms:['vcard','contactencoder','\u806f\u7d61\u4eba'],goal:'Extract contact and vCard conversion',boundary:'Separate text formatting, address book permissions and native storage.'},
 {id:'barcode',title:'QR and barcode encoding',terms:['zxing','qrcode','barcode','\u689d\u78bc'],goal:'Extract QR and barcode encoding logic',boundary:'Separate data encoding, image rendering and camera/hardware access.'},
 {id:'image',title:'Image processing and loading',terms:['sdwebimage','kingfisher','imageprocessor','resizeimage','\u5716\u7247'],goal:'Extract a specified image processing or loading operation',boundary:'Specify transformation, caching or loading; remote image services may be absent from the client.'},
 {id:'archive',title:'Archives and resources',terms:['ziparchive','zipfoundation','bootstrap','archive','unzip','\u58d3\u7e2e'],goal:'Extract a local archive or resource operation',boundary:'Confirm formats and data sources; metadata is not content or installation behavior.'},
 {id:'media',title:'Media dimensions and processing',terms:['scrcpy','avplayer','ffmpeg','videosize','audioprocess','\u5f71\u97f3'],goal:'Extract a specified local media operation',boundary:'Separate pure computation from codecs, devices, permissions and playback state.'},
 {id:'document',title:'Document and PDF conversion',terms:['pdfkit','pdfexport','documentconverter','\u532f\u51fa','\u6587\u4ef6'],goal:'Extract document conversion or export',boundary:'Confirm input/output formats, fonts, file system access and external tools.'},
 {id:'chat',title:'Local chat processing',terms:['chatview','messageparser','conversation','\u804a\u5929','\u8a0a\u606f'],goal:'Investigate local chat formatting, presentation and data processing boundaries',boundary:'Names do not establish recoverable chat transport, accounts or server storage.'},
 {id:'crypto',title:'Encoding, hashing and cryptographic operations',terms:['openssl','cryptokit','checksum','adler32','base64','\u96dc\u6e4a'],goal:'Extract a confirmed encoding, hashing or cryptographic operation',boundary:'Confirm algorithms and input domains; do not read or expose credentials or keys.'},
 {id:'notification',title:'Local notification processing',terms:['firebase_messaging','firebasemessaging','usernotification','pushnotification','\u63a8\u64ad'],goal:'Investigate local notification event handling',boundary:'Push delivery, service configuration and server logic are outside this local candidate claim.'}
] as const;
type Lead={kind:'inventory-path'|'recorded-observation';file:string;sourceSha256:string;format:string;encrypted:boolean;id?:string;name?:string;code?:boolean};
type Cursor={identity:string;file:number;observation:number};
type Card={id:string;title:string;suggestedGoal:string;status:'unconfirmed';basis:string;leadCountInScan:number;leads:Lead[];dependencyQuestion:string;componentCountInScan?:number};
export type FeatureMenuOptions={query?:string;choice?:string;facet?:string;cursor?:string;scanLimit?:number;offset?:number;limit?:number;budgetBytes?:number};

/** Bounded read-only recorded-context scan, usable beside REA without calling it. */
export async function featureMenu(workspace:string,options:FeatureMenuOptions={}){
 const root=await realpath(workspace),query=options.query?.trim()??'',scan=options.scanLimit??1000,offset=options.offset??0,limit=options.limit??8,budget=responseBudget(options.budgetBytes);
 if(query.length>1000||!Number.isInteger(scan)||scan<1||scan>5000||!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>12)throw new Error('Use query<=1000 characters, scanLimit1–5000, offset>=0 and limit1–12.');
 if(options.choice&&!rules.some(r=>r.id===options.choice))throw new Error('Choose a returned feature ID, or use query for your own description.');
 const facet=featureFacet(options.choice,options.facet);
 const db=openIndex(root,true);
 try{
  await assertWorkspaceInPlace(root,db);
  const epoch=metaValue(db,'epoch'),inventoryStatus=metaValue(db,'status')??'unknown',hasObservations=Boolean(db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='observations'").get());
  const fileCount=Number((db.prepare('SELECT count(*) n FROM files WHERE seen=? AND error IS NULL').get(epoch) as any).n);
  const joined=' FROM observations o JOIN files f ON f.path=o.artifact AND f.sha256=o.sha256 WHERE f.seen=? AND f.error IS NULL';
  const observationState=hasObservations?db.prepare('SELECT count(*) n,max(o.id) last'+joined).get(epoch) as any:{n:0,last:null};
  const identity=digest(JSON.stringify([root,epoch,inventoryStatus,fileCount,observationState.n,observationState.last,query,options.choice??null,scan,options.facet??null]));
  let cursor:Cursor={identity,file:0,observation:0};
  if(options.cursor){
   try{if(options.cursor.length>2000)throw 0;const value=JSON.parse(Buffer.from(options.cursor,'base64url').toString('utf8'));if(value.identity!==identity||!Number.isSafeInteger(value.file)||value.file<0||value.file>fileCount||!Number.isSafeInteger(value.observation)||value.observation<0||value.observation>observationState.n)throw 0;cursor=value;}
   catch{throw new Error('Feature cursor is stale or invalid; restart after index/analysis/query changes.');}
  }
  const files=db.prepare('SELECT path,sha256,format,facts FROM files WHERE seen=? AND error IS NULL ORDER BY path LIMIT ? OFFSET ?').all(epoch,scan,cursor.file) as any[];
  const observations=hasObservations?db.prepare("SELECT o.id,o.name,o.kind,o.artifact,o.sha256,json_extract(o.detail,'$.decompilationStatus') decompilation_status,json_extract(o.detail,'$.pseudocodeTruncated') code_truncated,json_type(o.detail,'$.pseudocode') code_type,f.format,f.facts"+joined+' ORDER BY o.id LIMIT ? OFFSET ?').all(epoch,scan,cursor.observation) as any[]:[];
  const leads:Lead[]=[...files.map(f=>({kind:'inventory-path' as const,file:f.path,sourceSha256:f.sha256,format:f.format,encrypted:Boolean(JSON.parse(f.facts??'{}').encrypted)})),
   ...observations.map(o=>({kind:'recorded-observation' as const,file:o.artifact,sourceSha256:o.sha256,format:o.format,encrypted:Boolean(JSON.parse(o.facts??'{}').encrypted),id:o.id,name:String(o.name??'').slice(0,240),code:['function','java-class'].includes(o.kind)&&o.decompilation_status!=='failed'&&!o.code_truncated&&o.code_type==='text'}))];
  const lower=query.toLowerCase();
  const componentLeads:Lead[]=[];
  const ranked:Card[]=rules.flatMap(rule=>{
   if(options.choice&&options.choice!==rule.id)return[];
   const queryMatch=!query||rule.terms.some(term=>lower.includes(term))||lower.includes(rule.title.toLowerCase());
   if(!queryMatch)return[];
   const broad=leads.filter(l=>rule.terms.some(term=>(l.file+' '+(l.name??'')).toLowerCase().includes(term)));
   const hits=facet?broad.filter(l=>facet.terms.some(term=>(l.file+' '+(l.name??'')).toLowerCase().includes(term))):broad;
   if(facet&&!hits.length)componentLeads.push(...broad.slice(0,2));
   if(!hits.length)return[];
   hits.sort((a,b)=>Number(Boolean(b.code))-Number(Boolean(a.code))||Number(b.kind==='recorded-observation')-Number(a.kind==='recorded-observation')||a.file.localeCompare(b.file)||String(a.id).localeCompare(String(b.id)));
   return[{id:rule.id,title:facet?facet.title:rule.title,suggestedGoal:facet?rule.goal+'; first identify the specified inputs and outputs of '+facet.title:rule.goal,status:'unconfirmed' as const,basis:hits.some(h=>h.code)?'recorded-code-lead':hits.some(h=>h.id)?'recorded-metadata-lead':'path-lead',leadCountInScan:hits.length,componentCountInScan:new Set(hits.map(h=>h.file+'\0'+h.sourceSha256)).size,leads:hits.slice(0,2),dependencyQuestion:facet?facet.question:rule.boundary,score:hits.filter(h=>h.code).length*3+hits.filter(h=>h.id).length*2+Math.min(hits.length,10)}];
  }).sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id)).map(({score,...card})=>card);
  const terms=[...new Set(lower.split(/[^\p{L}\p{N}_]+/u).filter(s=>s.length>=2))].slice(0,12);
  const customHits=query&&!ranked.length&&!facet?leads.filter(l=>terms.some(term=>(l.file+' '+(l.name??'')).toLowerCase().includes(term))).slice(0,2):[];
  if(customHits.length)ranked.push({id:'custom',title:'Custom feature leads',suggestedGoal:query,status:'unconfirmed',basis:customHits.some(h=>h.code)?'recorded-code-lead':'path-lead',leadCountInScan:customHits.length,leads:customHits,dependencyQuestion:'Confirm inputs, expected outputs, triggers and external dependencies; literal matches do not prove feature boundaries.'});
  const next={identity,file:cursor.file+files.length,observation:cursor.observation+observations.length};
  const more=next.file<fileCount||next.observation<observationState.n;
  return budgetItems({schema:'carve/feature-menu@1',workspace:root,query:query.slice(0,160),queryTruncated:query.length>160,status:ranked.length?'candidates-found':more?'continue-analysis-pages':inventoryStatus!=='indexed'?'inventory-incomplete':'needs-more-evidence',
   ...(options.choice?{refinement:{choice:options.choice,selectedFacet:facet?.id??null,basis:'question-templates-and-literal-name-filter-only',options:featureFacets[options.choice]!.map(f=>({id:f.id,title:f.title,question:f.question})),...(componentLeads.length?{componentLeadsNotFacetMatches:componentLeads}:{})}}:{}),
   total:ranked.length,offset,limit,coverage:{inventoryStatus,fileOffset:cursor.file,filesScanned:files.length,filesAvailable:fileCount,observationOffset:cursor.observation,observationsScanned:observations.length,observationsAvailable:Number(observationState.n),recordedPagesComplete:!more,complete:!more&&inventoryStatus==='indexed',nextCursor:more?Buffer.from(JSON.stringify(next)).toString('base64url'):null},
   otherOption:{label:'None of these; describe the feature to extract',argument:'query',questions:['Which operation or screen triggers this behavior?','What input is supplied and what output is expected?']},
   nextAction:ranked.length?'Show candidates; narrow with choice/facet or custom query. Record trigger/input/output/state and required UI/remote/host boundaries with scope / carve_scope, then inspect complete code/calls/dependencies through the separate REA MCP before reconstruction.':inventoryStatus!=='indexed'?'Resume inventory and inspect failures before interpreting missing candidates.':'Continue coverage pages if present; otherwise record missing answers with scope / carve_scope and investigate with the separate REA MCP. Do not invent a match.',
   scope:'Recorded names/paths only; no code bodies, target execution, fresh source hashing, semantic confidence, resolved cross-module edges or extraction success. REA remains a separate MCP; this tool never starts or proxies it.'},ranked.slice(offset,offset+limit).map(value=>({value})),budget);
 }finally{db.close();}
}
