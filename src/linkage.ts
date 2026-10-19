import {realpath} from 'node:fs/promises';
import path from 'node:path';
import {z} from 'zod';
import type {DatabaseSync} from 'node:sqlite';
import {openIndex} from './survey.js';
const kinds=['imports','exports','libraries'] as const;
export const linkageKind=z.enum(kinds);
export type LinkageKind=z.infer<typeof linkageKind>;
export function linkageTables(db:DatabaseSync){db.exec(`
 CREATE TABLE IF NOT EXISTS linkage_records(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,profile TEXT,kind TEXT,name TEXT,normalized_name TEXT,library TEXT,language TEXT,format TEXT,address TEXT);
 CREATE INDEX IF NOT EXISTS linkage_names ON linkage_records(kind,name,language,format,artifact);
 CREATE INDEX IF NOT EXISTS linkage_normalized_names ON linkage_records(kind,normalized_name,language,format,artifact);
 CREATE TABLE IF NOT EXISTS linkage_heads(artifact TEXT,kind TEXT,sha256 TEXT,profile TEXT,PRIMARY KEY(artifact,kind));
 CREATE TABLE IF NOT EXISTS linkage_pages(artifact TEXT,sha256 TEXT,profile TEXT,kind TEXT,offset INTEGER,records INTEGER,next_offset INTEGER,PRIMARY KEY(artifact,sha256,profile,kind,offset));
 `);}
const normalize=(name:string)=>name.startsWith('_')?name.slice(1):name;
export function saveLinkage(db:DatabaseSync,id:string,file:string,sha256:string,profile:string,language:string,format:string,item:Record<string,any>){
 const kind=({'native-import':'imports','native-export':'exports','native-library':'libraries'} as Record<string,string>)[item.kind];if(!kind)return;
 if(typeof item.name!=='string'||item.name.length>32768||typeof item.address!=='string'||item.address.length>32768||item.library!=null&&(typeof item.library!=='string'||item.library.length>32768))throw new Error('Invalid native linkage record.');
 db.prepare('INSERT OR IGNORE INTO linkage_records VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id,file,sha256,profile,kind,item.name,normalize(item.name),item.library??null,language,format,item.address);
}
export function saveLinkagePage(db:DatabaseSync,file:string,sha256:string,profile:string,kind:LinkageKind,end:Record<string,any>){
 if(end.linkageKind!==kind||!Number.isSafeInteger(end.offset)||end.offset<0||!Number.isSafeInteger(end.records)||end.records<0||end.nextOffset!==undefined&&(end.records===0||end.nextOffset!==end.offset+end.records))throw new Error('Invalid linkage page marker.');
 db.prepare('INSERT OR REPLACE INTO linkage_heads VALUES(?,?,?,?)').run(file,kind,sha256,profile);
 db.prepare('INSERT OR REPLACE INTO linkage_pages VALUES(?,?,?,?,?,?,?)').run(file,sha256,profile,kind,end.offset,end.records,end.nextOffset??null);
}
export function linkageCursor(identity:{file:string;sha256:string;profile:string;kind:LinkageKind},offset:number){return Buffer.from(JSON.stringify({...identity,offset})).toString('base64url');}
export function linkageOffset(cursor:string|undefined,identity:{file:string;sha256:string;profile:string;kind:LinkageKind}){
 if(!cursor)return 0;
 try{if(cursor.length>8192||!/^[a-zA-Z0-9_-]+$/.test(cursor))throw 0;const value=z.object({file:z.string(),sha256:z.string(),profile:z.string(),kind:linkageKind,offset:z.number().int().min(0).max(1000000000)}).strict().parse(JSON.parse(Buffer.from(cursor,'base64url').toString('utf8')));for(const key of ['file','sha256','profile','kind'] as const)if(value[key]!==identity[key])throw 0;return value.offset;}
 catch{throw new Error('Linkage cursor does not match this source, selected kind and exporter profile. Restart from the first page.');}
}
export function linkageCoverage(db:DatabaseSync,item:{artifact:string;sha256:string;profile:string;kind:LinkageKind}){
 let covered=0,complete=false,pages=0,inspectionTruncated=false;
 for(const row of db.prepare('SELECT offset,records,next_offset FROM linkage_pages WHERE artifact=? AND sha256=? AND profile=? AND kind=? ORDER BY offset').iterate(item.artifact,item.sha256,item.profile,item.kind)){
  if(pages>=10000){inspectionTruncated=true;break;}pages++;const start=Number(row.offset),end=start+Number(row.records);if(start>covered)break;
  if(end>=covered){covered=end;if(row.next_offset===null){complete=true;break;}}
 }
 return{coveredFromStart:covered,knownComplete:complete,inspectedPages:pages,inspectionTruncated,nextCursor:complete?null:linkageCursor({file:item.artifact,sha256:item.sha256,profile:item.profile,kind:item.kind},covered)};
}
export const activeLinkage=` FROM linkage_records r JOIN linkage_heads h ON h.artifact=r.artifact AND h.kind=r.kind AND h.sha256=r.sha256 AND h.profile=r.profile JOIN files f ON f.path=r.artifact AND f.sha256=r.sha256 JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') AND f.error IS NULL`;
export async function queryLinks(workspace:string,options:{file?:string;kind?:LinkageKind;query?:string;from?:string;symbolMatch?:'exact'|'leading-underscore';limit?:number;offset?:number}={}){
 const root=await realpath(workspace),limit=options.limit??20,offset=options.offset??0;
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||options.query!==undefined&&options.query.length>1000)throw new Error('Use linkage page limit1–100, a nonnegative offset and query up to1000 characters.');
 if(options.kind)linkageKind.parse(options.kind);if(options.symbolMatch&&!['exact','leading-underscore'].includes(options.symbolMatch))throw new Error('Choose exact or leading-underscore symbol matching.');
 if(options.from&&(options.file!==undefined||options.kind!==undefined||options.query!==undefined)||options.symbolMatch&&!options.from)throw new Error('Choose an import from ID for candidate mode, or file/kind/query for record mode.');
 if(options.from&&!/^[a-f0-9]{64}$/.test(options.from))throw new Error('Choose a returned import observation ID.');
 const db=openIndex(root,true);
 const scope='Only selected Ghidra loader-metadata pages matching current inventory hashes/latest indexed profiles are queried. Source/evidence bytes are not freshly rehashed by this read. Missing candidates do not prove absence; shared caches, dlopen, loader paths, ordinals, reexports, ABI and semantic closure remain unresolved.';
 try{
  if(!db.prepare("SELECT name FROM sqlite_master WHERE name='linkage_records'").get())return{schema:'carve/native-links@1',workspace:root,total:0,items:[],nextOffset:null,status:'no-linkage-index',scope};
  const args:(string|number)[]=[],clauses:string[]=[];let source:Record<string,any>|undefined;
  const candidates=Boolean(options.from);
  if(candidates){
   source=db.prepare('SELECT r.*'+activeLinkage+" WHERE r.id=? AND r.kind='imports'").get(options.from!) as Record<string,any>|undefined;
   if(!source)throw new Error('Import observation is absent or no longer matches the current inventory/profile.');
   clauses.push("r.kind='exports'",'r.artifact<>?','r.language=?','r.format=?');args.push(source.artifact,source.language,source.format);
   const column=options.symbolMatch==='leading-underscore'?'normalized_name':'name';clauses.push(`r.${column}=?`);args.push(source[column]);
  }else{
   if(options.file!==undefined){clauses.push('r.artifact=?');args.push(options.file);}if(options.kind){clauses.push('r.kind=?');args.push(options.kind);}if(options.query!==undefined){clauses.push('(instr(r.name,?)>0 OR instr(COALESCE(r.library,\'\'),?)>0)');args.push(options.query,options.query);}
  }
  const where=clauses.length?' WHERE '+clauses.join(' AND '):'';
  const total=Number((db.prepare('SELECT count(*) n'+activeLinkage+where).get(...args) as any).n);
  const rows=db.prepare('SELECT r.*'+activeLinkage+where+' ORDER BY r.artifact,r.kind,r.address,r.name,r.id LIMIT ? OFFSET ?').all(...args,limit,offset) as Record<string,any>[];
  const coverages=new Map<string,ReturnType<typeof linkageCoverage>>();
  const items=rows.map(row=>{const key=row.artifact+'\0'+row.kind;let coverage=coverages.get(key);if(!coverage){coverage=linkageCoverage(db,row as any);coverages.set(key,coverage);}return ({id:row.id,file:row.artifact,sourceSha256:row.sha256,kind:row.kind,name:row.name,library:row.library,address:row.address,language:row.language,format:row.format,exportProfile:row.profile,matchesCurrentInventory:true,freshBytesChecked:false,pageCoverage:coverage,...(candidates?{symbolMatch:options.symbolMatch??'exact',libraryBasenameHint:Boolean(source?.library&&path.posix.basename(String(source.library).replaceAll('\\','/'))===path.posix.basename(row.artifact)),semanticMatch:'unconfirmed',runtimeLoading:'unverified'}:{})});});
  return{schema:'carve/native-links@1',workspace:root,mode:candidates?'candidates':'records',...(source?{from:{id:source.id,file:source.artifact,name:source.name,library:source.library,language:source.language,format:source.format,sourceSha256:source.sha256,exportProfile:source.profile,freshBytesChecked:false,pageCoverage:linkageCoverage(db,source as any)}}:{}),status:'indexed-page',total,limit,offset,items,nextOffset:offset+rows.length<total?offset+rows.length:null,scope};
 }finally{db.close();}
}
