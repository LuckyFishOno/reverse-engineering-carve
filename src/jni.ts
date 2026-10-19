import {open,realpath,mkdir,writeFile,readFile,link,unlink,lstat} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {activeLinkage,linkageCoverage,linkageTables} from './linkage.js';

// Reads native method declarations from Java class files (JVMS chapter 4) and DEX files
// (source.android.com/docs/core/runtime/dex-format), then derives JNI symbol names
// (JNI specification, "Resolving Native Method Names"). Declarations are not bindings.
const MAX_CLASS=16*1024*1024,MAX_DEX=256*1024*1024,MAX_NATIVES=100000,ACC_NATIVE=0x0100,ACC_STATIC=0x0008;
const fail=(message:string):never=>{throw new Error('JNI declarations: '+message);};
export interface NativeDeclaration {className:string;internalName:string;method:string;descriptor:string;static:boolean;accessFlags:number;jniShortName:string;jniLongName:string;overloaded:boolean}

// Modified UTF-8: no raw NUL, two-byte NUL, surrogates encoded as separate three-byte units.
// Overlong forms are rejected like HotSpot's class-file check and ART's DEX verifier: a two-byte
// unit must encode NUL or a value of at least 0x80, a three-byte unit at least 0x800. HotSpot still
// accepts overlong forms in class files of major version 47 or older, so callers pass that flag.
export function decodeModifiedUtf8(data:Buffer,start:number,end:number,options:{allowOverlong?:boolean}={}){
 const units:number[]=[];
 for(let p=start;p<end;){
  const a=data[p]!;
  if(a===0)fail('raw NUL inside modified UTF-8.');
  if(a<0x80){units.push(a);p++;continue;}
  if((a&0xe0)===0xc0){const b=data[p+1];if(p+1>=end||b===undefined||(b&0xc0)!==0x80)fail('truncated two-byte modified UTF-8.');const unit=((a&0x1f)<<6)|(b!&0x3f);if(unit!==0&&unit<0x80&&!options.allowOverlong)fail('overlong two-byte modified UTF-8.');units.push(unit);p+=2;continue;}
  if((a&0xf0)===0xe0){const b=data[p+1],c=data[p+2];if(p+2>=end||b===undefined||c===undefined||(b&0xc0)!==0x80||(c&0xc0)!==0x80)fail('truncated three-byte modified UTF-8.');const unit=((a&0x0f)<<12)|((b!&0x3f)<<6)|(c!&0x3f);if(unit<0x800&&!options.allowOverlong)fail('overlong three-byte modified UTF-8.');units.push(unit);p+=3;continue;}
  fail('invalid modified UTF-8 lead byte.');
 }
 let text='';for(let i=0;i<units.length;i+=8192)text+=String.fromCharCode(...units.slice(i,i+8192));return text;
}
export function jniMangle(value:string){
 let out='';
 for(let i=0;i<value.length;i++){
  const c=value[i]!,code=value.charCodeAt(i);
  if(c==='/')out+='_';else if(c==='_')out+='_1';else if(c===';')out+='_2';else if(c==='[')out+='_3';
  else if(/[A-Za-z0-9]/.test(c))out+=c;else out+='_0'+code.toString(16).padStart(4,'0');
 }
 return out;
}
export function jniNames(internalName:string,method:string,descriptor:string){
 const args=/^\(([^)]*)\)/.exec(descriptor)?.[1];if(args===undefined)fail('invalid method descriptor.');
 const jniShortName='Java_'+jniMangle(internalName)+'_'+jniMangle(method);
 return{jniShortName,jniLongName:jniShortName+'__'+jniMangle(args!)};
}
function finish(raw:Omit<NativeDeclaration,'jniShortName'|'jniLongName'|'overloaded'>[]){
 const counts=new Map<string,number>();for(const d of raw){const key=d.internalName+'\0'+d.method;counts.set(key,(counts.get(key)??0)+1);}
 return raw.map(d=>({...d,...jniNames(d.internalName,d.method,d.descriptor),overloaded:(counts.get(d.internalName+'\0'+d.method)??0)>1}));
}
const dotted=(internal:string)=>internal.replaceAll('/','.');

export function classNatives(data:Buffer){
 if(data.length<10||data.length>MAX_CLASS||data.readUInt32BE(0)!==0xcafebabe)fail('expected one Java class file of at most16MiB.');
 let p=8;const need=(n:number)=>{if(p+n>data.length)fail('truncated class file.');};
 const u1=()=>{need(1);return data[p++]!;},u2=()=>{need(2);const v=data.readUInt16BE(p);p+=2;return v;},u4=()=>{need(4);const v=data.readUInt32BE(p);p+=4;return v;};
 const allowOverlong=data.readUInt16BE(6)<=47;const count=u2();if(count<1)fail('empty constant pool.');const pool:(string|number|null)[]=[null];
 for(let i=1;i<count;i++){
  const tag=u1();
  if(tag===1){const length=u2();need(length);pool[i]=decodeModifiedUtf8(data,p,p+length,{allowOverlong});p+=length;}
  // Class constants keep their name index (negated); other two-byte constants are not needed.
  else if(tag===7||tag===16||tag===8||tag===19||tag===20){const value=u2();pool[i]=tag===7?-value:null;}
  else if([3,4,9,10,11,12,17,18].includes(tag)){p+=4;need(0);pool[i]=null;}
  else if(tag===5||tag===6){p+=8;need(0);pool[i]=null;pool[++i]=null;if(i>=count)fail('long/double constant overruns the pool.');}
  else if(tag===15){p+=3;need(0);pool[i]=null;}
  else fail('unsupported constant-pool tag '+tag+'.');
 }
 const utf8=(index:number)=>{const value=pool[index];if(typeof value!=='string')fail('expected a UTF8 constant.');return value as string;};
 u2();const thisClass=pool[u2()];if(typeof thisClass!=='number'||thisClass>=0)fail('this_class is not a class constant.');
 const internalName=utf8(-(thisClass as number));u2();const interfaces=u2();need(interfaces*2);p+=interfaces*2;
 const skipAttributes=()=>{const n=u2();for(let i=0;i<n;i++){u2();const length=u4();need(length);p+=length;}};
 const fields=u2();for(let i=0;i<fields;i++){u2();u2();u2();skipAttributes();}
 const methods=u2();const raw=[];
 for(let i=0;i<methods;i++){
  const flags=u2(),method=utf8(u2()),descriptor=utf8(u2());skipAttributes();
  if(flags&ACC_NATIVE)raw.push({className:dotted(internalName),internalName,method,descriptor,static:Boolean(flags&ACC_STATIC),accessFlags:flags});
 }
 skipAttributes();if(p!==data.length)fail('trailing bytes after the class file.');
 return{format:'java-class',classes:1,natives:finish(raw)};
}

export function dexNatives(data:Buffer){
 if(data.length<0x70||data.length>MAX_DEX||!/^dex\n0[3-4]\d\0$/.test(data.subarray(0,8).toString('latin1')))fail('expected one DEX file of at most256MiB.');
 if(data.readUInt32LE(0x28)!==0x12345678||data.readUInt32LE(0x24)!==0x70||data.readUInt32LE(0x20)!==data.length)fail('unsupported DEX endian tag, header size or file size.');
 const u32=(at:number)=>{if(at<0||at+4>data.length)fail('offset outside the DEX file.');return data.readUInt32LE(at);};
 const u16=(at:number)=>{if(at<0||at+2>data.length)fail('offset outside the DEX file.');return data.readUInt16LE(at);};
 const table=(at:number,width:number)=>{const size=u32(at),offset=u32(at+4);if(size&&(offset+size*width>data.length))fail('DEX table outside the file.');return{size,offset};};
 const strings=table(0x38,4),types=table(0x40,4),protos=table(0x48,12),methods=table(0x58,8),classes=table(0x60,32);
 const uleb=(state:{p:number})=>{let result=0;for(let shift=0;shift<35;shift+=7){if(state.p>=data.length)fail('truncated uleb128.');const b=data[state.p++]!;result+=(b&0x7f)*2**shift;if(!(b&0x80))return result;}return fail('uleb128 exceeds32 bits.');};
 const cache=new Map<number,string>();
 const string=(index:number)=>{
  if(index>=strings.size)fail('string index outside the table.');const known=cache.get(index);if(known!==undefined)return known;
  const state={p:u32(strings.offset+index*4)};const units=uleb(state);const end=data.indexOf(0,state.p);if(end<0)fail('unterminated DEX string.');
  const text=decodeModifiedUtf8(data,state.p,end);if(text.length!==units)fail('DEX string length disagrees with its data.');cache.set(index,text);return text;
 };
 const type=(index:number)=>{if(index>=types.size)fail('type index outside the table.');return string(u32(types.offset+index*4));};
 const descriptor=(index:number)=>{
  if(index>=protos.size)fail('proto index outside the table.');const at=protos.offset+index*12,returnType=type(u32(at+4)),params=u32(at+8);let args='';
  if(params){const n=u32(params);if(params+4+n*2>data.length)fail('type list outside the file.');for(let i=0;i<n;i++)args+=type(u16(params+4+i*2));}
  return'('+args+')'+returnType;
 };
 const raw:Omit<NativeDeclaration,'jniShortName'|'jniLongName'|'overloaded'>[]=[];
 for(let c=0;c<classes.size;c++){
  const dataOffset=u32(classes.offset+c*32+24);if(!dataOffset)continue;
  const state={p:dataOffset};const staticFields=uleb(state),instanceFields=uleb(state),direct=uleb(state),virtual=uleb(state);
  for(let i=0;i<staticFields+instanceFields;i++){uleb(state);uleb(state);}
  for(const list of [direct,virtual]){
   let index=0;
   for(let i=0;i<list;i++){
    index+=uleb(state);const flags=uleb(state);uleb(state);if(!(flags&ACC_NATIVE))continue;
    if(index>=methods.size)fail('method index outside the table.');const at=methods.offset+index*8;
    const classDescriptor=type(u16(at));if(!/^L[^;]+;$/.test(classDescriptor))fail('native method owner is not a class type.');
    const internalName=classDescriptor.slice(1,-1);
    raw.push({className:dotted(internalName),internalName,method:string(u32(at+4)),descriptor:descriptor(u16(at+2)),static:Boolean(flags&ACC_STATIC),accessFlags:flags});
    if(raw.length>MAX_NATIVES)fail('more than100000 native declarations.');
   }
  }
 }
 return{format:'dex',classes:classes.size,natives:finish(raw)};
}

async function readSelected(file:string,max:number,signal?:AbortSignal){
 const handle=await open(file,'r');
 try{const info=await handle.stat();if(!info.isFile()||info.size>max)fail('selected input is not a regular file within its size limit.');const data=Buffer.alloc(info.size);let read=0;while(read<data.length){signal?.throwIfAborted();const r=await handle.read(data,read,data.length-read,read);if(!r.bytesRead)fail('input truncated during read.');read+=r.bytesRead;}return data;}
 finally{await handle.close();}
}
async function persistEvidence(root:string,id:string,text:string){
 const directory=path.join(root,'jni-evidence');await mkdir(directory,{recursive:true,mode:0o700});if(await realpath(directory)!==directory)throw new Error('JNI evidence directory follows a symlink.');
 const evidence=path.join(directory,id+'.json'),temporary=path.join(directory,'.'+randomUUID()+'.tmp');
 try{await writeFile(temporary,text,{flag:'wx',mode:0o600});try{await link(temporary,evidence);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;const info=await lstat(evidence);if(!info.isFile()||info.isSymbolicLink()||(await hashFile(evidence)).sha256!==digest(text))throw new Error('Existing JNI evidence changed; preserve it before retrying.');}}
 finally{await unlink(temporary).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});}
 return evidence;
}

export async function inspectJni(workspace:string,options:{files:string[];libraries?:string[];query?:string;limit?:number;offset?:number;budgetBytes?:number;signal?:AbortSignal}){
 const limit=options.limit??20,offset=options.offset??0,query=options.query??'',budget=responseBudget(options.budgetBytes);
 if(!Array.isArray(options.files)||options.files.length<1||options.files.length>500||new Set(options.files).size!==options.files.length)throw new Error('Choose1–500 distinct indexed class/DEX files.');
 if(options.libraries!==undefined&&(options.libraries.length<1||options.libraries.length>500))throw new Error('Choose1–500 library paths, or omit libraries to consider every indexed export page.');
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||query.length>1000)throw new Error('Use JNI limit1–100, a nonnegative offset and query<=1000 characters.');
 const root=await realpath(workspace);
 const parserSha256=digest(await readFile(fileURLToPath(import.meta.url)));const provider={name:'carve-jni-declarations',version:'1',parserSha256};
 const sources=[];const declarations:(NativeDeclaration&{file:string;observationId:string})[]=[];
 for(const file of options.files){
  const source=await indexedFile(root,file,options.signal);
  if(!['java-class','dex'].includes(source.facts.format))throw new Error(`Selected ${file} is ${source.facts.format}; choose an unpacked Java class or DEX file.`);
  const data=await readSelected(source.path,source.facts.format==='dex'?MAX_DEX:MAX_CLASS,options.signal);if(digest(data)!==source.sha256)throw new Error('Selected bytes changed since inventory.');
  const parsed=source.facts.format==='dex'?dexNatives(data):classNatives(data);
  if((await hashFile(source.path,options.signal)).sha256!==source.sha256)throw new Error('Selected input changed while parsing.');
  const detail={kind:'jni-declarations',name:'JNI native declarations in '+file,address:'file:0',provider,metadata:{format:parsed.format,classes:parsed.classes,natives:parsed.natives}};
  const id=digest(JSON.stringify({file,sha256:source.sha256,detail}));const text=JSON.stringify({schema:'carve/jni-declarations-evidence@1',file,sourceSha256:source.sha256,...detail},null,2)+'\n';
  const evidence=await persistEvidence(root,id,text);
  const db=openIndex(root);try{
   db.exec(`CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
    CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
    CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
   const content=parsed.natives.map(n=>n.className+'.'+n.method+n.descriptor+'\n'+n.jniShortName).join('\n');
   db.exec('BEGIN');try{const inserted=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,file,source.sha256,detail.kind,detail.name,detail.address,content,JSON.stringify(detail),evidence,digest(text));if(inserted.changes)db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(id,content);db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');throw error;}
  }finally{db.close();}
  sources.push({file,sourceSha256:source.sha256,format:parsed.format,classes:parsed.classes,natives:parsed.natives.length,observationId:id,evidence,evidenceSha256:digest(text)});
  for(const n of parsed.natives)declarations.push({...n,file,observationId:id});
 }
 const db=openIndex(root,true);
 try{
  const hasLinkage=Boolean(db.prepare("SELECT name FROM sqlite_master WHERE name='linkage_records'").get());
  const libraryClause=options.libraries?` AND r.artifact IN (${options.libraries.map(()=>'?').join(',')})`:'';const libraryArgs=options.libraries??[];
  // Libraries whose export metadata is indexed for the current inventory bytes.
  const libraries=hasLinkage?(db.prepare("SELECT DISTINCT h.artifact,h.sha256,h.profile,f.format FROM linkage_heads h JOIN files f ON f.path=h.artifact AND f.sha256=h.sha256 JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') AND f.error IS NULL WHERE h.kind='exports'"+(options.libraries?` AND h.artifact IN (${options.libraries.map(()=>'?').join(',')})`:'')+' ORDER BY h.artifact').all(...libraryArgs) as Record<string,any>[]):[];
  const indexed=new Set(libraries.map(l=>l.artifact));
  const missingLibraries=(options.libraries??[]).filter(l=>!indexed.has(l));
  const unindexedNative=Number((db.prepare("SELECT count(*) n FROM files f JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') WHERE f.backend='ghidra' AND f.error IS NULL"+(options.libraries?` AND f.path IN (${options.libraries.map(()=>'?').join(',')})`:'')).get(...libraryArgs) as any).n)-libraries.length;
  const coverage=libraries.map(l=>{
   const c=linkageCoverage(db,{artifact:l.artifact,sha256:l.sha256,profile:l.profile,kind:'exports'});
   const onLoad=db.prepare('SELECT r.name,r.address,r.id'+activeLinkage+" WHERE r.artifact=? AND r.kind='exports' AND (r.name IN ('JNI_OnLoad','_JNI_OnLoad') OR r.name LIKE 'JNI\\_OnLoad\\_%' ESCAPE '\\' OR r.name LIKE '\\_JNI\\_OnLoad\\_%' ESCAPE '\\')").all(l.artifact) as Record<string,any>[];
   return{file:l.artifact,sourceSha256:l.sha256,format:l.format,exportProfile:l.profile,exportsKnownComplete:c.knownComplete,coveredFromStart:c.coveredFromStart,nextCursor:c.nextCursor,jniOnLoad:onLoad.map(r=>({name:r.name,address:r.address,id:r.id}))};
  });
  const complete=coverage.length>0&&coverage.every(c=>c.exportsKnownComplete)&&!missingLibraries.length;
  const onLoadLibraries=coverage.filter(c=>c.jniOnLoad.length).map(c=>c.file);
  const lookup=hasLinkage?db.prepare('SELECT r.id,r.artifact,r.name,r.address,r.format'+activeLinkage+" WHERE r.kind='exports' AND r.name IN (?,?,?,?)"+libraryClause+' ORDER BY r.artifact,r.name'):undefined;
  const filtered=declarations.filter(d=>!query||(d.className+'.'+d.method+d.descriptor+' '+d.jniShortName+' '+d.file).toLowerCase().includes(query.toLowerCase()));
  const resolved=filtered.map(d=>{
   const rows=(lookup?lookup.all(d.jniShortName,d.jniLongName,'_'+d.jniShortName,'_'+d.jniLongName,...libraryArgs) as Record<string,any>[]:[])
    .filter(r=>!String(r.name).startsWith('_')||String(r.format).startsWith('mach-o'))
    .map(r=>{const symbol=String(r.name).replace(/^_/,'');return{id:r.id,file:r.artifact,name:r.name,address:r.address,form:symbol===d.jniLongName?'long':'short'};});
   const libraries=new Set(rows.map(r=>r.file));
   const status=rows.length===0?(complete&&!onLoadLibraries.length?'no-static-export-in-complete-index':'no-indexed-static-export'):libraries.size===1?'static-export-candidate':'multiple-library-candidates';
   return{value:{file:d.file,observationId:d.observationId,className:d.className,method:d.method,descriptor:d.descriptor,static:d.static,overloaded:d.overloaded,jniShortName:d.jniShortName,jniLongName:d.jniLongName,status,candidates:rows.slice(0,20),candidatesTruncated:rows.length>20,
    ...(rows.length===0&&onLoadLibraries.length?{dynamicRegistrationLeads:onLoadLibraries.slice(0,20)}:{}),...(d.overloaded?{note:'Overloaded native method: only the long-name form identifies one overload; a short-name export is ambiguous.'}:{})}};
  });
  const counts={declarations:declarations.length,selected:filtered.length,staticExportCandidates:resolved.filter(r=>r.value.status==='static-export-candidate').length,multipleLibraryCandidates:resolved.filter(r=>r.value.status==='multiple-library-candidates').length,withoutStaticExport:resolved.filter(r=>r.value.status.startsWith('no-')).length};
  return budgetItems({schema:'carve/jni-boundaries@1',status:'declarations-matched-to-indexed-exports',workspace:root,provider,executesTarget:false,sourcesFreshlyHashed:true,sources,
   libraries:{indexedExports:coverage.slice(0,50),indexedExportsTruncated:coverage.length>50,requestedWithoutExportIndex:missingLibraries,nativeArtifactsWithoutExportIndex:Math.max(0,unindexedNative),allSelectedExportsKnownComplete:complete},
   counts,query,offset,limit,total:resolved.length,
   scope:'Declared native methods and derived JNI symbol names, compared with indexed loader export metadata of current inventory libraries. A matching export is a static-binding candidate only: which library System.loadLibrary loads, RegisterNatives in JNI_OnLoad, ABI/architecture selection, signatures and behavior are not established. Missing matches are inconclusive unless every selected export index is complete and no library exports JNI_OnLoad. Library export bytes are not freshly rehashed by this read.'},resolved.slice(offset,offset+limit),budget);
 }finally{db.close();}
}
