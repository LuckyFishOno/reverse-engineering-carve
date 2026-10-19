import {open,realpath,mkdir,readFile,writeFile,link,unlink,lstat} from 'node:fs/promises';
import type {FileHandle} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {indexedFile,hashFile,openIndex,metaValue} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';

// Layouts: Microsoft PE/COFF specification (DOS stub, COFF file header, optional header, section
// table, import/delay-import/export directories). This reads declared tables only. It is not a
// Windows loader: no search order, KnownDLLs, side-by-side manifests, API-set resolution, binding,
// relocation or runtime-load proof, and it never executes the image.
export const PE_LIMITS={fileBytes:2**40,headerOffset:16*1024*1024,sections:96,importModules:4096,imports:100000,exports:100000,nameBytes:4096,readBytes:16*1024*1024} as const;
const machines=new Map([[0x14c,'i386'],[0x8664,'amd64'],[0x1c0,'arm'],[0x1c4,'armnt'],[0xaa64,'arm64'],[0xa641,'arm64ec'],[0xa64e,'arm64x'],[0x200,'ia64'],[0x5032,'riscv32'],[0x5064,'riscv64'],[0x0,'unknown']]);
const directoryNames=['export','import','resource','exception','certificate','base-relocation','debug','architecture','global-pointer','tls','load-config','bound-import','iat','delay-import','clr-runtime','reserved'];
export type PeSection={index:number;name:string;virtualAddress:number;virtualSize:number;rawOffset:number;rawSize:number;characteristics:number};
export type PeImport={ordinal?:number;hint?:number;name?:string;thunkRva:number};
export type PeImportModule={kind:'import'|'delay-import';index:number;name:string;descriptorRva:number;timeDateStamp:number;lookupTable:'name-table'|'address-table'|'none';entries:PeImport[];addressTableRva:number;status:'entries-read'|'bound-address-table-without-lookup-table'|'legacy-va-descriptor-not-interpreted'};
export type PeExport={ordinal:number;rva:number;names:string[];forwarder?:string};
export type PeMetadata={format:'pe32'|'pe32+';machine:number;machineName:string;characteristics:number;dll:boolean;timeDateStamp:number;subsystem:number;dllCharacteristics:number;entryRva:number;imageBase:string;sizeOfImage:number;sizeOfHeaders:number;
 sections:PeSection[];dataDirectories:{index:number;name:string;rva:number;size:number}[];managed:boolean;imports:PeImportModule[];exports:{name:string|null;ordinalBase:number;timeDateStamp:number;entries:PeExport[]}|null};

const fail=(message:string):never=>{throw new Error('PE loader: '+message);};
const u16=(b:Buffer,p:number)=>b.readUInt16LE(p),u32=(b:Buffer,p:number)=>b.readUInt32LE(p);
async function bytesAt(handle:FileHandle,size:number,position:number,length:number){
 if(!Number.isSafeInteger(position)||!Number.isSafeInteger(length)||position<0||length<0||length>PE_LIMITS.readBytes||position>size-length)fail(`range ${position}+${length} exceeds the file or the read budget.`);
 const data=Buffer.alloc(length);let got=0;while(got<length){const r=await handle.read(data,got,length-got,position+got);if(!r.bytesRead)fail('file is truncated.');got+=r.bytesRead;}return data;
}
const decoder=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});

export async function readPeLoader(file:string,options:{signal?:AbortSignal}={}):Promise<PeMetadata>{
 const handle=await open(file,'r');
 try{
  const stat=await handle.stat();if(!stat.isFile()||!Number.isSafeInteger(stat.size)||stat.size>PE_LIMITS.fileBytes)fail('choose a regular file with a safely addressable size.');
  const size=stat.size,read=(p:number,n:number)=>bytesAt(handle,size,p,n);
  const dos=await read(0,64);if(dos.toString('latin1',0,2)!=='MZ')fail('missing MZ header; not a PE image.');
  const peOffset=u32(dos,60);if(peOffset<64||peOffset>PE_LIMITS.headerOffset||peOffset%4!==0)fail('invalid e_lfanew.');
  const coff=await read(peOffset,24);if(u32(coff,0)!==0x4550)fail('missing PE\\0\\0 signature.');
  const machine=u16(coff,4),sectionCount=u16(coff,6),optionalBytes=u16(coff,20),characteristics=u16(coff,22);
  if(sectionCount<1||sectionCount>PE_LIMITS.sections)fail(`section count must be 1–${PE_LIMITS.sections}.`);
  if(!(characteristics&0x2))fail('COFF header does not mark an executable image (object files are not images).');
  if(optionalBytes<96)fail('optional header is too small for an image.');
  const optional=await read(peOffset+24,optionalBytes),magic=u16(optional,0);
  if(magic!==0x10b&&magic!==0x20b)fail(`unsupported optional header magic 0x${magic.toString(16)}.`);
  const plus=magic===0x20b,width=plus?8:4,directoryOffset=plus?112:96;
  if(optionalBytes<directoryOffset)fail('optional header is truncated.');
  const directoryCount=u32(optional,directoryOffset-4);if(directoryCount>16)fail('more than 16 data directories.');
  if(directoryOffset+directoryCount*8>optionalBytes)fail('data directories exceed the optional header.');
  const imageBase=plus?optional.readBigUInt64LE(24):BigInt(u32(optional,28));
  const sizeOfImage=u32(optional,56),sizeOfHeaders=u32(optional,60);
  const directories=Array.from({length:directoryCount},(_,i)=>({index:i,name:directoryNames[i]!,rva:u32(optional,directoryOffset+i*8),size:u32(optional,directoryOffset+i*8+4)}));
  const table=await read(peOffset+24+optionalBytes,sectionCount*40),sections:PeSection[]=[];
  for(let i=0;i<sectionCount;i++){
   const p=i*40,raw=table.subarray(p,p+8),end=raw.indexOf(0);
   const section={index:i,name:raw.toString('latin1',0,end<0?8:end),virtualSize:u32(table,p+8),virtualAddress:u32(table,p+12),rawSize:u32(table,p+16),rawOffset:u32(table,p+20),characteristics:u32(table,p+36)};
   // Raw data running past the end of the file is clipped when mapped, as LLVM does; a start outside it is malformed.
   if(section.rawSize&&section.rawOffset>=size)fail(`section ${section.name||i} raw data starts outside the file.`);
   sections.push(section);
  }
  // Same mapping LLVM's COFF reader uses: headers map 1:1, otherwise the file-backed part of a section.
  const offsetOf=(rva:number,length:number,what:string)=>{
   if(rva<sizeOfHeaders&&rva+length<=sizeOfHeaders&&rva+length<=size)return rva;
   for(const s of sections){const start=s.virtualAddress,end=start+Math.min(s.rawSize,size-s.rawOffset);if(rva>=start&&rva+length<=end)return s.rawOffset+(rva-start);}
   return fail(`${what} at RVA 0x${rva.toString(16)} is not backed by file data.`);
  };
  const cString=async(rva:number,what:string)=>{
   const offset=offsetOf(rva,1,what),chunk=await read(offset,Math.min(PE_LIMITS.nameBytes+1,size-offset)),end=chunk.indexOf(0);
   if(end<0)fail(`${what} is unterminated or longer than ${PE_LIMITS.nameBytes} bytes.`);
   try{return decoder.decode(chunk.subarray(0,end));}catch{return fail(`${what} is not valid UTF-8.`);}
  };
  const abort=()=>{if(options.signal?.aborted)fail('cancelled.');};
  let importCount=0;
  const thunks=async(tableRva:number,addressRva:number,what:string)=>{
   const entries:PeImport[]=[],flag=plus?1n<<63n:1n<<31n;
   for(let i=0;;i++){
    abort();if(importCount>=PE_LIMITS.imports)fail(`more than ${PE_LIMITS.imports} imports.`);
    const raw=await read(offsetOf(tableRva+i*width,width,what+' thunk'),width),value=plus?raw.readBigUInt64LE(0):BigInt(u32(raw,0));
    if(value===0n)break;importCount++;
    const thunkRva=addressRva+i*width;
    if(value&flag){entries.push({ordinal:Number(value&0xffffn),thunkRva});continue;}
    const hintRva=Number(value&0x7fffffffn),hint=u16(await read(offsetOf(hintRva,2,what+' hint'),2),0);
    entries.push({hint,name:await cString(hintRva+2,what+' name'),thunkRva});
   }
   return entries;
  };
  const imports:PeImportModule[]=[];
  const importDirectory=directories[1];
  if(importDirectory&&importDirectory.rva){
   for(let i=0;;i++){
    abort();if(i>=PE_LIMITS.importModules)fail(`more than ${PE_LIMITS.importModules} imported modules or a missing terminator.`);
    const descriptorRva=importDirectory.rva+i*20,d=await read(offsetOf(descriptorRva,20,'import descriptor'),20);
    const lookup=u32(d,0),stamp=u32(d,4),nameRva=u32(d,12),address=u32(d,16);
    if(!lookup&&!nameRva&&!address)break;
    const name=await cString(nameRva,'imported module name');
    // A bound image without a lookup table keeps resolved addresses in the IAT, not name RVAs.
    if(!lookup&&stamp!==0){imports.push({kind:'import',index:i,name,descriptorRva,timeDateStamp:stamp,lookupTable:'none',entries:[],addressTableRva:address,status:'bound-address-table-without-lookup-table'});continue;}
    imports.push({kind:'import',index:i,name,descriptorRva,timeDateStamp:stamp,lookupTable:lookup?'name-table':'address-table',entries:await thunks(lookup||address,address,`import ${name}`),addressTableRva:address,status:'entries-read'});
   }
  }
  const delayDirectory=directories[13];
  if(delayDirectory&&delayDirectory.rva){
   for(let i=0;;i++){
    abort();if(i>=PE_LIMITS.importModules)fail(`more than ${PE_LIMITS.importModules} delay-loaded modules or a missing terminator.`);
    const descriptorRva=delayDirectory.rva+i*32,d=await read(offsetOf(descriptorRva,32,'delay-import descriptor'),32);
    const attributes=u32(d,0),nameRva=u32(d,4),address=u32(d,12),names=u32(d,16),stamp=u32(d,28);
    if(!nameRva&&!address&&!names)break;
    // Attribute bit 0 clear is the old Visual C++ 6 layout with virtual addresses. Its module name is
    // recorded; its thunk tables are not interpreted rather than guessed.
    if(!(attributes&1)){
     if(plus)fail('64-bit delay-import descriptor uses virtual addresses.');
     const base=Number(imageBase);
     imports.push({kind:'delay-import',index:i,name:await cString(nameRva-base,'delay-loaded module name'),descriptorRva,timeDateStamp:stamp,lookupTable:'none',entries:[],addressTableRva:address-base,status:'legacy-va-descriptor-not-interpreted'});continue;
    }
    const name=await cString(nameRva,'delay-loaded module name');
    imports.push({kind:'delay-import',index:i,name,descriptorRva,timeDateStamp:stamp,lookupTable:'name-table',entries:await thunks(names,address,`delay import ${name}`),addressTableRva:address,status:'entries-read'});
   }
  }
  let exports:PeMetadata['exports']=null;const exportDirectory=directories[0];
  if(exportDirectory&&exportDirectory.rva){
   const e=await read(offsetOf(exportDirectory.rva,40,'export directory'),40);
   const nameRva=u32(e,12),base=u32(e,16),functions=u32(e,20),nameCount=u32(e,24),addresses=u32(e,28),namePointers=u32(e,32),ordinals=u32(e,36);
   if(functions>PE_LIMITS.exports||nameCount>PE_LIMITS.exports)fail(`more than ${PE_LIMITS.exports} exports.`);
   const rvas=functions?await read(offsetOf(addresses,functions*4,'export address table'),functions*4):Buffer.alloc(0);
   const pointers=nameCount?await read(offsetOf(namePointers,nameCount*4,'export name pointer table'),nameCount*4):Buffer.alloc(0);
   const nameOrdinals=nameCount?await read(offsetOf(ordinals,nameCount*2,'export ordinal table'),nameCount*2):Buffer.alloc(0);
   const names=new Map<number,string[]>();
   for(let i=0;i<nameCount;i++){
    abort();const index=u16(nameOrdinals,i*2);if(index>=functions)fail('export name refers to an ordinal outside the address table.');
    const name=await cString(u32(pointers,i*4),'export name');names.set(index,[...(names.get(index)??[]),name]);
   }
   const entries:PeExport[]=[];
   for(let i=0;i<functions;i++){
    const rva=u32(rvas,i*4);if(!rva)continue;
    const forwarded=rva>=exportDirectory.rva&&rva<exportDirectory.rva+exportDirectory.size;
    entries.push({ordinal:base+i,rva,names:(names.get(i)??[]).sort(),...(forwarded?{forwarder:await cString(rva,'export forwarder')}:{})});
   }
   exports={name:nameRva?await cString(nameRva,'export module name'):null,ordinalBase:base,timeDateStamp:u32(e,4),entries};
  }
  const clr=directories[14];
  return{format:plus?'pe32+':'pe32',machine,machineName:machines.get(machine)??'unrecognized',characteristics,dll:Boolean(characteristics&0x2000),timeDateStamp:u32(coff,8),subsystem:u16(optional,68),dllCharacteristics:u16(optional,70),
   entryRva:u32(optional,16),imageBase:'0x'+imageBase.toString(16),sizeOfImage,sizeOfHeaders,sections,dataDirectories:directories.filter(d=>d.rva||d.size),managed:Boolean(clr&&clr.rva&&clr.size),imports,exports};
 }finally{await handle.close();}
}

// Publishes a complete closed evidence file; an existing observation is never replaced.
export async function publishEvidence(evidence:string,text:string){
 const directory=path.dirname(evidence);await mkdir(directory,{recursive:true,mode:0o700});if(await realpath(directory)!==directory)throw new Error('Evidence directory follows a symlink.');
 const temporary=path.join(directory,'.'+randomUUID()+'.tmp');
 try{
  await writeFile(temporary,text,{flag:'wx',mode:0o600});
  try{await link(temporary,evidence);}catch(error){
   if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;
   const existing=await lstat(evidence);if(!existing.isFile()||existing.isSymbolicLink()||(await hashFile(evidence)).sha256!==digest(text))throw new Error('Existing evidence changed on disk. Preserve it for inspection before retrying.');
  }
 }finally{await unlink(temporary).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});}
}
export function recordObservation(db:ReturnType<typeof openIndex>,record:{id:string;file:string;sha256:string;detail:{kind:string;name:string;address:string};searchText:string;evidence:string;evidenceSha256:string}){
 db.exec(`CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
  CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
  CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
 db.exec('BEGIN');try{
  const inserted=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(record.id,record.file,record.sha256,record.detail.kind,record.detail.name,record.detail.address,record.searchText,JSON.stringify(record.detail),record.evidence,record.evidenceSha256);
  if(inserted.changes)db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(record.id,record.searchText);db.exec('COMMIT');
 }catch(error){db.exec('ROLLBACK');throw error;}
}

// API-set contracts are virtual names the OS maps to host DLLs; they are never files to look for.
const apiSet=(name:string)=>/^(api|ext)-ms-/i.test(name);
const escapeLike=(value:string)=>value.replace(/[\\%_]/g,'\\$&');
type View='summary'|'modules'|'imports'|'exports'|'sections';
export async function inspectPeLoader(workspace:string,options:{file:string;view?:View;offset?:number;limit?:number;budgetBytes?:number;signal?:AbortSignal}){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,budget=responseBudget(options.budgetBytes);
 if(!['summary','modules','imports','exports','sections'].includes(view))throw new Error('Use view summary, modules, imports, exports or sections.');
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use PE loader page limit 1–100 and a nonnegative offset.');
 const root=await realpath(workspace),target=await indexedFile(root,options.file,options.signal);
 const metadata=await readPeLoader(target.path,{signal:options.signal});
 if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while reading PE tables.');
 const provider={name:'carve-pe-loader',version:'1',parserSha256:digest(await readFile(fileURLToPath(import.meta.url)))};
 const detail={kind:'native-loader',name:`PE ${metadata.format} ${metadata.machineName} import/export tables`,address:'file:0',provider,metadata};
 const id=digest(JSON.stringify({file:options.file,sha256:target.sha256,detail}));
 const evidence=path.join(root,'loader-evidence',id+'.json'),text=JSON.stringify({schema:'carve/pe-loader-evidence@1',file:options.file,sourceSha256:target.sha256,...detail},null,2)+'\n';
 await publishEvidence(evidence,text);
 const db=openIndex(root);
 try{
  recordObservation(db,{id,file:options.file,sha256:target.sha256,detail,searchText:JSON.stringify({format:metadata.format,machine:metadata.machineName,modules:metadata.imports.map(m=>m.name),exports:metadata.exports?.entries.flatMap(e=>e.names).slice(0,2000)??[]}),evidence,evidenceSha256:digest(text)});
  const epoch=metaValue(db,'epoch');
  const candidates=db.prepare("SELECT path,sha256,format FROM files WHERE seen=? AND error IS NULL AND sha256 IS NOT NULL AND (lower(path)=lower(?) OR lower(path) LIKE ? ESCAPE '\\') ORDER BY path LIMIT 9");
  const exportsTotal=metadata.exports?.entries.length??0,importsTotal=metadata.imports.reduce((n,m)=>n+m.entries.length,0);
  const base={schema:'carve/pe-loader@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),
   status:'pe-tables-inspected',format:metadata.format,machine:metadata.machineName,dll:metadata.dll,managed:metadata.managed,subsystem:metadata.subsystem,entryRva:metadata.entryRva,imageBase:metadata.imageBase,
   counts:{sections:metadata.sections.length,modules:metadata.imports.filter(m=>m.kind==='import').length,delayModules:metadata.imports.filter(m=>m.kind==='delay-import').length,imports:importsTotal,exports:exportsTotal,forwarders:metadata.exports?.entries.filter(e=>e.forwarder).length??0},
   exportName:metadata.exports?.name??null,view,
   scope:'Declared PE import, delay-import and export tables of this file. Module candidates are inventory files with the same base name (case-insensitive); Windows search order, KnownDLLs, side-by-side manifests, API-set mapping, binding, ABI and runtime loading are not evaluated. Managed (.NET) images list only their native stub imports. Loader evidence is boundary support, never implementation-code evidence.'};
  let rows:{value:unknown}[];
  if(view==='summary')rows=[];
  else if(view==='modules')rows=metadata.imports.map(m=>{
   const found=apiSet(m.name)?[]:candidates.all(epoch,m.name,'%/'+escapeLike(m.name.toLowerCase())) as {path:string;sha256:string;format:string}[];
   return{value:{kind:m.kind,name:m.name,entries:m.entries.length,status:m.status,addressTableRva:m.addressTableRva,
    resolution:apiSet(m.name)?'api-set-contract':found.length?'inventory-basename-candidates':'not-in-inventory',
    candidates:found.slice(0,8).map(c=>({file:c.path,sourceSha256:c.sha256,format:c.format,freshBytesChecked:false})),candidatesTruncated:found.length>8,semanticMatch:'unconfirmed',runtimeLoading:'unverified'}};
  });
  else if(view==='imports')rows=metadata.imports.flatMap(m=>m.entries.map(e=>({value:{module:m.name,kind:m.kind,...e}})));
  else if(view==='exports')rows=(metadata.exports?.entries??[]).map(e=>({value:e}));
  else rows=metadata.sections.map(s=>({value:s}));
  if(view!=='summary'&&rows.length&&offset>=rows.length)throw new Error(`Use an offset below ${rows.length} for view ${view}.`);
  return budgetItems({...base,total:rows.length,offset},rows.slice(offset,offset+limit),budget);
 }finally{db.close();}
}
