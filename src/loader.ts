import {open,realpath,mkdir,readFile,writeFile,link,unlink,lstat} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import type {FileHandle} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';

// Layouts and constants: Apple SDK mach-o/{loader,fat}.h. This is a header
// reader, not a dyld simulator or an export/bind-opcode parser.
const MAX_COMMAND_BYTES=8*1024*1024,MAX_COMMANDS=4096,MAX_SLICES=64;
type Slice={index:number;offset:number;bytes:number;cpuType:number;cpuSubtype:number};
type Command={index:number;fileOffset:number;command:number;commandName:string;commandBytes:number;name:string;currentVersion?:number;compatibilityVersion?:number;useFlags?:number};
type Metadata={container:'thin'|'fat';slices:Slice[];slice:Slice;bits:32|64;endian:'little'|'big';fileType:number;flags:number;commandCount:number;commandBytes:number;dependencies:Command[];installNames:Command[];rpaths:Command[];dyldEnvironment:Command[];otherCommands:{index:number;command:number;fileOffset:number;commandBytes:number}[]};
const commands=new Map([[0xc,'LC_LOAD_DYLIB'],[0xd,'LC_ID_DYLIB'],[0x80000018,'LC_LOAD_WEAK_DYLIB'],[0x8000001f,'LC_REEXPORT_DYLIB'],[0x20,'LC_LAZY_LOAD_DYLIB'],[0x80000023,'LC_LOAD_UPWARD_DYLIB']]);
const thin=new Map([[0xfeedface,{bits:32 as const,little:false}],[0xcefaedfe,{bits:32 as const,little:true}],[0xfeedfacf,{bits:64 as const,little:false}],[0xcffaedfe,{bits:64 as const,little:true}]]);
async function bytesAt(handle:FileHandle,position:number,length:number,size:number){
 if(!Number.isSafeInteger(position)||!Number.isSafeInteger(length)||position<0||length<0||position>size-length||length>MAX_COMMAND_BYTES)throw new Error('Mach-O header range exceeds the file or metadata budget.');
 const data=Buffer.alloc(length);let got=0;while(got<length){const r=await handle.read(data,got,length-got,position+got);if(!r.bytesRead)throw new Error('Truncated Mach-O header.');got+=r.bytesRead;}return data;
}
const integer=(value:bigint)=>{if(value>BigInt(Number.MAX_SAFE_INTEGER))throw new Error('Mach-O slice offset/size exceeds safe file addressing.');return Number(value);};
export async function readMachOLoader(file:string,selected?:number):Promise<Metadata>{
 if(selected!==undefined&&(!Number.isInteger(selected)||selected<0||selected>=MAX_SLICES))throw new Error('Use a Mach-O slice index0–63.');
 const handle=await open(file,'r');
 try{
  const stat=await handle.stat();if(!stat.isFile()||!Number.isSafeInteger(stat.size))throw new Error('Choose a regular Mach-O file with a safely addressable size.');
  const first=await bytesAt(handle,0,8,stat.size),magic=first.readUInt32BE(0);let slices:Slice[],container:'thin'|'fat'='thin';
  if(thin.has(magic)){
   const h=await bytesAt(handle,0,12,stat.size),le=thin.get(magic)!.little;
   slices=[{index:0,offset:0,bytes:stat.size,cpuType:le?h.readUInt32LE(4):h.readUInt32BE(4),cpuSubtype:le?h.readUInt32LE(8):h.readUInt32BE(8)}];
  }else if([0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca].includes(magic)){
   container='fat';const little=magic===0xbebafeca||magic===0xbfbafeca,is64=magic===0xcafebabf||magic===0xbfbafeca,width=is64?32:20;
   const u32=(b:Buffer,p:number)=>little?b.readUInt32LE(p):b.readUInt32BE(p),count=u32(first,4);
   if(count<1||count>MAX_SLICES)throw new Error('Mach-O fat header requires1–64 slices.');
   const table=await bytesAt(handle,8,count*width,stat.size);slices=[];
   for(let i=0;i<count;i++){
    const p=i*width,offset=is64?integer(little?table.readBigUInt64LE(p+8):table.readBigUInt64BE(p+8)):u32(table,p+8),size=is64?integer(little?table.readBigUInt64LE(p+16):table.readBigUInt64BE(p+16)):u32(table,p+12),align=u32(table,p+(is64?24:16));
    if(align>52||offset%(2**align)!==0||offset<8+table.length||size<28||offset>stat.size-size||is64&&u32(table,p+28)!==0)throw new Error('Invalid Mach-O fat slice range/alignment/reserved field.');
    slices.push({index:i,offset,bytes:size,cpuType:u32(table,p),cpuSubtype:u32(table,p+4)});
   }
   const ordered=[...slices].sort((a,b)=>a.offset-b.offset);for(let i=1;i<ordered.length;i++)if(ordered[i]!.offset<ordered[i-1]!.offset+ordered[i-1]!.bytes)throw new Error('Overlapping Mach-O fat slices.');
   if(selected===undefined&&slices.length!==1)throw new Error('Choose --slice / slice explicitly for a universal Mach-O: '+JSON.stringify(slices));
  }else throw new Error('Loader inspection currently supports thin/universal Mach-O only. Other formats remain unsupported.');
  const slice=slices[selected??0];if(!slice)throw new Error('Selected Mach-O slice is absent.');
  const signature=await bytesAt(handle,slice.offset,4,stat.size),layout=thin.get(signature.readUInt32BE(0));if(!layout)throw new Error('Selected fat slice is not a supported thin Mach-O.');
  const headerBytes=layout.bits===64?32:28;if(slice.bytes<headerBytes)throw new Error('Truncated Mach-O slice header.');
  const header=await bytesAt(handle,slice.offset,headerBytes,stat.size),u32=(b:Buffer,p:number)=>layout.little?b.readUInt32LE(p):b.readUInt32BE(p);
  if(u32(header,4)!==slice.cpuType||u32(header,8)!==slice.cpuSubtype)throw new Error('Fat/thin Mach-O CPU identities disagree.');
  const count=u32(header,16),size=u32(header,20);
  if(count>MAX_COMMANDS||size>MAX_COMMAND_BYTES||size>slice.bytes-headerBytes||count*8>size)throw new Error('Mach-O load commands exceed the slice or4096-command/8MiB budget.');
  const data=await bytesAt(handle,slice.offset+headerBytes,size,stat.size);
  const result:Metadata={container,slices,slice,bits:layout.bits,endian:layout.little?'little':'big',fileType:u32(header,12),flags:u32(header,24),commandCount:count,commandBytes:size,dependencies:[],installNames:[],rpaths:[],dyldEnvironment:[],otherCommands:[]};let p=0;
  for(let index=0;index<count;index++){
   if(p>size-8)throw new Error('Truncated Mach-O load command.');const command=u32(data,p),length=u32(data,p+4);
   if(length<8||length%(layout.bits===64?8:4)!==0||length>size-p)throw new Error('Invalid Mach-O load-command size/alignment.');
   const commandName=commands.get(command),isString=command===0x8000001c||command===0x27;
   if(commandName||isString){
    const minimum=commandName?24:12;if(length<minimum)throw new Error('Truncated Mach-O library/path command.');
    const use=Boolean(commandName&&[0xc,0x80000018].includes(command)&&u32(data,p+12)===0x1a741800);
    const stringOffset=u32(data,p+8);if(stringOffset<(use?28:minimum)||stringOffset>=length||use&&stringOffset!==28)throw new Error('Invalid Mach-O command string offset.');
    const end=data.indexOf(0,p+stringOffset);if(end<0||end>=p+length||end-p-stringOffset>4096)throw new Error('Mach-O command string is unterminated or exceeds4096 bytes.');
    const name=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(data.subarray(p+stringOffset,end));if(!name)throw new Error('Empty Mach-O library/path command.');
    const item:Command={index,fileOffset:slice.offset+headerBytes+p,command,commandName:commandName??(command===0x27?'LC_DYLD_ENVIRONMENT':'LC_RPATH'),commandBytes:length,name,...(commandName?{currentVersion:u32(data,p+16),compatibilityVersion:u32(data,p+20),...(use?{useFlags:u32(data,p+24)}:{})}:{})};
    (command===0xd?result.installNames:command===0x8000001c?result.rpaths:command===0x27?result.dyldEnvironment:result.dependencies).push(item);
   }else result.otherCommands.push({index,command,fileOffset:slice.offset+headerBytes+p,commandBytes:length});
   p+=length;
  }
  if(p!==size)throw new Error('Mach-O command count and declared command bytes disagree.');
  return result;
 }finally{await handle.close();}
}

// Expand only paths whose bases are present in this selected image. Never read
// an external path, infer an inherited runpath stack, or pick the first match.
function expand(name:string,loaderDirectory:string,executableDirectory:string|undefined){
 if(process.platform==='win32')return null;
 for(const [prefix,base] of [['@loader_path',loaderDirectory],['@executable_path',executableDirectory]] as const){if(name===prefix||name.startsWith(prefix+'/'))return base?path.resolve(base,'.'+name.slice(prefix.length)):null;}
 return path.isAbsolute(name)?path.normalize(name):null;
}
export async function inspectLoader(workspace:string,options:{file:string;slice?:number;limit?:number;offset?:number;signal?:AbortSignal}){
 const limit=options.limit??20,offset=options.offset??0;
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use loader page limit1–100 and a nonnegative offset.');
 const root=await realpath(workspace),target=await indexedFile(root,options.file,options.signal);
 const metadata=await readMachOLoader(target.path,options.slice);
 if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while reading loader commands.');
 const parserSha256=digest(await readFile(fileURLToPath(import.meta.url))),provider={name:'carve-mach-o-loader',version:'1',parserSha256};
 const detail={kind:'native-loader',name:'Mach-O loader commands (slice'+metadata.slice.index+')',address:'file:'+metadata.slice.offset,provider,metadata};
 const id=digest(JSON.stringify({file:options.file,sha256:target.sha256,detail}));
 const evidence=path.join(root,'loader-evidence',id+'.json'),text=JSON.stringify({schema:'carve/mach-o-loader-evidence@1',file:options.file,sourceSha256:target.sha256,...detail},null,2)+'\n';
 const directory=path.dirname(evidence);await mkdir(directory,{recursive:true,mode:0o700});if(await realpath(directory)!==directory)throw new Error('Loader evidence directory follows a symlink.');
 const temporary=path.join(directory,'.'+randomUUID()+'.tmp');
 try{
  await writeFile(temporary,text,{flag:'wx',mode:0o600});
  // Publish a complete closed file without replacing an immutable observation.
  // Concurrent readers must never hash another writer's partially written file.
  try{await link(temporary,evidence);}catch(error){
   if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;
   const existing=await lstat(evidence);if(!existing.isFile()||existing.isSymbolicLink()||(await hashFile(evidence)).sha256!==digest(text))throw new Error('Existing loader evidence changed on disk. Preserve it for inspection before retrying.');
  }
 }finally{await unlink(temporary).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});}
 const db=openIndex(root);
 try{
  db.exec(`CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
   CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
   CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
  const inventoryRoot=JSON.parse((db.prepare("SELECT value FROM meta WHERE key='root'").get() as any).value) as string;
  const epoch=JSON.parse((db.prepare("SELECT value FROM meta WHERE key='epoch'").get() as any).value) as string;
  const lookup=db.prepare('SELECT path,sha256,format FROM files WHERE path=? AND seen=? AND error IS NULL AND sha256 IS NOT NULL');
  const directory=path.dirname(path.resolve(inventoryRoot,options.file)),executable=metadata.fileType===2?directory:undefined;let budget=256;
  const dependencies=metadata.dependencies.slice(offset,offset+limit).map(item=>{
   const rpath=item.name.startsWith('@rpath/');const bases=rpath?metadata.rpaths:[null];const paths=[];let inspected=0;
   for(const base of bases){
    if(inspected>=32||budget===0)break;inspected++;budget--;
    const expandedBase=base?expand(base.name,directory,executable):null;
    const expandedPath=rpath?(expandedBase?path.resolve(expandedBase,'./'+item.name.slice(7)):null):expand(item.name,directory,executable);
    const relative=expandedPath?path.relative(inventoryRoot,expandedPath):null;
    const inside=relative!==null&&relative!==''&&relative!=='..'&&!relative.startsWith('..'+path.sep)&&!path.isAbsolute(relative);
    const indexed=inside?lookup.get(relative!,epoch) as {path:string;sha256:string;format:string}|undefined:undefined;
    paths.push({rpathCommandIndex:base?.index??null,expandedPath,inventoryPath:inside?relative:null,status:!expandedPath?'unresolved-path-context':!inside?'outside-inventory':indexed?'indexed-path-candidate':'not-indexed',...(indexed?{candidate:{file:indexed.path,sourceSha256:indexed.sha256,format:indexed.format,freshBytesChecked:false}}:{})});
   }
   return{...item,paths,pathExpansionStatus:rpath&&bases.length===0?'no-local-rpaths':inspected<bases.length?'bounded-partial':'selected-image-only',pathsTruncated:inspected<bases.length,semanticMatch:'unconfirmed',runtimeLoading:'unverified'};
  });
  db.exec('BEGIN');try{
   const inserted=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,options.file,target.sha256,detail.kind,detail.name,detail.address,JSON.stringify(metadata,null,2),JSON.stringify(detail),evidence,digest(text));
   if(inserted.changes)db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(id,JSON.stringify(metadata));db.exec('COMMIT');
  }catch(error){db.exec('ROLLBACK');throw error;}
  return{schema:'carve/loader@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),status:'loader-commands-inspected',container:metadata.container,slices:metadata.slices,selectedSlice:metadata.slice,bits:metadata.bits,endian:metadata.endian,fileType:metadata.fileType,flags:metadata.flags,commandCount:metadata.commandCount,commandBytes:metadata.commandBytes,rpaths:metadata.rpaths,installNames:metadata.installNames,dyldEnvironment:metadata.dyldEnvironment,total:metadata.dependencies.length,offset,limit,dependencies,nextOffset:offset+dependencies.length<metadata.dependencies.length?offset+dependencies.length:null,
   scope:'Exact selected Mach-O slice load commands and bounded lexical path expansions in this inventory. No target execution, external-path reads, symlink/case resolution, environment overrides, inherited runpath stack, shared-cache search, symbol binding, ABI compatibility or runtime-load proof. Candidate bytes are inventory records only; rehash selected artifacts before reconstruction. Other commands are recorded by type/range without interpreting their payload. Loader evidence is boundary support, never implementation-code evidence.'};
 }finally{db.close();}
}
