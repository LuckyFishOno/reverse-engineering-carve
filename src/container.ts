import path from 'node:path';
import { mkdir, readFile, writeFile, cp, lstat, rm, realpath, link, unlink } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { crc32 } from 'node:zlib';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import yauzl, { type Entry, type ZipFile } from 'yauzl';
import { indexedFile, hashFile, claim } from './survey.js';

export function memberPath(name:string){
  const relative=name.endsWith('/')?name.slice(0,-1):name;
  if(!relative||relative.length>4096||/[\\\0:]/.test(relative)||relative.startsWith('/')||relative.split('/').some(s=>!s||s==='.'||s==='..'))throw new Error('Unsafe archive member path: '+JSON.stringify(name));
  return relative;
}
function nextEntry(zip:ZipFile){return new Promise<Entry|null>((resolve,reject)=>{
  const cleanup=()=>{zip.off('entry',entry);zip.off('end',end);zip.off('error',error);};
  const entry=(value:Entry)=>{cleanup();resolve(value);};const end=()=>{cleanup();resolve(null);};const error=(e:Error)=>{cleanup();reject(e);};
  zip.once('entry',entry);zip.once('end',end);zip.once('error',error);zip.readEntry();
});}

/** Bounded, one-member-at-a-time extraction. Never executes archive contents. */
export async function unpackContainer(workspace:string,options:{file:string;maxFiles?:number;maxEntries?:number;maxBytes?:number;maxFileBytes?:number;signal?:AbortSignal}){
  const maxFiles=options.maxFiles??1000,maxEntries=options.maxEntries??100000,maxBytes=options.maxBytes??4*1024**3,maxFileBytes=options.maxFileBytes??1024**3;
  for(const [name,value,upper] of [['maxFiles',maxFiles,1000000],['maxEntries',maxEntries,1000000],['maxBytes',maxBytes,1024**4],['maxFileBytes',maxFileBytes,1024**4]] as const)if(!Number.isSafeInteger(value)||value<1||value>upper)throw new Error(`${name} must be 1–${upper}.`);
  const root=await realpath(workspace);const source=await indexedFile(root,options.file);
  if(!['zip','apk','aab','aar','jar','ipa'].includes(source.facts.format))throw new Error('Select a ZIP-family indexed container. ASAR uses the JavaScript backend.');
  if(source.bytes>maxBytes)throw new Error('Archive input exceeds maxBytes; increase the explicit byte budget if appropriate.');
  const parent=path.join(root,'containers',source.sha256);await mkdir(parent,{recursive:true,mode:0o700});
  const release=await claim(parent,'.unpack.lock');let db:DatabaseSync|undefined;let zip:ZipFile|undefined;
  const content=path.join(parent,'content');const parts=path.join(parent,'parts');const snapshot=path.join(parent,'input.zip');
  try{
    const marker=path.join(parent,'.carve-container.json');
    try{const previous=JSON.parse(await readFile(marker,'utf8'));if(previous.schema!=='carve/container@1'||previous.original.sha256!==source.sha256||previous.content!==content)throw new Error('Container cache identity mismatch.');}
    catch(error){
      if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
      const {readdir}=await import('node:fs/promises');if((await readdir(parent)).some(n=>n!=='.unpack.lock'))throw new Error('Unrecognized container cache contents are preserved; choose another workspace.');
      await writeFile(marker,JSON.stringify({schema:'carve/container@1',workspace:root,original:{file:options.file,sha256:source.sha256,bytes:source.bytes},content},null,2),{flag:'wx'});
    }
    try{await lstat(snapshot);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;await cp(source.path,snapshot);}
    if((await hashFile(snapshot)).sha256!==source.sha256)throw new Error('Container snapshot bytes changed. Discard this owned cache and retry.');
    await mkdir(content,{recursive:true,mode:0o700});await rm(parts,{recursive:true,force:true});await mkdir(parts,{mode:0o700});
    db=new DatabaseSync(path.join(parent,'members.sqlite'));db.exec('PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS members(path TEXT PRIMARY KEY,ordinal INTEGER,kind TEXT,bytes REAL,sha256 TEXT,crc32 INTEGER,mtime REAL,ctime REAL,device REAL,inode REAL);');
    if(!(db.prepare('PRAGMA table_info(members)').all() as any[]).some(c=>c.name==='device'))db.exec('ALTER TABLE members ADD COLUMN device REAL;ALTER TABLE members ADD COLUMN inode REAL;');
    db.exec('CREATE INDEX IF NOT EXISTS member_physical ON members(device,inode);');
    const recorded=db.prepare('SELECT * FROM members WHERE path=?');const save=db.prepare('INSERT INTO members VALUES(?,?,?,?,?,?,?,?,?,?)');
    let totalBytes=Number((db.prepare('SELECT coalesce(sum(bytes),0) n FROM members').get() as any).n);if(totalBytes>maxBytes)throw new Error('Completed members exceed the current total byte budget.');let processed=0,cached=0,ordinal=0;let complete=false;let archiveError:Error|undefined;
    let active:NodeJS.ReadableStream|undefined;
    zip=await yauzl.openPromise(snapshot,{lazyEntries:true,autoClose:false,strictFileNames:true,validateEntrySizes:true});
    // Keep a listener during payload reads as well as central-directory reads.
    zip.on('error',(error:Error)=>{archiveError=error;(active as any)?.destroy(error);});
    while(processed<maxFiles){
      if(options.signal?.aborted)throw new Error('Container extraction cancelled.');if(archiveError)throw archiveError;
      const entry=await nextEntry(zip);if(!entry){complete=true;break;}ordinal++;
      if(ordinal>maxEntries)throw new Error('Container exceeds maxEntries; no complete extraction is claimed.');
      const relative=memberPath(entry.fileName);const output=path.join(content,relative);
      const mode=(entry.externalFileAttributes>>>16)&0xffff;const type=mode&0xf000;
      if(type&&![0x8000,0x4000].includes(type))throw new Error('Archive symlinks and special files are refused: '+relative);
      if(entry.generalPurposeBitFlag&1)throw new Error('Encrypted archive member needs an authorized unencrypted input.');
      const directory=entry.fileName.endsWith('/');if(type===0x4000&&!directory)throw new Error('Directory member has an inconsistent path.');
      if(!directory&&(!Number.isSafeInteger(entry.uncompressedSize)||entry.uncompressedSize<0||entry.uncompressedSize>maxFileBytes))throw new Error('Container member exceeds explicit file/total byte budgets: '+relative);
      const previous=recorded.get(relative) as any;
      if(previous){
        if(previous.ordinal!==ordinal)throw new Error('Duplicate archive member path: '+relative);
        const info=await lstat(output);if(info.isSymbolicLink()||directory!==info.isDirectory())throw new Error('Cached archive member changed type.');
        if(!directory&&(info.size!==previous.bytes||info.mtimeMs!==previous.mtime||info.ctimeMs!==previous.ctime)){
          if((await hashFile(output)).sha256!==previous.sha256)throw new Error('Cached extracted member bytes changed: '+relative);
          db.prepare('UPDATE members SET mtime=?,ctime=?,device=?,inode=? WHERE path=?').run(info.mtimeMs,info.ctimeMs,info.dev,info.ino,relative);
        }
        cached++;continue;
      }
      if(directory){await mkdir(output,{recursive:true,mode:0o700});save.run(relative,ordinal,'directory',0,null,null,null,null,null,null);continue;}
      if(!Number.isSafeInteger(entry.uncompressedSize)||entry.uncompressedSize<0||entry.uncompressedSize>maxFileBytes||totalBytes+entry.uncompressedSize>maxBytes)throw new Error('Container member exceeds explicit file/total byte budgets: '+relative);
      if(![0,8].includes(entry.compressionMethod))throw new Error('Unsupported ZIP compression method: '+entry.compressionMethod);
      await mkdir(path.dirname(output),{recursive:true,mode:0o700});
      const partial=path.join(parts,`${ordinal}.part`);let bytes=0,checksum=0;const hash=createHash('sha256');
      const meter=new Transform({transform(chunk:Buffer,_encoding,callback){bytes+=chunk.length;if(bytes>entry.uncompressedSize||bytes>maxFileBytes||totalBytes+bytes>maxBytes)return callback(new Error('Archive member exceeded its declared byte budget.'));hash.update(chunk);checksum=crc32(chunk,checksum);callback(null,chunk);}});
      const input=await zip.openReadStreamPromise(entry);active=input;
      try{
        await pipeline(input,meter,createWriteStream(partial,{flags:'wx',mode:0o600}),{signal:options.signal});
        if(archiveError)throw archiveError;
        if(bytes!==entry.uncompressedSize||(checksum>>>0)!==(entry.crc32>>>0))throw new Error('Archive member length/CRC32 mismatch: '+relative);
        // link is exclusive even on case-insensitive filesystems; do not overwrite collisions.
        const sha256=hash.digest('hex');
        try{await link(partial,output);}catch(error){
          // Recover the crash window between an exclusive file link and its DB row.
          if((error as NodeJS.ErrnoException).code!=='EEXIST'||(await lstat(output)).isSymbolicLink()||(await hashFile(output)).sha256!==sha256)throw error;
          const existing=await lstat(output);
          if(db.prepare('SELECT path FROM members WHERE device=? AND inode=? LIMIT 1').get(existing.dev,existing.ino))throw new Error('Archive member paths collide on this filesystem: '+relative);
        }
        await unlink(partial);const info=await lstat(output);
        save.run(relative,ordinal,'file',bytes,sha256,checksum>>>0,info.mtimeMs,info.ctimeMs,info.dev,info.ino);totalBytes+=bytes;processed++;
      }finally{active=undefined;await rm(partial,{force:true});}
    }
    await indexedFile(root,options.file);
    const files=Number((db.prepare("SELECT count(*) n FROM members WHERE kind='file'").get() as any).n);
    const report={schema:'carve/container-extraction@1',status:complete?'unpacked':'unpacking',workspace:root,original:{file:options.file,sha256:source.sha256,bytes:source.bytes},content,memberIndex:path.join(parent,'members.sqlite'),files,bytes:totalBytes,batch:{processed,cached},executesTarget:false,
      limits:{maxFiles,maxEntries,maxBytes,maxFileBytes},nextAction:complete?'Run reverse/survey on content in a new workspace to index member binaries.':'Repeat this unpack call to resume; completed members are preserved.',
      limitations:['ZIP family only; nested archives are not recursively expanded.','Symlinks/special files/encrypted members are refused. Members are stored without executable permission.','Completed members use metadata caching on resume; analysis rehashes selected bytes. Private workspace contents must not be modified concurrently.','An extracted IPA is not decrypted iOS code. Missing server logic and target behavior remain unverified.']};
    await writeFile(path.join(parent,'result.json'),JSON.stringify(report,null,2)+'\n');return report;
  }catch(error){await writeFile(path.join(parent,'failure.json'),JSON.stringify({status:'failed',message:(error as Error).message,originalSha256:source.sha256},null,2)+'\n');throw error;}
  finally{zip?.close();db?.close();await release();}
}
