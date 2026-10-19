import path from 'node:path';
import {constants} from 'node:fs';
import {open,realpath,mkdir,lstat,writeFile,link,unlink} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {digest} from './artifact.js';
import {assertWorkspaceInPlace,claim,indexedFile,metaValue,openIndex} from './survey.js';
import {assertReaNativeObservation} from './rea-native.js';
import {readMachOLoader} from './loader.js';
import {readMachOSymbol} from './macho-symbols.js';

const id=z.string().regex(/^[a-f0-9]{64}$/),address=z.string().regex(/^0x[0-9a-f]{1,16}$/),MAX=256*1024;
const relativeWorkspace=z.string().min(1).max(4096).refine(s=>s!=='.'&&!s.includes('\\')&&!s.includes('\0')&&!path.posix.isAbsolute(s)&&!/^[A-Za-z]:/.test(s)&&path.posix.normalize(s)===s,'Use a normalized relative workspace path.');
const snapshotSchema=z.discriminatedUnion('schema',[
 z.object({schema:z.literal('carve/rea-bridge@1'),from:id,to:id,stub:address,witness:z.unknown()}).strict(),
 z.object({schema:z.literal('carve/rea-bridge@2'),from:id,to:id,stub:address,toWorkspace:relativeWorkspace,witness:z.unknown()}).strict()
]);
export type BridgePathAccess=(file:string,newPath?:boolean)=>Promise<unknown>;
type Access=BridgePathAccess;
type WorkspaceAccess=(workspace:string)=>Promise<string>;
type Row=Record<string,any>;
const identity=(file:string,sha256:string,evidenceSha256:string,schema='carve/rea-bridge@1')=>digest(JSON.stringify({schema,file,sourceSha256:sha256,evidenceSha256}));
export function isReaBridgeObservation(row:Row,detail:Row){return Boolean(['carve/rea-bridge@1','carve/rea-bridge@2'].includes(detail.bridge?.schema)||detail.provider?.name==='carve-rea-bridge'||path.basename(path.dirname(row.evidence))==='rea-bridge-evidence'||row.id===identity(row.artifact,row.sha256,row.evidence_sha256)||row.id===identity(row.artifact,row.sha256,row.evidence_sha256,'carve/rea-bridge@2'));}

async function workspaceRoot(input:string,access?:Access,authorizeWorkspace?:WorkspaceAccess){
 await access?.(input);const root=await realpath(input);
 for(const name of ['.carve-workspace.json','index.sqlite','index.sqlite-wal','index.sqlite-shm'])await access?.(path.join(root,name),name.endsWith('-wal')||name.endsWith('-shm'));
 if(authorizeWorkspace&&await realpath(await authorizeWorkspace(root))!==root)throw new Error('Workspace authorization must preserve the selected workspace identity.');
 await assertWorkspaceInPlace(root);return root;
}

async function endpoint(root:string,id:string,access?:Access){
 const db=openIndex(root,true);
 try{
  if(!db.prepare("SELECT name FROM sqlite_master WHERE name='observations'").get())throw new Error('Import complete REA caller/callee observations first.');
  const row=db.prepare('SELECT * FROM observations WHERE id=?').get(id) as Row|undefined,sourceRoot=metaValue(db,'root') as string;
  if(!row||row.kind!=='function')throw new Error('Choose complete REA function IDs from their explicitly selected workspaces.');
  if(typeof row.artifact!=='string'||path.isAbsolute(row.artifact)||row.artifact.split(/[\\/]/).includes('..'))throw new Error('Bridge artifacts must be indexed relative files.');
  await access?.(path.resolve(sourceRoot,row.artifact));await access?.(row.evidence);return{row,sourceRoot};
 }finally{db.close();}
}

async function readSnapshot(file:string){
 const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const a=await h.stat();if(!a.isFile()||a.size>MAX)throw new Error('REA bridge snapshot exceeds256KiB or is not a regular file.');const b=Buffer.alloc(a.size+1);let total=0;for(;;){const r=await h.read(b,total,b.length-total);if(!r.bytesRead)break;total+=r.bytesRead;if(total>a.size)throw new Error('REA bridge snapshot changed while reading.');}const after=await h.stat();if(total!==a.size||a.size!==after.size||a.mtimeMs!==after.mtimeMs||a.ctimeMs!==after.ctimeMs)throw new Error('REA bridge snapshot changed while reading.');return b.subarray(0,total);}finally{await h.close();}
}

async function witness(root:string,toRoot:string,from:string,to:string,stub:string,signal?:AbortSignal,access?:Access){
 signal?.throwIfAborted();const {row:source,sourceRoot}=await endpoint(root,from,access),{row:target,sourceRoot:targetRoot}=await endpoint(toRoot,to,access);
 const a=await indexedFile(root,source.artifact,signal),b=await indexedFile(toRoot,target.artifact,signal);
 if(a.path===b.path)throw new Error('Choose two different actual source images, not two indexes of the same file.');
 for(const selected of [a,b])if(selected.facts.format!=='mach-o'||selected.facts.encrypted||selected.facts.family!=='native')throw new Error('Bridge currently supports unencrypted thin Mach-O native images only.');
 if(source.sha256!==a.sha256||target.sha256!==b.sha256)throw new Error('REA bridge endpoints belong to stale source revisions.');
 await assertReaNativeObservation(source,a);await assertReaNativeObservation(target,b);
 const caller=JSON.parse(source.detail),callee=JSON.parse(target.detail),call=caller.callees?.find((c:Row)=>c.address===stub);
 if(caller.provider?.name!=='rea'||callee.provider?.name!=='rea'||!isDeepStrictEqual(caller.provider.analysisProvider,callee.provider.analysisProvider)||callee.thunk)throw new Error('Choose complete REA endpoints from the same underlying analysis provider; target must be a defined non-thunk function.');
 if(caller.relationshipScope!=='rea-ghidra-outgoing@1'||!caller.relationshipEvidence?.referencesEvidenceId||!call?.thunk||!call.callSites?.length)throw new Error('Caller needs imported typed outgoing references with a direct call to the selected thunk.');
 const imported=await readMachOSymbol(a.path,{stub,callSites:call.callSites.map((s:Row)=>s.address)}),exported=await readMachOSymbol(b.path,{export:imported.symbol.name});
 if(imported.kind!=='import-stub'||exported.kind!=='defined-export'||imported.fileType!==2||exported.fileType!==6||!(imported.flags&0x80)||(imported.flags&0x100)||imported.cpu!==exported.cpu||imported.subtype!==exported.subtype)throw new Error('Bridge needs a matching executable/dylib CPU pair and two-level namespace without forced flat binding.');
 if(exported.symbol.value!==target.address||call.name!==imported.symbol.name||target.name!==exported.symbol.name)throw new Error('Raw import/export symbols do not match the selected REA thunk and target entry.');
 const loader=await readMachOLoader(a.path),library=await readMachOLoader(b.path),dependency=loader.dependencies[imported.libraryOrdinal-1];
 if(!dependency||dependency.command!==0xc||dependency.useFlags||loader.dyldEnvironment.length||loader.container!=='thin'||library.container!=='thin')throw new Error('Only direct strong LC_LOAD_DYLIB with an ordinary positive library ordinal is supported.');
 if(library.installNames.length!==1||library.installNames[0]!.name!==dependency.name)throw new Error('Target install name differs from the exact ordinal-selected dependency.');
 const directory=path.dirname(path.resolve(sourceRoot,source.artifact));
 const expand=(name:string)=>{for(const prefix of ['@loader_path','@executable_path'])if(name===prefix||name.startsWith(prefix+'/'))return path.resolve(directory,'.'+name.slice(prefix.length));return path.isAbsolute(name)?path.normalize(name):null;};
 let candidate:string|null;
 if(dependency.name.startsWith('@rpath/')){if(loader.rpaths.length!==1)throw new Error('Multiple/missing local rpaths remain ambiguous; this bridge does not simulate dyld resolution.');const base=expand(loader.rpaths[0]!.name);candidate=base?path.resolve(base,'./'+dependency.name.slice(7)):null;}else candidate=expand(dependency.name);
 if(!candidate||candidate!==path.resolve(targetRoot,target.artifact)||await realpath(candidate)!==b.path)throw new Error('Selected target is not the exact local lexical load-path candidate; same-name library alternatives stay unconfirmed.');
 const cross=root!==toRoot,toWorkspace=path.relative(root,toRoot).split(path.sep).join('/');
 const result={policy:'mach-o-two-level-direct-stub@1',from:{...(cross?{workspace:'.'}:{}),id:from,file:source.artifact,sha256:a.sha256,address:source.address,evidenceSha256:source.evidence_sha256},to:{...(cross?{workspace:toWorkspace}:{}),id:to,file:target.artifact,sha256:b.sha256,address:target.address,evidenceSha256:target.evidence_sha256},import:imported,export:exported,
  dependency:{ordinal:imported.libraryOrdinal,index:dependency.index,command:dependency.commandName,name:dependency.name,fileOffset:dependency.fileOffset,rpath:loader.rpaths.map(r=>({index:r.index,name:r.name,fileOffset:r.fileOffset})),candidateFile:target.artifact,targetInstallName:library.installNames[0]!.name},recordedCallSites:call.callSiteCount,callSitesTruncated:call.callSitesTruncated,
  runtimeLoading:'unverified',dependencyClosure:'not-established',semanticMatch:'unconfirmed'};
 for(const [workspace,row,selected] of [[root,source,a],[toRoot,target,b]] as const){
  if((await indexedFile(workspace,row.artifact,signal)).sha256!==selected.sha256||!isDeepStrictEqual((await endpoint(workspace,row.id,access)).row,row))throw new Error('Bridge source or endpoint record changed during inspection.');
  await assertReaNativeObservation(row,selected);
 }
 signal?.throwIfAborted();return result;
}

function normalized(s:z.infer<typeof snapshotSchema>){
 const w=s.witness as Awaited<ReturnType<typeof witness>>,detail={kind:'native-bridge',name:'REA static import: '+w.import.symbol.name,address:s.stub,provider:{name:'carve-rea-bridge',policy:'mach-o-two-level-direct-stub@1'},bridge:{schema:s.schema,from:s.from,to:s.to,stub:s.stub,...(s.schema==='carve/rea-bridge@2'?{toWorkspace:s.toWorkspace}:{}),witness:w}};
 return{detail,content:JSON.stringify(detail)};
}

export async function bridgeReaNative(workspace:string,options:{from:string;to:string;stub:string;toWorkspace?:string;signal?:AbortSignal;authorizePath?:Access;authorizeWorkspace?:WorkspaceAccess}){
 id.parse(options.from);id.parse(options.to);address.parse(options.stub);options.signal?.throwIfAborted();const access=options.authorizePath,root=await workspaceRoot(workspace,access,options.authorizeWorkspace),toRoot=options.toWorkspace===undefined?root:await workspaceRoot(path.resolve(root,options.toWorkspace),access,options.authorizeWorkspace);
 for(const name of ['index.sqlite','index.sqlite-wal','index.sqlite-shm','.scan.lock'])await access?.(path.join(root,name),name!=='index.sqlite');
 const release=await claim(root);
 try{
  const snapshot=snapshotSchema.parse({schema:root===toRoot?'carve/rea-bridge@1':'carve/rea-bridge@2',from:options.from,to:options.to,stub:options.stub,...(root!==toRoot?{toWorkspace:path.relative(root,toRoot).split(path.sep).join('/')}:{ }),witness:await witness(root,toRoot,options.from,options.to,options.stub,options.signal,access)}),bytes=Buffer.from(JSON.stringify(snapshot)+'\n');if(bytes.length>MAX)throw new Error('Bridge evidence exceeds256KiB.');
  const hash=digest(bytes),folder=path.join(root,'rea-bridge-evidence');await access?.(folder,true);await mkdir(folder,{recursive:true,mode:0o700});if((await lstat(folder)).isSymbolicLink()||await realpath(folder)!==folder)throw new Error('REA bridge storage follows a symlink.');const file=path.join(folder,hash+'.json'),temporary=path.join(folder,'.incoming-'+randomUUID());await access?.(file,true);await access?.(temporary,true);
  await writeFile(temporary,bytes,{flag:'wx',mode:0o600});try{try{await link(temporary,file);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;if(!(await readSnapshot(file)).equals(bytes))throw new Error('Existing bridge snapshot differs from its content identity.');}}finally{await unlink(temporary);}
  const record=normalized(snapshot),w=record.detail.bridge.witness,observationId=identity(w.from.file,w.from.sha256,hash,snapshot.schema),db=openIndex(root);
  try{db.exec('BEGIN IMMEDIATE');try{const previous=db.prepare('SELECT * FROM observations WHERE id=?').get(observationId) as Row|undefined;if(previous){if(previous.evidence!==file||previous.evidence_sha256!==hash||previous.detail!==JSON.stringify(record.detail)||previous.content!==record.content||previous.kind!=='native-bridge'||previous.name!==record.detail.name||previous.address!==options.stub||previous.artifact!==w.from.file||previous.sha256!==w.from.sha256)throw new Error('Existing bridge observation was modified.');}else db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(observationId,w.from.file,w.from.sha256,'native-bridge',record.detail.name,options.stub,record.content,JSON.stringify(record.detail),file,hash);db.prepare('DELETE FROM observation_search WHERE id=?').run(observationId);db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(observationId,record.content);db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');throw error;}}finally{db.close();}
  return{schema:snapshot.schema==='carve/rea-bridge@2'?'carve/rea-bridge-result@2':'carve/rea-bridge-result@1',status:'byte-bound-static-link',...(root!==toRoot?{workspace:root,toWorkspace:toRoot}:{}),observationId,evidence:file,evidenceSha256:hash,from:w.from,to:w.to,symbol:w.import.symbol.name,dependency:w.dependency,callSites:w.import.kind==='import-stub'?w.import.callSites:[],runtimeLoading:'unverified',dependencyClosure:'not-established',executesTarget:false,startsRea:false,
   nextAction:'Declare both complete implementation IDs in a multi-artifact contract; add this ID to the caller supportingEvidenceIds and relationship.bridgeEvidenceId. Compare actual original cases separately.'};
 }finally{await release();}
}

/** Bind a retained byte witness back to both live REA records and source images. */
export async function assertReaBridgeObservation(row:Row,workspace:string,signal?:AbortSignal,options:{authorizePath?:Access;authorizeWorkspace?:WorkspaceAccess}={}){
 const root=await workspaceRoot(workspace,options.authorizePath,options.authorizeWorkspace);await options.authorizePath?.(row.evidence);
 const bytes=await readSnapshot(row.evidence);if(digest(bytes)!==row.evidence_sha256)throw new Error('REA bridge snapshot changed after inspection.');const snapshot=snapshotSchema.parse(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
 const requested=snapshot.schema==='carve/rea-bridge@2'?path.resolve(root,snapshot.toWorkspace):root,toRoot=requested===root?root:await workspaceRoot(requested,options.authorizePath,options.authorizeWorkspace);
 if(toRoot!==requested||snapshot.schema==='carve/rea-bridge@2'&&toRoot===root)throw new Error('Bridge endpoint workspace path changed identity. Recreate the bridge for the selected workspaces.');
 const current=await witness(root,toRoot,snapshot.from,snapshot.to,snapshot.stub,signal,options.authorizePath);
 if(!isDeepStrictEqual(current,snapshot.witness))throw new Error('REA bridge witness no longer matches both current images and REA records.');
 const record=normalized(snapshot);if(row.id!==identity(current.from.file,current.from.sha256,row.evidence_sha256,snapshot.schema)||row.artifact!==current.from.file||row.sha256!==current.from.sha256||row.kind!=='native-bridge'||row.name!==record.detail.name||row.address!==snapshot.stub||row.content!==record.content||!isDeepStrictEqual(JSON.parse(row.detail),record.detail))throw new Error('REA bridge observation differs from its retained byte witness.');
 return current;
}
