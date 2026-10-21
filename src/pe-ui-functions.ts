import {realpath,lstat} from 'node:fs/promises';
import path from 'node:path';
import {assertReaNativeObservation} from './rea-native.js';
import {openIndex,indexedFile,metaValue} from './survey.js';
export type PeUiAccess=(file:string,newPath?:boolean)=>Promise<unknown>;
export type PeUiFunction={record:Record<string,any>;detail:Record<string,any>;target:Awaited<ReturnType<typeof indexedFile>>};

// Selected observations are revalidated even when they are not reachable from the UI entry.
export async function loadPeUiFunctions(root:string,ids:string[],signal?:AbortSignal,access?:PeUiAccess,expectedFile?:string){
 const db=openIndex(root,true),loaded:PeUiFunction[]=[],targets=new Map<string,PeUiFunction['target']>();let bytes=0;
 try{
  const sourceRoot=metaValue(db,'root');if(typeof sourceRoot!=='string')throw new Error('Missing indexed source root.');
  for(const id of [...ids].sort()){
   signal?.throwIfAborted();
   const row=db.prepare('SELECT * FROM observations WHERE id=?').get(id) as Record<string,any>|undefined;
   if(!row)throw new Error('PE UI function observation is missing: '+id);
   if(expectedFile!==undefined&&row.artifact!==expectedFile)throw new Error('PE UI function evidence must identify the same current indexed PE file.');
   if(row.kind!=='function'||typeof row.artifact!=='string'||path.isAbsolute(row.artifact)||row.artifact.includes('\\')||row.artifact.split('/').includes('..'))throw new Error('Choose imported indexed PE function observations.');
   const source=path.resolve(sourceRoot,row.artifact);await access?.(source);
   let target=targets.get(row.artifact);
   if(!target){if(targets.size>=16)throw new Error('PE UI dependencies exceed16selected source images.');target=await indexedFile(root,row.artifact,signal);targets.set(row.artifact,target);}
   if(row.sha256!==target.sha256||target.facts.format!=='pe')throw new Error('PE UI function evidence must identify a current indexed PE file.');
   const folder=path.join(root,'rea-native-evidence');await access?.(folder);
   if(!/^[a-f0-9]{64}$/.test(row.evidence_sha256)||row.evidence!==path.join(folder,row.evidence_sha256+'.json')||await realpath(folder)!==folder)throw new Error('PE UI function evidence must use an owned REA snapshot without redirects.');
   await access?.(row.evidence);const info=await lstat(row.evidence);if(!info.isFile()||info.isSymbolicLink())throw new Error('PE UI function snapshot must be a regular owned file.');
   bytes+=info.size;if(bytes>64*1024*1024)throw new Error('PE UI function snapshots exceed the cumulative 64 MiB budget.');
   await assertReaNativeObservation(row,target);const d=JSON.parse(row.detail);
   const record={observationId:id,file:row.artifact,sourceSha256:target.sha256,address:d.address,name:d.name,profile:d.provider.analysisProfileDigest,snapshotSha256:row.evidence_sha256,codeEvidenceId:d.rea.codeEvidenceId,procedureEvidenceId:d.rea.procedureEvidenceId,thunk:d.thunk,relationshipScope:d.relationshipScope,relationshipsIncomplete:d.calleesTruncated||d.referencesTruncated,producerAuthentication:'not-established'};
   loaded.push({record,detail:d,target});
  }
 }finally{db.close();}
 return loaded;
}
