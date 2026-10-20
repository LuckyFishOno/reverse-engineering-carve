import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile, realpath, cp, rm, mkdtemp, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { indexedFile, hashFile, openIndex } from './survey.js';
import { acquireProcessLease,type ToolProcess } from './process-lease.js';
import { digest } from './artifact.js';
import { runTool } from './tool-process.js';
import { windowRange } from './addresses.js';
import {resolveEngineResources,heapExhausted,heapFailure,type EngineResources} from './engine-resources.js';
import {reserveEngineHeap,type HeapReservation} from './engine-reservation.js';
import {linkageKind,linkageTables,saveLinkage,saveLinkagePage,linkageCursor,linkageOffset,type LinkageKind} from './linkage.js';

export async function nativeAnalysis(workspace:string,options:{file:string;ghidra:string;javaHome:string;function?:string;strings?:string;window?:string;linkage?:LinkageKind;bytes?:number;after?:string;limit?:number;timeoutMs?:number;resources?:EngineResources;signal?:AbortSignal;onProcess?:(process:ToolProcess)=>void|Promise<void>}) {
  if(process.platform==='win32')throw new Error('This direct headless adapter is currently verified on POSIX hosts only. Use an explicitly configured REA provider on Windows.');
  const limit=options.limit??500;if(!Number.isInteger(limit)||limit<1||limit>10000)throw new Error('Use limit 1–10000.');
  if([options.function,options.strings,options.window,options.linkage].filter(v=>v!==undefined).length>1)throw new Error('Choose function, strings, window or linkage; omit all for function inventory.');
  if(options.function!==undefined&&!options.function.trim()||options.window!==undefined&&!options.window.trim())throw new Error('Function/window selectors must not be empty.');
  if(options.bytes!==undefined&&!options.window)throw new Error('bytes requires a data window address.');
  const bytes=options.bytes??256;if(!Number.isInteger(bytes)||bytes<1||bytes>4096)throw new Error('Use data window bytes 1–4096.');
  if(options.after&&(options.function||options.window))throw new Error('after is only for inventory/string pages.');
  if(options.strings!==undefined&&options.strings.length>1000)throw new Error('String query exceeds 1000 characters.');
  const timeoutMs=options.timeoutMs??600000;if(!Number.isInteger(timeoutMs)||timeoutMs<1000||timeoutMs>86400000)throw new Error('Use timeoutMs 1000–86400000.');
  if(options.linkage!==undefined)linkageKind.parse(options.linkage);
  const resources=resolveEngineResources(options.resources);
  const root=await realpath(workspace);const target=await indexedFile(root,options.file,options.signal);
  if(target.facts.backend!=='ghidra')throw new Error(`Selected format ${target.facts.format} is not routed to Ghidra.`);
  if(target.facts.encrypted)throw new Error('Selected Mach-O declares encrypted code. An unencrypted authorized analysis input is required; no decrypted source is inferred.');
  const ghidra=await realpath(options.ghidra);const javaHome=await realpath(options.javaHome);
  const properties=await readFile(path.join(ghidra,'Ghidra/application.properties'),'utf8');const version=/^application.version=(.+)$/m.exec(properties)?.[1]?.trim();
  if(!version)throw new Error('Cannot identify the selected Ghidra release.');
  const script=fileURLToPath(new URL('../engines/ghidra/CarveExport.java',import.meta.url));const scriptSha=digest(await readFile(script));
  // Export-only script updates do not invalidate expensive completed auto-analysis.
  const analysisProfile=options.linkage?'ghidra-linkage-v1':'ghidra-default-v2';
  const key=digest(JSON.stringify({sha256:target.sha256,version,profile:analysisProfile}));
  const exportProfile=digest(JSON.stringify({analysis:key,scriptSha}));
  const cursorIdentity=options.linkage?{file:options.file,sha256:target.sha256,profile:exportProfile,kind:options.linkage}:undefined;
  const offset=cursorIdentity?linkageOffset(options.after,cursorIdentity):0;
  const cache=path.join(root,'analysis-cache','ghidra',key);await mkdir(cache,{recursive:true,mode:0o700});
  const runtime=await realpath(await mkdtemp(path.join(tmpdir(),'carve-ghidra-')));
  if(/\s/.test(runtime)){await rm(runtime,{recursive:true,force:true});throw new Error('Ghidra runtime temp path must not contain whitespace; select a suitable TMPDIR.');}
  const runDir=await mkdtemp(path.join(cache,'run-'));const evidence=path.join(runDir,'evidence.jsonl');
  const ready=path.join(cache,'ready.json');let reused=false;let analysisResources:{heapMiB:number;threads:number}|null=null;let reservation:HeapReservation|undefined;let release:(()=>Promise<void>)|undefined;
  const project=path.join(cache,'project');const snapshot=path.join(cache,'input.bin');
  try {
    const lease=await acquireProcessLease(cache,'analysis','.analysis.lock');release=async()=>lease.release();
    try {const saved=JSON.parse(await readFile(ready,'utf8'));reused=saved.key===key;if(reused)analysisResources=saved.analysisResources??null;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    if(!reused){await rm(project,{recursive:true,force:true});await mkdir(project);await cp(target.path,snapshot);if((await hashFile(snapshot)).sha256!==target.sha256)throw new Error('Source changed while creating the analysis snapshot.');}
    else if((await hashFile(snapshot)).sha256!==target.sha256)throw new Error('Cached input bytes changed; discard this owned analysis cache and rerun.');
    const mode=options.linkage?'linkage':options.window?'window':options.strings!==undefined?'strings':options.function?'function':'inventory';
    const args=[project,'RECarve',...(reused?['-process','input.bin','-noanalysis','-readOnly']:['-import',snapshot,...(options.linkage?['-noanalysis']:[])]),'-max-cpu',String(resources.threads),'-scriptPath',path.dirname(script),'-postScript',path.basename(script),evidence,mode,options.linkage??options.window??options.strings??options.function??'',options.linkage?String(offset):options.after??'',String(mode==='window'?bytes:limit)];
    const env:NodeJS.ProcessEnv={PATH:process.env.PATH,JAVA_HOME:javaHome,GHIDRA_HEADLESS_MAXMEM:`${resources.heapMiB}M`,JAVA_TOOL_OPTIONS:`-Duser.home=${runtime} -Djava.io.tmpdir=${runtime}`,LANG:'C.UTF-8'};
    reservation=await reserveEngineHeap(resources,{engine:'ghidra',workspace:root});
    let processResult;try{processResult=await runTool(path.join(ghidra,'support/analyzeHeadless'),args,{cwd:runDir,env,log:path.join(runDir,'engine.log'),timeoutMs,signal:options.signal,onProcess:async guard=>{await lease.register(guard);await options.onProcess?.(guard);}});}finally{reservation.release();}
    // Ghidra analyzers can log a heap failure and still exit 0; never cache such a project as completed.
    if(await heapExhausted(path.join(runDir,'engine.log')))throw new Error(heapFailure('Ghidra',resources));
    if(processResult.exitCode!==0)throw new Error(`Ghidra exited ${processResult.exitCode}: ${processResult.diagnostic}`);
    if((await stat(evidence)).size>256*1024*1024)throw new Error('Evidence page exceeds 256 MiB; reduce the page limit.');
    const evidenceHash=(await hashFile(evidence)).sha256;
    let header:any;let end:any;let functions=0;let failedDecompilations=0;let truncatedDecompilations=0;let observations=0;const observationIds:string[]=[];
    const db=openIndex(root);
    try {
      db.exec(`CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
        CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
        CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);
        CREATE TABLE IF NOT EXISTS native_windows(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,space TEXT,start TEXT,end TEXT);
        CREATE INDEX IF NOT EXISTS native_windows_location ON native_windows(artifact,sha256,space,start,end);`);
      linkageTables(db);
      const save=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)');
      const removeSearch=db.prepare('DELETE FROM observation_search WHERE id=?');const saveSearch=db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)');
      db.exec('BEGIN');
      try {
        const lines=createInterface({input:createReadStream(evidence),crlfDelay:Infinity});
        for await(const line of lines){
          if(!line)continue;if(Buffer.byteLength(line)>4*1024*1024)throw new Error('Evidence row exceeds 4 MiB.');const item=JSON.parse(line);
          if(item.kind==='header'){
            if(header||item.programSha256?.toLowerCase()!==target.sha256)throw new Error('Provider evidence belongs to different input bytes.');header=item;continue;
          }
          if(!header)throw new Error('Missing provider evidence header.');
          if(item.kind==='end'){end=item;continue;}
          if(end)throw new Error('Provider emitted observations after its end marker.');
          if(!['function','string','data-window','native-import','native-export','native-library'].includes(item.kind))throw new Error('Unexpected native evidence row kind.');
          if(item.kind==='function'){functions++;if(item.decompilationStatus==='failed')failedDecompilations++;if(item.pseudocodeTruncated)truncatedDecompilations++;}
          const name=item.kind.startsWith('native-')?item.name:item.kind==='function'?item.name:item.kind==='string'?item.text:'Data at '+item.address;
          const content=item.kind==='function'?[item.name,item.signature,item.pseudocode??'',...item.callees.map((c:any)=>c.name)].join('\n'):item.kind==='string'?item.text:JSON.stringify(item,null,2);
          // Preserve full decompilation when a later inventory page revisits the function.
          // Profiles also distinguish different engines/scripts for the same binary.
          const id=digest(JSON.stringify({file:options.file,sha:target.sha256,profile:exportProfile,kind:item.kind,address:item.address,recordSha256:digest(JSON.stringify(item))}));
          item.provider={name:'ghidra',version,scriptSha256:scriptSha,analysisProfile:key,exportProfile};
          save.run(id,options.file,target.sha256,item.kind,name,item.address,content,JSON.stringify(item),evidence,evidenceHash);
          saveLinkage(db,id,options.file,target.sha256,exportProfile,header.language,target.facts.format,item);
          observations++;if(observationIds.length<100)observationIds.push(id);
          if(item.kind==='data-window'){const range=windowRange(item.address,item.bytes);db.prepare('INSERT OR REPLACE INTO native_windows VALUES(?,?,?,?,?,?)').run(id,options.file,target.sha256,range.space,range.start,range.end);}
          removeSearch.run(id);saveSearch.run(id,content);
        }
        if(!header||!end)throw new Error('Ghidra did not establish a complete evidence export. Inspect the retained engine log.');
        if(options.linkage&&(end.mode!=='linkage'||end.offset!==offset||end.records!==observations||end.records>limit||typeof end.pageComplete!=='boolean'||end.pageComplete!==(end.nextOffset===undefined)))throw new Error('Linkage evidence and page counters differ.');
        if(options.linkage)saveLinkagePage(db,options.file,target.sha256,exportProfile,options.linkage,end);
        db.exec('COMMIT');
      }catch(error){db.exec('ROLLBACK');throw error;}
    }finally{db.close();}
    if(!reused)await writeFile(ready,JSON.stringify({key,targetSha256:target.sha256,version,analysisProfile,initialExportScriptSha256:scriptSha,analysisResources:{heapMiB:resources.heapMiB,threads:resources.threads}}));
    if(!reused)analysisResources={heapMiB:resources.heapMiB,threads:resources.threads};
    const result={schema:'carve/native-analysis@1',workspace:root,file:options.file,sourceSha256:target.sha256,container:target.container??null,programLanguage:header.language,provider:{name:'ghidra',version,scriptSha256:scriptSha,analysisProfile:key,exportProfile},executesTarget:false,reusedAnalysis:reused,resources,analysisResources,heapReservation:{registry:reservation!.registry,heapMiB:reservation!.heapMiB,reservedByOthersMiB:reservation!.reservedByOthersMiB,hostLimitMiB:reservation!.hostLimitMiB,reclaimedStale:reservation!.reclaimedStale},evidence,evidenceSha256:evidenceHash,functions,observations,observationIds,observationIdsTruncated:observations>observationIds.length,summary:end,
      analysisStage:options.linkage?'loader-only':'auto-analyzed-program',autoAnalysisPerformed:!options.linkage&&!reused,...(cursorIdentity?{nextCursor:end.nextOffset===undefined?null:linkageCursor(cursorIdentity,end.nextOffset)}:{}),
      selection:{mode,linkage:options.linkage??null,function:options.function??null,strings:options.strings??null,window:options.window??null,after:options.after??null,limit:mode==='window'?bytes:limit},
      status:mode==='linkage'?'linkage-page-exported':mode==='window'?'data-window-exported':mode==='strings'?'string-page-exported':options.function?(failedDecompilations?'decompilation-failed':truncatedDecompilations?'partial-function':end.selectionStatus==='one-function'?'function-exported':end.selectionStatus):'inventory-page-exported',
      cacheTrust:'The local owned Ghidra project is reused; its database has not been independently authenticated against external modifications.',
      limitations:['Pseudocode is recovered analysis text, not original source. Behavior and feature/UI connection remain unverified.','Only requested linkage/function/string pages or bounded loaded-memory windows are indexed. Dynamic calls, uninspected data and missing dependencies remain unknown.','A raw pointer value or neighboring registration entry is an investigation lead, not semantic confirmation.',...(reused&&!analysisResources?['The reused completed analysis predates recorded engine resources; its heap/thread budget is unknown.']:[])]};
    await writeFile(path.join(runDir,'result.json'),JSON.stringify(result,null,2)+'\n');return result;
  }catch(error){await writeFile(path.join(runDir,'failure.json'),JSON.stringify({status:'failed',message:(error as Error).message,sourceSha256:target.sha256,resources},null,2));throw error;}
  finally{if(release)await release();await rm(runtime,{recursive:true,force:true});}
}
export async function searchObservations(workspace:string,query:string,limit=20) {
  if(!query.trim()||query.length>1000||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use a search phrase of 1–1000 characters and limit 1–100.');
  const root=await realpath(workspace);const db=openIndex(root,true);
  try {
    const exists=db.prepare("SELECT name FROM sqlite_master WHERE name='observation_search'").get();if(!exists)return{schema:'carve/observation-search@1',items:[],status:'no-analysis-yet'};
    const phrase='"'+query.replaceAll('"','""')+'"';
    const epoch=JSON.parse((db.prepare("SELECT value FROM meta WHERE key='epoch'").get() as any).value);
    const rows=db.prepare('SELECT o.* FROM observation_search s JOIN observations o ON o.id=s.id JOIN files f ON f.path=o.artifact AND f.sha256=o.sha256 WHERE observation_search MATCH ? AND f.seen=? ORDER BY bm25(observation_search) LIMIT ?').all(phrase,epoch,limit) as Record<string,any>[];
    return{schema:'carve/observation-search@1',workspace:root,query,status:'observed-matches',semanticMatch:'unconfirmed',items:rows.map(r=>{const detail=JSON.parse(r.detail);return{id:r.id,artifact:r.artifact,sourceSha256:r.sha256,kind:r.kind,name:r.name,address:r.address,provider:detail.provider??null,truncated:Boolean(detail.pseudocodeTruncated??detail.truncated),excerpt:r.content.slice(0,2000),callees:detail.callees?.slice(0,20),references:detail.references?.slice(0,20),pointers:detail.pointers?.slice(0,20),evidence:r.evidence,evidenceSha256:r.evidence_sha256};})};
  }finally{db.close();}
}

export async function readObservation(workspace:string,id:string,offset=0,limit=12000) {
  if(!/^[a-f0-9]{64}$/.test(id)||!Number.isInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>12000)throw new Error('Use a valid observation ID, nonnegative offset and limit 1–12000.');
  const db=openIndex(await realpath(workspace),true);
  try {
    const row=db.prepare('SELECT * FROM observations WHERE id=?').get(id) as any;if(!row)throw new Error('Observation not found.');
    const detail=JSON.parse(row.detail);const text=detail.pseudocode??row.content;
    const current=db.prepare("SELECT f.sha256 FROM files f JOIN meta m ON m.key='epoch' AND f.seen=json_extract(m.value,'$') WHERE f.path=?").get(row.artifact) as any;
    return {schema:'carve/observation@1',id,artifact:row.artifact,sourceSha256:row.sha256,address:row.address,name:row.name,kind:row.kind,
      matchesCurrentInventory:current?.sha256===row.sha256,provider:detail.provider??null,truncated:Boolean(detail.pseudocodeTruncated??detail.truncated),decompilationStatus:detail.decompilationStatus??null,
      ...(detail.boundaryWarnings?.length?{boundaryWarningCount:detail.boundaryWarnings.length,boundaryWarnings:detail.boundaryWarnings.slice(0,5).map((w:any)=>({...w,message:w.message.slice(0,500),targetName:w.targetName.slice(0,200)})),boundaryWarningsTruncated:detail.boundaryWarnings.length>5||detail.boundaryWarnings.some((w:any)=>w.message.length>500||w.targetName.length>200)}:{}),
      ...(detail.rea?{externalEvidence:{schema:detail.rea.schema,adapter:detail.rea.adapter,codeEvidenceId:detail.rea.codeEvidenceId,procedureEvidenceId:detail.rea.procedureEvidenceId,analysisProfileDigest:detail.rea.analysisProfileDigest,inputRecords:detail.rea.inputRecords,authority:detail.rea.authority,limitationCount:detail.rea.limitations.length,limitations:detail.rea.limitations.slice(0,5).map((s:string)=>s.slice(0,500)),limitationsTruncated:detail.rea.limitations.length>5||detail.rea.limitations.some((s:string)=>s.length>500)},relationshipScope:detail.relationshipScope}:{}),
      ...(detail.relationshipEvidence?{relationshipEvidence:{calleesEvidenceId:detail.relationshipEvidence.calleesEvidenceId,referencesEvidenceId:detail.relationshipEvidence.referencesEvidenceId,coverageStatus:detail.relationshipEvidence.coverage?.status??'not-reported',coverageReasons:[...(detail.relationshipEvidence.coverage?.limitations??[]),...(detail.relationshipEvidence.coverage?.reason?[detail.relationshipEvidence.coverage.reason]:[])].slice(0,5).map((s:string)=>s.slice(0,1000)),perResultLimitations:detail.relationshipEvidence.perResultLimitations.slice(0,5).map((s:string)=>s.slice(0,1000)),coverageDetailsTruncated:(detail.relationshipEvidence.coverage?.limitations?.length??0)>5||detail.relationshipEvidence.perResultLimitations.length>5||[...(detail.relationshipEvidence.coverage?.limitations??[]),detail.relationshipEvidence.coverage?.reason??'',...detail.relationshipEvidence.perResultLimitations].some((s:string)=>s.length>1000),unresolvedCallCount:detail.relationshipEvidence.unresolvedCallCount,calleeReferenceAgreement:detail.relationshipEvidence.calleeReferenceAgreement,perResultLimitationCount:detail.relationshipEvidence.perResultLimitations.length},unresolvedCalls:detail.unresolvedCalls.slice(0,100).map((r:any)=>({address:r.address,reason:r.reason.slice(0,1000),reasonTruncated:r.reason.length>1000})),unresolvedCallsTruncated:detail.unresolvedCalls.length>100||detail.unresolvedCalls.some((r:any)=>r.reason.length>1000)}:{}),
      references:detail.references?.slice(0,100),callees:detail.callees?.slice(0,100),pointers:detail.pointers?.slice(0,100),linksTruncated:{references:Boolean(detail.referencesTruncated||detail.references?.length>100),callees:Boolean(detail.calleesTruncated||detail.callees?.length>100),pointers:Boolean(detail.pointers?.length>100)},
      text:text.slice(offset,offset+limit),offset,totalCharacters:text.length,nextOffset:offset+limit<text.length?offset+limit:null,evidence:row.evidence,evidenceSha256:row.evidence_sha256,
      limitation:'Recorded static analysis is not original source or proof of behavior. Rehash the input before analysis/verification.'};
  }finally{db.close();}
}
