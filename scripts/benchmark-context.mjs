import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {parseArgs} from 'node:util';
import {analysisContext} from '../dist/context.js';
import {readObservation} from '../dist/native.js';
import {hashFile,indexedFile} from '../dist/survey.js';
import {digest} from '../dist/artifact.js';

const {values}=parseArgs({options:{cases:{type:'string'},baseline:{type:'string'},python:{type:'string'},out:{type:'string'}}});
if(!values.cases||!values.baseline||!values.python||!values.out)throw new Error('Use --cases requests.json --baseline OLD_DIST/context.js --python VENV/bin/python --out NEW_DIRECTORY. See docs/CONTEXT.md.');
const out=path.resolve(values.out);await mkdir(out,{recursive:false});
const baselinePath=path.resolve(values.baseline),baseline=await import(pathToFileURL(baselinePath).href);
const cases=JSON.parse(await readFile(values.cases,'utf8'));assert.ok(Array.isArray(cases)&&cases.length>0&&cases.length<=20);
const results=[];const cache=path.join(out,'tokenizer-cache');await mkdir(cache);
function count(payloads){return new Promise((resolve,reject)=>{const child=execFile(values.python,[fileURLToPath(new URL('./count-context-tokens.py',import.meta.url))],{env:{...process.env,TIKTOKEN_CACHE_DIR:cache},timeout:60000,maxBuffer:1024*1024},(error,stdout,stderr)=>error?reject(new Error(String(error)+'\n'+stderr)):resolve(JSON.parse(stdout)));child.stdin.end(JSON.stringify(payloads));});}
for(const [index,entry]of cases.entries()){
 assert.ok(!entry.options?.view&&entry.options?.code===undefined&&!entry.options?.knownFingerprint);const options={...entry.options,budgetBytes:65536},workspace=path.resolve(entry.workspace);
 const old=await baseline.analysisContext(workspace,{...options,code:false}),outline=await analysisContext(workspace,{...options,view:'outline'}),auto=await analysisContext(workspace,{...options,view:'auto'}),reuse=await analysisContext(workspace,{...options,view:'auto',knownFingerprint:auto.fingerprint});
 for(const packet of [old,outline,auto]){assert.equal(packet.nextOffset,null);assert.equal(packet.receipt.responseBytes,Buffer.byteLength(JSON.stringify(packet)));assert.equal(packet.budgetLimited,false);}
 assert.deepEqual(outline.items.map(i=>i.id),old.items.map(i=>i.id));assert.deepEqual(auto.items.map(i=>i.id),old.items.map(i=>i.id));assert.equal(reuse.status,'unchanged-recorded-context');
 const reads=[],sources=[],evidence=new Map();
 for(const source of auto.sources){const selected=await indexedFile(workspace,source.file);assert.equal(selected.sha256,source.sha256);sources.push({file:source.file,path:selected.path,sha256:selected.sha256,bytes:selected.bytes});}
 for(const item of auto.items){
  const prior=old.items.find(r=>r.id===item.id);assert.equal(auto.sources[item.source].sha256,prior.sourceSha256);assert.deepEqual(item.provider===null?null:auto.providers[item.provider],prior.provider);assert.equal(item.recordTruncated,prior.recordTruncated);assert.equal(item.decompilationStatus,prior.decompilationStatus);
  const record=await readObservation(workspace,item.id);assert.equal(record.matchesCurrentInventory,true);assert.equal((await hashFile(record.evidence)).sha256,record.evidenceSha256);evidence.set(record.evidence,record.evidenceSha256);
  if(item.text){assert.equal(item.text.complete,true);assert.equal(record.nextOffset,null);assert.equal(record.text,item.text.value);reads.push(record);}
 }
 const oldReuse=await baseline.analysisContext(workspace,{...options,code:false,knownFingerprint:old.fingerprint});
 const named=[['oldOutline',old],['outline',outline],['auto',auto],['reuse',reuse],['oldReuse',oldReuse],...reads.map((read,i)=>['oldRead'+i,read])];
 const payloads=named.map(([,value])=>JSON.stringify(value)),tokenizer=await count(payloads),measurements={};
 for(let n=0;n<named.length;n++){const [name]=named[n],payload=payloads[n],filename=`${index}-${name}.json`;await writeFile(path.join(out,filename),payload+'\n',{flag:'wx'});measurements[name]={payload:filename,sha256:digest(payload),bytes:Buffer.byteLength(payload),tokens:tokenizer.tokens[n]};}
 const sum=(names,key)=>names.reduce((n,name)=>n+measurements[name][key],0),baselineNames=['oldOutline',...reads.map((_,i)=>'oldRead'+i)],baselineBodies={bytes:sum(baselineNames,'bytes'),tokens:sum(baselineNames,'tokens'),responses:baselineNames.length};
 for(const source of sources)assert.equal((await indexedFile(workspace,source.file)).sha256,source.sha256);
 for(const [file,sha256]of evidence)assert.equal((await hashFile(file)).sha256,sha256);
 results.push({name:entry.name,workspace,request:options,sources,evidence:[...evidence].map(([file,sha256])=>({file,sha256})),observationIds:auto.items.map(i=>i.id),inlineIds:auto.items.filter(i=>i.text).map(i=>i.id),tokenizer:{...tokenizer,tokens:undefined},measurements,baselineWithSameInlineBodies:baselineBodies,
  outlineReduction:{bytes:1-measurements.outline.bytes/measurements.oldOutline.bytes,tokens:1-measurements.outline.tokens/measurements.oldOutline.tokens},
  autoReductionAgainstOutlinePlusReads:{bytes:1-measurements.auto.bytes/baselineBodies.bytes,tokens:1-measurements.auto.tokens/baselineBodies.tokens},
  scope:'Same ordered observation IDs and inline recorded bodies checked. Old full observation reads also contain extra reference/evidence metadata. No model accuracy, latency, actual billing or universal savings claim. Source/evidence freshly checked separately from context API.'});
}
const cacheFiles=[];for(const file of await readdir(cache)){const hashed=await hashFile(path.join(cache,file));cacheFiles.push({file,sha256:hashed.sha256,bytes:hashed.bytes});}
const report={schema:'carve/context-benchmark@1',measuredAt:new Date().toISOString(),node:process.version,version:JSON.parse(await readFile(new URL('../package.json',import.meta.url),'utf8')).version,baseline:{path:baselinePath,sha256:(await hashFile(baselinePath)).sha256},implementation:{sha256:(await hashFile(fileURLToPath(new URL('../dist/context.js',import.meta.url)))).sha256},tokenizerCache:cacheFiles,cases:results};
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({report:path.join(out,'report.json'),cases:results.map(r=>({name:r.name,oldOutline:r.measurements.oldOutline,outline:r.measurements.outline,auto:r.measurements.auto,reuse:r.measurements.reuse,baselineWithSameInlineBodies:r.baselineWithSameInlineBodies,outlineReduction:r.outlineReduction,autoReductionAgainstOutlinePlusReads:r.autoReductionAgainstOutlinePlusReads}))},null,2));
