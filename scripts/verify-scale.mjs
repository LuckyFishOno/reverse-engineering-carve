import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,open,rm,stat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {survey,queryIndex,indexedFile} from '../dist/survey.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const parent=path.join(root,'artifacts');await mkdir(parent,{recursive:true});const work=await mkdtemp(path.join(parent,'scale-'));
const input=path.join(work,'input');const workspace=path.join(work,'workspace');await mkdir(input);
const count=25001;const started=performance.now();
for(let i=0;i<count;i+=32)await Promise.all(Array.from({length:Math.min(32,count-i)},(_,offset)=>writeFile(path.join(input,`${String(i+offset).padStart(6,'0')}.mjs`),`export const n=${i+offset};\n`)));
const large=path.join(input,'large.dat');const handle=await open(large,'wx');await handle.truncate(64*1024*1024);await handle.close();
let result;let batches=0;let hashed=0;let enumeratedEntries=0;let listedDirectories=0;
const inventoryStarted=performance.now();
do{result=await survey(input,{workspace,maxFiles:1000});batches++;hashed+=result.batch.hashed;enumeratedEntries+=result.batch.enumeratedEntries;listedDirectories+=result.batch.listedDirectories;
 if(batches>1){assert.equal(result.batch.enumeratedEntries,0);assert.equal(result.batch.listedDirectories,0);}
}while(result.status==='indexing'&&batches<40);
const inventoryMs=Math.round(performance.now()-inventoryStarted);
assert.equal(result.status,'indexed');assert.equal(result.files,count+1);assert.equal(hashed,count+1);assert.ok(batches>20);
assert.equal(enumeratedEntries,count+1);assert.equal(listedDirectories,1);
const page=await queryIndex(workspace,{limit:3});assert.equal(page.items.length,3);assert.equal(page.total,count+1);assert.equal(page.nextOffset,3);
const selected=await indexedFile(workspace,'large.dat');assert.equal(selected.bytes,64*1024*1024);
const refreshed=await survey(input,{workspace,refresh:true,maxFiles:100000});assert.equal(refreshed.batch.cached,count+1);assert.equal(refreshed.batch.hashed,0);
const report={schema:'carve/scale-check@1',status:'passed',checkedAt:new Date().toISOString(),node:process.version,platform:process.platform,
 files:result.files,largestFileBytes:selected.bytes,resumableBatches:batches,enumeratedEntries,listedDirectories,inventoryMs,metadataCacheHits:refreshed.batch.cached,elapsedMs:Math.round(performance.now()-started),
 processMaxRssKiB:process.resourceUsage().maxRSS,indexBytes:(await stat(path.join(workspace,'index.sqlite'))).size,
 workspace,limitations:['Synthetic flat directory and sparse data file; not a real system codebase benchmark.','Inventory only: no decompilation/reconstruction of 25,002 files is claimed.','Each directory listing finishes as one streaming disk-queue unit; incomplete listings may replay after interruption.','Peak RSS includes fixture generation and refresh; inventory batches run sequentially.']};
await writeFile(path.join(parent,'scale-verification-summary.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
await rm(input,{recursive:true}); // Keep the resumable index/evidence report, not 25,002 throwaway source files.
