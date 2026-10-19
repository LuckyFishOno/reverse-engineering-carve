// Real retained APK, static analysis and clarification only. No target execution.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,cp,readFile,writeFile} from 'node:fs/promises';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {hashFile} from '../dist/survey.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const engines=await readEngineConfiguration(path.join(root,'artifacts/engines/config.json'));
const upstream=path.join(root,'artifacts/third-party/zxing-4.7.8/BarcodeScanner-4.7.8.apk');
const original=await hashFile(upstream);assert.equal(original.sha256,'4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3');
const out=await mkdtemp(path.join(root,'artifacts/feature-scope-e2e-'));
const save=(file,value)=>writeFile(path.join(out,file),JSON.stringify(value,null,2)+'\n');
await save('engines.json',{jadx:engines.jadx,javaHome:engines.javaHome});
let diagnostics='',peer;const peers=[];
async function connect(){
 const client=new Client({name:'carve-real-apk-feature-scope',version:'1'});
 const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',path.join(out,'engines.json')],stderr:'pipe'});
 transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-8000);});
 await client.connect(transport);peers.push(transport.pid);return client;
}
const unwrap=r=>{if(r.isError)throw new Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return r.structuredContent??JSON.parse(r.content.find(c=>c.type==='text').text);};
const call=async(name,args)=>unwrap(await peer.callTool({name,arguments:args},undefined,{timeout:600000}));
function receipt(result){assert.equal(result.receipt.responseBytes,Buffer.byteLength(JSON.stringify(result)));assert.ok(result.receipt.responseBytes<=8192);return result.receipt.responseBytes;}
try{
 peer=await connect();const tools=(await peer.listTools()).tools;assert.equal(tools.length,48);assert.ok(!tools.some(t=>t.name==='procedure_pseudo_code'));
 await mkdir(path.join(out,'inputs'));await cp(upstream,path.join(out,'inputs/app.apk'));
 const container=await call('carve_reverse',{target:'inputs/app.apk',out:'container-work'});assert.equal(container.status,'awaiting-feature-choice');
 let unpacked;do{unpacked=await call('carve_unpack',{workspace:'container-work',file:'app.apk'});}while(unpacked.status!=='unpacked');
 const task=await call('carve_reverse',{target:path.relative(out,unpacked.content),out:'work'});assert.equal(task.status,'awaiting-feature-choice');
 const analysis=await call('carve_managed',{workspace:'work',file:'classes.dex',class:'com.google.zxing.common.BitArray'});assert.equal(analysis.status,'sources-exported');assert.equal(analysis.observationIds.length,1);
 const manifestFile=path.join(unpacked.content,'AndroidManifest.xml');
 await call('carve_reverse',{target:path.relative(out,manifestFile),out:'manifest-work'});
 const manifest=await call('carve_manifest',{workspace:'manifest-work',file:'AndroidManifest.xml'});assert.equal(manifest.status,'declarations-inspected');await save('manifest.json',manifest);
 const menu=await call('carve_features',{workspace:'work',choice:'barcode'});assert.ok(menu.refinement.options.some(o=>o.id==='payload'));receipt(menu);
 const narrow=await call('carve_features',{workspace:'work',choice:'barcode',facet:'payload'});receipt(narrow);
 const chosen=narrow.items.flatMap(item=>item.leads).find(lead=>lead.id===analysis.observationIds[0]);assert.ok(chosen);assert.equal(narrow.refinement.selectedFacet,'payload');
 const unmatched=await call('carve_features',{workspace:'work',choice:'barcode',facet:'scanner'});assert.equal(unmatched.status,'needs-more-evidence');assert.equal(unmatched.items.length,0);assert.ok(unmatched.refinement.componentLeadsNotFacetMatches.length);
 for(const result of [menu,narrow,unmatched])assert.ok(!JSON.stringify(result).includes('void reverse()'));await save('menu.json',menu);await save('narrow.json',narrow);await save('unmatched.json',unmatched);
 const draft=await call('carve_scope',{workspace:'work',request:{schema:'carve/feature-request@1',origin:'test-fixture',goal:'Reuse internal barcode bit operations',choice:'barcode',facet:'payload'}});receipt(draft);assert.equal(draft.status,'needs-clarification');assert.equal(draft.questions.filter(q=>q.audience==='user').length,7);await save('draft.json',draft);
 const dex=path.join(unpacked.content,'classes.dex'),dexIdentity=await hashFile(dex),manifestIdentity=await hashFile(manifestFile);
 const request={schema:'carve/feature-request@1',origin:'test-fixture',goal:'Fixture scope: original BitArray sequences preserving initialization, append, clear, reverse, set and flip state; excludes scanning, UI and servers.',choice:'barcode',facet:'payload',
  behavior:{trigger:'Local workflow invokes selected operations; initialization constructs an empty vector.',input:'Named step sequences, for example new -> append(5,3) -> clear -> read.',output:'Logical length and bit string at each step; investigate length-preserving clear through full code and behavior comparison.',state:'sequence'},
  boundary:{ui:'excluded',remote:'excluded',host:'excluded'},
  leads:[{workspace:'.',file:chosen.file,sourceSha256:chosen.sourceSha256,observationId:chosen.id},{workspace:'../manifest-work',file:'AndroidManifest.xml',sourceSha256:manifestIdentity.sha256,observationId:manifest.observationId}]};
 const revised=await call('carve_scope',{workspace:'work',request,parentId:draft.id});receipt(revised);assert.equal(revised.status,'ready-for-investigation');assert.equal(revised.verification,'not-run');assert.equal(revised.semanticMatch,'unconfirmed');assert.equal(revised.sourceCount,2);assert.deepEqual(revised.questions,[]);assert.equal(revised.sourceIdentityCheck,'selected-input-hashes-checked-during-this-write');await save('revised.json',revised);
 const saved=await readFile(path.join(task.workspace,'feature-requests',revised.id+'.json'));
 const repeated=await call('carve_scope',{workspace:'work',request,parentId:draft.id});assert.equal(repeated.id,revised.id);
 await peer.close();peer=await connect();
 const historical=await call('carve_scope',{workspace:'work',id:revised.id});receipt(historical);assert.equal(historical.sourceIdentityCheck,'recorded-only-no-current-source-check');
 assert.equal((await call('carve_scope',{workspace:'work',id:draft.id})).status,'needs-clarification');
 let offset=0,text='',pages=0;do{const page=await call('carve_scope',{workspace:'work',id:revised.id,view:'record',offset,characters:400,budgetBytes:2048});assert.equal(page.receipt.responseBytes,Buffer.byteLength(JSON.stringify(page)));assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;pages++;}while(offset!==null);
 const record=JSON.parse(text);assert.deepEqual(record,JSON.parse(saved));assert.equal(record.sources[1].workspace,'../manifest-work');assert.equal(record.sources[1].observation.recordedCompleteCode,false);assert.equal(record.request.origin,'test-fixture');
 const goal=request.goal+' scope-request:'+revised.id;
 const selectedTask=await call('carve_reverse',{target:path.relative(out,unpacked.content),goal,out:'work'});assert.notEqual(selectedTask.task,task.task);
 const taskBytes=await readFile(selectedTask.task);assert.ok(taskBytes.toString().includes(revised.id));
 const edited=Buffer.from(taskBytes.toString()+'\nTest-owned task edit retained across resumption.\n');await writeFile(selectedTask.task,edited);
 await call('carve_reverse',{target:path.relative(out,unpacked.content),goal,out:'work'});assert.deepEqual(await readFile(selectedTask.task),edited);assert.deepEqual(await readFile(path.join(task.workspace,'feature-requests',revised.id+'.json')),saved);
 assert.equal((await hashFile(upstream)).sha256,original.sha256);assert.equal((await hashFile(dex)).sha256,dexIdentity.sha256);assert.equal((await hashFile(manifestFile)).sha256,manifestIdentity.sha256);
 const report={schema:'carve/feature-scope-check@1',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,status:'passed',checkedAt:new Date().toISOString(),out,
  input:{file:upstream,sha256:original.sha256,dexSha256:dexIdentity.sha256,manifestSha256:manifestIdentity.sha256,originalsRetained:true,unchangedAfter:true},
  workflow:{category:'barcode',facet:'payload',selectedCodeObservation:analysis.observationIds[0],independentIndexedComponents:2,scopeId:revised.id,parentId:draft.id,missingUserQuestions:7,testAuthoredAnswers:true,originalDraftRetained:true,freshSessionRead:true,recordPages:pages,stableGoalTask:true,editedTaskPreserved:true},
  outputBytes:{category:receipt(menu),narrow:receipt(narrow),draft:receipt(draft),revised:receipt(revised),historical:receipt(historical),meaning:'Actual compact JSON UTF8 bytes, not model tokens or a saving percentage.'},
  architecture:{carveTools:tools.length,carvePeers:peers,managedBackend:'JADX',reaStarted:false,reaProxied:false,targetExecuted:false,androidStarted:false},
  limitations:['Static real-APK menu/clarification/resumption check, not a new extraction or behavioral comparison; no UI/camera/QR/server recovery or arbitrary-large-project proof.','Fixture answers are explicitly labeled, not user approval or verified original semantics. Scope hashes identify inputs and recorded metadata; complete code/evidence, relationships and behavior still require investigation.','Historical scope reads do not recheck inputs. Source relationships are proposed leads, not discovered dependency edges. Separate existing ART behavior reports were not rerun.']};
 await save('historical.json',historical);await save('report.json',report);await writeFile(path.join(root,'artifacts/feature-scope-verification-summary.json'),JSON.stringify({status:'passed',version:report.version,report:path.join(out,'report.json'),scopeId:revised.id},null,2)+'\n');console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json'),scopeId:revised.id}));
}catch(error){await save('failure.json',{status:'failed',message:error.stack,diagnostics});throw error;}finally{await peer?.close().catch(()=>{});await save('diagnostics.json',{diagnostics});}
