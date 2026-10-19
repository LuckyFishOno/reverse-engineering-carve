import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,writeFile,readFile,rm,realpath,mkdir} from 'node:fs/promises';
import {survey,queryIndex,openIndex,hashFile} from '../dist/survey.js';
import {reverseTask} from '../dist/reverse.js';
import {readObservation,searchObservations} from '../dist/native.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {readPackage} from '../dist/package.js';
import {runReference} from '../dist/reference.js';
import {digest} from '../dist/artifact.js';
import {traceBoundary} from '../dist/trace.js';
import {packageUsage} from '../dist/runtime.js';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {binaryXml,manifestFixture} from './fixtures/android-manifest.mjs';
import {inspectAndroidManifest} from '../dist/android-manifest.js';

async function fixture(t){
 const root=await mkdtemp(path.join(tmpdir(),'carve-reconstruct-test-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'test.dex');await writeFile(input,Buffer.from('dex\n035\0unit-test-input'));
 const workspace=path.join(root,'work');await survey(input,{workspace});
 const sha256=(await queryIndex(workspace)).items[0].sha256;
 const evidence=path.join(root,'synthetic-evidence.txt');await writeFile(evidence,'Synthetic evidence for validator unit tests, not a decompiler result.');
 const id=digest('synthetic-unit-test-row');const evidenceSha=(await hashFile(evidence)).sha256;
 const db=openIndex(workspace);db.exec(`CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);CREATE VIRTUAL TABLE observation_search USING fts5(id UNINDEXED,content);`);
 db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,'test.dex',sha256,'java-class','SyntheticClass.java','SyntheticClass.java','double x',JSON.stringify({pseudocode:'synthetic double x',provider:{name:'synthetic-test-only'},pseudocodeTruncated:false}),evidence,evidenceSha);
 db.prepare('INSERT INTO observation_search VALUES(?,?)').run(id,'double x');db.close();
 const implementation=path.join(root,'rewrite.mjs');await writeFile(implementation,'export const double=x=>x*2;');
 const contract=path.join(root,'contract.json');await writeFile(contract,JSON.stringify({schema:'carve/reconstruction@1',goal:'Double',file:'test.dex',evidenceIds:[id],behavior:{description:'Unit-test double operation',inputDomain:'JSON numbers',outputDomain:'JSON number'},dependencies:[{name:'server',status:'remote-required',detail:'Server algorithm is absent from this test input.'}],unknowns:['Actual binary behavior is not tested by this synthetic unit fixture.']}));
 return{root,input,workspace,id,evidence,implementation,contract,package:path.join(root,'tool')};
}
test('reverse task resumes stable goal and preserves edited contracts instead of inventing observations',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-reverse-'));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'app.mjs');await writeFile(input,'export const value=1;');
 const first=await reverseTask(input,{goal:'analyze feature',out:path.join(root,'workspace')});assert.equal(first.status,'ready-for-analysis');
 assert.equal(JSON.parse(await readFile(first.contract,'utf8')).behavior.description,null);
 await writeFile(first.contract,'user edited draft');const next=await reverseTask(input,{goal:'analyze feature',out:first.workspace});assert.equal(next.contract,first.contract);assert.equal(await readFile(next.contract,'utf8'),'user edited draft');
 const other=await reverseTask(input,{goal:'another feature',out:first.workspace});assert.notEqual(other.task,first.task);assert.equal(other.inventory.batch.hashed,0);
});
test('reconstruction binds evidence while leaving missing remote dependencies and rewritten source explicit',async t=>{
 const f=await fixture(t);const result=await reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package});
 assert.equal(result.status,'packaged-with-unknowns');assert.equal(result.unresolvedDependencies[0].status,'remote-required');
 const pkg=await readPackage(f.package);assert.equal(pkg.manifest.extractionKind,'behavior-reconstruction');assert.equal(pkg.manifest.reconstruction.original.file,'test.dex');assert.equal(pkg.manifest.source.target,await realpath(f.implementation));
 assert.equal(pkg.manifest.verification.status,'not-run');assert.match(await readFile(path.join(f.package,'README.md'),'utf8'),/agent reimplementation/);
 await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package}),/EEXIST/);
 await writeFile(f.evidence,'tampered');await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:path.join(f.root,'other')}),/evidence changed/);
});
test('version2 references compare raw stdin/stdout through actual CLI and MCP without an adapter process',async t=>{
 const f=await fixture(t);await writeFile(f.implementation,'export const double=bytes=>String.fromCharCode(...bytes);');await reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package});
 const reference=path.join(f.root,'raw-reference.json'),cases=path.join(f.root,'raw-cases.json'),config={schema:'carve/reference@2',command:[process.execPath,'-e','process.stdin.pipe(process.stdout)'],mode:'bytes-stdin',output:'utf8',scope:'external-harness',description:'Synthetic raw echo protocol test; this Node process does not execute the fixture DEX.',boundFiles:[]};
 await writeFile(reference,JSON.stringify(config));await writeFile(cases,JSON.stringify([{name:'empty',args:[[]],expected:''},{name:'NUL-newline',args:[[65,0,66,10]],expected:'A\u0000B\n'}]));
 const options={package:f.package,reference,cases,execute:true},result=await verifyReconstruction(f.workspace,options);assert.equal(result.status,'passed-supplied-cases');assert.equal(result.reference.schema,'carve/reference@2');assert.equal(result.verifiedScope,'declared-external-harness-cases');assert.equal(result.results[1].original.value,'A\u0000B\n');
 const cli=JSON.parse(execFileSync(process.execPath,[path.resolve('dist/cli.js'),'verify-reconstruction',f.workspace,'--package',f.package,'--cases',cases,'--reference',reference,'--execute'],{encoding:'utf8'}));assert.equal(cli.status,'passed-supplied-cases');assert.equal(cli.schema,'carve/verification-read@1');assert.equal(cli.unknownsCount,1);assert.equal(cli.verifiedScope,'declared-external-harness-cases');assert.equal(Object.hasOwn(cli,'results'),false);assert.ok(cli.receipt.responseBytes<=8192);
 const savedCase=JSON.parse(execFileSync(process.execPath,[path.resolve('dist/cli.js'),'verification',f.workspace,'--id',cli.id,'--view','case','--case-index','1','--field','original'],{encoding:'utf8'}));assert.deepEqual(JSON.parse(savedCase.text),result.results[1].original);
 const legacy=JSON.parse(execFileSync(process.execPath,[path.resolve('dist/cli.js'),'verify-reconstruction',f.workspace,'--package',f.package,'--cases',cases,'--reference',reference,'--execute','--full-report'],{encoding:'utf8'}));assert.deepEqual(legacy.results,result.results);
 const client=new Client({name:'raw-reference-protocol',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.resolve('dist/cli.js'),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());const response=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:'work',package:'tool',cases:'raw-cases.json',reference:'raw-reference.json',execute:true}});assert.equal(response.isError,undefined,response.content[0].text);const compact=JSON.parse(response.content[0].text);assert.equal(compact.total,2);assert.equal(compact.schema,'carve/verification-read@1');assert.equal(Object.hasOwn(compact,'results'),false);assert.equal(compact.receipt.responseBytes,Buffer.byteLength(response.content[0].text));
 const recorded=await client.callTool({name:'carve_verification',arguments:{workspace:'work',id:compact.id,view:'case',caseIndex:1,field:'original'}});assert.equal(recorded.isError,undefined);assert.deepEqual(JSON.parse(JSON.parse(recorded.content[0].text).text),result.results[1].original);
 const full=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:'work',package:'tool',cases:'raw-cases.json',reference:'raw-reference.json',execute:true,fullReport:true}});assert.equal(full.isError,undefined);assert.deepEqual(JSON.parse(full.content[0].text).results,result.results);
 await writeFile(reference,JSON.stringify({...config,scope:'target-cli'}));await assert.rejects(()=>verifyReconstruction(f.workspace,options),/target-cli requires/);
 await writeFile(reference,JSON.stringify({...config,schema:'carve/reference@1'}));await assert.rejects(()=>verifyReconstruction(f.workspace,options));
 await writeFile(reference,JSON.stringify(config));await writeFile(cases,JSON.stringify([{name:'invalid UTF8',args:[[255]]}]));const invalid=await verifyReconstruction(f.workspace,options);assert.equal(invalid.status,'failed');assert.equal(invalid.results[0].original.kind,'harness-error');
});
test('inventory-only and truncated evidence cannot support a packaged reconstruction; old observations are labeled historical',async t=>{
 const f=await fixture(t);const db=openIndex(f.workspace);db.prepare('UPDATE observations SET detail=? WHERE id=?').run(JSON.stringify({pseudocode:'partial',pseudocodeTruncated:true}),f.id);db.close();
 await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package}),/complete decompiled/);
 assert.equal((await readObservation(f.workspace,f.id)).matchesCurrentInventory,true);
 await writeFile(f.input,'changed revision');await survey(f.input,{workspace:f.workspace,refresh:true});
 assert.equal((await readObservation(f.workspace,f.id)).matchesCurrentInventory,false);assert.equal((await searchObservations(f.workspace,'double')).items.length,0);
 await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package}),/current selected input/);
});
test('boundary data can support code evidence but cannot replace it; traces expose data references without semantic confirmation',async t=>{
 const f=await fixture(t);const support=path.join(f.root,'synthetic-window.txt');await writeFile(support,'Synthetic pointer window for validator tests only.');
 const windowId=digest('synthetic-window'),stringId=digest('synthetic-string'),functionId=digest('synthetic-function');
 const db=openIndex(f.workspace);const sha=(db.prepare('SELECT sha256 FROM files').get()).sha256;const save=db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)');const evidenceSha=(await hashFile(support)).sha256;
 save.run(windowId,'test.dex',sha,'data-window','Synthetic registration window','3000','pointer window',JSON.stringify({pointers:[{address:'3000',targetFunction:'syntheticFn',targetFunctionAddress:'1000'}],references:[{targetFunction:'externalImport',targetFunctionAddress:'4000',targetExternal:true,targetThunk:false}],provider:{name:'synthetic-test-only'}}),support,evidenceSha);
 save.run(stringId,'test.dex',sha,'string','feature','2000','feature',JSON.stringify({references:[{address:'3008',targetAddress:'2000'}]}),support,evidenceSha);
 save.run(functionId,'test.dex',sha,'function','syntheticFn','1000','syntheticFn',JSON.stringify({callees:[]}),support,evidenceSha);db.close();
 const windows=openIndex(f.workspace);windows.exec('CREATE TABLE native_windows(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,space TEXT,start TEXT,end TEXT);');windows.prepare('INSERT INTO native_windows VALUES(?,?,?,?,?,?)').run(windowId,'test.dex',sha,'','00000000000000000000000000003000','0000000000000000000000000000300f');windows.close();
 const graph=await traceBoundary(f.workspace,stringId,{depth:3});assert.deepEqual(graph.nodes.map(n=>n.kind),['string','data-window','function']);assert.equal(graph.edges[0].relation,'data-reference-to-string');assert.ok(graph.edges.some(e=>e.relation==='raw-pointer-interpretation'));assert.ok(graph.edges.some(e=>e.to==='4000'&&e.external===true&&e.thunk===false&&!e.indexed));assert.equal(graph.semanticMatch,'unconfirmed');
 assert.equal(graph.edges[0].referenceAddress,'3008');assert.equal(graph.edges[0].to,'3000');assert.equal(graph.edges[0].toId,windowId);
 const contract=JSON.parse(await readFile(f.contract,'utf8'));contract.supportingEvidenceIds=[windowId,stringId];await writeFile(f.contract,JSON.stringify(contract));
 await reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package});
 const pkg=await readPackage(f.package);assert.equal(pkg.manifest.reconstruction.evidence.filter(e=>e.role==='boundary-support').length,2);
 contract.evidenceIds=[windowId];await writeFile(f.contract,JSON.stringify(contract));await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:path.join(f.root,'bad')}),/complete decompiled/);
 contract.evidenceIds=[f.id];await writeFile(f.contract,JSON.stringify(contract));await writeFile(support,'tampered supporting evidence');await assert.rejects(()=>reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:path.join(f.root,'stale')}),/evidence changed/);
});
test('reference verification discloses external harness scope, fails mismatches/errors and requires execution authorization',async t=>{
 const f=await fixture(t);await reconstruct(f.workspace,{contract:f.contract,implementation:f.implementation,export:'double',out:f.package});
 const harness=path.join(f.root,'harness.mjs');await writeFile(harness,"const args=JSON.parse(await new Promise(r=>{let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>r(s))}));console.log(JSON.stringify(args[0]*2));");
 const reference=path.join(f.root,'reference.json');await writeFile(reference,JSON.stringify({schema:'carve/reference@1',command:[process.execPath,harness],mode:'json-stdin',scope:'external-harness',description:'Synthetic validator test only',boundFiles:[harness]}));
 const cases=path.join(f.root,'cases.json');await writeFile(cases,JSON.stringify([{name:'two',args:[2],expected:4}]));
 const options={package:f.package,cases,reference,execute:true};
 await assert.rejects(()=>verifyReconstruction(f.workspace,{...options,execute:false}),/--execute/);
 await writeFile(cases,'[{"name":"nonfinite","args":[1e999]}]');await assert.rejects(()=>verifyReconstruction(f.workspace,options),/non-finite/);
 await writeFile(cases,JSON.stringify([{name:'two',args:[2],expected:4}]));
 let report=await verifyReconstruction(f.workspace,options);assert.equal(report.status,'passed-supplied-cases');assert.equal(report.verifiedScope,'declared-external-harness-cases');assert.equal(report.unresolvedDependencies.length,1);
 await writeFile(cases,JSON.stringify([{name:'wrong expected',args:[2],expected:999}]));report=await verifyReconstruction(f.workspace,options);assert.equal(report.status,'failed');
 await writeFile(harness,'process.exit(2)');report=await verifyReconstruction(f.workspace,options);assert.equal(report.status,'failed');assert.equal(report.results[0].original.kind,'harness-error');
 const config=JSON.parse(await readFile(reference,'utf8'));config.scope='target-cli';await writeFile(reference,JSON.stringify(config));await assert.rejects(()=>verifyReconstruction(f.workspace,options),/selected indexed binary/);
});
test('reference commands have bounded execution/output and never treat protocol failures as target errors',async()=>{
 const cwd=tmpdir();const exec=(code,args=[],mode='argv-values',timeout=2000)=>runReference([process.execPath,'-e',code],mode,args,cwd,timeout);
 assert.deepEqual(await exec('console.log(JSON.stringify(process.argv.slice(1)))',['hello;echo $(bad)',3]),{kind:'return',value:['hello;echo $(bad)','3']});
 for(const code of ['console.log("not JSON")','console.log(1);process.exit(2)','process.stdout.write("x".repeat(1100000))','console.log("1e999")'])assert.equal((await exec(code)).kind,'harness-error');
 assert.match((await exec('setInterval(()=>{},1000)',[],'argv-values',50)).detail,/timed out/);
 assert.equal((await exec('console.log(1)',[{}])).kind,'harness-error');
});
async function multiFixture(t,{outside=false}={}){
 const f=await fixture(t);const base=outside?await mkdtemp(path.join(tmpdir(),'carve-related-outside-')):path.join(f.root,'related');await mkdir(base,{recursive:true});if(outside)t.after(()=>rm(base,{recursive:true,force:true}));
 const library=path.join(base,'library.dex');await writeFile(library,Buffer.from('dex\n035\0unit-test-library'));const workspace=path.join(base,'work');await survey(library,{workspace});const sourceSha=(await hashFile(library)).sha256;
 const evidence=path.join(base,'library-evidence.txt');await writeFile(evidence,'Synthetic secondary code for validator tests only.');const id=digest('synthetic-library-unit-row');const db=openIndex(workspace);
 db.exec('CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);');
 db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,'library.dex',sourceSha,'java-class','SyntheticLibrary','SyntheticLibrary','library',JSON.stringify({pseudocode:'synthetic library code',provider:{name:'synthetic-test-only'}}),evidence,(await hashFile(evidence)).sha256);db.close();
 const old=JSON.parse(await readFile(f.contract,'utf8'));const contract={schema:'carve/reconstruction@2',goal:old.goal,primary:'app',artifacts:[{key:'app',file:'test.dex',evidenceIds:[f.id]},{key:'library',workspace:path.relative(f.workspace,workspace),file:'library.dex',evidenceIds:[id]}],relationships:[{from:{artifact:'app',id:f.id},to:{artifact:'library',id},kind:'calls',basis:'hypothesis',description:'Synthetic relationship claim; not actual execution evidence.'}],behavior:old.behavior,dependencies:[],unknowns:[]};await writeFile(f.contract,JSON.stringify(contract));
 return{...f,multi:contract,secondary:{library,workspace,id,evidence}};
}
const packageOptions=f=>({contract:f.contract,implementation:f.implementation,export:'double',out:f.package});
async function referenceFixture(f,code){
 const harness=path.join(f.root,'reference.mjs');await writeFile(harness,code??"let s='';for await(const d of process.stdin)s+=d;console.log(JSON.stringify(JSON.parse(s)[0]*2));");
 const reference=path.join(f.root,'reference.json'),cases=path.join(f.root,'cases.json');await writeFile(reference,JSON.stringify({schema:'carve/reference@1',command:[process.execPath,harness],mode:'json-stdin',scope:'external-harness',description:'Synthetic validator harness; does not execute original DEX',boundFiles:[harness]}));await writeFile(cases,JSON.stringify([{name:'double',args:[2],expected:4}]));return{package:f.package,cases,reference,execute:true};
}
test('multi-artifact contracts bind each workspace/code identity and retain hypotheses after comparison',async t=>{
 const f=await multiFixture(t);const packaged=await reconstruct(f.workspace,packageOptions(f));assert.equal(packaged.status,'packaged-with-unknowns');assert.equal(packaged.artifacts.length,2);assert.equal(packaged.unresolvedRelationships.length,1);assert.equal(packaged.relationships[0].semanticMatch,'unconfirmed');assert.deepEqual(packaged.evidence.map(e=>e.artifact),['app','library']);
 const pkg=await readPackage(f.package);assert.equal(pkg.manifest.reconstruction.schema,'carve/reconstruction-provenance@2');assert.equal(pkg.manifest.reconstruction.artifacts[1].workspace,await realpath(f.secondary.workspace));
 const report=await verifyReconstruction(f.workspace,await referenceFixture(f));assert.equal(report.status,'passed-supplied-cases');assert.equal(report.unresolvedRelationships.length,1);assert.equal(report.relationships[0].semanticMatch,'unconfirmed');assert.ok(report.reference.boundFiles.some(b=>b.file===path.join(path.dirname(packaged.artifacts[1].workspace),'library.dex')));
 const usage=await packageUsage(f.package);assert.equal(usage.reconstruction.artifacts.length,2);assert.equal(usage.reconstruction.unresolvedRelationships.length,1);
 await writeFile(f.secondary.evidence,'tampered secondary code');const options=await referenceFixture(f);await assert.rejects(()=>verifyReconstruction(f.workspace,options),/evidence changed/);
});
test('multi-artifact schemas reject missing, disconnected, duplicated and undeclared evidence endpoints',async t=>{
 const f=await multiFixture(t);const check=async change=>{const data=structuredClone(f.multi);change(data);await writeFile(f.contract,JSON.stringify(data));await assert.rejects(()=>reconstruct(f.workspace,packageOptions(f)));};
 await check(c=>c.primary='missing');await check(c=>c.artifacts[1].key='app');await check(c=>c.relationships=[]);await check(c=>c.relationships[0].to.id=digest('not bound'));
 await check(c=>c.relationships[0].basis='observed-runtime');await check(c=>c.relationships[0].from=c.relationships[0].to);
 await check(c=>{c.artifacts[1]={...c.artifacts[0],key:'library'};c.relationships[0].to.id=f.id;});
});
test('every secondary component requires current bytes and complete unmodified code evidence',async t=>{
 const f=await multiFixture(t);const db=openIndex(f.secondary.workspace);db.prepare('UPDATE observations SET detail=?').run(JSON.stringify({pseudocode:'truncated',pseudocodeTruncated:true}));db.close();await assert.rejects(()=>reconstruct(f.workspace,packageOptions(f)),/complete decompiled/);
 const reset=openIndex(f.secondary.workspace);reset.prepare('UPDATE observations SET detail=?').run(JSON.stringify({pseudocode:'synthetic full code'}));reset.close();await writeFile(f.secondary.library,'changed library');await assert.rejects(()=>reconstruct(f.workspace,packageOptions(f)),/changed since inventory/);
 await survey(f.secondary.library,{workspace:f.secondary.workspace,refresh:true});await assert.rejects(()=>reconstruct(f.workspace,packageOptions(f)),/current selected input/);
});
test('verification catches secondary source or analysis evidence changed by the actual reference process',async t=>{
 for(const target of ['library','evidence']){
  const f=await multiFixture(t);await reconstruct(f.workspace,packageOptions(f));const file=f.secondary[target];const options=await referenceFixture(f,`import{writeFileSync}from'node:fs';writeFileSync(${JSON.stringify(file)},'changed during reference');console.log(4);`);
  await assert.rejects(()=>verifyReconstruction(f.workspace,options),/bound bytes changed|evidence changed/);
  await assert.rejects(()=>readFile(path.join(f.package,'carve.verification.json')),/ENOENT/);
 }
});
test('MCP rejects related workspaces outside its root, including during verification',async t=>{
 const f=await multiFixture(t,{outside:true});await reconstruct(f.workspace,packageOptions(f));const options=await referenceFixture(f);
 const client=new Client({name:'multi-artifact-confine',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('../dist/cli.js',import.meta.url)),'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const create=await client.callTool({name:'carve_reconstruct',arguments:{workspace:f.workspace,contract:f.contract,implementation:f.implementation,export:'double',out:path.join(f.root,'mcp-tool')}});assert.equal(create.isError,true);assert.match(create.content[0].text,/outside/);
 const verify=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:f.workspace,...options}});assert.equal(verify.isError,true);assert.match(verify.content[0].text,/outside/);
});
async function supportFixture(t){
 const f=await fixture(t),input=path.join(f.root,'AndroidManifest.xml'),workspace=path.join(f.root,'manifest-work');await writeFile(input,binaryXml(manifestFixture()));await survey(input,{workspace});const manifest=await inspectAndroidManifest(workspace,{file:'AndroidManifest.xml'}),old=JSON.parse(await readFile(f.contract,'utf8'));
 const contract={schema:'carve/reconstruction@2',primary:'code',goal:old.goal,behavior:old.behavior,dependencies:[],unknowns:['Synthetic code unit test; not an original DEX runtime comparison.'],artifacts:[{key:'code',file:'test.dex',evidenceIds:[f.id]},{key:'manifest',workspace:path.relative(f.workspace,workspace),file:'AndroidManifest.xml',role:'boundary-support',evidenceIds:[],supportingEvidenceIds:[manifest.observationId]}],relationships:[{from:{artifact:'code',id:f.id},to:{artifact:'manifest',id:manifest.observationId},kind:'other',basis:'reviewed-static',description:'Synthetic declaration relationship only; no runtime loading proof.'}]};await writeFile(f.contract,JSON.stringify(contract));return{...f,support:{input,workspace,manifest},multi:contract};
}
test('support-only manifest artifacts bind their own bytes/evidence through packaging and verification',async t=>{
 const f=await supportFixture(t),pkg=await reconstruct(f.workspace,packageOptions(f));assert.equal(pkg.artifacts[1].role,'boundary-support');assert.deepEqual(pkg.artifacts[1].evidenceIds,[]);assert.equal(pkg.evidence.find(e=>e.artifact==='manifest').role,'boundary-support');assert.equal(pkg.relationships[0].semanticMatch,'unconfirmed');
 const result=await verifyReconstruction(f.workspace,await referenceFixture(f)),supportPath=await realpath(f.support.input);assert.equal(result.status,'passed-supplied-cases');assert.ok(result.reference.boundFiles.some(v=>v.file===supportPath));
 await writeFile(f.support.manifest.evidence,'tampered support');const options=await referenceFixture(f);await assert.rejects(()=>verifyReconstruction(f.workspace,options),/evidence changed/);
});
test('support roles cannot replace primary/implementation code, omit evidence or bypass confinement/freshness',async t=>{
 const f=await supportFixture(t),check=async change=>{const contract=structuredClone(f.multi);change(contract);await writeFile(f.contract,JSON.stringify(contract));await assert.rejects(()=>reconstruct(f.workspace,{...packageOptions(f),out:path.join(f.root,'bad')}));};
 await check(c=>c.primary='manifest');await check(c=>c.artifacts[1].supportingEvidenceIds=[]);await check(c=>c.artifacts[1].evidenceIds=[f.support.manifest.observationId]);await check(c=>delete c.artifacts[1].role);await check(c=>c.artifacts[1].role='implementation');await check(c=>c.relationships=[]);
 await writeFile(f.contract,JSON.stringify(f.multi));const realSupportWorkspace=await realpath(f.support.workspace);await assert.rejects(()=>reconstruct(f.workspace,{...packageOptions(f),out:path.join(f.root,'denied'),authorizeWorkspace:async p=>{if(p===realSupportWorkspace)throw new Error('Denied support workspace');return p;}}),/Denied support/);
 await writeFile(f.support.input,'changed manifest');await assert.rejects(()=>reconstruct(f.workspace,packageOptions(f)),/changed since inventory/);
});
