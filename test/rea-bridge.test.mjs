import test from 'node:test';import assert from 'node:assert/strict';import path from 'node:path';import {tmpdir} from 'node:os';import {fileURLToPath} from 'node:url';import {mkdtemp,mkdir,readFile,writeFile,rm,rename,symlink,realpath} from 'node:fs/promises';import {createHash} from 'node:crypto';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {reverseTask} from '../dist/reverse.js';import {openIndex} from '../dist/survey.js';import {parseReaNativeEvidence,importReaNative} from '../dist/rea-native.js';import {bridgeReaNative,assertReaBridgeObservation} from '../dist/rea-bridge.js';import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';import {relocateWorkspace} from '../dist/relocate.js';import {machoFixture} from './fixtures/macho-bridge.mjs';import {Client} from '@modelcontextprotocol/sdk/client/index.js';import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const actual=JSON.parse(await readFile(new URL('./fixtures/rea-native-bridge.json',import.meta.url),'utf8')).records,hash=b=>createHash('sha256').update(b).digest('hex'),exec=promisify(execFile);
function canonical(v){if(v===null||typeof v!=='object')return JSON.stringify(v);return Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';}
function seal(r){const {evidence_id,subject,...rest}=r;r.evidence_id='ev_'+hash(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));}
async function fixture(t,options={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-rea-bridge-')));t.after(()=>rm(root,{recursive:true,force:true}));const app=path.join(root,'app'),workspace=path.join(root,'work');for(const dir of ['bin','lib','decoy'])await mkdir(path.join(app,dir),{recursive:true});
 const images={caller:machoFixture({rpaths:options.rpaths}),library:machoFixture({library:true}),decoy:machoFixture({library:true})};images.decoy.bytes[0x300]=123;options.edit?.(images);const files={caller:'bin/quote',library:'lib/libcharge.dylib',decoy:'decoy/libcharge.dylib'},records={};for(const [name,image] of Object.entries(images))await writeFile(path.join(app,files[name]),image.bytes);
 const workspaces={caller:workspace,library:options.separate?path.join(root,'library-work'):workspace,decoy:options.separate?path.join(root,'decoy-work'):workspace},indexedFiles=Object.fromEntries(Object.entries(files).map(([key,file])=>[key,options.separate?path.basename(file):file]));
 if(options.separate){for(const name of ['caller','library','decoy'])await reverseTask(path.join(app,files[name]),{out:workspaces[name],goal:'Synthetic separate-workspace validator; not execution evidence'});}else await reverseTask(app,{out:workspace,goal:'Synthetic byte-witness validation; not execution evidence'});
 const captures=structuredClone(actual);for(const [name,group] of Object.entries(captures)){for(const r of Object.values(group)){r.subject.digest.sha256=hash(images[name].bytes);r.subject.name='Synthetic image validator, not actual decompilation';r.subject.local_path='/not/opened';seal(r);}const args={file:indexedFiles[name]};for(const [role,r] of Object.entries(group)){args[role]=path.join(root,name+'-'+role+'.json');await writeFile(args[role],JSON.stringify(r));}records[name]=await importReaNative(workspaces[name],args);}
 const run=(to='library')=>bridgeReaNative(workspace,{from:records.caller.observationId,to:records[to].observationId,stub:images.caller.stub,...(options.separate?{toWorkspace:workspaces[to]}:{})});
 const contract=bridge=>({schema:'carve/reconstruction@2',goal:'Synthetic bridge consistency check',primary:'app',artifacts:[{key:'app',file:indexedFiles.caller,evidenceIds:[records.caller.observationId],supportingEvidenceIds:[bridge.observationId]},{key:'lib',...(options.separate?{workspace:'../library-work'}:{}),file:indexedFiles.library,evidenceIds:[records.library.observationId]}],relationships:[{from:{artifact:'app',id:records.caller.observationId},to:{artifact:'lib',id:records.library.observationId},kind:'calls',basis:'reviewed-static',description:'Synthetic byte witness, not runtime/ABI proof',bridgeEvidenceId:bridge.observationId}],behavior:{description:'Validator only',inputDomain:'none',outputDomain:'zero'},dependencies:[],unknowns:['Synthetic image bytes are never executed.']});
 const pack=async(c,work=workspace)=>{await writeFile(path.join(root,'contract.json'),JSON.stringify(c));await writeFile(path.join(root,'rewrite.mjs'),'export const f=()=>0;');return reconstruct(work,{contract:path.join(root,'contract.json'),implementation:path.join(root,'rewrite.mjs'),export:'f',out:path.join(root,'package-'+Math.random())});};
 return{root,app,workspace,workspaces,indexedFiles,files,images,records,run,contract,pack};
}

test('retains actual REA cross-image capture semantic identities separately from synthetic validator bytes',()=>{
 assert.equal(parseReaNativeEvidence(actual.caller.code,'procedure_pseudo_code').evidence_id,'ev_d7b50e3daed3184b2153e6fadcce96b6320578cdaaeba5c2f6c184dbeb035d1f');assert.equal(parseReaNativeEvidence(actual.library.code,'procedure_pseudo_code').evidence_id,'ev_4b64a0ece45926f4224104037b8ca9e3d86fa4b8f80d48409e559e442be475a3');
});

test('binds direct instruction/stub/ordinal/load/export witnesses idempotently and repairs derived search',async t=>{
 const f=await fixture(t),proof=await f.run(),again=await f.run();assert.equal(proof.observationId,again.observationId);assert.equal(proof.status,'byte-bound-static-link');assert.equal(proof.callSites[0].target,f.images.caller.stub);assert.equal(proof.runtimeLoading,'unverified');assert.equal(proof.dependencyClosure,'not-established');assert.equal(proof.executesTarget,false);
 const db=openIndex(f.workspace);assert.equal(db.prepare("SELECT count(*) n FROM observations WHERE kind='native-bridge'").get().n,1);db.prepare('DELETE FROM observation_search WHERE id=?').run(proof.observationId);db.close();await f.run();const restored=openIndex(f.workspace,true);assert.equal(restored.prepare('SELECT count(*) n FROM observation_search WHERE id=?').get(proof.observationId).n,1);restored.close();
});

test('rejects same-name, same-install-name and same-export-address decoys at a different local path',async t=>{
 const f=await fixture(t);await assert.rejects(f.run('decoy'),/exact local lexical load-path/);assert.equal((await f.run()).to.file,f.files.library);
});

test('fails closed on unknown/multiple rpaths, flat namespaces, weak ordinals and modified original call bytes',async t=>{
 const options=[{rpaths:[]},{rpaths:['@loader_path/../lib','@loader_path/../decoy']},{rpaths:['@rpath/inherited']},{edit:x=>x.caller.bytes.writeUInt32LE(0x105,24)},{edit:x=>x.caller.bytes.writeUInt16LE(0x200,0x806)},{edit:x=>x.caller.bytes.writeUInt32LE(0x94000001,x.caller.layout.call)}];for(const o of options){const f=await fixture(t,o);await assert.rejects(f.run());}
});

test('refuses stale endpoint bytes and edited normalized REA call evidence',async t=>{
 const f=await fixture(t),original=await readFile(path.join(f.app,f.files.library));await writeFile(path.join(f.app,f.files.library),Buffer.concat([original,Buffer.from([1])]));await assert.rejects(f.run(),/changed|differs|stale/i);await writeFile(path.join(f.app,f.files.library),original);
 const db=openIndex(f.workspace),row=db.prepare('SELECT detail FROM observations WHERE id=?').get(f.records.caller.observationId),detail=JSON.parse(row.detail);detail.callees[0].callSites=[];db.prepare('UPDATE observations SET detail=? WHERE id=?').run(JSON.stringify(detail),f.records.caller.observationId);db.close();await assert.rejects(f.run(),/captured complete/);
});

test('multi-artifact packaging requires the exact declared bridge endpoints and support binding',async t=>{
 const f=await fixture(t),proof=await f.run(),c=f.contract(proof),result=await f.pack(c);assert.equal(result.relationships[0].staticBridge.symbol,'_carve_duration_charge');assert.equal(result.relationships[0].semanticMatch,'unconfirmed');assert.equal(result.relationships[0].staticBridge.runtimeLoading,'unverified');
 for(const edit of [x=>delete x.relationships[0].bridgeEvidenceId,x=>{x.artifacts[0].supportingEvidenceIds=[];},x=>{x.relationships[0].basis='hypothesis';},x=>{x.relationships[0].kind='loads';},x=>{x.artifacts[1].file=f.files.decoy;x.artifacts[1].evidenceIds=[f.records.decoy.observationId];x.relationships[0].to.id=f.records.decoy.observationId;}]){const bad=structuredClone(c);edit(bad);await assert.rejects(f.pack(bad),/bridge|Bridge/);}
 const single={schema:'carve/reconstruction@1',goal:c.goal,file:f.files.caller,evidenceIds:[f.records.caller.observationId],supportingEvidenceIds:[proof.observationId],behavior:c.behavior,dependencies:[],unknowns:c.unknowns};await assert.rejects(f.pack(single),/explicit multi-artifact/);
});

test('rejects bridge snapshot/SQL edits even after origin labels and snapshot paths are relabeled',async t=>{
 const f=await fixture(t),proof=await f.run(),c=f.contract(proof),bytes=await readFile(proof.evidence);await writeFile(proof.evidence,Buffer.concat([bytes,Buffer.from(' ')]));await assert.rejects(f.pack(c),/evidence changed|snapshot changed/);await writeFile(proof.evidence,bytes);
 const db=openIndex(f.workspace),r=db.prepare('SELECT detail FROM observations WHERE id=?').get(proof.observationId),detail=JSON.parse(r.detail);delete detail.bridge;detail.provider={name:'other'};const renamed=path.join(f.root,'relabeled.json');await writeFile(renamed,bytes);db.prepare('UPDATE observations SET detail=?,evidence=? WHERE id=?').run(JSON.stringify(detail),renamed,proof.observationId);db.close();await assert.rejects(f.pack(c),/differs from its retained/);
});

test('owned support survives missing producer files and workspace relocation',async t=>{
 const f=await fixture(t),proof=await f.run(),c=f.contract(proof);for(const name of ['caller','library','decoy'])for(const role of ['code','info','callees','references'])await rm(path.join(f.root,name+'-'+role+'.json'));const moved=path.join(f.root,'moved');await rename(f.workspace,moved);await relocateWorkspace(moved);assert.equal((await f.pack(c,moved)).relationships[0].staticBridge.runtimeLoading,'unverified');
});

test('actual CLI/MCP create the bridge, confine roots and refuse symlink support storage',async t=>{
 const f=await fixture(t),cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url)),args={workspace:'work',from:f.records.caller.observationId,to:f.records.library.observationId,stub:f.images.caller.stub};const result=await exec(process.execPath,[cli,'bridge-rea-native',f.workspace,'--from',args.from,'--to',args.to,'--stub',args.stub]);assert.equal(JSON.parse(result.stdout).status,'byte-bound-static-link');
 const client=new Client({name:'rea-bridge-confinement-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());const good=await client.callTool({name:'carve_bridge_rea_native',arguments:args});assert.ok(!good.isError);assert.equal(JSON.parse(good.content[0].text).observationId,JSON.parse(result.stdout).observationId);assert.equal((await client.callTool({name:'carve_bridge_rea_native',arguments:{...args,workspace:'../'}})).isError,true);
 const other=await fixture(t),outside=path.join(other.root,'elsewhere');await mkdir(outside);await symlink(outside,path.join(other.workspace,'rea-bridge-evidence'));await assert.rejects(other.run(),/symlink/);
});

test('bridge endpoints cannot be demoted to support-only IDs while another code record fills implementation',async t=>{
 const f=await fixture(t),proof=await f.run(),c=f.contract(proof),code=path.join(f.root,'caller-code.json');await writeFile(code,' '+await readFile(code,'utf8'));
 const another=await importReaNative(f.workspace,{file:f.files.caller,...Object.fromEntries(['code','info','callees','references'].map(role=>[role,path.join(f.root,'caller-'+role+'.json')]))});assert.notEqual(another.observationId,f.records.caller.observationId);c.artifacts[0].evidenceIds=[another.observationId];c.artifacts[0].supportingEvidenceIds.push(f.records.caller.observationId);await assert.rejects(f.pack(c),/exact declared caller\/callee implementation/);
});

test('cross-workspace bridge binds each endpoint namespace without copying records and keeps legacy IDs',async t=>{
 const f=await fixture(t,{separate:true}),proof=await f.run();assert.equal(proof.schema,'carve/rea-bridge-result@2');assert.equal(proof.from.workspace,'.');assert.equal(proof.to.workspace,'../library-work');assert.equal(proof.to.file,'libcharge.dylib');
 assert.equal((await f.run()).observationId,proof.observationId);const raw=JSON.parse(await readFile(proof.evidence,'utf8'));assert.equal(raw.schema,'carve/rea-bridge@2');assert.equal(raw.toWorkspace,'../library-work');
 const caller=openIndex(f.workspace,true);assert.equal(caller.prepare('SELECT 1 FROM observations WHERE id=?').get(f.records.library.observationId),undefined);caller.close();
 const packaged=await f.pack(f.contract(proof));assert.equal(packaged.relationships[0].staticBridge.symbol,'_carve_duration_charge');assert.equal(packaged.artifacts[1].workspace,f.workspaces.library);
 const same=await fixture(t),legacy=await same.run(),again=await bridgeReaNative(same.workspace,{from:same.records.caller.observationId,to:same.records.library.observationId,stub:same.images.caller.stub,toWorkspace:'.'});assert.equal(legacy.observationId,again.observationId);assert.equal(legacy.schema,'carve/rea-bridge-result@1');assert.equal(Object.hasOwn(JSON.parse(await readFile(legacy.evidence,'utf8')),'toWorkspace'),false);
});

test('cross-workspace decoys, undeclared indexes and redirected authorization never become contract endpoints',async t=>{
 const f=await fixture(t,{separate:true});await assert.rejects(f.run('decoy'),/exact local lexical load-path/);const proof=await f.run(),contract=f.contract(proof);
 // Identical bytes/records in a second index do not substitute the declared workspace.
 const alias=path.join(f.root,'same-input-work');await reverseTask(path.join(f.app,f.files.library),{out:alias,goal:'Synthetic duplicate index, not another image'});
 const args={file:f.indexedFiles.library,...Object.fromEntries(['code','info','callees','references'].map(role=>[role,path.join(f.root,'library-'+role+'.json')]))};const copied=await importReaNative(alias,args);assert.equal(copied.observationId,f.records.library.observationId);
 const bad=structuredClone(contract);bad.artifacts[1].workspace='../same-input-work';await assert.rejects(f.pack(bad),/explicitly declared/);
 await assert.rejects(()=>bridgeReaNative(f.workspace,{from:f.records.caller.observationId,to:f.records.library.observationId,toWorkspace:f.workspaces.library,stub:f.images.caller.stub,authorizeWorkspace:async input=>input===f.workspaces.library?alias:input}),/preserve.*identity/);
});

test('both endpoint source/evidence revisions are rebound during packaging and verification',async t=>{
 const f=await fixture(t,{separate:true}),proof=await f.run(),contract=f.contract(proof),pkg=await f.pack(contract),reference=path.join(f.root,'reference.json'),cases=path.join(f.root,'cases.json');
 await writeFile(reference,JSON.stringify({schema:'carve/reference@1',command:[process.execPath,'-e','console.log(0)'],mode:'argv-values',scope:'external-harness',description:'Owned echo only; synthetic Mach-O fixtures are not executed.',boundFiles:[]}));await writeFile(cases,JSON.stringify([{name:'synthetic transport only',args:[],expected:0}]));const options={package:pkg.out,cases,reference,execute:true};assert.equal((await verifyReconstruction(f.workspace,options)).status,'passed-supplied-cases');
 const library=openIndex(f.workspaces.library),row=library.prepare('SELECT * FROM observations WHERE id=?').get(f.records.library.observationId);library.close();
 const bytes=await readFile(row.evidence);await writeFile(row.evidence,Buffer.concat([bytes,Buffer.from(' ')]));await assert.rejects(f.pack(contract),/snapshot|evidence changed/);await assert.rejects(()=>verifyReconstruction(f.workspace,options),/snapshot|evidence changed/);await writeFile(row.evidence,bytes);
 const file=path.join(f.app,f.files.library),original=await readFile(file);await writeFile(file,Buffer.concat([original,Buffer.from([1])]));await assert.rejects(f.pack(contract),/changed|stale/);await assert.rejects(()=>verifyReconstruction(f.workspace,options),/changed|stale/);
});

test('cross-workspace snapshots cannot be relabeled, repointed or backed by modified endpoint rows',async t=>{
 const f=await fixture(t,{separate:true}),proof=await f.run(),contract=f.contract(proof),db=openIndex(f.workspace),row=db.prepare('SELECT * FROM observations WHERE id=?').get(proof.observationId);db.close();
 const bytes=await readFile(proof.evidence);await writeFile(proof.evidence,Buffer.concat([bytes,Buffer.from(' ')]));await assert.rejects(f.pack(contract),/snapshot changed|evidence changed/);await writeFile(proof.evidence,bytes);
 const moved=path.join(f.root,'other-name.json');await writeFile(moved,bytes);const edit=openIndex(f.workspace),detail=JSON.parse(row.detail);delete detail.bridge;detail.provider={name:'other'};edit.prepare('UPDATE observations SET detail=?,evidence=? WHERE id=?').run(JSON.stringify(detail),moved,proof.observationId);edit.close();await assert.rejects(f.pack(contract),/differs from its retained/);
 const target=openIndex(f.workspaces.library),record=target.prepare('SELECT * FROM observations WHERE id=?').get(f.records.library.observationId);target.prepare('UPDATE observations SET name=? WHERE id=?').run('renamed',record.id);target.close();await assert.rejects(f.run(),/differs from the captured/);
});

test('moving both workspaces with their parent preserves relative bridge commitments after explicit relocation',async t=>{
 const f=await fixture(t,{separate:true}),proof=await f.run(),contract=f.contract(proof),original=await readFile(proof.evidence);const moved=f.root+'-moved';await rename(f.root,moved);t.after(()=>rm(moved,{recursive:true,force:true}));
 for(const name of ['work','library-work','decoy-work'])await relocateWorkspace(path.join(moved,name));
 const workspace=path.join(moved,'work'),db=openIndex(workspace,true),row=db.prepare('SELECT * FROM observations WHERE id=?').get(proof.observationId);db.close();assert.deepEqual(await readFile(row.evidence),original);assert.equal((await assertReaBridgeObservation(row,workspace)).to.workspace,'../library-work');
 await writeFile(path.join(moved,'contract.json'),JSON.stringify(contract));await writeFile(path.join(moved,'rewrite.mjs'),'export const f=()=>0;');const packaged=await reconstruct(workspace,{contract:path.join(moved,'contract.json'),implementation:path.join(moved,'rewrite.mjs'),export:'f',out:path.join(moved,'new-package')});assert.equal(packaged.artifacts[1].workspace,path.join(moved,'library-work'));
});

test('cross-workspace CLI and MCP resolve toWorkspace against caller and require both roots',async t=>{
 const f=await fixture(t,{separate:true}),cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url)),args={workspace:'work',from:f.records.caller.observationId,to:f.records.library.observationId,stub:f.images.caller.stub,toWorkspace:'../library-work'};
 const result=JSON.parse((await exec(process.execPath,[cli,'bridge-rea-native',f.workspace,'--from',args.from,'--to',args.to,'--stub',args.stub,'--to-workspace',args.toWorkspace],{cwd:tmpdir()})).stdout);assert.equal(result.schema,'carve/rea-bridge-result@2');
 const client=new Client({name:'cross-workspace-root-test',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());const good=await client.callTool({name:'carve_bridge_rea_native',arguments:args});assert.ok(!good.isError);assert.equal(JSON.parse(good.content[0].text).observationId,result.observationId);
 const n=await fixture(t,{separate:true}),allowed=path.join(n.root,'allowed'),callerWork=path.join(allowed,'work'),callerInput=path.join(allowed,'input/quote');await mkdir(path.dirname(callerInput),{recursive:true});await rename(n.workspace,callerWork);await rename(path.join(n.app,n.files.caller),callerInput);await relocateWorkspace(callerWork,{target:callerInput});
 const narrow=new Client({name:'caller-only-root-test',version:'1'});await narrow.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',allowed],stderr:'pipe'}));t.after(()=>narrow.close());assert.ok(!(await narrow.callTool({name:'carve_index',arguments:{workspace:'work'}})).isError);const denied=await narrow.callTool({name:'carve_bridge_rea_native',arguments:{workspace:'work',from:n.records.caller.observationId,to:n.records.library.observationId,stub:n.images.caller.stub,toWorkspace:'../../library-work'}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
 const outside=await fixture(t,{separate:true}),alias=path.join(f.root,'outside-workspace');await symlink(outside.workspaces.library,alias);const symlinkDenied=await client.callTool({name:'carve_bridge_rea_native',arguments:{...args,toWorkspace:'../outside-workspace'}});assert.equal(symlinkDenied.isError,true);assert.match(symlinkDenied.content[0].text,/outside/);
});

test('MCP reconstruction and verification reject foreign endpoint evidence and SQLite symlinks',async t=>{
 const f=await fixture(t,{separate:true}),proof=await f.run(),contract=f.contract(proof),pkg=await f.pack(contract),cli=fileURLToPath(new URL('../dist/cli.js',import.meta.url));
 const reference=path.join(f.root,'reference.json'),cases=path.join(f.root,'cases.json');await writeFile(reference,JSON.stringify({schema:'carve/reference@1',command:[process.execPath,'-e','console.log(0)'],mode:'argv-values',scope:'external-harness',description:'Synthetic echo only',boundFiles:[]}));await writeFile(cases,JSON.stringify([{name:'not-original-execution',args:[],expected:0}]));
 const outside=await fixture(t,{separate:true}),target=openIndex(f.workspaces.library),row=target.prepare('SELECT * FROM observations WHERE id=?').get(f.records.library.observationId);await writeFile(path.join(outside.root,'foreign.json'),await readFile(row.evidence));target.prepare('UPDATE observations SET evidence=? WHERE id=?').run(path.join(outside.root,'foreign.json'),row.id);target.close();
 const client=new Client({name:'cross-workspace-evidence-confinement',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const pack=await client.callTool({name:'carve_reconstruct',arguments:{workspace:'work',contract:'contract.json',implementation:'rewrite.mjs',export:'f',out:'forbidden-package'}});assert.equal(pack.isError,true);assert.match(pack.content[0].text,/outside/);
 const verify=await client.callTool({name:'carve_verify_reconstruction',arguments:{workspace:'work',package:pkg.out,cases,reference,execute:true}});assert.equal(verify.isError,true);assert.match(verify.content[0].text,/outside/);
 await rename(path.join(f.workspaces.library,'index.sqlite'),path.join(f.workspaces.library,'index-saved.sqlite'));await symlink(path.join(outside.workspaces.library,'index.sqlite'),path.join(f.workspaces.library,'index.sqlite'));
 const bridge=await client.callTool({name:'carve_bridge_rea_native',arguments:{workspace:'work',from:f.records.caller.observationId,to:f.records.library.observationId,stub:f.images.caller.stub,toWorkspace:'../library-work'}});assert.equal(bridge.isError,true);assert.match(bridge.content[0].text,/outside/);
});
