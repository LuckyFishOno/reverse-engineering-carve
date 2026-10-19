// New intent and graph checks on retained real APK evidence; no new target execution.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdtemp,readFile,writeFile,cp} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {hashFile} from '../dist/survey.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),artifacts=path.join(root,'artifacts'),exec=promisify(execFile);
const prior=JSON.parse(await readFile(path.join(artifacts,'feature-scope-e2e-J2KZla/report.json'),'utf8'));
assert.equal(prior.version,'0.35.0');
const workspace=path.join(prior.out,'work'),legacyFile=path.join(workspace,'feature-requests',prior.workflow.scopeId+'.json'),legacy=await readFile(legacyFile),record=JSON.parse(legacy);
assert.equal(Object.hasOwn(record.request,'target'),false);
const out=await mkdtemp(path.join(artifacts,'project-intent-e2e-')),save=(file,value)=>writeFile(path.join(out,file),JSON.stringify(value,null,2)+'\n');
// Resolve the original DEX through its retained inventory, not a guessed container path.
const {indexedFile}=await import('../dist/survey.js');const selected=await indexedFile(workspace,'classes.dex');
const before={apk:(await hashFile(prior.input.file)).sha256,dex:(await hashFile(selected.path)).sha256};assert.equal(before.dex,prior.input.dexSha256);
let client;const peers=[];let diagnostics='';
async function connect(){const peer=new Client({name:'carve-project-intent-integration',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',artifacts],stderr:'pipe'});transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-8000);});await peer.connect(transport);peers.push(transport.pid);return peer;}
const call=async(name,args)=>{const result=await client.callTool({name,arguments:args});if(result.isError)throw new Error(result.content[0].text);return result.structuredContent??JSON.parse(result.content[0].text);};
try{
 client=await connect();assert.equal((await client.listTools()).tools.length,48);
 const old=await call('carve_scope',{workspace:path.relative(artifacts,workspace),id:prior.workflow.scopeId});assert.equal(Object.hasOwn(old,'target'),false);assert.equal(old.id,prior.workflow.scopeId);
 const targets=[];let parentId=prior.workflow.scopeId;
 for(const platform of ['windows','macos','browser']){
  const request={...record.request,target:{schema:'carve/target@1',platform,delivery:'module'}};
  const result=await call('carve_scope',{workspace:path.relative(artifacts,workspace),request,parentId});assert.equal(result.targetAssessment,'not-performed');assert.equal(result.verification,'not-run');assert.equal(result.sourceIdentityCheck,'selected-input-hashes-checked-during-this-write');assert.equal(result.receipt.responseBytes,Buffer.byteLength(JSON.stringify(result)));
  targets.push({platform,id:result.id,parentId});parentId=result.id;await save('target-'+platform+'.json',result);
 }
 await cp(path.join(root,'examples/project-plan.json'),path.join(out,'plan.json'));
 const first=await call('carve_project_plan',{plan:path.relative(artifacts,path.join(out,'plan.json')),limit:2,budgetBytes:4096});assert.equal(first.summary.features,4);assert.equal(first.summary.phases,3);
 await client.close();client=await connect();const last=await call('carve_project_plan',{plan:path.relative(artifacts,path.join(out,'plan.json')),offset:first.nextOffset,limit:2,budgetBytes:4096});assert.equal(last.planId,first.planId);assert.equal(last.nextOffset,null);assert.deepEqual([...first.items,...last.items].map(x=>x.id),['model','parser','storage','ui']);
 const resumed=await call('carve_scope',{workspace:path.relative(artifacts,workspace),id:targets.at(-1).id});assert.equal(resumed.target.platform,'browser');assert.equal(resumed.sourceIdentityCheck,'recorded-only-no-current-source-check');assert.equal(resumed.targetAssessment,'not-performed');
 const raw=(await exec(process.execPath,[path.join(root,'dist/cli.js'),'project-plan',path.join(out,'plan.json'),'--limit','2','--budget-bytes','4096'])).stdout;assert.equal(JSON.parse(raw).planId,first.planId);assert.equal(JSON.parse(raw).receipt.responseBytes,Buffer.byteLength(raw)-1);
 const cycle=JSON.parse(await readFile(path.join(out,'plan.json'),'utf8'));cycle.features.find(x=>x.id==='parser').dependsOn=['storage'];cycle.features.find(x=>x.id==='storage').dependsOn=['parser'];await save('cycle.json',cycle);
 const blocked=await call('carve_project_plan',{plan:path.relative(artifacts,path.join(out,'cycle.json'))});assert.equal(blocked.summary.inCycle,2);assert.equal(blocked.summary.blocked,1);assert.equal(blocked.summary.ready,1);
 assert.deepEqual(await readFile(legacyFile),legacy);assert.deepEqual({apk:(await hashFile(prior.input.file)).sha256,dex:(await hashFile(selected.path)).sha256},before);
 await save('plan-first.json',first);await save('plan-last.json',last);await save('cycle-result.json',blocked);
 const report={schema:'carve/project-intent-check@1',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,status:'passed',checkedAt:new Date().toISOString(),out,
  legacy:{version:prior.version,report:path.join(prior.out,'report.json'),id:prior.workflow.scopeId,scopeBytesUnchanged:true,oldTargetAbsent:true},
  retainedSources:{...before,originalInputsRetained:true,unchangedAfter:true,reanalyzed:false,newIntentRecordsAppendedToOwnedWorkspace:workspace},
  targets:{records:targets,assessment:'not-performed',behaviorVerification:'not-run',freshSelectedSourceHashes:true,historicalResume:true},
  declaredGraph:{planId:first.planId,features:4,phases:3,pages:2,cycleMembers:2,downstreamBlocked:1,cliMcpIdentityMatched:true,automaticallyDiscovered:false},
  architecture:{carveTools:48,carvePeers:peers,reaStarted:false,enginesStarted:false,agentsDispatched:false,targetExecuted:false},
  scope:'Intent persistence, old record compatibility and agent-declared graph ordering. No Windows/Mac/browser build, full software port or new original-runtime equivalence claim.'};
 await save('report.json',report);await writeFile(path.join(artifacts,'project-intent-verification-summary.json'),JSON.stringify({status:'passed',version:report.version,report:path.join(out,'report.json')},null,2)+'\n');console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json')}));
}catch(error){await save('failure.json',{message:error.stack,diagnostics});throw error;}finally{await client?.close().catch(()=>{});await save('diagnostics.json',{diagnostics});}
