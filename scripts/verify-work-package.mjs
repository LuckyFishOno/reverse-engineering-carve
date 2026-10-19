// Local task preparation through actual CLI and two independent MCP connections.
// Synthetic declarations only: no original source, dispatched agents or target execution.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdtemp,readFile,writeFile,cp,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile),cli=path.join(root,'dist/cli.js'),out=await mkdtemp(path.join(root,'artifacts/work-package-e2e-'));
const save=(name,data)=>writeFile(path.join(out,name),JSON.stringify(data,null,2)+'\n'),sha=b=>createHash('sha256').update(b).digest('hex');
for(const name of ['work-plan.json','work-spec.json'])await cp(path.join(root,'examples',name),path.join(out,name));
const peers=[];let client;let diagnostics='';
async function connect(){const peer=new Client({name:'carve-work-package-integration',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',out],stderr:'pipe'});transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-8000);});await peer.connect(transport);peers.push(transport.pid);return peer;}
async function call(args){const response=await client.callTool({name:'carve_work_package',arguments:args});if(response.isError)throw new Error(response.content[0].text);const value=JSON.parse(response.content[0].text);assert.equal(value.receipt.responseBytes,Buffer.byteLength(response.content[0].text));return value;}
try{
 const raw=(await exec(process.execPath,[cli,'work-package','create',path.join(out,'work-plan.json'),path.join(out,'work-spec.json'),'--feature','model','--out',path.join(out,'model'),'--budget-bytes','4096'])).stdout,model=JSON.parse(raw);assert.equal(model.receipt.responseBytes,Buffer.byteLength(raw)-1);
 client=await connect();assert.equal((await client.listTools()).tools.length,48);
 const parser=await call({action:'create',plan:'work-plan.json',spec:'work-spec.json',feature:'parser',out:'parser',budgetBytes:4096}),storage=await call({action:'create',plan:'work-plan.json',spec:'work-spec.json',feature:'storage',out:'storage',budgetBytes:4096}),ui=await call({action:'create',plan:'work-plan.json',spec:'work-spec.json',feature:'ui',out:'ui',budgetBytes:4096});
 const packages=[model,parser,storage,ui],records=[];for(const entry of packages){assert.deepEqual((await readdir(entry.package)).sort(),['TASK.md','manifest.json','work.json']);const bytes=await readFile(entry.recordFile);assert.equal(sha(bytes),entry.id);records.push(JSON.parse(bytes));await save(entry.feature+'-summary.json',entry);}
 assert.equal(records[1].dependencies[0].contractSha256,records[0].interface.sha256);assert.equal(records[2].dependencies[0].contractSha256,records[0].interface.sha256);assert.deepEqual(records[3].dependencies.map(d=>d.feature),['parser','storage']);
 const allFiles=records.flatMap(r=>r.assignment.files);assert.equal(new Set(allFiles).size,8);for(const r of records){assert.equal(r.verification,'not-run');assert.equal(r.targetAssessment,'not-performed');assert.equal(r.startsAgents,false);assert.equal(r.dependencyImplementation,'not-established');}
 await client.close();client=await connect();assert.equal((await call({action:'check',package:'parser',plan:'work-plan.json',spec:'work-spec.json'})).id,parser.id);
 let offset=0,text='',pageBytes=[];do{const page=await call({action:'read',package:'parser',view:'record',offset,characters:12000,budgetBytes:2048});assert.ok(page.receipt.responseBytes<=2048);text+=page.text;pageBytes.push(page.receipt.responseBytes);offset=page.nextOffset;}while(offset!==null);assert.deepEqual(JSON.parse(text),records[1]);
 const plan=JSON.parse(await readFile(path.join(out,'work-plan.json'),'utf8')),spec=JSON.parse(await readFile(path.join(out,'work-spec.json'),'utf8'));
 const declaredPlanBytes=Buffer.byteLength(JSON.stringify(plan)),declaredSpecBytes=Buffer.byteLength(JSON.stringify(spec));
 plan.features[0].contract.errors+=' Added error variant.';await save('changed-plan.json',plan);
 const stale=await client.callTool({name:'carve_work_package',arguments:{action:'check',package:'parser',plan:'changed-plan.json',spec:'work-spec.json'}});assert.equal(stale.isError,true);assert.match(stale.content[0].text,/Stale planId/);
 const conflict=structuredClone(spec);conflict.assignments[1].files=[conflict.assignments[0].files[0].toUpperCase()];await save('conflicting-spec.json',conflict);const denied=await client.callTool({name:'carve_work_package',arguments:{action:'create',plan:'work-plan.json',spec:'conflicting-spec.json',feature:'parser',out:'conflicting'}});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/Overlapping/);assert.ok(!(await readdir(out)).includes('conflicting'));
 for(const entry of packages)assert.equal(sha(await readFile(entry.recordFile)),entry.id);
 const comparison={declaredPlanBytes,declaredSpecBytes,selectedRecordBytes:Buffer.byteLength(text),summaryBytes:parser.receipt.responseBytes,recordPageBytes:pageBytes,measurement:'Actual UTF8 bytes for the original plan/spec revision used to create these synthetic packages; no model tokenizer, billing estimate or general savings percentage.'};
 const report={schema:'carve/work-package-check@1',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,status:'passed',checkedAt:new Date().toISOString(),out,
  taskPreparation:{planId:model.planId,specId:model.specId,features:packages.map(p=>({feature:p.feature,id:p.id,package:p.package})),completeInterfacesPinned:true,sharedDependencyPinsMatched:true,declaredEditableFiles:8,immutableHistoricalRecords:true,stalePlanRejected:true,caseAliasedOwnershipRejectedBeforeWrite:true,freshMcpReadAndCurrentCheck:true,utf16RecordRoundTrip:true},comparison,
  architecture:{carveTools:48,carvePeers:peers,reaStarted:false,agentsDispatched:false,targetExecuted:false},
  limitations:['Synthetic agent-authored declarations, not a recovered feature inventory.','Ownership is a declaration, not filesystem enforcement or a persistent claim.','Source/evidence references are unopened and unauthenticated.','Dependency implementation, acceptance execution, cross-task assembly and OS app build are not established.']};
 await save('report.json',report);await writeFile(path.join(root,'artifacts/work-package-verification-summary.json'),JSON.stringify({status:'passed',version:report.version,report:path.join(out,'report.json')},null,2)+'\n');console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json')}));
}catch(error){await save('failure.json',{message:error.stack,diagnostics});throw error;}finally{await client?.close().catch(()=>{});await save('diagnostics.json',{diagnostics});}
