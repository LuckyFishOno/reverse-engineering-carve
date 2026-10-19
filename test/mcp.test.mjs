import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm, symlink, readFile, mkdir, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

test('actual stdio MCP inspects, plans, extracts and confines the workspace', async t => {
  const root = await mkdtemp(path.join(tmpdir(), 'carve-mcp-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'app.mjs'), 'const scale=2;export function double(x){return x*scale}');
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../dist/cli.js', import.meta.url)), 'serve', '--root', root], stderr: 'pipe' });
  const client = new Client({ name: 'carve-integration-test', version: '1.0.0' });
  await client.connect(transport); t.after(() => client.close());
  // Observe public transport messages in wire order. The SDK schedules its
  // progress callback asynchronously, so a final notification and response in
  // the same read can remove the callback before it runs. Verify the server's
  // actual protocol ordering rather than depending on that client scheduling.
  const wire=[];const receive=transport.onmessage;transport.onmessage=(message,extra)=>{wire.push(message);receive?.(message,extra);};
  let queueRequestId;const send=transport.send.bind(transport);transport.send=(message,options)=>{if(message.method==='tools/call'&&message.params?.name==='carve_analysis_run')queueRequestId=message.id;return send(message,options);};
  assert.deepEqual((await client.listTools()).tools.map(t => t.name), ['carve_locate', 'carve_start', 'carve_use', 'carve_invoke', 'carve_feature_check', 'carve_discover', 'carve_inspect', 'carve_plan', 'carve_extract', 'carve_invoke_sequence', 'carve_probe', 'carve_contrast', 'carve_run', 'carve_reverse', 'carve_features', 'carve_scope', 'carve_project_plan', 'carve_work_package', 'carve_work_ledger', 'carve_platform', 'carve_survey', 'carve_import_rea_native', 'carve_bridge_rea_native', 'carve_relocate', 'carve_index', 'carve_native', 'carve_links', 'carve_loader', 'carve_manifest', 'carve_jni', 'carve_library_add', 'carve_library_find', 'carve_library_get', 'carve_context', 'carve_managed', 'carve_search', 'carve_observation', 'carve_trace', 'carve_reconstruct', 'carve_verify_reconstruction', 'carve_verification', 'carve_unpack','carve_analysis_enqueue','carve_analysis_jobs','carve_analysis_run','carve_analysis_start','carve_analysis_runs','carve_analysis_cancel']);
  const reversed=await client.callTool({name:'carve_reverse',arguments:{target:'app.mjs',goal:'double a number',out:'reverse-work'}});
  assert.equal(JSON.parse(reversed.content[0].text).status,'ready-for-analysis');
  const suggestions=await client.callTool({name:'carve_features',arguments:{workspace:'reverse-work',query:'unknown remote operation'}});
  assert.equal(JSON.parse(suggestions.content[0].text).status,'needs-more-evidence');
  const menuStart=await client.callTool({name:'carve_reverse',arguments:{target:'app.mjs',out:'reverse-work'}});
  assert.equal(JSON.parse(menuStart.content[0].text).status,'awaiting-feature-choice');
  const escapedMenu=await client.callTool({name:'carve_features',arguments:{workspace:'../'}});assert.equal(escapedMenu.isError,true);
  const indexed=await client.callTool({name:'carve_index',arguments:{workspace:'reverse-work'}});
  assert.equal(JSON.parse(indexed.content[0].text).items[0].format,'javascript');
  const queued=await client.callTool({name:'carve_analysis_enqueue',arguments:{workspace:'reverse-work',requests:[{file:'app.mjs'}]}});const job=JSON.parse(queued.content[0].text).items[0];assert.equal(job.status,'queued');
  const worked=await client.callTool({name:'carve_analysis_run',arguments:{workspace:'reverse-work'}},undefined,{onprogress:()=>{}});assert.equal(JSON.parse(worked.content[0].text).items[0].status,'completed');
  const progress=wire.filter(m=>m.method==='notifications/progress'&&m.params.progressToken===queueRequestId);assert.deepEqual(progress.map(m=>JSON.parse(m.params.message).phase),['job-started','job-finished']);assert.ok(progress.every(m=>JSON.parse(m.params.message).id===job.id));
  assert.ok(wire.indexOf(progress[1])<wire.findIndex(m=>m.id===queueRequestId&&m.result),'final job notification precedes its completed response on the wire');
  const recorded=await client.callTool({name:'carve_analysis_jobs',arguments:{workspace:'reverse-work',id:job.id}});assert.equal(JSON.parse(recorded.content[0].text).attempts[0].status,'completed');
  const missingEngine=await client.callTool({name:'carve_native',arguments:{workspace:'reverse-work',file:'app.mjs'}});
  assert.equal(missingEngine.isError,true);assert.match(missingEngine.content[0].text,/--engines/);
  const located = await client.callTool({name:'carve_locate',arguments:{target:'app.mjs'}});
  assert.equal(JSON.parse(located.content[0].text).status,'located');
  const started = await client.callTool({name:'carve_start',arguments:{target:'app.mjs',goal:'double a number',out:'task'}});
  assert.equal(JSON.parse(started.content[0].text).status,'draft-created');
  const discovered = await client.callTool({ name: 'carve_discover', arguments: { target: 'app.mjs', query: 'double' } });
  assert.equal(JSON.parse(discovered.content[0].text).candidates[0].selector.name, 'double');
  const inspect = await client.callTool({ name: 'carve_inspect', arguments: { target: 'app.mjs' } });
  assert.equal(JSON.parse(inspect.content[0].text).exports[0].name, 'double');
  const planned = await client.callTool({ name: 'carve_plan', arguments: { target: 'app.mjs', kind: 'export', name: 'double' } });
  assert.equal(JSON.parse(planned.content[0].text).plan.status, 'extractable');
  const extracted = await client.callTool({ name: 'carve_extract', arguments: { target: 'app.mjs', kind: 'export', name: 'double', out: 'output' } });
  assert.equal(JSON.parse(extracted.content[0].text).status, 'extracted');
  assert.match(await readFile(path.join(root, 'output/index.mjs'), 'utf8'), /as capability/);
  await writeFile(path.join(root,'feature.json'),JSON.stringify({schema:'carve/feature@1',title:'double',description:'double a number',
    target:{path:'app.mjs'},steps:['Use double'],acceptance:['Twice the number'],searchTerms:['double'],examples:[{name:'two',args:[2],expected:4}]}));
  const run = await client.callTool({ name:'carve_run',arguments:{target:'app.mjs',feature:'feature.json',execute:true,out:'automated'} });
  assert.equal(JSON.parse(run.content[0].text).status,'completed-for-supplied-examples');
  const used = await client.callTool({name:'carve_use',arguments:{package:'automated'}});
  assert.deepEqual(JSON.parse(used.content[0].text).example.args,[2]);
  const invoked = await client.callTool({name:'carve_invoke',arguments:{package:'automated',args:[9],execute:true}});
  assert.deepEqual(invoked.structuredContent,{value:18});
  const deniedInvoke = await client.callTool({name:'carve_invoke',arguments:{package:'automated',args:[9],execute:false}});
  assert.equal(deniedInvoke.isError,true);
  const unauthorized = await client.callTool({name:'carve_probe',arguments:{target:'app.mjs',feature:'feature.json',execute:false}});
  assert.equal(unauthorized.isError,true);
  await writeFile(path.join(root,'ambiguous.mjs'),'export const doubleA=x=>x*2;export const doubleB=x=>x+2;');
  const contrasted = await client.callTool({name:'carve_contrast',arguments:{target:'ambiguous.mjs',feature:'feature.json',execute:true,maxProbes:2}});
  assert.equal(JSON.parse(contrasted.content[0].text).status,'needs-observation');
  const deniedContrast = await client.callTool({name:'carve_contrast',arguments:{target:'ambiguous.mjs',feature:'feature.json',execute:false}});
  assert.equal(deniedContrast.isError,true);
  await symlink(tmpdir(), path.join(root, 'escape'));
  const escaped = await client.callTool({ name: 'carve_extract', arguments: { target: 'app.mjs', kind: 'export', name: 'double', out: 'escape/should-not-exist' } });
  assert.equal(escaped.isError, true); assert.match(escaped.content[0].text, /outside/);
  const outside = await client.callTool({ name: 'carve_inspect', arguments: { target: '../outside.mjs' } });
  assert.equal(outside.isError, true);
});
test('actual stdio inventory supports directory budgets, progress notifications and cancellation checkpoints',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-mcp-survey-'));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input');await mkdir(input);
 for(let i=0;i<5;i++)await mkdir(path.join(input,`empty-${i}`));
 const transport=new StdioClientTransport({command:process.execPath,args:[fileURLToPath(new URL('../dist/cli.js',import.meta.url)),'serve','--root',root],stderr:'pipe'});
 const client=new Client({name:'inventory-test',version:'1'});await client.connect(transport);t.after(()=>client.close());
 const progress=[];
 const first=await client.callTool({name:'carve_reverse',arguments:{target:'input',goal:'Inspect a capability',out:'empty-work',maxDirectories:1}},undefined,{onprogress:p=>progress.push(p)});
 const task=JSON.parse(first.content[0].text);assert.equal(task.status,'inventory-incomplete');assert.equal(task.inventory.batch.directoryAttempts,1);assert.equal(task.inventory.pendingDirectories,5);assert.ok(progress.length>0);assert.equal(JSON.parse(progress[0].message).phase,'directory-listed');
 const limited=await client.callTool({name:'carve_survey',arguments:{target:'input',workspace:'empty-work',maxDirectories:2}});assert.equal(JSON.parse(limited.content[0].text).batch.directoryAttempts,2);
 const full=path.join(root,'many');await mkdir(full);
 for(let i=0;i<1105;i+=32)await Promise.all(Array.from({length:Math.min(32,1105-i)},(_,j)=>writeFile(path.join(full,`${i+j}.mjs`),'export const n=1;')));
 const controller=new AbortController();let checkpoint=false;
 await assert.rejects(()=>client.callTool({name:'carve_survey',arguments:{target:'many',workspace:'cancel-work'}},undefined,{signal:controller.signal,onprogress:p=>{
  if(JSON.parse(p.message).phase==='listing'){checkpoint=true;controller.abort(new Error('test cancellation'));}
 }}),/test cancellation|abort/i);assert.equal(checkpoint,true);
 // Observe the original request releasing its live lock before issuing the continuation.
 let released=false;for(let i=0;i<100;i++){try{await access(path.join(root,'cancel-work/.scan.lock'));}catch(error){if(error.code!=='ENOENT')throw error;released=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(released,true);
 // Cancellation crosses stdio asynchronously: some files may commit before the
 // server receives it. Already committed files must survive and not be rehashed.
 const before=await client.callTool({name:'carve_index',arguments:{workspace:'cancel-work',limit:1}});const saved=JSON.parse(before.content[0].text).total;
 const resumed=await client.callTool({name:'carve_survey',arguments:{target:'many',workspace:'cancel-work'}});const result=JSON.parse(resumed.content[0].text);
 assert.equal(result.status,'indexed');assert.equal(result.files,1105);assert.equal(saved+result.batch.hashed,1105);assert.equal(result.batch.cached,0);assert.equal(result.failed,0);
});
