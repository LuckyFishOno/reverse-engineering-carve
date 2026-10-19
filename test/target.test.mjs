import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {targetSpecSchema} from '../dist/target.js';
import {featureRequestSchema} from '../dist/feature-intent.js';
import {featureScope} from '../dist/feature-scope.js';
import {survey,queryIndex} from '../dist/survey.js';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
const target=(platform,delivery,extra={})=>({schema:'carve/target@1',platform,delivery,...extra});
async function fixture(t){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-target-')));t.after(()=>rm(root,{recursive:true,force:true}));
 const input=path.join(root,'input');await mkdir(input);await writeFile(path.join(input,'owned.mjs'),'export const twice=x=>x*2;');
 const workspace=path.join(root,'work');await survey(input,{workspace});const indexed=(await queryIndex(workspace)).items[0];
 const request={schema:'carve/feature-request@1',origin:'test-fixture',goal:'Retain bounded arithmetic while selecting the destination independently',behavior:{trigger:'A local call',input:'An integer',output:'Twice the integer',state:'stateless'},boundary:{ui:'excluded',remote:'excluded',host:'excluded'},leads:[{file:indexed.path,sourceSha256:indexed.sha256}]};
 return{root,input,workspace,request};
}
test('target declares destination and delivery without inheriting a source platform or asserting support',()=>{
 for(const [platform,delivery] of [['windows','desktop-app'],['windows','cli'],['macos','desktop-app'],['linux','service'],['ios','mobile-app'],['android','mobile-app'],['browser','web-app'],['browser','module'],['server','service'],['portable','module']]){
  const value=target(platform,delivery);assert.deepEqual(targetSpecSchema.parse(value),value);
 }
 assert.equal(targetSpecSchema.parse(target('windows','cli',{runtime:'  custom-runtime  ',language:' Rust '})).runtime,'custom-runtime');
 const instruction='$(echo data); not a command';assert.equal(targetSpecSchema.parse(target('portable','module',{runtime:instruction})).runtime,instruction);
 for(const value of [target('browser','desktop-app'),target('windows','mobile-app'),target('macos','web-app'),target('portable','cli'),target('server','web-app'),target('server','desktop-app'),target('browser','service'),target('linux','module',{runtime:' '}),target('linux','cli',{architecture:'mips'}),target('macos','desktop-app',{sourcePlatform:'windows'}),target('macos','desktop-app',{language:'x'.repeat(101)}),{platform:'macos',delivery:'module'}])assert.equal(targetSpecSchema.safeParse(value).success,false);
});
test('omitted target keeps legacy normalized request bytes and immutable IDs unchanged',async t=>{
 const f=await fixture(t),first=await featureScope(f.workspace,{request:f.request});
 const file=path.join(f.workspace,'feature-requests',first.id+'.json'),before=await readFile(file),record=JSON.parse(before);
 assert.equal(Object.hasOwn(featureRequestSchema.parse(f.request),'target'),false);assert.equal(Object.hasOwn(record.request,'target'),false);assert.equal(Object.hasOwn(first,'targetAssessment'),false);
 assert.equal(createHash('sha256').update(before).digest('hex'),first.id);assert.equal((await featureScope(f.workspace,{request:f.request})).id,first.id);
 const second=await featureScope(f.workspace,{request:{...f.request,target:target('browser','module')},parentId:first.id});
 assert.notEqual(second.id,first.id);assert.deepEqual(await readFile(file),before);assert.equal((await featureScope(f.workspace,{id:first.id})).id,first.id);
});
test('target revisions survive historical record/source pages without claiming a completed port',async t=>{
 const f=await fixture(t);let parentId;
 for(const destination of [target('windows','desktop-app'),target('macos','desktop-app',{language:'Swift'}),target('browser','web-app'),target('server','service'),target('portable','module')]){
  const saved=await featureScope(f.workspace,{request:{...f.request,target:destination},parentId});assert.equal(saved.status,'ready-for-investigation');assert.equal(saved.targetAssessment,'not-performed');assert.equal(saved.verification,'not-run');assert.equal(saved.semanticMatch,'unconfirmed');assert.deepEqual(saved.target,destination);assert.equal(saved.receipt.responseBytes,Buffer.byteLength(JSON.stringify(saved)));
  const read=await featureScope(f.workspace,{id:saved.id,view:'sources'});assert.equal(read.sourceIdentityCheck,'recorded-only-no-current-source-check');assert.deepEqual(read.target,destination);
  let offset=0,text='';do{const page=await featureScope(f.workspace,{id:saved.id,view:'record',offset,characters:250,budgetBytes:2048});assert.ok(page.receipt.responseBytes<=2048);text+=page.text;offset=page.nextOffset;}while(offset!==null);
  assert.deepEqual(JSON.parse(text).request.target,destination);parentId=saved.id;
 }
});
test('actual CLI and a fresh MCP retain target intent through revision and root confinement',async t=>{
 const f=await fixture(t),file=path.join(f.root,'request.json'),request={...f.request,target:target('browser','module',{language:'JavaScript'})};await writeFile(file,JSON.stringify(request));
 const raw=(await exec(process.execPath,[cli,'scope',f.workspace,'--request',file])).stdout,saved=JSON.parse(raw);assert.equal(saved.target.platform,'browser');assert.equal(saved.receipt.responseBytes,Buffer.byteLength(raw)-1);
 const client=new Client({name:'target-spec-roundtrip',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',f.root],stderr:'pipe'}));t.after(()=>client.close());
 const read=await client.callTool({name:'carve_scope',arguments:{workspace:'work',id:saved.id}});assert.ok(!read.isError);const value=JSON.parse(read.content[0].text);assert.deepEqual(value.target,request.target);assert.equal(value.targetAssessment,'not-performed');
 const revised=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:{...request,target:target('windows','desktop-app')},parentId:saved.id}});assert.ok(!revised.isError);assert.equal(JSON.parse(revised.content[0].text).target.platform,'windows');
 const invalid=await client.callTool({name:'carve_scope',arguments:{workspace:'work',request:{...request,target:target('browser','desktop-app')}}});assert.equal(invalid.isError,true);
 const outside=await client.callTool({name:'carve_scope',arguments:{workspace:path.join(f.root,'..','other-work'),request}});assert.equal(outside.isError,true);
});
