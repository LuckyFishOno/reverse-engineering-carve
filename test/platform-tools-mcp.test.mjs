import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,writeFile,readFile,mkdir,rm,symlink} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey} from '../dist/survey.js';
import {buildPe} from './fixtures/pe-image.mjs';
const exec=promisify(execFile),cli=path.resolve('dist/cli.js');
async function setup(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-platform-protocol-')));t.after(()=>rm(root,{recursive:true,force:true}));const file=path.join(root,'fixture.exe'),bytes=buildPe({imports:[{name:'KERNEL32.dll',entries:['CreateFileW']},{name:'USER32.dll',entries:['MessageBoxW']},{name:'helper.dll',entries:['UnknownAppFeature']}]});await writeFile(file,bytes);const workspace=path.join(root,'work');await survey(file,{workspace});return{root,file,bytes,workspace};}
async function connect(root){const peer=new Client({name:'platform-protocol-test',version:'1'});await peer.connect(new StdioClientTransport({command:process.execPath,args:[cli,'serve','--root',root],stderr:'pipe'}));return peer;}
const call=(peer,request)=>peer.callTool({name:'carve_platform',arguments:{workspace:'work',file:'fixture.exe',request}});
const value=r=>{assert.ok(!r.isError,r.content[0].text);const result=JSON.parse(r.content[0].text);assert.equal(result.receipt.responseBytes,Buffer.byteLength(r.content[0].text));return result;};
test('CLI PE classification and fresh MCP target guidance keep source identity, versioned rules and unknown third-party behavior',async t=>{
 const {root,file,bytes,workspace}=await setup(t),raw=(await exec(process.execPath,[cli,'platform','dependencies',workspace,'--file','fixture.exe','--view','imports','--budget-bytes','8192'])).stdout,source=JSON.parse(raw);assert.equal(source.receipt.responseBytes,Buffer.byteLength(raw)-1);assert.equal(source.totals.imports,3);assert.equal(source.totals.unknown,1);assert.equal(source.items.find(i=>i.module==='helper.dll').category,'unknown');
 const peer=await connect(root);t.after(()=>peer.close());const categories=value(await call(peer,{kind:'dependencies',view:'categories',budgetBytes:8192}));assert.equal(categories.sourceSha256,source.sourceSha256);assert.equal(categories.provider.rulesSha256,source.provider.rulesSha256);assert.equal(categories.sourceFreshlyHashed,true);assert.equal(categories.executesTarget,false);
 const mac=value(await call(peer,{kind:'target-adapters',target:{schema:'carve/target@1',platform:'macos',delivery:'desktop-app'},view:'cards',budgetBytes:8192}));assert.equal(mac.sourceSha256,source.sourceSha256);assert.equal(mac.assessment,'static-guidance-not-verified');assert.equal(mac.items.find(i=>i.category==='ui-graphics').availability,'native-framework');assert.equal(mac.items.find(i=>i.category==='unknown').availability,'inspect-separately');
 const browser=value(await call(peer,{kind:'target-adapters',target:{schema:'carve/target@1',platform:'browser',delivery:'web-app'},view:'cards',budgetBytes:8192}));assert.notEqual(browser.observationId,mac.observationId);assert.equal(browser.items.find(i=>i.category==='ui-graphics').availability,'web-platform-api');assert.deepEqual(await readFile(file),bytes);
 assert.equal((await call(peer,{kind:'dependencies',category:'network'})).isError,true);await writeFile(file,Buffer.from('changed after indexing'));assert.equal((await call(peer,{kind:'dependencies'})).isError,true);
});
test('platform MCP rejects escaped evidence directories and redirected current sources before writing evidence',async t=>{
 const {root,workspace}=await setup(t),outside=await realpath(await mkdtemp(path.join(tmpdir(),'carve-platform-outside-')));t.after(()=>rm(outside,{recursive:true,force:true}));await mkdir(path.join(outside,'evidence'));await symlink(path.join(outside,'evidence'),path.join(workspace,'loader-evidence'));
 const peer=await connect(root);t.after(()=>peer.close());const denied=await call(peer,{kind:'dependencies'});assert.equal(denied.isError,true);assert.match(denied.content[0].text,/outside/);
});
