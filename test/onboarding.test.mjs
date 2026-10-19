import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,symlink,access} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createPackage} from '@electron/asar';
import {locate} from '../dist/locate.js';
import {startTask} from '../dist/session.js';
import {extract,outputCli} from '../dist/extract.js';
import {packageUsage} from '../dist/runtime.js';
async function fixture(t){const root=await mkdtemp(path.join(tmpdir(),"carve space's-"));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
test('application location finds a packed ASAR and creates a draft without invented observations',async t=>{
 const root=await fixture(t);const source=path.join(root,'source');await mkdir(source);
 await writeFile(path.join(source,'package.json'),'{"main":"main.cjs"}');await writeFile(path.join(source,'main.cjs'),'module.exports=x=>x*2;');
 const resources=path.join(root,'Example.app/Contents/Resources');await mkdir(resources,{recursive:true});await createPackage(source,path.join(resources,'app.asar'));
 const located=await locate(path.join(root,'Example.app'));
 assert.equal(located.status,'located');assert.equal(located.candidates[0].entryHint,'main.cjs');
 const out=path.join(root,'task');const started=await startTask(path.join(root,'Example.app'),{goal:'extract the numeric formatter',out});
 assert.equal(started.status,'draft-created');
 const feature=JSON.parse(await readFile(path.join(out,'feature.json'),'utf8'));assert.deepEqual(feature.examples,[]);assert.equal(feature.target.path,located.selectedTarget);
 assert.match(await readFile(started.task,'utf8'),/Leave unknowns unknown/);
 await assert.rejects(()=>startTask(source,{goal:'again',out}),/EEXIST/);
});
test('location does not guess among archives, traverse symlinks or hide truncated coverage',async t=>{
 const root=await fixture(t);const source=path.join(root,'source');await mkdir(source);await writeFile(path.join(source,'a.mjs'),'export const x=1;');
 const app=path.join(root,'app');await mkdir(app);await createPackage(source,path.join(app,'one.asar'));await createPackage(source,path.join(app,'two.asar'));
 const ambiguous=await locate(app);assert.equal(ambiguous.status,'needs-artifact-selection');assert.equal(ambiguous.selectedTarget,null);
 const truncated=await locate(app,{scanLimit:1});assert.equal(truncated.status,'incomplete-scan');assert.equal(truncated.selectedTarget,null);
 const links=path.join(root,'links');await mkdir(links);await symlink(path.join(app,'one.asar'),path.join(links,'app.asar'));
 assert.equal((await locate(links)).coverage.skippedSymlinks,1);assert.equal((await locate(links)).status,'unsupported-target');
 await writeFile(path.join(root,'native.exe'),'MZ');const out=path.join(root,'unsupported-task');
 assert.equal((await startTask(path.join(root,'native.exe'),{goal:'native',out})).status,'unsupported-target');await assert.rejects(()=>access(out),/ENOENT/);
});
test('standalone CLI shows help before loading code and supports exact raw text and exclusive file output',async t=>{
 const root=await fixture(t);await writeFile(path.join(root,'cli.mjs'),outputCli);await writeFile(path.join(root,'index.mjs'),'throw new Error("must not load");');
 assert.match(execFileSync(process.execPath,[path.join(root,'cli.mjs'),'--help'],{encoding:'utf8'}),/--raw/);
 await writeFile(path.join(root,'index.mjs'),'export const capability=value=>value;');
 const args=JSON.stringify(['a,b\r\n"quoted"']);const file=path.join(root,'result.txt');
 assert.equal(execFileSync(process.execPath,[path.join(root,'cli.mjs'),'--raw',args],{encoding:'utf8'}),'a,b\r\n"quoted"');
 execFileSync(process.execPath,[path.join(root,'cli.mjs'),'--raw','--out',file,args],{stdio:'pipe'});
 assert.equal(await readFile(file,'utf8'),'a,b\r\n"quoted"');
 assert.throws(()=>execFileSync(process.execPath,[path.join(root,'cli.mjs'),'--raw','--out',file,'["changed"]'],{stdio:'pipe'}));
 assert.equal(await readFile(file,'utf8'),'a,b\r\n"quoted"');
});
test('package usage derives executable shell-safe commands from recorded examples',async t=>{
 const root=await fixture(t);const input=path.join(root,'app.mjs');await writeFile(input,'export const echo=x=>x;');
 const feature=path.join(root,'feature.json');await writeFile(feature,JSON.stringify({schema:'carve/feature@1',title:'echo',description:'echo text',examples:[{name:'text',args:["O’Neil's $word `literal`"],expected:"O’Neil's $word `literal`"}]}));
 const out=path.join(root,'tool');await extract(input,{selector:{kind:'export',name:'echo'},out,feature});
 const usage=await packageUsage(out);assert.ok(usage.commands.raw);assert.equal(usage.mcpClientConfig.mcpServers.carved_capability.args.at(-1),'--execute');
 const result=execFileSync('/bin/sh',['-c',usage.commands.raw],{encoding:'utf8'});assert.equal(result,"O’Neil's $word `literal`");
 const noExamples=path.join(root,'without-examples');await extract(input,{selector:{kind:'export',name:'echo'},out:noExamples});
 assert.equal((await packageUsage(noExamples)).commands.run,null);
});
