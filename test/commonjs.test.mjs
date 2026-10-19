import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,rename} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {build} from 'esbuild';
import {createPackage} from '@electron/asar';
import {extract} from '../dist/extract.js';
import {verify} from '../dist/verify.js';
import {plan,inspect} from '../dist/mcp.js';
import {discover} from '../dist/discover.js';
async function setup(t,files){
 const root=await mkdtemp(path.join(tmpdir(),'carve-cjs-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const app=path.join(root,'app');await mkdir(app);
 for(const [name,code] of Object.entries(files)){await mkdir(path.dirname(path.join(app,name)),{recursive:true});await writeFile(path.join(app,name),code);}
 const cases=path.join(root,'cases.json');await writeFile(cases,JSON.stringify([{name:'six',args:[3],expected:6}]));
 return {root,app,cases,out:path.join(root,'tool')};
}
test('CommonJS capsules preserve literal requires, inline exports, JSON and directory main',async t=>{
 const {app,cases,out}=await setup(t,{
  'index.cjs':`const double=require('./math');const data=require('./factor');exports.format=x=>double(x)*data.factor;`,
  'math/package.json':'{"main":"lib.js"}', 'math/lib.js':'module.exports=x=>x*2;', 'factor.json':'{"factor":1}'
 });
 const result=await extract(app,{file:'index.cjs',selector:{kind:'export',name:'format'},out});
 assert.equal(result.manifest.modules.length,3);assert.equal(result.manifest.modules[0].retention,'declaration-closure');
 assert.equal(result.manifest.modules.filter(m=>m.retention==='whole-commonjs-module').length,2);
 assert.equal((await verify(out,{cases,execute:true})).status,'passed');
 const found=await discover(app,{query:'format'});assert.ok(found.candidates.some(c=>c.selector.name==='format'));
 assert.ok((await inspect(app,'index.cjs')).exports.some(e=>e.name==='format'));
});
test('require and import choose different package export conditions in one closure',async t=>{
 const {app,cases,out}=await setup(t,{
  'package.json':'{"type":"module"}',
  'index.js':`import {format as cjs} from './helper.cjs';import value from 'dual';export const format=x=>cjs(x)+value;`,
  'helper.cjs':`const n=require('dual');exports.format=x=>x+n;`,
  'node_modules/dual/package.json':'{"type":"module","exports":{"import":"./esm.js","require":"./cjs.cjs"}}',
  'node_modules/dual/esm.js':'export default 1;', 'node_modules/dual/cjs.cjs':'module.exports=2;'
 });
 const result=await extract(app,{file:'index.js',selector:{kind:'export',name:'format'},out});
 assert.equal(result.manifest.modules.length,4);assert.equal((await verify(out,{cases,execute:true})).status,'passed');
});
test('CommonJS cycles and lazy requires keep initialization order',async t=>{
 const {app,cases,out}=await setup(t,{
  'index.cjs':`exports.factor=2;const b=require('./b.cjs');exports.format=x=>b.double(x);`,
  'b.cjs':`const a=require('./index.cjs');exports.double=x=>x*a.factor;`
 });
 await extract(app,{file:'index.cjs',selector:{kind:'export',name:'format'},out});
 assert.equal((await verify(out,{cases,execute:true})).status,'passed');
});
test('CommonJS native builtin bridges run without a dynamic require fallback',async t=>{
 const {root,app,out}=await setup(t,{'index.cjs':`const path=require('node:path');module.exports=value=>path.posix.basename(value);`});
 const cases=path.join(root,'paths.json');await writeFile(cases,JSON.stringify([{name:'basename',args:['/a/b.txt'],expected:'b.txt'}]));
 const result=await extract(app,{file:'index.cjs',selector:{kind:'export',name:'default'},out});
 assert.deepEqual(result.manifest.output.runtimeDependencies,['node:path']);
 const report=await verify(out,{cases,execute:true});assert.equal(report.status,'passed',JSON.stringify(report.results));
 assert.doesNotMatch(await readFile(path.join(out,'index.mjs'),'utf8'),/Dynamic require/);
});
test('a minified shipped CommonJS bundle can expose a requested runtime export after ASAR extraction',async t=>{
 const {root,app,out,cases}=await setup(t,{});
 const bundled=await build({stdin:{contents:'export function format(x){return x*2}export function unrelated(x){return x+99}',sourcefile:'app.js'},bundle:true,format:'cjs',minify:true,write:false,platform:'node'});
 await writeFile(path.join(app,'bundle.cjs'),bundled.outputFiles[0].text);
 const asar=path.join(root,'app.asar');await createPackage(app,asar);
 const result=await extract(asar,{file:'bundle.cjs',selector:{kind:'export',name:'format'},out});
 assert.match(result.manifest.warnings.join('\n'),/runtime property/);
 const report=await verify(out,{cases,execute:true});assert.equal(report.status,'passed',JSON.stringify(report.results));
 await rename(app,app+'.removed');await rename(asar,asar+'.removed');
 assert.equal(execFileSync(process.execPath,[path.join(out,'cli.mjs'),'[3]'],{encoding:'utf8'}).trim(),'6');
});
test('dynamic, aliased, escaping and unavailable requires remain blocked without running source',async t=>{
 const {app}=await setup(t,{'index.cjs':''});
 for(const code of [
  `module.exports=x=>require(x);`, `const req=require;module.exports=x=>req('fs');`,
  `const fs=require('node:fs');module.exports=()=>fs.readFileSync('a');`,
  `module.exports=require('../outside.cjs');`, `module.exports=x=>process.env.SECRET;`
 ]){
  await writeFile(path.join(app,'index.cjs'),code);
  assert.equal((await plan(app,'index.cjs',{kind:'export',name:'default'})).plan.status,'blocked',code);
 }
});
test('a statically exported closed CommonJS declaration removes unrelated application requires',async t=>{
 const {app,cases,out}=await setup(t,{'index.cjs':`const editor=require('electron');function format(x){return x*2}module.exports={format};`});
 const result=await extract(app,{file:'index.cjs',selector:{kind:'export',name:'format'},out});
 assert.equal(result.manifest.modules[0].retention,'declaration-closure');
 assert.doesNotMatch(await readFile(path.join(out,'index.mjs'),'utf8'),/electron|editor/);
 // The original module needs Electron, so a separate explicit reference is required.
 assert.equal((await verify(out,{cases,execute:true})).status,'failed');
});
test('a null require condition blocks access instead of falling through to default',async t=>{
 const {app}=await setup(t,{
  'index.cjs':`module.exports=require('restricted');`,
  'node_modules/restricted/package.json':'{"exports":{"require":null,"default":"./index.cjs"}}',
  'node_modules/restricted/index.cjs':'module.exports=x=>x*2;'
 });
 assert.equal((await plan(app,'index.cjs',{kind:'export',name:'default'})).plan.status,'blocked');
});
test('an unexported closed CommonJS symbol can be extracted with an explicit harness requirement',async t=>{
 const {app,out}=await setup(t,{'index.cjs':`const editor=require('electron');function hiddenFormat(x){return x*2}module.exports=editor;`});
 await extract(app,{file:'index.cjs',selector:{kind:'symbol',name:'hiddenFormat'},out});
 assert.equal(execFileSync(process.execPath,[path.join(out,'cli.mjs'),'[3]'],{encoding:'utf8'}).trim(),'6');
 assert.doesNotMatch(await readFile(path.join(out,'index.mjs'),'utf8'),/electron|editor/);
});
