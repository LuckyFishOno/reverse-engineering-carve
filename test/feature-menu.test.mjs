import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {survey,openIndex} from '../dist/survey.js';
import {featureMenu} from '../dist/feature-menu.js';
import {reverseTask} from '../dist/reverse.js';

async function fixture(t,names=['SwipeEngine.framework/SwipeEngine','documentconverter-export.mjs']){
 const root=await mkdtemp(path.join(tmpdir(),'carve-feature-menu-'));t.after(()=>rm(root,{recursive:true,force:true}));
 const target=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(target);
 for(const name of names){const file=path.join(target,name);await mkdir(path.dirname(file),{recursive:true});await writeFile(file,'export const value=1;');}
 await survey(target,{workspace});return{root,target,workspace};
}

test('reverse without a goal offers grounded choices instead of choosing a feature',async t=>{
 const f=await fixture(t),result=await reverseTask(f.target,{out:f.workspace});
 assert.equal(result.status,'awaiting-feature-choice');
 assert.deepEqual(new Set(result.featureMenu.items.map(x=>x.id)),new Set(['swipe','document']));
 assert.ok(result.featureMenu.items.every(x=>x.status==='unconfirmed'&&x.basis==='path-lead'));
 assert.match(result.featureMenu.otherOption.label,/describe the feature/);
 const task=await readFile(result.task,'utf8');assert.match(task,/separate REA MCP/);
 const chosen=await reverseTask(f.target,{out:f.workspace,goal:'Extract swipe direction'});assert.equal(chosen.status,'ready-for-analysis');assert.notEqual(chosen.task,result.task);
});

test('recorded code leads preserve identities, omit bodies and exclude stale artifact hashes',async t=>{
 const f=await fixture(t),db=openIndex(f.workspace),file=db.prepare("SELECT * FROM files WHERE path='SwipeEngine.framework/SwipeEngine'").get();
 db.exec('CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,detail TEXT)');
 const add=db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?)');
 add.run('a'.repeat(64),file.path,file.sha256,'function','dragDirection swipe',JSON.stringify({pseudocode:'UNREAD_BODY_SENTINEL',decompilationStatus:'completed'}));
 add.run('b'.repeat(64),file.path,'0'.repeat(64),'function','vcard contactEncoder',JSON.stringify({pseudocode:'UNREAD_BODY_SENTINEL'}));db.close();
 const menu=await featureMenu(f.workspace);const swipe=menu.items.find(x=>x.id==='swipe');assert.equal(swipe.basis,'recorded-code-lead');assert.equal(swipe.leads[0].id,'a'.repeat(64));assert.ok(!menu.items.some(x=>x.id==='contact'));assert.ok(!JSON.stringify(menu).includes('UNREAD_BODY_SENTINEL'));
 assert.equal(menu.receipt.responseBytes,Buffer.byteLength(JSON.stringify(menu)));assert.ok(menu.receipt.responseBytes<=8192);
});

test('bounded scan exposes coverage and cursors; subsequent pages retain late features',async t=>{
 const f=await fixture(t,['a.mjs','b.mjs','z-swipe.mjs']);
 let menu=await featureMenu(f.workspace,{scanLimit:1}),pages=1;assert.equal(menu.coverage.complete,false);assert.equal(menu.status,'continue-analysis-pages');
 const ids=[];while(true){ids.push(...menu.items.map(x=>x.id));if(!menu.coverage.nextCursor)break;menu=await featureMenu(f.workspace,{scanLimit:1,cursor:menu.coverage.nextCursor});pages++;}
 assert.equal(pages,3);assert.deepEqual(ids,['swipe']);assert.equal(menu.coverage.complete,true);
});

test('cursors bind query and refreshed index revision',async t=>{
 const f=await fixture(t),menu=await featureMenu(f.workspace,{scanLimit:1});
 await assert.rejects(featureMenu(f.workspace,{scanLimit:1,cursor:menu.coverage.nextCursor,query:'swipe'}),/stale or invalid/);
 await survey(f.target,{workspace:f.workspace,refresh:true});
 await assert.rejects(featureMenu(f.workspace,{scanLimit:1,cursor:menu.coverage.nextCursor}),/stale or invalid/);
});

test('an exhausted recorded page never conceals unfinished input inventory',async t=>{
 const f=await fixture(t,['a.mjs','b.mjs','z-swipe.mjs']);
 await survey(f.target,{workspace:f.workspace,refresh:true,maxFiles:1,maxDirectories:1});
 const menu=await featureMenu(f.workspace,{query:'unobserved operation'});
 assert.equal(menu.status,'inventory-incomplete');assert.equal(menu.coverage.complete,false);assert.equal(menu.coverage.recordedPagesComplete,true);assert.equal(menu.coverage.nextCursor,null);assert.match(menu.nextAction,/Resume inventory/);
});

test('custom descriptions retain no-match and distinguish direct literal leads',async t=>{
 const f=await fixture(t,['coolMath.mjs']);
 const empty=await featureMenu(f.workspace,{query:'Investigate remote ranking'});assert.equal(empty.status,'needs-more-evidence');assert.equal(empty.items.length,0);assert.ok(empty.otherOption.questions.length);
 const custom=await featureMenu(f.workspace,{query:'coolMath'});assert.equal(custom.items[0].id,'custom');assert.equal(custom.items[0].suggestedGoal,'coolMath');assert.equal(custom.items[0].status,'unconfirmed');
 const injection=await featureMenu(f.workspace,{query:'" OR 1=1 --'});assert.equal(injection.items.length,0);
 await assert.rejects(featureMenu(f.workspace,{choice:'not-a-feature'}),/Choose a returned feature ID/);
});

test('choice narrows grounded categories, invalid bounds fail without target execution',async t=>{
 const f=await fixture(t);const menu=await featureMenu(f.workspace,{choice:'swipe'});assert.deepEqual(menu.items.map(x=>x.id),['swipe']);
 for(const options of [{scanLimit:0},{scanLimit:5001},{offset:-1},{limit:13},{query:'x'.repeat(1001)},{cursor:'invalid'},{budgetBytes:1000}])await assert.rejects(featureMenu(f.workspace,options));
 assert.match(menu.scope,/never starts or proxies/);
});

test('boundary facets distinguish geometry from interaction names without reading bodies or claiming matching',async t=>{
 const f=await fixture(t,['SwipeEngine.framework/SwipeEngine']),db=openIndex(f.workspace),file=db.prepare('SELECT * FROM files').get();db.exec('CREATE TABLE observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,detail TEXT)');
 for(const [id,name] of [['a','dragDirection'],['b','panGesture animation']])db.prepare('INSERT INTO observations VALUES(?,?,?,?,?,?)').run(id.repeat(64),file.path,file.sha256,'function',name,JSON.stringify({pseudocode:'UNREAD_BODY_SENTINEL'}));db.close();
 const menu=await featureMenu(f.workspace,{choice:'swipe'});assert.deepEqual(menu.refinement.options.map(f=>f.id),['direction','interaction','matching']);
 const direction=await featureMenu(f.workspace,{choice:'swipe',facet:'direction'});assert.equal(direction.items[0].leads[0].id,'a'.repeat(64));assert.equal(direction.items[0].componentCountInScan,1);assert.equal(direction.refinement.selectedFacet,'direction');assert.ok(!JSON.stringify(direction).includes('UNREAD_BODY_SENTINEL'));
 const matching=await featureMenu(f.workspace,{choice:'swipe',facet:'matching',query:'swipe'});assert.equal(matching.status,'needs-more-evidence');assert.equal(matching.items.length,0);assert.ok(matching.refinement.componentLeadsNotFacetMatches.length>0);assert.equal(matching.coverage.complete,true);
});

test('facet filters remain cursor-bound and invalid categories cannot select inherited object properties',async t=>{
 const f=await fixture(t),page=await featureMenu(f.workspace,{choice:'swipe',facet:'direction',scanLimit:1});await assert.rejects(()=>featureMenu(f.workspace,{choice:'swipe',facet:'interaction',scanLimit:1,cursor:page.coverage.nextCursor}),/stale/);
 for(const options of [{facet:'direction'},{choice:'swipe',facet:'missing'},{choice:'constructor',facet:'direction'}])await assert.rejects(()=>featureMenu(f.workspace,options));
});
