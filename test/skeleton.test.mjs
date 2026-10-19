import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readFile,writeFile,rm,realpath,readdir} from 'node:fs/promises';
import {analyzeProjectPlan,parseProjectPlan} from '../dist/project-plan.js';
import {createSkeleton,checkSkeleton,swiftModuleName,SUPPORTED_SKELETON_TARGETS} from '../dist/skeleton.js';

const examplePlan=JSON.parse(await readFile('examples/work-plan.json','utf8')),exampleSpec=JSON.parse(await readFile('examples/work-spec.json','utf8'));
async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-skeleton-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}
const contract=name=>({input:`${name} input`,output:`${name} output`,state:`${name} state`,errors:`${name} errors`});
// Rebinds a spec to an edited plan: new planId and per-feature taskIds, assignments as given.
function rebind(plan,assignments){
 const graph=analyzeProjectPlan(parseProjectPlan(plan));
 return{schema:'carve/work-spec@1',planId:graph.planId,assignments:assignments.map(a=>({acceptance:[{name:'builds',criterion:'compiles'}],...a,taskId:graph.tasks.find(t=>t.id===a.feature).taskId}))};
}
const plan=(features,target={schema:'carve/target@1',platform:'macos',delivery:'cli'})=>({schema:'carve/project-plan@1',goal:'Skeleton fixture',target,features});

test('module names, supported targets and refusals before anything is written',async t=>{
 const root=await scratch(t);
 assert.deepEqual(['model','storage-core','a.b_c','2fa'].map(swiftModuleName),['Model','StorageCore','ABC','F2fa']);
 assert.deepEqual(SUPPORTED_SKELETON_TARGETS.map(x=>x.platform+'/'+x.delivery),['macos/desktop-app','macos/cli','macos/module']);
 const one=[{id:'core',title:'Core',contract:contract('core')}];
 const web=plan(one,{schema:'carve/target@1',platform:'browser',delivery:'web-app'});
 await assert.rejects(()=>createSkeleton(web,rebind(web,[{feature:'core',files:['Sources/core/Module.swift']}]),path.join(root,'web')),/browser\/web-app is not supported yet \(unsupported-target\)\. Supported: macos\/desktop-app, macos\/cli, macos\/module/);
 const refuse=async(features,assignments,pattern)=>{const p=plan(features);await assert.rejects(()=>createSkeleton(p,rebind(p,assignments),path.join(root,'x')),pattern);};
 await refuse(one,[{feature:'core',files:['Sources/core/data.json']}],/only \.swift files.*layout-unsupported/);
 await refuse(one,[{feature:'core',files:['App/core.swift']}],/not under Sources\/<dir>\/ or Tests\/<dir>\//);
 await refuse(one,[{feature:'core',files:['Sources/core/A.swift','Sources/other/B.swift']}],/spreads its files over several directories/);
 await refuse(one,[{feature:'core',files:['Tests/core/CoreTests.swift']}],/has no assigned Swift source file/);
 await refuse(one,[{feature:'core',files:['Sources/CarveShared/Core.swift']}],/collides with a skeleton-owned or system name/);
 await refuse([{id:'a-b',title:'A',contract:contract('a')},{id:'a.b',title:'B',contract:contract('b')}],[{feature:'a-b',files:['Sources/ab1/M.swift']},{feature:'a.b',files:['Sources/ab2/M.swift']}],/map to the same Swift module name AB/);
 await refuse([{id:'foundation',title:'F',contract:contract('f')}],[{feature:'foundation',files:['Sources/f/M.swift']}],/reserved Swift module name Foundation/);
 await refuse([{id:'x',title:'X',contract:contract('x'),dependsOn:['y']},{id:'y',title:'Y',contract:contract('y'),dependsOn:['x']}],[{feature:'x',files:['Sources/x/M.swift']}],/cycl/);
 await refuse([{id:'p',title:'P',contract:contract('p')},{id:'q',title:'Q',contract:contract('q')}],[{feature:'p',files:['Sources/shared/P.swift']},{feature:'q',files:['Sources/shared/Q.swift']}],/share Sources\/shared/);
 await assert.rejects(()=>createSkeleton(examplePlan,{...exampleSpec,planId:'0'.repeat(64)},path.join(root,'stale')),/Stale planId/);
 assert.deepEqual(await readdir(root),[],'refusals write nothing');
});

test('the generated package owns shell files, puts stubs at assigned paths and keeps plan text inside comments',async t=>{
 const root=await scratch(t);
 const tricky='line one\n*/ fatalError("escaped")\r\nfinal line';
 const p=plan([{id:'core',title:'Core',contract:{...contract('core'),input:tricky}},{id:'report-view',title:'Report',contract:contract('report'),dependsOn:['core']},{id:'extra',title:'Unassigned',dependsOn:['core']}]);
 const created=await createSkeleton(p,rebind(p,[{feature:'core',files:['Sources/core/Module.swift','Sources/core/Helpers.swift','Tests/core/ModuleTests.swift']},{feature:'report-view',files:['Sources/report/Module.swift']}]),path.join(root,'app'));
 assert.deepEqual(created.features.map(f=>[f.id,f.module,f.phase,f.owner,f.sourceDir,f.testDir]),[
  ['core','Core',1,'work-package','Sources/core','Tests/core'],['extra','Extra',2,'skeleton-unassigned-feature','Sources/extra',null],['report-view','ReportView',2,'work-package','Sources/report',null]]);
 const manifest=JSON.parse(await readFile(path.join(created.skeleton,'carve-skeleton.json'),'utf8'));
 assert.equal(manifest.schema,'carve/skeleton@1');assert.equal(manifest.app.defaultFlow,'extra');assert.equal(manifest.target.delivery,'cli');
 const owners=Object.fromEntries(manifest.files.map(f=>[f.path,f.owner]));
 assert.deepEqual(owners,{'Package.swift':'skeleton','Sources/CarveShared/Feature.swift':'skeleton','Sources/CarveApp/Registry.swift':'skeleton','Sources/CarveApp/Command.swift':'skeleton','Sources/CarveApp/main.swift':'skeleton',
  'Sources/core/Helpers.swift':'feature:core','Sources/core/Module.swift':'feature:core','Tests/core/ModuleTests.swift':'feature:core','Sources/extra/Module.swift':'feature:extra','Sources/report/Module.swift':'feature:report-view','SKELETON.md':'skeleton'});
 const stub=await readFile(path.join(created.skeleton,'Sources/core/Module.swift'),'utf8'),graph=analyzeProjectPlan(parseProjectPlan(p));
 assert.match(stub,/throw FeatureError\.notImplemented\(id\)/);assert.ok(stub.includes(`contractSha256 = "${graph.tasks.find(x=>x.id==='core').contractSha256}"`));
 for(const line of stub.split('\n').filter(l=>l.includes('escaped')||l.includes('line one')||l.includes('final line')))assert.ok(line.startsWith('//'),'plan text stays in comments: '+line);
 assert.match(await readFile(path.join(created.skeleton,'Sources/report/Module.swift'),'utf8'),/import Core\n/);
 assert.match(await readFile(path.join(created.skeleton,'Sources/core/Helpers.swift'),'utf8'),/^\/\/ Placeholder/);
 const pkg=await readFile(path.join(created.skeleton,'Package.swift'),'utf8');
 assert.match(pkg,/\.target\(name: "ReportView", dependencies: \["CarveShared", "Core"\], path: "Sources\/report"\)/);assert.match(pkg,/\.testTarget\(name: "CoreTests"/);assert.match(pkg,/\.executable\(name: "CarveApp"/);
 await assert.rejects(()=>createSkeleton(p,rebind(p,[{feature:'core',files:['Sources/core/Module.swift']}]),path.join(root,'app')),/EEXIST/);
 const library=plan([{id:'core',title:'Core',contract:contract('core')}],{schema:'carve/target@1',platform:'macos',delivery:'module'});
 const lib=await createSkeleton(library,rebind(library,[{feature:'core',files:['Sources/core/Module.swift']}]),path.join(root,'lib'));
 const libManifest=JSON.parse(await readFile(path.join(lib.skeleton,'carve-skeleton.json'),'utf8'));assert.equal(libManifest.app,null);
 assert.ok(!libManifest.files.some(f=>f.path.startsWith('Sources/CarveApp/')));assert.match(await readFile(path.join(lib.skeleton,'Package.swift'),'utf8'),/\.library\(name: "CarveFeatures"/);
});

const swift=(()=>{if(process.platform!=='darwin')return false;try{execFileSync('/usr/bin/env',['swift','--version'],{stdio:'ignore'});return true;}catch{return false;}})();
test('the example desktop app builds, reports stubs honestly and picks up replaced feature files without shell changes',{timeout:900000},async t=>{
 if(!swift){t.skip('no macOS Swift toolchain on this host');return;}
 const root=await scratch(t),created=await createSkeleton(examplePlan,exampleSpec,path.join(root,'app')),app=created.skeleton;
 const first=await checkSkeleton(app);assert.equal(first.build.passed,true,await readFile(first.build.log,'utf8').catch(()=>''));
 assert.deepEqual(first.selfTest.report.features.map(f=>f.id+':'+f.status),['model:not-implemented','parser:blocked-by-dependency','storage:blocked-by-dependency','ui:blocked-by-dependency']);
 assert.equal(first.selfTest.exitCode,0);assert.equal(first.flow.report.flow,'ui');assert.equal(first.flow.report.completed,false);
 const pins=Object.fromEntries(JSON.parse(await readFile(path.join(app,'carve-skeleton.json'),'utf8')).features.map(f=>[f.id,f.contractSha256]));
 // A work-package submission replaces only feature-owned files; parser consumes model's output.
 await writeFile(path.join(app,'Sources/model/Module.swift'),`import CarveShared\npublic enum ModelFeature: CarveFeature {\n    public static let id = "model"\n    public static let contractSha256 = "${pins.model}"\n    public static let dependsOn: [String] = []\n    public static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse { FeatureResponse(payload: "document:" + request.payload) }\n}\n`);
 await writeFile(path.join(app,'Sources/parser/Module.swift'),`import CarveShared\nimport Model\npublic enum ParserFeature: CarveFeature {\n    public static let id = "parser"\n    public static let contractSha256 = "${pins.parser}"\n    public static let dependsOn: [String] = ["model"]\n    public static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse {\n        guard let document = dependencies[feature: "model"] else { throw FeatureError.failed(id, "missing model output") }\n        return FeatureResponse(payload: "tokens(" + document.payload + ")")\n    }\n}\n`);
 const second=await checkSkeleton(app,{test:true});assert.equal(second.build.passed,true);assert.equal(second.test.passed,true);
 assert.deepEqual(second.featureFiles.filter(f=>f.changedFromStub).map(f=>f.path),['Sources/model/Module.swift','Sources/parser/Module.swift']);
 assert.deepEqual(second.selfTest.report.features.map(f=>f.id+':'+f.status),['model:implemented-ok','parser:implemented-ok','storage:not-implemented','ui:blocked-by-dependency']);
 assert.equal(second.selfTest.report.features.find(f=>f.id==='parser').outputCharacters,'tokens(document:)'.length,'parser received model output');
 const storage=path.join(app,'Sources/storage/Module.swift');await writeFile(storage,(await readFile(storage,'utf8')).replace(pins.storage,'0'.repeat(64)));
 const mismatch=await checkSkeleton(app);assert.equal(mismatch.selfTest.exitCode,2);assert.equal(mismatch.selfTest.report.features.find(f=>f.id==='storage').status,'contract-mismatch');
 await writeFile(path.join(app,'Package.swift'),(await readFile(path.join(app,'Package.swift'),'utf8'))+'\n// edited\n');
 await assert.rejects(()=>checkSkeleton(app),/skeleton-owned files were edited \(Package\.swift\)/);
});
