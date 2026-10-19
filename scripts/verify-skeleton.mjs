// Builds the three supported macOS skeleton deliveries with the host Swift toolchain, replaces two
// feature-owned files as a simulated work-package submission, and launches the desktop app window
// briefly. Plans and specs are the bundled synthetic examples; no original program is involved.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {spawn} from 'node:child_process';
import {analyzeProjectPlan,parseProjectPlan} from '../dist/project-plan.js';
import {createSkeleton,checkSkeleton} from '../dist/skeleton.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),out=await mkdtemp(path.join(root,'artifacts/skeleton-e2e-'));
const plan=JSON.parse(await readFile(path.join(root,'examples/work-plan.json'),'utf8')),spec=JSON.parse(await readFile(path.join(root,'examples/work-spec.json'),'utf8'));
const retarget=delivery=>{const p=structuredClone(plan);p.target={schema:'carve/target@1',platform:'macos',delivery};const graph=analyzeProjectPlan(parseProjectPlan(p)),s=structuredClone(spec);s.planId=graph.planId;for(const a of s.assignments)a.taskId=graph.tasks.find(t=>t.id===a.feature).taskId;return{plan:p,spec:s};};
const statuses=report=>report?.features?.map(f=>f.id+':'+f.status)??null;
const report={schema:'carve/skeleton-verification@1',checkedAt:new Date().toISOString(),out,cases:{}};
// Swift build products go to a temporary directory removed at the end; reports and logs stay in out.
const products=await mkdtemp(path.join(tmpdir(),'carve-skeleton-build-')),scratch=name=>path.join(products,name);
try{

// desktop-app: stubs, then a simulated submission of model and parser, then a short window launch.
const desktop=await createSkeleton(plan,spec,path.join(out,'desktop-app')),first=await checkSkeleton(desktop.skeleton,{scratchPath:scratch('desktop-app')});
assert.equal(first.build.passed,true);assert.deepEqual(statuses(first.selfTest.report),['model:not-implemented','parser:blocked-by-dependency','storage:blocked-by-dependency','ui:blocked-by-dependency']);
const pins=Object.fromEntries(JSON.parse(await readFile(path.join(desktop.skeleton,'carve-skeleton.json'),'utf8')).features.map(f=>[f.id,f.contractSha256]));
await writeFile(path.join(desktop.skeleton,'Sources/model/Module.swift'),`import CarveShared\npublic enum ModelFeature: CarveFeature {\n    public static let id = "model"\n    public static let contractSha256 = "${pins.model}"\n    public static let dependsOn: [String] = []\n    public static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse { FeatureResponse(payload: "document:" + request.payload) }\n}\n`);
await writeFile(path.join(desktop.skeleton,'Sources/parser/Module.swift'),`import CarveShared\nimport Model\npublic enum ParserFeature: CarveFeature {\n    public static let id = "parser"\n    public static let contractSha256 = "${pins.parser}"\n    public static let dependsOn: [String] = ["model"]\n    public static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse {\n        guard let document = dependencies[feature: "model"] else { throw FeatureError.failed(id, "missing model output") }\n        return FeatureResponse(payload: "tokens(" + document.payload + ")")\n    }\n}\n`);
const second=await checkSkeleton(desktop.skeleton,{test:true,scratchPath:scratch('desktop-app')});
assert.equal(second.build.passed,true);assert.equal(second.test.passed,true);
assert.deepEqual(statuses(second.selfTest.report),['model:implemented-ok','parser:implemented-ok','storage:not-implemented','ui:blocked-by-dependency']);
const binary=path.join(scratch('desktop-app'),'debug/CarveApp'),child=spawn(binary,[],{stdio:'ignore'});
const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
const alive=await Promise.race([exited.then(()=>false),new Promise(resolve=>setTimeout(()=>resolve(true),4000))]);child.kill('SIGTERM');const end=await exited;
assert.equal(alive,true,'the desktop app process must still be running after 4 seconds');
report.cases['desktop-app']={skeleton:desktop.skeleton,toolchain:first.host.toolchain,stubs:statuses(first.selfTest.report),afterSubmission:statuses(second.selfTest.report),
 flow:{target:second.flow.report.flow,completed:second.flow.report.completed,steps:second.flow.report.steps.map(s=>s.id+':'+s.status)},swiftTest:second.test.passed,
 changedFeatureFiles:second.featureFiles.filter(f=>f.changedFromStub).map(f=>f.path),windowLaunch:{aliveAfterMs:4000,terminatedBy:end.signal??end.code,windowContentInspected:false}};

for(const delivery of ['cli','module']){
 const {plan:p,spec:s}=retarget(delivery),created=await createSkeleton(p,s,path.join(out,delivery)),checked=await checkSkeleton(created.skeleton,{test:delivery==='module',scratchPath:scratch(delivery)});
 assert.equal(checked.build.passed,true,delivery+' build');
 if(delivery==='cli')assert.deepEqual(statuses(checked.selfTest.report),['model:not-implemented','parser:blocked-by-dependency','storage:blocked-by-dependency','ui:blocked-by-dependency']);
 else{assert.equal(checked.selfTest,undefined);assert.equal(checked.test.passed,true,'module swift test');}
 report.cases[delivery]={skeleton:created.skeleton,build:checked.build.passed,selfTest:statuses(checked.selfTest?.report),swiftTest:checked.test?.passed??null};
}
report.status='passed';
}finally{await rm(products,{recursive:true,force:true});}
report.buildProducts='temporary directory, removed after the run';
report.scope='Synthetic example plan/spec only. Builds and self-tests on this macOS host; stubs report not-implemented and the two replaced modules are fixtures, not ported behavior. The window launch checks that the process stays up; its content was not inspected.';
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({status:report.status,report:path.join(out,'report.json')}));
