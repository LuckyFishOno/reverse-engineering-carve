import path from 'node:path';
import {prepareSkeletonWiring,type SkeletonWiring} from './skeleton-wiring.js';
import type {BridgePathAccess} from './rea-bridge.js';
import {mkdir,writeFile,readFile,lstat,realpath} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {z} from 'zod';
import {digest} from './artifact.js';
import {parseProjectPlan,analyzeProjectPlan} from './project-plan.js';
import {bindWorkContract,workSpecSchema} from './work-contract.js';
import {runTool} from './tool-process.js';

// A minimal target App skeleton generated from a project plan and its work specification. The
// skeleton owns the package manifest, shared types and the app shell; each feature's assigned files
// receive an initial stub that only reports not-implemented. Building it proves the shell and the
// declared dependency graph compile on this host; it is not a port and implements no behavior.
export const SKELETON_VERSION='carve/skeleton@1';
export const SUPPORTED_SKELETON_TARGETS=[{platform:'macos',delivery:'desktop-app'},{platform:'macos',delivery:'cli'},{platform:'macos',delivery:'module'}] as const;
const RESERVED=new Set(['carveshared','carveapp','swift','foundation','dispatch','darwin','xctest','testing','swiftui','appkit','combine','coregraphics','observation','os','packagedescription']);
const SELF_TEST_MARKER='CARVE-SELF-TEST ',FLOW_MARKER='CARVE-FLOW ';
type FileEntry={path:string;owner:string;text:string|Buffer};
export type SkeletonFeature={id:string;module:string;phase:number;dependsOn:string[];contractSha256:string;taskId:string;sourceDir:string;testDir:string|null;owner:'work-package'|'skeleton-unassigned-feature'};

const fail=(message:string):never=>{throw new Error('Skeleton: '+message);};
export function swiftModuleName(id:string){const name=id.split(/[-._]+/).filter(Boolean).map(part=>part[0]!.toUpperCase()+part.slice(1)).join('');return /^[A-Za-z_]/.test(name)?name:'F'+name;}
// Plan text goes into Swift line comments only; every line is prefixed so nothing escapes the comment.
const commentLines=(label:string,value:string|undefined)=>value===undefined?[]:[`//   ${label}:`,...value.split(/\r\n|\r|\n/).map(line=>'//     '+line)];

function layout(plan:ReturnType<typeof parseProjectPlan>,spec:z.infer<typeof workSpecSchema>){
 const analysis=analyzeProjectPlan(plan);
 const blocked=analysis.tasks.filter(t=>t.status!=='ready');
 if(blocked.length)fail(`the plan must be acyclic; ${blocked.length} feature(s) are in or behind a cycle (${blocked.slice(0,8).map(t=>t.id).join(', ')}). Swift targets cannot depend on each other in a cycle.`);
 const assignments=new Map(spec.assignments.map(a=>[a.feature,a])),modules=new Map<string,string>(),dirs=new Map<string,string>(),features:SkeletonFeature[]=[];
 for(const task of analysis.tasks){
  const feature=plan.features.find(f=>f.id===task.id)!,module=swiftModuleName(task.id),moduleKey=module.toLowerCase();
  if(RESERVED.has(moduleKey))fail(`feature ${task.id} maps to the reserved Swift module name ${module}.`);
  if(modules.has(moduleKey))fail(`features ${modules.get(moduleKey)} and ${task.id} map to the same Swift module name ${module}.`);modules.set(moduleKey,task.id);
  const assignment=assignments.get(task.id);let sourceDir:string,testDir:string|null=null;
  if(assignment){
   const sources:string[]=[],tests:string[]=[];
   for(const file of assignment.files){
    const parts=file.split('/');
    if(!file.endsWith('.swift')&&!(parts[0]==='Sources'&&parts[2]==='Resources'&&parts.length>=4))fail(`feature ${task.id} is assigned ${file}; this target supports only .swift files under Sources/<dir>/ or Tests/<dir>/ (layout-unsupported).`);
    if(parts.length<3||(parts[0]!=='Sources'&&parts[0]!=='Tests'))fail(`feature ${task.id} is assigned ${file}, which is not under Sources/<dir>/ or Tests/<dir>/ (layout-unsupported).`);
    (parts[0]==='Sources'?sources:tests).push(parts[1]!);
   }
   if(!assignment.files.some(f=>f.startsWith('Sources/')&&f.endsWith('.swift')&&!f.includes('/Resources/')))fail(`feature ${task.id} has no assigned Swift source file under Sources/<dir>/ (layout-unsupported).`);
   if(new Set(sources).size>1||new Set(tests).size>1)fail(`feature ${task.id} spreads its files over several directories; one Sources/<dir>/ and at most one Tests/<dir>/ per feature (layout-unsupported).`);
   sourceDir='Sources/'+sources[0];if(tests.length)testDir='Tests/'+tests[0];
  }else sourceDir='Sources/'+task.id;
  for(const dir of [sourceDir,testDir].filter((d):d is string=>d!==null)){
   const name=dir.split('/')[1]!.toLowerCase();if(RESERVED.has(name))fail(`directory ${dir} of feature ${task.id} collides with a skeleton-owned or system name (layout-unsupported).`);
   const key=dir.toLowerCase();if(dirs.has(key))fail(`features ${dirs.get(key)} and ${task.id} share ${dir}; each feature needs its own directory (layout-unsupported).`);dirs.set(key,task.id);
  }
  features.push({id:task.id,module,phase:task.phase!,dependsOn:[...feature.dependsOn].sort(),contractSha256:task.contractSha256??'',taskId:task.taskId,sourceDir,testDir,owner:assignment?'work-package':'skeleton-unassigned-feature'});
 }
 return{analysis,features,assignments};
}

function stubSource(feature:SkeletonFeature,features:Map<string,SkeletonFeature>,contract:Record<string,string>|undefined){
 return [`// Initial stub generated by RECarve ${SKELETON_VERSION} for feature "${feature.id}".`,
  `// Owner: ${feature.owner==='work-package'?'the work package assigned to this feature':'the skeleton (this feature has no work assignment yet)'}.`,
  '// Replace run(_:dependencies:) with the real implementation. Keep id, contractSha256 and dependsOn',
  '// unless the plan changes; the app reports contract-mismatch when contractSha256 differs from the plan.',
  '// Declared interface (from the project plan; pinned by contractSha256):',
  ...commentLines('input',contract?.input),...commentLines('output',contract?.output),...commentLines('state',contract?.state),...commentLines('errors',contract?.errors),
  ...(contract?[]:['//   (no interface declared in the plan)']),
  'import CarveShared',...feature.dependsOn.map(id=>`import ${features.get(id)!.module}`),'',
  `public enum ${feature.module}Feature: CarveFeature {`,
  `    public static let id = "${feature.id}"`,
  `    public static let contractSha256 = "${feature.contractSha256}"`,
  `    public static let dependsOn: [String] = [${feature.dependsOn.map(d=>`"${d}"`).join(', ')}]`,'',
  '    public static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse {',
  '        throw FeatureError.notImplemented(id)','    }','}',''].join('\n');
}
const placeholder=(feature:SkeletonFeature,role:string)=>`// Placeholder generated by RECarve ${SKELETON_VERSION} for ${role} of feature "${feature.id}". Owned by its work package.\n`;
function stubTest(feature:SkeletonFeature){
 return [`// Initial test stub generated by RECarve ${SKELETON_VERSION} for feature "${feature.id}". Owned by its work package.`,
  'import XCTest','import CarveShared',`@testable import ${feature.module}`,'',
  `final class ${feature.module}FeatureTests: XCTestCase {`,'    func testDeclaresPlannedInterface() {',
  `        XCTAssertEqual(${feature.module}Feature.id, "${feature.id}")`,`        XCTAssertEqual(${feature.module}Feature.contractSha256, "${feature.contractSha256}")`,
  '    }','}',''].join('\n');
}

const SHARED=`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.
import Foundation

public struct FeatureRequest: Sendable, Equatable {
    public let payload: String
    public init(payload: String) { self.payload = payload }
}

public struct FeatureResponse: Sendable, Equatable {
    public let payload: String
    public init(payload: String) { self.payload = payload }
}

public struct FeatureOutputs: Sendable {
    private let values: [String: FeatureResponse]
    public init(_ values: [String: FeatureResponse] = [:]) { self.values = values }
    /// Output of a direct dependency, read as dependencies[feature: "id"]; nil when it did not run.
    public subscript(feature feature: String) -> FeatureResponse? { values[feature] }
}

public enum FeatureError: Error, Equatable {
    case notImplemented(String)
    case failed(String, String)
}

public protocol CarveFeature {
    static var id: String { get }
    static var contractSha256: String { get }
    static var dependsOn: [String] { get }
    static func run(_ request: FeatureRequest, dependencies: FeatureOutputs) throws -> FeatureResponse
}

public struct RegisteredFeature: Sendable {
    public let id: String
    public let phase: Int
    public let dependsOn: [String]
    public let expectedContractSha256: String
    public let declaredContractSha256: String
    public let run: @Sendable (FeatureRequest, FeatureOutputs) throws -> FeatureResponse
    public init(id: String, phase: Int, dependsOn: [String], expectedContractSha256: String, declaredContractSha256: String,
                run: @escaping @Sendable (FeatureRequest, FeatureOutputs) throws -> FeatureResponse) {
        self.id = id; self.phase = phase; self.dependsOn = dependsOn
        self.expectedContractSha256 = expectedContractSha256; self.declaredContractSha256 = declaredContractSha256; self.run = run
    }
}

public struct FeatureResult: Sendable {
    public let id: String
    public let status: String
    public let detail: String?
    public let output: FeatureResponse?
}

/// Runs features in plan phase order. A feature whose direct dependency did not succeed is not run.
public enum SkeletonRunner {
    public static func evaluate(_ features: [RegisteredFeature], input: String) -> [FeatureResult] {
        var outputs: [String: FeatureResponse] = [:]
        var results: [FeatureResult] = []
        for feature in features {
            if feature.declaredContractSha256 != feature.expectedContractSha256 {
                results.append(FeatureResult(id: feature.id, status: "contract-mismatch", detail: "module declares \\(feature.declaredContractSha256), plan expects \\(feature.expectedContractSha256)", output: nil))
                continue
            }
            let missing = feature.dependsOn.filter { outputs[$0] == nil }
            if !missing.isEmpty {
                results.append(FeatureResult(id: feature.id, status: "blocked-by-dependency", detail: missing.joined(separator: ","), output: nil))
                continue
            }
            var inputs: [String: FeatureResponse] = [:]
            for dependency in feature.dependsOn { inputs[dependency] = outputs[dependency] }
            do {
                let output = try feature.run(FeatureRequest(payload: input), FeatureOutputs(inputs))
                outputs[feature.id] = output
                results.append(FeatureResult(id: feature.id, status: "implemented-ok", detail: nil, output: output))
            } catch FeatureError.notImplemented {
                results.append(FeatureResult(id: feature.id, status: "not-implemented", detail: nil, output: nil))
            } catch FeatureError.failed(_, let message) {
                results.append(FeatureResult(id: feature.id, status: "failed", detail: message, output: nil))
            } catch {
                results.append(FeatureResult(id: feature.id, status: "failed", detail: String(describing: error), output: nil))
            }
        }
        return results
    }

    public static func closure(of target: String, in features: [RegisteredFeature]) -> [RegisteredFeature] {
        let byId = Dictionary(uniqueKeysWithValues: features.map { ($0.id, $0) })
        var needed: Set<String> = []
        var pending = [target]
        while let next = pending.popLast() {
            if needed.insert(next).inserted, let feature = byId[next] { pending.append(contentsOf: feature.dependsOn) }
        }
        return features.filter { needed.contains($0.id) }
    }

    public static func json(_ value: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    public static func describe(_ result: FeatureResult) -> [String: Any] {
        var entry: [String: Any] = ["id": result.id, "status": result.status]
        if let detail = result.detail { entry["detail"] = detail }
        if let output = result.output { entry["outputCharacters"] = output.payload.count }
        return entry
    }
}
`;

function registry(features:SkeletonFeature[],planId:string,defaultFlow:string){
 return [`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.`,'import CarveShared',...features.map(f=>`import ${f.module}`),'',
  'enum CarveRegistry {',`    static let planId = "${planId}"`,`    static let defaultFlow = "${defaultFlow}"`,
  '    /// Features in plan phase order; expected contract pins come from the plan, declared ones from each module.',
  '    static let features: [RegisteredFeature] = [',
  ...features.map(f=>`        RegisteredFeature(id: "${f.id}", phase: ${f.phase}, dependsOn: [${f.dependsOn.map(d=>`"${d}"`).join(', ')}], expectedContractSha256: "${f.contractSha256}", declaredContractSha256: ${f.module}Feature.contractSha256, run: { try ${f.module}Feature.run($0, dependencies: $1) }),`),
  '    ]','}',''].join('\n');
}
const COMMAND=`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.
import Foundation
import CarveShared

enum CarveCommand {
    static func handles(_ arguments: [String]) -> Bool {
        arguments.contains("--self-test") || arguments.contains("--flow") || arguments.contains("--help")
    }

    static func value(after flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else { return nil }
        return arguments[index + 1]
    }

    /// Exit code 0 when every feature ran or was reported; 2 when a module's contract pin differs from the plan.
    static func run(_ arguments: [String]) -> Int32 {
        let input = value(after: "--input", in: arguments) ?? ""
        if arguments.contains("--flow") {
            let target = value(after: "--flow", in: arguments) ?? CarveRegistry.defaultFlow
            guard CarveRegistry.features.contains(where: { $0.id == target }) else {
                print("${FLOW_MARKER}" + SkeletonRunner.json(["schema": "carve/skeleton-flow@1", "error": "unknown feature \\(target)"]))
                return 1
            }
            let results = SkeletonRunner.evaluate(SkeletonRunner.closure(of: target, in: CarveRegistry.features), input: input)
            let last = results.last { $0.id == target }
            var report: [String: Any] = ["schema": "carve/skeleton-flow@1", "planId": CarveRegistry.planId, "flow": target,
                                         "steps": results.map(SkeletonRunner.describe), "completed": last?.status == "implemented-ok"]
            if let output = last?.output { report["output"] = output.payload }
            print("${FLOW_MARKER}" + SkeletonRunner.json(report))
            return results.contains { $0.status == "contract-mismatch" } ? 2 : 0
        }
        if arguments.contains("--self-test") {
            let results = SkeletonRunner.evaluate(CarveRegistry.features, input: input)
            print("${SELF_TEST_MARKER}" + SkeletonRunner.json(["schema": "carve/skeleton-self-test@1", "planId": CarveRegistry.planId,
                "features": results.map(SkeletonRunner.describe), "implemented": results.filter { $0.status == "implemented-ok" }.count, "total": results.count]))
            return results.contains { $0.status == "contract-mismatch" } ? 2 : 0
        }
        print("RECarve skeleton for plan \\(CarveRegistry.planId). Options: --self-test [--input TEXT], --flow FEATURE [--input TEXT]. Default flow: \\(CarveRegistry.defaultFlow).")
        return 0
    }
}
`;
const CLI_MAIN=`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.
import Foundation

exit(CarveCommand.run(Array(CommandLine.arguments.dropFirst())))
`;
const APP_MAIN=`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.
import Foundation
import SwiftUI
import CarveShared

let arguments = Array(CommandLine.arguments.dropFirst())
if CarveCommand.handles(arguments) { exit(CarveCommand.run(arguments)) }
CarveSkeletonApp.main()

struct CarveSkeletonApp: App {
    var body: some Scene {
        WindowGroup("RECarve skeleton") { SkeletonStatusView() }
    }
}

/// Shows each planned feature and the status of its current implementation.
struct SkeletonStatusView: View {
    private let results = SkeletonRunner.evaluate(CarveRegistry.features, input: "")
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Plan \\(CarveRegistry.planId.prefix(12))").font(.headline)
            Text("\\(results.filter { $0.status == "implemented-ok" }.count) of \\(results.count) features implemented").font(.subheadline)
            ForEach(results, id: \\.id) { result in
                HStack { Text(result.id).bold(); Spacer(); Text(result.status).foregroundStyle(result.status == "implemented-ok" ? .green : .secondary) }
            }
        }
        .padding(20)
        .frame(minWidth: 360, minHeight: 200)
    }
}
`;

function packageManifest(features:SkeletonFeature[],delivery:string,wiring?:SkeletonWiring){
 const app=delivery!=='module',targets=[`        .target(name: "CarveShared", path: "Sources/CarveShared")`];
 for(const f of features){
 const products=(wiring?.packages??[]).flatMap(p=>p.products.filter(x=>x.features.includes(f.id)).map(x=>`.product(name: "${x.name}", package: "${p.id}")`));
 const resources=(wiring?.resources??[]).filter(r=>r.feature===f.id).map(r=>`.${r.rule}(${JSON.stringify(r.path.slice(f.sourceDir.length+1))})`);
 const link=wiring?.links.find(l=>l.feature===f.id),settings=[...(link?.frameworks??[]).map(x=>`.linkedFramework("${x}")`),...(link?.libraries??[]).map(x=>`.linkedLibrary("${x}")`)];
 targets.push(`        .target(name: "${f.module}", dependencies: [${['"CarveShared"',...f.dependsOn.map(d=>`"${features.find(x=>x.id===d)!.module}"`),...products].join(', ')}], path: "${f.sourceDir}"${resources.length?', resources: ['+resources.join(', ')+']':''}${settings.length?', linkerSettings: ['+settings.join(', ')+']':''})`);
 }
 if(app)targets.push(`        .executableTarget(name: "CarveApp", dependencies: [${['"CarveShared"',...features.map(f=>`"${f.module}"`)].join(', ')}], path: "Sources/CarveApp")`);
 for(const f of features)if(f.testDir)targets.push(`        .testTarget(name: "${f.module}Tests", dependencies: ["CarveShared", "${f.module}"], path: "${f.testDir}")`);
 const products=app?'.executable(name: "CarveApp", targets: ["CarveApp"])':`.library(name: "CarveFeatures", targets: [${features.map(f=>`"${f.module}"`).join(', ')}])`;
 return [`// swift-tools-version:5.9`,`// Generated by RECarve ${SKELETON_VERSION}. Skeleton-owned: regenerate the skeleton instead of editing.`,'import PackageDescription','',
  'let package = Package(','    name: "CarveSkeleton",',...(wiring?.resources.length?['    defaultLocalization: "en",']:[]),'    platforms: [.macOS(.v13)],',`    products: [${products}],`,...(wiring?.packages.length?['    dependencies: [',wiring.packages.map(p=>p.kind==='local'?`        .package(name: "${p.id}", path: "Vendor/${p.id}")`:`        .package(name: "${p.id}", url: "${p.url}", revision: "${p.revision}")`).join(',\n'),'    ],']:[]),'    targets: [',targets.join(',\n'),'    ]',')',''].join('\n');
}

export async function createSkeleton(planInput:unknown,specInput:unknown,out:string,options:{signal?:AbortSignal;wiring?:unknown;sourceRoot?:string;authorizePath?:BridgePathAccess}={}){
 const plan=parseProjectPlan(planInput),spec=workSpecSchema.parse(specInput),target=plan.target;
 if(!SUPPORTED_SKELETON_TARGETS.some(t=>t.platform===target.platform&&t.delivery===target.delivery))
  fail(`target ${target.platform}/${target.delivery} is not supported yet (unsupported-target). Supported: ${SUPPORTED_SKELETON_TARGETS.map(t=>t.platform+'/'+t.delivery).join(', ')}.`);
 // Same validation as work packages: current plan revision, task ids, file ownership and complete interfaces.
 const records=new Map(spec.assignments.map(a=>[a.feature,bindWorkContract(planInput,specInput,a.feature)]));
 const {analysis,features}=layout(plan,spec),byId=new Map(features.map(f=>[f.id,f])),specId=[...records.values()][0]!.specId;
 const prepared=options.wiring?await prepareSkeletonWiring(options.wiring,options.sourceRoot,features,new Map(spec.assignments.map(a=>[a.feature,a])),analysis.planId,specId,options.authorizePath):undefined;
 if(!prepared&&spec.assignments.some(a=>a.files.some(f=>!f.endsWith('.swift'))))fail('Assigned resources require explicit wiring and input pins.');
 const last=Math.max(...features.map(f=>f.phase)),defaultFlow=features.filter(f=>f.phase===last).sort((a,b)=>b.dependsOn.length-a.dependsOn.length||(a.id<b.id?-1:1))[0]!.id;
 const files:FileEntry[]=[{path:'Package.swift',owner:'skeleton',text:packageManifest(features,target.delivery,prepared?.wiring)},{path:'Sources/CarveShared/Feature.swift',owner:'skeleton',text:SHARED}];
 if(target.delivery!=='module')files.push({path:'Sources/CarveApp/Registry.swift',owner:'skeleton',text:registry(features,analysis.planId,defaultFlow)},
  {path:'Sources/CarveApp/Command.swift',owner:'skeleton',text:COMMAND},{path:'Sources/CarveApp/main.swift',owner:'skeleton',text:target.delivery==='desktop-app'?APP_MAIN:CLI_MAIN});
 for(const feature of features){
  const record=records.get(feature.id),contract=plan.features.find(f=>f.id===feature.id)!.contract as Record<string,string>|undefined,owner='feature:'+feature.id;
  if(!record){files.push({path:feature.sourceDir+'/Module.swift',owner,text:stubSource(feature,byId,contract)});continue;}
  const assigned=[...record.assignment.files].sort(),sources=assigned.filter(f=>f.startsWith('Sources/')&&f.endsWith('.swift')),tests=assigned.filter(f=>f.startsWith('Tests/'));
  const primary=sources.find(f=>path.posix.basename(f)==='Module.swift')??sources[0]!,primaryTest=tests.find(f=>path.posix.basename(f)==='ModuleTests.swift')??tests[0];
  for(const file of sources)files.push({path:file,owner,text:file===primary?stubSource(feature,byId,contract):placeholder(feature,'a source file')});
  for(const file of tests)files.push({path:file,owner,text:file===primaryTest?stubTest(feature):placeholder(feature,'a test file')});
 }
 for(const copied of prepared?.copied??[]){const existing=files.find(f=>f.path===copied.path);if(existing)existing.text=copied.text;else files.push({path:copied.path,owner:copied.owner,text:copied.text});}
 files.push({path:'SKELETON.md',owner:'skeleton',text:readme(features,target.delivery,defaultFlow,Boolean(prepared))});
 // The parent must already exist; the skeleton folder itself must not.
 const root=path.resolve(out),parent=await realpath(path.dirname(root)),dir=path.join(parent,path.basename(root));
 await options.authorizePath?.(dir,true);options.signal?.throwIfAborted();await mkdir(dir);
 const written=[];
 try{
  for(const file of files){options.signal?.throwIfAborted();const full=path.join(dir,...file.path.split('/'));await options.authorizePath?.(full,true);await mkdir(path.dirname(full),{recursive:true});await writeFile(full,file.text,{flag:'wx'});
   written.push({path:file.path,owner:file.owner,sha256:digest(file.text),bytes:Buffer.byteLength(file.text)});}
  const manifest={schema:SKELETON_VERSION,generator:{name:'carve-skeleton',version:'1',sha256:digest(await readFile(fileURLToPath(import.meta.url)))},planId:analysis.planId,specId,target,
   ...(prepared?{wiring:prepared.wiring,wiringSha256:digest(JSON.stringify(prepared.wiring)),inputPins:prepared.copied.map(f=>({path:f.path,sha256:f.sha256}))}:{}),packageName:'CarveSkeleton',app:target.delivery==='module'?null:{target:'CarveApp',defaultFlow},features,files:written,
   scope:prepared?'A generated shell with explicitly pinned agent implementations/resources and remaining stubs. Copied inputs are not recovered original behavior; only checkSkeleton establishes host build results.':'A buildable shell and the declared dependency graph with not-implemented stubs. Not a port: no feature behavior, no original comparison, no target-platform completeness. Built only when checkSkeleton reports it.'};
  await options.authorizePath?.(path.join(dir,'carve-skeleton.json'),true);await writeFile(path.join(dir,'carve-skeleton.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx'});
  return{schema:'carve/skeleton-created@1',skeleton:dir,planId:analysis.planId,specId,target,features:features.map(f=>({id:f.id,module:f.module,phase:f.phase,owner:f.owner,sourceDir:f.sourceDir,testDir:f.testDir})),
   files:written.length,defaultFlow:manifest.app?.defaultFlow??null,built:false,next:'Run checkSkeleton to build it on this host.'};
 }catch(error){throw new Error('Skeleton creation did not finish; partial files retained at '+dir+'. '+(error as Error).message);}
}

function readme(features:SkeletonFeature[],delivery:string,defaultFlow:string,wired=false){
 return [`# RECarve skeleton`,'',`Generated by RECarve ${SKELETON_VERSION} for a macOS ${delivery}. Skeleton-owned files are listed in carve-skeleton.json; feature files belong to their work packages.`,'',
  '| Feature | Swift module | Phase | Depends on | Files |','| --- | --- | --- | --- | --- |',
  ...features.map(f=>`| ${f.id} | ${f.module} | ${f.phase} | ${f.dependsOn.join(', ')||'—'} | ${f.sourceDir}${f.testDir?', '+f.testDir:''} |`),'',
  wired?'Assigned implementation and resource files may be copied from pinned inputs; remaining features are stubs. Building establishes host compilation only, not original equivalence. See carve-skeleton.json for exact inputs and wiring.':'Every feature starts as a stub that throws `FeatureError.notImplemented`. Building this package shows the shell and dependency graph compile; it does not mean any feature works.','',
  '```sh','swift build',...(delivery==='module'?['swift test']:['.build/debug/CarveApp --self-test',`.build/debug/CarveApp --flow ${defaultFlow}`]),'```',''].join('\n');
}

export const manifestSchema=z.object({schema:z.literal(SKELETON_VERSION),planId:z.string(),specId:z.string(),target:z.object({platform:z.string(),delivery:z.string()}).passthrough(),
 app:z.object({target:z.string(),defaultFlow:z.string()}).nullable(),features:z.array(z.object({id:z.string()}).passthrough()),
 files:z.array(z.object({path:z.string(),owner:z.string(),sha256:z.string(),bytes:z.number()}).strict())}).passthrough();
const parseMarker=(text:string,marker:string)=>{const line=text.split('\n').reverse().find(l=>l.startsWith(marker));if(!line)return null;try{return JSON.parse(line.slice(marker.length));}catch{return null;}};

/** Builds the skeleton with the host Swift toolchain and runs its self-test and default flow. */
export async function checkSkeleton(input:string,options:{test?:boolean;flow?:string;timeoutMs?:number;signal?:AbortSignal;scratchPath?:string;authorizePath?:BridgePathAccess}={}){
 const dir=await realpath(path.resolve(input));await options.authorizePath?.(dir);await options.authorizePath?.(path.join(dir,'carve-skeleton.json'));const manifestInfo=await lstat(path.join(dir,'carve-skeleton.json'));if(!manifestInfo.isFile()||manifestInfo.size>4194304)fail('manifest must be regular and at most4MiB.');const raw=await readFile(path.join(dir,'carve-skeleton.json'),'utf8');if(Buffer.byteLength(raw)>4194304)fail('manifest is larger than 4MiB.');
 const manifest=manifestSchema.parse(JSON.parse(raw)),files=[];if(manifest.files.length>4096||new Set(manifest.files.map(f=>f.path.normalize('NFC').toLowerCase())).size!==manifest.files.length)fail('invalid manifest file count/duplicates.');
 for(const file of manifest.files){
  if(path.isAbsolute(file.path)||file.path.split('/').some(p=>!p||p==='.'||p==='..')||/[\\\x00-\x1f]/.test(file.path))fail('unsafe manifest file path.');const full=path.join(dir,...file.path.split('/'));await options.authorizePath?.(full);if(await realpath(full)!==full)fail('manifest files must not redirect through symlinks.');let info;try{info=await lstat(full);}catch{fail(`file ${file.path} is missing.`);}
  if(info!.isSymbolicLink()||!info!.isFile()||info!.size>8388608)fail(`file ${file.path} must be a regular file, not a link.`);
  const sha=digest(await readFile(full));files.push({path:file.path,owner:file.owner,changed:sha!==file.sha256});
 }
 const changedSkeleton=files.filter(f=>(f.owner==='skeleton'||f.owner==='skeleton-vendor')&&f.changed&&f.path!=='SKELETON.md');
 if(changedSkeleton.length)fail(`skeleton-owned files were edited (${changedSkeleton.map(f=>f.path).join(', ')}); regenerate instead.`);
 const logs=path.join(dir,'.carve-check');await options.authorizePath?.(logs,true);await mkdir(logs,{recursive:true});if(await realpath(logs)!==logs)fail('check logs must not redirect through symlinks.');const stamp=new Date().toISOString().replace(/[:.]/g,'-');
 const env={PATH:process.env.PATH??'/usr/bin:/bin',HOME:process.env.HOME??dir,TMPDIR:process.env.TMPDIR??'/tmp',LANG:'en_US.UTF-8',...(process.env.DEVELOPER_DIR?{DEVELOPER_DIR:process.env.DEVELOPER_DIR}:{})};
 // Build products default to <skeleton>/.build; callers may keep them elsewhere (they can be hundreds of MiB).
 const timeoutMs=options.timeoutMs??900000,scratch=options.scratchPath?path.resolve(options.scratchPath):path.join(dir,'.build');
 if(!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>900000)fail('timeoutMs must be50–900000.');await options.authorizePath?.(scratch,true);try{if(await realpath(scratch)!==scratch)fail('scratch path must not redirect through symlinks.');}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}
 const run=async(name:string,command:string,args:string[])=>{const log=path.join(logs,`${stamp}-${name}.log`);await options.authorizePath?.(log,true);const r=await runTool(command,args,{cwd:dir,env,log,timeoutMs,signal:options.signal,maxLogBytes:16*1024*1024});return{exitCode:r.exitCode,log,text:await readFile(log,'utf8')};};
 const toolchain=(await run('version','/usr/bin/env',['swift','--version'])).text.trim().split('\n')[0]??'unknown';
 const build=await run('build','/usr/bin/env',['swift','build','--package-path',dir,'--scratch-path',scratch]);
 const result:Record<string,unknown>={schema:'carve/skeleton-check@1',skeleton:dir,planId:manifest.planId,target:manifest.target,host:{platform:process.platform,arch:process.arch,toolchain},
  featureFiles:files.filter(f=>f.owner.startsWith('feature:')).map(f=>{const copied=Array.isArray(manifest.inputPins)&&manifest.inputPins.some(x=>x.path===f.path);return{path:f.path,owner:f.owner,baseline:copied?'copied-input':'generated-stub',changedFromBaseline:f.changed,...(!copied?{changedFromStub:f.changed}:{})};}),
  build:{exitCode:build.exitCode,log:build.log,passed:build.exitCode===0,products:scratch}};
 if(build.exitCode===0&&manifest.app){
  const binary=path.join(scratch,'debug','CarveApp');
  const self=await run('self-test',binary,['--self-test']);result.selfTest={exitCode:self.exitCode,log:self.log,report:parseMarker(self.text,SELF_TEST_MARKER)};
  const flow=await run('flow',binary,['--flow',options.flow??manifest.app.defaultFlow]);result.flow={exitCode:flow.exitCode,log:flow.log,report:parseMarker(flow.text,FLOW_MARKER)};
 }
 if(build.exitCode===0&&options.test){const test=await run('test','/usr/bin/env',['swift','test','--package-path',dir,'--scratch-path',scratch]);result.test={exitCode:test.exitCode,log:test.log,passed:test.exitCode===0};}
 result.scope='Build and self-test on this host only. Stubs report not-implemented; implemented-ok means a module returned without error, not that it matches the original program.';
 return result;
}
