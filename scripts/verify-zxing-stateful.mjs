// Local managed-backend test. No REA proxy/merged MCP, no app installation.
import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtemp,mkdir,cp,writeFile,readFile,rename,access} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readEngineConfiguration,readAndroidConfiguration} from '../dist/engine-config.js';
import {hashFile} from '../dist/survey.js';
import {readObservation} from '../dist/native.js';
import {prepareAndroidReference} from '../dist/android.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
const {values}=parseArgs({options:{engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')},runtime:{type:'string',default:path.join(root,'artifacts/android/config.json')}}});
const engines=await readEngineConfiguration(values.engines),device=await readAndroidConfiguration(values.runtime);
const upstream=path.join(root,'artifacts/third-party/zxing-4.7.8/BarcodeScanner-4.7.8.apk'),original=await hashFile(upstream);
assert.equal(original.sha256,'4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3','Pinned shipped APK required; obtain with verify:apk-manifest first.');
assert.ok(device.serial,'Explicit device serial required.');
const out=await mkdtemp(path.join(root,'artifacts/zxing-stateful-e2e-'));
const save=(name,value)=>writeFile(path.join(out,name),JSON.stringify(value,null,2)+'\n');
await save('engines.json',{jadx:engines.jadx,javaHome:engines.javaHome});
const client=new Client({name:'zxing-original-art-stateful',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',path.join(out,'engines.json')],stderr:'pipe'});
let diagnostics='';transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-8000);});
const unwrap=r=>{if(r.isError)throw new Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return r.structuredContent??JSON.parse(r.content.find(c=>c.type==='text').text);};
const call=async(c,name,args)=>unwrap(await c.callTool({name,arguments:args},undefined,{timeout:600000}));
try{
 await client.connect(transport);const tools=(await client.listTools()).tools;assert.equal(tools.length,48);assert.ok(!tools.some(t=>t.name==='procedure_pseudo_code'));
 await mkdir(path.join(out,'inputs'));await cp(upstream,path.join(out,'inputs/app.apk'));
 await call(client,'carve_reverse',{target:'inputs/app.apk',goal:'Inspect original shipped APK and reuse mutable BitArray operations',out:'container-work'});
 let unpacked;do{unpacked=await call(client,'carve_unpack',{workspace:'container-work',file:'app.apk'});}while(unpacked.status!=='unpacked');
 const task=await call(client,'carve_reverse',{target:path.relative(out,unpacked.content),goal:'Rebuild bounded BitArray state operations and compare ordered original ART object lifetimes',out:'work'});
 const analysis=await call(client,'carve_managed',{workspace:'work',file:'classes.dex',class:'com.google.zxing.common.BitArray'});assert.equal(analysis.status,'sources-exported');assert.equal(analysis.observationIds.length,1);
 let offset=0,text='';do{const page=await readObservation(task.workspace,analysis.observationIds[0],offset,12000);assert.equal(page.truncated,false);text+=page.text;offset=page.nextOffset;}while(offset!==null);
 for(const piece of ['new int[1]','this.size = 0','void clear()','appendBits(int value, int numBits)','void reverse()'])assert.ok(text.includes(piece),'Review complete original class: '+piece);
 await save('static-boundary.json',{analysis,text,scope:'Complete class from the original shipped DEX, not upstream source or a recompiled target. Reviewed constructor/size/clear/append/set/flip/reverse; no runtime call trace or general closure proof.'});
 const dex=path.join(unpacked.content,'classes.dex'),dexIdentity=await hashFile(dex);assert.equal(dexIdentity.sha256,'cfa20314b24e002b195501a59e02da4b023447b42808eab89b4757406a8ad0e3');
 await mkdir(path.join(out,'source'));await cp(path.join(root,'examples/android/zxing-bitarray-stateful.mjs'),path.join(out,'source/step.mjs'));
 await writeFile(path.join(out,'source/package.json'),JSON.stringify({name:'bitarray-reconstruction',version:'0.0.0',private:true,license:'UNLICENSED'}));
 await cp(path.join(root,'artifacts/third-party/zxing-4.7.8/LICENSE'),path.join(out,'source/LICENSE.zxing'));
 await writeFile(path.join(out,'source/NOTICE'),'Investigated ZXing Barcode Scanner4.7.8 shipped APK (Apache-2.0). Independent bounded JavaScript reconstruction, not recovered source. Output licensing is UNLICENSED pending review.\n');
 await writeFile(path.join(out,'source/wrong.mjs'),"import{bitArrayStep}from'./step.mjs';export function wrong(...args){bitArrayStep('new');return bitArrayStep(...args)}\n");
 await save('contract.json',{schema:'carve/reconstruction@1',goal:'Reuse bounded mutable bit-vector operations from the shipped ZXing APK',file:'classes.dex',evidenceIds:analysis.observationIds,
  behavior:{description:'One original no-argument BitArray per sequence. read returns getSize/getSizeInBytes/get(i) snapshots; append calls appendBits, clear zeroes bits without changing size, reverse/set/flip call the shipped methods. new explicitly replaces the object with the shipped no-argument constructor.',inputDomain:'Named operation arguments: read/clear/reverse/new with no parameters; append signed32 value and count0–32, total size<=4096; set/flip an existing nonnegative index.1–64 valid steps per sequence. Domain rejection is adapter policy, not original invalid-input behavior.',outputDomain:'One JSON snapshot {size,sizeInBytes,bits} per step. bits is a0/1 string of logical length. Fresh empty object/module per sequence; new is an adapter lifecycle operation, not a recovered original method.'},
  dependencies:[{name:'visible BitArray state',status:'reimplemented',detail:'Independent local boolean vector; no Android, APK, DEX or third-party library loaded by the candidate.'}],unknowns:['Only selected valid logical states and operations are compared; backing int-array capacity/padding/aliasing, other constructors/methods, clone/equality/hash/toBytes and invalid Java input/exception behavior are outside this boundary.','The reviewed harness controls the object lifetime and calls original shipped methods. Staging hashes/classloader identity are observations, not independent per-method tracing or a general dependency closure proof.','Android API35 ARM64 emulator ART only; no physical-device/all-runtime equivalence, QR/UI/scanning/network/server/hardware recovery, concurrent/timed or cross-request persistent sessions.']});
 for(const [implementation,exportName,pkg] of [['step.mjs','bitArrayStep','bitarray-package'],['wrong.mjs','wrong','wrong-package']])await call(client,'carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'source/'+implementation,export:exportName,out:pkg});
 const classes=path.join(out,'harness-classes'),harnessDex=path.join(out,'harness-dex');await mkdir(classes);await mkdir(harnessDex);
 const harnessSource=path.join(root,'examples/android/ZxingBitArraySequenceHarness.java');await exec(path.join(engines.javaHome,'bin/javac'),['--release','8','-d',classes,harnessSource]);
 await exec(path.join(engines.javaHome,'bin/java'),['-cp',engines.r8??path.join(root,'artifacts/engines/r8-9.5.26.jar'),'com.android.tools.r8.D8','--min-api','21','--output',harnessDex,path.join(classes,'carve/reference/ZxingBitArraySequenceHarness.class')]);
 const reference={schema:'carve/android-reference@4',mode:'json-sequence-stdin',adb:device.adb,serial:device.serial,serverPort:device.serverPort??5037,harness:path.join(harnessDex,'classes.dex'),entryClass:'carve.reference.ZxingBitArraySequenceHarness',dependencies:[],description:'Reviewed source-owned bounded framing/reflection adapter. One original shipped BitArray object per ART VM/sequence; new explicitly calls the original constructor again. Snapshots call original getSize/getSizeInBytes/get. No BitArray algorithm or target class is compiled into the adapter.'};
 await save('reference.json',reference);
 const snapshot=bits=>({size:bits.length,sizeInBytes:Math.ceil(bits.length/8),bits}),first=[['read'],['append',5,3],['clear'],['read'],['append',3,2],['reverse'],['flip',4],['set',2],['new'],['read'],['append',-2147483648,32]];
 const expected=['','101','000','000','00011','11000','11001','11101','','','1'+'0'.repeat(31)].map(snapshot);
 const cases=[{name:'initial state, clear preserves length, mutation and new object',steps:first.map((args,i)=>({args,expected:expected[i]}))},{name:'fresh sequence without explicit new',steps:[{args:['read'],expected:snapshot('')},{args:['reverse'],expected:snapshot('')},{args:['append',1,1],expected:snapshot('1')},{args:['append',0,0],expected:snapshot('1')}]}];
 for(const width of [0,1,7,8,9,30,31,32,33,63,64,65,95,96,97,127,128,129]){
  const calls=[['read']];let remaining=width;
  while(remaining>0){const n=Math.min(32,remaining);calls.push(['append',remaining%2?-2147483648:-1,n]);remaining-=n;}
  calls.push(['reverse'],['read'],['reverse']);if(width)calls.push(['flip',0],['set',width-1]);calls.push(['clear'],['read'],['append',5,3],['reverse'],['new'],['read']);cases.push({name:'logical length and word boundary '+width,steps:calls.map(args=>({args}))});
 }
 // Long64-step sequence and deterministic mixes test growth/order without a per-step reset.
 cases.push({name:'maximum64 ordered steps',steps:[{args:['read'],expected:snapshot('')},...Array.from({length:63},(_,i)=>({args:['append',i%2?-1:-2147483648,32]}))]});
 let seed=0xa7014b32;const rand=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
 for(let i=0;i<12;i++){const calls=[['read']];let size=0;for(let j=1;j<30;j++){const op=rand()%9;if(op<3){const width=rand()%33;calls.push(['append',rand()|0,width]);size+=width;}else if(op===3&&size){calls.push(['flip',rand()%size]);}else if(op===4&&size){calls.push(['set',rand()%size]);}else if(op===5)calls.push(['clear']);else if(op===6)calls.push(['reverse']);else if(op===7){calls.push(['new']);size=0;}else calls.push(['read']);}cases.push({name:'deterministic mixed lifecycle '+i,steps:calls.map(args=>({args}))});}
 const steps=cases.reduce((n,item)=>n+item.steps.length,0);assert.ok(steps<=1000);const serialized=JSON.stringify({schema:'carve/sequence-cases@1',cases});assert.ok(Buffer.byteLength(serialized)<=1048576);await writeFile(path.join(out,'cases.json'),serialized+'\n');
 const options={workspace:'work',cases:'cases.json',reference:'reference.json',execute:true,timeoutMs:10000,fullReport:true};
 // Negative subset only; wrong implementation resets for every call.
 await save('negative-cases.json',{schema:'carve/sequence-cases@1',cases:[cases[0]]});
 const negative=await call(client,'carve_verify_reconstruction',{...options,cases:'negative-cases.json',package:'wrong-package'});await save('negative-reset-per-call.json',negative);assert.equal(negative.status,'failed');assert.equal(negative.results[0].steps[2].passed,false);
 const comparison=await call(client,'carve_verify_reconstruction',{...options,package:'bitarray-package'});await save('comparison.json',comparison);
 assert.equal(comparison.status,'passed-supplied-cases');assert.equal(comparison.total,cases.length);assert.equal(comparison.passedSteps,steps);assert.equal(comparison.verifiedScope,'selected-dex-android-harness-sequences');assert.equal(comparison.androidRuntime.inputMode,'json-sequence-stdin');assert.equal(comparison.androidRuntime.cleanup,'removed');assert.equal(comparison.androidRuntime.processLifetime,'one-sequence');
 // Read the existing compact archive without re-executing all original sequences.
 const {id}=await import('../dist/verification-archive.js').then(async m=>m.archiveVerificationReport(task.workspace,comparison));
 const summary=await call(client,'carve_verification',{workspace:'work',id,budgetBytes:8192});await save('summary.json',summary);assert.equal(summary.totalSteps,steps);
 const page=await call(client,'carve_verification',{workspace:'work',id,view:'case',caseIndex:0,field:'steps',item:2});assert.deepEqual(JSON.parse(page.text).original.value,snapshot('000'));await save('step-page.json',page);
 // Separate runtime identity/protocol checks are not additional feature cases.
 const target={path:dex,sha256:dexIdentity.sha256,facts:dexIdentity.facts};
 const {mode:ignoredMode,...fields}=reference;
 const identitySession=await prepareAndroidReference(task.workspace,target,{...fields,schema:'carve/android-reference@2',mode:'argv-values'});
 let runtimeIdentity;try{runtimeIdentity=await identitySession.run(['--identity'],10000);assert.equal(runtimeIdentity.kind,'return');assert.equal(runtimeIdentity.value.className,'com.google.zxing.common.BitArray');assert.ok(runtimeIdentity.value.classLoader.includes(identitySession.identity.files[0].remote));assert.deepEqual(runtimeIdentity.value.initial,snapshot(''));}finally{assert.equal(await identitySession.cleanup(),'removed');}
 await save('runtime-identity.json',{...runtimeIdentity,staging:identitySession.identity,scope:'Observed classloader and constructor snapshot plus staged original DEX hashes. Not independent call instrumentation.'});
 const session=await prepareAndroidReference(task.workspace,target,reference);const protocol=[];
 try{
  for(const calls of [[['read'],['append',1,33]],[['append',2147483648,1]],[['set',0]],[['unknown']],[['read',1]],[['append',1,1],['flip',1]]]){const result=await session.run(calls,5000);assert.equal(result.kind,'harness-error');protocol.push({calls,result});}
  for(let i=0;i<2;i++)assert.deepEqual(await session.run([['read'],['append',5,3],['read']],5000),{kind:'return',value:['','101','101'].map(bits=>({kind:'return',value:snapshot(bits)}))});
  await session.verifyRemote();
 }finally{assert.equal(await session.cleanup(),'removed');}
 await save('protocol-checks.json',{invalidDomainRequests:protocol,freshVmTwice:true,scope:'Adapter framing/domain rejection and separate request lifetime checks, not original invalid-input behavior.'});
 const usage=await call(client,'carve_use',{package:'bitarray-package'});assert.equal(usage.example,null);assert.deepEqual(usage.exampleSequence.calls,first);
 const stored=await call(client,'carve_library_add',{package:'bitarray-package',library:'functions',name:'zxing-bitarray',title:'Original APK bit-array lifecycle reconstruction',description:'Reusable bit-vector append, update, reverse and clear, compared per sequence against original DEX on ART; clear preserves length and new reconstructs state.',tags:['android','stateful','bitarray']});
 assert.equal((await call(client,'carve_library_find',{library:'functions',query:'bitarray'})).total,1);assert.deepEqual((await call(client,'carve_library_get',{library:'functions',name:'zxing-bitarray'})).usage.exampleSequence.calls,first);
 await mkdir(path.join(out,'archive'));for(const folder of ['source','bitarray-package','wrong-package']){await rename(path.join(out,folder),path.join(out,'archive',folder));await assert.rejects(()=>access(path.join(out,folder)));}
 const capability=(await import(pathToFileURL(path.join(stored.package,'index.mjs')))).capability;assert.deepEqual(first.map(args=>capability(...args)),expected);
 const invoked=JSON.parse((await exec(process.execPath,[path.join(root,'dist/cli.js'),'invoke-sequence',stored.package,'--calls',JSON.stringify(first),'--execute'])).stdout);assert.deepEqual(invoked.value.map(row=>row.value),expected);
 const libraryClient=new Client({name:'bitarray-library-only',version:'1'});try{await libraryClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',path.join(out,'functions')],stderr:'pipe'}));for(let i=0;i<2;i++)assert.deepEqual((await call(libraryClient,'carve_invoke_sequence',{package:'zxing-bitarray',calls:first,execute:true})).value,expected.map(value=>({kind:'return',value})));}finally{await libraryClient.close();}
 assert.equal((await hashFile(upstream)).sha256,original.sha256);assert.equal((await hashFile(dex)).sha256,dexIdentity.sha256);
 const report={schema:'carve/zxing-stateful-check@1',status:'passed',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,checkedAt:new Date().toISOString(),out,
  upstream:{file:upstream,...original,url:'https://github.com/zxing/zxing/releases/tag/BS-4.7.8',publishedDigestAvailable:false,unchangedAfter:true},dex:{file:dex,...dexIdentity,unchangedAfter:true},analysis,
  harness:{source:harnessSource,sourceSha256:(await hashFile(harnessSource)).sha256,compiledClassSha256:(await hashFile(path.join(classes,'carve/reference/ZxingBitArraySequenceHarness.class'))).sha256,dex:reference.harness,dexSha256:(await hashFile(reference.harness)).sha256,targetRecompiled:false,objectLifetime:'One original no-argument constructor per sequence; explicit new replaces it, all other steps reuse it.',invocationEvidence:'Reviewed reflection adapter and separate classloader observation; no independent method trace.'},
  architecture:{carveTools:tools.length,carvePid:transport.pid,managedBackend:'JADX',reaStarted:false,reaProxied:false,nativeProviderUsed:false,reason:'Pure managed original DEX boundary. Existing RECarve managed backend is used; independent REA MCP native workflows remain unchanged.'},
  comparison:{passed:comparison.passed,total:comparison.total,passedSteps:comparison.passedSteps,totalSteps:comparison.totalSteps,scope:comparison.verifiedScope,android:comparison.androidRuntime,report:path.join(out,'comparison.json'),negativeResetPerCallRejected:true},
  reuse:{package:stored.package,wholeSequenceExample:true,constructionPathsArchived:true,originalInputsRetained:true,directImport:true,cli:true,libraryOnlyMcp:true,twoRequestsFresh:true},
  limitations:['Selected valid operations/observable logical bits only, not full ZXing, QR/UI/server or APK recovery. new is an explicit adapter operation, clear retains original logical length.','Only one API35 ARM64 emulator ART runtime; no physical-device/all-device, backing-capacity/aliasing, other APIs/exception semantics, concurrency/timing or cross-request state proof.','Original DEX is staged/hashed, loaded through a reviewed reflection boundary with classloader observation. This is not independent per-call instrumentation, general equivalence, producer authentication or dependency closure.']};
 await save('report.json',report);const summaryFile=path.join(root,'artifacts/zxing-stateful-verification-summary.json');await writeFile(summaryFile,JSON.stringify({status:'passed',version:report.version,report:path.join(out,'report.json'),function:stored.package,sequences:cases.length,steps,androidApi:comparison.androidRuntime.api},null,2)+'\n');console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json'),function:stored.package,sequences:cases.length,steps}));
}catch(error){await save('failure.json',{status:'failed',message:error.stack,diagnostics});throw error;}finally{await client.close().catch(()=>{});await save('diagnostics.json',{diagnostics});}
