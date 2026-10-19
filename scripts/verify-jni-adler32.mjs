import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdir,mkdtemp,readFile,writeFile,cp,rm} from 'node:fs/promises';
import {execFile,spawnSync} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {reverseTask} from '../dist/reverse.js';
import {hashFile} from '../dist/survey.js';
import {nativeAnalysis,readObservation} from '../dist/native.js';
import {managedAnalysis} from '../dist/managed.js';
import {inspectJni} from '../dist/jni.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {addCapability,getCapability} from '../dist/library.js';
import {invoke} from '../dist/runtime.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const execute=promisify(execFile);
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('The pinned Temurin libzip case is macOS arm64.');
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const engines=await readEngineConfiguration(process.argv[2]??path.join(root,'artifacts/engines/config.json'));const jdk=engines.javaHome,java=path.join(jdk,'bin/java');
assert.match(await readFile(path.join(jdk,'release'),'utf8'),/IMPLEMENTOR_VERSION="Temurin-21\.0\.12\.1\+1"/,'pinned Temurin JDK');
const pinned={'jmods/java.base.jmod':'c56b9ec12246262b4afdd8cdad3e4adf68171ae3300953248576661ab6a09cf7','lib/libzip.dylib':'46e21dc95a453fd5c14050ebf75b1e7a23a75ab3964fca43d69d9dfc1d35df45'};
for(const [file,sha256] of Object.entries(pinned))assert.equal((await hashFile(path.join(jdk,file))).sha256,sha256,file);
const out=await mkdtemp(path.join(root,'artifacts/jni-adler32-e2e-'));const input=path.join(out,'input'),extracted=path.join(out,'jmod');
const state={schema:'carve/jni-adler32-check@1',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,out,jdk:{implementor:'Temurin-21.0.12.1+1',pinned},analyses:[],status:'investigating'};
const save=()=>writeFile(path.join(out,'report.json'),JSON.stringify(state,null,2)+'\n');await save();
async function record(workspace,id){let first,offset=0;const text=[];do{const page=await readObservation(workspace,id,offset);first??=page;text.push(page.text);offset=page.nextOffset;if(offset>1048576)throw new Error('Evidence reader budget exceeded.');}while(offset!==null);return{...first,text:text.join(''),nextOffset:null};}
try{
 // The JDK's own jmod tool unpacks the shipped module; the JVM later runs the same build from lib/modules.
 await execute(path.join(jdk,'bin/jmod'),['extract','--dir',extracted,path.join(jdk,'jmods/java.base.jmod')]);
 await mkdir(path.join(input,'classes/java/util/zip'),{recursive:true});await mkdir(path.join(input,'lib'));
 await cp(path.join(extracted,'classes/java/util/zip/Adler32.class'),path.join(input,'classes/java/util/zip/Adler32.class'));await cp(path.join(jdk,'lib/libzip.dylib'),path.join(input,'lib/libzip.dylib'));
 await rm(extracted,{recursive:true});
 const goal='Reuse the JDK java.util.zip.Adler32 checksum by following its JNI native declaration into the shipped libzip implementation.';
 const task=await reverseTask(input,{goal,out:path.join(out,'work')});assert.equal(task.inventory.status,'indexed');const workspace=task.workspace;
 const provider={ghidra:engines.ghidra,javaHome:jdk,timeoutMs:1800000};
 let after;do{const page=await nativeAnalysis(workspace,{file:'lib/libzip.dylib',...provider,linkage:'exports',limit:1000,after});state.analyses.push(page);after=page.nextCursor??undefined;}while(after);
 const jni=await inspectJni(workspace,{files:['classes/java/util/zip/Adler32.class'],libraries:['lib/libzip.dylib']});state.jni=jni;
 const updateBytes=jni.items.find(i=>i.method==='updateBytes');assert.equal(updateBytes.status,'static-export-candidate');assert.equal(updateBytes.descriptor,'(I[BII)I');assert.equal(updateBytes.static,true);
 const exportRecord=updateBytes.candidates[0];assert.equal(exportRecord.name,'_Java_java_util_zip_Adler32_updateBytes');
 // Java side: complete JADX class decompilation.
 const managed=await managedAnalysis(workspace,{file:'classes/java/util/zip/Adler32.class',jadx:engines.jadx,javaHome:jdk});state.analyses.push(managed);assert.equal(managed.status,'sources-exported');
 const javaCode=await record(workspace,managed.observationIds[0]);assert.equal(javaCode.truncated,false);
 assert.match(javaCode.text,/private static native int updateBytes\(int \w+, byte\[\] \w+, int \w+, int \w+\);/);assert.match(javaCode.text,/this\.adler = updateBytes\(this\.adler, \w+, \w+, \w+\);/);assert.match(javaCode.text,/private int adler = 1;/);
 assert.match(javaCode.text,/& 4294967295L|& 0xffffffffL/i,'getValue widens the int state as unsigned');
 // Native side: JNI entry → adler32 → adler32_z, followed through actual callees.
 const native={};for(const selector of ['_Java_java_util_zip_Adler32_updateBytes']){const r=await nativeAnalysis(workspace,{file:'lib/libzip.dylib',...provider,function:selector});state.analyses.push(r);assert.equal(r.status,'function-exported');native.entry=await record(workspace,r.observationIds[0]);}
 const callee=(code,name)=>{const c=code.callees.find(c=>c.name===name);assert.ok(c,'callee '+name);return c.address;};
 for(const [key,from,name] of [['adler32','entry','_adler32'],['core','adler32','_adler32_z']]){const r=await nativeAnalysis(workspace,{file:'lib/libzip.dylib',...provider,function:callee(native[from],name)});state.analyses.push(r);assert.equal(r.status,'function-exported');native[key]=await record(workspace,r.observationIds[0]);}
 for(const code of Object.values(native)){assert.equal(code.truncated,false);assert.equal(code.decompilationStatus,'completed');}
 assert.match(native.entry.text,/\+ 0x6f0\)/,'JNIEnv GetPrimitiveArrayCritical slot');assert.match(native.entry.text,/\+ 0x6f8\)/,'JNIEnv ReleasePrimitiveArrayCritical slot');assert.match(native.entry.text,/_adler32\(/);
 assert.match(native.adler32.text,/_adler32_z\(/);assert.match(native.core.text,/0xfff1/);assert.match(native.core.text,/0x15b0/);
 state.boundary={jniDeclarationsId:updateBytes.observationId,exportRecordId:exportRecord.id,javaCodeId:javaCode.id,nativeCodeIds:Object.fromEntries(Object.entries(native).map(([k,v])=>[k,{id:v.id,name:v.name,address:v.address}])),
  scope:'Reviewed Java declaration/call site, derived JNI name, matching libzip export and three decompiled native functions (JNI array access, adler32, adler32_z with modulus 0xfff1 and block 0x15b0).'};await save();
 // Runtime binding evidence: the interpreter with the diagnostic intrinsic disabled links the native method from the loaded JDK libzip.
 const harnessSource=path.join(root,'examples/jvm/Adler32Harness.java'),harness=path.join(out,'harness');await mkdir(harness);
 await execute(path.join(jdk,'bin/javac'),['--release','21','-d',harness,harnessSource]);const harnessClass=path.join(harness,'carve/reference/Adler32Harness.class');
 const flags=['-Xint','-XX:+UnlockDiagnosticVMOptions','-XX:-UseAdler32Intrinsics','-Xshare:off'];
 const runtimeLog=path.join(out,'runtime-jni.log'),libraryLog=path.join(out,'runtime-library.log');
 const linked=spawnSync(java,[...flags,`-Xlog:jni+resolve=debug:file=${runtimeLog}`,`-Xlog:library=info:file=${libraryLog}`,'-Xlog:all=warning:stderr','-cp',harness,'carve.reference.Adler32Harness'],{input:Buffer.from([1,2,3]),encoding:'utf8',timeout:30000});
 assert.equal(linked.status,0,linked.stderr);assert.equal(linked.stdout,'851975');
 const jniLog=await readFile(runtimeLog,'utf8'),libLog=await readFile(libraryLog,'utf8');
 assert.match(jniLog,/Dynamic-linking native method java\.util\.zip\.Adler32\.updateBytes \.\.\. JNI/);assert.ok(libLog.includes('Loaded library '+path.join(jdk,'lib/libzip.dylib')));
 state.runtime={flags,jniLog:runtimeLog,libraryLog,observed:['java.util.zip.Adler32.updateBytes dynamically linked through JNI','JDK lib/libzip.dylib loaded'],scope:'JVM link/load logs for one run; not per-call instrumentation. The default JVM enables an Adler32 intrinsic that can bypass this native path; cases use the same flags to compare the native implementation.'};await save();
 // Independent implementation and contract.
 const source=path.join(out,'implementation');await mkdir(source);await writeFile(path.join(source,'package.json'),JSON.stringify({name:'jdk-adler32-reconstruction',version:'0.0.0',type:'module',license:'UNLICENSED'}));
 await writeFile(path.join(source,'NOTICE'),'Analyzed input: Eclipse Temurin 21.0.12.1+1 java.base (GPL-2.0 with Classpath Exception) and libzip with bundled zlib (zlib license). Independent JS behavior reconstruction; no upstream source was copied. This notice does not assign a license to the generated reconstruction.\n');
 const implementation=path.join(source,'adler32.mjs');await cp(path.join(root,'examples/jvm/adler32.mjs'),implementation);
 const unknowns=['Only a fresh Adler32 updated once with a whole byte array, then getValue(), is reconstructed. update(int), ByteBuffer/direct-memory paths, offsets/lengths, reset and multi-call state are not compared.','The default HotSpot configuration may use an Adler32 JIT intrinsic instead of libzip; cases compare the interpreter with that diagnostic intrinsic disabled, so intrinsic equivalence is not established.','JNI/C signatures and the JNIEnv slot meanings are analyzer/JNI-table interpretations. Runtime logs show linking and library load, not per-call tracing.','The JDK stays installed. The JVM executes java.base from lib/modules of the same build; the analyzed class bytes come from java.base.jmod of that build.','Input validation and the1048576-byte API bound are reconstruction choices, not Java exception behavior. Inputs longer than16657 bytes were not compared because the cases file is limited to1MiB.'];
 const contract={schema:'carve/reconstruction@2',goal,primary:'java',
  artifacts:[{key:'java',file:'classes/java/util/zip/Adler32.class',evidenceIds:[javaCode.id],supportingEvidenceIds:[updateBytes.observationId]},{key:'native',file:'lib/libzip.dylib',evidenceIds:[native.entry.id,native.adler32.id,native.core.id],supportingEvidenceIds:[exportRecord.id]}],
  relationships:[{from:{artifact:'java',id:javaCode.id},to:{artifact:'native',id:native.entry.id},kind:'calls',basis:'reviewed-static',description:'Adler32.update calls the static native updateBytes(I[BII)I; its derived JNI short name is exported by libzip, whose decompiled entry obtains the array and calls adler32 → adler32_z. A JVM jni+resolve log and library log separately show the link/load for one run. Not a per-call trace.'}],
  behavior:{description:'Adler-32 checksum of one complete byte array, matching new java.util.zip.Adler32(); update(bytes,0,length); getValue()',inputDomain:'One JSON array of0–1048576 integer bytes0–255; supplied original comparisons cover0–16657 bytes including three 5552-byte reduction blocks',outputDomain:'One JSON integer0–4294967295'},
  dependencies:[{name:'Adler-32 accumulation',status:'reimplemented',detail:'Closed JS loop with modulus65521 and reduction every5552 bytes, from the reviewed adler32_z; no JVM or native library is required by the result.'}],unknowns};
 const contractFile=path.join(out,'contract.json');await writeFile(contractFile,JSON.stringify(contract,null,2));
 const cases=[];let seed=0xad1e32;const random=n=>Array.from({length:n},()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed>>>24;});
 for(let n=0;n<100;n++)cases.push({name:'length-'+n,args:[random(n)]});
 for(const n of [5550,5551,5552,5553,5554,11103,11104,11105,16655,16656,16657])cases.push({name:'block-'+n,args:[random(n)]});
 for(const n of [5551,5552,5553,11104])cases.push({name:'max-bytes-'+n,args:[Array(n).fill(255)]});
 for(const n of [1,5552,5553])cases.push({name:'zeros-'+n,args:[Array(n).fill(0)]});
 for(const [text,expected] of [['Wikipedia',300286872],['abc',38600999],['',1]])cases.push({name:'known-'+(text||'empty'),args:[[...Buffer.from(text)]],expected});
 cases.push({name:'all-bytes',args:[Array.from({length:256},(_,i)=>i)]},{name:'descending',args:[Array.from({length:256},(_,i)=>255-i)]},{name:'unicode-bytes',args:[[...Buffer.from('\u6f22\u5b57😀\0\r\n')]]});
 while(cases.length<160)cases.push({name:'random-'+cases.length,args:[random(1+((cases.length*977)%2000))]});assert.equal(cases.length,160);assert.ok(Buffer.byteLength(JSON.stringify(cases))<1048576,'cases file limit');
 const casesFile=path.join(out,'cases.json'),reference=path.join(out,'reference.json');await writeFile(casesFile,JSON.stringify(cases));
 await writeFile(reference,JSON.stringify({schema:'carve/reference@2',command:[java,...flags,'-Xlog:disable','-Xlog:all=warning:stderr','-cp',harness,'carve.reference.Adler32Harness'],mode:'bytes-stdin',output:'json',scope:'external-harness',
  description:'Source-owned invocation adapter on the installed JDK: shipped java.util.zip.Adler32 plus its native libzip updateBytes compute each value (interpreter, diagnostic Adler32 intrinsic disabled). The adapter contains no checksum code.',
  boundFiles:[harnessClass,harnessSource,path.join(jdk,'lib/libzip.dylib'),path.join(jdk,'lib/modules'),path.join(jdk,'lib/server/libjvm.dylib')]}));
 const packaged=await reconstruct(workspace,{contract:contractFile,implementation,export:'adler32',out:path.join(out,'tool')});
 const verified=await verifyReconstruction(workspace,{package:packaged.out,cases:casesFile,reference,execute:true,timeoutMs:30000});
 assert.equal(verified.status,'passed-supplied-cases',JSON.stringify(verified.failures?.slice?.(0,2)??verified.status));assert.equal(verified.total,160);
 assert.ok(verified.reference.boundFiles.some(f=>f.file===path.join(jdk,'lib/libzip.dylib')&&f.sha256===pinned['lib/libzip.dylib']));
 // Reusable function folder; intermediate package and rewrite source removed.
 const library=path.join(out,'functions');const stored=await addCapability(packaged.out,{library,name:'adler32',description:'Compute the Adler-32 checksum of a byte array, reconstructed from the JDK JNI declaration and libzip implementation.',tags:['adler32','checksum','jni','zlib','jdk']});
 await rm(packaged.out,{recursive:true});await rm(source,{recursive:true});
 const checked=await getCapability(library,'adler32');assert.equal(checked.usage.verification.source.total,160);
 const sample=[...Buffer.from('Wikipedia')];assert.deepEqual(await invoke(stored.package,[sample],{execute:true}),{kind:'return',value:300286872});
 const module=await import(pathToFileURL(stored.entry).href);assert.equal(module.capability(sample),300286872);
 const client=new Client({name:'jni-adler32-function',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve-tool',stored.package,'--execute'],stderr:'pipe'}));
 try{const result=await client.callTool({name:'capability',arguments:{args:[sample]}});assert.equal(result.structuredContent.value,300286872);}finally{await client.close();}
 Object.assign(state,{status:'passed',checkedAt:new Date().toISOString(),packaged,verification:verified,stored,independence:{rewriteAndIntermediatePackageRemoved:true,originalInstalledJdkRetained:true,directImport:true,restrictedInvoke:true,mcp:true},
  scope:'Shipped JDK two-component JNI operation: Java class code and JNI declaration evidence, libzip export and three native code records, JVM link/load logs and160 comparisons against the installed JDK through a source-owned adapter. A small bounded checksum, not complete JDK/zlib recovery.'});await save();
 console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json'),function:stored.package,cases:verified.total}));
}catch(error){state.status='failed';state.error=String(error?.stack??error);await save();throw error;}
