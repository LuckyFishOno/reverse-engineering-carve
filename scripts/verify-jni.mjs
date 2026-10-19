import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,mkdtemp,readFile,writeFile,cp,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {survey,hashFile} from '../dist/survey.js';
import {nativeAnalysis} from '../dist/native.js';
import {inspectJni} from '../dist/jni.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const execute=promisify(execFile);
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const enginesFile=process.argv[2]??path.join(root,'artifacts/engines/config.json');const engines=await readEngineConfiguration(enginesFile);
const jdk=engines.javaHome;const release=await readFile(path.join(jdk,'release'),'utf8');
assert.match(release,/IMPLEMENTOR_VERSION="Temurin-21\.0\.12\.1\+1"/,'pinned Temurin JDK');
const pinned={'jmods/java.base.jmod':'c56b9ec12246262b4afdd8cdad3e4adf68171ae3300953248576661ab6a09cf7','lib/libzip.dylib':'46e21dc95a453fd5c14050ebf75b1e7a23a75ab3964fca43d69d9dfc1d35df45','lib/libjava.dylib':'30ed8d3f55fce957cd51ce59783115ee3574283c34b52e1b19c4c5382337722d'};
for(const [file,sha256] of Object.entries(pinned))assert.equal((await hashFile(path.join(jdk,file))).sha256,sha256,file);
const out=await mkdtemp(path.join(root,'artifacts/jni-e2e-'));const input=path.join(out,'input'),workspace=path.join(out,'work'),extracted=path.join(out,'jmod');
// The JDK's own jmod tool unpacks the shipped module; Carve does not parse the JMOD container.
await execute(path.join(jdk,'bin/jmod'),['extract','--dir',extracted,path.join(jdk,'jmods/java.base.jmod')]);
await mkdir(path.join(input,'classes/java/lang'),{recursive:true});await mkdir(path.join(input,'lib'));
await cp(path.join(extracted,'classes/java/util/zip'),path.join(input,'classes/java/util/zip'),{recursive:true});
for(const name of ['Object.class','Thread.class'])await cp(path.join(extracted,'classes/java/lang',name),path.join(input,'classes/java/lang',name));
for(const name of ['libzip.dylib','libjava.dylib'])await cp(path.join(jdk,'lib',name),path.join(input,'lib',name));
const scrcpy=path.join(root,'artifacts/third-party/scrcpy-5.0.1/container-work/containers/764eb6f79811d5211fe9df341120882ba9994c7a61b897d7bf3fb662e53bc536/content/classes.dex');
const zxing=path.join(root,'artifacts/third-party/zxing-4.7.8/container-work/containers/4d8c739e115e7aaf824dda3f2a55667459c48c2f140d15eadfd6d3d6271bb0b3/content/classes.dex');
await mkdir(path.join(input,'dex'));
// Official D8 converts the same shipped class bytes, so the DEX parser is checked against real declarations.
const r8=process.argv[3]??path.join(root,'artifacts/engines/r8-9.5.26.jar');const d8=path.join(out,'d8');await mkdir(d8);
const zipClasses=(await readdir(path.join(input,'classes/java/util/zip'))).filter(n=>n.endsWith('.class')).sort();
await execute(path.join(jdk,'bin/java'),['-cp',r8,'com.android.tools.r8.D8','--min-api','26','--output',d8,...zipClasses.map(n=>path.join(input,'classes/java/util/zip',n))],{maxBuffer:16*1024*1024});
await cp(path.join(d8,'classes.dex'),path.join(input,'dex/zip-d8.dex'));await cp(scrcpy,path.join(input,'dex/scrcpy-classes.dex'));await cp(zxing,path.join(input,'dex/zxing-classes.dex'));
await survey(input,{workspace});
// Index complete loader export pages with real Ghidra (no auto-analysis).
const exportPages={};
for(const lib of ['lib/libzip.dylib','lib/libjava.dylib']){
 let after,pages=0;do{const page=await nativeAnalysis(workspace,{file:lib,ghidra:engines.ghidra,javaHome:jdk,linkage:'exports',limit:1000,after});after=page.nextCursor??undefined;pages++;}while(after);exportPages[lib]=pages;
}
// Independent oracle: Apple nm over the same shipped bytes.
const nmJni=async lib=>new Set((await execute('nm',['-gU',path.join(input,lib)],{maxBuffer:16*1024*1024})).stdout.split('\n').map(l=>l.trim().split(/\s+/).at(-1)).filter(n=>n?.startsWith('_Java_')).map(n=>n.slice(1)));
const zipFiles=(await readdir(path.join(input,'classes/java/util/zip'))).filter(n=>n.endsWith('.class')).sort().map(n=>'classes/java/util/zip/'+n);
const all=async(options)=>{const items=[];let offset=0,first;while(true){const page=await inspectJni(workspace,{...options,limit:100,offset,budgetBytes:65536});first??=page;items.push(...page.items);if(page.nextOffset===null)break;offset=page.nextOffset;}return{...first,items};};
const zip=await all({files:zipFiles,libraries:['lib/libzip.dylib']});const zipExports=await nmJni('lib/libzip.dylib');
assert.equal(zip.libraries.allSelectedExportsKnownComplete,true);
assert.equal(zip.counts.declarations,zipExports.size,'every java.util.zip native declaration has one libzip Java_ export');
assert.ok(zip.items.every(i=>i.status==='static-export-candidate'&&i.candidates.length===1&&i.candidates[0].form==='short'));
assert.deepEqual(new Set(zip.items.map(i=>i.jniShortName)),zipExports,'derived names equal nm exports exactly');
const d8zip=await all({files:['dex/zip-d8.dex'],libraries:['lib/libzip.dylib']});
const key=i=>[i.className,i.method,i.descriptor,i.static,i.overloaded,i.jniShortName,i.jniLongName,i.status,i.candidates.map(c=>c.name).join()].join(' ');
assert.deepEqual(d8zip.items.map(key).sort(),zip.items.map(key).sort(),'D8 DEX declarations equal class-file declarations');
const lang=await all({files:['classes/java/lang/Object.class','classes/java/lang/Thread.class'],libraries:['lib/libjava.dylib']});const javaExports=await nmJni('lib/libjava.dylib');
for(const item of lang.items){
 const expected=javaExports.has(item.jniShortName)||javaExports.has(item.jniLongName);
 assert.equal(item.status==='static-export-candidate',expected,item.className+'.'+item.method);
 if(!expected){assert.equal(item.status,'no-indexed-static-export');assert.deepEqual(item.dynamicRegistrationLeads,['lib/libjava.dylib']);}
}
const onLoad=lang.libraries.indexedExports[0].jniOnLoad.map(e=>e.name);assert.deepEqual(onLoad,['_JNI_OnLoad']);
// Runtime cross-check: one JVM start logs which java.lang natives are registered versus linked by symbol name.
const jvmLog=path.join(out,'runtime-jni.log');await execute(path.join(jdk,'bin/java'),['-Xshare:off',`-Xlog:jni+resolve=debug:file=${jvmLog}`,'-Xlog:all=warning:stderr','-version']);
const logText=await readFile(jvmLog,'utf8');const logged=kind=>new Set([...logText.matchAll(new RegExp(kind+' (?:JNI )?native method (java\\.lang\\.(?:Object|Thread)\\.\\w+)','g'))].map(m=>m[1]));
const registered=logged('Registering JNI'),linked=logged('Dynamic-linking');const member=i=>i.className+'.'+i.method;
assert.deepEqual([...registered].sort(),lang.items.filter(i=>i.status==='no-indexed-static-export').map(member).sort(),'every runtime-registered java.lang native is one without a static export');
for(const name of linked)assert.equal(lang.items.find(i=>member(i)===name)?.status,'static-export-candidate',name+' linked by symbol');
const dex=[];for(const file of ['dex/scrcpy-classes.dex','dex/zxing-classes.dex']){const r=await all({files:[file]});dex.push({file,sourceSha256:r.sources[0].sourceSha256,classes:r.sources[0].classes,nativeDeclarations:r.counts.declarations,examples:r.items.slice(0,5).map(i=>i.className+'.'+i.method+i.descriptor)});}
const client=new Client({name:'carve-jni-integration',version:'1'});await client.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],stderr:'pipe'}));
let mcp;try{const reply=await client.callTool({name:'carve_jni',arguments:{workspace:'work',files:['classes/java/util/zip/Adler32.class'],libraries:['lib/libzip.dylib']}});assert.equal(reply.isError,undefined,reply.content[0].text);mcp=JSON.parse(reply.content[0].text);}finally{await client.close();}
assert.deepEqual(mcp.items.map(i=>i.status),['static-export-candidate','static-export-candidate','static-export-candidate']);
const report={schema:'carve/jni-e2e@1',status:'passed',checkedAt:new Date().toISOString(),node:process.version,jdk:{implementor:'Temurin-21.0.12.1+1',pinned},
 exportPages,zip:{classFiles:zipFiles.length,declarations:zip.counts.declarations,nmJavaExports:zipExports.size,staticExportCandidates:zip.counts.staticExportCandidates,declarationEvidence:zip.sources.filter(s=>s.natives).map(s=>({file:s.file,natives:s.natives,observationId:s.observationId}))},
 lang:{declarations:lang.counts.declarations,staticExportCandidates:lang.counts.staticExportCandidates,withoutStaticExport:lang.counts.withoutStaticExport,jniOnLoad:onLoad,items:lang.items.map(i=>({member:i.className+'.'+i.method+i.descriptor,status:i.status}))},
 d8:{tool:'r8-9.5.26 D8 --min-api 26',dexSha256:d8zip.sources[0].sourceSha256,classes:d8zip.sources[0].classes,declarations:d8zip.counts.declarations,equalToClassFiles:true},
 runtime:{log:jvmLog,registered:[...registered].sort(),linkedBySymbol:[...linked].sort(),scope:'One java -version start; it shows registration/linking that occurred in that run, not every possible later link.'},
 dex,mcpAdler32:mcp.items.map(i=>({method:i.method,descriptor:i.descriptor,candidate:i.candidates[0]?.name})),
 scope:'Static declaration-to-export candidates in shipped JDK bytes, checked against Apple nm. Apart from one java -version start whose jni+resolve log is compared with the java.lang results, it does not observe System.loadLibrary, trace RegisterNatives call sites, prove signatures/ABI or verify behavior. The D8 DEX check compares DEX parsing with class-file parsing of the same shipped declarations. The shipped scrcpy/ZXing DEX inputs only demonstrate parsing; they declare no native methods according to this parser, which was not checked against another DEX tool.'};
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({status:report.status,report:path.join(out,'report.json'),zip:report.zip.declarations,d8:report.d8.declarations,lang:{candidates:report.lang.staticExportCandidates,without:report.lang.withoutStaticExport},dex:dex.map(d=>[d.file,d.classes,d.nativeDeclarations])},null,2));
