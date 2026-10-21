// Independent REA producer, real shipped PE bytes, explicit JNI harness and Carve reconstruction.
import assert from 'node:assert/strict';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {mkdtemp,mkdir,readFile,writeFile,copyFile,rename,readdir} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify,parseArgs} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
import {readPeLoader} from '../dist/pe-loader.js';
import {hashFile} from '../dist/survey.js';
import {runReference} from '../dist/reference.js';
import {parseProjectPlan,analyzeProjectPlan} from '../dist/project-plan.js';
import {createWorkPackage} from '../dist/work-package.js';
import {collectPeBehaviorEvidence} from './pe-behavior-rea.mjs';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
const {values:options}=parseArgs({options:{engines:{type:'string',default:path.join(root,'artifacts/engines/config.json')},'rea-install':{type:'string',default:path.join(root,'artifacts/rea-local')},python:{type:'string',default:path.join(root,'artifacts/pe-behavior-venv/bin/python')}}});
const engines=await readEngineConfiguration(path.resolve(options.engines)),python=path.resolve(options.python);
assert.equal((await exec(python,['-c','import unicorn;print(unicorn.__version__)'])).stdout.trim(),'2.1.4');
const relative='Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll',source=path.join(engines.ghidra,relative);
const expectedSha='c769642c8a489e8fc078b8387fb9865ac5c5482ce22301a40d00145fa1304b27';
assert.equal((await hashFile(source)).sha256,expectedSha,'This reviewed reconstruction requires the exact shipped DLL');
await mkdir(path.join(root,'artifacts'),{recursive:true});
const out=await mkdtemp(path.join(root,'artifacts/pe-version-e2e-')),save=(name,data)=>writeFile(path.join(out,name),JSON.stringify(data,null,2)+'\n');
await mkdir(path.join(out,'input'));await copyFile(source,path.join(out,'input/lib7-Zip-JBinding.dll'));
const metadata=await readPeLoader(source);assert.equal(metadata.machine,0x8664);
const fields=['major','minor','build','version','date','copyright'],targets=fields.map(field=>{
 const found=metadata.exports.entries.filter(e=>e.names.includes('Java_net_sf_sevenzipjbinding_SevenZip_nativeGetVersion'+field[0].toUpperCase()+field.slice(1)));
 assert.equal(found.length,1);assert.ok(!found[0].forwarder);return [field,'0x'+(BigInt(metadata.imageBase)+BigInt(found[0].rva)).toString(16)];
});
// Compile the installed JDK declaration to verify the reviewed 64-bit JNI slot.
await writeFile(path.join(out,'jni-offset.c'),'#include <stddef.h>\n#include <jni.h>\n_Static_assert(sizeof(void*) == 8, "64-bit pointers required");\n_Static_assert(offsetof(struct JNINativeInterface_, NewStringUTF) == 0x538, "Unexpected JNI slot");\n');
await exec('clang',['-fsyntax-only','-I'+path.join(engines.javaHome,'include'),'-I'+path.join(engines.javaHome,'include/darwin'),path.join(out,'jni-offset.c')]);
await save('images.json',{schema:'carve/third-party-pe-version@1',sha256:expectedSha,metadata,entries:Object.fromEntries(targets),newStringUtfOffset:0x538});
await save('source.json',{path:source,distributionRelativePath:relative,sha256:expectedSha,jniHeader:await hashFile(path.join(engines.javaHome,'include/jni.h')),windowsExecuted:false,jvmExecuted:false});
await copyFile(path.join(root,'examples/pe-version/original.py'),path.join(out,'original.py'));
await copyFile(path.join(root,'examples/pe-version/implementation.mjs'),path.join(out,'implementation.mjs'));
const producer=await collectPeBehaviorEvidence(out,{},engines,path.resolve(options['rea-install']),[['lib7-Zip-JBinding.dll',targets]]);
assert.equal(producer.closed,true);
const client=new Client({name:'third-party-pe-version',version:'1'}),transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out],cwd:out,stderr:'pipe'});
let diagnostics='';transport.stderr?.on('data',b=>{diagnostics=(diagnostics+b.toString()).slice(-16000);});
const call=async(name,args)=>{const r=await client.callTool({name,arguments:args},undefined,{timeout:600000});if(r.isError)throw Error(r.content.filter(c=>c.type==='text').map(c=>c.text).join('\n'));return JSON.parse(r.content.find(c=>c.type==='text').text);};
const limitations='Six exact third-party version exports only. Original AMD64 machine code runs at its preferred base under Unicorn with one ASCII-only JNI NewStringUTF stub. No DLL initialization, JVM, Windows loader/OS/UI, archive operations, allocation failures or complete dependency closure are verified.';
try{
 await client.connect(transport);assert.notEqual(transport.pid,producer.pid);
 await call('carve_reverse',{target:'input',goal:'Reuse six third-party DLL version metadata exports without Windows or JNI',out:'work'});
 const ids=[];for(const record of producer.records){
  const imported=await call('carve_import_rea_native',{workspace:'work',file:record.file,...Object.fromEntries(['code','info','callees','references'].map(role=>[role,path.relative(out,record[role])]))});ids.push(imported.observationId);
 }
 const expected={major:16,minor:2,build:0,version:'16.02',date:'2016-05-21',copyright:'Igor Pavlov : Public domain'};
 const dependencies=await call('carve_pe_ui',{workspace:'work',file:'lib7-Zip-JBinding.dll',view:'dependencies',entryMode:'selected-functions',functionIds:ids,limit:100,budgetBytes:65536});await save('dependency-boundary.json',dependencies);assert.equal(dependencies.visited,6);assert.equal(dependencies.counts.byKind['function-entry'],6);assert.ok(dependencies.counts.byKind['data-reference']>=3);
 const dependencyReport=JSON.parse(await readFile(dependencies.dependencyEvidence,'utf8')),dataBindings=dependencyReport.rows.filter(r=>r.kind==='data-reference').map(row=>{const field=targets.find(([,address])=>address===row.sourceAddress)?.[0];assert.ok(['version','date','copyright'].includes(field));const bytes=Buffer.from(expected[field]+'\0','ascii');assert.equal(row.bytes.hex.slice(0,bytes.length*2),bytes.toString('hex'));return {observationId:row.from,sourceAddress:row.sourceAddress,targetAddress:row.targetAddress,handling:'embedded-readonly',description:'Reviewed terminated ASCII '+field+' string returned through the declared JNI slot',bytes:{length:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')}};});assert.equal(dataBindings.length,3);
 await save('contract.json',{schema:'carve/reconstruction@2',goal:'Reuse the pinned DLL version metadata as an independent module',primary:'library',artifacts:[{key:'library',file:'lib7-Zip-JBinding.dll',evidenceIds:ids,dataBindings}],relationships:[],behavior:{description:'Reviewed reconstruction of six version metadata exports',inputDomain:'One field: major, minor, build, version, date or copyright',outputDomain:'Integer metadata or printable ASCII string; unknown fields throw'},dependencies:[{name:'JNI NewStringUTF',status:'reimplemented',detail:'Standalone module returns strings directly; original comparison models only the selected ASCII JNI callback.'}],unknowns:[limitations,'JNI indirect jumps remain unresolved in the static dependency report. The declared harness supplies one reviewed slot; it does not resolve the graph.']});
 await save('reconstruction.json',await call('carve_reconstruct',{workspace:'work',contract:'contract.json',implementation:'implementation.mjs',export:'versionInfo',out:'function'}));

 const traces=[];for(const field of fields){const result=await runReference([python,path.join(out,'original.py'),'--trace'],'json-stdin',[field],out,3000);assert.equal(result.kind,'return',JSON.stringify(result));assert.equal(result.value.value,expected[field]);assert.equal(result.value.trace.newStringUtfCalls,['copyright','date','version'].includes(field)?1:0);traces.push({field,...result.value});}await save('original-traces.json',traces);
 await save('toolchain.json',{python,unicorn:'2.1.4',pythonExecutable:await hashFile(python)});
 await writeFile(path.join(out,'original.mjs'),`import {spawnSync} from 'node:child_process';import {readFileSync} from 'node:fs';import {fileURLToPath} from 'node:url';const config=JSON.parse(readFileSync(new URL('./toolchain.json',import.meta.url)));const r=spawnSync(config.python,[fileURLToPath(new URL('./original.py',import.meta.url))],{input:readFileSync(0,'utf8'),encoding:'utf8',timeout:3000});if(r.error||r.status!==0)throw Error(r.stderr||String(r.error));process.stdout.write(r.stdout);\n`);
 await writeFile(path.join(out,'candidate.mjs'),`import {readFileSync} from 'node:fs';import {capability} from './function/index.mjs';console.log(JSON.stringify(capability(...JSON.parse(readFileSync(0,'utf8')))));\n`);
 await writeFile(path.join(out,'mutant.mjs'),`import {readFileSync} from 'node:fs';readFileSync(0);console.log(0);\n`);
 await save('cases.json',{schema:'carve/acceptance-cases@1',cases:fields.map(field=>({name:field,args:[field],expected:expected[field]}))});
 const plan={schema:'carve/project-plan@1',goal:'Reuse third-party PE version metadata',target:{schema:'carve/target@1',platform:'macos',delivery:'module'},features:[{id:'version',title:'Version metadata',contract:{input:'Declared metadata field',output:'Integer or ASCII string',state:'Stateless',errors:'Unknown field rejected'}}]},analysis=analyzeProjectPlan(parseProjectPlan(plan)),spec={schema:'carve/work-spec@1',planId:analysis.planId,assignments:[{feature:'version',taskId:analysis.tasks[0].taskId,files:['candidate.mjs'],acceptance:[{name:'compare',criterion:'All six declared original export results match the independent module'}]}]};
 await save('plan.json',plan);await save('work-spec.json',spec);const task=await createWorkPackage(plan,spec,'version',path.join(out,'task'));
 const names=['images.json','source.json','jni-offset.c','original.py','original.mjs','candidate.mjs','mutant.mjs','toolchain.json','cases.json','contract.json','reconstruction.json','dependency-boundary.json','original-traces.json','input/lib7-Zip-JBinding.dll'];
 async function tree(directory){for(const e of await readdir(path.join(out,directory),{withFileTypes:true})){const p=directory+'/'+e.name;if(e.isDirectory())await tree(p);else if(e.isFile())names.push(p);else throw Error('Nonregular acceptance input');}}
 for(const directory of ['function','producer','work/rea-native-evidence','work/ui-evidence'])await tree(directory);
 const files=await Promise.all(names.map(async p=>({path:p,sha256:(await hashFile(path.join(out,p))).sha256})));
 const command=file=>({runtime:'node',file,args:[]}),check={id:'compare',kind:'original-comparison',acceptance:['compare'],command:command('candidate.mjs'),comparison:{original:command('original.mjs'),cases:'cases.json',mode:'cases',scope:'declared-harness',limitations}},checks={schema:'carve/acceptance-spec@1',packageId:task.id,files,checks:[check]};
 await save('checks.json',checks);const request={package:'task',root:out,plan:'plan.json',spec:'work-spec.json'};
 const accepted=await call('carve_work_acceptance',{...request,action:'run',checks:'checks.json',out:'accepted',execute:true,timeoutMs:5000});await save('acceptance.json',accepted);assert.equal(accepted.status,'passed-declared-acceptance');
 await save('negative-checks.json',{...checks,checks:[{...check,command:command('mutant.mjs')}]});const rejected=await call('carve_work_acceptance',{...request,action:'run',checks:'negative-checks.json',out:'rejected',execute:true,timeoutMs:5000});assert.equal(rejected.categories['original-comparison'],'failed');
 const original=await readFile(path.join(out,'input/lib7-Zip-JBinding.dll'));try{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),Buffer.concat([original,Buffer.from([0])]));const stale=await client.callTool({name:'carve_work_acceptance',arguments:{...request,action:'read',directory:'accepted'}});assert.equal(stale.isError,true);await save('stale-rejection.json',stale);}finally{await writeFile(path.join(out,'input/lib7-Zip-JBinding.dll'),original);}
 const stored=await call('carve_library_add',{package:'function',library:'functions',name:'sevenzip-version',title:'Reviewed third-party version metadata',description:limitations,tags:['pe','jni','version']});
 const fresh=new Client({name:'version-library-only',version:'1'});await rename(path.join(out,'input'),path.join(out,'input-offline'));
 try{assert.equal((await runReference([python,path.join(out,'original.py')],'json-stdin',['version'],out,3000)).kind,'harness-error');
  await fresh.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',path.join(out,'functions')],stderr:'pipe'}));
  const module=await import(pathToFileURL(path.join(stored.package,'index.mjs')));for(const field of fields){assert.equal(module.capability(field),expected[field]);const response=await fresh.callTool({name:'carve_invoke',arguments:{package:'sevenzip-version',args:[field],execute:true}});assert.ok(!response.isError);assert.equal(JSON.parse(response.content[0].text).value,expected[field]);}assert.throws(()=>module.capability('__proto__'),/Unknown version field/);
 }finally{await fresh.close();await rename(path.join(out,'input-offline'),path.join(out,'input'));}
 assert.equal((await hashFile(source)).sha256,expectedSha);assert.equal((await hashFile(path.join(out,'input/lib7-Zip-JBinding.dll'))).sha256,expectedSha);
 assert.equal((await call('carve_work_acceptance',{...request,action:'read',directory:'accepted'})).reportSha256,accepted.reportSha256);
 const report={schema:'carve/third-party-pe-version-e2e@1',status:'passed',out,sourceSha256:expectedSha,cases:fields.length,dataBindings:dataBindings.length,visitedFunctions:dependencies.visited,scope:'declared-harness',windowsExecuted:false,jvmExecuted:false,archiveOperationsVerified:false,producerClosedBeforeImport:producer.closed,acceptanceReportSha256:accepted.reportSha256,negative:{mutantRejected:true,staleOriginalRejected:true},independence:{originalCopyOffline:true,libraryOnlyMcp:true,directImport:true,originalsRestoredUnchanged:true},function:stored.package,limitations};await save('report.json',report);await writeFile(path.join(root,'artifacts/pe-version-verification-summary.json'),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
}catch(error){await save('failure.json',{message:error.stack});throw error;}finally{await client.close();await writeFile(path.join(out,'carve-diagnostics.log'),diagnostics);}
