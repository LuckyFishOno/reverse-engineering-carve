import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readFile,writeFile,mkdir,mkdtemp} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {prepareAndroidReference} from '../dist/android.js';
import {hashFile} from '../dist/survey.js';
import {shellCommand} from '../dist/runtime.js';
import {readEngineConfiguration,readAndroidConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const engines=await readEngineConfiguration(process.argv[2]??path.join(root,'artifacts/engines/config.json'));
const config=await readAndroidConfiguration(process.argv[3]??path.join(root,'artifacts/android/config.json'));
if(!config.serial)throw new Error('Runtime config must select an explicit serial.');
const out=await mkdtemp(path.join(root,'artifacts/android-protocol-'));const classes=path.join(out,'classes'),dex=path.join(out,'dex');await mkdir(classes);await mkdir(dex);
const exec=promisify(execFile);await exec(path.join(engines.javaHome,'bin/javac'),['--release','8','-Xlint:-options','-d',classes,path.join(root,'examples/android/RuntimeProbeHarness.java')]);
await exec(path.join(engines.javaHome,'bin/java'),['-cp',engines.r8??path.join(root,'artifacts/engines/r8-9.5.26.jar'),'com.android.tools.r8.D8','--min-api','21','--output',dex,path.join(classes,'carve/reference/RuntimeProbeHarness.class')]);
const file=path.join(dex,'classes.dex');const hashed=await hashFile(file);
const session=await prepareAndroidReference(out,{path:file,sha256:hashed.sha256,facts:hashed.facts},{schema:'carve/android-reference@1',adb:config.adb,serverPort:config.serverPort??5037,serial:config.serial,harness:file,entryClass:'carve.reference.RuntimeProbeHarness',dependencies:[],description:'Owned protocol-only test; not a third-party feature equivalence comparison.'});
let cleanup;try{
 const marker=session.identity.remote+'/injection-marker';const input=`apostrophe ' ; $(touch ${marker}) ; "\u4f60\u597d\n`;
 assert.deepEqual(await session.run(['echo',input],2000),{kind:'return',value:input});
 await exec(config.adb,['-P',String(config.serverPort??5037),'-s',config.serial,'shell','-T',shellCommand(['test','!','-e',marker])]);
 assert.deepEqual(await session.run(['stderr'],2000),{kind:'return',value:true});
 assert.equal((await session.run(['throw'],2000)).kind,'harness-error');
 assert.equal((await session.run(['sleep'],100)).kind,'harness-error');
 const excessive=await session.run(['huge'],3000);assert.equal(excessive.kind,'harness-error');assert.match(excessive.detail,/output exceeded 1 MiB/);
 await session.verifyRemote();
}finally{cleanup=await session.cleanup();}
assert.equal(cleanup,'removed');const report={schema:'carve/android-protocol-check@1',status:'passed',out,runtime:session.identity,checks:['remote-argv-quoting','stderr-separation','nonzero-exit','remote-timeout','output-budget','remote-hashes','private-directory-cleanup'],scope:'Owned protocol harness only, separate from third-party capability comparisons.'};
// Separate DEX tests the structured transport with no target algorithm.
const jsonClasses=path.join(out,'json-classes'),jsonDex=path.join(out,'json-dex');await mkdir(jsonClasses);await mkdir(jsonDex);
await exec(path.join(engines.javaHome,'bin/javac'),['--release','8','-d',jsonClasses,path.join(root,'examples/android/JsonStdinHarness.java')]);
await exec(path.join(engines.javaHome,'bin/java'),['-cp',engines.r8??path.join(root,'artifacts/engines/r8-9.5.26.jar'),'com.android.tools.r8.D8','--min-api','21','--output',jsonDex,path.join(jsonClasses,'carve/reference/JsonStdinHarness.class')]);
const jsonFile=path.join(jsonDex,'classes.dex'),jsonHash=await hashFile(jsonFile),jsonSession=await prepareAndroidReference(out,{path:jsonFile,sha256:jsonHash.sha256,facts:jsonHash.facts},{schema:'carve/android-reference@2',mode:'json-stdin',adb:config.adb,serverPort:config.serverPort??5037,serial:config.serial,harness:jsonFile,entryClass:'carve.reference.JsonStdinHarness',dependencies:[],description:'Owned structured-stdin transport echo; no third-party algorithm.'});
try{
 const marker=jsonSession.identity.remote+'/injection-marker',value=[{nested:[null,true,false,17,'\0\ufeff\u4e2d\u6587😀'],literal:`$(touch ${marker}); '"\n`,large:'x'.repeat(300000)}];
 assert.deepEqual(await jsonSession.run(value,5000),{kind:'return',value});
 await exec(config.adb,['-P',String(config.serverPort??5037),'-s',config.serial,'shell','-T',shellCommand(['test','!','-e',marker])]);
 for(const bad of [[NaN],[undefined],['x'.repeat(1048576)]])assert.equal((await jsonSession.run(bad,5000)).kind,'harness-error');
 await jsonSession.verifyRemote();
}finally{assert.equal(await jsonSession.cleanup(),'removed');}
report.structuredRuntime=jsonSession.identity;report.checks.push('json-stdin-nested-nul-unicode','json-stdin-large-off-argv','json-stdin-injection-is-data','json-stdin-invalid-preflight','json-stdin-remote-hashes-cleanup');
// This echo is deliberately not a sequence-outcome producer. Finite JSON alone
// must not count as a successful ordered reference protocol.
const invalidSequenceSession=await prepareAndroidReference(out,{path:jsonFile,sha256:jsonHash.sha256,facts:jsonHash.facts},{schema:'carve/android-reference@4',mode:'json-sequence-stdin',adb:config.adb,serverPort:config.serverPort??5037,serial:config.serial,harness:jsonFile,entryClass:'carve.reference.JsonStdinHarness',dependencies:[],description:'Owned echo as a deliberately invalid sequence producer; no third-party behavior.'});
try{
 const result=await invalidSequenceSession.run([['echo'],['again']],5000);assert.equal(result.kind,'harness-error');assert.match(result.detail,/exactly one finite return\/throw outcome/);
 for(const bad of [[],[1],Array.from({length:65},()=>[])])assert.equal((await invalidSequenceSession.run(bad,5000)).kind,'harness-error');
 await invalidSequenceSession.verifyRemote();
}finally{assert.equal(await invalidSequenceSession.cleanup(),'removed');}
report.sequenceProtocolRuntime=invalidSequenceSession.identity;report.checks.push('sequence-json-is-not-outcomes','sequence-step-bounds','sequence-remote-hashes-cleanup');
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/android-protocol-summary.json'),JSON.stringify({status:'passed',report:path.join(out,'report.json')},null,2));console.log(JSON.stringify({status:'passed',checks:report.checks,report:path.join(out,'report.json')},null,2));
