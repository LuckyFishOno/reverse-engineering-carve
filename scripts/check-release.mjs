import {spawn} from 'node:child_process';
import {mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {parseArgs} from 'node:util';
const options=parseArgs({options:{'native-engines':{type:'string'},'android-runtime':{type:'string'},r8:{type:'string'},scale:{type:'boolean'},jq:{type:'boolean'},'analysis-queue':{type:'boolean'},'analysis-background':{type:'boolean'},'multi-artifact':{type:'boolean'},'native-links':{type:'boolean'},'native-loader':{type:'boolean'},openssl:{type:'boolean'},'openssl-prefix':{type:'string'},'apk-manifest':{type:'boolean'},aapt2:{type:'string'},'zxing-vcard':{type:'boolean'},'termux-bootstrap':{type:'boolean'},'engine-resources':{type:'boolean'},'pe-behavior':{type:'boolean'},'pe-state':{type:'boolean'},'pe-sequence':{type:'boolean'},'pe-version':{type:'boolean'},'pe-crc':{type:'boolean'},'pe-crc-dispatch':{type:'boolean'},'pe-python':{type:'string'},'rea-install':{type:'string'},jni:{type:'boolean'},'jni-adler32':{type:'boolean'}},allowPositionals:true});
const rea=options.positionals[0];
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const logRoot=path.join(root,'artifacts','checks');await mkdir(logRoot,{recursive:true});
const checks=[];
async function check(name,command,args){
 const start=performance.now();let output='';
 const result=await new Promise(resolve=>{
  const child=spawn(command,args,{cwd:root,env:process.env,stdio:['ignore','pipe','pipe']});
  const collect=data=>{output+=data.toString();if(output.length>4*1024*1024){output=output.slice(-2*1024*1024);}};
  child.stdout.on('data',collect);child.stderr.on('data',collect);
  child.on('error',error=>resolve({code:null,error:error.message}));child.on('close',code=>resolve({code}));
 });
 const log=path.join(logRoot,name+'.log');await writeFile(log,output);
 const item={name,status:result.code===0?'passed':'failed',exitCode:result.code,elapsedMs:Math.round(performance.now()-start),log,...(result.error?{error:result.error}:{})};
 checks.push(item);console.log(`${name}: ${item.status} (${item.elapsedMs} ms)`);
 if(item.status==='failed') process.stderr.write(output.slice(-5000));
 return item;
}
const built=await check('build',process.execPath,['node_modules/typescript/bin/tsc']);
if(built.status==='passed'){
 await check('content-hygiene',process.execPath,['scripts/check-content.mjs']);
 const tests=(await readdir(path.join(root,'test'))).filter(f=>f.endsWith('.test.mjs')).sort().map(f=>'test/'+f);
 await check('tests',process.execPath,['--test','--test-concurrency=2','--test-reporter=spec',...tests]);
 await Promise.all([
  check('asar-demo',process.execPath,['scripts/demo.mjs']),
  check('public-packages',process.execPath,['scripts/verify-public.mjs']),
  check('clean-install',process.execPath,['scripts/verify-install.mjs'])
 ]);
 if(rea) await check('rea-integration',process.execPath,['scripts/verify-rea.mjs',rea]);
 if(options.values['pe-behavior'])await check('pe-behavior-integration',process.execPath,['scripts/verify-pe-behavior.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['pe-sequence'])await check('pe-sequence-integration',process.execPath,['scripts/verify-pe-sequence.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['pe-state'])await check('pe-state-integration',process.execPath,['scripts/verify-pe-state.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['pe-version'])await check('pe-version-integration',process.execPath,['scripts/verify-pe-version.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['pe-crc'])await check('pe-crc-integration',process.execPath,['scripts/verify-pe-crc.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['pe-crc-dispatch'])await check('pe-crc-dispatch-integration',process.execPath,['scripts/verify-pe-crc-dispatch.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['rea-install']?['--rea-install',options.values['rea-install']]:[]),...(options.values['pe-python']?['--python',options.values['pe-python']]:[])]);
 if(options.values['native-engines'])await check('native-dex-integration',process.execPath,['scripts/verify-native.mjs',options.values['native-engines'],...(options.values.r8?[options.values.r8]:[])]);
 if(options.values.jq)await check('jq-native-third-party',process.execPath,['scripts/verify-jq.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['android-runtime']){
  const engines=options.values['native-engines']??path.join(root,'artifacts/engines/config.json');
  await check('android-protocol',process.execPath,['scripts/verify-android-protocol.mjs',engines,options.values['android-runtime']]);
  await check('android-third-party',process.execPath,['scripts/verify-android.mjs','--engines',engines,'--runtime',options.values['android-runtime']]);
 }
 if(options.values['analysis-queue'])await check('component-queue',process.execPath,['scripts/verify-analysis-queue.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['analysis-background'])await check('background-analysis',process.execPath,['scripts/verify-analysis-background.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['multi-artifact'])await check('multi-artifact',process.execPath,['scripts/verify-multi-artifact.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['native-links'])await check('native-links',process.execPath,['scripts/verify-links.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['native-loader'])await check('native-loader',process.execPath,['scripts/verify-loader.mjs']);
 if(options.values.openssl)await check('openssl-native-third-party',process.execPath,['scripts/verify-openssl.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values['openssl-prefix']?['--prefix',options.values['openssl-prefix']]:[])]);
 if(options.values['apk-manifest'])await check('apk-manifest-third-party',process.execPath,['scripts/verify-apk-manifest.mjs','--aapt2',options.values.aapt2??path.join(root,'artifacts/engines/aapt2/aapt2'),'--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['zxing-vcard'])await check('zxing-vcard-android-third-party',process.execPath,['scripts/verify-zxing-vcard.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),'--runtime',options.values['android-runtime']??path.join(root,'artifacts/android/config.json')]);
 if(options.values['termux-bootstrap'])await check('termux-bootstrap-jni-android',process.execPath,['scripts/verify-termux-bootstrap.mjs','--engines',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),'--runtime',options.values['android-runtime']??path.join(root,'artifacts/android/config.json')]);
 if(options.values.scale)await check('scale-inventory',process.execPath,['scripts/verify-scale.mjs']);
 if(options.values.jni)await check('jni-jdk-third-party',process.execPath,['scripts/verify-jni.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json'),...(options.values.r8?[options.values.r8]:[])]);
 if(options.values['jni-adler32'])await check('jni-adler32-jdk-third-party',process.execPath,['scripts/verify-jni-adler32.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
 if(options.values['engine-resources'])await check('engine-resources-third-party',process.execPath,['scripts/verify-engine-resources.mjs',options.values['native-engines']??path.join(root,'artifacts/engines/config.json')]);
}
const files=['package.json','package-lock.json','tsconfig.json','README.md','README.zh-TW.md','CHANGELOG.md','LICENSE','DEVELOPMENT.md','MILESTONE.md','CONTRIBUTING.md'];
async function walk(directory){for(const item of await readdir(path.join(root,directory),{withFileTypes:true})){
 const name=path.posix.join(directory,item.name);if(item.isDirectory()) await walk(name);else if(item.isFile()) files.push(name);
}}
for(const directory of ['src','test','scripts','examples','skills','engines','docs']) await walk(directory);
const sourceHash=createHash('sha256');for(const file of files.sort()) sourceHash.update(file+'\0').update(await readFile(path.join(root,file))).update('\0');
const summary={schema:'carve/release-check@1',version:JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,
 checkedAt:new Date().toISOString(),node:process.version,platform:process.platform,status:checks.every(c=>c.status==='passed')?'passed':'failed',
 sourceSetSha256:sourceHash.digest('hex'),checks,reaIntegration:rea?'executed':'not-requested',nativeIntegration:options.values['native-engines']?'executed':'not-requested',peBehaviorIntegration:options.values['pe-behavior']?'executed':'not-requested',peStateIntegration:options.values['pe-state']?'executed':'not-requested',peSequenceIntegration:options.values['pe-sequence']?'executed':'not-requested',peVersionIntegration:options.values['pe-version']?'executed':'not-requested',peCrcIntegration:options.values['pe-crc']?'executed':'not-requested',peCrcDispatchIntegration:options.values['pe-crc-dispatch']?'executed':'not-requested',jqIntegration:options.values.jq?'executed':'not-requested',androidIntegration:options.values['android-runtime']?'executed':'not-requested',scaleInventory:options.values.scale?'executed':'not-requested',
 analysisQueue:options.values['analysis-queue']?'executed':'not-requested',engineResources:options.values['engine-resources']?'executed':'not-requested',jni:options.values.jni?'executed':'not-requested',jniAdler32:options.values['jni-adler32']?'executed':'not-requested',analysisBackground:options.values['analysis-background']?'executed':'not-requested',multiArtifact:options.values['multi-artifact']?'executed':'not-requested',nativeLinks:options.values['native-links']?'executed':'not-requested',nativeLoader:options.values['native-loader']?'executed':'not-requested',opensslIntegration:options.values.openssl?'executed':'not-requested',apkManifestIntegration:options.values['apk-manifest']?'executed':'not-requested',zxingVCardIntegration:options.values['zxing-vcard']?'executed':'not-requested',termuxBootstrapIntegration:options.values['termux-bootstrap']?'executed':'not-requested',scope:'Local checks on this host. Does not claim remote CI, arbitrary application cloning or equivalence beyond tested cases.'};
const destination=path.join(root,'artifacts','verification-summary.json');await writeFile(destination,JSON.stringify(summary,null,2)+'\n');
console.log(JSON.stringify({status:summary.status,version:summary.version,summary:destination},null,2));
if(summary.status!=='passed') process.exitCode=1;
