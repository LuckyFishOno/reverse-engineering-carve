import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,readFile,cp,symlink,realpath} from 'node:fs/promises';
import {createServer} from 'node:net';
import {execFile,spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {promisify} from 'node:util';
import {emulatorLaunchPlan,inspectEmulatorPlan,launchEmulator} from '../scripts/android-emulator.mjs';
const execute=promisify(execFile);
const script=path.resolve('scripts/android-emulator.mjs');
async function fixture(){
 const directory=await realpath(await mkdtemp(path.join(tmpdir(),'carve-emulator-paths-')));
 const sdk=path.join(directory,'SDK with spaces');
 for(const p of ['platform-tools','emulator','image','avd/Test.avd','user'])await mkdir(path.join(sdk,p),{recursive:true});
 for(const p of ['platform-tools/adb','emulator/emulator'])await writeFile(path.join(sdk,p),'not executable: tests must not launch SDK commands');
 await writeFile(path.join(sdk,'avd/Test.ini'),'path='+path.join(sdk,'avd/Test.avd')+'\n');
 const config={sdkRoot:'SDK with spaces',adb:'SDK with spaces/platform-tools/adb',emulator:'SDK with spaces/emulator/emulator',image:'SDK with spaces/image',avdHome:'SDK with spaces/avd',userHome:'SDK with spaces/user',avd:'Test',serial:'emulator-5580',consolePort:5580,serverPort:5039};
 const file=path.join(directory,'config.json');await writeFile(file,JSON.stringify(config));return {directory,sdk,config,file};
}

test('Android launcher resolves config through symlink and another cwd without executing SDK',async()=>{
 const f=await fixture(),link=path.join(f.directory,'elsewhere');await mkdir(link);const file=path.join(link,'settings.json');await symlink(f.file,file);
 const p=await emulatorLaunchPlan(file);assert.equal(p.command,path.join(f.sdk,'emulator/emulator'));assert.equal(p.env.ANDROID_AVD_HOME,path.join(f.sdk,'avd'));assert.equal(p.env.ADB_SERVER_SOCKET,'tcp:localhost:5039');assert.deepEqual(p.args.slice(0,4),['-avd','Test','-port','5580']);
 // Use occupied/absent flags below, avoiding dependence on this host's development ports.
 await assert.rejects(()=>launchEmulator(p,{adbServerListening:false,consoleListening:false,transportListening:false}),/ADB server is absent/);
 await assert.rejects(()=>launchEmulator(p,{adbServerListening:true,consoleListening:true,transportListening:false}),/ports are occupied/);
 await assert.rejects(()=>launchEmulator(p,{adbServerListening:true,consoleListening:false,transportListening:true}),/ports are occupied/);
});

test('moved Android AVD with old absolute .ini is refused unchanged, then works with reviewed path',async()=>{
 const f=await fixture(),copy=await realpath(await mkdtemp(path.join(tmpdir(),'carve-moved-emulator-')));await cp(f.directory,copy,{recursive:true});
 const file=path.join(copy,'config.json'),ini=path.join(copy,'SDK with spaces/avd/Test.ini'),before=await readFile(ini,'utf8');
 await assert.rejects(()=>emulatorLaunchPlan(file),/another location/);assert.equal(await readFile(ini,'utf8'),before);
 await writeFile(ini,'path='+path.join(copy,'SDK with spaces/avd/Test.avd')+'\n');const plan=await emulatorLaunchPlan(file);assert.ok(plan.command.startsWith(copy+path.sep));
});

test('Android launcher rejects ambiguous AVD path, serial mismatch and conflicting ports',async()=>{
 const f=await fixture();
 for(const override of [{serial:'emulator-5554'},{consolePort:5581},{serverPort:5580},{avd:'../other'},{serverPort:5037.5}]){
  await writeFile(f.file,JSON.stringify({...f.config,...override}));await assert.rejects(()=>emulatorLaunchPlan(f.file));
 }
 await writeFile(f.file,JSON.stringify(f.config));await writeFile(path.join(f.sdk,'avd/Test.ini'),'path='+path.join(f.sdk,'avd/Test.avd')+'\npath=/other\n');await assert.rejects(()=>emulatorLaunchPlan(f.file),/one absolute/);
});

test('Android port inspection observes live selected sockets without ADB commands',async()=>{
 const servers=[];
 try{
  for(let i=0;i<3;i++){const server=createServer(socket=>socket.end());await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);}
  const [first,second,third]=servers.map(s=>s.address().port);
  // The inspector uses consolePort+1, so reuse the same live socket for that branch in a second call.
  const observed=await inspectEmulatorPlan({config:{serverPort:first,consolePort:second}});assert.equal(observed.adbServerListening,true);assert.equal(observed.consoleListening,true);
  const transport=await inspectEmulatorPlan({config:{serverPort:first,consolePort:third-1}});assert.equal(transport.transportListening,true);
 }finally{await Promise.all(servers.map(s=>new Promise(resolve=>s.close(resolve))));}
});

test('Android --check from unrelated cwd is read-only and foreground child preserves argv and exit',async()=>{
 const f=await fixture();
 const check=await execute(process.execPath,[script,'--config',f.file,'--check'],{cwd:tmpdir()});const result=JSON.parse(check.stdout);assert.equal(result.command,path.join(f.sdk,'emulator/emulator'));assert.equal(result.selection.avd,'Test');
 const output=path.join(f.directory,'child-result.json'),plan=await emulatorLaunchPlan(f.file);
 plan.command=process.execPath;plan.args=['-e','require("node:fs").writeFileSync(process.argv[1],JSON.stringify({argv:process.argv.slice(2),avd:process.env.ANDROID_AVD_HOME}));process.exitCode=7',output,'quoted ; $(not-a-command)'];
 assert.deepEqual(await launchEmulator(plan,{adbServerListening:true,consoleListening:false,transportListening:false}),{exitCode:7,signal:null});
 assert.deepEqual(JSON.parse(await readFile(output,'utf8')),{argv:['quoted ; $(not-a-command)'],avd:path.join(f.sdk,'avd')});
});


test('foreground launcher forwards termination to its owned child', {timeout:10000}, async()=>{
 const f=await fixture(),ready=path.join(f.directory,'ready'),ack=path.join(f.directory,'terminated');
 const childCode=`const fs=require('node:fs');process.on('SIGTERM',()=>{fs.writeFileSync(${JSON.stringify(ack)},'terminated');process.exit(0)});fs.writeFileSync(${JSON.stringify(ready)},'ready');setTimeout(()=>process.exit(9),5000)`;
 const wrapper=`import {launchEmulator} from ${JSON.stringify(pathToFileURL(script).href)};const result=await launchEmulator({command:process.execPath,args:['-e',${JSON.stringify(childCode)}],env:process.env,cwd:process.cwd()},{adbServerListening:true,consoleListening:false,transportListening:false});console.log(JSON.stringify(result));`;
 const child=spawn(process.execPath,['--input-type=module','-e',wrapper],{stdio:['ignore','pipe','pipe']});let stdout='',stderr='';child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);
 const closed=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});
 try{
  let seen=false;for(let i=0;i<100;i++){if(await readFile(ready,'utf8').catch(()=>null)==='ready'){seen=true;break;}await new Promise(r=>setTimeout(r,20));}
  assert.ok(seen,'owned child started: '+stderr);child.kill('SIGTERM');assert.deepEqual(await closed,{code:0,signal:null});assert.equal(await readFile(ack,'utf8'),'terminated');assert.deepEqual(JSON.parse(stdout),{exitCode:0,signal:null});
 }finally{if(child.exitCode===null&&child.signalCode===null)child.kill('SIGTERM');await closed;}
});
