import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {readFile, realpath, stat} from 'node:fs/promises';
import {createConnection} from 'node:net';
import {spawn} from 'node:child_process';
import {parseArgs} from 'node:util';
import {readAndroidConfiguration} from '../dist/engine-config.js';

const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// Development launcher only. It never creates/wipes an AVD or starts/stops an ADB server.
export async function emulatorLaunchPlan(file=path.join(root,'artifacts/android/config.json')) {
  const config=await readAndroidConfiguration(file);
  for(const key of ['sdkRoot','adb','emulator','image','avdHome','userHome']) {
    if(typeof config[key]!=='string')throw new Error('Runtime configuration requires '+key+'.');
    const actual=await realpath(config[key]);
    if((await stat(actual)).isDirectory()!==!['adb','emulator'].includes(key))throw new Error('Unexpected file type: '+key);
    config[key]=actual;
  }
  if(typeof config.avd!=='string'||!/^\w[\w.-]{0,99}$/.test(config.avd))throw new Error('Select an explicit AVD name.');
  if(!Number.isInteger(config.consolePort)||config.consolePort<1024||config.consolePort>65534||config.consolePort%2!==0)throw new Error('consolePort must be an even unprivileged port.');
  if(config.serial!==`emulator-${config.consolePort}`)throw new Error('serial must match consolePort.');
  if(!Number.isInteger(config.serverPort)||config.serverPort<1024||config.serverPort>65535||[config.consolePort,config.consolePort+1].includes(config.serverPort))throw new Error('Select a separate unprivileged ADB serverPort.');
  const ini=await readFile(path.join(config.avdHome,config.avd+'.ini'),'utf8');
  const paths=ini.split(/\r?\n/).map(s=>/^path\s*=\s*(.+?)\s*$/.exec(s)).filter(Boolean);
  if(paths.length!==1||!path.isAbsolute(paths[0][1]))throw new Error('AVD .ini must contain one absolute path= entry.');
  const expected=await realpath(path.join(config.avdHome,config.avd+'.avd'));
  if(await realpath(paths[0][1]).catch(()=>null)!==expected)throw new Error('AVD .ini points to another location. Review its path= after moving the SDK; no AVD files were changed.');
  const env={...process.env,ANDROID_AVD_HOME:config.avdHome,ANDROID_EMULATOR_HOME:config.userHome,ANDROID_USER_HOME:config.userHome,ANDROID_SDK_ROOT:config.sdkRoot,ANDROID_HOME:config.sdkRoot,
    ANDROID_ADB_SERVER_PORT:String(config.serverPort),ADB_SERVER_PORT:String(config.serverPort),ADB_SERVER_SOCKET:`tcp:localhost:${config.serverPort}`,ADB_LOCAL_TRANSPORT_MAX_PORT:String(config.consolePort+1),ADB_MDNS_AUTO_CONNECT:'0'};
  return {config,command:config.emulator,args:['-avd',config.avd,'-port',String(config.consolePort),'-no-window','-no-audio','-no-boot-anim','-no-snapshot','-no-metrics','-accel','on','-gpu','swiftshader_indirect','-camera-back','none','-camera-front','none'],env,cwd:config.sdkRoot};
}

export async function portListening(port) {
  return new Promise((resolve,reject)=>{
    const socket=createConnection({host:'127.0.0.1',port});
    socket.once('connect',()=>{socket.destroy();resolve(true);});
    socket.setTimeout(1500,()=>{socket.destroy();reject(new Error('Port probe timed out: '+port));});
    socket.once('error',error=>{socket.destroy();if(error.code==='ECONNREFUSED')resolve(false);else reject(error);});
  });
}
export async function inspectEmulatorPlan(plan) {
  const {serverPort,consolePort}=plan.config;
  return {adbServerListening:await portListening(serverPort),consoleListening:await portListening(consolePort),transportListening:await portListening(consolePort+1)};
}
export async function launchEmulator(plan,checks) {
  checks??=await inspectEmulatorPlan(plan);
  if(!checks.adbServerListening)throw new Error('Selected ADB server is absent. Start the private server explicitly before launching the emulator.');
  if(checks.consoleListening||checks.transportListening)throw new Error('Selected emulator ports are occupied; refusing to launch or stop another process.');
  // A foreground owned child: signals never use historical PID records or device serials.
  const child=spawn(plan.command,plan.args,{cwd:plan.cwd,env:plan.env,stdio:'inherit'});
  const forward=signal=>{if(child.exitCode===null&&child.signalCode===null)child.kill(signal);};
  const interrupt=()=>forward('SIGINT'),terminate=()=>forward('SIGTERM');
  process.on('SIGINT',interrupt);process.on('SIGTERM',terminate);
  try{return await new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({exitCode:code,signal}));});}
  finally{process.off('SIGINT',interrupt);process.off('SIGTERM',terminate);}
}

async function main(){
  const {values}=parseArgs({options:{config:{type:'string',default:path.join(root,'artifacts/android/config.json')},check:{type:'boolean',default:false}}});
  const plan=await emulatorLaunchPlan(values.config),checks=await inspectEmulatorPlan(plan);
  if(values.check){console.log(JSON.stringify({schema:'carve/android-emulator-preflight@1',config:path.resolve(values.config),command:plan.command,args:plan.args,selection:{avd:plan.config.avd,serial:plan.config.serial,serverPort:plan.config.serverPort},...checks,scope:'Path/port inspection only. A listening socket does not prove ADB or Android boot identity; no process was started or stopped.'},null,2));return;}
  const result=await launchEmulator(plan,checks);process.exitCode=result.exitCode??1;
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)main().catch(error=>{process.stderr.write(error.message+'\n');process.exitCode=1;});
