import {realpath} from 'node:fs/promises';
import path from 'node:path';
import {boundedJson} from './reconstruction.js';

// Engine and Android runtime configuration files may record installation paths relative to the
// configuration file itself, so a project folder that holds both can move without rewriting them.
// Absolute paths are kept as written; every other field is passed through unchanged.
export const enginePathKeys=['ghidra','javaHome','jadx','r8'] as const;
export const androidPathKeys=['sdkRoot','adb','emulator','image','avdHome','userHome'] as const;
export async function readConfiguration(file:string,keys:readonly string[]):Promise<Record<string,unknown>>{
  const actual=await realpath(file);const value=(await boundedJson(actual)).value as unknown;
  if(!value||typeof value!=='object'||Array.isArray(value))throw new Error('Configuration must be a JSON object: '+file);
  const base=path.dirname(actual),result:Record<string,unknown>={...value as Record<string,unknown>};
  for(const key of keys){
    const entry=result[key];if(entry===undefined)continue;
    if(typeof entry!=='string'||!entry||entry.includes('\0'))throw new Error(`Configuration ${key} must be a non-empty path string: ${file}`);
    result[key]=path.resolve(base,entry);
  }
  return result;
}
export const readEngineConfiguration=(file:string)=>readConfiguration(file,enginePathKeys);
export const readAndroidConfiguration=(file:string)=>readConfiguration(file,androidPathKeys);
