import {createReadStream} from 'node:fs';
import {totalmem,availableParallelism} from 'node:os';
import {z} from 'zod';

// Defaults preserve the pre-0.20 fixed engine launch settings exactly.
export const DEFAULT_HEAP_MIB=1024;
export const DEFAULT_THREADS=2;
export const engineResources=z.object({heapMiB:z.number().int().min(256).max(1048576).optional(),threads:z.number().int().min(1).max(1024).optional()}).strict();
export type EngineResources=z.infer<typeof engineResources>;
export interface ResolvedEngineResources {schema:'carve/engine-resources@1';heapMiB:number;threads:number;requested:{heapMiB:number|null;threads:number|null};host:{memoryMiB:number;parallelism:number;heapLimitMiB:number};scope:string}

export function hostEngineLimits(){
  const memoryMiB=Math.floor(totalmem()/1048576);
  return{memoryMiB,parallelism:availableParallelism(),heapLimitMiB:Math.max(256,Math.floor(memoryMiB*0.75))};
}
export function resolveEngineResources(requested?:EngineResources):ResolvedEngineResources{
  const parsed=engineResources.parse(requested??{});const host=hostEngineLimits();
  const heapMiB=parsed.heapMiB??DEFAULT_HEAP_MIB,threads=parsed.threads??DEFAULT_THREADS;
  if(parsed.heapMiB!==undefined&&heapMiB>host.heapLimitMiB)throw new Error(`heapMiB ${heapMiB} exceeds this host's engine heap limit ${host.heapLimitMiB} MiB (75% of ${host.memoryMiB} MiB physical memory).`);
  if(parsed.threads!==undefined&&threads>host.parallelism)throw new Error(`threads ${threads} exceeds this host's available parallelism ${host.parallelism}.`);
  return{schema:'carve/engine-resources@1',heapMiB,threads,requested:{heapMiB:parsed.heapMiB??null,threads:parsed.threads??null},host,
    scope:'Requested JVM maximum heap and engine worker-thread budget. Native decompiler processes, JVM metaspace/stacks and OS caches use memory beyond the heap; actual peak memory is not measured. Resources do not enter analysis cache identity.'};
}
const marker=Buffer.from('java.lang.OutOfMemoryError');
// Streams the whole retained log so an early heap failure cannot scroll out of the diagnostic tail.
export async function heapExhausted(log:string){
  let carry=Buffer.alloc(0);
  for await(const chunk of createReadStream(log)){
    const data=Buffer.concat([carry,chunk as Buffer]);if(data.includes(marker))return true;
    carry=data.subarray(Math.max(0,data.length-marker.length+1));
  }
  return false;
}
export function heapFailure(engine:string,resources:ResolvedEngineResources){
  return `${engine} reported java.lang.OutOfMemoryError with heapMiB ${resources.heapMiB}; the analysis is incomplete and was not recorded as completed. Retry with a larger heapMiB (host limit ${resources.host.heapLimitMiB} MiB) or a narrower scope.`;
}
