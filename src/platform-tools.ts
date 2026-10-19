import {z} from 'zod';
import {PLATFORM_CATEGORIES,inspectPlatformDependencies,type PlatformCategory} from './platform-dependencies.js';
import {inspectTargetAdapters} from './target-adapters.js';
import {targetSpecSchema} from './target.js';
const page={offset:z.number().int().nonnegative().optional(),limit:z.number().int().min(1).max(100).optional(),budgetBytes:z.number().int().min(1024).max(65536).optional()};
export const platformRequestSchema=z.discriminatedUnion('kind',[
 z.object({kind:z.literal('dependencies'),view:z.enum(['summary','categories','imports','rules']).optional(),category:z.enum(Object.keys(PLATFORM_CATEGORIES) as [PlatformCategory,...PlatformCategory[]]).optional(),...page}).strict(),
 z.object({kind:z.literal('target-adapters'),target:targetSpecSchema,view:z.enum(['summary','cards']).optional(),...page}).strict()
]);
export async function inspectPlatform(workspace:string,file:string,input:unknown,signal?:AbortSignal){
 const request=platformRequestSchema.parse(input);signal?.throwIfAborted();
 if(request.kind==='dependencies'&&request.category&&request.view!=='imports')throw new Error('A category filter requires the imports view.');
 return request.kind==='dependencies'?inspectPlatformDependencies(workspace,{...request,file,signal}):inspectTargetAdapters(workspace,{...request,file,signal});
}
