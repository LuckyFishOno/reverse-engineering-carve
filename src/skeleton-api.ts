import path from 'node:path';
import {readFile,writeFile,realpath} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {createSkeleton,checkSkeleton,manifestSchema} from './skeleton.js';
import {parseProjectPlan,analyzeProjectPlan} from './project-plan.js';
import {workSpecSchema,bindWorkContract,canonicalWork} from './work-contract.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import type {BridgePathAccess} from './rea-bridge.js';
type Options={signal?:AbortSignal;authorizePath?:BridgePathAccess;budgetBytes?:number;offset?:number;limit?:number;wiring?:unknown;sourceRoot?:string;execute?:boolean;test?:boolean;flow?:string;timeoutMs?:number;scratchPath?:string};
function paging(options:Options){const budget=responseBudget(options.budgetBytes),offset=options.offset??0,limit=options.limit??8;if(!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use offset>=0 and limit1–100.');return{budget,offset,limit};}
export async function skeletonCreate(plan:unknown,spec:unknown,out:string,options:Options={}){
 const {budget,offset,limit}=paging(options);if(offset!==0)throw new Error('Create skeleton from offset0.');
 const result=await createSkeleton(plan,spec,out,options);
 return budgetItems({schema:'carve/skeleton-view@1',action:'create',skeleton:result.skeleton,planId:result.planId,specId:result.specId,target:result.target,built:false,originalComparison:'not-performed',files:result.files,total:result.features.length,offset},result.features.slice(offset,offset+limit).map(value=>({value})),budget);
}
export async function skeletonCheck(input:string,current:{plan:unknown;spec:unknown},options:Options={}){
 if(options.execute!==true)throw new Error('Skeleton checks execute trusted Swift manifests, dependencies and feature code with host permissions. Supply execute:true; not a security sandbox.');
 const {budget,offset,limit}=paging(options);options.signal?.throwIfAborted();const dir=await realpath(input);await options.authorizePath?.(dir);await options.authorizePath?.(path.join(dir,'carve-skeleton.json'));
 const {boundedJson}=await import('./reconstruction.js');const raw=(await boundedJson(path.join(dir,'carve-skeleton.json'))).value;
 const plan=parseProjectPlan(current.plan),spec=workSpecSchema.parse(current.spec),a=analyzeProjectPlan(plan),record=bindWorkContract(plan,spec,spec.assignments[0]!.feature);
 if(raw.planId!==a.planId||raw.specId!==record.specId)throw new Error('Skeleton is stale for the current plan/spec. Generate a new snapshot.');
 const result=await checkSkeleton(dir,options),data=canonicalWork(result)+'\n',report=path.join(dir,'.carve-check','result-'+randomUUID()+'.json');await options.authorizePath?.(report,true);await writeFile(report,data,{flag:'wx',mode:0o600});
 const rows=result.featureFiles as Record<string,unknown>[];if(offset>rows.length)throw new Error('Skeleton feature offset exceeds available rows.');
 const self=result.selfTest as any,flow=result.flow as any;
 return budgetItems({schema:'carve/skeleton-view@1',action:'check',skeleton:dir,planId:a.planId,specId:record.specId,build:result.build,test:result.test??null,selfTest:self?{exitCode:self.exitCode,implemented:self.report?.implemented??null,total:self.report?.total??null}:null,flow:flow?{exitCode:flow.exitCode,status:flow.report?.status??null}:null,reportFile:report,reportSha256:digest(data),originalComparison:'not-performed',scope:result.scope,total:rows.length,offset},rows.slice(offset,offset+limit).map(value=>({value})),budget);
}

export async function skeletonInspect(input:string,options:Options={}){
 const {budget,offset,limit}=paging(options),dir=await realpath(input);await options.authorizePath?.(dir);const file=path.join(dir,'carve-skeleton.json');await options.authorizePath?.(file);const {boundedJson}=await import('./reconstruction.js');const raw=await boundedJson(file),manifest=manifestSchema.parse(raw.value);
 if(offset>manifest.features.length)throw new Error('Skeleton feature offset exceeds available rows.');
 return budgetItems({schema:'carve/skeleton-view@1',action:'inspect',skeleton:dir,planId:manifest.planId,specId:manifest.specId,manifestSha256:raw.sha256,target:manifest.target,total:manifest.features.length,offset,authority:'Recorded manifest declarations only; no current file integrity, build or behavior verification.',originalComparison:'not-performed'},manifest.features.slice(offset,offset+limit).map(value=>({value})),budget);
}
