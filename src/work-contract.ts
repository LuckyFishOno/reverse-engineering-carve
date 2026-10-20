import {z} from 'zod';
import {behaviorSchema,behaviorAcceptance} from './behavior.js';
import {digest} from './artifact.js';
import {parseProjectPlan,analyzeProjectPlan} from './project-plan.js';
import {targetSpecSchema} from './target.js';

const hash=z.string().regex(/^[a-f0-9]{64}$/),featureId=z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),text=(n:number)=>z.string().trim().min(1).max(n);
export const completeInterfaceSchema=z.object({input:text(2000),output:text(2000),state:text(2000),errors:text(2000),behavior:behaviorSchema.optional()}).strict();
function portableFile(file:string){
 if(file.length>1024||file.startsWith('/')||/[\\<>:"|?*\x00-\x1f\x7f]/.test(file))return false;
 return file.split('/').every(part=>part!==''&&part!=='.'&&part!=='..'&&!/[ .]$/.test(part)&&! /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}
const sourceContext=z.object({workspace:text(4096),file:text(4096),sourceSha256:hash,evidenceIds:z.array(hash).max(32).default([])}).strict();
export const workSpecSchema=z.object({schema:z.literal('carve/work-spec@1'),planId:hash,
 assignments:z.array(z.object({feature:featureId,taskId:hash,
  files:z.array(z.string().min(1).max(1024).refine(portableFile,'Use a portable relative POSIX file path, without traversal, reserved names or ambiguous separators.')).min(1).max(64),
  acceptance:z.array(z.object({name:text(100),criterion:text(2000)}).strict()).min(1).max(32),
  sourceContext:z.array(sourceContext).max(16).default([])
 }).strict()).min(1).max(500)
}).strict();
export type WorkSpec=z.infer<typeof workSpecSchema>;
const authority='Agent-declared plan, exact interface pins, source references and ownership instructions. Source/evidence paths are not opened or authenticated; ownership is not an OS sandbox; acceptance is not executed.';
export const workRecordSchema=z.object({schema:z.literal('carve/work-package@1'),planId:hash,specId:hash,taskId:hash,featureSha256:hash,
 goal:text(2000),projectUnknowns:z.array(text(500)).max(64),target:targetSpecSchema,
 feature:z.object({id:featureId,title:text(200),description:text(2000).optional(),unknowns:z.array(text(500)).max(32),evidenceIds:z.array(hash).max(32)}).strict(),
 interface:z.object({sha256:hash,contract:completeInterfaceSchema}).strict(),
 dependencies:z.array(z.object({feature:featureId,taskId:hash,contractSha256:hash,contract:completeInterfaceSchema}).strict()).max(64),
 assignment:z.object({files:z.array(z.string().min(1).max(1024).refine(portableFile)).min(1).max(64),acceptance:z.array(z.object({name:text(100),criterion:text(2000),behaviorScenario:z.string().optional()}).strict()).min(1).max(64),sourceContext:z.array(sourceContext).max(16)}).strict(),
 ownership:z.object({scope:z.literal('supplied-assignments-only'),assignedFeatures:z.number().int().min(1).max(500),unassignedFeatures:z.number().int().min(0).max(499)}).strict(),
 authority:z.literal(authority),verification:z.literal('not-run'),targetAssessment:z.literal('not-performed'),dependencyImplementation:z.literal('not-established'),startsAgents:z.literal(false)
}).strict().superRefine((record,ctx)=>{
 if(record.interface.sha256!==identity(record.interface.contract)||record.dependencies.some(d=>d.contractSha256!==identity(d.contract)))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Interface content differs from its declared pin.'});
 if(new Set(record.dependencies.map(d=>d.feature)).size!==record.dependencies.length||record.dependencies.some(d=>d.feature===record.feature.id))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Dependency interfaces must name distinct other features.'});
 if(record.interface.contract.behavior){
  const expected=behaviorAcceptance(record.interface.contract.behavior),actual=record.assignment.acceptance.filter(a=>a.behaviorScenario!==undefined);
  if(canonicalWork(expected)!==canonicalWork(actual))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Generated behavior acceptance differs from the pinned contract.'});
 }else if(record.assignment.acceptance.some(a=>a.behaviorScenario!==undefined))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Behavior acceptance requires a pinned behavior contract.'});
 if(new Set(record.assignment.files.map(key)).size!==record.assignment.files.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate editable file.'});
});
export function canonicalWork(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonicalWork).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).filter(k=>(value as Record<string,unknown>)[k]!==undefined).sort().map(k=>JSON.stringify(k)+':'+canonicalWork((value as Record<string,unknown>)[k])).join(',')+'}';
 return JSON.stringify(value);
}
const identity=(value:unknown)=>digest(canonicalWork(value));
const bytes=(value:unknown)=>{let serialized;try{serialized=JSON.stringify(value);}catch{throw new Error('Work specification must be JSON data.');}if(!serialized||Buffer.byteLength(serialized)>1048576)throw new Error('Work specification must be JSON data <=1MiB.');};
const key=(file:string)=>file.normalize('NFC').toLowerCase();

/** Exact declared interface pins, not ABI compatibility or authenticated source bindings. */
export function bindWorkContract(planInput:unknown,specInput:unknown,selected:string):WorkRecord{
 const plan=parseProjectPlan(planInput),analysis=analyzeProjectPlan(plan);bytes(specInput);featureId.parse(selected);
 const spec=workSpecSchema.parse(specInput);if(spec.planId!==analysis.planId)throw new Error('Stale planId: regenerate assignments from the current complete project plan.');
 const tasks=new Map(analysis.tasks.map(t=>[t.id,t])),features=new Map(plan.features.map(f=>[f.id,f]));
 const assignments=new Map<string,WorkSpec['assignments'][number]>(),owners=new Map<string,string>();
 let totalFiles=0;
 for(const assignment of spec.assignments){
  const task=tasks.get(assignment.feature);if(!task||task.taskId!==assignment.taskId)throw new Error('Assignment references an unknown feature or stale taskId: '+assignment.feature);
  if(assignments.has(assignment.feature))throw new Error('Duplicate feature assignment: '+assignment.feature);assignments.set(assignment.feature,assignment);
  if(new Set(assignment.acceptance.map(a=>a.name)).size!==assignment.acceptance.length)throw new Error('Acceptance names must be unique per assignment.');
  totalFiles+=assignment.files.length;if(totalFiles>4000)throw new Error('Use at most4000 declared output files across assignments.');
  for(const file of assignment.files){const normalized=key(file);if(owners.has(normalized))throw new Error('Overlapping file ownership: '+file);owners.set(normalized,assignment.feature);}
 }
 // File/directory prefix collisions also cross task boundaries and case/Unicode aliases.
 for(const file of owners.keys()){const parts=file.split('/');for(let i=1;i<parts.length;i++)if(owners.has(parts.slice(0,i).join('/')))throw new Error('A declared output file is an ancestor of another output file.');}
 const own=assignments.get(selected),task=tasks.get(selected),feature=features.get(selected);if(!own||!task||!feature)throw new Error('Select a feature with an explicit assignment.');
 if(task.status!=='ready')throw new Error('A cyclic or cycle-blocked feature needs its dependency boundary resolved before a work package can be created.');
 const requireInterface=(id:string)=>{const f=features.get(id)!,parsed=completeInterfaceSchema.safeParse(f.contract);if(!parsed.success)throw new Error('Complete input/output/state/errors interface is required for '+id+'.');return parsed.data;};
 const ownInterface=requireInterface(selected),dependencies=feature.dependsOn.map(id=>({feature:id,taskId:tasks.get(id)!.taskId,contractSha256:tasks.get(id)!.contractSha256!,contract:requireInterface(id)}));
 const generated=ownInterface.behavior?behaviorAcceptance(ownInterface.behavior):[];
 for(const d of dependencies)if(d.contract.behavior)behaviorAcceptance(d.contract.behavior);
 if(generated.some(g=>own.acceptance.some(a=>a.name===g.name)))throw new Error('Manual acceptance names must not collide with generated behavior scenario names.');
 const normalized={...spec,assignments:[...spec.assignments].map(a=>({...a,files:[...a.files].sort()})).sort((a,b)=>a.feature<b.feature?-1:1)},specId=identity(normalized);
 return{schema:'carve/work-package@1' as const,planId:analysis.planId,specId,taskId:task.taskId,featureSha256:task.featureSha256,
  goal:plan.goal,projectUnknowns:plan.unknowns,target:plan.target,feature:{id:feature.id,title:feature.title,description:feature.description,unknowns:feature.unknowns,evidenceIds:feature.evidenceIds},
  interface:{sha256:task.contractSha256!,contract:ownInterface},dependencies,assignment:{files:[...own.files].sort(),acceptance:[...own.acceptance,...generated],sourceContext:own.sourceContext},
  ownership:{scope:'supplied-assignments-only' as const,assignedFeatures:assignments.size,unassignedFeatures:plan.features.length-assignments.size},
  authority,
  verification:'not-run' as const,targetAssessment:'not-performed' as const,dependencyImplementation:'not-established' as const,startsAgents:false as const};
}
export type WorkRecord=z.infer<typeof workRecordSchema>;
