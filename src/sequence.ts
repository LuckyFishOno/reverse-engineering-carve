import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import type {Outcome} from './execution.js';

export const MAX_SEQUENCE_STEPS=64;
export const stepOutcomeSchema=z.discriminatedUnion('kind',[
 z.object({kind:z.literal('return'),value:z.unknown()}).strict(),
 z.object({kind:z.literal('throw'),error:z.object({name:z.string(),message:z.string()}).strict()}).strict()
]);
export type StepOutcome=z.infer<typeof stepOutcomeSchema>;
export type SequenceOutcome={kind:'return';value:StepOutcome[]}|{kind:'harness-error';detail:string};
export const sequenceCasesSchema=z.object({schema:z.literal('carve/sequence-cases@1'),cases:z.array(z.object({name:z.string().min(1).max(8000),steps:z.array(z.object({args:z.array(z.unknown()),expected:z.unknown().optional()}).strict()).min(1).max(MAX_SEQUENCE_STEPS)}).strict()).min(1).max(200)}).strict();
export const sequenceExampleSchema=z.object({calls:z.array(z.array(z.unknown())).min(1).max(MAX_SEQUENCE_STEPS),outcomes:z.array(stepOutcomeSchema).min(1).max(MAX_SEQUENCE_STEPS),origin:z.string().optional(),scope:z.string().optional()}).strict();
export function sequenceCalls(value:unknown):unknown[][]{
 const calls=z.array(z.array(z.unknown())).min(1).max(MAX_SEQUENCE_STEPS).parse(value);
 const json=JSON.stringify(calls,(_key,item)=>{
  if(['undefined','function','symbol','bigint'].includes(typeof item)||typeof item==='number'&&!Number.isFinite(item))throw new Error('Sequence arguments must contain finite JSON values.');return item;
 });
 if(Buffer.byteLength(json)>1048576)throw new Error('Sequence input exceeds 1 MiB.');
 return JSON.parse(json);
}
export function sequenceOutcome(outcome:Outcome,count:number):SequenceOutcome{
 if(outcome.kind==='harness-error')return outcome;
 if(outcome.kind!=='return')return{kind:'harness-error',detail:'Sequence protocol requires an array of return/throw outcomes.'};
 try{
  const rows=z.array(stepOutcomeSchema).length(count).parse(outcome.value);
  if(rows.some(row=>row.kind==='return'&&!Object.hasOwn(row,'value')))throw new Error('A return outcome must contain value.');
  JSON.stringify(rows,(_key,item)=>{if(typeof item==='number'&&!Number.isFinite(item))throw new Error('Non-finite sequence output.');return item;});
  return{kind:'return',value:rows};
 }catch{return{kind:'harness-error',detail:'Sequence protocol requires exactly one finite return/throw outcome per requested step.'};}
}
/** Preserve a whole successful sequence: an isolated step may depend on earlier state. */
export function recordedSequenceExample(report:Record<string,any>){
 if(report.comparisonMode!=='stateful-sequences'||report.status!=='passed-supplied-cases')return undefined;
 for(const row of report.results??[]){
  if(row.passed!==true||!Array.isArray(row.calls)||row.original?.kind!=='return'||row.candidate?.kind!=='return')continue;
  const parsed=sequenceExampleSchema.safeParse({calls:row.calls,outcomes:row.original.value,origin:'recorded-reference-sequence',scope:report.verifiedScope});
  if(parsed.success&&parsed.data.calls.length===parsed.data.outcomes.length&&isDeepStrictEqual(row.original.value,row.candidate.value)&&Buffer.byteLength(JSON.stringify(parsed.data))<=4096)return parsed.data;
 }
 return undefined;
}
