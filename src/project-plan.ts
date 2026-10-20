import {z} from 'zod';
import {behaviorSchema,behaviorSummary} from './behavior.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {targetSpecSchema} from './target.js';

// A whole-project port plan is written by the agent: features, their declared dependencies and
// optional interface contracts. Planning only orders that declaration. It never executes code,
// reads files, starts REA or agents, or turns the plan into evidence of coverage or behavior.
export const PROJECT_PLAN_LIMITS={features:500,dependsOnPerFeature:64,edges:4000,inputBytes:1048576,unknowns:64,featureUnknowns:32,evidenceIds:32} as const;
const featureId=z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/,'Feature ids are 1–64 lowercase letters, digits, ".", "_" or "-", starting with a letter or digit.');
const text=(max:number)=>z.string().trim().min(1).max(max);
const contractSchema=z.object({input:text(2000).optional(),output:text(2000).optional(),state:text(2000).optional(),errors:text(2000).optional(),behavior:behaviorSchema.optional()}).strict()
 .refine(contract=>Object.keys(contract).length>0,'A contract needs at least one of input, output, state or errors, or a structured behavior contract.');
const featureSchema=z.object({
 id:featureId,title:text(200),description:text(2000).optional(),
 dependsOn:z.array(featureId).max(PROJECT_PLAN_LIMITS.dependsOnPerFeature).default([]),
 contract:contractSchema.optional(),
 unknowns:z.array(text(500)).max(PROJECT_PLAN_LIMITS.featureUnknowns).default([]),
 // Declared by the agent; planning does not open or authenticate them.
 evidenceIds:z.array(z.string().regex(/^[a-f0-9]{64}$/)).max(PROJECT_PLAN_LIMITS.evidenceIds).default([])
}).strict();
export const projectPlanSchema=z.object({
 schema:z.literal('carve/project-plan@1'),goal:text(2000),target:targetSpecSchema,
 features:z.array(featureSchema).min(1).max(PROJECT_PLAN_LIMITS.features),
 unknowns:z.array(text(500)).max(PROJECT_PLAN_LIMITS.unknowns).default([])
}).strict().superRefine((plan,ctx)=>{
 const ids=new Set<string>();let edges=0;
 plan.features.forEach((feature,index)=>{if(ids.has(feature.id))ctx.addIssue({code:z.ZodIssueCode.custom,path:['features',index,'id'],message:`Duplicate feature id ${feature.id}.`});ids.add(feature.id);});
 plan.features.forEach((feature,index)=>{
  const seen=new Set<string>();edges+=feature.dependsOn.length;
  feature.dependsOn.forEach((dependency,position)=>{
   const at=['features',index,'dependsOn',position];
   if(dependency===feature.id)ctx.addIssue({code:z.ZodIssueCode.custom,path:at,message:`Feature ${feature.id} cannot depend on itself.`});
   else if(!ids.has(dependency))ctx.addIssue({code:z.ZodIssueCode.custom,path:at,message:`Feature ${feature.id} depends on unknown feature ${dependency}.`});
   if(seen.has(dependency))ctx.addIssue({code:z.ZodIssueCode.custom,path:at,message:`Feature ${feature.id} lists dependency ${dependency} more than once.`});
   seen.add(dependency);
  });
  const evidence=new Set(feature.evidenceIds);if(evidence.size!==feature.evidenceIds.length)ctx.addIssue({code:z.ZodIssueCode.custom,path:['features',index,'evidenceIds'],message:`Feature ${feature.id} lists an evidence id more than once.`});
 });
 if(edges>PROJECT_PLAN_LIMITS.edges)ctx.addIssue({code:z.ZodIssueCode.custom,path:['features'],message:`A plan may declare at most ${PROJECT_PLAN_LIMITS.edges} dependencies; it has ${edges}.`});
});
export type ProjectPlan=z.infer<typeof projectPlanSchema>;
type Feature=ProjectPlan['features'][number];

// Sorted-key JSON so equal plans hash equally regardless of key or feature order.
function canonical(value:unknown):string{
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().filter(k=>(value as Record<string,unknown>)[k]!==undefined).map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
 return JSON.stringify(value);
}
const hash=(value:unknown)=>digest(canonical(value));
// UTF-16 prefix that never ends inside a surrogate pair.
function clip(value:string,max:number){if(value.length<=max)return{text:value,truncated:false};let end=max;const code=value.charCodeAt(end-1);if(code>=0xd800&&code<=0xdbff)end--;return{text:value.slice(0,end),truncated:true};}

export function parseProjectPlan(input:unknown):ProjectPlan{
 let bytes:number;try{bytes=Buffer.byteLength(JSON.stringify(input)??'');}catch{throw new Error('Project plan must be JSON-serializable data.');}
 if(bytes>PROJECT_PLAN_LIMITS.inputBytes)throw new Error(`Project plan exceeds ${PROJECT_PLAN_LIMITS.inputBytes} bytes of JSON.`);
 const parsed=projectPlanSchema.safeParse(input);
 if(!parsed.success){const issues=parsed.error.issues;throw new Error('Invalid project plan: '+issues.slice(0,5).map(i=>`${i.path.join('.')||'plan'}: ${i.message}`).join('; ')+(issues.length>5?`; and ${issues.length-5} more issue(s).`:''));}
 // Feature and dependency order carry no meaning; sort them so identities are stable.
 const features=[...parsed.data.features].map(f=>({...f,dependsOn:[...f.dependsOn].sort(),evidenceIds:[...f.evidenceIds].sort()})).sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
 return{...parsed.data,features};
}

export interface PlannedTask {id:string;taskId:string;featureSha256:string;contractSha256:string|null;status:'ready'|'in-cycle'|'blocked';phase:number|null;cycle:string|null;dependsOn:string[];dependents:number;blockedBy:string[]}
export interface PlanAnalysis {planId:string;plan:ProjectPlan;tasks:PlannedTask[];cycles:{id:string;members:string[]}[];phases:number;edges:number}

export function analyzeProjectPlan(plan:ProjectPlan):PlanAnalysis{
 const features=plan.features,index=new Map(features.map((f,i)=>[f.id,i])),n=features.length;
 const dependents:number[][]=features.map(()=>[]);let edges=0;
 features.forEach((f,i)=>{for(const d of f.dependsOn){dependents[index.get(d)!]!.push(i);edges++;}});
 // Iterative Tarjan over dependency edges; recursion would overflow on long chains.
 const order:number[]=new Array(n).fill(-1),low:number[]=new Array(n).fill(0),onStack:boolean[]=new Array(n).fill(false),stack:number[]=[],component:number[]=new Array(n).fill(-1);
 const components:number[][]=[];let counter=0;
 for(let start=0;start<n;start++){
  if(order[start]!==-1)continue;
  const work:[number,number][]=[[start,0]];order[start]=low[start]=counter++;stack.push(start);onStack[start]=true;
  while(work.length){
   const frame=work[work.length-1]!,[node,next]=frame,deps=features[node]!.dependsOn;
   if(next<deps.length){
    frame[1]++;const target=index.get(deps[next]!)!;
    if(order[target]===-1){order[target]=low[target]=counter++;stack.push(target);onStack[target]=true;work.push([target,0]);}
    else if(onStack[target])low[node]=Math.min(low[node]!,order[target]!);
    continue;
   }
   work.pop();if(work.length){const parent=work[work.length-1]![0];low[parent]=Math.min(low[parent]!,low[node]!);}
   if(low[node]===order[node]){const members:number[]=[];let member:number;do{member=stack.pop()!;onStack[member]=false;component[member]=components.length;members.push(member);}while(member!==node);components.push(members);}
  }
 }
 // Cycles are named by their smallest member id order, so names are stable for one plan.
 const cyclic=components.map((members,c)=>({c,members:members.map(m=>features[m]!.id).sort()})).filter(x=>x.members.length>1).sort((a,b)=>a.members[0]!<b.members[0]!?-1:1);
 const cycleName=new Map<number,string>();cyclic.forEach((x,i)=>cycleName.set(x.c,`cycle-${i+1}`));
 // Components form a DAG; Kahn's algorithm gives phases and carries cycle blockage downstream.
 const cn=components.length,indegree=new Array(cn).fill(0),next:Set<number>[]=components.map(()=>new Set());
 features.forEach((f,i)=>{for(const d of f.dependsOn){const from=component[index.get(d)!]!,to=component[i]!;if(from!==to&&!next[from]!.has(to)){next[from]!.add(to);indegree[to]++;}}});
 const phase:(number|null)[]=new Array(cn).fill(null),blockers:Set<string>[]=components.map(()=>new Set()),queue:number[]=[];
 for(let c=0;c<cn;c++)if(indegree[c]===0)queue.push(c);
 const depth=new Array(cn).fill(1);
 for(let head=0;head<queue.length;head++){
  const c=queue[head]!,own=cycleName.get(c),blocked=own!==undefined||blockers[c]!.size>0;
  if(!blocked)phase[c]=depth[c];
  for(const to of next[c]!){
   if(own!==undefined)blockers[to]!.add(own);for(const b of blockers[c]!)blockers[to]!.add(b);
   depth[to]=Math.max(depth[to],depth[c]+1);if(--indegree[to]===0)queue.push(to);
  }
 }
 const target=plan.target;
 const contractHash=(f:Feature)=>f.contract?hash(f.contract):null;
 const tasks=features.map((f,i):PlannedTask=>{
  const c=component[i]!,cycle=cycleName.get(c)??null,blockedBy=[...blockers[c]!].sort();
  const featureSha256=hash({id:f.id,title:f.title,description:f.description,contract:f.contract,unknowns:f.unknowns,evidenceIds:f.evidenceIds});
  // A task changes when the target, the feature itself or a direct dependency's contract changes.
  const taskId=hash({schema:'carve/project-task@1',target,feature:featureSha256,dependencies:f.dependsOn.map(d=>({id:d,contractSha256:contractHash(features[index.get(d)!]!)}))});
  return{id:f.id,taskId,featureSha256,contractSha256:contractHash(f),status:cycle?'in-cycle':blockedBy.length?'blocked':'ready',phase:cycle||blockedBy.length?null:phase[c]!,cycle,dependsOn:f.dependsOn,dependents:dependents[i]!.length,blockedBy};
 });
 // Development order: ready tasks by phase, then cycle members by cycle, then blocked tasks.
 const rank={ready:0,'in-cycle':1,blocked:2} as const;
 tasks.sort((a,b)=>rank[a.status]-rank[b.status]||(a.phase??0)-(b.phase??0)||(a.cycle??'').localeCompare(b.cycle??'',undefined,{numeric:true})||(a.id<b.id?-1:a.id>b.id?1:0));
 return{planId:hash(plan),plan,tasks,cycles:cyclic.map((x,i)=>({id:`cycle-${i+1}`,members:x.members})),phases:Math.max(0,...tasks.map(t=>t.phase??0)),edges};
}

const LIST=16;
const bounded=(values:string[])=>({values:values.slice(0,LIST),total:values.length});
export function planProject(input:unknown,options:{offset?:number;limit?:number;budgetBytes?:number}={}){
 const budget=responseBudget(options.budgetBytes),offset=options.offset??0,limit=options.limit??20;
 if(!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use limit 1–100.');
 const analysis=analyzeProjectPlan(parseProjectPlan(input)),plan=analysis.plan,features=new Map(plan.features.map(f=>[f.id,f]));
 if(!Number.isInteger(offset)||offset<0||offset>=analysis.tasks.length)throw new Error(`Use an offset from 0 to ${analysis.tasks.length-1}.`);
 const goal=clip(plan.goal,160),count=(status:PlannedTask['status'])=>analysis.tasks.filter(t=>t.status===status).length;
 const cards=analysis.tasks.slice(offset,offset+limit).map(task=>{
  const f=features.get(task.id)!,title=clip(f.title,120),deps=bounded(task.dependsOn),blocked=bounded(task.blockedBy);
  return{value:{id:task.id,taskId:task.taskId,title:title.text,...(title.truncated?{titleTruncated:true}:{}),status:task.status,phase:task.phase,cycle:task.cycle,
   dependsOn:deps.values,...(deps.total>deps.values.length?{dependsOnTotal:deps.total}:{}),dependents:task.dependents,
   blockedBy:blocked.values,...(blocked.total>blocked.values.length?{blockedByTotal:blocked.total}:{}),
   contract:{present:Boolean(f.contract),fields:f.contract?Object.keys(f.contract).sort():[],sha256:task.contractSha256,...(f.contract?.behavior?{behavior:behaviorSummary(f.contract.behavior)}:{})},
   featureSha256:task.featureSha256,declaredUnknowns:f.unknowns.length,declaredEvidenceIds:f.evidenceIds.length}};
 });
 return budgetItems({schema:'carve/project-plan-view@1',planId:analysis.planId,goal:goal.text,...(goal.truncated?{goalTruncated:true}:{}),target:plan.target,
  summary:{features:plan.features.length,dependencies:analysis.edges,phases:analysis.phases,ready:count('ready'),cycles:analysis.cycles.length,inCycle:count('in-cycle'),blocked:count('blocked'),projectUnknowns:plan.unknowns.length},
  order:'ready by phase (one phase has no mutual dependencies), then cycle members, then blocked; ties by id',
  authority:'Agent-declared plan ordered as written. Not engine evidence, verified code, complete feature coverage, target build support or dispatched work. Declared evidence ids are not opened or authenticated.',
  total:analysis.tasks.length,offset,limit},cards,budget);
}
