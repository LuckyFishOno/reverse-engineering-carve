import {z} from 'zod';
import {provenanceSchema,provenanceSummary} from './provenance.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
const text=z.string().trim().min(1).max(1200),id=z.string().regex(/^[a-z][a-z0-9-]{0,47}$/),hash=z.string().regex(/^[a-f0-9]{64}$/);
export const behaviorSchema=z.object({
 schema:z.literal('carve/behavior@1'),
 provenance:provenanceSchema.optional(),
 lifecycle:z.object({lifetime:z.enum(['unknown','independent','session','persistent']),initialize:text.optional(),reset:text.optional(),close:text.optional(),isolation:text.optional(),restart:text.optional()}).strict(),
 interaction:z.object({mode:z.enum(['unknown','none','events','stream']),surface:text.optional(),actions:z.array(z.object({id,trigger:text,expected:text.optional()}).strict()).max(24)}).strict(),
 protocol:z.object({mode:z.enum(['unknown','none','request-response','interactive']),name:text.optional(),negotiation:text.optional(),framing:text.optional(),ordering:text.optional()}).strict(),
 persistence:z.object({mode:z.enum(['unknown','none','memory','disk','remote']),retained:text.optional(),excluded:text.optional(),restart:text.optional()}).strict(),
 errors:z.object({mode:z.enum(['unknown','none','specified']),rationale:text.optional(),cases:z.array(z.object({id,trigger:text,expected:text.optional(),recovery:text.optional()}).strict()).max(16)}).strict(),
 scenarios:z.array(z.object({id,title:text,validation:z.enum(['manual','ui','protocol','restart','stateful-sequence']),
  covers:z.array(z.string().regex(/^[a-z][a-zA-Z0-9.-]{0,100}$/)).min(1).max(80),
  steps:z.array(z.object({action:text,expected:text}).strict()).min(1).max(16),
  sequenceCase:z.object({casesSha256:hash,name:text}).strict().optional()
 }).strict()).max(24)
}).strict().superRefine((b,ctx)=>{
 for(const [label,rows] of [['interaction.actions',b.interaction.actions],['errors.cases',b.errors.cases],['scenarios',b.scenarios]] as const){
  if(new Set(rows.map(row=>row.id)).size!==rows.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate IDs in '+label+'.'});
 }
 if(b.interaction.mode==='none'&&b.interaction.actions.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Interaction none cannot declare UI actions.'});
 if(b.errors.mode!=='specified'&&b.errors.cases.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Error cases require specified error mode.'});
 for(const s of b.scenarios){
  if(new Set(s.covers).size!==s.covers.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate scenario coverage: '+s.id});
  if(s.sequenceCase&&s.validation!=='stateful-sequence')ctx.addIssue({code:z.ZodIssueCode.custom,message:'sequenceCase requires stateful-sequence validation.'});
 }
 const known=new Set(requirements(b).map(r=>r.id));
 for(const c of b.provenance?.claims??[])if(!known.has(c.subject))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Unknown provenance requirement '+c.subject+'.'});
 for(const s of b.scenarios)for(const key of s.covers)if(!known.has(key))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Unknown behavior requirement '+key+' in '+s.id+'.'});
});
export type Behavior=z.infer<typeof behaviorSchema>;
type Requirement={id:string;description:string;declared:boolean};
function requirements(b:Behavior):Requirement[]{
 const rows:Requirement[]=[];
 const add=(id:string,description:string,declared:unknown)=>rows.push({id,description,declared:Boolean(declared)});
 add('lifecycle.lifetime','State lifetime must be explicit.',b.lifecycle.lifetime!=='unknown');
 add('lifecycle.isolation','Define isolation across calls, tabs, sessions or instances.',b.lifecycle.isolation);
 for(const key of ['initialize','reset','close','restart'] as const)if(b.lifecycle[key]!==undefined||(key==='restart'?b.lifecycle.lifetime==='persistent':['session','persistent'].includes(b.lifecycle.lifetime)))add('lifecycle.'+key,'Define lifecycle '+key+' behavior.',b.lifecycle[key]);
 add('interaction.mode','Specify whether interaction is absent, event-based or streaming.',b.interaction.mode!=='unknown');
 if(['events','stream'].includes(b.interaction.mode)||b.interaction.surface!==undefined||b.interaction.actions.length){
  add('interaction.surface','Identify the actual input surface.',b.interaction.surface);
  add('interaction.actions','Declare at least one required interaction.',b.interaction.actions.length);
  for(const a of b.interaction.actions)add('interaction.action.'+a.id,a.trigger,a.expected);
 }
 add('protocol.mode','Distinguish no protocol, request-response and a continuous interactive session.',b.protocol.mode!=='unknown');
 for(const key of ['name','negotiation','framing','ordering'] as const)if(['request-response','interactive'].includes(b.protocol.mode)||b.protocol[key]!==undefined)add('protocol.'+key,'Define protocol '+key+'.',b.protocol[key]);
 add('persistence.mode','Specify where state is retained, or explicitly retain none.',b.persistence.mode!=='unknown');
 for(const key of ['retained','excluded','restart'] as const)if(!['none','unknown'].includes(b.persistence.mode)||b.persistence[key]!==undefined)add('persistence.'+key,'Define persisted-state '+key+'.',b.persistence[key]);
 add('errors.mode','Declare error behavior or explicitly justify none.',b.errors.mode!=='unknown');
 if(b.errors.mode==='none')add('errors.rationale','Explain why no error behavior is in scope.',b.errors.rationale);
 if(b.errors.mode==='specified'){
  add('errors.cases','Declare at least one failure case.',b.errors.cases.length);
  for(const c of b.errors.cases){add('errors.case.'+c.id,c.trigger,c.expected);add('errors.recovery.'+c.id,'Define recovery after '+c.trigger,c.recovery);}
 }
 return rows;
}
function canonical(v:unknown):string{
 if(Array.isArray(v))return '['+v.map(canonical).join(',')+']';
 if(v&&typeof v==='object')return '{'+Object.keys(v).filter(k=>(v as Record<string,unknown>)[k]!==undefined).sort().map(k=>JSON.stringify(k)+':'+canonical((v as Record<string,unknown>)[k])).join(',')+'}';
 return JSON.stringify(v);
}
export function assessBehavior(input:unknown){
 let size:number;try{size=Buffer.byteLength(JSON.stringify(input)??'');}catch{throw new Error('Behavior contract must be JSON data.');}
 if(size>1048576)throw new Error('Behavior contract exceeds1MiB.');
 const contract=behaviorSchema.parse(input),sha256=digest(canonical(contract));
 const rows=requirements(contract).map(r=>{
  const validationKinds=r.id==='lifecycle.restart'||r.id==='persistence.restart'?['restart']:r.id.startsWith('interaction.')&&['events','stream'].includes(contract.interaction.mode)?['ui']:r.id.startsWith('protocol.')&&['request-response','interactive'].includes(contract.protocol.mode)?['protocol']:[];
  const scenarios=contract.scenarios.filter(s=>s.covers.includes(r.id)&&(!validationKinds.length||validationKinds.includes(s.validation))).map(s=>s.id);
  return{...r,provenanceStatus:contract.provenance?.claims.some(c=>c.subject===r.id)?'declared':'unclassified',provenance:(contract.provenance?.claims??[]).filter(c=>c.subject===r.id).map(c=>({id:c.id,kind:c.kind,authenticated:false})),validationKinds,scenarios,status:!r.declared?'missing-declaration':!scenarios.length?'missing-scenario':'declared-for-validation'};
 });
 const gaps=rows.filter(r=>r.status!=='declared-for-validation').map(r=>({id:r.id,reason:r.status,prompt:r.description+(r.validationKinds.length?' Required validation kind: '+r.validationKinds.join(', ')+'.':'')}));
 if(!contract.scenarios.length)gaps.push({id:'scenarios',reason:'missing-scenario',prompt:'Supply ordered actions with expected observations; a build check alone is insufficient.'});
 for(const s of contract.scenarios)if(s.validation==='stateful-sequence'&&!s.sequenceCase)gaps.push({id:'scenario.'+s.id,reason:'missing-sequence-reference',prompt:'Pin the existing sequence-cases file SHA256 and named case; the reference is not executed or authenticated here.'});
 return{contract,sha256,status:gaps.length?'needs-clarification':'declared-for-validation',requirements:rows,gaps,verification:'not-run',semanticMatch:'unconfirmed',executesTarget:false};
}
export function behaviorSummary(input:unknown){const r=assessBehavior(input);return{sha256:r.sha256,status:r.status,requirements:r.requirements.length,unresolved:r.gaps.length,scenarios:r.contract.scenarios.length,verification:r.verification,provenance:{...provenanceSummary(r.contract.provenance),unclassifiedRequirements:r.requirements.filter(row=>row.provenanceStatus==='unclassified').length}};}
export function behaviorAcceptance(input:unknown){
 const r=assessBehavior(input);if(r.status!=='declared-for-validation')throw new Error('Behavior contract needs clarification: '+r.gaps.slice(0,5).map(g=>g.id).join(', '));
 return r.contract.scenarios.map(s=>({name:'behavior:'+s.id,criterion:'Validate the ordered actions and expected observations of pinned interface.contract.behavior scenario '+s.id+'. Validation mode: '+s.validation+'. No execution or original equivalence is implied.',behaviorScenario:s.id}));
}
export function checkBehavior(input:unknown,options:{view?:'summary'|'requirements'|'scenarios'|'gaps'|'provenance';offset?:number;limit?:number;budgetBytes?:number}={}){
 const budget=responseBudget(options.budgetBytes),view=options.view??'summary',offset=options.offset??0,limit=options.limit??10;
 if(!['summary','requirements','scenarios','gaps','provenance'].includes(view)||!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use behavior summary/requirements/scenarios/gaps/provenance, offset>=0, limit1–100.');
 const r=assessBehavior(input),rows=view==='summary'?[]:view==='requirements'?r.requirements:view==='gaps'?r.gaps:view==='provenance'?(r.contract.provenance?.claims??[]):r.contract.scenarios;
 if(offset>rows.length)throw new Error('Behavior offset exceeds selected rows.');
 return budgetItems({schema:'carve/behavior-check@1',...behaviorSummary(r.contract),semanticMatch:'unconfirmed',executesTarget:false,startsRea:false,authority:'Declared requirements and scenario coverage only; text, references and expected observations are not authenticated or executed.',view,total:rows.length,offset},rows.slice(offset,offset+limit).map(value=>({value})),budget);
}
