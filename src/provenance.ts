import {z} from 'zod';
const text=z.string().trim().min(1).max(1200),hash=z.string().regex(/^[a-f0-9]{64}$/);
const reference=z.object({sourceSha256:hash,evidenceId:hash,locator:text}).strict();
const common={id:z.string().regex(/^[a-z][a-z0-9-]{0,47}$/),subject:text,statement:text};
export const provenanceSchema=z.object({schema:z.literal('carve/provenance@1'),claims:z.array(z.discriminatedUnion('kind',[
 z.object({...common,kind:z.literal('original-evidence'),references:z.array(reference).min(1).max(16),limits:text}).strict(),
 z.object({...common,kind:z.literal('hypothesis'),basis:z.array(reference).max(16),uncertainty:text}).strict(),
 z.object({...common,kind:z.literal('target-design'),rationale:text}).strict(),
 z.object({...common,kind:z.literal('verified-behavior'),comparison:z.object({reportSha256:hash,originalSha256:hash,candidateSha256:hash,casesSha256:hash,scope:text,environment:text,limitations:text}).strict()}).strict()
])).max(64)}).strict().superRefine((p,ctx)=>{
 if(new Set(p.claims.map(c=>c.id)).size!==p.claims.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate provenance claim IDs.'});
});
export type Provenance=z.infer<typeof provenanceSchema>;
export function provenanceSummary(input?:Provenance){
 if(!input)return{status:'unclassified' as const,authenticated:false as const};
 const p=provenanceSchema.parse(input);
 return{status:'declared' as const,authenticated:false as const,claims:p.claims.length,counts:Object.fromEntries(['original-evidence','hypothesis','target-design','verified-behavior'].map(k=>[k,p.claims.filter(c=>c.kind===k).length])),authority:'Agent-declared classifications and content pins only; references and comparison reports are not opened or authenticated. Verified-behavior labels are reported claims, not RECarve verification.'};
}
