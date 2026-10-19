import {z} from 'zod';

/** Requested destination only; independent of source format and engine support. */
export const targetSpecSchema=z.object({
 schema:z.literal('carve/target@1'),
 platform:z.enum(['windows','macos','linux','ios','android','browser','server','portable']),
 delivery:z.enum(['desktop-app','mobile-app','web-app','module','cli','service']),
 runtime:z.string().trim().min(1).max(100).optional(),
 language:z.string().trim().min(1).max(100).optional(),
 architecture:z.enum(['x86','x86_64','arm','arm64','universal']).optional()
}).strict().superRefine((target,ctx)=>{
 const invalid=target.delivery==='desktop-app'&&!['windows','macos','linux'].includes(target.platform)
  ||target.delivery==='mobile-app'&&!['ios','android'].includes(target.platform)
  ||target.delivery==='web-app'&&target.platform!=='browser'
  ||target.platform==='browser'&&!['web-app','module'].includes(target.delivery)
  ||target.platform==='portable'&&target.delivery!=='module'
  ||target.platform==='server'&&!['module','cli','service'].includes(target.delivery);
 if(invalid)ctx.addIssue({code:z.ZodIssueCode.custom,path:['delivery'],message:'Choose a delivery form compatible with the declared target platform. This does not assess build/runtime availability.'});
});
export type TargetSpec=z.infer<typeof targetSpecSchema>;
