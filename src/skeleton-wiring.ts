import path from 'node:path';
import {open,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {z} from 'zod';
import {digest} from './artifact.js';
import type {BridgePathAccess} from './rea-bridge.js';
import type {SkeletonFeature} from './skeleton.js';
const hash=z.string().regex(/^[a-f0-9]{64}$/),identifier=z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/);
const relative=z.string().min(1).max(1024).refine(s=>!path.isAbsolute(s)&&!/[\\<>:"|?*\x00-\x1f\x7f]/.test(s)&&s.split('/').every(p=>p!==''&&p!=='.'&&p!=='..'&&!/[ .]$/.test(p)),'Use an unambiguous portable relative path.');
const pin=z.object({path:relative,sha256:hash}).strict(),product=z.object({name:identifier,features:z.array(z.string()).min(1).max(64)}).strict();
export const skeletonWiringSchema=z.object({schema:z.literal('carve/skeleton-wiring@1'),planId:hash,specId:hash,
 files:z.array(pin).max(256).default([]),
 resources:z.array(z.object({feature:z.string(),path:relative,rule:z.enum(['copy','process'])}).strict()).max(128).default([]),
 packages:z.array(z.discriminatedUnion('kind',[
  z.object({kind:z.literal('local'),id:z.string().regex(/^[a-z][a-z0-9-]{0,47}$/),files:z.array(pin).min(1).max(128),products:z.array(product).min(1).max(32)}).strict(),
  z.object({kind:z.literal('remote'),id:z.string().regex(/^[a-z][a-z0-9-]{0,47}$/),url:z.string().regex(/^https:\/\/[A-Za-z0-9._/-]+$/).max(1024),revision:z.string().regex(/^[a-f0-9]{40}$/),products:z.array(product).min(1).max(32)}).strict()
 ])).max(32).default([]),
 links:z.array(z.object({feature:z.string(),frameworks:z.array(identifier).max(32).default([]),libraries:z.array(identifier).max(32).default([])}).strict()).max(64).default([])
}).strict();
export type SkeletonWiring=z.infer<typeof skeletonWiringSchema>;
export async function readWiringFile(root:string,file:string,sha256:string,authorize?:BridgePathAccess){
 const full=path.join(root,file);await authorize?.(full);if(await realpath(full)!==full)throw new Error('Skeleton wiring inputs must not redirect through symlinks.');
 const handle=await open(full,constants.O_RDONLY|constants.O_NOFOLLOW);try{const before=await handle.stat();if(!before.isFile()||before.size>8388608)throw new Error('Skeleton input must be regular and at most8MiB.');const b=Buffer.alloc(before.size+1);let n=0;while(n<b.length){const r=await handle.read(b,n,b.length-n);if(!r.bytesRead)break;n+=r.bytesRead;}const after=await handle.stat();if(n!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||digest(b.subarray(0,n))!==sha256)throw new Error('Skeleton wiring input changed: '+file);return b.subarray(0,n);}finally{await handle.close();}
}
export async function prepareSkeletonWiring(input:unknown,sourceRoot:string|undefined,features:SkeletonFeature[],assignments:Map<string,{files:string[]}>,planId:string,specId:string,authorize?:BridgePathAccess){
 if(Buffer.byteLength(JSON.stringify(input)??'')>1048576)throw new Error('Skeleton wiring exceeds1MiB.');
 const wiring=skeletonWiringSchema.parse(input);if(wiring.planId!==planId||wiring.specId!==specId)throw new Error('Skeleton wiring has stale plan/spec pins.');
 const byFeature=new Map(features.map(f=>[f.id,f])),owners=new Map([...assignments].flatMap(([id,a])=>a.files.map(file=>[file,id] as const))),keys=new Set<string>();
 const unique=(key:string)=>{key=key.normalize('NFC').toLowerCase();if(keys.has(key))throw new Error('Duplicate skeleton wiring declaration: '+key);keys.add(key);};
 for(const f of wiring.files){unique('file:'+f.path);if(!owners.has(f.path))throw new Error('Wiring file is outside assigned ownership: '+f.path);}
 for(const r of wiring.resources){unique('resource:'+r.path);const f=byFeature.get(r.feature);if(!f||owners.get(r.path)!==r.feature||r.path.endsWith('.swift')||!r.path.startsWith(f.sourceDir+'/Resources/')||!wiring.files.some(p=>p.path===r.path))throw new Error('Resources require a pinned assigned file under the owning Sources/<dir>/Resources/.');}
 for(const [file]of owners)if(!file.endsWith('.swift')&&!wiring.resources.some(r=>r.path===file))throw new Error('Every assigned resource needs a wiring rule and input pin.');
 for(const p of wiring.packages){unique('package:'+p.id);for(const product of p.products){unique('product:'+p.id+':'+product.name);for(const id of product.features){unique('product-target:'+p.id+':'+product.name+':'+id);if(!byFeature.has(id))throw new Error('Package product references an unknown feature.');}}
  if(p.kind==='local'){if(!p.files.some(f=>f.path==='Package.swift'))throw new Error('Local packages require a pinned Package.swift.');for(const f of p.files)unique('vendor:'+p.id+'/'+f.path);}}
 for(const l of wiring.links){unique('link:'+l.feature);if(!byFeature.has(l.feature))throw new Error('Link settings reference an unknown feature.');for(const x of l.frameworks)unique('framework:'+l.feature+':'+x);for(const x of l.libraries)unique('library:'+l.feature+':'+x);}
 const all=[...wiring.files.map(f=>({...f,owner:'feature:'+owners.get(f.path)})),...wiring.packages.flatMap(p=>p.kind==='local'?p.files.map(f=>({...f,path:'Vendor/'+p.id+'/'+f.path,owner:'skeleton-vendor'})):[])];
 if(all.length>512)throw new Error('Use at most512 copied skeleton inputs.');
 if(all.length&&!sourceRoot)throw new Error('Pinned inputs require sourceRoot.');
 let root:string|undefined;if(sourceRoot){root=path.resolve(sourceRoot);await authorize?.(root);if(await realpath(root)!==root)throw new Error('Skeleton source root must not redirect through symlinks.');}
 const copied=[];let total=0;for(const f of all){const text=await readWiringFile(root!,f.path,f.sha256,authorize);total+=text.length;if(total>67108864)throw new Error('Skeleton copied inputs exceed64MiB.');copied.push({...f,text});}
 return{wiring,copied};
}
