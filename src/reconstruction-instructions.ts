import path from 'node:path';
import {constants} from 'node:fs';
import {open,realpath} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {digest} from './artifact.js';
import {parseReaNativeEvidence} from './rea-native.js';
import {loadPeUiFunctions,type PeUiAccess} from './pe-ui-functions.js';
import {readPeLoader} from './pe-loader.js';

const sha=z.string().regex(/^[a-f0-9]{64}$/),address=z.string().regex(/^0x[0-9a-f]{1,16}$/),text=z.string().trim().min(1).max(2000);
const file=z.string().min(1).max(1024).refine(s=>!path.isAbsolute(s)&&!/[\\\x00-\x1f]/.test(s)&&s.split('/').every(p=>p!==''&&p!=='.'&&p!=='..'),'Use a workspace-relative regular file without traversal.');
const parameter=z.object({name:z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/),location:z.enum(['rcx','rdx','r8','r9']),type:z.enum(['uint32','uint64','pointer']),description:text}).strict();
export const reconstructionInstructionReview=z.object({
 observationId:sha,instructions:z.object({file,sha256:sha}).strict(),inferredSignature:z.string().max(8192),difference:text,
 abi:z.object({convention:z.literal('windows-x64'),parameters:z.array(parameter).max(4),result:z.discriminatedUnion('location',[
  z.object({location:z.literal('eax'),type:z.literal('uint32')}).strict(),
  z.object({location:z.literal('rax'),type:z.enum(['uint64','pointer'])}).strict(),
  z.object({location:z.literal('none'),type:z.literal('void')}).strict()
 ])}).strict(),
 bytes:z.array(z.object({address,length:z.number().int().min(1).max(256),sha256:sha}).strict()).min(1).max(16)
}).strict().superRefine((v,ctx)=>{
 if(new Set(v.abi.parameters.map(p=>p.location)).size!==v.abi.parameters.length||new Set(v.abi.parameters.map(p=>p.name)).size!==v.abi.parameters.length)ctx.addIssue({code:z.ZodIssueCode.custom,message:'ABI parameter names and locations must be unique.'});
});

async function bounded(file:string,max:number){
 const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await h.stat();if(!before.isFile()||before.size>max)throw new Error('Instruction evidence must be a regular bounded file.');const buffer=Buffer.alloc(before.size+1);let length=0;while(length<buffer.length){const r=await h.read(buffer,length,buffer.length-length,null);if(!r.bytesRead)break;length+=r.bytesRead;}const b=buffer.subarray(0,length),after=await h.stat();if(b.length!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw new Error('Instruction evidence changed while reading.');return b;}finally{await h.close();}
}

export async function bindReconstructionInstructions(root:string,file:string,ids:string[],reviews:z.infer<typeof reconstructionInstructionReview>[],signal?:AbortSignal,access?:PeUiAccess){
 const loaded=await loadPeUiFunctions(root,ids,signal,access,file),metadata=await readPeLoader(loaded[0]!.target.path,{signal}),seen=new Set<string>();let total=0;
 if(metadata.machine!==0x8664)throw new Error('Instruction ABI reviews currently require AMD64 PE inputs.');
 const results=[];
 for(const review of reviews){
  signal?.throwIfAborted();if(seen.has(review.observationId))throw new Error('Duplicate instruction review observation.');seen.add(review.observationId);
  const fn=loaded.find(f=>f.record.observationId===review.observationId);if(!fn)throw new Error('Instruction review requires a declared complete implementation observation.');
  if(review.inferredSignature!==fn.detail.signature)throw new Error('Instruction review inferred signature differs from imported evidence.');
  const source=path.resolve(root,review.instructions.file);await access?.(source);
  if(await realpath(source)!==source)throw new Error('Instruction evidence must be an owned workspace file without redirects.');
  const raw=await bounded(source,1048576);total+=raw.length;if(total>4*1048576)throw new Error('Instruction reviews exceed the cumulative4MiB evidence budget.');
  if(digest(raw)!==review.instructions.sha256)throw new Error('Instruction evidence SHA256 differs from its pin.');
  const record=parseReaNativeEvidence(JSON.parse(raw.toString('utf8')),'read_function_instructions');
  if(record.subject.digest.sha256!==fn.target.sha256||record.subject.format!=='pe'||record.subject.architecture!=='x86_64'||record.provider.id!=='ghidra'||record.analysis_profile.digest!==fn.record.profile||!isDeepStrictEqual(record.provider,fn.detail.provider.analysisProvider)||record.parameters.procedure!==fn.record.address)throw new Error('Instruction evidence must match source, provider, profile and exact function selector.');
  const normalized=record.normalized_result as any,rawResult=record.raw_result as any;
  if(!rawResult||!isDeepStrictEqual(rawResult.value,normalized)||!Array.isArray(rawResult.limitations)||rawResult.limitations.length||!normalized||!isDeepStrictEqual(normalized.procedure?.body,fn.detail.body)||normalized.procedure?.address!==fn.record.address||normalized.procedure?.name!==fn.record.name||normalized.procedure?.classification?.external!==false||normalized.procedure?.classification?.thunk!==fn.record.thunk||!Array.isArray(normalized.instructions)||!normalized.instructions.length||normalized.instructions.length>10000||!Array.isArray(normalized.limitations))throw new Error('Instruction evidence requires the complete matching function body and unmodified listing.');
  const instructions:{address:bigint;text:string}[]=[];let previous=-1n;
  for(const line of normalized.instructions){
   const match=typeof line==='string'&&line.length<=8192?/^(0x[0-9a-f]{1,16}): (.+)$/.exec(line):null;if(!match)throw new Error('Unsupported instruction listing line.');const point=BigInt(match[1]!);
   if(point<=previous||!fn.detail.body.ranges.some((r:any)=>BigInt(r.start)<=point&&point<=BigInt(r.end)))throw new Error('Instruction listing addresses must be ordered and within the imported body.');previous=point;instructions.push({address:point,text:line});
  }
  const witnesses=[];let end=-1n;
  const input=await open(fn.target.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{if(!(await input.stat()).isFile())throw new Error('Instruction byte source must be a regular file.');for(const selection of review.bytes){
   const start=BigInt(selection.address),last=start+BigInt(selection.length)-1n;
   if(start<=end||!instructions.some(i=>i.address===start)||!fn.detail.body.ranges.some((r:any)=>BigInt(r.start)<=start&&last<=BigInt(r.end)&&(instructions.some(i=>i.address===last+1n)||last===BigInt(r.end))))throw new Error('Reviewed byte ranges must be ordered, disjoint and bounded by listed instructions inside one function-body range.');end=last;
   const rva=start-BigInt(metadata.imageBase),matches=metadata.sections.filter(s=>rva>=BigInt(s.virtualAddress)&&rva+BigInt(selection.length)<=BigInt(s.virtualAddress)+BigInt(s.rawSize));
   if(matches.length!==1||!(matches[0]!.characteristics&0x20000000))throw new Error('Instruction bytes require one executable file-backed section.');
   const section=matches[0]!,offset=section.rawOffset+Number(rva-BigInt(section.virtualAddress)),bytes=Buffer.alloc(selection.length),read=await input.read(bytes,0,bytes.length,offset);
   if(read.bytesRead!==bytes.length||digest(bytes)!==selection.sha256)throw new Error('Reviewed instruction bytes differ from their source SHA256.');
   const listing=instructions.filter(i=>i.address>=start&&i.address<=last).map(i=>i.text);
   witnesses.push({...selection,fileOffset:offset,section:section.name,hex:bytes.toString('hex'),instructionCount:listing.length,instructionTextSha256:digest(JSON.stringify(listing)),instructions:listing.slice(0,16).map(line=>line.slice(0,512)),instructionsTruncated:listing.length>16||listing.some(line=>line.length>512)});
  }}finally{await input.close();}
  results.push({...review,sourceSha256:fn.target.sha256,snapshotSha256:fn.record.snapshotSha256,decompilerPseudocodeSha256:digest(fn.detail.pseudocode),instructions:{...review.instructions,evidenceId:record.evidence_id,provider:record.provider,profile:record.analysis_profile.digest,parameters:record.parameters,limitations:[...record.limitations,...normalized.limitations]},bytes:witnesses,verification:'not-run',authority:'Unsigned source-bound REA instruction text plus original byte witnesses. Instruction decoding and ABI semantics remain unverified; the ABI and difference are agent declarations.'});
 }
 return results;
}
