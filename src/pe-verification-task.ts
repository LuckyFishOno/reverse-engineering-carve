import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,readFile,writeFile,realpath,rm,open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {digest} from './artifact.js';
import {readPackage} from './package.js';
import {readPeLoader} from './pe-loader.js';
import {loadPeUiFunctions} from './pe-ui-functions.js';
import {reconstructionContract,bindReconstruction,assertReconstructionBinding,type WorkspaceAccess} from './reconstruction-contract.js';
import type {BridgePathAccess} from './rea-bridge.js';

const text=z.string().min(1).max(4096),sha=z.string().regex(/^[a-f0-9]{64}$/),name=z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/),argument=z.number().int().min(0).max(3);
export const peVerificationSpec=z.object({schema:z.literal('carve/pe-verification-task@1'),artifact:z.string().regex(/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/),observationId:sha,
 python:text.refine(path.isAbsolute,'Python executable must be absolute.'),
 bindings:z.array(z.discriminatedUnion('kind',[
  z.object({parameter:name,kind:z.literal('uint32'),argument}).strict(),
  z.object({parameter:name,kind:z.literal('bytes'),argument,maxLength:z.number().int().min(1).max(4096),alignment:z.number().int().min(0).max(7).optional()}).strict(),
  z.object({parameter:name,kind:z.literal('inout-bytes'),argument,maxLength:z.number().int().min(1).max(4096),alignment:z.number().int().min(0).max(7).optional()}).strict(),
  z.object({parameter:name,kind:z.literal('output-bytes'),argument,maxLength:z.number().int().min(1).max(4096),alignment:z.number().int().min(0).max(7).optional()}).strict(),
  z.object({parameter:name,kind:z.literal('uint32-array'),argument,length:z.number().int().min(1).max(1024)}).strict(),
  z.object({parameter:name,kind:z.literal('length'),of:name}).strict()
 ])).max(4),instructionLimit:z.number().int().min(1).max(1000000).default(100000),timeoutMicros:z.number().int().min(1000).max(1000000).default(1000000),
 sequence:z.object({initializers:z.array(z.union([z.array(z.number().int().min(0).max(0xffffffff)).max(4),z.object({observationId:sha,args:z.array(z.number().int().min(0).max(0xffffffff)).max(4)}).strict()])).max(8),helpers:z.array(sha).max(8).optional(),boundaries:z.array(z.object({observationId:sha,result:z.union([z.literal(0),z.literal(1)]),phase:z.literal('initialization'),expectedCalls:z.number().int().min(1).max(8),reason:z.string().trim().min(1).max(512)}).strict()).max(4).optional(),memory:z.array(z.object({address:z.string().regex(/^0x[0-9a-fA-F]+$/),length:z.number().int().min(1).max(65536),access:z.enum(['read','read-write','initialize-write']),initializedSha256:sha.optional()}).strict()).max(16)}).strict().optional()
}).strict();
export const peReferenceSchema=z.object({schema:z.literal('carve/pe-reference@1'),task:text,taskSha256:sha}).strict();
type Access={authorizePath?:BridgePathAccess;authorizeWorkspace?:WorkspaceAccess;signal?:AbortSignal};
const runnerSource=fileURLToPath(new URL('../engines/pe-abi-runner.py',import.meta.url));
async function regular(file:string,max:number){
 const h=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await h.stat();if(!before.isFile()||before.size>max)throw new Error('PE task files must be regular and within their byte budget.');const buffer=Buffer.alloc(before.size+1);let n=0;while(n<buffer.length){const r=await h.read(buffer,n,buffer.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}const after=await h.stat();if(n!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw new Error('PE task file changed while reading.');return buffer.subarray(0,n);}finally{await h.close();}
}
async function json(file:string,access?:BridgePathAccess){
 await access?.(file);if(await realpath(file)!==path.resolve(file))throw new Error('PE task files must not use redirects.');const data=await regular(file,1048576);return {value:JSON.parse(data.toString('utf8')),sha256:digest(data)};
}
async function context(workspace:string,packagePath:string,access:Access){
 const pkg=await readPackage(packagePath),provenance=pkg.manifest.reconstruction;
 if(provenance?.schema!=='carve/reconstruction-provenance@2')throw new Error('PE verification tasks require a version2 reconstruction package.');
 const contract=reconstructionContract.parse(provenance.contract),bound=await bindReconstruction(workspace,contract,access.authorizeWorkspace,access.signal,access.authorizePath);assertReconstructionBinding(provenance,bound);
 return {pkg,bound};
}
async function descriptor(spec:z.infer<typeof peVerificationSpec>,ctx:Awaited<ReturnType<typeof context>>,access:Access){
 const artifact=ctx.bound.artifacts.find(a=>a.key===spec.artifact),review=artifact?.instructionReviews?.find(r=>r.observationId===spec.observationId);
 if(!artifact||!review)throw new Error('PE task requires the exact selected artifact instruction review.');
 if(review.abi.result.location!=='eax'||review.abi.result.type!=='uint32')throw new Error('PE tasks currently require an EAX uint32 result.');
 const functions=await loadPeUiFunctions(artifact.workspace,[spec.observationId],access.signal,access.authorizePath,artifact.file),fn=functions[0]!,metadata=await readPeLoader(fn.target.path,{signal:access.signal});
 if(fn.target.bytes>16*1048576||metadata.sizeOfImage<4096||metadata.sizeOfImage>16*1048576||BigInt(metadata.imageBase)%4096n)throw new Error('PE task image/file exceeds its16MiB aligned-image policy.');
 const imageStart=BigInt(metadata.imageBase),imageEnd=imageStart+BigInt(metadata.sizeOfImage);if(imageEnd>1n<<47n)throw new Error('PE task requires a low canonical preferred image address.');
 for(const [start,end] of [[0x71000000n,spec.sequence?0x71500000n:0x71080000n],[0x72000000n,0x72010000n],[0x73000000n,0x73001000n]] as const)if(imageStart<end&&imageEnd>start)throw new Error('PE image overlaps generated harness memory.');
 function coverage(body:typeof fn.detail.body,witnesses:{address:string;length:number}[]){
 for(const range of body.ranges){let next=BigInt(range.start);for(const bytes of witnesses){const start=BigInt(bytes.address),end=start+BigInt(bytes.length);if(start>=BigInt(range.start)&&start<=BigInt(range.end)){if(start!==next||end>BigInt(range.end)+1n)throw new Error('PE task byte coverage has gaps or crosses body ranges.');next=end;}}if(next!==BigInt(range.end)+1n)throw new Error('PE task requires byte witnesses covering every complete function-body range.');}
 }
 coverage(fn.detail.body,review.bytes);
 async function reviewedFunction(id:string){
  const selected=artifact!.instructionReviews?.find(r=>r.observationId===id);
  if(!selected)throw new Error('Initializer/helper requires an exact selected artifact instruction review.');
  const [loaded]=await loadPeUiFunctions(artifact!.workspace,[id],access.signal,access.authorizePath,artifact!.file);
  if(!loaded||loaded.target.sha256!==fn.target.sha256||loaded.target.path!==fn.target.path)throw new Error('Initializer/helper must use the same original PE image.');
  coverage(loaded.detail.body,selected.bytes);
  return {observationId:id,entry:loaded.record.address,body:loaded.detail.body.ranges as {start:string;end:string}[],reviewSha256:digest(JSON.stringify(selected)),abi:selected.abi};
 }
 if(spec.bindings.length!==review.abi.parameters.length||new Set(spec.bindings.map(b=>b.parameter)).size!==spec.bindings.length)throw new Error('Every ABI parameter requires exactly one task binding.');
 const inputs=spec.bindings.filter(b=>b.kind!=='length').map(b=>b.argument).sort((a,b)=>a-b);
 if(inputs.some((index,i)=>index!==i))throw new Error('PE task input indices must be unique and contiguous from0.');
 const bindings=spec.bindings.map(binding=>{
  const parameter=review.abi.parameters.find(p=>p.name===binding.parameter);if(!parameter)throw new Error('Task binding names must match reviewed ABI parameters.');
  if(binding.kind==='uint32'&&parameter.type!=='uint32'||['bytes','uint32-array','output-bytes','inout-bytes'].includes(binding.kind)&&parameter.type!=='pointer'||binding.kind==='length'&&!['uint32','uint64'].includes(parameter.type))throw new Error('Task binding types differ from the reviewed ABI.');
  if(binding.kind==='length'&&!spec.bindings.some(b=>(b.kind==='bytes'||b.kind==='output-bytes'||b.kind==='inout-bytes')&&b.parameter===binding.of))throw new Error('Derived lengths must reference a declared byte buffer.');
  return {...binding,register:parameter.location};
 });
 const initializers=[];const helpers=[];const boundaries=[];
 let memory: {address:string;length:number;access:'read'|'read-write'|'initialize-write';section:string}[]=[];
 if(spec.sequence){
  for(const initial of spec.sequence.initializers){
   const selected=Array.isArray(initial)?await reviewedFunction(spec.observationId):await reviewedFunction(initial.observationId),args=Array.isArray(initial)?initial:initial.args;
   if(selected.abi.parameters.some(p=>p.type!=='uint32')||!(selected.abi.result.location==='eax'&&selected.abi.result.type==='uint32'||selected.abi.result.location==='none'&&selected.abi.result.type==='void'))throw new Error('Initializer ABI requires uint32 scalar parameters and a void or EAX uint32 result.');
   if(args.length!==selected.abi.parameters.length)throw new Error('Initializer argument count must match the reviewed function.');
   initializers.push({...selected,args,inputCount:args.length,bindings:selected.abi.parameters.map((p,i)=>({parameter:p.name,kind:'uint32' as const,argument:i,register:p.location}))});
  }
  if(new Set(spec.sequence.helpers??[]).size!==(spec.sequence.helpers??[]).length)throw new Error('Duplicate helper observations.');
  for(const id of spec.sequence.helpers??[])helpers.push(await reviewedFunction(id));
  if(new Set((spec.sequence.boundaries??[]).map(b=>b.observationId)).size!==(spec.sequence.boundaries??[]).length)throw new Error('Duplicate predicate boundary observations.');
  for(const boundary of spec.sequence.boundaries??[]){
   const selected=await reviewedFunction(boundary.observationId);
   if(selected.abi.parameters.length||selected.abi.result.location!=='eax'||selected.abi.result.type!=='uint32')throw new Error('Predicate boundary requires a reviewed no-argument EAX uint32 ABI.');
   if(selected.observationId===spec.observationId||[...initializers,...helpers].some(f=>f.observationId===selected.observationId))throw new Error('A predicate boundary cannot also be an executable entry or helper.');
   boundaries.push({...selected,...boundary,originalExecution:'not-executed',semantics:'declared-constant-predicate'});
  }
  const selected=[await reviewedFunction(spec.observationId),...initializers,...helpers,...boundaries];
  for(let i=0;i<selected.length;i++)for(let j=0;j<i;j++)if(selected[i]!.observationId!==selected[j]!.observationId&&selected[i]!.body.some(a=>selected[j]!.body.some(b=>BigInt(a.start)<=BigInt(b.end)&&BigInt(b.start)<=BigInt(a.end))))throw new Error('Distinct reviewed function bodies must not overlap.');
  let total=0;
  memory=spec.sequence.memory.map(region=>{
   const start=BigInt(region.address),end=start+BigInt(region.length);
   const section=metadata.sections.find(s=>start>=imageStart+BigInt(s.virtualAddress)&&end<=imageStart+BigInt(s.virtualAddress)+BigInt(s.virtualSize));
   if(!section||!(section.characteristics&0x40000000)||(section.characteristics&0x20000000)||region.access!=='read'&&!(section.characteristics&0x80000000))throw new Error('Declared sequence memory must fit a readable non-executable section with matching write permission.');
   total+=region.length;if(total>65536)throw new Error('Sequence memory exceeds64KiB.');
   return {...region,section:section.name};
  });
  for(let i=0;i<memory.length;i++)for(let j=0;j<i;j++){const a=memory[i]!,b=memory[j]!;if(BigInt(a.address)<BigInt(b.address)+BigInt(b.length)&&BigInt(b.address)<BigInt(a.address)+BigInt(a.length))throw new Error('Sequence memory ranges must not overlap.');}
 }
 return {schema:'carve/pe-abi-task@1',emulator:'Unicorn2.1.4',policy:spec.bindings.some(b=>b.kind==='output-bytes'||b.kind==='inout-bytes')?(spec.sequence?'reviewed-functions-stateful-outputs@1':'single-function-output-buffers@1'):(spec.sequence?'reviewed-functions-stateful-inputs@1':'single-function-readonly-inputs@1'),...(spec.sequence?{memory,initializers,helpers,boundaries}:{}),spec,packageManifestSha256:ctx.pkg.manifestSha256,reviewSha256:digest(JSON.stringify(review)),source:{path:fn.target.path,sha256:fn.target.sha256,metadata},entry:fn.record.address,body:fn.detail.body.ranges,bindings,inputCount:inputs.length,runnerSha256:digest(await readFile(runnerSource)),limitations:(spec.bindings.some(b=>b.kind==='output-bytes'||b.kind==='inout-bytes')?'Writable buffers return {returnValue,outputs}. Pure outputs take capacities, forbid reads before writes and preserve unwritten nulls; inout buffers take caller bytes, permit initial reads and preserve untouched bytes. ':'')+(spec.sequence?'Reviewed AMD64 entry and explicitly selected initializer/helper bodies; ordered initialization runs once per sequence. Initializers accept uint32 scalars and may return void. Caller input buffers are readonly; output and initialized inout buffers are separately declared. All buffers are invocation-local and unmapped after each call. initialize-write regions reject computation writes; declared initialized hashes are checked before compared calls. Helpers are body allowlists, not independently enforced call-edge or ABI proofs. Declared section memory starts from source bytes or PE zero-fill and persists within at most64 calls. No loader, OS behavior or inferred initialization semantics; memory permissions and ABI remain agent declarations. Predicate boundaries replace original bodies with declared0/1 only during initialization; original boundary bodies are not executed. Boundary declarations: '+JSON.stringify(spec.sequence.boundaries??[])+'':'One reviewed AMD64 PE function, register inputs and explicitly declared bounded buffers. No loader, globals, initializer, external calls, rebasing or OS behavior. ABI semantics remain agent declarations; stack reads require prior writes and integer nonvolatile registers are checked.')};
}
export async function preparePeVerification(workspace:string,options:{package:string;spec:string;out:string}&Access){
 const parsed=await json(path.resolve(options.spec),options.authorizePath),spec=peVerificationSpec.parse(parsed.value),ctx=await context(workspace,options.package,options),task=await descriptor(spec,ctx,options);
 const out=path.resolve(options.out),relative=path.relative(ctx.pkg.root,out);if(!relative||!relative.startsWith('..'+path.sep)&&relative!=='..'&&!path.isAbsolute(relative))throw new Error('PE task output must be outside the candidate package.');await options.authorizePath?.(out,true);await mkdir(out,{mode:0o700});
 try{
  if(await realpath(out)!==out)throw new Error('PE task output must not use redirects.');
  const files={task:path.join(out,'task.json'),runner:path.join(out,'runner.py'),reference:path.join(out,'reference.json')};
  for(const file of Object.values(files))await options.authorizePath?.(file,true);
  const data=JSON.stringify(task,null,2)+'\n',taskSha256=digest(data);
  await writeFile(files.task,data,{flag:'wx',mode:0o600});await writeFile(files.runner,await readFile(runnerSource),{flag:'wx',mode:0o600});
  await writeFile(files.reference,JSON.stringify({schema:'carve/pe-reference@1',task:files.task,taskSha256},null,2)+'\n',{flag:'wx',mode:0o600});
  const after=await context(workspace,options.package,options);if(!isDeepStrictEqual(task,await descriptor(spec,after,options)))throw new Error('PE task input changed during preparation.');
  return {schema:'carve/prepared-pe-verification@1',status:'prepared-not-executed',taskSha256,...files,policy:task.policy,verification:'not-run',nextAction:'Use verify-reconstruction with the generated reference, explicit cases and execute authorization.'};
 }catch(error){await rm(out,{recursive:true,force:true});throw error;}
}
export async function loadPeVerification(workspace:string,packagePath:string,reference:z.infer<typeof peReferenceSchema>,access:Access){
 const taskPath=path.resolve(reference.task),parsed=await json(taskPath,access.authorizePath);if(parsed.sha256!==reference.taskSha256)throw new Error('Prepared PE task SHA256 changed.');
 const spec=peVerificationSpec.parse(parsed.value.spec),ctx=await context(workspace,packagePath,access),expected=await descriptor(spec,ctx,access);
 if(!isDeepStrictEqual(parsed.value,expected))throw new Error('Prepared PE task does not match the current package, reviewed ABI or execution policy.');
 const runner=path.join(path.dirname(taskPath),'runner.py');await access.authorizePath?.(runner);
 if(await realpath(runner)!==runner||digest(await regular(runner,65536))!==expected.runnerSha256)throw new Error('Prepared PE runner changed or is redirected.');
 return {schema:spec.sequence?'carve/reference@3' as const:'carve/reference@1' as const,command:[spec.python,runner,taskPath,parsed.sha256],scope:'external-harness' as const,mode:spec.sequence?'json-sequence-stdin' as const:'json-stdin' as const,description:'Generated reviewed PE task '+parsed.sha256+'. '+expected.limitations,boundFiles:[runner,taskPath]};
}
