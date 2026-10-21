import {open} from 'node:fs/promises';
import type {PeMetadata} from './pe-loader.js';
import type {PeCallSite,PeSlot} from './pe-calls.js';
import type {UiNode} from './pe-ui.js';
import {decodeResourceArgumentPrefix32} from './pe-resource-api-x86.js';

export const PE_RESOURCE_API_LIMITS={prefixBytes:256,instructions:64,stackWords:64,matches:8} as const;
export function resourceApiKind(slot:PeSlot){
 const name=slot.name??'',module=slot.module.toLowerCase();
 if(module==='user32.dll'){
  if(/^LoadString[AW]$/.test(name))return 'string';
  if(/^LoadMenu[AW]$/.test(name))return 'menu';
  if(/^LoadAccelerators[AW]$/.test(name))return 'accelerator';
 }
 if(['kernel32.dll','kernelbase.dll'].includes(module)){
  if(/^FindResourceEx[AW]$/.test(name))return 'find-ex';
  if(/^FindResource[AW]$/.test(name))return 'find';
 }
 return null;
}

// A whitelist decoder from the exact recorded entry, never a backward byte-pattern search.
export function decodeResourceArgumentPrefix(code:Buffer){
 const regs:(bigint|null)[]=Array(16).fill(null),instructions:{offset:number;bytes:string;operation:string}[]=[];let p=0;
 const stop=(reason:string)=>({complete:false,reason,offset:p,instructions,arguments:null});
 while(p<code.length){
  if(instructions.length>=PE_RESOURCE_API_LIMITS.instructions)return stop('instruction-limit');
  const start=p;let rex=0;if(code[p]!>=0x40&&code[p]!<=0x4f)rex=code[p++]!;
  const op=code[p++],wide=Boolean(rex&8),r=rex&4?8:0,b=rex&1?8:0;
  const finish=(operation:string)=>instructions.push({offset:start,bytes:code.subarray(start,p).toString('hex'),operation});
  if(op===0x90&&!rex){finish('nop');continue;}
  if(op!==undefined&&op>=0xb8&&op<=0xbf){
   const n=wide?8:4,dst=op-0xb8+b;if(dst===4||p+n>code.length)return stop('unsupported-or-truncated-move');
   regs[dst]=wide?code.readBigUInt64LE(p):BigInt(code.readUInt32LE(p));p+=n;finish('mov-immediate');continue;
  }
  if((op===0x83||op===0x81)&&rex===0x48&&(code[p]===0xec||code[p]===0xc4)){
   const n=op===0x83?1:4;if(p+1+n>code.length)return stop('truncated-stack-adjustment');p+=1+n;regs[4]=null;finish('stack-adjustment');continue;
  }
  if(op===0x31||op===0x33||op===0x89||op===0x8b){
   if(p>=code.length)return stop('truncated-register-instruction');const modrm=code[p++]!,reg=((modrm>>3)&7)+r,rm=(modrm&7)+b;
   if((modrm>>6)!==3)return stop('memory-operation-not-supported');
   const dst=op===0x33||op===0x8b?reg:rm,src=op===0x33||op===0x8b?rm:reg;
   if(dst===4)return stop('stack-register-write-not-supported');
   if(op===0x31||op===0x33){if(dst!==src)return stop('nonzero-xor-not-supported');regs[dst]=0n;finish('xor-self');}
   else{const value=regs[src];regs[dst]=value===null||value===undefined?null:wide?value:value&0xffffffffn;finish('mov-register');}continue;
  }
  if(op===0x8d&&wide&&!(rex&3)&&p<code.length){
   const modrm=code[p++]!,mod=modrm>>6,dst=((modrm>>3)&7)+r,n=mod===1?1:mod===2?4:0;
   if(dst===4||!n||(modrm&7)!==4||code[p++]!==0x24||p+n>code.length)return stop('address-expression-not-supported');
   p+=n;regs[dst]=null;finish('stack-address');continue;
  }
  return stop('unsupported-instruction-or-control-flow');
 }
 const hex=(v:bigint|null|undefined)=>v===null||v===undefined?null:'0x'+v.toString(16);
 return {complete:true,reason:null,offset:p,instructions,arguments:{rcx:hex(regs[1]),rdx:hex(regs[2]),r8:hex(regs[8]),r9:hex(regs[9])}};
}

export async function inspectPeResourceApi(file:string,m:PeMetadata,fn:Record<string,any>,site:PeCallSite,resources:UiNode[],signal?:AbortSignal){
 const kind=resourceApiKind(site.slot);if(!kind)return null;
 const result:Record<string,any>={api:site.slot.name,module:site.slot.module,apiIdentity:'import-name-declaration',architecture:m.machineName,status:'arguments-unresolved',moduleBinding:'unverified',languageSelection:'unverified',runtimeUse:'unverified',scope:'Caller-image candidates only; no module/Windows loader binding.',candidates:[],candidatesTotal:0,candidatesTruncated:false};
 if(m.machine!==0x8664&&m.machine!==0x14c){result.reason='unsupported-architecture';return result;}
 result.callingConvention=m.machine===0x14c?'x86-stack-arguments':'windows-x64-registers';
 const start=BigInt(fn.address)-BigInt(m.imageBase),end=BigInt(site.instructionEndRva),call=BigInt(site.instructionRva);
 if(start<0n||end>BigInt(m.sizeOfImage)||call<start||call-start>BigInt(PE_RESOURCE_API_LIMITS.prefixBytes)){result.reason='entry-prefix-outside-budget';return result;}
 if(!fn.body.ranges.some((range:any)=>BigInt(range.start)<=BigInt(fn.address)&&BigInt(range.end)>=BigInt(m.imageBase)+end-1n)){result.reason='prefix-outside-recorded-body';return result;}
 const sections=m.sections.filter(s=>start<BigInt(s.virtualAddress+Math.max(s.virtualSize,s.rawSize))&&end>BigInt(s.virtualAddress));
 const section=sections[0];if(sections.length!==1||!section||!(section.characteristics&0x20000000)||start<BigInt(section.virtualAddress)||end>BigInt(section.virtualAddress+section.rawSize)||start<BigInt(m.sizeOfHeaders)){result.reason='prefix-section-unresolved';return result;}
 const handle=await open(file,'r');
 try{
  signal?.throwIfAborted();const offset=section.rawOffset+Number(start)-section.virtualAddress,length=Number(call-start),stat=await handle.stat();if(offset+length>stat.size)throw new Error('Resource argument prefix is not file-backed.');
  const code=Buffer.alloc(length);let got=0;while(got<length){signal?.throwIfAborted();const read=await handle.read(code,got,length-got,offset+got);if(!read.bytesRead)throw new Error('Resource argument source truncated during inspection.');got+=read.bytesRead;}
  const decoded=m.machine===0x14c?decodeResourceArgumentPrefix32(code,PE_RESOURCE_API_LIMITS):decodeResourceArgumentPrefix(code);result.prefix={entryAddress:fn.address,fileOffset:offset,bytes:code.toString('hex'),...decoded};
  if(!decoded.complete){result.reason=decoded.reason;return result;}
  const args=decoded.arguments! as Record<string,string|null>,small=(v:string|null)=>v!==null&&BigInt(v)<=65535n?Number(BigInt(v)):null;
  const values=m.machine===0x14c?[args.stack0!,args.stack1!,args.stack2!,args.stack3!]:[args.rcx!,args.rdx!,args.r8!,args.r9!];
  const id=small(values[kind==='find-ex'?2:1]!),type=kind==='string'?6:kind==='menu'?4:kind==='accelerator'?9:small(values[kind==='find-ex'?1:2]!);
  result.arguments=args;result.requestedLanguage=kind==='find-ex'?small(values[3]!):null;
  if(id===null||type===null){result.reason='numeric-id-or-type-not-proven';return result;}
  const name=kind==='string'?Math.floor(id/16)+1:id;result.resourceRequest={type,name,...(kind==='string'?{stringId:id,stringIndex:id%16}:{})};
  const matches=resources.filter(r=>r.resource?.[0]===type&&r.resource?.[1]===name);result.candidatesTotal=matches.length;result.candidatesTruncated=matches.length>PE_RESOURCE_API_LIMITS.matches;
  result.candidates=matches.slice(0,PE_RESOURCE_API_LIMITS.matches).map(r=>({resourceId:r.id,resource:r.resource,payloadSha256:r.payloadSha256,payloadRva:r.rva,payloadBytes:r.bytes,requestedLanguageMatches:result.requestedLanguage===null?null:r.resource?.[2]===result.requestedLanguage}));
  result.status=matches.length?'caller-image-candidates':'no-caller-image-match';return result;
 }finally{await handle.close();}
}
