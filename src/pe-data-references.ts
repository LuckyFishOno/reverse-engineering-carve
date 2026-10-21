import {open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import type {PeMetadata} from './pe-loader.js';

const address=(v:unknown):v is string=>typeof v==='string'&&/^0x[0-9a-f]{1,16}$/.test(v);
export const PE_DATA_PREVIEW_BYTES=64;

// Bounded initial file bytes, not inferred variable sizes or observed runtime memory.
export async function inspectPeDataReference(file:string,metadata:PeMetadata,reference:Record<string,any>,body:{ranges:{start:string;end:string}[]},knownWrite=false,signal?:AbortSignal){
 signal?.throwIfAborted();
 const kind=reference.kind,source=reference.address,target=reference.targetAddress;
 const row:Record<string,any>={kind:'data-reference',sourceAddress:source,targetAddress:target,access:kind.read&&kind.write?'read-write':kind.write?'write':kind.read?'read':'address-only',referenceType:kind.type,referenceBasis:'imported-typed-reference',instructionSemantics:'not-decoded',state:'unknown',status:'unresolved',sourceSection:null,section:null,bytes:null,runtimeValue:'unverified',dependencyClosure:'not-established'};
 if(!address(source)||!body.ranges.some(r=>address(r.start)&&address(r.end)&&BigInt(source)>=BigInt(r.start)&&BigInt(source)<=BigInt(r.end))){row.status='source-outside-function-body';return row;}
 const sourceRva=BigInt(source)-BigInt(metadata.imageBase),sources=metadata.sections.filter(s=>sourceRva>=BigInt(s.virtualAddress)&&sourceRva<BigInt(s.virtualAddress+Math.max(s.virtualSize,s.rawSize)));
 if(sources.length!==1||sourceRva<0n||sourceRva>=BigInt(metadata.sizeOfImage)||sourceRva<BigInt(metadata.sizeOfHeaders)){row.status='source-section-unresolved';return row;}
 row.sourceSection={index:sources[0]!.index,name:sources[0]!.name,executable:Boolean(sources[0]!.characteristics&0x20000000)};
 if(!address(target)){row.status='non-image-target';return row;}
 const rvaBig=BigInt(target)-BigInt(metadata.imageBase);if(rvaBig<0n||rvaBig>0xffffffffn){row.status='target-outside-image';return row;}
 const rva=Number(rvaBig);row.targetRva=rva;
 row.targetDirectories=metadata.dataDirectories.filter(d=>rva>=d.rva&&rva<d.rva+d.size&&d.index!==4).map(d=>({index:d.index,name:d.name}));
 if(rva>=metadata.sizeOfImage){row.status='target-outside-image';return row;}
 const sections=metadata.sections.filter(s=>rva>=s.virtualAddress&&rva<s.virtualAddress+Math.max(s.virtualSize,s.rawSize));
 if(sections.length>1||(sections.length&&rva<metadata.sizeOfHeaders)){row.status='ambiguous-section-mapping';return row;}
 if(!sections.length){row.status=rva<metadata.sizeOfHeaders?'image-header-target':'unmapped-target';return row;}
 const s=sections[0]!,delta=rva-s.virtualAddress;
 const writable=Boolean(s.characteristics&0x80000000),executable=Boolean(s.characteristics&0x20000000),readable=Boolean(s.characteristics&0x40000000);
 row.section={index:s.index,name:s.name,virtualAddress:s.virtualAddress,virtualSize:s.virtualSize,rawOffset:s.rawOffset,rawSize:s.rawSize,readable,writable,executable};
 row.state=knownWrite||kind.write||writable?'mutable-state-candidate':readable&&!executable?'read-only-data-candidate':'unknown';
 row.knownSelectedWrite=knownWrite||kind.write;
 if(delta>=s.rawSize){row.status='virtual-only-target';return row;}
 const handle=await open(file,'r');
 try{
  const stat=await handle.stat(),offset=s.rawOffset+delta,length=Math.min(PE_DATA_PREVIEW_BYTES,s.rawSize-delta,stat.size-offset,metadata.sizeOfImage-rva);
  if(length<=0){row.status='file-data-unavailable';return row;}
  if(metadata.sections.some(other=>other.index!==s.index&&other.virtualAddress<rva+length&&other.virtualAddress+Math.max(other.virtualSize,other.rawSize)>rva)){row.status='ambiguous-section-mapping';return row;}
  const bytes=Buffer.alloc(length);let got=0;while(got<length){signal?.throwIfAborted();const part=await handle.read(bytes,got,length-got,offset+got);if(!part.bytesRead)throw new Error('PE data source was truncated during inspection.');got+=part.bytesRead;}
  row.status='file-bytes-captured';row.bytes={fileOffset:offset,length,hex:bytes.toString('hex'),sha256:createHash('sha256').update(bytes).digest('hex'),scope:'bounded-initial-file-prefix',objectExtent:'unknown',maxBytes:PE_DATA_PREVIEW_BYTES};
  // Encodings are conservative printable ASCII/UTF-16LE candidates with observed terminators.
  const candidates:Record<string,any>[]=[];
  if(readable&&!executable){
   const end=bytes.indexOf(0);if(end>=4&&bytes.subarray(0,end).every(b=>b>=32&&b<=126))candidates.push({encoding:'ascii',text:bytes.toString('ascii',0,end),byteLength:end+1,terminated:true});
   let n=0;while(n+1<bytes.length&&bytes[n]!>=32&&bytes[n]!<=126&&bytes[n+1]===0)n+=2;
   if(n>=8&&n+1<bytes.length&&bytes[n]===0&&bytes[n+1]===0)candidates.push({encoding:'utf-16le',text:bytes.toString('utf16le',0,n),byteLength:n+2,terminated:true});
  }
  row.stringCandidates=candidates;
  row.scalarPreview=readable&&!executable&&bytes.length>=4?{encoding:'uint32-le',value:bytes.readUInt32LE(0),interpretation:'initial-byte-interpretation-only',declaredType:'unknown'}:null;
  return row;
 }finally{await handle.close();}
}
