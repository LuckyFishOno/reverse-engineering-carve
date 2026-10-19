import {open} from 'node:fs/promises';
import {constants} from 'node:fs';
import {digest} from './artifact.js';

const BUDGET=8*1024*1024,MAX_SYMBOLS=500000;
const hex=(n:bigint)=>'0x'+n.toString(16);
type Section={index:number;name:string;segment:string;address:bigint;size:bigint;offset:number;flags:number;indirectStart:number;stubBytes:number};

/** Selected nlist/indirect-symbol evidence only; no bind-opcode or dyld emulation. */
export async function readMachOSymbol(file:string,query:{stub:string;callSites?:string[]}|{export:string}){
 const result=await inspectMachO(file,query);if(result.kind==='direct-branch')throw new Error('Unexpected branch query.');return result;
}
/** Original ARM64 B-immediate only; no fallthrough, ABI or semantic claim. */
export async function readMachOBranch(file:string,source:string,target:string){
 const result=await inspectMachO(file,{branch:source,target});if(result.kind!=='direct-branch')throw new Error('Expected a direct branch.');return{...result,schema:'carve/mach-o-branch@1'};
}
async function inspectMachO(file:string,query:{stub:string;callSites?:string[]}|{export:string}|{branch:string;target:string}){
 const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const before=await handle.stat();if(!before.isFile()||!Number.isSafeInteger(before.size))throw new Error('Choose a regular safely addressable Mach-O file.');
  const read=async(offset:number,size:number)=>{if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(size)||offset<0||size<0||size>BUDGET||offset>before.size-size)throw new Error('Mach-O symbol range exceeds the file or8MiB table budget.');const bytes=Buffer.alloc(size);let got=0;while(got<size){const r=await handle.read(bytes,got,size-got,offset+got);if(!r.bytesRead)throw new Error('Truncated Mach-O symbol metadata.');got+=r.bytesRead;}return bytes;};
  const header=await read(0,32);if(header.readUInt32LE(0)!==0xfeedfacf)throw new Error('Static REA bridge requires a thin little-endian64-bit Mach-O.');
  const cpu=header.readUInt32LE(4),subtype=header.readUInt32LE(8),fileType=header.readUInt32LE(12),count=header.readUInt32LE(16),size=header.readUInt32LE(20),flags=header.readUInt32LE(24);
  if(![0x100000c,0x1000007].includes(cpu)||count>4096||count*8>size)throw new Error('Unsupported Mach-O CPU or command budget.');
  const commands=await read(32,size),sections:Section[]=[];let p=0,sym:{offset:number;count:number;strings:number;stringBytes:number}|undefined,indirect:{offset:number;count:number}|undefined;
  const name=(b:Buffer,start:number)=>new TextDecoder('utf-8',{fatal:true}).decode(b.subarray(start,start+16).subarray(0,b.subarray(start,start+16).indexOf(0)<0?16:b.subarray(start,start+16).indexOf(0)));
  for(let i=0;i<count;i++){
   if(p>commands.length-8)throw new Error('Truncated Mach-O load command.');const kind=commands.readUInt32LE(p),bytes=commands.readUInt32LE(p+4);if(bytes<8||bytes%8||bytes>commands.length-p)throw new Error('Invalid Mach-O load-command extent.');
   if(kind===2){if(bytes!==24||sym)throw new Error('Missing/duplicate Mach-O symbol-table identity.');sym={offset:commands.readUInt32LE(p+8),count:commands.readUInt32LE(p+12),strings:commands.readUInt32LE(p+16),stringBytes:commands.readUInt32LE(p+20)};}
   if(kind===0xb){if(bytes!==80||indirect)throw new Error('Invalid/duplicate Mach-O dynamic symbol table.');indirect={offset:commands.readUInt32LE(p+56),count:commands.readUInt32LE(p+60)};}
   if(kind===0x19){
    if(bytes<72)throw new Error('Truncated Mach-O segment.');const n=commands.readUInt32LE(p+64);if(n>255||72+n*80!==bytes||sections.length+n>255)throw new Error('Mach-O section count exceeds the symbol ordinal budget.');
    const vm=commands.readBigUInt64LE(p+24),vmBytes=commands.readBigUInt64LE(p+32),fileOffset=commands.readBigUInt64LE(p+40),fileBytes=commands.readBigUInt64LE(p+48);
    for(let j=0;j<n;j++){const at=p+72+j*80,s={index:sections.length+1,name:name(commands,at),segment:name(commands,at+16),address:commands.readBigUInt64LE(at+32),size:commands.readBigUInt64LE(at+40),offset:commands.readUInt32LE(at+48),flags:commands.readUInt32LE(at+64),indirectStart:commands.readUInt32LE(at+68),stubBytes:commands.readUInt32LE(at+72)};
     if(s.flags&0x80000400||(s.flags&255)===8){if(fileOffset+fileBytes>BigInt(before.size)||s.address<vm||s.address+s.size>vm+vmBytes||BigInt(s.offset)<fileOffset||BigInt(s.offset)+s.size>fileOffset+fileBytes||s.address-vm!==BigInt(s.offset)-fileOffset)throw new Error('Executable section contradicts its file-backed segment mapping.');}
     sections.push(s);}
   }
   p+=bytes;
  }
  if(p!==commands.length||!sym||sym.count>MAX_SYMBOLS||sym.stringBytes<1)throw new Error('Mach-O symbols are missing or exceed the supported budget.');
  const symbols=await read(sym.offset,sym.count*16),strings=await read(sym.strings,sym.stringBytes);
  const symbol=(index:number)=>{if(index<0||index>=sym!.count)throw new Error('Indirect Mach-O symbol ordinal lies outside nlist.');const at=index*16,str=symbols.readUInt32LE(at);if(str>=strings.length)throw new Error('Mach-O symbol name lies outside its string table.');const end=strings.indexOf(0,str);if(end<0||end-str>4096)throw new Error('Mach-O symbol name is unterminated or exceeds4096bytes.');const text=new TextDecoder('utf-8',{fatal:true}).decode(strings.subarray(str,end));return{index,name:text,type:symbols[at+4]!,section:symbols[at+5]!,description:symbols.readUInt16LE(at+6),value:hex(symbols.readBigUInt64LE(at+8)),nlistFileOffset:sym!.offset+at,nameFileOffset:sym!.strings+str};};
  let result;
  if('branch' in query){
   if(cpu!==0x100000c||!/^0x[0-9a-f]{1,16}$/.test(query.branch)||!/^0x[0-9a-f]{1,16}$/.test(query.target))throw new Error('Boundary diagnostics require default-space ARM64 Mach-O B-immediate addresses.');
   const source=BigInt(query.branch),target=BigInt(query.target),code=(address:bigint,width:bigint)=>sections.filter(s=>(s.flags&255)===0&&Boolean(s.flags&0x80000400)&&address>=s.address&&address+width<=s.address+s.size);
   const from=code(source,4n),to=code(target,4n);if(source%4n||target%4n||from.length!==1||to.length!==1)throw new Error('Boundary branch endpoints require unique aligned file-backed instruction sections.');
   const fileOffset=from[0]!.offset+Number(source-from[0]!.address),bytes=await read(fileOffset,4),word=bytes.readUInt32LE(0);
   if(word>>>26!==5)throw new Error('Boundary diagnostic requires an original ARM64 B-immediate, not BL/conditional/computed flow.');
   const immediate=word&0x3ffffff,decoded=source+BigInt(immediate>=0x2000000?immediate-0x4000000:immediate)*4n;
   if(decoded!==target)throw new Error('Original ARM64 boundary branch destination differs from the diagnostic/reference.');
   result={kind:'direct-branch' as const,address:hex(source),target:hex(target),fileOffset,bytes:4,sha256:digest(bytes),encoding:'aarch64-b-immediate' as const,fallthrough:false as const};
  }else if('stub' in query){
   if(!/^0x[0-9a-f]{1,16}$/.test(query.stub))throw new Error('Choose a returned default-space stub address.');const address=BigInt(query.stub),matches=sections.filter(s=>(s.flags&255)===8&&address>=s.address&&address<s.address+s.size);if(matches.length!==1||!indirect)throw new Error('Selected REA thunk is not a unique symbol stub with an indirect table.');const s=matches[0]!;
   if(s.stubBytes<1||s.stubBytes>1024||s.size%BigInt(s.stubBytes)||(address-s.address)%BigInt(s.stubBytes))throw new Error('REA thunk must identify an exact complete symbol stub.');
   const index=s.indirectStart+Number((address-s.address)/BigInt(s.stubBytes));if(!Number.isSafeInteger(index)||index>=indirect.count||indirect.count>1000000)throw new Error('Stub indirect-symbol range exceeds the table.');const entry=await read(indirect.offset+index*4,4),n=entry.readUInt32LE(0);if(n&0xc0000000)throw new Error('Local/absolute indirect entries do not identify a library import.');const imported=symbol(n);
   if(imported.type!==1||imported.section!==0||imported.value!=='0x0'||(imported.description&0xc0))throw new Error('Bridge requires a strong undefined external nlist symbol.');const ordinal=imported.description>>>8;if(ordinal===0||ordinal>=254)throw new Error('Flat/self/dynamic/special library ordinals are unsupported.');
   const fileOffset=s.offset+Number(address-s.address),stub=await read(fileOffset,s.stubBytes);
   const callSites=[];if((query.callSites?.length??0)>20)throw new Error('Use at most20selected direct call sites.');
   for(const value of query.callSites??[]){
    if(!/^0x[0-9a-f]{1,16}$/.test(value))throw new Error('Choose a default-space direct call site.');const source=BigInt(value),width=cpu===0x100000c?4:5,matching=sections.filter(s=>(s.flags&255)===0&&Boolean(s.flags&0x80000400)&&source>=s.address&&source+BigInt(width)<=s.address+s.size);if(matching.length!==1)throw new Error('Call site must be in one file-backed instruction section.');const section=matching[0]!,at=section.offset+Number(source-section.address),instruction=await read(at,width);let target:bigint;
    if(cpu===0x100000c){const word=instruction.readUInt32LE(0);if((word>>>26)!==0x25||source%4n)throw new Error('Only direct AArch64 BL-immediate call sites are supported.');const immediate=word&0x3ffffff;target=source+BigInt(immediate>=0x2000000?immediate-0x4000000:immediate)*4n;}else{if(instruction[0]!==0xe8)throw new Error('Only direct x86_64 E8-rel32 call sites are supported.');target=source+5n+BigInt(instruction.readInt32LE(1));}
    if(target!==address)throw new Error('Decoded original call instruction does not target the selected import stub.');callSites.push({address:hex(source),fileOffset:at,bytes:width,sha256:digest(instruction),target:hex(target),encoding:cpu===0x100000c?'aarch64-bl-immediate':'x86_64-e8-rel32'});
   }
   result={kind:'import-stub' as const,symbol:imported,libraryOrdinal:ordinal,callSites,stub:{address:hex(address),fileOffset,bytes:s.stubBytes,sha256:digest(stub),section:s.name,segment:s.segment,indirectIndex:index,indirectFileOffset:indirect.offset+index*4}};
  }else{
   if(!query.export||Buffer.byteLength(query.export)>4096)throw new Error('Choose a nonempty symbol name within4096bytes.');const found=[];
   for(let i=0;i<sym.count;i++){const at=i*16,type=symbols[at+4]!;if((type&0xe0)||(type&0x0f)!==0x0f||(type&0x10))continue;const candidate=symbol(i);if(candidate.name===query.export)found.push(candidate);if(found.length>1)break;}
   if(found.length!==1)throw new Error('Target needs one exact defined external nlist symbol.');const exported=found[0]!,s=sections.find(s=>s.index===exported.section),value=BigInt(exported.value);
   if(!s||(exported.description&0xc0)||!(s.flags&0x80000400)||value<s.address||value>=s.address+s.size)throw new Error('Target export is weak, non-code or outside its executable section.');
   const fileOffset=s.offset+Number(value-s.address);await read(fileOffset,1);result={kind:'defined-export' as const,symbol:exported,location:{address:exported.value,fileOffset,section:s.name,segment:s.segment}};
  }
  const after=await handle.stat();if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.ino!==after.ino)throw new Error('Mach-O changed during selected symbol inspection.');
  return{schema:'carve/mach-o-symbol@1',cpu,subtype,fileType,flags,...result};
 }finally{await handle.close();}
}
