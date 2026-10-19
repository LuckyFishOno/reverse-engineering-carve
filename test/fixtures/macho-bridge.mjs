// Header/byte validator fixture only. It is not a compiled executable.
export function machoFixture({library=false,cpu=0x100000c,textOffset=library?0x2d8:0x400,stubOffset=0x598,callOffset=0x4c8,rpaths=['@loader_path/../lib']}={}){
 const bytes=Buffer.alloc(0x900),base=library?0n:0x100000000n,symbol='_carve_duration_charge';
 bytes.writeUInt32LE(0xfeedfacf);bytes.writeUInt32LE(cpu,4);bytes.writeUInt32LE(library?6:2,12);bytes.writeUInt32LE(0x85,24);
 const seg=Buffer.alloc(library?152:232);seg.writeUInt32LE(0x19);seg.writeUInt32LE(seg.length,4);seg.write('__TEXT',8);seg.writeBigUInt64LE(base,24);seg.writeBigUInt64LE(0x1000n,32);seg.writeBigUInt64LE(0n,40);seg.writeBigUInt64LE(BigInt(bytes.length),48);seg.writeUInt32LE(library?1:2,64);
 const section=(at,name,offset,size,flags)=>{seg.write(name,at);seg.write('__TEXT',at+16);seg.writeBigUInt64LE(base+BigInt(offset),at+32);seg.writeBigUInt64LE(BigInt(size),at+40);seg.writeUInt32LE(offset,at+48);seg.writeUInt32LE(flags,at+64);};
 section(72,'__text',textOffset,library?0x80:0x100,0x80000400);if(!library){section(152,'__stubs',stubOffset,12,0x80000408);seg.writeUInt32LE(12,152+72);}
 const strCommand=(kind,text,minimum)=>{const b=Buffer.alloc(Math.ceil((minimum+Buffer.byteLength(text)+1)/8)*8);b.writeUInt32LE(kind);b.writeUInt32LE(b.length,4);b.writeUInt32LE(minimum,8);b.write(text,minimum);return b;};
 const syms=Buffer.alloc(24);syms.writeUInt32LE(2);syms.writeUInt32LE(24,4);syms.writeUInt32LE(0x800,8);syms.writeUInt32LE(1,12);syms.writeUInt32LE(0x850,16);syms.writeUInt32LE(64,20);
 const dynamic=Buffer.alloc(80);dynamic.writeUInt32LE(0xb);dynamic.writeUInt32LE(80,4);dynamic.writeUInt32LE(0x840,56);dynamic.writeUInt32LE(1,60);
 const commands=[seg,strCommand(library?0xd:0xc,'@rpath/libcharge.dylib',24),...(!library?rpaths.map(p=>strCommand(0x8000001c,p,12)):[]),syms,...(!library?[dynamic]:[])];
 let offset=32,symsOffset,dynamicOffset;for(const cmd of commands){if(cmd===syms)symsOffset=offset;if(cmd===dynamic)dynamicOffset=offset;cmd.copy(bytes,offset);offset+=cmd.length;}
 bytes.writeUInt32LE(commands.length,16);bytes.writeUInt32LE(offset-32,20);bytes.writeUInt32LE(1,0x800);bytes[0x804]=library?15:1;bytes[0x805]=library?1:0;bytes.writeUInt16LE(library?0:0x100,0x806);bytes.writeBigUInt64LE(library?BigInt(textOffset):0n,0x808);bytes.write(symbol,0x851);
 if(!library){const delta=stubOffset-callOffset;if(cpu===0x100000c)bytes.writeUInt32LE(0x94000000+((delta/4)&0x3ffffff),callOffset);else{bytes[callOffset]=0xe8;bytes.writeInt32LE(delta-5,callOffset+1);}}
 return{bytes,base,stub:'0x'+(base+BigInt(stubOffset)).toString(16),call:'0x'+(base+BigInt(callOffset)).toString(16),export:'0x'+BigInt(textOffset).toString(16),symbol,layout:{symCommand:symsOffset,dynamicCommand:dynamicOffset,nlist:0x800,strings:0x850,indirect:0x840,call:callOffset,stub:stubOffset,textSection:32+72,stubSection:32+152}};
}
