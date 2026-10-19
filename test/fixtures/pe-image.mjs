// Synthetic PE images for parser tests. All tables live in one ".data" section at RVA 0x1000; an
// optional executable ".text" section at RVA 0x8000 holds code produced by `code(info)`, which can
// ask for the RVA of any import address table slot. These are fixtures, not real Windows programs.
export function buildPe({plus=true,machine=plus?0x8664:0x14c,dll=false,imports=[],delay=[],legacyDelay=null,exports=null,clr=false,boundFirst=false,characteristics,magic,sections,code=null}={}){
 const sectionRva=0x1000,rawOffset=0x200,data=Buffer.alloc(0x6000),textRva=0x8000;let cursor=0;
 const alloc=(n,align=8)=>{cursor=Math.ceil(cursor/align)*align;const at=cursor;cursor+=n;if(cursor>data.length)throw new Error('fixture too large');return at;};
 const rva=at=>sectionRva+at,imageBase=plus?0x140000000n:0x400000n,width=plus?8:4,flag=plus?1n<<63n:1n<<31n,slots=new Map();
 const str=s=>{const b=Buffer.from(s+'\0');const at=alloc(b.length,2);b.copy(data,at);return rva(at);};
 const thunks=(entries,module)=>{const at=alloc((entries.length+1)*width);entries.forEach((e,i)=>{let v;
  if(typeof e==='string'){const h=alloc(2+Buffer.byteLength(e)+1,2);data.writeUInt16LE(100+i,h);Buffer.from(e+'\0').copy(data,h+2);v=BigInt(rva(h));}else v=flag|BigInt(e.ordinal);
  plus?data.writeBigUInt64LE(v,at+i*width):data.writeUInt32LE(Number(v),at+i*width);
  if(module)slots.set(`${module}!${typeof e==='string'?e:'#'+e.ordinal}`,rva(at)+i*width);});return rva(at);};
 const dirs=Array.from({length:16},()=>[0,0]);
 if(imports.length){const d=alloc((imports.length+1)*20,4);imports.forEach((m,i)=>{const p=d+i*20,name=str(m.name),lookup=thunks(m.entries),address=thunks(m.entries,m.name);
  data.writeUInt32LE(boundFirst&&i===0?0:lookup,p);data.writeUInt32LE(boundFirst&&i===0?0x5f5e0ff:0,p+4);data.writeUInt32LE(name,p+12);data.writeUInt32LE(address,p+16);});dirs[1]=[rva(d),(imports.length+1)*20];}
 if(delay.length||legacyDelay){const all=[...delay,...(legacyDelay?[legacyDelay]:[])],d=alloc((all.length+1)*32,4);all.forEach((m,i)=>{const p=d+i*32,legacy=m===legacyDelay,shift=legacy&&!plus?Number(imageBase):0;
  data.writeUInt32LE(legacy?0:1,p);data.writeUInt32LE(str(m.name)+shift,p+4);data.writeUInt32LE(rva(alloc(width))+shift,p+8);data.writeUInt32LE(thunks(m.entries,legacy?null:m.name)+shift,p+12);data.writeUInt32LE(thunks(m.entries)+shift,p+16);});dirs[13]=[rva(d),(all.length+1)*32];}
 if(exports){const start=alloc(40,4),fns=exports.functions,names=fns.flatMap((f,i)=>(f.names??[]).map(n=>[n,i])).sort((a,b)=>a[0]<b[0]?-1:1);
  const table=alloc(fns.length*4,4),pointers=alloc(names.length*4,4),ordinals=alloc(names.length*2,2),moduleName=str(exports.name);
  fns.forEach((f,i)=>data.writeUInt32LE(f.forwarder?str(f.forwarder):f.rva??0,table+i*4));
  names.forEach(([n,i],j)=>{data.writeUInt32LE(str(n),pointers+j*4);data.writeUInt16LE(exports.ordinalIndex?.[n]??i,ordinals+j*2);});
  const end=cursor;data.writeUInt32LE(moduleName,start+12);data.writeUInt32LE(exports.base,start+16);data.writeUInt32LE(exports.count??fns.length,start+20);data.writeUInt32LE(names.length,start+24);
  data.writeUInt32LE(rva(table),start+28);data.writeUInt32LE(rva(pointers),start+32);data.writeUInt32LE(rva(ordinals),start+36);dirs[0]=[rva(start),end-start];}
 if(clr)dirs[14]=[rva(alloc(72,4)),72];
 const slot=key=>{const value=slots.get(key);if(value===undefined)throw new Error('fixture has no slot '+key);return value;};
 const text=code?code({slot,textRva,imageBase}):null,count=sections??(text?2:1);
 const optional=plus?240:224,pe=0x40,textRaw=rawOffset+data.length,out=Buffer.alloc(textRaw+(text?Math.ceil(text.length/0x200)*0x200:0));
 out.write('MZ',0,'latin1');out.writeUInt32LE(pe,60);out.writeUInt32LE(0x4550,pe);
 out.writeUInt16LE(machine,pe+4);out.writeUInt16LE(count,pe+6);out.writeUInt32LE(0x12345678,pe+8);out.writeUInt16LE(optional,pe+20);out.writeUInt16LE(characteristics??(0x0002|(dll?0x2000:0)|(plus?0x20:0x100)),pe+22);
 const o=pe+24;out.writeUInt16LE(magic??(plus?0x20b:0x10b),o);out.writeUInt32LE(text?textRva:0x1010,o+16);plus?out.writeBigUInt64LE(imageBase,o+24):out.writeUInt32LE(Number(imageBase),o+28);
 out.writeUInt32LE(0x1000,o+32);out.writeUInt32LE(0x200,o+36);out.writeUInt32LE(0x10000,o+56);out.writeUInt32LE(0x200,o+60);out.writeUInt16LE(3,o+68);
 const dd=plus?112:96;out.writeUInt32LE(16,o+dd-4);dirs.forEach(([r,s],i)=>{out.writeUInt32LE(r,o+dd+i*8);out.writeUInt32LE(s,o+dd+i*8+4);});
 const st=o+optional;out.write('.data',st,'latin1');out.writeUInt32LE(data.length,st+8);out.writeUInt32LE(sectionRva,st+12);out.writeUInt32LE(data.length,st+16);out.writeUInt32LE(rawOffset,st+20);out.writeUInt32LE(0xc0000040,st+36);
 if(text&&count>=2){const t=st+40;out.write('.text',t,'latin1');out.writeUInt32LE(text.length,t+8);out.writeUInt32LE(textRva,t+12);out.writeUInt32LE(out.length-textRaw,t+16);out.writeUInt32LE(textRaw,t+20);out.writeUInt32LE(0x60000020,t+36);text.copy(out,textRaw);}
 data.copy(out,rawOffset);return out;
}
