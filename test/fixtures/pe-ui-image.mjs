// Source-owned PE resources and AFX-like rows; no third-party application bytes.
import {buildPe} from './pe-image.mjs';
class Writer {
 chunks=[];size=0;
 bytes(b){this.chunks.push(b);this.size+=b.length;return this;}
 w(n){const b=Buffer.alloc(2);b.writeUInt16LE(n);return this.bytes(b);}
 d(n){const b=Buffer.alloc(4);b.writeUInt32LE(n);return this.bytes(b);}
 text(s){return this.bytes(Buffer.from(s+'\0','utf16le'));}
 align(){return this.bytes(Buffer.alloc((4-this.size%4)%4));}
 result(){return Buffer.concat(this.chunks);}
}
function menu(label='Open',title='Sessions'){return new Writer().w(0).w(0).w(0x90).text(title).w(0).w(1001).text(label).w(0x80).w(1002).text('New folder').result();}
function menuEx(){return new Writer().w(1).w(4).d(0).align().d(0).d(0).d(2001).w(0x81).text('Tools').align().d(0).align().d(0).d(0).d(1003).w(0x80).text('Inspect \u{1f50e}').result();}
function dialog(extended){
 const w=new Writer();
 if(extended)w.w(1).w(0xffff).d(0).d(0).d(0x40).w(2);else w.d(0x40).d(0).w(2);
 w.w(0).w(0).w(100).w(100).w(0xffff).w(101).w(0).text('Folder manager').w(9);
 if(extended)w.w(400).bytes(Buffer.from([0,1]));w.text('Segoe UI');
 w.align();if(extended)w.d(0).d(0).d(0);else w.d(0).d(0);
 w.w(0).w(0).w(20).w(10);if(extended)w.d(1002);else w.w(1002);
 w.w(0xffff).w(0x80).text('Create');
 if(extended)w.w(1).bytes(Buffer.from([0x42]));else w.w(4).bytes(Buffer.from([0x42,0x43]));
 w.align();if(extended)w.d(0).d(0).d(0);else w.d(0).d(0);
 w.w(0).w(0).w(50).w(80);if(extended)w.d(2000);else w.w(2000);
 w.text('SysTreeView32').text('').w(0);return w.result();
}
export function buildUiPe({plus=false,extended=false,machine,malformedMenu=false,code,imports,delay,menuLabel='Open',menuTitle='Sessions'}={}){
 const base=0x2000,raw=0x1200,resource=Buffer.alloc(0x3000);let cursor=0;
 const alloc=(n,align=4)=>{cursor=Math.ceil(cursor/align)*align;const p=cursor;cursor+=n;if(cursor>resource.length)throw new Error('UI fixture overflow');return p;};
 const strings=new Writer();for(let i=0;i<16;i++){const text=i===9?'Session label':'';strings.w(text.length).bytes(Buffer.from(text,'utf16le'));}
 const resources=[{keys:[4,101,1033],bytes:malformedMenu?Buffer.from([0,0,0,0,0x80,0,1,0,65,0]):menu(menuLabel,menuTitle)},
 {keys:[4,'Named menu',1028],bytes:menuEx()},{keys:[5,201,1033],bytes:dialog(extended)},
 {keys:[6,63,1033],bytes:strings.result()},{keys:[9,301,1033],bytes:new Writer().w(0x89).w(79).w(1001).w(0).result()}];
 const tree=new Map();for(const r of resources){let t=tree;for(const k of r.keys.slice(0,2)){if(!t.has(k))t.set(k,new Map());t=t.get(k);}t.set(r.keys[2],r);}
 const directory=t=>{
  const entries=[...t].sort(([a],[b])=>typeof a===typeof b?String(a).localeCompare(String(b)):typeof a==='string'?-1:1),p=alloc(16+8*t.size);
  resource.writeUInt16LE(entries.filter(([k])=>typeof k==='string').length,p+12);resource.writeUInt16LE(entries.filter(([k])=>typeof k==='number').length,p+14);
  entries.forEach(([k,v],i)=>{
   let name=k;if(typeof k==='string'){const b=Buffer.from(k,'utf16le'),s=alloc(2+b.length,2);resource.writeUInt16LE(b.length/2,s);b.copy(resource,s+2);name=(s+0x80000000)>>>0;}
   let target;if(v instanceof Map)target=(directory(v)+0x80000000)>>>0;else{target=alloc(16);const payload=alloc(v.bytes.length);v.bytes.copy(resource,payload);resource.writeUInt32LE(base+payload,target);resource.writeUInt32LE(v.bytes.length,target+4);v.payloadOffset=raw+payload;}
   resource.writeUInt32LE(name,p+16+i*8);resource.writeUInt32LE(target,p+20+i*8);
  });return p;
 };directory(tree);
 const bytes=buildPe({plus,...(machine===undefined?{}:{machine}),imports:imports??[{name:'helper.dll',entries:['ReadSettings']}],delay,code:code??(()=>Buffer.alloc(0x40,0xc3))});
 const optional=0x40+24,dd=optional+(plus?112:96);bytes.writeUInt32LE(base,dd+16);bytes.writeUInt32LE(cursor,dd+20);resource.subarray(0,cursor).copy(bytes,raw);
 const width=plus?8:4,rowSize=plus?32:24,table=0x5200,imageBase=plus?0x140000000n:0x400000n;
 for(const [i,code] of [0,2].entries()){
  const at=table+i*rowSize;bytes.writeUInt32LE(0x111,at);bytes.writeUInt32LE(code,at+4);bytes.writeUInt32LE(1001,at+8);bytes.writeUInt32LE(1002,at+12);
  if(width===8){bytes.writeBigUInt64LE(58n,at+16);bytes.writeBigUInt64LE(imageBase+0x8010n,at+24);}else{bytes.writeUInt32LE(58,at+16);bytes.writeUInt32LE(Number(imageBase+0x8010n),at+20);}
 }
 return{bytes,resources,raw,directoryOptionalOffset:dd+16,table,rowSize};
}
