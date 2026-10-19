// Source-owned byte fixture, independent of the production parser.
export const android='http://schemas.android.com/apk/res/android';
export const attr=(name,value,options={})=>({name,value,namespace:android,...options});
export function binaryXml(tree,{utf8=true,prefix='android'}={}){
 const strings=[],ids=new Map(),id=s=>{if(s===null||s===undefined)return 0xffffffff;if(!ids.has(s)){ids.set(s,strings.length);strings.push(s);}return ids.get(s);};
 const events=[],resourceIds=new Map();id(prefix);id(android);
 function visit(n){id(n.name);id(n.namespace);for(const a of n.attributes??[]){id(a.name);id(a.namespace);id(a.rawValue??(typeof a.value==='string'?a.value:null));if((a.type??(typeof a.value==='string'?3:16))===3)id(a.value);if(a.resourceId)resourceIds.set(id(a.name),a.resourceId);}events.push({kind:'start',n});for(const child of n.children??[])visit(child);events.push({kind:'end',n});}visit(tree);
 const chunk=(type,header,payload)=>{const b=Buffer.alloc(header+payload.length);b.writeUInt16LE(type);b.writeUInt16LE(header,2);b.writeUInt32LE(b.length,4);payload.copy(b,header);return b;};
 const length8=n=>n<128?Buffer.from([n]):Buffer.from([0x80|(n>>8),n&255]);const length16=n=>{const b=Buffer.alloc(n<32768?2:4);b.writeUInt16LE(n<32768?n:0x8000|(n>>>16));if(b.length===4)b.writeUInt16LE(n&65535,2);return b;};
 const offsets=[],parts=[];let length=0;for(const s of strings){offsets.push(length);const bytes=Buffer.from(s,utf8?'utf8':'utf16le'),b=Buffer.concat(utf8?[length8(s.length),length8(bytes.length),bytes,Buffer.alloc(1)]:[length16(s.length),bytes,Buffer.alloc(2)]);parts.push(b);length+=b.length;}
 const body=Buffer.alloc(strings.length*4+length+(4-length%4)%4);offsets.forEach((n,i)=>body.writeUInt32LE(n,i*4));Buffer.concat(parts).copy(body,strings.length*4);
 const pool=chunk(1,28,body);pool.writeUInt32LE(strings.length,8);pool.writeUInt32LE(utf8?0x100:0,16);pool.writeUInt32LE(28+strings.length*4,20);
 const mapSize=resourceIds.size?Math.max(...resourceIds.keys())+1:0,map=Buffer.alloc(mapSize*4);for(const [i,r]of resourceIds)map.writeUInt32LE(r,i*4);
 const node=(type,ext,line=1)=>{const b=chunk(type,16,ext);b.writeUInt32LE(line,8);b.writeUInt32LE(0xffffffff,12);return b;};
 const namespace=type=>{const ext=Buffer.alloc(8);ext.writeUInt32LE(id(prefix));ext.writeUInt32LE(id(android),4);return node(type,ext);};
 const xml=events.map(({kind,n})=>{
  const as=n.attributes??[],ext=Buffer.alloc(kind==='start'?20+as.length*20:8);ext.writeUInt32LE(id(n.namespace));ext.writeUInt32LE(id(n.name),4);
  if(kind==='start'){ext.writeUInt16LE(20,8);ext.writeUInt16LE(20,10);ext.writeUInt16LE(as.length,12);as.forEach((a,i)=>{const p=20+i*20,type=a.type??(typeof a.value==='string'?3:16);ext.writeUInt32LE(id(a.namespace),p);ext.writeUInt32LE(id(a.name),p+4);ext.writeUInt32LE(id(a.rawValue??(typeof a.value==='string'?a.value:null)),p+8);ext.writeUInt16LE(8,p+12);ext[p+15]=type;ext.writeUInt32LE(type===3?id(a.value):a.value>>>0,p+16);});}return node(kind==='start'?0x102:0x103,ext,n.line??1);
 });
 return chunk(3,8,Buffer.concat([pool,...(mapSize?[chunk(0x180,8,map)]:[]),namespace(0x100),...xml,namespace(0x101)]));
}
export function manifestFixture(count=3){return{name:'manifest',attributes:[attr('package','example.carve',{namespace:null}),attr('versionCode',7,{resourceId:0x0101021b})],children:[
 {name:'uses-sdk',attributes:[attr('targetSdkVersion',35)]},
 {name:'uses-permission',attributes:[attr('name','android.permission.CAMERA')]},
 {name:'application',children:Array.from({length:count},(_,i)=>({name:i===1?'activity-alias':'activity',attributes:[attr('name',i===0?'.Main':i===1?'Alias':'feature.Screen'+i),...(i===1?[attr('targetActivity','.Main'),attr('exported',1,{type:18})]:[])],children:i===0?[{name:'intent-filter',children:[{name:'action',attributes:[attr('name','android.intent.action.MAIN')]},{name:'category',attributes:[attr('name','android.intent.category.LAUNCHER')]},{name:'data',attributes:[attr('scheme','carve')]}]}]:[]}))}
]};}
