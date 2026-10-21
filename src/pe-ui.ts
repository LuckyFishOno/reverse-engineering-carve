import {open,readFile,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readPeLoader,publishEvidence,recordObservation,type PeMetadata} from './pe-loader.js';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {bindPeUiEntries} from './pe-ui-entries.js';
import {inspectPeUiDependencies} from './pe-ui-dependencies.js';
import type {PeUiAccess} from './pe-ui-functions.js';

// Microsoft PE resources and standard/extended MENU/DIALOG templates. Message-map scans are
// deliberately candidates: an AFX-like row does not prove table ownership or a function boundary.
export const PE_UI_LIMITS={resourceBytes:16*1024*1024,scanBytes:64*1024*1024,entries:50000,nodes:50000,edges:100000,textUnits:8192,depth:32,handlers:10000} as const;
type Key=number|string;
export type UiNode={id:string;kind:string;label:string;fileOffset?:number;rva?:number;commandId?:number;resource?:Key[];[key:string]:unknown};
export type UiEdge={from:string;to:string;kind:string;basis:string;[key:string]:unknown};
const fail=(s:string):never=>{throw new Error('PE UI: '+s);};
const utf16=new TextDecoder('utf-16le',{fatal:true});
class Cursor{
 p=0;
 constructor(readonly b:Buffer){}
 need(n:number){if(n<0||this.p>this.b.length-n)fail('truncated resource template.');}
 w(){this.need(2);const n=this.b.readUInt16LE(this.p);this.p+=2;return n;}
 d(){this.need(4);const n=this.b.readUInt32LE(this.p);this.p+=4;return n;}
 skip(n:number){this.need(n);this.p+=n;}
 align(){this.skip((4-this.p%4)%4);}
 text():string{const start=this.p;for(let i=0;i<=PE_UI_LIMITS.textUnits;i++){if(this.w()===0){try{return utf16.decode(this.b.subarray(start,this.p-2));}catch{return fail('invalid UTF16 text.');}}}return fail('resource string exceeds the text budget.');}
 field():Key{const at=this.p,n=this.w();if(n===0)return '';if(n===0xffff)return this.w();this.p=at;return this.text();}
}
function offsetOf(m:PeMetadata,size:number,rva:number,n:number){
 if(!Number.isSafeInteger(rva)||!Number.isSafeInteger(n)||rva<0||n<0||rva+n>0x100000000)fail('invalid RVA range.');
 const choices:number[]=[];
 if(rva<m.sizeOfHeaders&&rva+n<=m.sizeOfHeaders&&rva+n<=size)choices.push(rva);
 for(const s of m.sections)if(rva>=s.virtualAddress&&rva+n<=s.virtualAddress+Math.min(s.rawSize,Math.max(0,size-s.rawOffset)))choices.push(s.rawOffset+rva-s.virtualAddress);
 if(choices.length!==1)fail('resource/code range is unmapped or ambiguously mapped.');return choices[0]!;
}
const va=(m:PeMetadata,rva:number)=>'0x'+(BigInt(m.imageBase)+BigInt(rva)).toString(16);
export async function readPeUi(file:string,options:{signal?:AbortSignal}={}){
 const metadata=await readPeLoader(file,options),h=await open(file,'r');
 try{
  const size=(await h.stat()).size;
  const read=async(p:number,n:number)=>{options.signal?.throwIfAborted();if(n>PE_UI_LIMITS.scanBytes||p<0||p>size-n)fail('file range exceeds bounds/budget.');const b=Buffer.alloc(n);let got=0;while(got<n){const r=await h.read(b,got,n-got,p+got);if(!r.bytesRead)fail('input truncated during read.');got+=r.bytesRead;}return b;};
  const nodes:UiNode[]=[{id:'image',kind:'image',label:path.basename(file),imageBase:metadata.imageBase,machine:metadata.machineName}],edges:UiEdge[]=[],issues:{resource?:Key[];message:string}[]=[];
  const node=(n:UiNode)=>{if(nodes.length>=PE_UI_LIMITS.nodes)fail('node budget exceeded.');nodes.push(n);};
  const edge=(e:UiEdge)=>{if(edges.length>=PE_UI_LIMITS.edges)fail('edge budget exceeded.');edges.push(e);};
  const commandIds=new Set<number>();let resourceEntries=0,resourceLeaves=0,parsed=0,skipped=0,payloadBytes=0;
  const commands=new Set<number>();
  const bind=(item:UiNode)=>{
   const id=item.commandId;if(id===undefined||id<=0||id>=0xffff)return;
   commandIds.add(id);if(!commands.has(id)){commands.add(id);node({id:'command:'+id,kind:'command',label:'Command '+id,commandId:id});}
   edge({from:item.id,to:'command:'+id,kind:'declares-command',basis:'resource-template-field'});
  };
  const dir=metadata.dataDirectories.find(d=>d.index===2);
  if(dir?.rva){
   if(!dir.size||dir.size>PE_UI_LIMITS.resourceBytes)fail('resource directory size exceeds the 16 MiB budget or is empty.');
   const base=offsetOf(metadata,size,dir.rva,dir.size),tree=await read(base,dir.size),active=new Set<number>();
   const range=(p:number,n:number)=>{if(!Number.isSafeInteger(p)||p<0||n<0||p>tree.length-n)fail('resource directory reference out of bounds.');};
   const key=(raw:number):Key=>{if(!(raw&0x80000000))return raw;const at=raw&0x7fffffff;range(at,2);const count=tree.readUInt16LE(at);if(count>PE_UI_LIMITS.textUnits)fail('resource name exceeds text budget.');range(at+2,count*2);try{return utf16.decode(tree.subarray(at+2,at+2+count*2));}catch{return fail('invalid UTF16 resource name.');}};
   const seenPaths=new Set<string>();
   const walk=async(at:number,keys:Key[])=>{
    options.signal?.throwIfAborted();if(keys.length>8||active.has(at))fail('cyclic/deep resource directory.');range(at,16);active.add(at);
    const count=tree.readUInt16LE(at+12)+tree.readUInt16LE(at+14);range(at+16,count*8);
    for(let i=0;i<count;i++){
     if(++resourceEntries>PE_UI_LIMITS.entries)fail('resource entry budget exceeded.');
     const p=at+16+i*8,keys2=[...keys,key(tree.readUInt32LE(p))],target=tree.readUInt32LE(p+4);
     if(target&0x80000000){await walk(target&0x7fffffff,keys2);continue;}
     range(target,16);resourceLeaves++;const pathKey=JSON.stringify(keys2);if(seenPaths.has(pathKey))fail('duplicate resource path.');seenPaths.add(pathKey);
     const type=keys2[0];if(keys2.length!==3||![4,5,6,9].includes(type as number)){skipped++;continue;}
     const rva=tree.readUInt32LE(target),length=tree.readUInt32LE(target+4);
     payloadBytes+=length;if(length>PE_UI_LIMITS.resourceBytes||payloadBytes>PE_UI_LIMITS.scanBytes)fail('resource payload exceeds individual/cumulative byte budget.');
     const fileOffset=offsetOf(metadata,size,rva,length),raw=await read(fileOffset,length),prefix='resource:'+digest(pathKey);
     const resource:UiNode={id:prefix,kind:'resource',label:({4:'Menu',5:'Dialog',6:'Strings',9:'Accelerators'} as Record<number,string>)[type as number]+' '+String(keys2[1]),resource:keys2,fileOffset,rva,bytes:length,payloadSha256:digest(raw)};
     const local:UiNode[]=[],localEdges:UiEdge[]=[];
     const add=(n:Omit<UiNode,'id'>,at:number,parent=prefix)=>{if(local.length>=PE_UI_LIMITS.nodes)fail('template node budget exceeded.');const result={...n,id:prefix+'@'+at,resource:keys2,fileOffset:fileOffset+at};local.push(result as UiNode);localEdges.push({from:parent,to:result.id,kind:'contains',basis:'resource-template-layout'});return result.id;};
     try{
      const c=new Cursor(raw);
      if(type===4){
       const version=c.w(),header=c.w();if(version!==0&&version!==1||version===1&&header<4)fail('unsupported menu version/header.');c.skip(header);
       const menu=(parent:string,depth:number)=>{
        if(depth>PE_UI_LIMITS.depth)fail('menu nesting exceeds depth budget.');let end=false;
        while(!end){
         options.signal?.throwIfAborted();if(local.length>=PE_UI_LIMITS.nodes)fail('menu item budget exceeded.');
         if(version===1)c.align();const at=c.p;
         let flags:number,commandId:number|undefined,popup:boolean,typeFlags:number|undefined,state:number|undefined;
         if(version===1){typeFlags=c.d();state=c.d();commandId=c.d();flags=c.w();popup=Boolean(flags&1);}
         else{flags=c.w();popup=Boolean(flags&0x10);if(!popup)commandId=c.w();}
         const label=c.text(),id=add({kind:'menu-item',label,commandId,popup,flags,...(typeFlags===undefined?{}:{typeFlags,state})},at,parent);end=Boolean(flags&0x80);
         if(popup){if(version===1){c.align();c.d();}menu(id,depth+1);}
        }
       };menu(prefix,0);
      }else if(type===5){
       c.need(4);const extended=raw.readUInt16LE(2)===0xffff;let style:number,count:number;
       if(extended){if(c.w()!==1||c.w()!==0xffff)fail('unsupported extended dialog version.');c.d();c.d();style=c.d();count=c.w();c.skip(8);}
       else{style=c.d();c.d();count=c.w();c.skip(8);}
       const menu=c.field(),windowClass=c.field(),title=c.text();resource.label=title||resource.label;resource.template=extended?'extended':'standard';resource.menu=menu;resource.windowClass=windowClass;resource.style=style;
       if(style&0x40){c.w();if(extended)c.skip(4);c.text();}
       for(let j=0;j<count;j++){
        c.align();const at=c.p;let controlStyle:number,id:number;
        if(extended){c.d();c.d();controlStyle=c.d();c.skip(8);id=c.d();}else{controlStyle=c.d();c.d();c.skip(8);id=c.w();}
        const controlClass=c.field(),title=c.field(),extra=c.w();
        // Standard creation-data length includes its WORD; extended extraCount excludes it.
        if(extra){if(!extended&&extra<2)fail('invalid standard dialog creation-data size.');c.skip(extended?extra:extra-2);}
        add({kind:'dialog-control',label:typeof title==='string'?title:'#'+title,commandId:id,controlClass,style:controlStyle,title},at);
       }
      }else if(type===6){
       const block=keys2[1];if(typeof block!=='number'||block<1)fail('string-table block needs a positive numeric ID.');
       for(let j=0;j<16;j++){const at=c.p,count=c.w();if(count>PE_UI_LIMITS.textUnits)fail('string-table value exceeds text budget.');c.need(count*2);const label=utf16.decode(raw.subarray(c.p,c.p+count*2));c.skip(count*2);if(count)add({kind:'string',label,stringId:(Number(block)-1)*16+j},at);}
      }else{
       let end=false;while(!end){const at=c.p,flags=c.w(),keyCode=c.w(),commandId=c.w();c.w();add({kind:'accelerator',label:'Key '+keyCode,commandId,flags,keyCode},at);end=Boolean(flags&0x80);}
      }
     }catch(error){issues.push({resource:keys2,message:(error as Error).message});continue;}
     node(resource);edge({from:'image',to:prefix,kind:'contains',basis:'PE-resource-directory'});
     for(const n of local){node(n);bind(n);}for(const e of localEdges)edge(e);parsed++;
    }
    active.delete(at);
   };await walk(0,[]);
  }
  // DLL declarations are artifact-level boundary leads, never attributed to individual callbacks.
  for(const [i,m] of metadata.imports.entries()){
   const id='import:'+i;node({id,kind:'import-module',label:m.name,importKind:m.kind,descriptorRva:m.descriptorRva,entries:m.entries.length});
   edge({from:'image',to:id,kind:'declares-import',basis:'PE-import-directory',runtimeLoading:'unverified',handlerAttribution:'not-established'});
  }
  let scannedBytes=0,handlerRows=0;
  const width=metadata.machine===0x14c?4:metadata.machine===0x8664?8:0;
  if(width&&commandIds.size){
   const ids=[...commandIds].sort((a,b)=>a-b),functions=new Set<number>();
   for(const s of metadata.sections){
    if(s.characteristics&0x20000000||!s.rawSize||s.rawOffset>=size)continue;
    const n=Math.min(s.rawSize,size-s.rawOffset);scannedBytes+=n;if(scannedBytes>PE_UI_LIMITS.scanBytes)fail('message-map scan exceeds 64 MiB.');const b=await read(s.rawOffset,n),entryBytes=width===4?24:32;
    for(let p=0;p<=b.length-entryBytes;p+=width){
     if((p&0xffff)===0)options.signal?.throwIfAborted();if(b.readUInt32LE(p)!==0x111)continue;
     const code=b.readUInt32LE(p+4),first=b.readUInt32LE(p+8),last=b.readUInt32LE(p+12),signature=width===4?BigInt(b.readUInt32LE(p+16)):b.readBigUInt64LE(p+16),pointer=width===4?BigInt(b.readUInt32LE(p+20)):b.readBigUInt64LE(p+24),rva=pointer-BigInt(metadata.imageBase);
     if(code>0xffff||!first||last<first||last>=0xffff||last-first>4096||signature<1n||signature>1024n||rva<0n||rva>0xffffffffn)continue;
     let lo=0,hi=ids.length;while(lo<hi){const mid=(lo+hi)>>>1;if(ids[mid]!<first)lo=mid+1;else hi=mid;}
     const matches:number[]=[];for(let i=lo;i<ids.length&&ids[i]!<=last;i++)matches.push(ids[i]!);if(!matches.length)continue;
     const executable=metadata.sections.filter(section=>Boolean(section.characteristics&0x20000000)&&Number(rva)>=section.virtualAddress&&Number(rva)<section.virtualAddress+Math.min(section.rawSize,Math.max(0,size-section.rawOffset)));
     if(executable.length!==1)continue;
     if(++handlerRows>PE_UI_LIMITS.handlers)fail('handler candidate budget exceeded.');
     const entryRva=Number(rva),rowId='dispatch:'+String(s.rawOffset+p),handlerId='handler:'+entryRva,codeOffset=offsetOf(metadata,size,entryRva,1);
     if(!functions.has(entryRva)){
      functions.add(entryRva);node({id:handlerId,kind:'handler-candidate',label:va(metadata,entryRva),rva:entryRva,fileOffset:codeOffset,address:va(metadata,entryRva),functionBoundary:'unverified',semanticMatch:'unconfirmed',nextAction:'Inspect this address using the separate REA MCP; retain its complete code and outgoing references.'});
     }
     node({id:rowId,kind:'dispatch-row-candidate',label:'WM_COMMAND '+first+(last===first?'':'–'+last),rva:s.virtualAddress+p,fileOffset:s.rawOffset+p,bytes:b.subarray(p,p+entryBytes).toString('hex'),commandFirst:first,commandLast:last,notification:code,signature:signature.toString(),layout:width===4?'AFX-like-x86-24':'AFX-like-x64-32',owner:'unverified'});
     for(const commandId of matches)edge({from:'command:'+commandId,to:rowId,kind:'dispatch-candidate',basis:'numeric-command-range-and-table-byte-pattern',notification:code,ownership:'unverified'});
     edge({from:rowId,to:handlerId,kind:'points-to',basis:'file-backed-executable-image-VA-field',functionBoundary:'unverified'});
    }
   }
  }
  return{metadata:{format:metadata.format,machine:metadata.machineName,imageBase:metadata.imageBase},nodes,edges,issues,counts:{resourceEntries,resourceLeaves,parsedResources:parsed,skippedResources:skipped,nodes:nodes.length,edges:edges.length,commands:commands.size,handlerRows,scannedBytes},handlerScan:width?'AFX-like-byte-pattern-candidates':'unsupported-machine',limitations:['Resource declarations are not observed UI interactions.','WM_COMMAND matches do not prove message-map/class ownership or a function entry. ID reuse, ranges and notification codes require REA review.','Dynamic menus, runtime-created controls, WM_NOTIFY, non-MFC frameworks and encoded member-pointer layouts are not resolved.','DLLs are artifact-level import declarations; handler-to-DLL calls, persistence paths, dependency closure and runtime semantics remain unverified.']};
 }finally{await h.close();}
}

export type PeUiOptions={file:string;view?:'summary'|'nodes'|'edges'|'boundary'|'issues'|'entries'|'dependencies';functionIds?:string[];dependencyIds?:string[];dependencyDepth?:number;entryMode?:'ui-command'|'selected-functions';authorizePath?:PeUiAccess;command?:number;query?:string;offset?:number;limit?:number;budgetBytes?:number;signal?:AbortSignal};
export async function inspectPeUi(workspace:string,options:PeUiOptions){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,budget=responseBudget(options.budgetBytes);
 if(!['summary','nodes','edges','boundary','issues','entries','dependencies'].includes(view)||!Number.isSafeInteger(offset)||offset<0||!Number.isInteger(limit)||limit<1||limit>100)throw new Error('Use PE UI summary/nodes/edges/boundary/issues/entries/dependencies, offset>=0 and limit1–100.');
 if(options.command!==undefined&&(!Number.isInteger(options.command)||options.command<1||options.command>=65535)||options.query!==undefined&&(options.query.length>1000||!options.query.trim()))throw new Error('Use command1–65534 and a nonempty query up to1000 characters.');
 const selectedFunctions=options.entryMode==='selected-functions';
 if(options.entryMode!==undefined&&(!['ui-command','selected-functions'].includes(options.entryMode)||view!=='dependencies'))throw new Error('Entry mode is only supported in dependencies view.');
 if(selectedFunctions&&(options.command!==undefined||!options.functionIds?.length))throw new Error('Selected-functions mode requires function IDs and no command ID.');
 if((view==='boundary'||view==='entries'||view==='dependencies'&&!selectedFunctions)&&options.command===undefined)throw new Error('Boundary view requires one command ID.');
 if(view==='issues'&&(options.command!==undefined||options.query!==undefined))throw new Error('Issues view does not accept command/query filters.');
 if(view==='summary'&&(options.command!==undefined||options.query!==undefined||offset))throw new Error('Summary does not accept command/query/offset filters.');
 if(options.functionIds!==undefined&&(!['entries','dependencies'].includes(view)||!Array.isArray(options.functionIds)||options.functionIds.length>16||new Set(options.functionIds).size!==options.functionIds.length||options.functionIds.some(id=>typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id))))throw new Error('Use up to16unique function observation IDs with entries/dependencies views only.');
 if((view==='entries'||view==='dependencies')&&options.query!==undefined)throw new Error('Selected entries/dependencies view does not accept query filters.');
 if(options.dependencyIds!==undefined&&(view!=='dependencies'||!Array.isArray(options.dependencyIds)||options.dependencyIds.length>32||new Set(options.dependencyIds).size!==options.dependencyIds.length||options.dependencyIds.some(id=>typeof id!=='string'||!/^[a-f0-9]{64}$/.test(id))))throw new Error('Use up to32unique dependency observation IDs in dependencies view only.');
 if(options.dependencyDepth!==undefined&&(view!=='dependencies'||!Number.isInteger(options.dependencyDepth)||options.dependencyDepth<0||options.dependencyDepth>8))throw new Error('Use dependency depth0–8in dependencies view only.');
 const root=await realpath(workspace),target=await indexedFile(root,options.file,options.signal),graph=await readPeUi(target.path,options);
 if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while reading PE UI evidence.');
 const provider={name:'carve-pe-ui',version:'1',parserSha256:digest(await readFile(fileURLToPath(import.meta.url)))};
 const detail={kind:'native-ui',name:'PE UI resources and command-handler candidates',address:'file:0',provider,graph};
 const id=digest(JSON.stringify({file:options.file,sourceSha256:target.sha256,detail})),evidence=path.join(root,'ui-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/pe-ui-evidence@1',file:options.file,sourceSha256:target.sha256,...detail},null,2)+'\n';await publishEvidence(evidence,text);
 const db=openIndex(root);try{recordObservation(db,{id,file:options.file,sha256:target.sha256,detail,searchText:graph.nodes.filter(n=>['menu-item','dialog-control','string','import-module'].includes(n.kind)).map(n=>n.label).join('\n'),evidence,evidenceSha256:digest(text)});}finally{db.close();}
 if(view==='dependencies'){
  const result=await inspectPeUiDependencies(root,target,options.file,graph,options.command!,options.functionIds??[],options.dependencyIds??[],options.dependencyDepth??3,options.signal,options.authorizePath,options.entryMode);
  if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected UI source changed while inspecting dependencies.');
  if(offset>result.rows.length)throw new Error('PE UI dependency offset exceeds selected results.');
  const report={schema:'carve/pe-ui-dependencies@1',file:options.file,sourceSha256:target.sha256,uiObservationId:id,uiEvidenceSha256:digest(text),command:options.command,...(selectedFunctions?{entryMode:'selected-functions'}:{}),...result};
  const reportText=JSON.stringify(report,null,2)+'\n',dependencyId=digest(reportText),dependencyEvidence=path.join(root,'ui-evidence',dependencyId+'.json');await publishEvidence(dependencyEvidence,reportText);
  const page=result.rows.slice(offset,offset+limit).map(row=>{
   const previewFields:string[]=[];
   const preview=(value:unknown,key:string):unknown=>{
    if(typeof value==='string'&&[...value].length>512){previewFields.push(key);return [...value].slice(0,512).join('');}
    if(Array.isArray(value)){if(value.length>8)previewFields.push(key);return value.slice(0,8).map((v,i)=>preview(v,key+'['+i+']'));}
    if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,preview(v,key?key+'.'+k:k)]));return value;
   };
   return{value:{...preview(row,'') as Record<string,unknown>,previewFields,fullValuesInEvidence:true}};
  });
  return budgetItems({schema:'carve/pe-ui@1',view,workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,observationId:id,dependencyId,dependencyEvidence,command:options.command,...(selectedFunctions?{entryMode:'selected-functions'}:{}),total:result.rows.length,offset,visited:result.visited,counts:result.counts,depth:result.depth,rowLimitReached:result.rowLimitReached,dependencyClosure:'not-established',executesTarget:false,startsRea:false,scope:result.scope,limitations:result.limitations},page,budget);
 }
 if(view==='entries'){
  const bound=await bindPeUiEntries(root,target,options.file,graph,options.command!,options.functionIds??[],options.signal);
  if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while binding PE UI entries.');
  if(offset>bound.entries.length)throw new Error('PE UI offset exceeds selected results.');
  const binding={schema:'carve/pe-ui-entries@1',file:options.file,sourceSha256:target.sha256,uiObservationId:id,uiEvidenceSha256:digest(text),command:options.command,...bound};
  const bindingText=JSON.stringify(binding,null,2)+'\n',bindingId=digest(bindingText),bindingEvidence=path.join(root,'ui-evidence',bindingId+'.json');
  await publishEvidence(bindingEvidence,bindingText);
  return budgetItems({schema:'carve/pe-ui@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,view,command:options.command,observationId:id,evidence,evidenceSha256:digest(text),bindingId,bindingEvidence,total:bound.entries.length,offset,executesTarget:false,startsRea:false,scope:bound.scope,limitations:bound.limitations},bound.entries.slice(offset,offset+limit).map(value=>{const dispatch=value.dispatch as unknown[];return{value:{...value,dispatch:dispatch.slice(0,8),dispatchTotal:dispatch.length,dispatchTruncated:dispatch.length>8,fullValuesInEvidence:true}};}),budget);
 }
 let selected=graph.nodes;
 if(options.command!==undefined){
  const wanted=new Set(['command:'+options.command]);
  for(const e of graph.edges)if(e.kind==='declares-command'&&e.to==='command:'+options.command)wanted.add(e.from);
  let changed=true;while(changed){changed=false;for(const e of graph.edges){if((e.kind==='dispatch-candidate'||e.kind==='points-to')&&wanted.has(e.from)&&!wanted.has(e.to)){wanted.add(e.to);changed=true;}if(e.kind==='contains'&&wanted.has(e.to)&&!wanted.has(e.from)){wanted.add(e.from);changed=true;}}}
  selected=selected.filter(n=>wanted.has(n.id));
 }
 if(options.query){const q=options.query.toLowerCase();selected=selected.filter(n=>n.label.toLowerCase().includes(q));}
 const selectedIds=new Set(selected.map(n=>n.id));
 const selectedEdges=graph.edges.filter(e=>selectedIds.has(e.from)&&selectedIds.has(e.to));
 const values=view==='summary'?[]:view==='issues'?graph.issues:view==='edges'?selectedEdges:selected;
 if(offset>values.length)throw new Error('PE UI offset exceeds selected results.');
 const adjacency=new Map<string,UiEdge[]>();
 if(view==='boundary')for(const e of selectedEdges)for(const id of new Set([e.from,e.to])){const list=adjacency.get(id)??[];list.push(e);adjacency.set(id,list);}
 const page=values.slice(offset,offset+limit).map(value=>{
  const fields:string[]=[];
  const preview=(value:unknown,field:string):unknown=>{
   if(typeof value==='string'&&value.length>512){const chars=[...value];if(chars.length>512){fields.push(field);return chars.slice(0,512).join('');}}
   if(Array.isArray(value))return value.map((v,i)=>preview(v,field+'['+i+']'));
   if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,preview(v,field?field+'.'+k:k)]));
   return value;
  };
  let card=value as Record<string,unknown>;
  if(view==='boundary'){const links=adjacency.get(String(card.id))??[];card={...card,edges:links.slice(0,8),edgesTotal:links.length,edgesTruncated:links.length>8};}
  const compact=preview(card,'') as Record<string,unknown>;
  return{value:{...compact,...(fields.length?{previewFields:fields,fullValuesInEvidence:true}:{})}};
 });
 const base={schema:'carve/pe-ui@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,executesTarget:false,startsRea:false,observationId:id,evidence,evidenceSha256:digest(text),provider,view,counts:graph.counts,handlerScan:graph.handlerScan,issues:graph.issues.length,limitations:graph.limitations,command:options.command??null,total:values.length,offset};
 return budgetItems(base,page,budget);
}
