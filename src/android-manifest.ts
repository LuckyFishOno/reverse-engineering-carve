import {open,realpath,mkdir,writeFile,readFile,link,unlink,lstat} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';

// Android's ResChunk_header, ResStringPool_header, ResXMLTree_* and Res_value.
// Specification: AOSP libs/androidfw/include/androidfw/ResourceTypes.h.
// This reads compiled XML declarations; it is not Android's PackageManager.
const MAX_BYTES=8*1024*1024,NO=0xffffffff,ANDROID='http://schemas.android.com/apk/res/android';
const fail=(message:string):never=>{throw new Error('Android binary XML: '+message);};
export type XmlAttribute={namespace:string|null;name:string;resourceId:string|null;rawValue:string|null;type:number;data:number;value:string|number|boolean|null};
export type XmlNode={index:number;parent:number|null;fileOffset:number;line:number;namespace:string|null;name:string;attributes:XmlAttribute[]};
const hex=(n:number)=>'0x'+n.toString(16).padStart(8,'0');
export function parseAndroidXml(data:Buffer){
 if(data.length<8||data.length>MAX_BYTES)fail('requires8 bytes–8MiB.');
 function chunk(p:number){
  if(p<0||p>data.length-8)fail('truncated chunk header.');
  const type=data.readUInt16LE(p),header=data.readUInt16LE(p+2),size=data.readUInt32LE(p+4);
  if(header<8||header%4||size<header||size%4||size>data.length-p)fail('invalid chunk size/alignment.');
  return{type,header,size,end:p+size};
 }
 const root=chunk(0);if(root.type!==3||root.header!==8||root.size!==data.length)fail('expected one complete compiled XML document, not plain/protobuf XML or an APK. Unpack the APK first.');
 let strings:string[]|undefined,encoding:'utf8'|'utf16'|undefined,resources:number[]|undefined,decodedBytes=0,expandedBytes=0,attributes=0,events=0;
 const nodes:XmlNode[]=[],stack:XmlNode[]=[],namespaces:{prefix:string|null;uri:string;depth:number}[]=[];
 const str=(id:number,nullable=false):string|null=>{if(id===NO&&nullable)return null;if(!strings||id>=strings.length)fail('string reference outside the pool.');return strings![id]!;};
 const name=(id:number)=>{const n=str(id)!;if(!n||n.length>512||/[\s\0:<>&"']/u.test(n))fail('invalid/excessive XML name.');return n;};
 const expansion=(...values:(string|null)[])=>{for(const value of values)expandedBytes+=value===null?0:Buffer.byteLength(value);if(expandedBytes>1024*1024)fail('expanded XML text exceeds1MiB.');};
 const ns=(id:number)=>{const uri=str(id,true);if(uri!==null&&!namespaces.some(n=>n.uri===uri))fail('namespace URI has no active declaration.');return uri;};
 for(let p=8;p<data.length;){
  const c=chunk(p);if(++events>32768)fail('exceeds32768 XML chunks.');
  if(c.type===1){
   if(strings||nodes.length||namespaces.length||c.header!==28)fail('unexpected string pool.');
   const count=data.readUInt32LE(p+8),styles=data.readUInt32LE(p+12),flags=data.readUInt32LE(p+16),start=data.readUInt32LE(p+20),styleStart=data.readUInt32LE(p+24);
   if(count>32768||styles!==0||styleStart!==0||(flags&~0x101)!==0)fail('string pool exceeds32768 strings or uses unsupported styles/flags.');
   if(start<c.header+count*4||start%4||start>c.size)fail('invalid string-pool offset table.');
   strings=[];encoding=flags&0x100?'utf8':'utf16';
   const poolEnd=c.end;
   for(let i=0;i<count;i++){
    let at=p+start+data.readUInt32LE(p+c.header+i*4);
    const length=(wide:boolean)=>{
     if(at>poolEnd-(wide?2:1))return fail('truncated string length.');
     const first=wide?data.readUInt16LE(at):data[at]!;at+=wide?2:1;
     if(first&(wide?0x8000:0x80)){if(at>poolEnd-(wide?2:1))return fail('truncated extended string length.');const second=wide?data.readUInt16LE(at):data[at]!;at+=wide?2:1;return(first&(wide?0x7fff:0x7f))*(wide?65536:256)+second;}return first;
    };
    if(at<p+start||at>=poolEnd)fail('string offset outside the string data.');
    const units=length(encoding==='utf16'),bytes=encoding==='utf8'?length(false):units*2,terminator=encoding==='utf8'?1:2;
    if(bytes>1024*1024||at>poolEnd-bytes-terminator)fail('string exceeds its pool or1MiB limit.');
    if(encoding==='utf16'&&(at%2||data.readUInt16LE(at+bytes)!==0)||encoding==='utf8'&&data[at+bytes]!==0)fail('invalid string alignment/terminator.');
    let text:string;try{text=new TextDecoder(encoding==='utf8'?'utf-8':'utf-16le',{fatal:true,ignoreBOM:true}).decode(data.subarray(at,at+bytes));}catch{fail('invalid string encoding.');}
    if(text!.length!==units)fail('declared UTF16 string length disagrees with decoded text.');
    decodedBytes+=Buffer.byteLength(text!);if(decodedBytes>16*1024*1024)fail('decoded strings exceed16MiB.');strings.push(text!);
   }
  }else if(c.type===0x180){
   if(!strings||resources||nodes.length||namespaces.length||c.header!==8||(c.size-8)/4>strings.length)fail('invalid/repeated resource map.');
   resources=[];for(let at=p+8;at<c.end;at+=4)resources.push(data.readUInt32LE(at));
  }else{
   if(!strings||c.header!==16)fail('XML node needs a prior string pool and a16-byte header.');
   str(data.readUInt32LE(p+12),true);const ext=p+16;
   if(c.type===0x100||c.type===0x101){
    if(c.size!==24)fail('invalid namespace chunk.');const prefix=str(data.readUInt32LE(ext),true),uri=str(data.readUInt32LE(ext+4))!;
    if(!uri||uri.length>4096||prefix!==null&&(prefix.length>256||/[\s\0:<>&"']/u.test(prefix)))fail('invalid/excessive namespace.');
    if(c.type===0x100){if(namespaces.length>=128||nodes.length&&stack.length===0||namespaces.some(n=>n.depth===stack.length&&n.prefix===prefix))fail('invalid/excessive namespace scope.');namespaces.push({prefix,uri,depth:stack.length});}
    else{const previous=namespaces.pop();if(!previous||previous.prefix!==prefix||previous.uri!==uri||previous.depth!==stack.length)fail('unbalanced namespace.');}
   }else if(c.type===0x102){
    if(c.size<36||stack.length>=128||nodes.length>=8192)fail('truncated node or8192-node/128-depth limit exceeded.');
    const namespace=ns(data.readUInt32LE(ext)),tag=name(data.readUInt32LE(ext+4)),start=data.readUInt16LE(ext+8),width=data.readUInt16LE(ext+10),count=data.readUInt16LE(ext+12);
    if(start<20||start%4||width!==20||count>256||ext+start>c.end-count*width||attributes+count>32768)fail('invalid/excessive attribute table.');
    for(const at of [ext+14,ext+16,ext+18])if(data.readUInt16LE(at)>count)fail('attribute special index outside the table.');
    if(!stack.length&&nodes.length)fail('multiple root elements.');
    expansion(namespace,tag);const node:XmlNode={index:nodes.length,parent:stack.at(-1)?.index??null,fileOffset:p,line:data.readUInt32LE(p+8),namespace,name:tag,attributes:[]},keys=new Set<string>();
    for(let i=0;i<count;i++){
     const at=ext+start+i*width,namespace=ns(data.readUInt32LE(at)),nameId=data.readUInt32LE(at+4),attrName=name(nameId),key=JSON.stringify([namespace,attrName]);
     if(keys.has(key))fail('duplicate namespaced attribute.');keys.add(key);
     const rawValue=str(data.readUInt32LE(at+8),true),size=data.readUInt16LE(at+12),reserved=data[at+14],type=data[at+15]!,value=data.readUInt32LE(at+16);
     if(size!==8||reserved!==0)fail('unsupported typed-value layout.');
     // Preserve the raw type/data for unresolved resources, dimensions, floats,
     // dynamic IDs and vendor types. Do not substitute the raw string for them.
     const decoded=type===3?str(value):type===0x12?value!==0:type===0x10?value|0:type===0x11?hex(value):type===1?'@'+hex(value):type===2?'?'+hex(value):null;
     expansion(namespace,attrName,rawValue,typeof decoded==='string'?decoded:null);node.attributes.push({namespace,name:attrName,resourceId:resources?.[nameId]?hex(resources[nameId]!):null,rawValue,type,data:value,value:decoded});
    }
    attributes+=count;nodes.push(node);stack.push(node);
   }else if(c.type===0x103){
    if(c.size!==24)fail('invalid end-element chunk.');const namespace=ns(data.readUInt32LE(ext)),tag=name(data.readUInt32LE(ext+4)),previous=stack.pop();
    if(!previous||previous.namespace!==namespace||previous.name!==tag)fail('unbalanced element.');
    if(namespaces.some(n=>n.depth>stack.length))fail('namespace ends after its declaring element.');
   }else fail('unsupported XML chunk '+hex(c.type)+'; no partial success is recorded.');
  }
  p=c.end;
 }
 if(!nodes.length||stack.length||namespaces.length)fail('missing root or unclosed element/namespace.');
 return{encoding:encoding!,stringCount:strings!.length,attributeCount:attributes,nodes};
}

function attribute(node:XmlNode,name:string,namespace:string|null=ANDROID){return node.attributes.find(a=>a.namespace===namespace&&a.name===name);}
function stringAttribute(node:XmlNode,name:string,namespace:string|null=ANDROID){const a=attribute(node,name,namespace);return a?.type===3?String(a.value):null;}
export function manifestDeclarations(parsed:ReturnType<typeof parseAndroidXml>){
 const root=parsed.nodes[0]!;if(root.name!=='manifest'||root.namespace!==null)fail('root must be an unqualified manifest.');
 const packageName=stringAttribute(root,'package',null),children=new Map<number,XmlNode[]>();
 for(const node of parsed.nodes)if(node.parent!==null){const list=children.get(node.parent)??[];list.push(node);children.set(node.parent,list);}
 const direct=(node:XmlNode,tag?:string)=>(children.get(node.index)??[]).filter(n=>n.namespace===null&&(!tag||n.name===tag));
 const applications=direct(root,'application');if(applications.length>1)fail('multiple application declarations.');
 const application=applications[0],sdk=direct(root,'uses-sdk');if(sdk.length>1)fail('multiple uses-sdk declarations.');
 const qualify=(value:string|null)=>!value||!packageName?null:value.startsWith('.')?packageName+value:value.includes('.')?value:packageName+'.'+value;
 const components=(application?direct(application):[]).filter(n=>['activity','activity-alias','service','receiver','provider'].includes(n.name)).map(node=>{
  const declaredName=stringAttribute(node,'name'),alias=node.name==='activity-alias',target=alias?stringAttribute(node,'targetActivity'):declaredName;
  const filters=direct(node,'intent-filter').map(filter=>({node:filter.index,attributes:filter.attributes,actions:direct(filter,'action').map(n=>stringAttribute(n,'name')),categories:direct(filter,'category').map(n=>stringAttribute(n,'name')),data:direct(filter,'data').map(n=>({node:n.index,attributes:n.attributes}))}));
  return{node:node.index,kind:node.name,declaredName,qualifiedName:qualify(declaredName),codeClassCandidate:qualify(target),classMatch:'unconfirmed',attributes:node.attributes,
   exportedDeclaration:attribute(node,'exported')??null,enabledDeclaration:attribute(node,'enabled')??null,runtimeAvailability:'unverified',
   launcherDeclared:filters.some(f=>f.actions.includes('android.intent.action.MAIN')&&f.categories.includes('android.intent.category.LAUNCHER')),intentFilters:filters};
 });
 return{packageName,manifestNode:root.index,applicationNode:application?.index??null,sdkNode:sdk[0]?.index??null,
  versionCode:attribute(root,'versionCode')??null,versionName:attribute(root,'versionName')??null,minSdkVersion:sdk[0]?attribute(sdk[0],'minSdkVersion')??null:null,targetSdkVersion:sdk[0]?attribute(sdk[0],'targetSdkVersion')??null:null,
  components,permissions:direct(root).filter(n=>['uses-permission','uses-permission-sdk-23','uses-permission-sdk-m'].includes(n.name)),features:direct(root,'uses-feature')};
}
export const manifestSection=['components','permissions','features','nodes'] as const;
export async function inspectAndroidManifest(workspace:string,options:{file:string;section?:typeof manifestSection[number];query?:string;limit?:number;offset?:number;budgetBytes?:number;signal?:AbortSignal}){
 const limit=options.limit??20,offset=options.offset??0,section=options.section??'components',query=options.query??'',budget=responseBudget(options.budgetBytes);
 if(!manifestSection.includes(section)||!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0||query.length>1000)throw new Error('Use manifest section components/permissions/features/nodes, limit1–100, nonnegative offset and query<=1000 characters.');
 const root=await realpath(workspace),source=await indexedFile(root,options.file,options.signal),handle=await open(source.path,'r');let data:Buffer;
 try{const info=await handle.stat();if(!info.isFile()||info.size>MAX_BYTES)fail('selected file exceeds8MiB or is not regular.');data=Buffer.alloc(info.size);let read=0;while(read<data.length){options.signal?.throwIfAborted();const r=await handle.read(data,read,data.length-read,read);if(!r.bytesRead)fail('input truncated during read.');read+=r.bytesRead;}}finally{await handle.close();}
 if(digest(data!)!==source.sha256)throw new Error('Manifest bytes changed since inventory.');
 const parsed=parseAndroidXml(data!),declarations=manifestDeclarations(parsed);
 if((await hashFile(source.path,options.signal)).sha256!==source.sha256)throw new Error('Manifest changed while parsing.');
 const provider={name:'carve-android-binary-xml',version:'1',parserSha256:digest(await readFile(fileURLToPath(import.meta.url)))};
 const detail={kind:'android-manifest',name:'Android manifest '+(declarations.packageName??'(unresolved package)'),address:'file:0',provider,metadata:{...parsed,...declarations}};
 const id=digest(JSON.stringify({file:options.file,sha256:source.sha256,detail})),evidence=path.join(root,'manifest-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/android-manifest-evidence@1',file:options.file,sourceSha256:source.sha256,...detail},null,2)+'\n';
 const directory=path.dirname(evidence);await mkdir(directory,{recursive:true,mode:0o700});if(await realpath(directory)!==directory)throw new Error('Manifest evidence directory follows a symlink.');const temporary=path.join(directory,'.'+randomUUID()+'.tmp');
 try{await writeFile(temporary,text,{flag:'wx',mode:0o600});try{await link(temporary,evidence);}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;const info=await lstat(evidence);if(!info.isFile()||info.isSymbolicLink()||(await hashFile(evidence)).sha256!==digest(text))throw new Error('Existing manifest evidence changed; preserve it before retrying.');}}finally{await unlink(temporary).catch(error=>{if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;});}
 const db=openIndex(root);try{
  db.exec(`CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,artifact TEXT,sha256 TEXT,kind TEXT,name TEXT,address TEXT,content TEXT,detail TEXT,evidence TEXT,evidence_sha256 TEXT);
   CREATE VIRTUAL TABLE IF NOT EXISTS observation_search USING fts5(id UNINDEXED,content);
   CREATE INDEX IF NOT EXISTS observations_location ON observations(artifact,sha256,kind,address);`);
  db.exec('BEGIN');try{const inserted=db.prepare('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?,?)').run(id,options.file,source.sha256,detail.kind,detail.name,detail.address,JSON.stringify(detail.metadata),JSON.stringify(detail),evidence,digest(text));if(inserted.changes)db.prepare('INSERT INTO observation_search(id,content) VALUES(?,?)').run(id,JSON.stringify(detail.metadata));db.exec('COMMIT');}catch(error){db.exec('ROLLBACK');throw error;}
 }finally{db.close();}
 const items=(section==='nodes'?parsed.nodes:declarations[section]).filter(item=>!query||JSON.stringify(item).toLowerCase().includes(query.toLowerCase()));
 return budgetItems({schema:'carve/android-manifest@1',status:'declarations-inspected',workspace:root,file:options.file,sourceSha256:source.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),packageName:declarations.packageName,encoding:parsed.encoding,
  sdk:{min:declarations.minSdkVersion,target:declarations.targetSdkVersion},counts:{nodes:parsed.nodes.length,components:declarations.components.length,permissions:declarations.permissions.length,features:declarations.features.length},section,query,offset,limit,total:items.length,
  scope:'Selected compiled XML declarations only. Class names/aliases are leads, not DEX matches, resolved intent routing or runtime availability. Missing exported/enabled remain unspecified; no OS defaults/security verdict inferred. Resource IDs/labels, styles, protobuf/plain XML, split/dynamic manifests, UI event flow and server logic are unresolved. Read complete nodes/evidence before reconstructing. This is boundary support, never implementation code.'},items.slice(offset,offset+limit).map(value=>({value})),budget);
}
