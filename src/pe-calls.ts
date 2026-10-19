import {open,realpath,readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {readPeLoader,publishEvidence,recordObservation,type PeMetadata} from './pe-loader.js';

// Import call sites in x86 / x86-64 PE images: `call [slot]` and `jmp [slot]` through an import
// address table slot (RIP-relative on x86-64, absolute on x86), and `call rel32` into such a jump
// thunk. Scanning matches byte patterns inside executable sections whose operand lands exactly on
// an import slot; it is not a disassembler, so a match is a candidate until an instruction address
// from real code evidence is verified with decodePeImportCall. Calls that load a slot into a
// register first (mov reg,[slot]; call reg) are not found.
export const PE_CALL_LIMITS={scanBytes:256*1024*1024,sites:200000} as const;
export type PeSlot={rva:number;module:string;importKind:'import'|'delay-import';descriptorRva:number;name?:string;ordinal?:number;hint?:number};
// instructionRva is the opcode (FF or E8). A scan cannot tell whether a 0x48 byte before an FF
// opcode is a REX.W prefix or the end of the previous instruction, so it reports precedingByteRexW
// instead of guessing; the operand end (instructionEndRva) and the slot are the same either way.
export type PeCallSite={instructionRva:number;instructionEndRva:number;fileOffset:number;form:'call-indirect'|'jump-indirect'|'call-via-thunk';bytes:string;precedingByteRexW?:boolean;rexW?:boolean;slotRva:number;thunkRva?:number;slot:PeSlot};
const supported=new Map([[0x8664,'x86-64'],[0x14c,'x86']]);
const fail=(message:string):never=>{throw new Error('PE import calls: '+message);};

function slotMap(metadata:PeMetadata){
 const slots=new Map<number,PeSlot>();
 for(const module of metadata.imports)for(const entry of module.entries)
  slots.set(entry.thunkRva,{rva:entry.thunkRva,module:module.name,importKind:module.kind,descriptorRva:module.descriptorRva,...(entry.name!==undefined?{name:entry.name,hint:entry.hint}:{ordinal:entry.ordinal})});
 return slots;
}
const executable=(characteristics:number)=>Boolean(characteristics&0x20000000||characteristics&0x20);
function sectionOf(metadata:PeMetadata,rva:number){return metadata.sections.find(s=>rva>=s.virtualAddress&&rva<s.virtualAddress+Math.max(s.virtualSize,s.rawSize));}

// Decodes one indirect call/jump through a slot at byte position p of a section buffer.
function indirectAt(code:Buffer,p:number,sectionRva:number,machine:number,imageBase:bigint){
 if(code[p]!==0xff||(code[p+1]!==0x15&&code[p+1]!==0x25)||p+6>code.length)return null;
 const form=code[p+1]===0x15?'call-indirect' as const:'jump-indirect' as const,operand=code.readInt32LE(p+2);
 let slotRva:number;
 if(machine===0x8664)slotRva=sectionRva+p+6+operand;
 else{const va=BigInt(code.readUInt32LE(p+2))-imageBase;if(va<0n||va>0xffffffffn)return null;slotRva=Number(va);}
 return{form,slotRva};
}

export async function readPeImportCalls(file:string,options:{signal?:AbortSignal}={}){
 const metadata=await readPeLoader(file,options),architecture=supported.get(metadata.machine);
 if(!architecture)return{metadata,architecture:null,sites:[] as PeCallSite[],scannedBytes:0,status:'unsupported-machine' as const};
 const slots=slotMap(metadata),imageBase=BigInt(metadata.imageBase),sites:PeCallSite[]=[],thunks=new Map<number,PeCallSite>();
 const handle=await open(file,'r');let scannedBytes=0;
 try{
  const size=(await handle.stat()).size;const sections=[];
  for(const s of metadata.sections){
   if(!executable(s.characteristics)||!s.rawSize||s.rawOffset>=size)continue;
   const length=Math.min(s.rawSize,s.virtualSize||s.rawSize,size-s.rawOffset);scannedBytes+=length;
   if(scannedBytes>PE_CALL_LIMITS.scanBytes)fail(`executable sections exceed the ${PE_CALL_LIMITS.scanBytes}-byte scan budget.`);
   const code=Buffer.alloc(length);let got=0;while(got<length){const r=await handle.read(code,got,length-got,s.rawOffset+got);if(!r.bytesRead)fail('file is truncated.');got+=r.bytesRead;}
   sections.push({s,code});
  }
  const push=(site:PeCallSite)=>{if(sites.length>=PE_CALL_LIMITS.sites)fail(`more than ${PE_CALL_LIMITS.sites} import call sites.`);sites.push(site);};
  for(const {s,code} of sections){
   for(let p=code.indexOf(0xff);p>=0;p=code.indexOf(0xff,p+1)){
    if(options.signal?.aborted)fail('cancelled.');
    const decoded=indirectAt(code,p,s.virtualAddress,metadata.machine,imageBase);if(!decoded)continue;const slot=slots.get(decoded.slotRva);if(!slot)continue;
    const rex=metadata.machine===0x8664&&p>0&&code[p-1]===0x48;
    const site:PeCallSite={instructionRva:s.virtualAddress+p,instructionEndRva:s.virtualAddress+p+6,fileOffset:s.rawOffset+p,form:decoded.form,bytes:code.subarray(p,p+6).toString('hex'),...(rex?{precedingByteRexW:true}:{}),slotRva:decoded.slotRva,slot};
    // A call may target a jump thunk at the opcode or at its REX.W prefix.
    push(site);if(site.form==='jump-indirect'){thunks.set(site.instructionRva,site);if(rex)thunks.set(site.instructionRva-1,site);}
   }
  }
  // call rel32 whose target is one of the jump thunks found above.
  if(thunks.size)for(const {s,code} of sections){
   for(let p=code.indexOf(0xe8);p>=0;p=code.indexOf(0xe8,p+1)){
    if(p+5>code.length)break;if(options.signal?.aborted)fail('cancelled.');
    const target=s.virtualAddress+p+5+code.readInt32LE(p+1),thunk=thunks.get(target);if(!thunk)continue;
    push({instructionRva:s.virtualAddress+p,instructionEndRva:s.virtualAddress+p+5,fileOffset:s.rawOffset+p,form:'call-via-thunk',bytes:code.subarray(p,p+5).toString('hex'),slotRva:thunk.slotRva,thunkRva:target,slot:thunk.slot});
   }
  }
 }finally{await handle.close();}
 sites.sort((a,b)=>a.instructionRva-b.instructionRva);
 return{metadata,architecture,sites,scannedBytes,status:'byte-pattern-candidates' as const};
}

// Decodes exactly one instruction at an RVA taken from real code evidence (a disassembler or
// decompiler record), following at most one call into a jump thunk.
export async function decodePeImportCall(file:string,instructionRva:number,options:{signal?:AbortSignal;metadata?:PeMetadata}={}){
 if(!Number.isSafeInteger(instructionRva)||instructionRva<0||instructionRva>0xffffffff)fail('instructionRva must be a 32-bit RVA.');
 const metadata=options.metadata??await readPeLoader(file,options);if(!supported.has(metadata.machine))fail(`machine ${metadata.machineName} is not supported; x86 and x86-64 only.`);
 const slots=slotMap(metadata),imageBase=BigInt(metadata.imageBase),handle=await open(file,'r');
 try{
  const size=(await handle.stat()).size;
  const bytesAt=async(rva:number,length:number)=>{
   const s=sectionOf(metadata,rva);if(!s||!executable(s.characteristics))fail(`RVA 0x${rva.toString(16)} is not in an executable section.`);
   const offset=s!.rawOffset+(rva-s!.virtualAddress);if(rva-s!.virtualAddress+length>s!.rawSize||offset+length>size)fail(`RVA 0x${rva.toString(16)} is not backed by file data.`);
   const data=Buffer.alloc(length);await handle.read(data,0,length,offset);return{data,offset};
  };
  const indirect=async(rva:number)=>{
   const first=await bytesAt(rva,1),rex=metadata.machine===0x8664&&first.data[0]===0x48,skip=rex?1:0;
   const s=sectionOf(metadata,rva)!;if(rva-s.virtualAddress+6+skip>s.rawSize)return null;
   const {data,offset}=await bytesAt(rva,6+skip);
   const decoded=indirectAt(data,skip,rva,metadata.machine,imageBase);if(!decoded)return null;
   const slot=slots.get(decoded.slotRva);if(!slot)fail(`instruction at RVA 0x${rva.toString(16)} reads 0x${decoded.slotRva.toString(16)}, which is not an import address table slot.`);
   return{instructionRva:rva,instructionEndRva:rva+6+skip,fileOffset:offset,form:decoded.form,bytes:data.subarray(0,6+skip).toString('hex'),...(rex?{rexW:true}:{}),slotRva:decoded.slotRva,slot:slot!};
  };
  const direct=await indirect(instructionRva);if(direct)return direct as PeCallSite;
  const {data,offset}=await bytesAt(instructionRva,5);
  if(data[0]!==0xe8)fail(`instruction at RVA 0x${instructionRva.toString(16)} is not call/jmp through an import slot or call rel32 (bytes ${data.toString('hex')}).`);
  const thunkRva=instructionRva+5+data.readInt32LE(1),thunk=await indirect(thunkRva);
  if(!thunk||thunk.form!=='jump-indirect')fail(`call rel32 at RVA 0x${instructionRva.toString(16)} targets 0x${thunkRva.toString(16)}, which is not a jump through an import slot.`);
  return{instructionRva,instructionEndRva:instructionRva+5,fileOffset:offset,form:'call-via-thunk',bytes:data.toString('hex'),slotRva:thunk!.slotRva,thunkRva,slot:thunk!.slot} as PeCallSite;
 }finally{await handle.close();}
}

const parser=async()=>({parserSha256:digest(await readFile(fileURLToPath(import.meta.url)))});
type View='summary'|'sites'|'apis';
export async function inspectPeImportCalls(workspace:string,options:{file:string;view?:View;offset?:number;limit?:number;budgetBytes?:number;signal?:AbortSignal}){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,budget=responseBudget(options.budgetBytes);
 if(!['summary','sites','apis'].includes(view))throw new Error('Use view summary, sites or apis.');
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use page limit 1–100 and a nonnegative offset.');
 const root=await realpath(workspace),target=await indexedFile(root,options.file,options.signal),scan=await readPeImportCalls(target.path,{signal:options.signal});
 if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while scanning import calls.');
 const provider={name:'carve-pe-import-calls',version:'1',...await parser()};
 const apis=new Map<string,{module:string;importKind:string;name?:string;ordinal?:number;slotRva:number;sites:number}>();
 for(const module of scan.metadata.imports)for(const entry of module.entries)apis.set(`${entry.thunkRva}`,{module:module.name,importKind:module.kind,...(entry.name!==undefined?{name:entry.name}:{ordinal:entry.ordinal}),slotRva:entry.thunkRva,sites:0});
 for(const site of scan.sites)apis.get(`${site.slotRva}`)!.sites++;
 const detail={kind:'native-import-calls',name:`PE ${scan.architecture??scan.metadata.machineName} import call-site candidates`,address:'file:0',provider,status:scan.status,scannedBytes:scan.scannedBytes,sites:scan.sites};
 const id=digest(JSON.stringify({file:options.file,sha256:target.sha256,detail})),evidence=path.join(root,'loader-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/pe-import-calls-evidence@1',file:options.file,sourceSha256:target.sha256,...detail},null,2)+'\n';
 await publishEvidence(evidence,text);
 const db=openIndex(root);
 try{recordObservation(db,{id,file:options.file,sha256:target.sha256,detail,searchText:JSON.stringify([...apis.values()].filter(a=>a.sites).map(a=>`${a.module}!${a.name??'#'+a.ordinal}`)),evidence,evidenceSha256:digest(text)});}finally{db.close();}
 const forms={'call-indirect':0,'jump-indirect':0,'call-via-thunk':0};for(const site of scan.sites)forms[site.form]++;
 const all=[...apis.values()];
 const base={schema:'carve/pe-import-calls@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),
  status:scan.status,architecture:scan.architecture,scannedBytes:scan.scannedBytes,counts:{sites:scan.sites.length,...forms,imports:all.length,importsWithSites:all.filter(a=>a.sites).length},view,
  scope:'Byte patterns in executable sections whose operand is exactly an import address table slot: call/jmp [slot] and call rel32 into such a jmp thunk. Candidates, not disassembly; verify one instruction address from real code evidence with the bridge. Register-indirect calls (mov reg,[slot]; call reg), GetProcAddress, COM vtables and runtime loading are not found. Import names come from the declared tables only.'};
 const rows:{value:unknown}[]=view==='sites'?scan.sites.map(s=>({value:{instructionRva:s.instructionRva,instructionEndRva:s.instructionEndRva,form:s.form,bytes:s.bytes,...(s.precedingByteRexW?{precedingByteRexW:true}:{}),slotRva:s.slotRva,...(s.thunkRva!==undefined?{thunkRva:s.thunkRva}:{}),module:s.slot.module,...(s.slot.name!==undefined?{name:s.slot.name}:{ordinal:s.slot.ordinal})}}))
  :view==='apis'?all.sort((a,b)=>a.module.localeCompare(b.module)||(a.name??'').localeCompare(b.name??'')||(a.ordinal??0)-(b.ordinal??0)).map(a=>({value:a})):[];
 if(view!=='summary'&&rows.length&&offset>=rows.length)throw new Error(`Use an offset below ${rows.length} for view ${view}.`);
 return budgetItems({...base,total:rows.length,offset},rows.slice(offset,offset+limit),budget);
}

// Byte-bound static link from one verified caller instruction to the export it imports in a
// same-named library file of the same inventory. It proves the declared tables agree; it does not
// prove which DLL Windows would load (search order, KnownDLLs, manifests, API sets) or ABI.
export async function bridgePeImportCall(workspace:string,options:{caller:{file:string;instructionRva:number};library?:{file:string};signal?:AbortSignal}){
 const root=await realpath(workspace),caller=await indexedFile(root,options.caller.file,options.signal);
 const callerMetadata=await readPeLoader(caller.path,{signal:options.signal});
 const site=await decodePeImportCall(caller.path,options.caller.instructionRva,{signal:options.signal,metadata:callerMetadata});
 let library:null|{file:string;sourceSha256:string;exportName:string|null;export:{ordinal:number;rva:number;names:string[];forwarder?:string}}=null;
 if(options.library){
  if(path.basename(options.library.file).toLowerCase()!==site.slot.module.toLowerCase())throw new Error(`Library ${options.library.file} does not have the imported module name ${site.slot.module}.`);
  const indexed=await indexedFile(root,options.library.file,options.signal),metadata=await readPeLoader(indexed.path,{signal:options.signal});
  const entries=metadata.exports?.entries??[];
  const found=site.slot.name!==undefined?entries.find(e=>e.names.includes(site.slot.name!)):entries.find(e=>e.ordinal===site.slot.ordinal);
  if(!found)throw new Error(`${options.library.file} does not export ${site.slot.name??'ordinal '+site.slot.ordinal}.`);
  if((await hashFile(indexed.path,options.signal)).sha256!==indexed.sha256)throw new Error('Library changed while reading its export table.');
  library={file:options.library.file,sourceSha256:indexed.sha256,exportName:metadata.exports?.name??null,export:found};
 }
 if((await hashFile(caller.path,options.signal)).sha256!==caller.sha256)throw new Error('Caller changed while decoding the import call.');
 const provider={name:'carve-pe-import-bridge',version:'1',...await parser()};
 const witness={caller:{file:options.caller.file,sourceSha256:caller.sha256,machine:callerMetadata.machineName,instruction:{rva:site.instructionRva,endRva:site.instructionEndRva,fileOffset:site.fileOffset,form:site.form,bytes:site.bytes,sha256:digest(Buffer.from(site.bytes,'hex'))},...(site.thunkRva!==undefined?{thunkRva:site.thunkRva}:{})},
  import:{slotRva:site.slotRva,descriptorRva:site.slot.descriptorRva,module:site.slot.module,importKind:site.slot.importKind,...(site.slot.name!==undefined?{name:site.slot.name,hint:site.slot.hint}:{ordinal:site.slot.ordinal})},library};
 const status=library?(library.export.forwarder?'byte-bound-static-import-forwarded':'byte-bound-static-import'):'import-resolved-library-not-selected';
 const detail={kind:'native-import-bridge',name:`${site.slot.module}!${site.slot.name??'#'+site.slot.ordinal} from RVA 0x${site.instructionRva.toString(16)}`,address:'rva:0x'+site.instructionRva.toString(16),provider,status,witness};
 const id=digest(JSON.stringify({file:options.caller.file,sha256:caller.sha256,detail})),evidence=path.join(root,'loader-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/pe-import-bridge-evidence@1',...detail},null,2)+'\n';
 await publishEvidence(evidence,text);
 const db=openIndex(root);
 try{recordObservation(db,{id,file:options.caller.file,sha256:caller.sha256,detail,searchText:detail.name,evidence,evidenceSha256:digest(text)});}finally{db.close();}
 return{schema:'carve/pe-import-bridge@1',workspace:root,observationId:id,evidence,evidenceSha256:digest(text),executesTarget:false,provider,status,witness,
  resolution:library?'same-name-inventory-file':'not-evaluated',runtimeLoading:'unverified',semanticMatch:'unconfirmed',
  scope:'Declared tables only: the caller instruction bytes read this import address table slot, the slot belongs to this import descriptor, and the selected same-name library exports this name or ordinal. Windows search order, KnownDLLs, side-by-side manifests, API-set mapping, forwarder targets, binding and ABI are not evaluated.'};
}
