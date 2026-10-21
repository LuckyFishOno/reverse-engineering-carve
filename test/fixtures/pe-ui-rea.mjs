import path from 'node:path';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {importReaNative} from '../../dist/rea-native.js';
const template=JSON.parse(await readFile(new URL('./rea-native-relationships.json',import.meta.url),'utf8')).records.feature_fee;
const hash=v=>createHash('sha256').update(v).digest('hex');
const canonical=v=>v===null||typeof v!=='object'?JSON.stringify(v):Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
const seal=r=>{const {evidence_id,subject,...rest}=r;r.evidence_id='ev_'+hash(canonical({subject:{digest:subject.digest,format:subject.format,architecture:subject.architecture},...rest}));};
// These commitments are synthetic validator fixtures, never actual REA execution claims.
export async function importPeFunction(root,workspace,file,bytes,{address,name='handler',length=16,calls=[],unresolved=[],preset='default',relationships=true,dataReference=false}={}){
 const records=structuredClone(template),entry='0x'+BigInt(address).toString(16);
 const body={available:true,provenance:'ghidra-function-body-address-set',ranges:[{start:entry,end:'0x'+(BigInt(entry)+BigInt(length-1)).toString(16)}],total_bytes:length,span_bytes:length,non_contiguous:false,contains_entry:true};
 const classification={external:false,thunk:false,thunk_target:null,provenance:'ghidra-function-manager'},identity={address:entry,name,classification,body};
 const architecture=bytes.readUInt16LE(0x44)===0x14c?'x86':'x86_64';
 for(const r of Object.values(records)){
  r.subject={...r.subject,name:'Synthetic PE dependency bytes',format:'pe',architecture,digest:{sha256:hash(bytes)}};
  Object.assign(r.analysis_profile.parameters,{target_format:'pe',architecture,available_architectures:[architecture],analyzer_preset:preset});r.analysis_profile.digest=hash(canonical({provider:r.analysis_profile.provider,parameters:r.analysis_profile.parameters}));
  r.parameters={procedure:entry,...(r.operation==='procedure_references'?{direction:'outgoing'}:{})};r.limitations=[];
 }
 const info=records.info.normalized_result;Object.assign(info,{entrypoint:entry,name,length,body,classification});records.info.raw_result={value:structuredClone(info),limitations:[]};
 const references=calls.map((c,i)=>({source_address:c.site,target_address:c.target,source_procedure:identity,target_procedure:null,kind:{available:true,provenance:'ghidra-reference-manager',type:'UNCONDITIONAL_CALL',flow:true,call:true,jump:false,data:false,read:false,write:false,indirect:Boolean(c.indirect),computed:Boolean(c.indirect),conditional:false,terminal:false,primary:true,operand_index:i,external:c.target.includes(':')}}));
 if(dataReference)references.push({source_address:entry,target_address:typeof dataReference==='object'?dataReference.target:'0x403000',source_procedure:identity,target_procedure:null,kind:{...references[0]?.kind,available:true,provenance:'ghidra-reference-manager',type:'DATA',flow:false,call:false,jump:false,data:true,read:typeof dataReference==='object'?dataReference.read:true,write:typeof dataReference==='object'?dataReference.write:false,indirect:false,computed:false,conditional:false,terminal:false,primary:true,operand_index:0,external:false}});
 const refValue={procedure:identity,direction:'outgoing',reference_kinds_available:true,references,unresolved_calls:unresolved};
 records.references.normalized_result=refValue;records.references.raw_result={value:structuredClone(refValue),limitations:[]};
 records.callees.normalized_result=[...new Set(calls.map(c=>c.target))];records.callees.raw_result={value:structuredClone(records.callees.normalized_result),limitations:[],relationship_coverage:records.callees.relationship_coverage};
 const files={};for(const [role,r] of Object.entries(records)){seal(r);const p=path.join(root,hash(file+address+preset+role)+'.json');await writeFile(p,JSON.stringify(r));if(relationships||role==='code'||role==='info')files[role]=p;}
 return importReaNative(workspace,{file,...files});
}
