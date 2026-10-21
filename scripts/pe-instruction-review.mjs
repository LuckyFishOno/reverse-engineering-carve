// Build explicit reviewed ABI declarations for the pinned integration targets only.
import assert from 'node:assert/strict';
import path from 'node:path';
import {mkdir,readFile,copyFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export async function peInstructionReview(out,metadata,record,observationId,abi,difference){
 const info=JSON.parse(await readFile(record.info,'utf8')).normalized_result;
 const folder=path.join(out,'work/instruction-evidence');await mkdir(folder,{recursive:true});
 const destination=path.join(folder,record.label+'.json');await copyFile(record.instructions,destination);
 const input=await readFile(path.join(out,'input',record.file));
 const bytes=info.body.ranges.map(range=>{
  const address=BigInt(range.start),rva=address-BigInt(metadata.imageBase),length=Number(BigInt(range.end)-address+1n);
  assert.ok(length>=1&&length<=256,'Integration review ranges require explicit bounded bodies');
  const sections=metadata.sections.filter(s=>rva>=BigInt(s.virtualAddress)&&rva+BigInt(length)<=BigInt(s.virtualAddress)+BigInt(s.rawSize));assert.equal(sections.length,1);
  const offset=sections[0].rawOffset+Number(rva-BigInt(sections[0].virtualAddress));
  return {address:range.start,length,sha256:sha(input.subarray(offset,offset+length))};
 });
 return {observationId,instructions:{file:'instruction-evidence/'+record.label+'.json',sha256:sha(await readFile(destination))},inferredSignature:info.signature,difference,abi,bytes};
}
