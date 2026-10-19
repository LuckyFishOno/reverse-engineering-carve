import {sequenceExampleSchema,recordedSequenceExample} from './sequence.js';
import path from 'node:path';
import {lstat,readFile,writeFile} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import {z} from 'zod';
import {digest} from './artifact.js';
import {hashFile} from './survey.js';

const scope=z.enum(['selected-original-cli-cases','declared-external-harness-cases','selected-dex-android-harness-cases','selected-original-cli-sequences','declared-external-harness-sequences','selected-dex-android-harness-sequences']);
const sha=z.string().regex(/^[a-f0-9]{64}$/);
const receiptSchema=z.object({schema:z.literal('carve/reconstruction-verification-summary@1'),manifestSha256:sha,reportSha256:sha,reportBytes:z.number().int().min(1).max(512*1024*1024),status:z.enum(['passed-supplied-cases','failed']),checkedAt:z.string().min(1).max(100),scope,passed:z.number().int().min(0).max(200),total:z.number().int().min(1).max(200),analysisWarningCount:z.number().int().min(1).max(8000).optional(),comparisonMode:z.literal('stateful-sequences').optional(),totalSteps:z.number().int().min(1).max(1000).optional(),passedSteps:z.number().int().min(0).max(1000).optional(),exampleSequence:sequenceExampleSchema.optional(),example:z.object({args:z.array(z.unknown()),expected:z.unknown()}).strict().nullable()}).strict();
function validate(value:unknown){JSON.stringify(value,(_key,v)=>{if(typeof v==='number'&&!Number.isFinite(v))throw new Error('Non-finite receipt.');return v;});}

export async function saveVerificationReport(root:string,report:Record<string,any>){
 const text=JSON.stringify(report,null,2)+'\n';let example:{args:unknown[];expected:unknown}|null=null;
 for(const row of report.results??[])if(row.passed===true&&Array.isArray(row.args)&&row.original?.kind==='return'&&row.candidate?.kind==='return'&&isDeepStrictEqual(row.original.value,row.candidate.value)){
  const candidate={args:row.args,expected:row.original.value};if(Buffer.byteLength(JSON.stringify(candidate))<=4096){example=candidate;break;}
 }
 const receipt={schema:'carve/reconstruction-verification-summary@1',manifestSha256:report.manifestSha256,reportSha256:digest(text),reportBytes:Buffer.byteLength(text),status:report.status,checkedAt:report.checkedAt,scope:report.verifiedScope,passed:report.passed,total:report.total,...(report.analysisWarningCount?{analysisWarningCount:report.analysisWarningCount}:{}),...(report.comparisonMode==='stateful-sequences'?{comparisonMode:report.comparisonMode,totalSteps:report.totalSteps,passedSteps:report.passedSteps,exampleSequence:recordedSequenceExample(report)}:{}),example};
 await writeFile(path.join(root,'carve.verification.json'),text);
 await writeFile(path.join(root,'carve.verification-summary.json'),JSON.stringify(receipt,null,2)+'\n');
}

export async function readVerificationSummary(root:string,manifestSha256:string){
 const file=path.join(root,'carve.verification-summary.json'),info=await lstat(file);
 if(!info.isFile()||info.size>65536)throw new Error('Invalid or oversized verification summary.');
 const text=await readFile(file,'utf8');if(Buffer.byteLength(text)>65536)throw new Error('Oversized verification summary.');const receipt=receiptSchema.parse(JSON.parse(text));validate(receipt);
 if(receipt.manifestSha256!==manifestSha256||receipt.passed>receipt.total||(receipt.status==='passed-supplied-cases')!==(receipt.passed===receipt.total))throw new Error('Unbound or inconsistent verification summary.');
 if(receipt.example&&(!Object.hasOwn(receipt.example,'expected')||Buffer.byteLength(JSON.stringify(receipt.example))>4096))throw new Error('Invalid verification example.');
 if(receipt.comparisonMode==='stateful-sequences'&&(receipt.totalSteps===undefined||receipt.passedSteps===undefined||receipt.passedSteps>receipt.totalSteps||receipt.example!==null||receipt.exampleSequence&&(receipt.exampleSequence.calls.length!==receipt.exampleSequence.outcomes.length||Buffer.byteLength(JSON.stringify(receipt.exampleSequence))>4096)))throw new Error('Invalid sequence verification summary.');
 const sequenceScope=receipt.scope.endsWith('-sequences');
 if(sequenceScope!==(receipt.comparisonMode==='stateful-sequences')||sequenceScope&&(receipt.totalSteps!<receipt.total||(receipt.status==='passed-supplied-cases')!==(receipt.passedSteps===receipt.totalSteps)))throw new Error('Inconsistent sequence scope/counters.');
 const report=path.join(root,'carve.verification.json'),reportInfo=await lstat(report);if(!reportInfo.isFile()||reportInfo.size!==receipt.reportBytes)throw new Error('Verification report size changed.');
 const current=await hashFile(report);if(current.sha256!==receipt.reportSha256||current.bytes!==receipt.reportBytes)throw new Error('Verification report checksum changed.');
 return{verification:{status:receipt.status,checkedAt:receipt.checkedAt,scope:receipt.scope,passed:receipt.passed,total:receipt.total,reportSha256:receipt.reportSha256,reportBytes:receipt.reportBytes,preview:'checksum-bound-summary',...(receipt.analysisWarningCount?{analysisWarningCount:receipt.analysisWarningCount}:{}),...(receipt.comparisonMode?{comparisonMode:receipt.comparisonMode,totalSteps:receipt.totalSteps,passedSteps:receipt.passedSteps}:{}),authority:'Recorded local summary with freshly checked report checksum; counters are not independently rederived or authenticated.'},exampleSequence:receipt.status==='passed-supplied-cases'?receipt.exampleSequence:undefined,example:receipt.status==='passed-supplied-cases'&&receipt.example?{...receipt.example,origin:'recorded-reference-comparison',scope:receipt.scope}:undefined};
}
