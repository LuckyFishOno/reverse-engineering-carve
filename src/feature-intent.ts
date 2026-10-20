import {z} from 'zod';
import {behaviorSchema,behaviorSummary} from './behavior.js';
import {targetSpecSchema} from './target.js';

// Questions and literal-name filters only. They do not classify runtime behavior.
export const featureFacets:Record<string,{id:string;title:string;terms:string[];question:string}[]>={
 swipe:[
  {id:'direction',title:'Direction, distance and thresholds',terms:['direction','angle','distance','offset','threshold','percentage','geometry','\u65b9\u5411','\u9580\u6abb'],question:'Which coordinates or distance are supplied, and should the result be a direction, ratio or dismissal decision?'},
  {id:'interaction',title:'Gestures, card state and animation',terms:['gesture','pan','animation','drag','cardview','\u624b\u52e2','\u52d5\u756b'],question:'Which interaction states and animations are required? Include native UI or only state transitions?'},
  {id:'matching',title:'Matching and recommendations',terms:['match','recommend','ranking','score','\u914d\u5c0d','\u63a8\u85a6'],question:'Reuse local rules, process server responses, or investigate unavailable server decisions?'}],
 contact:[{id:'format',title:'Contact text formatting',terms:['vcard','encode','format','serialize','\u6587\u5b57'],question:'Which fields are supplied, and is the output serialized text or display content?'},{id:'storage',title:'Address book access',terms:['contacts','addressbook','store','permission','\u901a\u8a0a\u9304'],question:'Include address book permissions and device storage?'}],
 barcode:[{id:'payload',title:'Data and bit encoding',terms:['encode','decode','encoder','decoder','bitarray','payload'],question:'Return text or bits, or a complete barcode image?'},{id:'render',title:'Barcode image output',terms:['bitmap','matrix','render','writer','\u5716\u7247'],question:'Return pixels, vectors or a specified image format?'},{id:'scanner',title:'Camera scanning workflow',terms:['camera','capture','scan','preview','\u76f8\u6a5f'],question:'Include camera access, permissions, focus and continuous scanning state?'}],
 image:[{id:'transform',title:'Image transforms',terms:['resize','crop','transform','processor','filter','\u7e2e\u653e','\u88c1\u5207'],question:'What are the input/output formats and size constraints?'},{id:'fetch',title:'Image loading',terms:['fetch','download','loader','url','\u8f09\u5165'],question:'Does data come from local files or network services?'},{id:'cache',title:'Caching and invalidation',terms:['cache','expiry','disk','\u5feb\u53d6'],question:'Preserve caches across operations, processes or on disk?'}],
 archive:[{id:'metadata',title:'Archive catalog and metadata',terms:['catalog','entry','metadata','index','bootstrap'],question:'List or query entries, or also read their original content?'},{id:'content',title:'Compression and decompression',terms:['compress','inflate','deflate','unzip','extract','\u89e3\u58d3'],question:'Which formats, input sources and output file behaviors must be preserved?'}],
 media:[{id:'geometry',title:'Dimensions and aspect ratios',terms:['size','dimension','ratio','constraint','\u5c3a\u5bf8'],question:'How are dimensions, aspect ratio, alignment and limits specified?'},{id:'codec',title:'Codec core',terms:['codec','encoder','decoder','ffmpeg','\u7de8\u78bc'],question:'Does this require a specific codec, hardware or platform API?'},{id:'playback',title:'Playback and capture state',terms:['player','playback','capture','session','\u64ad\u653e'],question:'Which playback/capture states and device behaviors are required?'}],
 document:[{id:'format',title:'Text formatting and field conversion',terms:['escape','quote','format','serialize','parser','\u6b04\u4f4d'],question:'What are the input data and exact output format?'},{id:'render',title:'Document rendering and export',terms:['pdf','font','render','export','layout','\u5b57\u578b'],question:'Include fonts, layout and native export behavior?'}],
 chat:[{id:'format',title:'Message data processing',terms:['parser','format','serialize','message','\u8a0a\u606f'],question:'Transform message data, sort messages or parse specific content?'},{id:'display',title:'Conversation UI',terms:['view','cell','layout','conversation','\u756b\u9762'],question:'Include native UI or only presentation data?'},{id:'transport',title:'Sending and synchronization',terms:['send','sync','socket','transport','\u50b3\u9001'],question:'Are server, account and transport protocol references available?'}],
 crypto:[{id:'digest',title:'Hashes and checksums',terms:['hash','digest','checksum','adler32','\u96dc\u6e4a'],question:'What are the input bytes, incremental update and reset rules?'},{id:'codec',title:'Encoding and decoding',terms:['base64','encode','decode','codec','\u7de8\u78bc'],question:'What are the input/output character sets and byte formats?'}],
 notification:[{id:'event',title:'Notification event handling',terms:['handler','event','payload','callback','\u4e8b\u4ef6'],question:'Parse payloads, dispatch events or display notifications?'},{id:'delivery',title:'Push delivery workflow',terms:['push','delivery','messaging','token','\u63a8\u64ad'],question:'Include server delivery and platform registration? How will unavailable services be verified?'}]
};
export function featureFacet(choice?:string,facet?:string){
 if(facet===undefined)return undefined;
 const found=choice&&Object.hasOwn(featureFacets,choice)&&featureFacets[choice]!.find(f=>f.id===facet);
 if(!found)throw new Error('Choose a boundary facet returned for the selected feature choice.');return found;
}
const text=z.string().trim().min(1).max(2000),id=z.string().regex(/^[a-f0-9]{64}$/),boundary=z.enum(['excluded','required','unknown']);
export const featureRequestSchema=z.object({
 schema:z.literal('carve/feature-request@1'),origin:z.enum(['user-described','agent-proposed','test-fixture']).default('agent-proposed'),goal:text,choice:z.string().min(1).max(40).optional(),facet:z.string().min(1).max(40).optional(),
 target:targetSpecSchema.optional(),
 contract:behaviorSchema.optional(),
 behavior:z.object({trigger:text.optional(),input:text.optional(),output:text.optional(),state:z.enum(['stateless','sequence','unknown']).default('unknown')}).strict().default({state:'unknown'}),
 boundary:z.object({ui:boundary.default('unknown'),remote:boundary.default('unknown'),host:boundary.default('unknown')}).strict().default({ui:'unknown',remote:'unknown',host:'unknown'}),
 leads:z.array(z.object({workspace:z.string().min(1).max(4096).default('.'),file:z.string().min(1).max(4096),sourceSha256:id,observationId:id.optional()}).strict()).max(16).default([])
}).strict().superRefine((request,ctx)=>{
 if(request.choice&&!Object.hasOwn(featureFacets,request.choice))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Choose a returned feature category or omit choice for a custom request.'});
 if(request.facet&&(!Object.hasOwn(featureFacets,request.choice??'')||!featureFacets[request.choice??'']!.some(f=>f.id===request.facet)))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Facet must belong to the selected feature category.'});
});
export type FeatureRequest=z.infer<typeof featureRequestSchema>;
export function featureQuestions(request:FeatureRequest){
 const questions:{id:string;audience:'user'|'agent';prompt:string}[]=[];
 for(const [id,prompt] of [['trigger','Which operation or screen triggers this behavior?'],['input','What input is supplied? A synthetic example is sufficient.'],['output','What exact output is expected?']] as const)if(!request.behavior[id])questions.push({id,audience:'user',prompt});
 if(request.behavior.state==='unknown'&&(!request.contract||request.contract.lifecycle.lifetime==='unknown'))questions.push({id:'state',audience:'user',prompt:'Are calls independent, or do they require sequences, initialization and reset?'});
 for(const [id,prompt] of [['ui','Include UI, gestures and animations?'],['remote','Include remote decisions/transport or only local processing?'],['host','Include operating system, file/permission or hardware behavior?']] as const)if(request.boundary[id]==='unknown')questions.push({id,audience:'user',prompt});
 if(request.contract&&((request.behavior.state==='stateless'&&['session','persistent'].includes(request.contract.lifecycle.lifetime))||(request.behavior.state==='sequence'&&request.contract.lifecycle.lifetime==='independent')))questions.push({id:'state-contract-conflict',audience:'user',prompt:'The legacy state declaration and structured lifetime disagree. Clarify whether calls share a session or are independent.'});
 if(request.contract&&request.boundary.ui==='excluded'&&['events','stream'].includes(request.contract.interaction.mode))questions.push({id:'ui-contract-conflict',audience:'user',prompt:'The boundary excludes UI but the structured contract requires UI interaction. Choose the intended boundary.'});
 if(request.contract&&behaviorSummary(request.contract).status==='needs-clarification')questions.push({id:'behavior-contract',audience:'user',prompt:'Resolve the structured behavior declarations and scenario coverage using carve_behavior_check gaps view.'});
 if(!request.leads.length)questions.push({id:'leads',audience:'agent',prompt:'Select relevant components or observations from the current index. Continue investigating if none exist; never invent sources.'});
 return questions;
}
