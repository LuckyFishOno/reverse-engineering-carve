import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,realpath,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {buildUiPe} from './fixtures/pe-ui-image.mjs';
import {importPeFunction} from './fixtures/pe-ui-rea.mjs';
import {survey} from '../dist/survey.js';
import {inspectPeUi} from '../dist/pe-ui.js';
import {decodeResourceArgumentPrefix,PE_RESOURCE_API_LIMITS} from '../dist/pe-resource-api.js';
import {decodeResourceArgumentPrefix32} from '../dist/pe-resource-api-x86.js';

async function fixture(t,{prefix='4883ec284c8d442420bae90300004531c9',api='LoadStringW',module='user32.dll',plus=true,length=100,unresolved=false}={}){
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-resource-api-')));t.after(()=>rm(root,{recursive:true,force:true}));const input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const before=Buffer.from(prefix,'hex'),callRva=0x8010+before.length,base=plus?0x140000000n:0x400000n,va=r=>'0x'+(base+BigInt(r)).toString(16);
 const built=buildUiPe({plus,imports:[{name:module,entries:[api]}],code:({slot,imageBase})=>{const b=Buffer.alloc(384,0xc3);before.copy(b,16);b[16+before.length]=0xff;b[17+before.length]=0x15;const rva=slot(module+'!'+api);plus?b.writeInt32LE(rva-callRva-6,18+before.length):b.writeUInt32LE(Number(imageBase)+rva,18+before.length);return b;}});
 await writeFile(path.join(input,'app.exe'),built.bytes);await survey(input,{workspace});const fn=await importPeFunction(root,workspace,'app.exe',built.bytes,{address:va(0x8010),length,calls:unresolved?[]:[{site:va(callRva),target:'EXTERNAL:0x1',indirect:true}],unresolved:unresolved?[{address:va(callRva),reason:'Synthetic decoder-identified call without destination'}]:[]});
 const inspect=()=>inspectPeUi(workspace,{file:'app.exe',view:'dependencies',command:1001,functionIds:[fn.observationId],limit:100,budgetBytes:65536});return {root,workspace,fn,inspect};
}
test('byte-bound x64 API arguments identify a string-table candidate without binding module, language or runtime use',async t=>{
 const f=await fixture(t),r=await f.inspect(),row=r.items.find(r=>r.resourceApi),api=row.resourceApi;
 assert.equal(api.status,'caller-image-candidates');assert.deepEqual(api.resourceRequest,{type:6,name:63,stringId:1001,stringIndex:9});assert.equal(api.arguments.rdx,'0x3e9');assert.equal(api.arguments.rcx,null);assert.equal(api.moduleBinding,'unverified');assert.equal(api.languageSelection,'unverified');assert.equal(api.runtimeUse,'unverified');assert.equal(api.prefix.complete,true);assert.deepEqual(api.candidates[0].resource,[6,63,1033]);assert.ok(row.nextSteps.some(s=>s.action==='review-resource-api'));assert.equal(r.counts.byResourceApiStatus['caller-image-candidates'],1);
 const report=JSON.parse(await readFile(r.dependencyEvidence,'utf8'));assert.equal(report.rows.find(r=>r.resourceApi).resourceApi.prefix.instructions.length,4);
});
test('register copies and zero extension are decoded; unsupported instructions discard argument conclusions',()=>{
 const decoded=decodeResourceArgumentPrefix(Buffer.from('48b8ffffffffffffffff89c2','hex'));assert.equal(decoded.arguments.rdx,'0xffffffff');
 for(const bytes of ['bae9030000eb00','bae9030000e800000000','bae90300000fb6c0','ba0100','4889c4','41ba01000000418bd2']){
  const r=decodeResourceArgumentPrefix(Buffer.from(bytes,'hex'));if(bytes==='41ba01000000418bd2'){assert.equal(r.complete,true);assert.equal(r.arguments.rdx,'0x1');}else{assert.equal(r.complete,false);assert.equal(r.arguments,null);}
 }
 assert.equal(decodeResourceArgumentPrefix(Buffer.alloc(65,0x90)).reason,'instruction-limit');
});
test('branches, preceding calls, dynamic IDs, pointers and non-ABI register assignments remain unresolved',async t=>{
 for(const options of [{prefix:'bae9030000eb00'},{prefix:'e800000000bae9030000'},{prefix:'4883ec28'},{prefix:'48ba0000400100000000'},{plus:false,prefix:'bae9030000'}]){
  const f=await fixture(t,options),r=await f.inspect(),api=r.items.find(r=>r.resourceApi)?.resourceApi;assert.ok(api);assert.equal(api.status,'arguments-unresolved');assert.equal(api.candidatesTotal,0);
 }
});
test('FindResourceEx parameter order is explicit and requested language never silently selects a loaded resource',async t=>{
 const f=await fixture(t,{module:'kernel32.dll',api:'FindResourceExW',prefix:'ba0600000041b83f00000041b904040000'}),api=(await f.inspect()).items.find(r=>r.resourceApi).resourceApi;
 assert.deepEqual(api.resourceRequest,{type:6,name:63});assert.equal(api.requestedLanguage,1028);assert.equal(api.candidates[0].requestedLanguageMatches,false);assert.equal(api.languageSelection,'unverified');
 const menu=await fixture(t,{api:'LoadMenuW',prefix:'ba65000000'});assert.deepEqual((await menu.inspect()).items.find(r=>r.resourceApi).resourceApi.resourceRequest,{type:4,name:101});
});
test('named API lookalikes, oversized entry prefixes and unproven instruction boundaries do not produce resolved resource requests',async t=>{
 const other=await fixture(t,{module:'other.dll'});assert.ok(!(await other.inspect()).items.some(r=>r.resourceApi));
 const long=await fixture(t,{prefix:'90'.repeat(257),length:280}),api=(await long.inspect()).items.find(r=>r.resourceApi).resourceApi;assert.equal(api.reason,'entry-prefix-outside-budget');assert.equal(api.candidatesTotal,0);
 const short=await fixture(t,{length:18});assert.ok(!(await short.inspect()).items.some(r=>r.resourceApi));
});

test('recorded unresolved call locations can carry byte-bound API leads without becoming resolved call edges',async t=>{
 const f=await fixture(t,{unresolved:true}),result=await f.inspect(),row=result.items.find(r=>r.kind==='unresolved-call');assert.equal(row.reason,'Synthetic decoder-identified call without destination');assert.equal(row.relationshipBasis,'recorded-unresolved-call-location');assert.equal(row.resourceApi.resourceRequest.stringId,1001);assert.equal(row.resourceApi.moduleBinding,'unverified');assert.ok(!result.items.some(r=>r.kind==='call-dependency'));assert.equal(result.dependencyClosure,'not-established');
});


test('x86 right-to-left pushes recover numeric resource IDs while keeping caller stack loads unknown',async t=>{
 const f=await fixture(t,{plus:false,prefix:'5089e06a005068e9030000ff742414'}),api=(await f.inspect()).items.find(r=>r.resourceApi).resourceApi;
 assert.equal(api.callingConvention,'x86-stack-arguments');assert.equal(api.arguments.stack0,null);assert.equal(api.arguments.stack1,'0x3e9');assert.equal(api.arguments.stack2,null);assert.equal(api.arguments.stack3,'0x0');assert.equal(api.resourceRequest.stringId,1001);assert.equal(api.moduleBinding,'unverified');
 const find=await fixture(t,{plus:false,module:'kernel32.dll',api:'FindResourceExW',prefix:'68090400006a3f6a0653'}),request=(await find.inspect()).items.find(r=>r.resourceApi).resourceApi;assert.deepEqual(request.resourceRequest,{type:6,name:63});assert.equal(request.requestedLanguage,1033);assert.equal(request.candidates[0].requestedLanguageMatches,true);
});
test('x86 stack tracking preserves pushed values across register changes and handles signed pushes, pops and stack adjustments',()=>{
 const decode=hex=>decodeResourceArgumentPrefix32(Buffer.from(hex,'hex'),PE_RESOURCE_API_LIMITS);
 assert.equal(decode('680000000068e9030000585053').arguments.stack1,'0x3e9');
 assert.equal(decode('b8e90300005031c053').arguments.stack1,'0x3e9');
 assert.equal(decode('6aff').arguments.stack0,'0xffffffff');
 assert.equal(decode('680000000068e903000083c40453').arguments.stack1,'0x0');
 assert.equal(decode('bae90300008b14245253').arguments.stack1,null);
 assert.equal(decode('81ec0001000050').reason,'stack-limit');
});
test('x86 memory writes, alignment changes, branches, calls and truncated operands discard stack argument conclusions',()=>{
 for(const hex of ['68e9030000c7042465000000','68e9030000eb00','68e9030000e800000000','83e4f0','41','680102','ff7424','8d4424','5c','83ec03']){
  const result=decodeResourceArgumentPrefix32(Buffer.from(hex,'hex'),PE_RESOURCE_API_LIMITS);assert.equal(result.complete,false,hex);assert.equal(result.arguments,null,hex);
 }
});
