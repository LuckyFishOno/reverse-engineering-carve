import assert from 'node:assert/strict';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,mkdtemp,readFile,writeFile,cp,chmod,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StdioClientTransport} from '@modelcontextprotocol/sdk/client/stdio.js';
import {reverseTask} from '../dist/reverse.js';
import {hashFile} from '../dist/survey.js';
import {nativeAnalysis,searchObservations,readObservation} from '../dist/native.js';
import {traceBoundary} from '../dist/trace.js';
import {reconstruct,verifyReconstruction} from '../dist/reconstruction.js';
import {invoke,packageUsage} from '../dist/runtime.js';
import {readEngineConfiguration} from '../dist/engine-config.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('The pinned jq reference executable is macOS arm64.');
const enginesFile=process.argv[2]??path.join(root,'artifacts/engines/config.json');const engines=await readEngineConfiguration(enginesFile);
const version='jq-1.8.2',sha256='2d75340ba57a4b4b4c8708a21c2dc8e958a48aaa8bba13b27f77f6e4c0eca07e';
const url=`https://github.com/jqlang/jq/releases/download/${version}/jq-macos-arm64`;
const upstream=path.join(root,'artifacts/third-party',version);await mkdir(upstream,{recursive:true});const cached=path.join(upstream,'jq-macos-arm64');
try{await readFile(cached);}catch(error){if(error.code!=='ENOENT')throw error;const response=await fetch(url);if(!response.ok)throw new Error('Official jq release download failed');await writeFile(cached,Buffer.from(await response.arrayBuffer()));}
assert.equal((await hashFile(cached)).sha256,sha256,'official pinned release digest');
const license=path.join(upstream,'COPYING');try{await readFile(license);}catch(error){if(error.code!=='ENOENT')throw error;const response=await fetch(`https://raw.githubusercontent.com/jqlang/jq/${version}/COPYING`);if(!response.ok)throw new Error('jq license download failed');await writeFile(license,await response.text());}
const out=await mkdtemp(path.join(root,'artifacts/jq-e2e-'));const input=path.join(out,'input');await mkdir(input);const binary=path.join(input,'jq');await cp(cached,binary);await chmod(binary,0o700);
const task=await reverseTask(binary,{goal:'Extract UTF8 byte length from the shipped native jq program; locate the builtin through static evidence, distinguish codepoint length, and compare with the original executable.',out:path.join(out,'work')});
const workspace=task.workspace;const provider={file:'jq',ghidra:engines.ghidra,javaHome:engines.javaHome};
const client=new Client({name:'carve-jq-integration',version:'1'});const transport=new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve','--root',out,'--engines',enginesFile],stderr:'pipe'});await client.connect(transport);
const call=async(name,args)=>{const response=await client.callTool({name,arguments:args},undefined,{timeout:1200000});if(response.isError)throw new Error(response.content[0].text);return JSON.parse(response.content[0].text);};
const analyses=[];let string,window,selected,helper,graph;
async function observation(id){
 let first,offset=0;const parts=[];
 while(true){const page=await readObservation(workspace,id,offset);first??=page;parts.push(page.text);if(page.nextOffset===null)break;offset=page.nextOffset;if(offset>1048576)throw new Error('Selected observation exceeds this fixture reader budget.');}
 return{...first,text:parts.join(''),nextOffset:null};
}
try{
 analyses.push(await call('carve_native',{workspace:'work',file:'jq',strings:'utf8bytelength',limit:10,timeoutMs:1200000}));
 string=await observation(analyses.at(-1).observationIds[0]);assert.equal(string.kind,'string','feature-name bytes found');
 const page=await call('carve_native',{workspace:'work',file:'jq',strings:'',limit:1});assert.equal(page.observationIds.length,1);assert.ok(page.summary.nextAddress);
 const next=await call('carve_native',{workspace:'work',file:'jq',strings:'',limit:1,after:page.summary.nextAddress});assert.equal(next.observationIds.length,1);assert.notEqual((await observation(page.observationIds[0])).address,(await observation(next.observationIds[0])).address);analyses.push(page,next);
 const reference=string.references.find(r=>r.type==='DATA'&&!r.functionAddress);assert.ok(reference,'data-only registration reference, not a direct call');
 // A reviewed layout hypothesis from the observed repeated table: fn/name/arity, 24-byte records.
 // Inspect surrounding entries before selecting; proximity alone is not semantic confirmation.
 const start=(BigInt('0x'+reference.address)-32n).toString(16);
 analyses.push(await call('carve_native',{workspace:'work',file:'jq',window:start,bytes:128}));assert.equal(analyses.at(-1).reusedAnalysis,true);
 window=await observation(analyses.at(-1).observationIds[0]);assert.equal(window.kind,'data-window');
 const data=JSON.parse(window.text);assert.equal(data.pointerSize,8);assert.equal(data.byteOrder,'little');
 const label=data.pointers.find(p=>p.targetText==='utf8bytelength');assert.equal(label.address,reference.address);
 const slot=(BigInt('0x'+label.address)-8n).toString(16);const fn=data.pointers.find(p=>p.address===slot&&p.targetFunctionAddress&&!p.thunk);assert.ok(fn,'reviewed function slot');
 const position=Number(BigInt('0x'+slot)-BigInt('0x'+start));assert.equal(Buffer.from(data.hex,'hex').readBigUInt64LE(position+16),1n,'registration arity field');
 const nearby=data.pointers.filter(p=>p.targetText).map(p=>p.targetText);assert.ok(nearby.includes('length')&&nearby.includes('type'),'neighboring records corroborate the table layout');
 analyses.push(await call('carve_native',{workspace:'work',file:'jq',function:fn.targetFunctionAddress}));assert.equal(analyses.at(-1).status,'function-exported');
 selected=await observation(analyses.at(-1).observationIds[0]);assert.equal(selected.address,fn.targetFunctionAddress);
 const body=selected;assert.equal(body.decompilationStatus,'completed');
 // Follow observed callees, without a hardcoded implementation address.
 // The byte-length helper reads the jv string header and shifts its stored length flag.
 for(const callee of selected.callees.filter(c=>!c.external&&!/stack_chk/.test(c.name))){
  analyses.push(await nativeAnalysis(workspace,{...provider,function:callee.address}));
  for(const id of analyses.at(-1).observationIds){const observed=await observation(id);if(observed.address===callee.address&&observed.decompilationStatus==='completed'&&/return\s+\w+\s*>>\s*1/.test(observed.text)&&/\+ 8/.test(observed.text)&&observed.text.length<2000){helper=observed;break;}}
  if(helper)break;
 }
 assert.ok(helper,'code evidence follows the length header, not only the registration name');
 graph=await traceBoundary(workspace,string.id,{depth:3,maxNodes:40});assert.ok(graph.nodes.some(n=>n.id===window.id));assert.ok(graph.nodes.some(n=>n.address===fn.targetFunctionAddress));assert.equal(graph.semanticMatch,'unconfirmed');
 // An instruction window is another actual view of the selected machine code.
 analyses.push(await call('carve_native',{workspace:'work',file:'jq',window:helper.address,bytes:64}));
 const instructionWindow=await observation(analyses.at(-1).observationIds[0]);assert.equal(instructionWindow.kind,'data-window');assert.ok(JSON.parse(instructionWindow.text).instructions.length>0);
}finally{await client.close();}
const source=path.join(out,'source');await mkdir(source);const implementation=path.join(source,'length.mjs');await cp(path.join(root,'examples/native-app/jq-utf8-length.mjs'),implementation);await cp(license,path.join(source,'LICENSE'));await writeFile(path.join(source,'package.json'),JSON.stringify({name:'jq-utf8-length-reimplementation',version:'0.0.0',license:'MIT',private:true}));
const contract={schema:'carve/reconstruction@1',goal:'Independent UTF8 byte length from jq',file:'jq',evidenceIds:[selected.id,helper.id],supportingEvidenceIds:[string.id,window.id],
 behavior:{description:'Length of the UTF8 bytes representing the selected JSON string, including embedded NUL. Distinct from codepoint/grapheme/UTF16 length. jv memory representation and jq VM are replaced by an independent JSON-string contract.',inputDomain:'One well-formed Unicode string in a JSON positional args array; serialized input <=1MiB. Unpaired surrogates and non-string jq semantics are outside this contract.',outputDomain:'JSON integer byte count'},dependencies:[{name:'jq jv string representation and numeric result boxing',status:'reimplemented',detail:'The selected helper reads a stored UTF8 byte length; independent JS counts equivalent UTF8 bytes for the declared Unicode contract instead of copying jq VM state.'}],unknowns:['Other jq builtins, error behavior for nonstrings, malformed Unicode, raw invalid UTF8 input and jq integration outside this invocation remain unverified.','Only pinned macOS arm64 executable and supplied cases are compared; other targets/inputs are unknown.']};
const contractFile=path.join(out,'contract.json');await writeFile(contractFile,JSON.stringify(contract,null,2));const pkg=path.join(out,'utf8-tool');await reconstruct(workspace,{contract:contractFile,implementation,export:'utf8ByteLength',out:pkg});
// A later, differently paginated string export must not overwrite evidence already bound by a package.
const immutable=await readObservation(workspace,string.id);
analyses.push(await nativeAnalysis(workspace,{...provider,strings:'',limit:10000}));
const sameString=await nativeAnalysis(workspace,{...provider,strings:'utf8bytelength',limit:1});analyses.push(sameString);assert.ok(sameString.observationIds.includes(string.id),'identical observations keep a stable ID');
const retained=await readObservation(workspace,string.id);assert.equal(retained.evidenceSha256,immutable.evidenceSha256);assert.equal(retained.evidence,immutable.evidence);
const cases=[{name:'ASCII',args:['hello'],expected:5},{name:'empty',args:[''],expected:0},{name:'Chinese',args:['\u4f60\u597d'],expected:6},{name:'astral',args:['😀'],expected:4},{name:'combining',args:['e\u0301'],expected:3},{name:'embedded NUL',args:['a\0b'],expected:3},{name:'control and quoting',args:['\n\t\r"\\']},{name:'large BMP',args:['\u4e2d'.repeat(8192)]},{name:'large astral',args:['😀'.repeat(4096)]}];
let state=987654321;const random=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state;};
while(cases.length<160){let value='';const size=random()%80;for(let i=0;i<size;i++){let point=random()%0x110000;if(point>=0xd800&&point<=0xdfff)point+=0x800;value+=String.fromCodePoint(point);}cases.push({name:'Unicode sample '+cases.length,args:[value]});}
const casesFile=path.join(out,'cases.json');await writeFile(casesFile,JSON.stringify(cases,null,2));const referenceFile=path.join(out,'reference.json');
await writeFile(referenceFile,JSON.stringify({schema:'carve/reference@1',command:[binary,'-c','.[0] | utf8bytelength'],mode:'json-stdin',scope:'target-cli',description:'Actual original jq executable dispatches its utf8bytelength builtin on the first JSON argument; no recompiled reference algorithm.',boundFiles:[]},null,2));
const verification=await verifyReconstruction(workspace,{package:pkg,cases:casesFile,reference:referenceFile,execute:true});if(verification.status!=='passed-supplied-cases')console.error(JSON.stringify(verification.results.filter(r=>!r.passed).slice(0,5),null,2));assert.equal(verification.status,'passed-supplied-cases');assert.equal(verification.verifiedScope,'selected-original-cli-cases');
const exec=promisify(execFile);const contrast=await exec(binary,['-n','-c','["é","😀","é","a\\u0000b"] | map([utf8bytelength,length])']);
const distinction=JSON.parse(contrast.stdout);assert.deepEqual(distinction.slice(0,3),[[2,1],[4,1],[3,2]]);
await rm(input,{recursive:true});await rm(source,{recursive:true});
assert.deepEqual(await invoke(pkg,['a\0b'],{execute:true}),{kind:'return',value:3});const standalone=await exec(process.execPath,[path.join(pkg,'cli.mjs'),'["\u4f60\u597d"]']);assert.equal(JSON.parse(standalone.stdout),6);const usage=await packageUsage(pkg);assert.equal(usage.example.origin,'recorded-reference-comparison');
const capabilityClient=new Client({name:'carve-independent-jq-test',version:'1'});try{await capabilityClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(root,'dist/cli.js'),'serve-tool',pkg,'--execute'],stderr:'pipe'}));assert.deepEqual((await capabilityClient.callTool({name:'capability',arguments:{args:['😀']}})).structuredContent,{value:4});}finally{await capabilityClient.close();}
const report={schema:'carve/jq-native-e2e@1',status:'passed',checkedAt:new Date().toISOString(),out,upstream:{project:'jqlang/jq',version,url,sha256},analyses,location:{string,window,selectedFunction:selected,helper,graph,registrationLayout:{stride:24,functionOffset:0,nameOffset:8,arityOffset:16,authority:'Reviewed from observed table bytes/neighbors; not automatically inferred for arbitrary software.'}},verification,distinction,
 independence:{originalInvocationPathRemoved:true,reimplementationSourceRemoved:true,analysisSnapshotsRetained:true,cli:true,invoke:true,capabilityMcp:true},
 limitations:['One bounded builtin from a real stripped native release; not whole-program or arbitrary software reconstruction.','Ghidra pseudocode signatures/ABI are inferred; comparisons use the actual jq CLI boundary, not direct calls through an invented C ABI.','Registration layout was investigated/reviewed by the agent; generic automatic semantic localization and complete cross-binary closure remain unfinished.']};
const reportFile=path.join(out,'report.json');await writeFile(reportFile,JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/jq-verification-summary.json'),JSON.stringify({status:'passed',out,report:reportFile,cases:verification.total,originalExecutable:true,independent:true},null,2)+'\n');console.log(JSON.stringify({status:'passed',cases:verification.total,originalExecutable:true,independent:true,report:reportFile},null,2));
