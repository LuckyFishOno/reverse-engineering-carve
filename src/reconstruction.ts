import path from 'node:path';
import { readFile, writeFile, stat, realpath, mkdtemp, mkdir, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isDeepStrictEqual } from 'node:util';
import { z } from 'zod';
import { hashFile } from './survey.js';
import { extract } from './extract.js';
import { digest } from './artifact.js';
import { readPackage } from './package.js';
import {sequenceCasesSchema,sequenceCalls,sequenceOutcome} from './sequence.js';
import { invoke,invokeSequence } from './runtime.js';
import { runReference } from './reference.js';
import { androidReferenceSchema, prepareAndroidReference } from './android.js';
import {saveVerificationReport} from './verification-receipt.js';
import {archiveVerificationReport} from './verification-archive.js';
import type {BridgePathAccess} from './rea-bridge.js';

import {reconstructionContract,bindReconstruction,assertReconstructionBinding,contractText as text,type WorkspaceAccess} from './reconstruction-contract.js';
const referenceFields={command:z.array(z.string().min(1).max(32768)).min(1).max(100),scope:z.enum(['target-cli','external-harness']),description:text,boundFiles:z.array(z.string().min(1)).max(100).default([])};
const referenceSchema=z.discriminatedUnion('schema',[
 z.object({schema:z.literal('carve/reference@1'),...referenceFields,mode:z.enum(['argv-values','json-stdin'])}).strict(),
 z.object({schema:z.literal('carve/reference@2'),...referenceFields,mode:z.enum(['argv-values','json-stdin','text-stdin','bytes-stdin']),output:z.enum(['json','utf8','bytes'])}).strict(),
 z.object({schema:z.literal('carve/reference@3'),...referenceFields,mode:z.literal('json-sequence-stdin')}).strict()
]);

export async function boundedJson(file:string){
  if((await stat(file)).size>1048576)throw new Error('JSON input exceeds 1 MiB.');const value=await readFile(file,'utf8');if(Buffer.byteLength(value)>1048576)throw new Error('JSON input exceeds 1 MiB.');
  const parsed=JSON.parse(value);const pending=[parsed];
  while(pending.length){const item=pending.pop();if(typeof item==='number'&&!Number.isFinite(item))throw new Error('JSON input contains a non-finite number.');if(item&&typeof item==='object')for(const child of Object.values(item))pending.push(child);}
  return{value:parsed,sha256:digest(value)};
}

export async function reconstruct(workspace:string,options:{contract:string;implementation:string;export:string;out:string;feature?:string;authorizeWorkspace?:WorkspaceAccess;authorizePath?:BridgePathAccess;signal?:AbortSignal}){
  const root=await realpath(workspace);const parsed=await boundedJson(options.contract);const contract=reconstructionContract.parse(parsed.value);
  const bound=await bindReconstruction(root,contract,options.authorizeWorkspace,options.signal,options.authorizePath);const {target,evidence}=bound;
  const result=await extract(options.implementation,{selector:{kind:'export',name:options.export},out:options.out,feature:options.feature});
  const incomplete=contract.dependencies.filter(d=>!['available','reimplemented'].includes(d.status));
  const analysisWarnings=bound.evidence.filter(e=>e.boundaryWarnings?.length).map(e=>({id:e.id,name:e.name,address:e.address,...(e.artifact?{artifact:e.artifact}:{}),boundaryWarnings:e.boundaryWarnings}));const analysisWarningCount=analysisWarnings.reduce((n,e)=>n+e.boundaryWarnings.length,0);
  const provenance={schema:contract.schema==='carve/reconstruction@2'?'carve/reconstruction-provenance@2':'carve/reconstruction-provenance@1',method:'agent-reimplementation',workspace:root,contract,contractSha256:parsed.sha256,
    original:bound.original,evidence,...(contract.schema==='carve/reconstruction@2'?{primary:contract.primary,artifacts:bound.artifacts,relationships:bound.relationships,unresolvedRelationships:bound.unresolvedRelationships}:{}),
    ...(analysisWarningCount?{analysisWarnings,analysisWarningCount}:{}),status:incomplete.length||contract.unknowns.length||bound.unresolvedRelationships.length||analysisWarningCount?'packaged-with-unknowns':'packaged-unverified',
    unresolvedDependencies:incomplete,behavioralVerification:'not-run',limitation:'Reimplementation based on static evidence. Neither original source recovery nor general behavior equivalence has been established.'};
  try{
    assertReconstructionBinding(provenance,await bindReconstruction(root,contract,options.authorizeWorkspace,options.signal,options.authorizePath));
    const manifest:any=result.manifest;manifest.extractionKind='behavior-reconstruction';manifest.reconstruction=provenance;
    const readme=`# Reconstructed capability\n\nGoal: ${contract.goal}\n\n${contract.behavior.description}\n\nInput domain: ${contract.behavior.inputDomain}\nOutput domain: ${contract.behavior.outputDomain}\n\nThis package contains an agent reimplementation based on ${target.facts.format} decompilation evidence. The manifest source/inputs describe the implementation used to build this package; reconstruction.original binds the primary analyzed binary; version2 also binds every declared artifact and relationship. Relationships are agent declarations anchored to evidence, not automatically resolved links. This is not a claim of recovered original source.\n\nRun \`node cli.mjs '[ARGS...]'\` or \`node cli.mjs --help\`. With Carve installed, \`carve use /path/to/package\` provides CLI commands and stdio MCP configuration. No original app is required to invoke the emitted implementation.\n\nStatus: ${provenance.status}. See carve.manifest.json for all dependencies, evidence and unknowns. No behaviors have been verified by packaging. Later verification results apply only to the explicitly supplied cases and reference scope.\n\nThe generated package is UNLICENSED; determine applicable rights before redistribution. Carve's MIT license does not relicense input code.\n`;
    await writeFile(path.join(result.out,'README.md'),readme);
    const entry=manifest.output.files.find((f:any)=>f.file==='README.md');entry.sha256=digest(readme);entry.bytes=Buffer.byteLength(readme);
    await writeFile(path.join(result.out,'carve.manifest.json'),JSON.stringify(manifest,null,2)+'\n');
    await readPackage(result.out);
    return{schema:'carve/reconstruction-package@1',out:result.out,status:provenance.status,original:provenance.original,...(contract.schema==='carve/reconstruction@2'?{artifacts:bound.artifacts,relationships:bound.relationships,unresolvedRelationships:bound.unresolvedRelationships}:{}),evidence,...(analysisWarningCount?{analysisWarnings,analysisWarningCount}:{}),unresolvedDependencies:incomplete,unknowns:contract.unknowns,verification:'not-run',nextAction:'Use verify-reconstruction with a trusted original invocation or explicitly scoped harness; then carve use for independent invocation.'};
  }catch(error){await rm(result.out,{recursive:true,force:true});throw error;}
}

export async function verifyReconstruction(workspace:string,options:{package:string;cases:string;reference:string;execute:boolean;timeoutMs?:number;signal?:AbortSignal;authorizeWorkspace?:WorkspaceAccess;authorizePath?:BridgePathAccess}){
  if(!options.execute)throw new Error('Verification executes the trusted reference and candidate. Pass --execute; reference execution uses user permissions.');
  const timeoutMs=options.timeoutMs??3000;if(!Number.isInteger(timeoutMs)||timeoutMs<50||timeoutMs>30000)throw new Error('timeoutMs must be between 50 and 30000.');
  const root=await realpath(workspace);const pkg=await readPackage(options.package);const provenance=pkg.manifest.reconstruction;
  if(pkg.manifest.extractionKind!=='behavior-reconstruction'||!['carve/reconstruction-provenance@1','carve/reconstruction-provenance@2'].includes(provenance?.schema))throw new Error('Choose a package created by reconstruct.');
  const contract=reconstructionContract.parse(provenance.contract);
  if((contract.schema==='carve/reconstruction@2')!==(provenance.schema==='carve/reconstruction-provenance@2'))throw new Error('Contract and reconstruction provenance versions differ.');
  const bound=await bindReconstruction(root,contract,options.authorizeWorkspace,options.signal,options.authorizePath);assertReconstructionBinding(provenance,bound);
  const raw=await boundedJson(options.cases);
  const refRaw=await boundedJson(options.reference);
  const androidConfig=['carve/android-reference@1','carve/android-reference@2','carve/android-reference@3','carve/android-reference@4'].includes(refRaw.value.schema)?androidReferenceSchema.parse(refRaw.value):undefined;
  const commandConfig=androidConfig?undefined:referenceSchema.parse(refRaw.value);
  const sequences=commandConfig?.schema==='carve/reference@3'||androidConfig?.schema==='carve/android-reference@4'?sequenceCasesSchema.parse(raw.value).cases:undefined;
  const cases=sequences?undefined:z.array(z.object({name:text,args:z.array(z.unknown()),expected:z.unknown().optional()}).strict()).min(1).max(200).parse(raw.value);
  const names=(sequences??cases!).map(c=>c.name);if(new Set(names).size!==names.length)throw new Error('Case names must be unique.');
  if(sequences){
    if(sequences.reduce((n,c)=>n+c.steps.length,0)>1000)throw new Error('Sequence cases exceed1000 total steps.');
    for(const item of sequences)sequenceCalls(item.steps.map(step=>step.args));
  }else if(cases!.some(c=>JSON.stringify(c.args).length>1048576))throw new Error('Case arguments exceed 1 MiB.');
  if(commandConfig){
    if(!path.isAbsolute(commandConfig.command[0]!))throw new Error('Reference executable must be an absolute path.');
    commandConfig.command[0]=await realpath(commandConfig.command[0]!);
    if(commandConfig.scope==='target-cli'&&commandConfig.command[0]!==bound.target.path)throw new Error('target-cli requires executing the selected indexed binary itself. Use external-harness and explain the boundary for other programs.');
  }
  const reference=androidConfig??commandConfig!;const files:{file:string;sha256:string}[]=[];
  const androidLibraries=androidConfig&&'nativeLibraries' in androidConfig?androidConfig.nativeLibraries??[]:[];
  for(const file of new Set([...bound.targets.map(t=>t.target.path),...(commandConfig?[commandConfig.command[0]!,...commandConfig.boundFiles]:[androidConfig!.adb,androidConfig!.harness,...androidConfig!.dependencies,...androidLibraries.map(l=>l.file)])])){const actual=await realpath(file);files.push({file:actual,sha256:(await hashFile(actual)).sha256});}
  const temporary=await realpath(await mkdtemp(path.join(tmpdir(),'carve-reconstruction-verify-')));
  let android:Awaited<ReturnType<typeof prepareAndroidReference>>|undefined;let cleanupStatus:string|undefined;
  try{
    if(androidConfig)android=await prepareAndroidReference(root,bound.target,androidConfig,{signal:options.signal});
    const candidate=path.join(temporary,'candidate');await mkdir(candidate);
    for(const f of pkg.files)await cp(path.join(pkg.root,f),path.join(candidate,f));
    await writeFile(path.join(candidate,'carve.manifest.json'),pkg.manifestText);await readPackage(candidate);
    const results:any[]=[];
    if(sequences){
      for(const item of sequences){
        if(options.signal?.aborted)throw new Error('Reconstruction verification cancelled.');
        const calls=item.steps.map(step=>step.args);
        const original=sequenceOutcome(android?await android.run(calls,timeoutMs):await runReference(commandConfig!.command,'json-stdin',calls,temporary,timeoutMs,options.signal),calls.length);
        const rebuilt=await invokeSequence(candidate,calls,{execute:true,timeoutMs,signal:options.signal});
        const steps=item.steps.map((step,index)=>{
          const originalStep=original.kind==='return'?original.value[index]:undefined,candidateStep=rebuilt.kind==='return'?rebuilt.value[index]:undefined;
          const passed=Boolean(originalStep&&candidateStep&&isDeepStrictEqual(originalStep,candidateStep)&&(!Object.hasOwn(step,'expected')||originalStep.kind==='return'&&isDeepStrictEqual(originalStep.value,step.expected)));
          return{index,args:step.args,passed,...(originalStep?{original:originalStep}:{}),...(candidateStep?{candidate:candidateStep}:{}),...(Object.hasOwn(step,'expected')?{expected:step.expected}:{})};
        });
        results.push({name:item.name,calls,passed:steps.every(step=>step.passed),original,candidate:rebuilt,steps});
      }
    }else for(const item of cases!){
      if(options.signal?.aborted)throw new Error('Reconstruction verification cancelled.');
      const original=android?await android.run(item.args,timeoutMs):await runReference(commandConfig!.command,commandConfig!.mode as 'argv-values'|'json-stdin'|'text-stdin'|'bytes-stdin',item.args,temporary,timeoutMs,options.signal,commandConfig!.schema==='carve/reference@2'?commandConfig!.output:'json');
      const rebuilt=await invoke(candidate,item.args,{execute:true,timeoutMs,signal:options.signal});
      const passed=original.kind==='return'&&rebuilt.kind==='return'&&isDeepStrictEqual(original.value,rebuilt.value)&&(!Object.hasOwn(item,'expected')||isDeepStrictEqual(original.value,item.expected));
      results.push({name:item.name,args:item.args,passed,original,candidate:rebuilt,...(Object.hasOwn(item,'expected')?{expected:item.expected}:{})});
    }
    // Verification is invalid if any bound executable/input changed during execution.
    for(const file of files)if((await hashFile(file.file)).sha256!==file.sha256)throw new Error('Reference bound bytes changed during verification.');
    if(android)await android.verifyRemote();
    assertReconstructionBinding(provenance,await bindReconstruction(root,contract,options.authorizeWorkspace,options.signal,options.authorizePath));
    if((await readPackage(pkg.root)).manifestSha256!==pkg.manifestSha256)throw new Error('Candidate package changed during verification.');
    if(android)cleanupStatus=await android.cleanup();
    const report={schema:'carve/reconstruction-verification@1',status:results.every(r=>r.passed)?'passed-supplied-cases':'failed',checkedAt:new Date().toISOString(),
      original:provenance.original,...(contract.schema==='carve/reconstruction@2'?{artifacts:bound.artifacts,relationships:bound.relationships,unresolvedRelationships:bound.unresolvedRelationships}:{}),manifestSha256:pkg.manifestSha256,casesSha256:raw.sha256,referenceConfigSha256:refRaw.sha256,
      ...(provenance.analysisWarningCount?{analysisWarnings:provenance.analysisWarnings,analysisWarningCount:provenance.analysisWarningCount}:{}),reference:{...reference,boundFiles:files},androidRuntime:android?{...android.identity,logDirectory:android.logDirectory,cleanup:cleanupStatus}:null,passed:results.filter(r=>r.passed).length,total:results.length,
      ...(sequences?{comparisonMode:'stateful-sequences',totalSteps:sequences.reduce((n,c)=>n+c.steps.length,0),passedSteps:results.reduce((n,r)=>n+r.steps.filter((step:any)=>step.passed).length,0)}:{}),
      verifiedScope:sequences?(android?'selected-dex-android-harness-sequences':commandConfig!.scope==='target-cli'?'selected-original-cli-sequences':'declared-external-harness-sequences'):android?'selected-dex-android-harness-cases':commandConfig!.scope==='target-cli'?'selected-original-cli-cases':'declared-external-harness-cases',
      unresolvedDependencies:provenance.unresolvedDependencies,unknowns:contract.unknowns,candidateEnvironment:{freshProcesses:true,originalApplicationCopied:false,nodePermissions:true,securitySandbox:false,...(sequences?{processLifetime:'one-sequence',stepsShareModuleInstance:true,crossSequenceModuleState:false}:{})},
      limitations:[...(sequences?['State is compared only within each supplied ordered sequence. A fresh process/module is used per sequence; OS, files, network, timers, concurrent operations and state across separate requests are not established. The reference command or Android harness declares this protocol; Carve does not prove its internal implementation or dependency closure.']:[]),'Only supplied cases and the declared invocation boundary were compared; this does not prove full feature equivalence.','Reference execution uses host/device permissions and may access libraries/state/network. Selected artifacts and explicitly bound reference files are hashed; hashing does not prove every artifact was loaded or every declared relationship executed.',android?'Selected DEX bytes and any declared native libraries were staged and hashed on the identified Android runtime; actual loading/method invocation depends on the reviewed harness; UI, server, hardware and other-device behavior remain unverified.':'An external command harness comparison does not establish Android/device, UI, server or original binary behavior.'],results};
    await archiveVerificationReport(root,report);await saveVerificationReport(pkg.root,report);return report;
  }finally{if(android&&!cleanupStatus)await android.cleanup();await rm(temporary,{recursive:true,force:true});}
}
