#!/usr/bin/env node
import {runWorkAcceptance,readWorkAcceptance} from './work-acceptance.js';
import {skeletonCreate,skeletonCheck,skeletonInspect} from './skeleton-api.js';
import { Command } from 'commander';
import {checkBehavior} from './behavior.js';
import { inspect, plan, serve } from './mcp.js';
import { extract } from './extract.js';
import { verify } from './verify.js';
import { analyzeWithRea } from './rea.js';
import type { Selector } from './analyze.js';
import { createFeature, readFeature, featurePrompt } from './feature.js';
import { discover } from './discover.js';
import { VERSION } from './version.js';
import {bridgeReaNative} from './rea-bridge.js';
import { probe, runFeature } from './probe.js';
import { contrast } from './contrast.js';
import { readFile, writeFile } from 'node:fs/promises';
import { locate } from './locate.js';
import { startTask } from './session.js';
import { packageUsage, invoke, invokeSequence, serveTool, shellCommand } from './runtime.js';
import { survey, queryIndex, type SurveyOptions } from './survey.js';
import { nativeAnalysis, searchObservations, readObservation } from './native.js';
import { managedAnalysis } from './managed.js';
import { reverseTask } from './reverse.js';
import {featureMenu} from './feature-menu.js';
import {featureScope} from './feature-scope.js';
import {planProject} from './project-plan.js';
import {createWorkPackage,readWorkPackage,type WorkOptions} from './work-package.js';
import {createWorkLedger,registerWork,claimWork,releaseWork,submitWork,requeueWork,queryWorkLedger,workClaimSchema,WORK_STATES} from './work-ledger.js';
import {inspectPlatform} from './platform-tools.js';
import {importReaNative} from './rea-native.js';
import { reconstruct, verifyReconstruction, boundedJson } from './reconstruction.js';
import {enqueueAnalysis,queryAnalysisJobs,runAnalysisQueue} from './analysis-queue.js';
import {startAnalysisRun,queryAnalysisRuns,cancelAnalysisRun} from './analysis-background.js';
import {queryLinks} from './linkage.js';
import {inspectLoader} from './loader.js';
import {inspectPeUi} from './pe-ui.js';
import {inspectAndroidManifest} from './android-manifest.js';
import {inspectJni} from './jni.js';
import {readVerificationArchive,verificationResponse} from './verification-archive.js';
import {responseBudget} from './context-budget.js';
import {addCapability,findCapabilities,getCapability} from './library.js';
import {analysisContext} from './context.js';
import { traceBoundary } from './trace.js';
import { unpackContainer } from './container.js';
import {readEngineConfiguration} from './engine-config.js';
import {relocateWorkspace} from './relocate.js';

const cli = new Command().name('carve').description('Investigate and reconstruct software capabilities using local analysis, CLI and MCP tools.').version(VERSION);
const output = (value: unknown): void => { process.stdout.write(JSON.stringify(value, null, 2) + '\n'); };
const compactOutput = (value: unknown): void => { process.stdout.write(JSON.stringify(value) + '\n'); };
const cliResources = (options: { heapMib?: string; threads?: string }) => ({ heapMiB: options.heapMib === undefined ? undefined : Number(options.heapMib), threads: options.threads === undefined ? undefined : Number(options.threads) });
async function inventoryBatch<T>(options:Record<string,any>,run:(batch:Omit<SurveyOptions,'workspace'>)=>Promise<T>){
  return withCancellation(signal=>run({maxFiles:Number(options.maxFiles),maxDirectories:Number(options.maxDirectories),refresh:options.refresh,signal,
    onProgress:options.progress?progress=>{process.stderr.write(JSON.stringify({schema:'carve/survey-progress@1',...progress})+'\n');}:undefined}));
}
async function withCancellation<T>(run:(signal:AbortSignal)=>Promise<T>){
  const controller=new AbortController();const cancel=()=>controller.abort();
  process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
  try{return await run(controller.signal);}
  finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
cli.command('locate').argument('<target>').description('Locate JavaScript/ASAR inside an application without executing it')
  .option('--json', 'Emit a machine-readable report').option('--scan-limit <count>', 'Maximum visited entries', '20000')
  .action(async (target, options) => {
    const result = await locate(target, { scanLimit: Number(options.scanLimit) });
    if (options.json) output(result);
    else {
      process.stdout.write(`Artifact location: ${result.status}\n` + result.candidates.map(c => `  ${c.target} (${c.moduleCount} JavaScript modules)`).join('\n') + '\n' + result.nextAction + '\n');
      if (result.selectedTarget) process.stdout.write(`Next: ${shellCommand([process.execPath, process.argv[1]!, 'inspect', result.selectedTarget])}\n`);
    }
    if (result.status !== 'located') process.exitCode = 1;
  });
cli.command('start').argument('<target>').description('Create an agent task from an app path and a plain-language goal')
  .requiredOption('--goal <description>', 'The capability you want to extract').requiredOption('--out <directory>', 'New task directory')
  .option('--json', 'Emit a machine-readable report').action(async (target, options) => {
    const result = await startTask(target, { goal: options.goal, out: options.out });
    if (options.json) output(result);
    else process.stdout.write(`Task: ${result.status}\n${result.out ? `Saved in: ${result.out}\nGive your agent this instruction:\nRead ${result.task} and complete the extraction task.\n` : ''}${result.nextAction}\n`);
    if (result.status !== 'draft-created') process.exitCode = 1;
  });
cli.command('use').argument('<package>').description('Show real example commands and MCP configuration for an extracted package')
  .option('--json', 'Emit a machine-readable report').action(async (input, options) => {
    const result = await packageUsage(input);
    if (options.json) output(result);
    else process.stdout.write(`${result.title}\n\n${result.reconstruction?`Inputs: ${result.reconstruction.behavior.inputDomain}\nOutputs: ${result.reconstruction.behavior.outputDomain}\nComparison: ${result.verification.status}${result.verification.scope?' ('+result.verification.scope+')':''}\n\n`:''}${result.commands.sequence?`Run sequence example:\n${result.commands.sequence}\n`:''}${result.commands.run ? `Run example:\n${result.commands.run}\n` : result.nextAction + '\n'}${result.commands.raw ? `\nRaw text:\n${result.commands.raw}\nSave text:\n${result.commands.saveText}\n` : ''}\nMCP client configuration:\n${JSON.stringify(result.mcpClientConfig, null, 2)}\n`);
  });
cli.command('invoke').argument('<package>').description('Invoke a trusted extracted capability in a fresh restricted process')
  .requiredOption('--args <json>', 'JSON positional argument array').option('--execute', 'Allow trusted package execution')
  .option('--raw', 'Return text without JSON encoding').option('--out <file>', 'Write to a new file')
  .option('--timeout <milliseconds>', 'Execution deadline', '3000').action(async (input, options) => {
    if (Buffer.byteLength(options.args) > 1048576) throw new Error('Input exceeds 1 MiB.');
    const result = await invoke(input, JSON.parse(options.args), { execute: Boolean(options.execute), timeoutMs: Number(options.timeout) });
    if (result.kind !== 'return') { output(result); process.exitCode = 1; return; }
    if (options.raw && typeof result.value !== 'string') throw new Error('--raw requires a string result.');
    const text = options.raw ? result.value as string : JSON.stringify(result.value, null, 2) + '\n';
    if (options.out) await writeFile(options.out, text, { flag: 'wx' }); else process.stdout.write(text);
  });
cli.command('invoke-sequence').argument('<package>').description('Run1–64 ordered calls in one fresh process, sharing module state within the sequence')
  .requiredOption('--calls <json>', 'JSON array of positional argument arrays').option('--execute', 'Allow trusted package execution')
  .option('--timeout <milliseconds>', 'Deadline for the complete sequence', '3000').action(async(input,options)=>{
    if(Buffer.byteLength(options.calls)>1048576)throw new Error('Sequence input exceeds 1 MiB.');
    const result=await withCancellation(signal=>invokeSequence(input,JSON.parse(options.calls),{execute:Boolean(options.execute),timeoutMs:Number(options.timeout),signal}));output(result);if(result.kind!=='return')process.exitCode=1;
  });
cli.command('serve-tool').argument('<package>').description('Expose a trusted extracted capability over stdio MCP')
  .option('--execute', 'Allow trusted package execution').option('--timeout <milliseconds>', 'Per-call deadline', '3000')
  .action(async (input, options) => { await serveTool(input, { execute: Boolean(options.execute), timeoutMs: Number(options.timeout) }); });
cli.command('survey').argument('<target>').description('Stream a large software inventory into a resumable SQLite workspace')
  .requiredOption('--workspace <directory>', 'Persistent analysis workspace').option('--max-files <count>', 'Files processed per resumable batch', '10000')
  .option('--max-directories <count>', 'Directory listings per batch; each listing finishes as one unit', '1000').option('--progress', 'Write checkpoint progress as JSON lines to stderr')
  .option('--refresh', 'Start a new inventory revision and reuse metadata-matching hashes').action(async(target,options)=>output(await inventoryBatch(options,batch=>survey(target,{workspace:options.workspace,...batch}))));
const library=cli.command('library').description('Store reusable function folders for direct imports and LLM discovery/invocation');
library.command('add').argument('<package>').requiredOption('--library <folder>', 'Local function library').requiredOption('--name <name>', 'Stable lowercase capability name')
  .option('--title <text>', 'Display title').option('--description <text>', 'Discovery description').option('--tag <text...>', 'Discovery tags')
  .action(async(input,options)=>output(await addCapability(input,{library:options.library,name:options.name,title:options.title,description:options.description,tags:options.tag})));
library.command('find').argument('<library>').option('--query <text>', 'Literal keyword/tag', '').option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Catalogue offset', '0').option('--budget-bytes <bytes>', 'Compact UTF8 JSON response budget1024–65536', '8192')
  .action(async(input,options)=>{process.stdout.write(JSON.stringify(await findCapabilities(input,{query:options.query,limit:Number(options.limit),offset:Number(options.offset),budgetBytes:Number(options.budgetBytes)}))+'\n');});
library.command('get').argument('<library>').argument('<name>').action(async(input,name)=>output(await getCapability(input,name)));
cli.command('reverse').argument('<target>').description('Create/resume a format-aware capability reconstruction task for your agent')
  .option('--goal <description>', 'Capability to reconstruct; omit to inspect candidate features').requiredOption('--out <workspace>', 'Persistent workspace')
  .option('--max-files <count>', 'Inventory files per resumable batch', '10000').option('--max-directories <count>', 'Directory listings per batch; each listing finishes as one unit', '1000')
  .option('--progress', 'Write inventory checkpoint progress as JSON lines to stderr').option('--refresh', 'Start a fresh inventory revision')
  .action(async(target,options)=>output(await inventoryBatch(options,batch=>reverseTask(target,{goal:options.goal,out:options.out,...batch}))));
cli.command('features').argument('<workspace>').description('Show recorded feature leads beside the separate REA MCP; no target execution')
  .option('--query <description>', 'Your own feature description').option('--choice <id>', 'Narrow to a returned rule ID').option('--facet <id>', 'Narrow to a returned boundary facet of that choice')
  .option('--cursor <cursor>', 'Continue a bounded inventory/observation scan').option('--scan-limit <count>', 'Rows per source1–5000', '1000')
  .option('--offset <count>', 'Candidate offset in this scan', '0').option('--limit <count>', 'Candidate page1–12', '8').option('--budget-bytes <bytes>', 'Compact JSON response budget', '8192')
  .action(async(workspace,options)=>compactOutput(await featureMenu(workspace,{query:options.query,choice:options.choice,facet:options.facet,cursor:options.cursor,scanLimit:Number(options.scanLimit),offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes)})));
cli.command('scope').argument('<workspace>').description('Save or read a source-linked feature request and missing questions; never claims extraction or executes the target')
  .option('--request <json>', 'Full carve/feature-request@1 JSON for a new immutable record').option('--id <sha256>', 'Read an existing scope record')
  .option('--parent <sha256>', 'Prior scope ID when submitting a complete revised request').option('--view <name>', 'summary, sources or record', 'summary')
  .option('--offset <count>', 'Source index or JSON text UTF16 offset', '0').option('--limit <count>', 'Source cards1–16', '8').option('--characters <count>', 'Record text characters1–12000', '12000')
  .option('--budget-bytes <bytes>', 'Compact JSON response budget', '8192')
  .action(async(workspace,options)=>compactOutput(await withCancellation(async signal=>featureScope(workspace,{request:options.request?(await boundedJson(options.request)).value:undefined,id:options.id,parentId:options.parent,view:options.view,offset:Number(options.offset),limit:Number(options.limit),characters:Number(options.characters),budgetBytes:Number(options.budgetBytes),signal}))));
cli.command('behavior-check').argument('<json>').description('Check structured lifecycle/UI/protocol/persistence requirements and declared scenario coverage; never executes cases')
  .option('--view <name>', 'summary, requirements, scenarios, gaps or provenance', 'summary').option('--offset <count>', 'Row offset', '0').option('--limit <count>', 'Rows1–100', '10').option('--budget-bytes <bytes>', 'Compact JSON response budget', '8192')
  .action(async(file,options)=>compactOutput(checkBehavior((await boundedJson(file)).value,{...options,offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes)})));
cli.command('project-plan').argument('<json>').description('Order an agent-declared project graph and page its tasks; no dispatch or target execution')
  .option('--offset <count>', 'Task offset', '0').option('--limit <count>', 'Task cards1–100', '20')
  .option('--budget-bytes <bytes>', 'Compact JSON response budget1024–65536', '8192')
  .action(async(input,options)=>compactOutput(planProject((await boundedJson(input)).value,{offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes)})));
const workPackage=cli.command('work-package').description('Prepare immutable interface-pinned agent tasks; no agents are started');
const workPages=(command:Command)=>command.option('--view <name>', 'summary, record, dependencies or acceptance', 'summary')
  .option('--offset <count>', 'Row index or record UTF16 offset', '0').option('--limit <count>', 'Rows1–100', '8')
  .option('--characters <count>', 'Record page characters1–12000', '2000').option('--budget-bytes <bytes>', 'Compact JSON budget1024–65536', '8192');
const workOptions=(options:Record<string,string>,signal:AbortSignal):WorkOptions=>({view:options.view as WorkOptions['view'],offset:Number(options.offset),limit:Number(options.limit),characters:Number(options.characters),budgetBytes:Number(options.budgetBytes),signal});
workPages(workPackage.command('create').argument('<plan>').argument('<spec>').requiredOption('--feature <id>', 'Feature with an explicit assignment').requiredOption('--out <directory>', 'New directory; existing directories are refused'))
  .action(async(plan,spec,options)=>compactOutput(await withCancellation(async signal=>createWorkPackage((await boundedJson(plan)).value,(await boundedJson(spec)).value,options.feature,options.out,workOptions(options,signal)))));
workPages(workPackage.command('read').argument('<directory>'))
  .action(async(input,options)=>compactOutput(await withCancellation(signal=>readWorkPackage(input,workOptions(options,signal)))));
workPages(workPackage.command('check').argument('<directory>').requiredOption('--plan <json>', 'Current complete project plan').requiredOption('--spec <json>', 'Current work specification'))
  .action(async(input,options)=>compactOutput(await withCancellation(async signal=>readWorkPackage(input,workOptions(options,signal),{plan:(await boundedJson(options.plan)).value,spec:(await boundedJson(options.spec)).value}))));
const acceptance=cli.command('work-acceptance').description('Execute explicitly trusted checks or inspect pinned local results; no automatic ledger acceptance');
acceptance.command('run').argument('<package>').requiredOption('--root <directory>', 'Trusted implementation root').requiredOption('--checks <json>', 'Acceptance command/file-pin specification').requiredOption('--plan <json>', 'Current plan').requiredOption('--spec <json>', 'Current work specification').requiredOption('--out <directory>', 'New result directory').option('--execute', 'Authorize trusted command execution').option('--timeout-ms <ms>', 'Per-command deadline50–30000', '3000').option('--budget-bytes <bytes>', 'Response budget', '8192')
 .action(async(pkg,o)=>compactOutput(await withCancellation(async signal=>runWorkAcceptance(pkg,o.root,(await boundedJson(o.checks)).value,o.out,{plan:(await boundedJson(o.plan)).value,spec:(await boundedJson(o.spec)).value},{execute:o.execute,timeoutMs:Number(o.timeoutMs),budgetBytes:Number(o.budgetBytes),signal}))));
acceptance.command('read').argument('<directory>').requiredOption('--package <directory>', 'Current work package').requiredOption('--root <directory>', 'Implementation root').requiredOption('--plan <json>', 'Current plan').requiredOption('--spec <json>', 'Current work specification').option('--claim <json>', 'Optional reported verification claim to bind to this report').option('--check-id <id>', 'Passing comparison check for claim binding').option('--offset <count>', 'Acceptance row offset', '0').option('--limit <count>', 'Acceptance rows', '8').option('--budget-bytes <bytes>', 'Response budget', '8192')
 .action(async(dir,o)=>compactOutput(await readWorkAcceptance(dir,o.package,o.root,{plan:(await boundedJson(o.plan)).value,spec:(await boundedJson(o.spec)).value},{claim:o.claim?(await boundedJson(o.claim)).value:undefined,checkId:o.checkId,offset:Number(o.offset),limit:Number(o.limit),budgetBytes:Number(o.budgetBytes)})));
const skeleton=cli.command('skeleton').description('Generate or inspect a Swift project snapshot with explicit package/resource wiring');
const skeletonPages=(c:Command)=>c.option('--offset <count>', 'Feature row offset', '0').option('--limit <count>', 'Feature rows1–100', '8').option('--budget-bytes <bytes>', 'JSON response budget', '8192');
skeletonPages(skeleton.command('create').argument('<plan>').argument('<spec>').requiredOption('--out <directory>', 'New snapshot directory').option('--wiring <json>', 'Pinned dependency/resource/input declarations').option('--source-root <directory>', 'Pinned implementation and vendored inputs'))
 .action(async(plan,spec,o)=>compactOutput(await withCancellation(async signal=>skeletonCreate((await boundedJson(plan)).value,(await boundedJson(spec)).value,o.out,{signal,wiring:o.wiring?(await boundedJson(o.wiring)).value:undefined,sourceRoot:o.sourceRoot,offset:Number(o.offset),limit:Number(o.limit),budgetBytes:Number(o.budgetBytes)}))));
skeletonPages(skeleton.command('inspect').argument('<directory>')).action(async(dir,o)=>compactOutput(await skeletonInspect(dir,{offset:Number(o.offset),limit:Number(o.limit),budgetBytes:Number(o.budgetBytes)})));
skeletonPages(skeleton.command('check').argument('<directory>').requiredOption('--plan <json>', 'Current project plan').requiredOption('--spec <json>', 'Current work specification').option('--execute', 'Execute trusted Swift build and feature code').option('--test', 'Run Swift tests').option('--flow <feature>', 'Flow to exercise').option('--scratch-path <directory>', 'Swift build products').option('--timeout-ms <ms>', 'Per-command deadline50–900000', '900000'))
 .action(async(dir,o)=>compactOutput(await withCancellation(async signal=>skeletonCheck(dir,{plan:(await boundedJson(o.plan)).value,spec:(await boundedJson(o.spec)).value},{signal,execute:o.execute,test:o.test,flow:o.flow,scratchPath:o.scratchPath,timeoutMs:Number(o.timeoutMs),offset:Number(o.offset),limit:Number(o.limit),budgetBytes:Number(o.budgetBytes)}))));
const ledger=cli.command('work-ledger').description('Coordinate durable claims, retries and handoffs; does not start agents or merge code');
const ledgerBudget=(command:Command)=>command.option('--budget-bytes <bytes>', 'Compact JSON budget1024–65536', '8192');
const ledgerCurrent=(command:Command)=>command.requiredOption('--plan <json>', 'Current complete project plan').requiredOption('--spec <json>', 'Current work specification');
const currentWork=async(options:Record<string,string>)=>({plan:(await boundedJson(options.plan!)).value,spec:(await boundedJson(options.spec!)).value});
const claimFile=async(file:string)=>{const data=(await boundedJson(file)).value;if(data.schema==='carve/work-ledger-view@1'&&data.action==='claim'){const {id,owner,attempt,claimId}=data.job??{};return workClaimSchema.parse({id,owner,attempt,claimId});}return workClaimSchema.parse(data);};
ledgerBudget(ledger.command('create').argument('<directory>')).action(async(dir,options)=>compactOutput(await withCancellation(signal=>createWorkLedger(dir,{signal,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledgerCurrent(ledger.command('register').argument('<directory>').requiredOption('--package <folder>', 'Existing immutable work package'))).action(async(dir,options)=>compactOutput(await withCancellation(async signal=>registerWork(dir,options.package,await currentWork(options),{signal,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledgerCurrent(ledger.command('claim').argument('<directory>').requiredOption('--id <sha256>', 'Registered package ID').requiredOption('--owner <label>', 'Declared worker label; not authenticated identity').option('--retry', 'Explicitly retry failed work'))).action(async(dir,options)=>compactOutput(await withCancellation(async signal=>claimWork(dir,options.id,options.owner,await currentWork(options),{signal,retry:options.retry,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledger.command('close').argument('<directory>').requiredOption('--claim <json>', 'Saved claim response or id/owner/attempt/claimId JSON').requiredOption('--outcome <name>', 'released or failed').requiredOption('--reason <text>', 'Why the worker stopped; coordinate before releasing')).action(async(dir,options)=>compactOutput(await withCancellation(async signal=>releaseWork(dir,await claimFile(options.claim),options.outcome,options.reason,{signal,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledgerCurrent(ledger.command('submit').argument('<directory>').requiredOption('--claim <json>', 'Saved claim response or exact identity JSON').requiredOption('--submission <json>', 'Proposal or implementation declaration with agent-reported checks').option('--output-root <directory>', 'Required only for implementation; contains every assigned file'))).action(async(dir,options)=>compactOutput(await withCancellation(async signal=>submitWork(dir,await claimFile(options.claim),await currentWork(options),(await boundedJson(options.submission)).value,options.outputRoot,{signal,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledgerCurrent(ledger.command('requeue').argument('<directory>').requiredOption('--id <sha256>', 'Registered package ID').requiredOption('--attempt <count>', 'Current proposed/submitted attempt').requiredOption('--submission-id <sha256>', 'Exact recorded submission SHA').requiredOption('--reviewer <label>', 'Declared reviewer label').requiredOption('--reason <text>', 'Why this result needs a new attempt'))).action(async(dir,options)=>compactOutput(await withCancellation(async signal=>requeueWork(dir,options.id,Number(options.attempt),options.submissionId,options.reviewer,options.reason,await currentWork(options),{signal,budgetBytes:Number(options.budgetBytes)}))));
ledgerBudget(ledger.command('read').argument('<directory>').option('--view <name>', 'jobs, attempts or result', 'jobs').option('--id <sha256>', 'Registered package ID').option('--status <name>', WORK_STATES.join(', ')).option('--attempt <count>', 'Attempt to read in result view').option('--offset <count>', 'Row or result UTF16 offset', '0').option('--limit <count>', 'Rows1–100', '20').option('--characters <count>', 'Result text characters1–12000', '2000')).action(async(dir,options)=>compactOutput(await withCancellation(signal=>queryWorkLedger(dir,{...options,signal,attempt:options.attempt===undefined?undefined:Number(options.attempt),offset:Number(options.offset),limit:Number(options.limit),characters:Number(options.characters),budgetBytes:Number(options.budgetBytes)}))));
const platform=cli.command('platform').description('Classify recorded PE imports and inspect target adapter guidance; no port or target execution');
const platformPages=(command:Command)=>command.requiredOption('--file <path>', 'Selected indexed PE file').option('--view <name>', 'summary or a supported paged view', 'summary').option('--offset <count>', 'Row offset', '0').option('--limit <count>', 'Rows1–100', '20').option('--budget-bytes <bytes>', 'Compact JSON budget1024–65536', '8192');
platformPages(platform.command('dependencies').argument('<workspace>').option('--category <name>', 'Filter imports view to one category')).action(async(workspace,options)=>compactOutput(await withCancellation(signal=>inspectPlatform(workspace,options.file,{kind:'dependencies',view:options.view,category:options.category,offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes)},signal))));
platformPages(platform.command('adapters').argument('<workspace>').requiredOption('--target <json>', 'carve/target@1 JSON file')).action(async(workspace,options)=>compactOutput(await withCancellation(async signal=>inspectPlatform(workspace,options.file,{kind:'target-adapters',target:(await boundedJson(options.target)).value,view:options.view,offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes)},signal))));
cli.command('import-rea-native').argument('<workspace>').description('Import complete REA native code/info and optional outgoing relationships; never starts or proxies REA')
  .requiredOption('--file <path>', 'Indexed native file').requiredOption('--code <json>', 'Complete procedure_pseudo_code Evidence JSON').requiredOption('--info <json>', 'Matching procedure_info Evidence JSON')
  .option('--callees <json>', 'Matching procedure_callees Evidence JSON').option('--references <json>', 'Matching outgoing procedure_references Evidence JSON')
  .action(async(workspace,options)=>output(await importReaNative(workspace,{file:options.file,code:options.code,info:options.info,callees:options.callees,references:options.references})));
cli.command('bridge-rea-native').argument('<workspace>').description('Bind a direct REA call across two Mach-O images using original instruction/stub/symbol/load metadata')
  .requiredOption('--from <id>', 'Complete REA caller observation ID').requiredOption('--to <id>', 'Complete REA callee observation ID in another indexed file').requiredOption('--stub <address>', 'Recorded import thunk address in the caller image')
  .option('--to-workspace <directory>', 'Callee workspace, resolved relative to the caller workspace; defaults to the same workspace')
  .action(async(workspace,options)=>output(await bridgeReaNative(workspace,{from:options.from,to:options.to,stub:options.stub,toWorkspace:options.toWorkspace})));
cli.command('reconstruct').argument('<workspace>').description('Package an agent reimplementation with binary and decompilation provenance')
  .requiredOption('--contract <json>', 'Completed reconstruction contract').requiredOption('--implementation <file>', 'Reimplemented JavaScript source')
  .requiredOption('--export <name>', 'Reimplemented export').requiredOption('--out <directory>', 'New independent package').option('--feature <json>', 'Optional behavior examples').option('--verification-spec <json>', 'Optional reviewed bounded PE task specification').option('--verification-out <directory>', 'New generated verification task directory')
  .action(async(workspace,options)=>{if(Boolean(options.verificationSpec)!==Boolean(options.verificationOut))throw new Error('Use verification-spec and verification-out together.');output(await reconstruct(workspace,{contract:options.contract,implementation:options.implementation,export:options.export,out:options.out,feature:options.feature,verificationTask:options.verificationSpec?{spec:options.verificationSpec,out:options.verificationOut}:undefined}));});
cli.command('verify-reconstruction').argument('<workspace>').description('Compare a reconstruction against an explicitly scoped trusted reference command')
  .requiredOption('--package <directory>', 'Reconstruction package').requiredOption('--cases <json>', 'Named args/expected cases or carve/sequence-cases@1')
  .requiredOption('--reference <json>', 'Reference command/protocol and invocation scope (reference@1/@2/@3 or Android)').option('--execute', 'Execute trusted reference and candidate code')
  .option('--full-report', 'Explicit compatibility output: all recorded case inputs/results').option('--budget-bytes <bytes>', 'Summary compact JSON budget1024–65536', '8192')
  .option('--timeout <milliseconds>', 'Deadline per case/process', '3000').action(async(workspace,options)=>{
    responseBudget(Number(options.budgetBytes));
    const result=await withCancellation(signal=>verifyReconstruction(workspace,{package:options.package,cases:options.cases,reference:options.reference,execute:Boolean(options.execute),timeoutMs:Number(options.timeout),signal}));process.stdout.write(JSON.stringify(options.fullReport?result:await verificationResponse(workspace,result,Number(options.budgetBytes)))+'\n');if(result.status!=='passed-supplied-cases')process.exitCode=1;
  });
cli.command('verification').argument('<workspace>').requiredOption('--id <sha256>', 'Pinned recorded archive ID').option('--view <name>', 'summary, cases, case or metadata', 'summary')
  .option('--offset <count>', 'Case-list or UTF16 text offset', '0').option('--limit <count>', 'Case cards per page1–100', '20').option('--failed-only', 'Filter case cards')
  .option('--case-index <index>', 'Selected case index0–199').option('--field <name>', 'Recorded case/metadata field').option('--item <index>', 'Select one array item in the field')
  .option('--characters <count>', 'Text characters1–12000', '2000').option('--budget-bytes <bytes>', 'Compact UTF8 JSON budget1024–65536', '8192')
  .action(async(workspace,o)=>{process.stdout.write(JSON.stringify(await readVerificationArchive(workspace,{...o,offset:Number(o.offset),limit:Number(o.limit),caseIndex:o.caseIndex===undefined?undefined:Number(o.caseIndex),item:o.item===undefined?undefined:Number(o.item),characters:Number(o.characters),budgetBytes:Number(o.budgetBytes)}))+'\n');});
cli.command('relocate').argument('<workspace>').description('Rewrite a moved workspace\'s target binding, container lineage and evidence paths after verifying evidence hashes')
  .option('--target <path>', 'New location of the surveyed target when it did not move together with the workspace').option('--from <path>', 'Previous absolute workspace path, for workspaces that do not record it')
  .action(async(workspace,options)=>output(await withCancellation(async signal=>relocateWorkspace(workspace,{target:options.target,from:options.from,signal}))));
cli.command('index').argument('<workspace>').option('--query <text>', 'Literal path fragment').option('--backend <name>', 'Filter by backend')
  .option('--limit <count>', 'Page size, 1–200', '50').option('--offset <count>', 'Page offset', '0')
  .action(async(workspace,options)=>output(await queryIndex(workspace,{query:options.query,backend:options.backend,limit:Number(options.limit),offset:Number(options.offset)})));
const queue=cli.command('queue').description('Persist component requests and run or control bounded local analysis batches');
const queueEngines=async(file?:string)=>file?await readEngineConfiguration(file):{};
queue.command('add').argument('<workspace>').requiredOption('--requests <json>', 'JSON array of1–100 file/native/managed requests').option('--engines <json>', 'Explicit Ghidra/JADX/JDK configuration')
  .action(async(workspace,options)=>output(await withCancellation(async signal=>enqueueAnalysis(workspace,(await boundedJson(options.requests)).value,await queueEngines(options.engines),signal))));
queue.command('list').argument('<workspace>').option('--id <job>', 'Include one job and paginated attempt history').option('--status <state>', 'Filter job state').option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Page offset', '0')
  .action(async(workspace,options)=>output(await queryAnalysisJobs(workspace,{id:options.id,status:options.status,limit:Number(options.limit),offset:Number(options.offset)})));
queue.command('run').argument('<workspace>').option('--engines <json>', 'Same configured provider used when enqueueing').option('--max-jobs <count>', 'Analysis requests per batch1–10', '1').option('--retry', 'Explicitly retry failed/interrupted jobs after actual process recovery').option('--progress', 'Write job transitions as JSON lines to stderr')
  .action(async(workspace,options)=>{
    const result=await withCancellation(async signal=>runAnalysisQueue(workspace,{engines:await queueEngines(options.engines),maxJobs:Number(options.maxJobs),retry:options.retry,signal,onProgress:options.progress?progress=>{process.stderr.write(JSON.stringify({schema:'carve/analysis-progress@1',...progress})+'\n');}:undefined}));
    output(result);if(result.items.some(item=>item.status!=='completed'))process.exitCode=1;
  });
queue.command('start').argument('<workspace>').description('Start a background batch that survives normal launcher exit; returns a run ID')
  .option('--engines <json>', 'Same configured provider used when enqueueing').option('--max-jobs <count>', 'Analysis requests per batch1–10', '1')
  .option('--retry', 'Explicitly retry failed/interrupted jobs').option('--max-run-ms <milliseconds>', 'Execution budget1000–86400000; cleanup may take longer', '86400000')
  .action(async(workspace,options)=>output(await withCancellation(async signal=>startAnalysisRun(workspace,{engines:await queueEngines(options.engines),maxJobs:Number(options.maxJobs),retry:Boolean(options.retry),maxRunMs:Number(options.maxRunMs),signal}))));
queue.command('runs').argument('<workspace>').description('Inspect recorded batch status and actual worker/engine liveness')
  .option('--id <run>', 'Returned run UUID').option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Page offset', '0')
  .action(async(workspace,options)=>output(await queryAnalysisRuns(workspace,{id:options.id,limit:Number(options.limit),offset:Number(options.offset)})));
queue.command('cancel').argument('<workspace>').requiredOption('--id <run>', 'Returned run UUID')
  .description('Persist cancellation; query runs to confirm owned processes have stopped')
  .action(async(workspace,options)=>output(await cancelAnalysisRun(workspace,options.id)));
cli.command('unpack').argument('<workspace>').description('Extract ZIP-family members with resumable checkpoints, CRC32 and explicit resource budgets')
  .requiredOption('--file <path>', 'Indexed relative ZIP/APK/IPA/JAR/AAB/AAR path').option('--max-files <count>', 'New files per batch', '1000')
  .option('--max-entries <count>', 'Total archive entries admitted', '100000').option('--max-bytes <bytes>', 'Total decompressed/input byte budget', String(4*1024**3))
  .option('--max-file-bytes <bytes>', 'Single decompressed member budget', String(1024**3))
  .action(async(workspace,options)=>output(await unpackContainer(workspace,{file:options.file,maxFiles:Number(options.maxFiles),maxEntries:Number(options.maxEntries),maxBytes:Number(options.maxBytes),maxFileBytes:Number(options.maxFileBytes)})));
cli.command('native').argument('<workspace>').description('Index native functions/strings or decompile one function with Ghidra')
  .requiredOption('--file <path>', 'Indexed relative binary path').requiredOption('--ghidra <directory>', 'Ghidra installation').requiredOption('--java-home <directory>', 'Full JDK')
  .option('--function <name-or-address>', 'Selected function; omission exports an inventory page').option('--after <address>', 'Continue function inventory after an observed address')
  .option('--linkage <kind>', 'Loader metadata only: imports, exports or libraries; after is an opaque cursor')
  .option('--strings <substring>', 'Query defined strings instead of function inventory; after is a string cursor')
  .option('--window <address>', 'Inspect a bounded loaded-memory/reference/pointer window').option('--bytes <count>', 'Memory window bytes, 1–4096')
  .option('--limit <count>', 'Functions per page', '500').option('--timeout <milliseconds>', 'Engine deadline', '600000')
  .option('--heap-mib <MiB>', 'JVM maximum heap, default1024; checked against host memory').option('--threads <count>', 'Engine worker threads, default2; checked against host parallelism')
  .action(async(workspace,options)=>output(await nativeAnalysis(workspace,{resources:cliResources(options),file:options.file,ghidra:options.ghidra,javaHome:options.javaHome,function:options.function,linkage:options.linkage,strings:options.strings,window:options.window,bytes:options.bytes===undefined?undefined:Number(options.bytes),after:options.after,limit:Number(options.limit),timeoutMs:Number(options.timeout)})));
cli.command('pe-ui').argument('<workspace>').description('Inspect PE UI resources and command-handler candidates without running the target or REA')
  .requiredOption('--file <path>', 'Indexed relative PE path').option('--view <name>', 'summary, nodes, edges, boundary, issues, entries or dependencies', 'summary')
  .option('--dependency-ids <ids...>', 'Explicit imported helper/DLL observations for dependencies view (maximum32)')
  .option('--entry-mode <mode>', 'Dependencies roots: ui-command (default) or selected-functions (no command)')
  .option('--dependency-depth <count>', 'Dependencies expansion depth0–8(default3)')
  .option('--function-ids <ids...>', 'Explicit imported REA observation IDs for entries/dependencies views (maximum16)')
  .option('--command <id>', 'Filter one numeric command; required for boundary/entries and default dependencies').option('--query <text>', 'Literal case-insensitive node-label filter')
  .option('--offset <count>', 'Result offset', '0').option('--limit <count>', 'Page size1–100', '20').option('--budget-bytes <bytes>', 'Compact UTF8 response budget1024–65536', '8192')
  .action(async(workspace,options)=>compactOutput(await withCancellation(signal=>inspectPeUi(workspace,{...options,command:options.command===undefined?undefined:Number(options.command),dependencyDepth:options.dependencyDepth===undefined?undefined:Number(options.dependencyDepth),offset:Number(options.offset),limit:Number(options.limit),budgetBytes:Number(options.budgetBytes),signal}))));
cli.command('loader').argument('<workspace>').description('Inspect Mach-O load commands and bounded static path candidates without Ghidra or target execution')
  .requiredOption('--file <path>', 'Indexed relative Mach-O path').option('--slice <index>', 'Explicit universal-binary slice index0–63')
  .option('--limit <count>', 'Dependency page size1–100', '20').option('--offset <count>', 'Dependency page offset', '0')
  .action(async(workspace,options)=>output(await withCancellation(signal=>inspectLoader(workspace,{file:options.file,slice:options.slice===undefined?undefined:Number(options.slice),limit:Number(options.limit),offset:Number(options.offset),signal}))));
cli.command('manifest').argument('<workspace>').description('Inspect an unpacked compiled Android manifest without external engines or target execution')
  .requiredOption('--file <path>', 'Indexed relative compiled AndroidManifest.xml path')
  .option('--section <name>', 'components, permissions, features or complete nodes', 'components').option('--query <text>', 'Literal case-insensitive filter', '')
  .option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Filtered page offset', '0').option('--budget-bytes <bytes>', 'Compact UTF8 JSON budget1024–65536', '8192')
  .action(async(workspace,options)=>{const result=await withCancellation(signal=>inspectAndroidManifest(workspace,{...options,limit:Number(options.limit),offset:Number(options.offset),budgetBytes:Number(options.budgetBytes),signal}));process.stdout.write(JSON.stringify(result)+'\n');});
cli.command('jni').argument('<workspace>').description('Match Java/DEX native method declarations to indexed JNI library exports without engines or target execution')
  .requiredOption('--file <paths...>', 'Indexed relative Java class or DEX files (1–500)').option('--library <paths...>', 'Restrict candidates to these indexed native libraries')
  .option('--query <text>', 'Literal class/method/symbol filter', '').option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Filtered page offset', '0').option('--budget-bytes <bytes>', 'Compact UTF8 JSON budget1024–65536', '8192')
  .action(async(workspace,options)=>{const result=await withCancellation(signal=>inspectJni(workspace,{files:options.file,libraries:options.library,query:options.query,limit:Number(options.limit),offset:Number(options.offset),budgetBytes:Number(options.budgetBytes),signal}));process.stdout.write(JSON.stringify(result)+'\n');});
cli.command('context').argument('<workspace>').description('Retrieve compact recorded context with adaptive short-code inclusion, without running an LLM or engine')
  .option('--query <text>', 'Keyword/identifier query').option('--id <ids...>', 'Explicit observation IDs instead of a query').option('--file <path>', 'Narrow to one indexed artifact')
  .option('--view <mode>', 'auto (default), outline or excerpt').option('--code', 'Alias for --view excerpt; at most1200 code points per item').option('--offset <count>', 'Offset in the bounded ranked candidate pool', '0')
  .option('--budget-bytes <bytes>', 'Compact UTF8 JSON payload budget1024–65536', '8192').option('--known-fingerprint <sha256>', 'Return a small unchanged receipt for the same recorded packet')
  .action(async(workspace,options)=>{process.stdout.write(JSON.stringify(await analysisContext(workspace,{query:options.query,ids:options.id,file:options.file,view:options.view,code:options.code,offset:Number(options.offset),budgetBytes:Number(options.budgetBytes),knownFingerprint:options.knownFingerprint}))+'\n');});
cli.command('links').argument('<workspace>').description('Page indexed native metadata or unresolved candidate libraries for an import ID')
  .option('--file <path>', 'Indexed relative artifact').option('--kind <kind>', 'imports, exports or libraries').option('--query <text>', 'Literal name/library fragment')
  .option('--from <id>', 'Import observation ID for candidate mode').option('--symbol-match <mode>', 'exact or leading-underscore, candidate mode only')
  .option('--limit <count>', 'Page size1–100', '20').option('--offset <count>', 'Page offset', '0')
  .action(async(workspace,options)=>output(await queryLinks(workspace,{file:options.file,kind:options.kind,query:options.query,from:options.from,symbolMatch:options.symbolMatch,limit:Number(options.limit),offset:Number(options.offset)})));
cli.command('managed').argument('<workspace>').description('Decompile DEX/APK/JAR/class input through JADX without executing the target')
  .requiredOption('--file <path>', 'Indexed relative input path').requiredOption('--jadx <executable>', 'JADX launcher').requiredOption('--java-home <directory>', 'Full JDK')
  .option('--class <name>', 'Narrow to one class').option('--mode <mode>', 'JADX output: auto, simple or fallback', 'auto').option('--timeout <milliseconds>', 'Engine deadline', '600000')
  .option('--heap-mib <MiB>', 'JVM maximum heap, default1024; checked against host memory').option('--threads <count>', 'JADX worker threads, default2; checked against host parallelism')
  .action(async(workspace,options)=>output(await managedAnalysis(workspace,{resources:cliResources(options),file:options.file,jadx:options.jadx,javaHome:options.javaHome,class:options.class,mode:options.mode,timeoutMs:Number(options.timeout)})));
cli.command('search').argument('<workspace>').argument('<query>').description('Search indexed static evidence without loading the entire project')
  .option('--limit <count>', 'Results, 1–100', '20').action(async(workspace,query,options)=>output(await searchObservations(workspace,query,Number(options.limit))));
cli.command('observation').argument('<workspace>').argument('<id>').option('--offset <count>', 'Text offset', '0').option('--limit <count>', 'Characters, 1–12000', '12000')
  .action(async(workspace,id,options)=>output(await readObservation(workspace,id,Number(options.offset),Number(options.limit))));
cli.command('trace').argument('<workspace>').argument('<id>').description('Trace bounded static string references and native function calls')
  .option('--depth <count>', 'Depth, 0–8', '2').option('--max-nodes <count>', 'Nodes, 1–200', '50')
  .action(async(workspace,id,options)=>output(await traceBoundary(workspace,id,{depth:Number(options.depth),maxNodes:Number(options.maxNodes)})));
const select = (options: { export?: string; symbol?: string }): Selector => {
  if (Boolean(options.export) === Boolean(options.symbol)) throw new Error('Choose exactly one --export NAME or --symbol NAME.');
  return options.export ? { kind: 'export', name: options.export } : { kind: 'symbol', name: options.symbol! };
};
const selection = (command: Command) => command.option('--file <path>', 'Module inside a directory or ASAR')
  .option('--export <name>', 'Public ESM/CommonJS export').option('--symbol <name>', 'Top-level local binding, including minified names');
cli.command('inspect').argument('<target>').option('--file <path>', 'Inspect a module inside a directory or ASAR').action(async (target, options) => output(await inspect(target, options.file)));
cli.command('brief').argument('<description>').requiredOption('--out <file>', 'New feature specification JSON').option('--target <path>', 'Original application or artifact')
  .action(async (description, options) => output(await createFeature(description, options.out, options.target)));
cli.command('prompt').argument('<feature>').action(async file => { const spec = await readFeature(file); process.stdout.write(featurePrompt(spec.feature, file)); });
cli.command('discover').argument('<target>').option('--query <description>', 'Observed behavior or technical search terms')
  .option('--feature <file>', 'Feature specification with examples and search terms').option('--file <path>', 'Narrow to one module')
  .option('--evidence <file>', 'REA application Evidence to bind by source bytes')
  .option('--limit <count>', 'Maximum candidates', '12').option('--scan-limit <count>', 'Maximum scanned modules', '1000')
  .action(async (target, options) => output(await discover(target, { query: options.query, feature: options.feature, file: options.file,
    evidence: options.evidence, limit: Number(options.limit), scanLimit: Number(options.scanLimit) })));
const probing = (command: Command) => command.argument('<target>').requiredOption('--feature <file>', 'Observable behavior specification')
  .option('--file <path>', 'Narrow candidate discovery to a module').option('--evidence <file>', 'REA Evidence')
  .option('--execute', 'Execute trusted original/candidate code; not a security sandbox')
  .option('--max-candidates <count>', 'Probe up to 1–10 lexical candidates', '5')
  .option('--timeout <milliseconds>', 'Per-case execution deadline', '3000');
probing(cli.command('probe')).action(async (target, options) => {
  const result = await probe(target, { feature: options.feature, execute: Boolean(options.execute), file: options.file,
    evidence: options.evidence, maxCandidates: Number(options.maxCandidates), timeoutMs: Number(options.timeout) });
  output(result); if (result.status !== 'one-tested-match') process.exitCode = 1;
});
probing(cli.command('contrast')).option('--max-probes <count>', 'Additional boundary inputs, 1–24', '12')
  .option('--inputs <file>', 'Explicit named args arrays instead of generated boundaries').option('--out <file>', 'Save report to a new JSON file')
  .action(async (target, options) => {
    let inputs;
    if (options.inputs) {
      const text = await readFile(options.inputs, 'utf8');
      if (Buffer.byteLength(text) > 1048576) throw new Error('Contrast inputs exceed 1 MiB.');
      inputs = JSON.parse(text);
    }
    const result = await contrast(target, { feature: options.feature, execute: Boolean(options.execute), file: options.file,
      evidence: options.evidence, maxCandidates: Number(options.maxCandidates), timeoutMs: Number(options.timeout), maxProbes: Number(options.maxProbes), inputs });
    if (options.out) await writeFile(options.out, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
    output(result);
  });
probing(cli.command('run')).requiredOption('--out <directory>', 'New output package').action(async (target, options) => {
  const result = await runFeature(target, { feature: options.feature, execute: Boolean(options.execute), file: options.file,
    out: options.out, evidence: options.evidence, maxCandidates: Number(options.maxCandidates), timeoutMs: Number(options.timeout) });
  output(result); if (result.status !== 'completed-for-supplied-examples') process.exitCode = 1;
});
selection(cli.command('plan').argument('<target>')).action(async (target, options) => {
  const result = await plan(target, options.file, select(options)); output(result); if (result.plan?.status === 'blocked') process.exitCode = 1;
});
selection(cli.command('extract').argument('<target>')).requiredOption('--out <directory>', 'New package directory').option('--feature <file>', 'Embed a behavior specification and its examples')
  .option('--evidence <file>', 'Bind REA Evidence to the extracted modules')
  .action(async (target, options) => output(await extract(target, { file: options.file, selector: select(options), out: options.out, feature: options.feature, evidence: options.evidence })));
cli.command('verify').argument('<package>').option('--cases <file>', 'JSON cases; defaults to the embedded feature examples')
  .option('--execute', 'Execute trusted reference and candidate code with your user permissions')
  .option('--reference <file>', 'Explicit exported reference harness instead of the original module')
  .option('--reference-export <name>', 'Export on the reference harness')
  .option('--timeout <milliseconds>', 'Per-implementation, per-case execution deadline', '3000')
  .action(async (directory, options) => {
    const result = await verify(directory, { cases: options.cases, execute: Boolean(options.execute), reference: options.reference, referenceExport: options.referenceExport, timeoutMs: Number(options.timeout) });
    output(result); if (result.status !== 'passed') process.exitCode = 1;
  });
cli.command('rea').argument('<target>').requiredOption('--out <file>', 'New file to receive verbatim REA evidence')
  .option('--rea-bin <executable>', 'Installed REA executable', 'rea')
  .action(async (target, options) => output(await analyzeWithRea(target, options.out, options.reaBin)));
cli.command('serve').requiredOption('--root <directory>', 'Workspace root for stdio MCP tools').option('--engines <json>', 'Explicit Ghidra/JADX/JDK configuration; optional for JavaScript tools').action(async options => { await serve(options.root,options.engines); });
try { await cli.parseAsync(); } catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(JSON.stringify({ error: message }) + '\n');
  process.exitCode = message.startsWith('Extraction blocked:') ? 1 : 2;
}
