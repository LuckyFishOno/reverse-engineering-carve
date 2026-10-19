import { mkdtemp, mkdir, cp, writeFile, rm, realpath, lstat } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import {readVerificationSummary} from './verification-receipt.js';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readPackage } from './package.js';
import { readFeature } from './feature.js';
import {sequenceCalls,sequenceOutcome,recordedSequenceExample,type SequenceOutcome} from './sequence.js';
import { worker, sequenceWorker, run, type Outcome } from './execution.js';
import { VERSION } from './version.js';
import { digest } from './artifact.js';

export const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
export function shellCommand(args: string[]) { return args.map(shellQuote).join(' '); }
export async function packageUsage(input: string) {
  const pkg = await readPackage(input);
  const feature = pkg.manifest.feature ? await readFeature(path.join(pkg.root, 'carve.feature.json')) : undefined;
  const reconstruction=pkg.manifest.extractionKind==='behavior-reconstruction'?pkg.manifest.reconstruction:null;
  let example:{args:unknown[];expected?:unknown;origin?:string;scope?:string}|undefined = feature?.feature.examples.find(e => Object.hasOwn(e, 'expected'));
  let verification:any={status:'not-read'};let exampleSequence:ReturnType<typeof recordedSequenceExample>;
  if(reconstruction){
    try{
      const file=path.join(pkg.root,'carve.verification.json');if((await lstat(file)).size>1048576){try{const preview=await readVerificationSummary(pkg.root,pkg.manifestSha256);verification=preview.verification;example??=preview.example;exampleSequence=preview.exampleSequence;}catch(error){throw new Error('Large comparison summary unavailable: '+(error as Error).message);}}
      else{
      const text=await pkg.artifact.optionalText('carve.verification.json');if(!text)throw new Error('Empty comparison report.');
      const report=JSON.parse(text);
      JSON.stringify(report,(_key,value)=>{if(typeof value==='number'&&!Number.isFinite(value))throw new Error('Non-finite report.');return value;});
      if(report.schema!=='carve/reconstruction-verification@1'||report.manifestSha256!==pkg.manifestSha256)verification={status:'unbound-report'};
      else{
        verification={status:report.status,checkedAt:report.checkedAt,scope:report.verifiedScope,passed:report.passed,total:report.total,reportSha256:digest(text),authority:'Recorded local comparison, not independently authenticated.',...(report.comparisonMode?{comparisonMode:report.comparisonMode,totalSteps:report.totalSteps,passedSteps:report.passedSteps}:{}),...(report.analysisWarningCount?{analysisWarningCount:report.analysisWarningCount}:{})};
        exampleSequence=recordedSequenceExample(report);
        const recorded=Array.isArray(report.results)&&report.results.find((r:any)=>r.passed===true&&Array.isArray(r.args)&&r.original?.kind==='return'&&r.candidate?.kind==='return'&&isDeepStrictEqual(r.original.value,r.candidate.value));
        if(!example&&report.status==='passed-supplied-cases'&&recorded)example={args:recorded.args,expected:recorded.original.value,origin:'recorded-reference-comparison',scope:report.verifiedScope};
      }
      }
    }catch(error){verification={status:(error as NodeJS.ErrnoException).code==='ENOENT'?'not-run':'unreadable-report'};}
  }
  if(pkg.folder){
    example??=pkg.manifest.library.example??undefined;exampleSequence??=pkg.manifest.library.exampleSequence??undefined;
    if(!['passed-supplied-cases','failed'].includes(verification.status))verification={status:'recorded-before-library-import',source:pkg.manifest.library.sourceVerification,sourceManifestSha256:pkg.manifest.library.sourceManifestSha256,authority:'Recorded source-package result; unchanged implementation bytes were checked during import. Folder import does not rerun behavior comparisons.'};
  }
  const analysisWarnings=(Array.isArray(reconstruction?.analysisWarnings)?reconstruction.analysisWarnings:[]).flatMap((e:any)=>(Array.isArray(e.boundaryWarnings)?e.boundaryWarnings:[]).map((w:any)=>({id:e.id,name:e.name,artifact:e.artifact,address:w.address,target:w.target,message:String(w.message).slice(0,500),instruction:w.instruction,reasonForProviderFlow:w.reasonForProviderFlow})));
  const cli = path.join(pkg.root, 'cli.mjs');
  const carveCli = fileURLToPath(new URL('./cli.js', import.meta.url));
  const mcp = { command: process.execPath, args: [carveCli, 'serve-tool', pkg.root, '--execute'] };
  return { schema: 'carve/usage@1', package: pkg.root,format:pkg.folder?'capability-folder':'standalone-package',title:pkg.manifest.library?.title??feature?.feature.title ?? reconstruction?.contract.goal ?? pkg.manifest.selector?.name ?? 'Extracted capability',
    description:pkg.manifest.library?.description??feature?.feature.description ?? reconstruction?.contract.behavior.description ?? null, manifestSha256: pkg.manifestSha256,
    moduleImport:{file:pkg.entry,export:'capability',code:`import { capability } from ${JSON.stringify(pathToFileURL(pkg.entry).href)};`},
    reconstruction:reconstruction?{behavior:reconstruction.contract.behavior,original:reconstruction.original,...(reconstruction.schema==='carve/reconstruction-provenance@2'?{artifacts:reconstruction.artifacts,relationships:reconstruction.relationships,unresolvedRelationships:reconstruction.unresolvedRelationships}:{}),unresolvedDependencies:reconstruction.unresolvedDependencies,unknowns:reconstruction.contract.unknowns}:null,
    verification,...(analysisWarnings.length?{analysisWarnings:{count:analysisWarnings.length,items:analysisWarnings.slice(0,5),truncated:analysisWarnings.length>5||analysisWarnings.some((w:any)=>w.message.length===500),authority:'Retained static analysis warnings, not resolved by passing behavior cases. Full statements remain in manifest.reconstruction.analysisWarnings.'}}:{}),exampleSequence:exampleSequence??null,example: example ? { args: example.args, expected: example.expected, origin: example.origin,...(example.scope?{scope:example.scope}:{}) } : null,
    commands: { shell: 'POSIX',sequence:exampleSequence?shellCommand([process.execPath,carveCli,'invoke-sequence',pkg.root,'--calls',JSON.stringify(exampleSequence.calls),'--execute']):null, help:pkg.folder?null:shellCommand([process.execPath, cli, '--help']),
      run: !pkg.folder&&example ? shellCommand([process.execPath, cli, JSON.stringify(example.args)]) : null,
      raw: !pkg.folder&&example && typeof example.expected === 'string' ? shellCommand([process.execPath, cli, '--raw', JSON.stringify(example.args)]) : null,
      saveText: !pkg.folder&&example && typeof example.expected === 'string' ? shellCommand([process.execPath, cli, '--raw', '--out', 'result.txt', JSON.stringify(example.args)]) : null,
      mcp: shellCommand([mcp.command, ...mcp.args]) }, mcpClientConfig: { mcpServers: { carved_capability: mcp } },
    nextAction:exampleSequence?'Reuse the complete exampleSequence with invoke-sequence / carve_invoke_sequence. Steps share one module instance; a new sequence starts fresh. A single step is not an independent verified example.':pkg.folder?'Import capability from the returned moduleImport file, or call carve_invoke with this folder and JSON args. Read the domains and unknowns first. No standalone program installation is needed.': example ? 'Run the example command, or add the displayed MCP configuration to your client to call capability with {args:[...]}. The original application is not needed.'
      : 'Inspect the selected function signature and provide a JSON args array. No usable example was recorded; Carve does not invent one.',
    limitations: ['Examples are supplied expectations or recorded comparison observations, not a proof of untested behavior.', 'Invoking trusted extracted code still executes code; Node permissions are not a malicious-code sandbox.'] };
}

export async function invoke(input:string,args:unknown[],options:{execute:boolean;timeoutMs?:number;signal?:AbortSignal}):Promise<Outcome>{return invokeOperation(input,args,options,false);}
export async function invokeSequence(input:string,calls:unknown[][],options:{execute:boolean;timeoutMs?:number;signal?:AbortSignal}):Promise<SequenceOutcome>{
 const checked=sequenceCalls(calls);return sequenceOutcome(await invokeOperation(input,checked,options,true),checked.length);
}
async function invokeOperation(input: string, args: unknown[], options: { execute: boolean; timeoutMs?: number; signal?: AbortSignal },sequence:boolean): Promise<Outcome> {
  if (!options.execute) throw new Error('Invoking an extracted capability executes code. Pass --execute for a trusted package.');
  if (!Array.isArray(args)) throw new Error('Pass function arguments as a JSON array.');
  const text = JSON.stringify(args);
  if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('Input exceeds 1 MiB.');
  const timeoutMs = options.timeoutMs ?? 3000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30_000) throw new Error('timeoutMs must be between 50 and 30000.');
  const pkg = await readPackage(input);
  const temp = await realpath(await mkdtemp(path.join(tmpdir(), 'carve-invoke-')));
  try {
    const candidateRoot = path.join(temp, 'candidate'); await mkdir(candidateRoot);
    for (const file of pkg.files) await cp(path.join(pkg.root, file), path.join(candidateRoot, file));
    // Validate the copied bytes too, in case files changed while copying.
    const copied = await readPackageFromSnapshot(pkg, candidateRoot);
    const runner = path.join(temp, 'worker.mjs'); await writeFile(runner, sequence?sequenceWorker:worker);
    return await run(runner, copied, 'capability', args, candidateRoot, timeoutMs, true, options.signal);
  } finally { await rm(temp, { recursive: true, force: true }); }
}
async function readPackageFromSnapshot(pkg: Awaited<ReturnType<typeof readPackage>>, root: string) {
  await writeFile(path.join(root, 'carve.manifest.json'), pkg.manifestText, { flag: 'wx' });
  return (await readPackage(root)).entry;
}
export function outcomeReply(outcome: Outcome) {
  if (outcome.kind === 'return') return { content: [{ type: 'text' as const, text: JSON.stringify({ value: outcome.value }) }], structuredContent: { value: outcome.value } };
  const error = outcome.kind === 'throw' ? outcome.error : { name: 'ExecutionError', message: outcome.detail };
  return { isError: true, content: [{ type: 'text' as const, text: JSON.stringify({ error }) }], structuredContent: { error } };
}
export async function serveTool(input: string, options: { execute: boolean; timeoutMs?: number }) {
  if (!options.execute) throw new Error('Serving an extracted capability enables code execution. Pass --execute for a trusted package.');
  if (options.timeoutMs !== undefined && (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 50 || options.timeoutMs > 30000)) throw new Error('timeoutMs must be between 50 and 30000.');
  const usage = await packageUsage(input);
  const server = new McpServer({ name: 'carved-capability', version: VERSION });
  server.registerTool('capability_info', { description: 'Read the extracted capability description, recorded example, provenance fingerprint and usage. Does not execute the capability.',
    inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false } }, async () => {
      const info = await packageUsage(usage.package);
      return { content: [{ type: 'text' as const, text: JSON.stringify(info) }] };
    });
  let running = 0;
  server.registerTool('capability', { description: `Run the trusted extracted capability: ${usage.title}. Pass its positional arguments in args. Each call starts a fresh restricted Node process; the original app is not accessed.`,
    inputSchema: { args: z.array(z.unknown()) }, annotations: { readOnlyHint: false, openWorldHint: true } }, async (args, extra) => {
      if (running >= 4) return outcomeReply({ kind: 'harness-error', detail: 'At most four concurrent calls are allowed.' });
      running++;
      try { return outcomeReply(await invoke(usage.package, args.args, { execute: true, timeoutMs: options.timeoutMs, signal: extra.signal })); }
      catch (error) { return outcomeReply({ kind: 'harness-error', detail: (error as Error).message }); }
      finally { running--; }
    });
  server.registerTool('capability_sequence',{description:'Run1–64 ordered calls in one fresh restricted process with a shared module instance. Each new sequence starts fresh; no state survives separate requests. Results are per-step return/throw outcomes; timeout/output/protocol failures invalidate the sequence.',inputSchema:{calls:z.array(z.array(z.unknown())).min(1).max(64)},annotations:{readOnlyHint:false,openWorldHint:true}},async(args,extra)=>{
    if(running>=4)return outcomeReply({kind:'harness-error',detail:'At most four concurrent calls are allowed.'});running++;
    try{return outcomeReply(await invokeSequence(usage.package,args.calls,{execute:true,timeoutMs:options.timeoutMs,signal:extra.signal}));}
    catch(error){return outcomeReply({kind:'harness-error',detail:(error as Error).message});}finally{running--;}
  });
  await server.connect(new StdioServerTransport());
  return server;
}
