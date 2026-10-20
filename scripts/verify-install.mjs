import {createHash} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, readFile, rename, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {binaryXml,manifestFixture} from '../test/fixtures/android-manifest.mjs';
import {buildPe} from '../test/fixtures/pe-image.mjs';
import {buildUiPe} from '../test/fixtures/pe-ui-image.mjs';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const temp = await mkdtemp(path.join(tmpdir(), 'carve-install-'));
await mkdir(path.join(root, 'artifacts'), { recursive: true });
try {
  const packed = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', temp], { cwd: root, encoding: 'utf8' }));
  const tarball = path.join(temp, packed[0].filename);
  const prefix = path.join(temp, 'clean-install');
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', prefix, tarball], { cwd: temp, stdio: 'pipe' });
  const executable = path.join(prefix, 'node_modules', '.bin', process.platform === 'win32' ? 'recarve.cmd' : 'recarve');
  const help = execFileSync(executable, ['--help'], { cwd: temp, encoding: 'utf8' });
  if (!help.includes('Investigate and reconstruct software capabilities')) throw new Error('Installed executable did not start.');
  const input = path.join(temp, 'bundle.mjs');
  await writeFile(input, 'const factor=2;export function double(x){return x*factor}');
  const out = path.join(temp, 'double-tool');
  const extraction = JSON.parse(execFileSync(executable, ['extract', input, '--export', 'double', '--out', out], { cwd: temp, encoding: 'utf8' }));
  await rm(input);
  const result = JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[21]'], { cwd: out, encoding: 'utf8' }));
  if (result !== 42 || extraction.status !== 'extracted') throw new Error('Installed package could not extract an independent capability.');
  const app=path.join(temp,'app');await mkdir(app);
  await writeFile(path.join(app,'main.mjs'),'import {double} from "./helper.mjs";export function format(x){return double(x)}');
  await writeFile(path.join(app,'helper.mjs'),'export const double=x=>x*2;');
  const feature=path.join(temp,'feature.json');await writeFile(feature,JSON.stringify({schema:'carve/feature@1',title:'format',description:'format a number',target:{path:app},steps:['Use format'],searchTerms:['format'],acceptance:['Double the number'],examples:[{name:'twenty one',args:[21],expected:42}]}));
  const completed=JSON.parse(execFileSync(executable,['run',app,'--feature',feature,'--out',path.join(temp,'automated-tool'),'--execute'],{cwd:temp,encoding:'utf8'}));
  if(completed.status!=='completed-for-supplied-examples') throw new Error('Installed feature workflow did not complete.');
  await writeFile(path.join(app,'ambiguous.cjs'),'exports.formatA=x=>x*2;exports.formatB=x=>x+21;');
  const contrasted=JSON.parse(execFileSync(executable,['contrast',app,'--file','ambiguous.cjs','--feature',feature,'--execute','--max-probes','2'],{cwd:temp,encoding:'utf8'}));
  if(contrasted.status!=='needs-observation'||!contrasted.questions.length) throw new Error('Installed CommonJS contrast workflow did not produce a question.');
  const located=JSON.parse(execFileSync(executable,['locate',app,'--json'],{cwd:temp,encoding:'utf8'}));
  if(located.status!=='located') throw new Error('Installed location failed.');
  const started=JSON.parse(execFileSync(executable,['start',app,'--goal','extract format','--out',path.join(temp,'task'),'--json'],{cwd:temp,encoding:'utf8'}));
  if(started.status!=='draft-created') throw new Error('Installed task setup failed.');
  const reversed=JSON.parse(execFileSync(executable,['reverse',app,'--goal','investigate format','--out',path.join(temp,'reconstruction-work')],{cwd:temp,encoding:'utf8'}));
  if(reversed.status!=='ready-for-analysis') throw new Error('Installed reconstruction task/index failed.');
  const indexed=JSON.parse(execFileSync(executable,['index',reversed.workspace,'--limit','1'],{cwd:temp,encoding:'utf8'}));
  if(indexed.items.length!==1||indexed.total!==3)throw new Error('Installed paginated inventory failed.');
  const packagedRoot=path.join(prefix,'node_modules/reverse-engineering-carve');
  const behaviorExample=path.join(packagedRoot,'examples/behavior/interactive-console.json'),behaviorInput=JSON.parse(await readFile(behaviorExample,'utf8'));
  const behaviorCli=JSON.parse(execFileSync(executable,['behavior-check',behaviorExample,'--view','requirements','--limit','3'],{cwd:temp,encoding:'utf8'}));
  if(behaviorCli.status!=='declared-for-validation'||behaviorCli.verification!=='not-run'||behaviorCli.nextOffset!==3)throw new Error('Installed behavior contract CLI failed.');
  const behaviorClient=new Client({name:'carve-packed-behavior',version:'1'});try{
    await behaviorClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await behaviorClient.callTool({name:'carve_behavior_check',arguments:{contract:behaviorInput}}),result=JSON.parse(called.content[0].text);
    const provenanceCall=await behaviorClient.callTool({name:'carve_behavior_check',arguments:{contract:behaviorInput,view:'provenance'}}),provenance=JSON.parse(provenanceCall.content[0].text);
    if(provenanceCall.isError||provenance.items[0]?.kind!=='target-design'||provenance.provenance.authenticated!==false)throw new Error('Installed provenance classification failed.');
    if(called.isError||result.sha256!==behaviorCli.sha256||result.executesTarget!==false)throw new Error('Installed behavior MCP differs from CLI.');
  }finally{await behaviorClient.close();}
  const scopeRequest=path.join(temp,'scope-request.json');await writeFile(scopeRequest,JSON.stringify({schema:'carve/feature-request@1',origin:'test-fixture',goal:'Extract number formatting; more answers are still needed.'}));
  const scopeRaw=execFileSync(executable,['scope',reversed.workspace,'--request',scopeRequest,'--budget-bytes','8192'],{cwd:temp,encoding:'utf8'}),scope=JSON.parse(scopeRaw);
  if(scope.status!=='needs-clarification'||scope.questions.filter(q=>q.audience==='user').length!==7||scope.receipt.responseBytes!==Buffer.byteLength(scopeRaw)-1)throw new Error('Installed clarification CLI failed.');
  const scopeClient=new Client({name:'carve-packed-scope-test',version:'1'});try{
    await scopeClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const tools=(await scopeClient.listTools()).tools;if(tools.length!==52||!tools.some(t=>t.name==='carve_scope'))throw new Error('Installed scope MCP is missing.');
    const called=await scopeClient.callTool({name:'carve_scope',arguments:{workspace:'reconstruction-work',id:scope.id}}),stored=called.structuredContent??JSON.parse(called.content[0].text);
    if(called.isError||stored?.id!==scope.id||stored.sourceIdentityCheck!=='recorded-only-no-current-source-check'||stored.verification!=='not-run')throw new Error('Installed historical scope MCP failed.');
    const withTarget=await scopeClient.callTool({name:'carve_scope',arguments:{workspace:'reconstruction-work',parentId:scope.id,request:{schema:'carve/feature-request@1',origin:'test-fixture',goal:'Reuse formatting in a browser module',target:{schema:'carve/target@1',platform:'browser',delivery:'module'}}}});
    const destination=withTarget.structuredContent??JSON.parse(withTarget.content[0].text);if(withTarget.isError||destination.target?.platform!=='browser'||destination.targetAssessment!=='not-performed'||destination.parentId!==scope.id)throw new Error('Installed target intent failed.');
    const menu=await scopeClient.callTool({name:'carve_features',arguments:{workspace:'reconstruction-work',choice:'document',facet:'format'}});
    if(menu.isError||(menu.structuredContent??JSON.parse(menu.content[0].text)).refinement.selectedFacet!=='format')throw new Error('Installed feature facet MCP failed.');
  }finally{await scopeClient.close();}
  const projectInput=path.join(temp,'project-plan.json');await writeFile(projectInput,await readFile(path.join(packagedRoot,'examples/project-plan.json')));
  const projectText=execFileSync(executable,['project-plan',projectInput,'--limit','2','--budget-bytes','4096'],{cwd:temp,encoding:'utf8'}),project=JSON.parse(projectText);if(project.summary.features!==4||project.items.length!==2||project.receipt.responseBytes!==Buffer.byteLength(projectText)-1)throw new Error('Installed project-plan CLI failed.');
  const projectClient=new Client({name:'carve-packed-project-plan',version:'1'});try{
    await projectClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await projectClient.callTool({name:'carve_project_plan',arguments:{plan:'project-plan.json',offset:2,limit:2,budgetBytes:4096}}),page=called.structuredContent??JSON.parse(called.content[0].text);if(called.isError||page.planId!==project.planId||page.items.length!==2||page.nextOffset!==null)throw new Error('Installed project-plan MCP failed.');
  }finally{await projectClient.close();}
  for(const name of ['work-plan.json','work-spec.json'])await writeFile(path.join(temp,name),await readFile(path.join(packagedRoot,'examples',name)));
  const workFolder=path.join(temp,'parser-work'),workRaw=execFileSync(executable,['work-package','create',path.join(temp,'work-plan.json'),path.join(temp,'work-spec.json'),'--feature','parser','--out',workFolder],{cwd:temp,encoding:'utf8'}),work=JSON.parse(workRaw);
  if(work.currentPlanCheck!=='matched-supplied-plan-and-spec'||work.verification!=='not-run'||work.receipt.responseBytes!==Buffer.byteLength(workRaw)-1)throw new Error('Installed work-package CLI failed.');
  const workClient=new Client({name:'carve-packed-work-package',version:'1'});try{
    await workClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await workClient.callTool({name:'carve_work_package',arguments:{action:'check',package:'parser-work',plan:'work-plan.json',spec:'work-spec.json',view:'dependencies'}}),checked=JSON.parse(called.content[0].text);
    if(called.isError||checked.id!==work.id||checked.items[0].feature!=='model'||checked.currentPlanCheck!=='matched-supplied-plan-and-spec')throw new Error('Installed work-package MCP failed.');
    const smoke='process.stdout.write("ready")';await writeFile(path.join(temp,'acceptance-smoke.mjs'),smoke);
    const record=JSON.parse(await readFile(path.join(workFolder,'work.json'),'utf8')),acceptanceChecks={schema:'carve/acceptance-spec@1',packageId:work.id,files:[{path:'acceptance-smoke.mjs',sha256:createHash('sha256').update(smoke).digest('hex')}],checks:[{id:'smoke',kind:'build',acceptance:[record.assignment.acceptance[0].name],command:{runtime:'node',file:'acceptance-smoke.mjs',args:[]},expectedStdout:'ready'}]};
    await writeFile(path.join(temp,'acceptance-checks.json'),JSON.stringify(acceptanceChecks));
    const acceptanceRoot=await realpath(temp);
    const acceptanceRun=JSON.parse(execFileSync(executable,['work-acceptance','run',work.package,'--root',acceptanceRoot,'--checks',path.join(temp,'acceptance-checks.json'),'--plan',path.join(temp,'work-plan.json'),'--spec',path.join(temp,'work-spec.json'),'--out',path.join(acceptanceRoot,'acceptance-run'),'--execute'],{cwd:temp,encoding:'utf8'}));
    const acceptanceRead=await workClient.callTool({name:'carve_work_acceptance',arguments:{action:'read',package:'parser-work',root:'.',plan:'work-plan.json',spec:'work-spec.json',directory:'acceptance-run'}}),receipt=JSON.parse(acceptanceRead.content[0].text);
    if(acceptanceRead.isError||receipt.reportSha256!==acceptanceRun.reportSha256||receipt.categories.build!=='passed-declared-checks'||receipt.categories['original-comparison']!=='not-run')throw new Error('Installed acceptance CLI/MCP failed.');
  }finally{await workClient.close();}
  const snapshotFolder=path.join(await realpath(temp),'swift-snapshot');
  const skeletonCli=JSON.parse(execFileSync(executable,['skeleton','create',path.join(temp,'work-plan.json'),path.join(temp,'work-spec.json'),'--out',snapshotFolder],{cwd:temp,encoding:'utf8'}));
  if(skeletonCli.built!==false||skeletonCli.originalComparison!=='not-performed')throw new Error('Installed skeleton creation failed.');
  const skeletonClient=new Client({name:'carve-packed-skeleton',version:'1'});try{
    await skeletonClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const inspected=await skeletonClient.callTool({name:'carve_skeleton',arguments:{action:'inspect',directory:'swift-snapshot',limit:1}});if(inspected.isError)throw new Error(inspected.content[0].text);const snapshot=JSON.parse(inspected.content[0].text);if(snapshot.planId!==skeletonCli.planId||snapshot.items.length!==1||snapshot.nextOffset!==1)throw new Error('Installed skeleton inspection differs.');
    const denied=await skeletonClient.callTool({name:'carve_skeleton',arguments:{action:'check',directory:'swift-snapshot',plan:'work-plan.json',spec:'work-spec.json'}});if(!denied.isError)throw new Error('Installed skeleton check must require execution authorization.');
  }finally{await skeletonClient.close();}
  const installedLedger=JSON.parse(execFileSync(executable,['work-ledger','create',path.join(temp,'ledger')],{cwd:temp,encoding:'utf8'}));
  execFileSync(executable,['work-ledger','register',installedLedger.ledger,'--package',work.package,'--plan',path.join(temp,'work-plan.json'),'--spec',path.join(temp,'work-spec.json')],{cwd:temp,stdio:'pipe'});
  const installedClaim=JSON.parse(execFileSync(executable,['work-ledger','claim',installedLedger.ledger,'--id',work.id,'--owner','installed-fixture-worker','--plan',path.join(temp,'work-plan.json'),'--spec',path.join(temp,'work-spec.json')],{cwd:temp,encoding:'utf8'}));
  const ledgerClient=new Client({name:'carve-packed-work-ledger',version:'1'});try{
    await ledgerClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const read=await ledgerClient.callTool({name:'carve_work_ledger',arguments:{ledger:'ledger',request:{action:'read',id:work.id}}}),status=JSON.parse(read.content[0].text);if(read.isError||status.items[0].claimId!==installedClaim.job.claimId||status.items[0].status!=='claimed')throw new Error('Installed ledger did not retain the CLI claim.');
    const {id,owner,attempt,claimId}=installedClaim.job,closed=await ledgerClient.callTool({name:'carve_work_ledger',arguments:{ledger:'ledger',request:{action:'close',claim:{id,owner,attempt,claimId},outcome:'released',reason:'Owned installed fixture explicitly stopped.'}}});if(closed.isError||JSON.parse(closed.content[0].text).job.status!=='queued')throw new Error('Installed ledger release failed.');
  }finally{await ledgerClient.close();}
  const peInput=path.join(temp,'platform.exe'),peWork=path.join(temp,'platform-work');await writeFile(peInput,buildPe({imports:[{name:'KERNEL32.dll',entries:['CreateFileW']},{name:'USER32.dll',entries:['MessageBoxW']}]}));
  execFileSync(executable,['survey',peInput,'--workspace',peWork],{cwd:temp,stdio:'pipe'});const classified=JSON.parse(execFileSync(executable,['platform','dependencies',peWork,'--file','platform.exe'],{cwd:temp,encoding:'utf8'}));if(classified.totals.imports!==2||classified.totals.unknown!==0)throw new Error('Installed PE platform CLI failed.');
  const platformClient=new Client({name:'carve-packed-platform',version:'1'});try{
    await platformClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await platformClient.callTool({name:'carve_platform',arguments:{workspace:'platform-work',file:'platform.exe',request:{kind:'target-adapters',target:{schema:'carve/target@1',platform:'macos',delivery:'desktop-app'},view:'cards'}}}),assessment=JSON.parse(called.content[0].text);
    if(called.isError||assessment.assessment!=='static-guidance-not-verified'||assessment.items.find(i=>i.category==='ui-graphics').availability!=='native-framework')throw new Error('Installed target adapter MCP failed.');
  }finally{await platformClient.close();}
  const uiInput=path.join(temp,'ui.exe'),uiWork=path.join(temp,'ui-work');await writeFile(uiInput,buildUiPe({plus:true,extended:true}).bytes);
  execFileSync(executable,['survey',uiInput,'--workspace',uiWork],{cwd:temp,stdio:'pipe'});
  const uiCli=JSON.parse(execFileSync(executable,['pe-ui',uiWork,'--file','ui.exe','--view','boundary','--command','1001','--limit','100','--budget-bytes','16384'],{cwd:temp,encoding:'utf8'}));
  if(!uiCli.items.some(n=>n.kind==='handler-candidate'))throw new Error('Installed PE UI CLI is missing handler candidates.');
  const uiClient=new Client({name:'carve-packed-pe-ui',version:'1'});try{
    await uiClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await uiClient.callTool({name:'carve_pe_ui',arguments:{workspace:'ui-work',file:'ui.exe'}}),report=JSON.parse(called.content[0].text);
    if(called.isError||report.observationId!==uiCli.observationId||report.counts.handlerRows!==2||report.executesTarget!==false)throw new Error('Installed PE UI MCP graph differs from CLI.');
  }finally{await uiClient.close();}
  const nativeInput=path.join(temp,'loader-fixture'),nativeWorkspace=path.join(temp,'loader-work'),header=Buffer.alloc(32),command=Buffer.alloc(48);
  header.writeUInt32LE(0xfeedfacf,0);header.writeUInt32LE(0x100000c,4);header.writeUInt32LE(2,12);header.writeUInt32LE(1,16);header.writeUInt32LE(48,20);command.writeUInt32LE(12,0);command.writeUInt32LE(48,4);command.writeUInt32LE(24,8);command.write('@loader_path/sibling',24);
  await writeFile(nativeInput,Buffer.concat([header,command]));execFileSync(executable,['survey',nativeInput,'--workspace',nativeWorkspace],{cwd:temp,stdio:'pipe'});
  const loader=JSON.parse(execFileSync(executable,['loader',nativeWorkspace,'--file','loader-fixture'],{cwd:temp,encoding:'utf8'}));if(loader.status!=='loader-commands-inspected'||loader.dependencies[0].name!=='@loader_path/sibling')throw new Error('Installed engine-free loader reader failed.');
  const contextText=execFileSync(executable,['context',nativeWorkspace,'--id',loader.observationId,'--budget-bytes','4096'],{cwd:temp,encoding:'utf8'}),context=JSON.parse(contextText);if(context.items[0].id!==loader.observationId||context.receipt.responseBytes!==Buffer.byteLength(contextText)-1)throw new Error('Installed budgeted context reader failed.');const outlineText=execFileSync(executable,['context',nativeWorkspace,'--id',loader.observationId,'--view','outline','--budget-bytes','4096'],{cwd:temp,encoding:'utf8'}),outline=JSON.parse(outlineText);if(outline.schema!=='carve/analysis-context@2'||outline.view!=='outline'||outline.sources[outline.items[0].source].sha256!==context.sources[context.items[0].source].sha256||outline.items.some(i=>i.text))throw new Error('Installed context view selection failed.');
  const functionLibrary=path.join(temp,'functions');execFileSync(executable,['library','add',out,'--library',functionLibrary,'--name','double-number'],{cwd:temp,stdio:'pipe'});await rm(out,{recursive:true});const found=JSON.parse(execFileSync(executable,['library','find',functionLibrary,'--query','double'],{cwd:temp,encoding:'utf8'}));if(found.items[0].name!=='double-number')throw new Error('Installed function catalogue search failed.');const folder=JSON.parse(execFileSync(executable,['library','get',functionLibrary,'double-number'],{cwd:temp,encoding:'utf8'}));if(folder.usage.format!=='capability-folder'||JSON.parse(execFileSync(executable,['invoke',folder.usage.package,'--args','[21]','--execute'],{cwd:temp,encoding:'utf8'}))!==42)throw new Error('Installed function folder invocation failed.');
  const statefulInput=path.join(temp,'stateful.mjs'),statefulPackage=path.join(temp,'stateful-package');await writeFile(statefulInput,'let n=0;export function next(){return ++n}');
  execFileSync(executable,['extract',statefulInput,'--export','next','--out',statefulPackage],{cwd:temp,stdio:'pipe'});await rm(statefulInput);
  execFileSync(executable,['library','add',statefulPackage,'--library',functionLibrary,'--name','stateful-next'],{cwd:temp,stdio:'pipe'});await rm(statefulPackage,{recursive:true});
  for(let i=0;i<2;i++){const r=JSON.parse(execFileSync(executable,['invoke-sequence',path.join(functionLibrary,'stateful-next'),'--calls','[[],[],[]]','--execute'],{cwd:temp,encoding:'utf8'}));if(r.kind!=='return'||JSON.stringify(r.value)!==JSON.stringify([1,2,3].map(value=>({kind:'return',value}))))throw new Error('Installed stateful sequence CLI failed.');}
  const loaderClient=new Client({name:'carve-packed-loader-test',version:'1'});try{
    await loaderClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const sequence=await loaderClient.callTool({name:'carve_invoke_sequence',arguments:{package:'functions/stateful-next',calls:[[],[]],execute:true}});if(sequence.isError||JSON.stringify(sequence.structuredContent?.value)!==JSON.stringify([{kind:'return',value:1},{kind:'return',value:2}]))throw new Error('Installed stateful sequence MCP failed.');
    const called=await loaderClient.callTool({name:'carve_loader',arguments:{workspace:'loader-work',file:'loader-fixture'}});if(called.isError||JSON.parse(called.content[0].text).observationId!==loader.observationId)throw new Error('Installed engine-free loader MCP failed.');
  }finally{await loaderClient.close();}
  const manifestInput=path.join(temp,'AndroidManifest.xml'),manifestWorkspace=path.join(temp,'manifest-work');await writeFile(manifestInput,binaryXml(manifestFixture()));execFileSync(executable,['survey',manifestInput,'--workspace',manifestWorkspace],{cwd:temp,stdio:'pipe'});
  const manifestRaw=execFileSync(executable,['manifest',manifestWorkspace,'--file','AndroidManifest.xml','--query','Alias'],{cwd:temp,encoding:'utf8'}),manifest=JSON.parse(manifestRaw);if(manifest.status!=='declarations-inspected'||manifest.items[0].codeClassCandidate!=='example.carve.Main'||manifest.receipt.responseBytes!==Buffer.byteLength(manifestRaw)-1)throw new Error('Installed compiled Android manifest CLI failed.');
  const manifestClient=new Client({name:'carve-packed-manifest-test',version:'1'});try{
    await manifestClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await manifestClient.callTool({name:'carve_manifest',arguments:{workspace:'manifest-work',file:'AndroidManifest.xml',query:'Alias'}});if(called.isError||JSON.parse(called.content[0].text).observationId!==manifest.observationId)throw new Error('Installed compiled Android manifest MCP failed.');
  }finally{await manifestClient.close();}
  const moving=path.join(temp,'moving-project'),movingInput=path.join(moving,'input'),movingWork=path.join(moving,'work');await mkdir(movingInput,{recursive:true});await writeFile(path.join(movingInput,'tool'),Buffer.concat([header,command]));
  execFileSync(executable,['survey',movingInput,'--workspace',movingWork],{cwd:temp,stdio:'pipe'});execFileSync(executable,['loader',movingWork,'--file','tool'],{cwd:temp,stdio:'pipe'});
  const moved=path.join(temp,'moved-project');await rename(moving,moved);const relocationClient=new Client({name:'carve-packed-relocation-test',version:'1'});try{
    await relocationClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',moved],stderr:'pipe'}));
    const called=await relocationClient.callTool({name:'carve_relocate',arguments:{workspace:'work'}});if(called.isError)throw new Error('Installed relocation MCP failed: '+called.content[0].text);const relocated=JSON.parse(called.content[0].text);if(!relocated.moved||relocated.evidence.files!==1||!relocated.evidence.hashVerified||relocated.target.to!==await realpath(path.join(moved,'input')))throw new Error('Installed relocation did not bind the moved bytes/evidence.');
    const inspected=await relocationClient.callTool({name:'carve_loader',arguments:{workspace:'work',file:'tool'}});if(inspected.isError||JSON.parse(inspected.content[0].text).status!=='loader-commands-inspected')throw new Error('Installed inspection after relocation failed.');
  }finally{await relocationClient.close();}
  if(!(await readFile(path.join(packagedRoot,'engines/ghidra/CarveExport.java'),'utf8')).includes('class CarveExport'))throw new Error('Packaged Ghidra script is missing.');
  if(!(await readFile(path.join(packagedRoot,'docs/RECONSTRUCTION.md'),'utf8')).includes('carve/reference@1'))throw new Error('Packaged reconstruction documentation is missing.');
  const requests=path.join(temp,'requests.json');await writeFile(requests,JSON.stringify([{file:'helper.mjs'}]));
  execFileSync(executable,['queue','add',reversed.workspace,'--requests',requests],{cwd:temp,stdio:'pipe'});
  const background=JSON.parse(execFileSync(executable,['queue','start',reversed.workspace],{cwd:temp,encoding:'utf8',timeout:15000}));
  let finished;
  for(let n=0;n<100;n++){
    const runs=JSON.parse(execFileSync(executable,['queue','runs',reversed.workspace,'--id',background.run.id],{cwd:temp,encoding:'utf8'}));
    const item=runs.items[0];if(item.recordedStatus==='completed'&&item.liveness.owner==='gone'){finished=item;break;}
    if(['failed','partial','interrupted'].includes(item.observedStatus))throw new Error('Installed background analysis failed: '+JSON.stringify(item));
    await new Promise(resolve=>setTimeout(resolve,30));
  }
  if(!finished)throw new Error('Installed background worker did not finish after launcher exit.');
  const jobs=JSON.parse(execFileSync(executable,['queue','list',reversed.workspace],{cwd:temp,encoding:'utf8'}));
  if(jobs.items[0].status!=='completed')throw new Error('Installed background component result was not completed.');
  const tool=path.join(temp,'automated-tool');
  const usage=JSON.parse(execFileSync(executable,['use',tool,'--json'],{cwd:temp,encoding:'utf8'}));
  if(usage.example.args[0]!==21) throw new Error('Installed usage example is wrong.');
  const {archiveVerificationReport}=await import(pathToFileURL(path.join(packagedRoot,'dist/verification-archive.js')).href);
  const archive=await archiveVerificationReport(reversed.workspace,{schema:'carve/reconstruction-verification@1',manifestSha256:'a'.repeat(64),status:'passed-supplied-cases',checkedAt:new Date().toISOString(),verifiedScope:'declared-external-harness-cases',passed:1,total:1,unknowns:['Synthetic archive fixture only; no reference executed by this archive test.'],unresolvedDependencies:[],limitations:[],results:[{name:'owned recorded sample',args:[21],passed:true,original:{kind:'return',value:42},candidate:{kind:'return',value:42}}]});
  await rm(app,{recursive:true});
  const recordedText=execFileSync(executable,['verification',reversed.workspace,'--id',archive.id,'--budget-bytes','4096'],{cwd:temp,encoding:'utf8'}),recorded=JSON.parse(recordedText);if(recorded.total!==1||recorded.unknownsCount!==1||recorded.receipt.responseBytes!==Buffer.byteLength(recordedText)-1||Object.hasOwn(recorded,'results'))throw new Error('Installed budgeted verification archive CLI failed.');
  const recordedClient=new Client({name:'carve-packed-verification-test',version:'1'});try{
    await recordedClient.connect(new StdioClientTransport({command:process.execPath,args:[path.join(packagedRoot,'dist/cli.js'),'serve','--root',temp],stderr:'pipe'}));
    const called=await recordedClient.callTool({name:'carve_verification',arguments:{workspace:'reconstruction-work',id:archive.id,view:'case',caseIndex:0,field:'original'}});if(called.isError||JSON.parse(JSON.parse(called.content[0].text).text).value!==42)throw new Error('Installed verification archive MCP failed: '+JSON.stringify(called));
  }finally{await recordedClient.close();}
  const invoked=JSON.parse(execFileSync(executable,['invoke',tool,'--args','[21]','--execute'],{cwd:temp,encoding:'utf8'}));
  if(invoked!==42) throw new Error('Installed independent invocation failed.');
  const transport=new StdioClientTransport({command:process.execPath,args:[path.join(prefix,'node_modules/reverse-engineering-carve/dist/cli.js'),'serve-tool',tool,'--execute'],stderr:'pipe'});
  const client=new Client({name:'carve-packed-runtime-test',version:'1'});
  try {
    await client.connect(transport);
    const called=await client.callTool({name:'capability',arguments:{args:[21]}});
    if(called.structuredContent?.value!==42) throw new Error('Installed independent MCP invocation failed.');
  } finally {await client.close();}
  const report = { installedFromTarball: true, cleanPrefix: true, sourceRemoved: true, independentResult: result,
    completeFeatureWorkflow:true,packagedWorkLedgerCliMcp:true,packagedPlatformCliMcp:true,packagedWorkPackageCliMcp:true,packagedProjectPlanCliMcp:true,packagedTargetIntent:true,packagedScopeCli:true,packagedScopeMcp:true,packagedFeatureFacets:true,packagedSkillExample:true,commonjsContrast:true,taskSetup:true,reconstructionTask:true,paginatedInventory:true,packagedNativeScript:true,packagedReconstructionDocs:true,packagedLoader:true,engineFreeLoaderMcp:true,packagedFunctionLibrary:true,packagedStatefulSequenceCli:true,packagedStatefulSequenceMcp:true,packagedContextBudget:true,packagedRecordedVerification:true,packagedRelocationMcp:true,relocatedEvidenceHashChecked:true,recordedReadAfterSourceRemoval:true,backgroundWorkerAfterLauncherExit:true,packageUsage:true,independentInvocation:true,independentMcp:true,
    packageBytes: packed[0].size, unpackedBytes: packed[0].unpackedSize, integrity: packed[0].integrity };
  await writeFile(path.join(root, 'artifacts/install-verification.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally { await rm(temp, { recursive: true, force: true }); }
