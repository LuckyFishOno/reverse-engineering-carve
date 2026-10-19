import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {mkdtemp,mkdir,writeFile,readFile,rm,realpath} from 'node:fs/promises';
import {DatabaseSync} from 'node:sqlite';
import {survey} from '../dist/survey.js';
import {readPeImportCalls} from '../dist/pe-calls.js';
import {classifyPlatformDependencies,PLATFORM_CATEGORIES} from '../dist/platform-dependencies.js';
import {targetSpecSchema} from '../dist/target.js';
import {adapterGuidance,assessTargetAdapters,inspectTargetAdapters,TARGET_ADAPTER_GUIDANCE,ADAPTER_AVAILABILITY,ADAPTER_GUIDANCE_SHA256,ADAPTER_GUIDANCE_VERSION} from '../dist/target-adapters.js';
import {buildPe} from './fixtures/pe-image.mjs';

const target=(platform,delivery)=>({schema:'carve/target@1',platform,delivery});
const platforms=['windows','macos','linux','ios','android','browser','server','portable'],deliveries=['desktop-app','mobile-app','web-app','module','cli','service'];
const validTargets=platforms.flatMap(p=>deliveries.map(d=>target(p,d))).filter(t=>targetSpecSchema.safeParse(t).success);
async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-adapters-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}

test('every category has guidance for every valid target, with stable ids and documented availability',()=>{
 assert.equal(validTargets.length,26);
 for(const t of validTargets)for(const category of Object.keys(PLATFORM_CATEGORIES)){
  const entry=adapterGuidance(category,t);assert.ok(entry.availability in ADAPTER_AVAILABILITY,`${category} ${t.platform}/${t.delivery}`);
  assert.ok(entry.options.length>0&&entry.cautions.length>0,entry.id);
 }
 const ids=TARGET_ADAPTER_GUIDANCE.map(e=>e.id);assert.equal(new Set(ids).size,ids.length,'guidance ids are unique');
 assert.match(ADAPTER_GUIDANCE_SHA256,/^[a-f0-9]{64}$/);assert.equal(ADAPTER_GUIDANCE_VERSION,'carve/target-adapter-guidance@1');
 const pick=(category,p,d)=>{const e=adapterGuidance(category,target(p,d));return[e.availability,e.id];};
 assert.deepEqual(pick('file-system','macos','desktop-app'),['standard-library','fs-posix']);
 assert.deepEqual(pick('ui-graphics','macos','desktop-app'),['native-framework','ui-macos']);
 assert.deepEqual(pick('registry-system','macos','desktop-app'),['decision-required','sys-macos']);
 assert.deepEqual(pick('console-stdio','macos','desktop-app'),['restricted','console-graphical-delivery']);
 assert.deepEqual(pick('console-stdio','macos','cli'),['standard-library','console-posix']);
 assert.deepEqual(pick('ui-graphics','macos','cli'),['not-applicable','ui-headless-delivery']);
 assert.deepEqual(pick('ui-graphics','windows','desktop-app'),['same-platform','same-platform-windows-ui-graphics']);
 assert.deepEqual(pick('ui-graphics','windows','service'),['not-applicable','ui-headless-delivery'],'delivery limits come before same-platform reuse');
 assert.deepEqual(pick('network','browser','web-app'),['requires-helper','net-browser']);
 assert.deepEqual(pick('process-thread','browser','web-app'),['web-platform-api','proc-browser']);
 assert.deepEqual(pick('dynamic-loading','ios','mobile-app'),['restricted','dyn-ios']);
 assert.deepEqual(pick('crypto-security','ios','mobile-app'),['native-framework','crypto-apple']);
 assert.deepEqual(pick('registry-system','server','service'),['decision-required','sys-server']);
 assert.deepEqual(pick('file-system','portable','module'),['decision-required','fs-portable']);
 assert.deepEqual(pick('unknown','linux','cli'),['inspect-separately','unknown-modules']);
});

test('an assessment has one card per present category, bounded samples and explicit decision lists',()=>{
 const imports=[
  ...Array.from({length:12},(_,i)=>({module:'KERNEL32.dll',importKind:'import',name:`CreateFile${i}`,slotRva:i,category:'file-system',surface:'windows-system',ruleId:'win32-files',callSites:1})),
  {module:'USER32.dll',importKind:'import',name:'CreateWindowExW',slotRva:100,category:'ui-graphics',surface:'windows-system',ruleId:'ui-graphics-modules',callSites:3},
  {module:'ADVAPI32.dll',importKind:'import',name:'RegOpenKeyExW',slotRva:101,category:'registry-system',surface:'windows-system',ruleId:'registry',callSites:0},
  {module:'plugin.dll',importKind:'import',name:'Run',slotRva:102,category:'unknown',surface:'other-module',ruleId:'non-system-module',callSites:null}];
 const mac=assessTargetAdapters(imports,target('macos','desktop-app'));
 assert.equal(mac.assessment,'static-guidance-not-verified');assert.equal(mac.guidanceSha256,ADAPTER_GUIDANCE_SHA256);
 assert.deepEqual(mac.cards.map(c=>[c.category,c.availability,c.imports,c.callSites]),[['file-system','standard-library',12,12],['ui-graphics','native-framework',1,3],['registry-system','decision-required',1,0],['unknown','inspect-separately',1,null]]);
 const files=mac.cards[0];assert.deepEqual([files.samples.values.length,files.samples.total,files.modules.values],[8,12,['KERNEL32.dll']]);
 assert.deepEqual(mac.needsDecision,['registry-system','unknown']);assert.deepEqual(mac.notApplicable,[]);
 assert.deepEqual(mac.byAvailability,{'standard-library':{categories:1,imports:12},'native-framework':{categories:1,imports:1},'decision-required':{categories:1,imports:1},'inspect-separately':{categories:1,imports:1}});
 const service=assessTargetAdapters(imports,target('linux','service'));assert.deepEqual(service.notApplicable,['ui-graphics']);
 assert.match(mac.scope,/does not show that a replacement behaves like the original/);
 assert.throws(()=>assessTargetAdapters(imports,target('browser','desktop-app')),/compatible with the declared target platform/);
 assert.throws(()=>assessTargetAdapters(imports,{...target('macos','cli'),gpu:true}),/Unrecognized key/);
});

test('workspace inspection rehashes the source, records evidence per target and pages cards within budget',async t=>{
 const root=await scratch(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'KERNEL32.dll',entries:['CreateFileW','CreateThread']},{name:'WS2_32.dll',entries:['connect']},{name:'USER32.dll',entries:['MessageBoxW']}],
  code:({slot,textRva})=>{const b=Buffer.from([0xff,0x15,0,0,0,0,0xc3]);b.writeInt32LE(slot('WS2_32.dll!connect')-(textRva+6),2);return b;}}));
 await survey(input,{workspace});
 const mac=await inspectTargetAdapters(workspace,{file:'app.exe',target:target('macos','desktop-app')});
 assert.equal(mac.schema,'carve/target-adapters@1');assert.equal(mac.executesTarget,false);assert.equal(mac.assessment,'static-guidance-not-verified');
 assert.deepEqual(mac.needsDecision,[]);assert.equal(mac.receipt.responseBytes,Buffer.byteLength(JSON.stringify(mac)));
 const web=await inspectTargetAdapters(workspace,{file:'app.exe',target:target('browser','web-app'),view:'cards',budgetBytes:3000});
 assert.ok(web.receipt.responseBytes<=3000);assert.deepEqual(web.needsDecision,['network']);assert.notEqual(web.observationId,mac.observationId);
 const cards=[];let offset=0;for(;;){const page=await inspectTargetAdapters(workspace,{file:'app.exe',target:target('browser','web-app'),view:'cards',offset,limit:1,budgetBytes:4096});cards.push(...page.items);if(page.nextOffset===null)break;offset=page.nextOffset;}
 assert.deepEqual(cards.map(c=>[c.category,c.availability,c.callSites]),[['file-system','web-platform-api',0],['process-thread','web-platform-api',0],['network','requires-helper',1],['ui-graphics','web-platform-api',0]]);
 const evidence=JSON.parse(await readFile(web.evidence,'utf8'));assert.equal(evidence.schema,'carve/target-adapter-evidence@1');assert.deepEqual(evidence.assessment.target,target('browser','web-app'));
 const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});
 try{assert.equal(db.prepare("SELECT count(*) n FROM observations WHERE kind='target-adapter-assessment'").get().n,2);}finally{db.close();}
 await assert.rejects(()=>inspectTargetAdapters(workspace,{file:'app.exe',target:target('portable','cli')}),/compatible with the declared target platform/);
 await assert.rejects(()=>inspectTargetAdapters(workspace,{file:'app.exe',target:target('macos','cli'),view:'all'}),/Use view summary or cards/);
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'KERNEL32.dll',entries:['ExitProcess']}]}));
 await assert.rejects(()=>inspectTargetAdapters(workspace,{file:'app.exe',target:target('macos','cli')}),/changed since inventory/);
});

const ghidra=fileURLToPath(new URL('../artifacts/engines/ghidra/ghidra_12.1.4_PUBLIC/',import.meta.url));
test('real Windows images: the GUI program needs UI adapters, console tools do not, and COM needs a decision on macOS',async t=>{
 if(!existsSync(ghidra)){t.skip('local Ghidra distribution is not available');return;}
 const assess=async(relative,t2)=>{const scan=await readPeImportCalls(path.join(ghidra,relative));return assessTargetAdapters(classifyPlatformDependencies(scan.metadata,scan.architecture?scan.sites:null).imports,t2);};
 const card=(a,category)=>{const c=a.cards.find(x=>x.category===category);return c?[c.availability,c.imports]:null;};
 const hello='docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe';
 assert.deepEqual(card(await assess(hello,target('macos','desktop-app')),'ui-graphics'),['native-framework',22]);
 assert.deepEqual(card(await assess(hello,target('browser','web-app')),'ui-graphics'),['web-platform-api',22]);
 assert.deepEqual(card(await assess(hello,target('linux','cli')),'ui-graphics'),['not-applicable',22]);
 const wallace=await assess('docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceSrc.exe',target('macos','cli'));
 assert.equal(card(wallace,'ui-graphics'),null);assert.deepEqual(card(wallace,'console-stdio'),['standard-library',3]);assert.deepEqual(card(wallace,'runtime-library'),['standard-library',20]);
 const sevenZip=await assess('Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll',target('macos','module'));
 assert.deepEqual(card(sevenZip,'registry-system'),['decision-required',6]);assert.ok(sevenZip.needsDecision.includes('registry-system'));
 const ia64=await assess('GPL/DMG/data/os/win_x86_64/llio_ia64.dll',target('linux','module'));assert.ok(ia64.cards.every(c=>c.callSites===null),'IA-64 call sites are not scanned');
});
