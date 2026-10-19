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
import {classifyImport,classifyPlatformDependencies,inspectPlatformDependencies,PLATFORM_CATEGORIES,PLATFORM_DEPENDENCY_RULES,PLATFORM_RULES_SHA256,PLATFORM_RULES_VERSION} from '../dist/platform-dependencies.js';
import {buildPe} from './fixtures/pe-image.mjs';

async function scratch(t){const root=await realpath(await mkdtemp(path.join(tmpdir(),'carve-platform-')));t.after(()=>rm(root,{recursive:true,force:true}));return root;}

test('the rule table classifies representative imports by name first, then by module, and reports the rule',()=>{
 const cases=[
  ['KERNEL32.dll','CreateFileW','file-system','windows-system','win32-files'],['kernel32.DLL','ReadFile','file-system','windows-system','win32-files'],
  ['KERNEL32.dll','LoadLibraryW','dynamic-loading','windows-system','module-loading'],['KERNEL32.dll','GetProcAddress','dynamic-loading','windows-system','module-loading'],
  ['KERNEL32.dll','CreateProcessW','process-thread','windows-system','win32-processes-threads-memory'],['KERNEL32.dll','InterlockedPushEntrySList','os-specific','windows-system','win32-exceptions-errors-debug'],
  ['KERNEL32.dll','GlobalMemoryStatusEx','os-specific','windows-system','win32-system-information-devices'],['KERNEL32.dll','MultiByteToWideChar','text-locale-time','windows-system','win32-text-locale-time'],
  ['KERNEL32.dll','WriteConsoleW','console-stdio','windows-system','win32-console'],['KERNEL32.dll',undefined,'os-specific','windows-system','windows-core-other'],
  ['ADVAPI32.dll','RegOpenKeyExW','registry-system','windows-system','registry'],['ADVAPI32.dll','CryptAcquireContextW','crypto-security','windows-system','crypto-apis'],
  ['ADVAPI32.dll','OpenProcessToken','crypto-security','windows-system','token-acl-sid'],['ADVAPI32.dll','SystemFunction036','crypto-security','windows-system','crypto-apis'],
  ['ADVAPI32.dll','GetUserNameW','os-specific','windows-system','win32-system-information-devices'],['ADVAPI32.dll','StartServiceW','registry-system','windows-system','services'],
  ['ADVAPI32.dll','SomethingUndocumented','registry-system','windows-system','advapi32-other'],
  ['RPCRT4.dll','UuidCreate','os-specific','windows-system','rpc-runtime'],['rpcrt4.dll','RpcStringFreeW','os-specific','windows-system','rpc-runtime'],['RPCRT4.dll',undefined,'os-specific','windows-system','rpc-runtime'],
  ['WS2_32.dll','connect','network','windows-system','network-modules'],['WS2_32.dll',undefined,'network','windows-system','network-modules'],['WININET.dll','InternetOpenW','network','windows-system','network-modules'],
  ['bcrypt.dll','BCryptGenRandom','crypto-security','windows-system','crypto-apis'],['CRYPT32.dll','CertFreeCertificateContext','crypto-security','windows-system','crypto-apis'],
  ['USER32.dll','CreateWindowExW','ui-graphics','windows-system','ui-graphics-modules'],['USER32.dll','CharUpperW','text-locale-time','windows-system','user32-text'],['GDI32.dll','TextOutA','ui-graphics','windows-system','ui-graphics-modules'],
  ['SHELL32.dll','ShellExecuteW','process-thread','windows-system','shell-execute'],['SHELL32.dll','SHGetFolderPathW','file-system','windows-system','shell-folders-files'],
  ['SHELL32.dll','Shell_NotifyIconW','ui-graphics','windows-system','shell-ui'],['SHELL32.dll','SHChangeNotify','registry-system','windows-system','com-system-integration-modules'],
  ['SHLWAPI.dll','PathFileExistsW','file-system','windows-system','shlwapi-paths'],['SHLWAPI.dll','StrStrIW','text-locale-time','windows-system','shlwapi-strings'],
  ['ole32.dll','CoCreateInstance','registry-system','windows-system','com-system-integration-modules'],['OLEAUT32.dll',undefined,'registry-system','windows-system','com-system-integration-modules'],
  ['VERSION.dll','GetFileVersionInfoW','file-system','windows-system','file-version-module'],['dbghelp.dll','MiniDumpWriteDump','os-specific','windows-system','debug-help-modules'],
  ['api-ms-win-core-file-l1-1-0.dll','CreateFileW','file-system','windows-system','win32-files'],['api-ms-win-core-synch-l1-2-0.dll','SomeNewApi','process-thread','windows-system','api-set-process-thread'],
  ['msvcrt.dll','fopen','file-system','c-runtime','crt-file-io'],['msvcrt.dll','printf','console-stdio','c-runtime','crt-stdio'],['msvcrt.dll','sprintf','text-locale-time','c-runtime','crt-string-formatting'],
  ['msvcrt.dll','malloc','runtime-library','c-runtime','crt-runtime'],['msvcrt.dll','_beginthreadex','process-thread','c-runtime','crt-process-environment'],['msvcrt.dll','strftime','text-locale-time','c-runtime','crt-locale-time'],
  ['api-ms-win-crt-stdio-l1-1-0.dll','__stdio_common_vfprintf','console-stdio','c-runtime','crt-stdio'],['api-ms-win-crt-stdio-l1-1-0.dll','__stdio_common_vsprintf_s','text-locale-time','c-runtime','crt-string-formatting'],
  ['VCRUNTIME140_1.dll','__CxxFrameHandler4','runtime-library','c-runtime','crt-runtime'],['MSVCP140.dll','?_Xlength_error@std@@YAXPEBD@Z','runtime-library','c-runtime','crt-runtime'],
  ['MSVCR100D.dll','CreateFileW','runtime-library','c-runtime','crt-runtime'],
  ['helper.dll','CreateFileW','unknown','other-module','non-system-module'],['Qt5Core.dll','QString::fromUtf8','unknown','other-module','non-system-module']];
 for(const [module,name,category,surface,ruleId] of cases)assert.deepEqual(classifyImport(module,name),{category,surface,ruleId},`${module}!${name??'(ordinal)'}`);
 const ids=PLATFORM_DEPENDENCY_RULES.map(r=>r.id);assert.equal(new Set(ids).size,ids.length,'rule ids are unique');
 assert.ok(PLATFORM_DEPENDENCY_RULES.every(r=>r.category in PLATFORM_CATEGORIES&&r.category!=='unknown'));
 assert.match(PLATFORM_RULES_SHA256,/^[a-f0-9]{64}$/);assert.equal(PLATFORM_RULES_VERSION,'carve/platform-rules@1');
 assert.deepEqual(Object.keys(PLATFORM_CATEGORIES),['file-system','process-thread','network','ui-graphics','registry-system','crypto-security','dynamic-loading','text-locale-time','console-stdio','runtime-library','os-specific','unknown']);
});

test('PE32 and PE32+ images are classified per import with call-site counts; unread descriptors still name their module',async t=>{
 const root=await scratch(t),file64=path.join(root,'app.exe'),file32=path.join(root,'app32.exe');
 const imports=[{name:'KERNEL32.dll',entries:['CreateFileW','LoadLibraryW']},{name:'WS2_32.dll',entries:[{ordinal:115},'connect']},{name:'helper.dll',entries:['Run']}];
 await writeFile(file64,buildPe({imports,delay:[{name:'USER32.dll',entries:['MessageBoxW']}],code:({slot,textRva})=>{
  const b=[],i32=v=>{const x=Buffer.alloc(4);x.writeInt32LE(v);b.push(...x);},call=k=>{b.push(0xff,0x15);i32(slot(k)-(textRva+b.length+4));};
  call('KERNEL32.dll!CreateFileW');call('KERNEL32.dll!CreateFileW');call('WS2_32.dll!connect');call('USER32.dll!MessageBoxW');b.push(0xc3);return Buffer.from(b);}}));
 const scan=await readPeImportCalls(file64),result=classifyPlatformDependencies(scan.metadata,scan.sites);
 assert.deepEqual(result.imports.map(i=>[i.module,i.name??'#'+i.ordinal,i.importKind,i.category,i.ruleId,i.callSites]),[
  ['KERNEL32.dll','CreateFileW','import','file-system','win32-files',2],['KERNEL32.dll','LoadLibraryW','import','dynamic-loading','module-loading',0],
  ['WS2_32.dll','#115','import','network','network-modules',0],['WS2_32.dll','connect','import','network','network-modules',1],
  ['helper.dll','Run','import','unknown','non-system-module',0],['USER32.dll','MessageBoxW','delay-import','ui-graphics','ui-graphics-modules',1]]);
 assert.equal(result.rulesSha256,PLATFORM_RULES_SHA256);assert.deepEqual(result.unreadModules,[]);
 await writeFile(file32,buildPe({plus:false,imports:[{name:'ADVAPI32.dll',entries:['RegOpenKeyExA']},{name:'msvcrt.dll',entries:['fopen','printf']}],boundFirst:true}));
 const meta32=(await readPeImportCalls(file32)).metadata,classic=classifyPlatformDependencies(meta32,null);
 assert.deepEqual(classic.imports.map(i=>[i.module,i.name,i.category,i.surface,i.callSites]),[['msvcrt.dll','fopen','file-system','c-runtime',null],['msvcrt.dll','printf','console-stdio','c-runtime',null]]);
 assert.deepEqual(classic.unreadModules,[{module:'ADVAPI32.dll',importKind:'import',status:'bound-address-table-without-lookup-table',category:'registry-system',surface:'windows-system',ruleId:'advapi32-other'}]);
});

test('workspace views keep source hashes, budgets and traceable rules',async t=>{
 const root=await scratch(t),input=path.join(root,'input'),workspace=path.join(root,'work');await mkdir(input);
 const many=Array.from({length:30},(_,i)=>`Function${i}`);
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'KERNEL32.dll',entries:['CreateFileW','ReadFile','WriteFile','LoadLibraryW']},{name:'USER32.dll',entries:['CreateWindowExW']},{name:'plugin.dll',entries:many}],
  code:({slot,textRva})=>{const b=Buffer.from([0xff,0x15,0,0,0,0,0xc3]);b.writeInt32LE(slot('KERNEL32.dll!ReadFile')-(textRva+6),2);return b;}}));
 await survey(input,{workspace});
 const summary=await inspectPlatformDependencies(workspace,{file:'app.exe'});
 assert.equal(summary.schema,'carve/platform-dependencies@1');assert.equal(summary.executesTarget,false);assert.equal(summary.callSitesScanned,true);
 assert.deepEqual(summary.summary,{'file-system':{imports:3,callSites:1},'ui-graphics':{imports:1,callSites:0},'dynamic-loading':{imports:1,callSites:0},unknown:{imports:30,callSites:0}});
 assert.deepEqual(summary.totals,{imports:35,unknown:30,otherModules:1,unreadModules:0});assert.equal(summary.provider.rulesSha256,PLATFORM_RULES_SHA256);
 assert.match(summary.scope,/not observed behavior; it does not say a target-platform replacement exists or that anything was ported/);
 assert.equal(summary.receipt.responseBytes,Buffer.byteLength(JSON.stringify(summary)));
 const cards=await inspectPlatformDependencies(workspace,{file:'app.exe',view:'categories'});
 const unknown=cards.items.find(c=>c.category==='unknown');assert.deepEqual([unknown.samples.values.length,unknown.samples.total,unknown.modules.values,unknown.rules.values],[8,30,['plugin.dll'],['non-system-module']]);
 assert.deepEqual(cards.items.find(c=>c.category==='file-system').surfaces,{'windows-system':3,'c-runtime':0,'other-module':0});
 const files=await inspectPlatformDependencies(workspace,{file:'app.exe',view:'imports',category:'file-system'});assert.deepEqual(files.items.map(i=>i.name),['CreateFileW','ReadFile','WriteFile']);
 const pages=[];let offset=0;for(;;){const page=await inspectPlatformDependencies(workspace,{file:'app.exe',view:'imports',offset,limit:100,budgetBytes:2600});assert.ok(page.receipt.responseBytes<=2600);pages.push(...page.items);if(page.nextOffset===null)break;offset=page.nextOffset;}
 assert.equal(pages.length,35);
 const rules=await inspectPlatformDependencies(workspace,{file:'app.exe',view:'rules',limit:100,budgetBytes:65536});
 assert.deepEqual(rules.items.map(r=>r.id),PLATFORM_DEPENDENCY_RULES.map(r=>r.id));assert.equal(rules.items[0].order,0);assert.equal(typeof rules.items[0].name,'string');
 await assert.rejects(()=>inspectPlatformDependencies(workspace,{file:'app.exe',view:'imports',category:'gaming'}),/Unknown category/);
 await assert.rejects(()=>inspectPlatformDependencies(workspace,{file:'app.exe',view:'graph'}),/Use view summary, categories, imports or rules/);
 const evidence=JSON.parse(await readFile(summary.evidence,'utf8'));assert.equal(evidence.schema,'carve/platform-dependencies-evidence@1');assert.equal(evidence.imports.length,35);
 const db=new DatabaseSync(path.join(workspace,'index.sqlite'),{readOnly:true});
 try{assert.equal(db.prepare("SELECT count(*) n FROM observations WHERE kind='platform-dependencies'").get().n,1);}finally{db.close();}
 await writeFile(path.join(input,'app.exe'),buildPe({imports:[{name:'KERNEL32.dll',entries:['ExitProcess']}]}));
 await assert.rejects(()=>inspectPlatformDependencies(workspace,{file:'app.exe'}),/changed since inventory/);
});

// Real Windows images in the local Ghidra distribution; nothing is executed.
const ghidra=fileURLToPath(new URL('../artifacts/engines/ghidra/ghidra_12.1.4_PUBLIC/',import.meta.url));
const realFiles=['GPL/DMG/data/os/win_x86_32/llio_amd64.dll','GPL/DMG/data/os/win_x86_32/llio_i386.dll','GPL/DMG/data/os/win_x86_32/llio_ia64.dll','GPL/DMG/data/os/win_x86_64/llio_amd64.dll','GPL/DMG/data/os/win_x86_64/llio_i386.dll','GPL/DMG/data/os/win_x86_64/llio_ia64.dll',
 'GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_24.exe','GPL/DemanglerGnu/os/win_x86_64/demangler_gnu_v2_41.exe','Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe','Ghidra/Features/Decompiler/os/win_x86_64/sleigh.exe',
 'Ghidra/Features/FileFormats/data/sevenzipnativelibs/Windows-amd64/lib7-Zip-JBinding.dll','Ghidra/Features/FileFormats/os/win_x86_64/lzfse.exe','Ghidra/Features/PDB/os/win_x86_64/pdb.exe',
 'docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceSrc.exe','docs/GhidraClass/ExerciseFiles/VersionTracking/WallaceVersion2.exe','docs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe'];
test('sixteen real Windows images: every import matches a specific rule and documented examples land where expected',async t=>{
 if(!existsSync(ghidra)){t.skip('local Ghidra distribution is not available');return;}
 const totals={},found=new Map();let imports=0,sites=0;
 for(const relative of realFiles){
  const scan=await readPeImportCalls(path.join(ghidra,relative)),result=classifyPlatformDependencies(scan.metadata,scan.architecture?scan.sites:null);
  for(const i of result.imports){imports++;sites+=i.callSites??0;totals[i.category]=(totals[i.category]??0)+1;found.set(`${path.basename(relative)}|${i.module}!${i.name??'#'+i.ordinal}`,i);
   assert.ok(!['no-rule','windows-core-other','advapi32-other','non-system-module'].includes(i.ruleId),`${relative} ${i.module}!${i.name} only matched a fallback rule`);}
  assert.deepEqual(result.unreadModules,[]);
 }
 assert.equal(imports,1323);assert.equal(sites,5116);
 assert.deepEqual(totals,{'os-specific':186,'file-system':166,'text-locale-time':216,'process-thread':463,'dynamic-loading':70,'console-stdio':95,'runtime-library':92,'registry-system':13,'ui-graphics':22});
 const pick=(file,key)=>{const i=found.get(`${file}|${key}`);assert.ok(i,key);return[i.category,i.surface,i.ruleId];};
 assert.deepEqual(pick('WinHelloCPP.exe','USER32.dll!CreateWindowExA'),['ui-graphics','windows-system','ui-graphics-modules']);
 assert.deepEqual(pick('WinHelloCPP.exe','GDI32.dll!TextOutA'),['ui-graphics','windows-system','ui-graphics-modules']);
 assert.deepEqual(pick('lib7-Zip-JBinding.dll','OLEAUT32.dll!SysAllocString'),['registry-system','windows-system','com-system-integration-modules']);
 assert.deepEqual(pick('pdb.exe','OLEAUT32.dll!#6'),['registry-system','windows-system','com-system-integration-modules']);
 assert.deepEqual(pick('decompile.exe','KERNEL32.dll!CreateFileW'),['file-system','windows-system','win32-files']);
 assert.deepEqual(pick('WallaceSrc.exe','MSVCR100D.dll!printf'),['console-stdio','c-runtime','crt-stdio']);
 assert.equal(found.get('decompile.exe|KERNEL32.dll!CreateFileW').callSites>0,true);
 assert.equal(found.get('llio_ia64.dll|KERNEL32.dll!CreateFileW').callSites,null,'IA-64 call sites are not scanned');
});
