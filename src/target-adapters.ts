import {realpath,readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {publishEvidence,recordObservation} from './pe-loader.js';
import {readPeImportCalls} from './pe-calls.js';
import {classifyPlatformDependencies,PLATFORM_CATEGORIES,type PlatformCategory,type ClassifiedImport} from './platform-dependencies.js';
import {targetSpecSchema,type TargetSpec} from './target.js';

// What each source-platform dependency category generally needs on a declared target. This is a
// static, versioned guidance table written from platform documentation, matched by category,
// target platform and delivery form (first match wins, entry id reported). It is not a build, a
// compatibility test or proof that a replacement behaves like the original; every card says so.
export const ADAPTER_AVAILABILITY={
 'same-platform':'The source API family exists on the target; check version and SDK availability',
 'standard-library':'Usually covered by the target C/C++ or language standard library and POSIX',
 'native-framework':'Needs the target platform frameworks; an adapter layer rewrites calls',
 'web-platform-api':'Covered only by browser APIs with their permission and capability limits',
 'restricted':'Partly available; some source behavior has no target counterpart',
 'requires-helper':'Needs a server, proxy or native helper outside the target runtime',
 'not-applicable':'Does not exist in this delivery form; remove or move to another component',
 'decision-required':'No direct counterpart; a person must choose the replacement design',
 'inspect-separately':'A non-system module; classify and plan it as its own component'} as const;
export type AdapterAvailability=keyof typeof ADAPTER_AVAILABILITY;
type Platform=TargetSpec['platform'];type Delivery=TargetSpec['delivery'];
type Guidance={id:string;category:PlatformCategory;platforms?:readonly Platform[];deliveries?:readonly Delivery[];availability:AdapterAvailability;options:readonly string[];cautions:readonly string[]};
const posix=['macos','linux'] as const,mobile=['ios','android'] as const,anyPlatform=undefined;
const g=(id:string,category:PlatformCategory,availability:AdapterAvailability,where:{platforms?:readonly Platform[];deliveries?:readonly Delivery[]},options:string[],cautions:string[]):Guidance=>({id,category,availability,...where,options,cautions});

export const TARGET_ADAPTER_GUIDANCE:readonly Guidance[]=[
 // Delivery forms without a user interface or console come first.
 g('ui-headless-delivery','ui-graphics','not-applicable',{deliveries:['cli','service','module']},['Move UI into a separate client component','Expose the core as a library or service interface'],['Window message loops and dialogs have no headless counterpart']),
 g('ui-server','ui-graphics','not-applicable',{platforms:['server','portable']},['Serve a separate web or desktop client'],['Rendering and input handling must leave the core module']),
 g('console-graphical-delivery','console-stdio','restricted',{deliveries:['desktop-app','mobile-app','web-app']},['Route output to a log or an in-app view','Use a terminal component only if the product needs one'],['Console windows, colors and cursor control are not part of a GUI app']),
 // Same platform: the source API family is still there.
 ...(['file-system','process-thread','network','ui-graphics','registry-system','crypto-security','dynamic-loading','text-locale-time','console-stdio','runtime-library','os-specific'] as const).map(category=>
  g(`same-platform-windows-${category}`,category,'same-platform',{platforms:['windows']},['Keep the Win32 / CRT calls or wrap them behind the module interface'],['Check minimum Windows version, SDK and runtime redistributables'])),
 // Files and paths.
 g('fs-posix','file-system','standard-library',{platforms:posix},['POSIX open/read/write/stat','C++17 <filesystem>','Foundation FileManager (macOS)'],['Drive letters and backslash separators','Case sensitivity differs (Linux sensitive, macOS usually insensitive)','UTF-16 wide paths become UTF-8','Windows share modes and mandatory locks have no direct equivalent']),
 g('fs-mobile','file-system','restricted',{platforms:mobile},['App container directories','Document pickers and platform storage APIs'],['No arbitrary filesystem paths','Sandbox and user-permission rules']),
 g('fs-browser','file-system','web-platform-api',{platforms:['browser']},['Origin Private File System','File System Access API where supported','File input and download'],['No arbitrary paths; access is per user grant','API support differs between browsers']),
 g('fs-server','file-system','standard-library',{platforms:['server']},['POSIX or language file APIs','Object storage when files are shared between instances'],['Containers may have read-only or ephemeral filesystems']),
 g('fs-portable','file-system','decision-required',{platforms:['portable']},['Inject a storage interface from the host'],['A portable module should not assume a filesystem']),
 // Processes, threads, synchronization, OS memory.
 g('proc-posix','process-thread','standard-library',{platforms:posix},['std::thread / pthreads','posix_spawn or fork/exec','mmap/mprotect for VirtualAlloc/VirtualProtect','Condition variables and semaphores for events'],['Waitable handles and WaitForMultipleObjects need redesign','Command-line quoting and inheritance differ','Fiber-local storage has no direct equivalent']),
 g('proc-mobile','process-thread','restricted',{platforms:mobile},['Platform threads and dispatch queues / coroutines'],['iOS forbids child processes; Android restricts them','Background execution limits']),
 g('proc-browser','process-thread','web-platform-api',{platforms:['browser']},['Web Workers','SharedArrayBuffer and Atomics with cross-origin isolation'],['No processes','No blocking waits on the main thread']),
 g('proc-server','process-thread','standard-library',{platforms:['server']},['Language threads, process APIs and job queues'],['Container process limits']),
 g('proc-portable','process-thread','decision-required',{platforms:['portable']},['Accept a scheduler or executor from the host'],['A portable module should not create OS threads by itself']),
 // Network.
 g('net-posix','network','standard-library',{platforms:posix},['BSD sockets (close to Winsock)','URLSession (macOS) or libcurl for WinINet/WinHTTP'],['WSAStartup, WSA error codes and overlapped I/O differ','Use kqueue (macOS) or epoll (Linux) instead of IOCP']),
 g('net-mobile','network','native-framework',{platforms:mobile},['URLSession / Network.framework','OkHttp or platform HTTP stacks'],['Transport security rules','Background and battery limits']),
 g('net-browser','network','requires-helper',{platforms:['browser']},['fetch, WebSocket, WebTransport, WebRTC','A server-side proxy for raw TCP/UDP protocols'],['No raw sockets','CORS and mixed-content rules']),
 g('net-server','network','standard-library',{platforms:['server']},['Sockets and HTTP client/server libraries'],['Firewall and container networking']),
 g('net-portable','network','decision-required',{platforms:['portable']},['Inject a transport interface from the host'],['A portable module should not open sockets itself']),
 // UI, graphics, input, multimedia.
 g('ui-macos','ui-graphics','native-framework',{platforms:['macos']},['AppKit or SwiftUI','Core Graphics for GDI drawing','A cross-platform toolkit (Qt and similar)'],['The Win32 window/message model has no equivalent; the event loop is redesigned','Resources and dialogs are rebuilt']),
 g('ui-linux','ui-graphics','native-framework',{platforms:['linux']},['GTK or Qt','Cairo or Skia for drawing'],['The Win32 window/message model is redesigned']),
 g('ui-mobile','ui-graphics','native-framework',{platforms:mobile},['UIKit / SwiftUI','Android Views / Jetpack Compose'],['Desktop window layouts do not fit mobile screens and input']),
 g('ui-browser','ui-graphics','web-platform-api',{platforms:['browser']},['DOM and CSS','Canvas, WebGL or WebGPU for drawing'],['No native dialogs or multiple top-level windows','Keyboard shortcuts compete with the browser']),
 // Registry, services, COM, shell integration.
 g('sys-macos','registry-system','decision-required',{platforms:['macos']},['UserDefaults / property lists for settings','launchd for background services','Direct calls or XPC instead of COM'],['There is no registry or COM; data layout and activation must be redesigned']),
 g('sys-linux','registry-system','decision-required',{platforms:['linux']},['XDG config files','systemd services','D-Bus instead of COM'],['There is no registry or COM']),
 g('sys-mobile','registry-system','decision-required',{platforms:mobile},['UserDefaults / SharedPreferences','Platform background task APIs'],['No services, registry or COM']),
 g('sys-browser','registry-system','decision-required',{platforms:['browser']},['localStorage or IndexedDB for settings','Service workers for limited background work'],['No services, registry, COM or shell integration']),
 g('sys-server','registry-system','decision-required',{platforms:['server','portable']},['Configuration files or environment variables','Host-provided configuration'],['No registry or COM']),
 // Cryptography, certificates, tokens, access control.
 g('crypto-apple','crypto-security','native-framework',{platforms:['macos','ios']},['CryptoKit / Security.framework','Keychain for credentials','OpenSSL or libsodium for portability'],['Token, ACL and SID logic has no direct counterpart; Unix permissions and sandbox entitlements differ']),
 g('crypto-linux-server','crypto-security','standard-library',{platforms:['linux','server']},['OpenSSL or libsodium','libsecret or a secrets store'],['Token, ACL and SID logic must be redesigned']),
 g('crypto-android','crypto-security','native-framework',{platforms:['android']},['Java Cryptography Architecture','Android Keystore'],['Token and ACL logic has no counterpart']),
 g('crypto-browser','crypto-security','web-platform-api',{platforms:['browser']},['Web Crypto API'],['Limited algorithm set and asynchronous API','No keychain, certificate store or ACL access']),
 g('crypto-portable','crypto-security','standard-library',{platforms:['portable']},['A pure library such as libsodium compiled with the module'],['Key storage must come from the host']),
 // Dynamic loading.
 g('dyn-posix','dynamic-loading','standard-library',{platforms:[...posix,'server']},['dlopen / dlsym'],['Every DLL loaded at runtime must itself be found and ported','GetProcAddress names hide dependencies; inventory them first']),
 g('dyn-ios','dynamic-loading','restricted',{platforms:['ios']},['Link modules statically or ship signed frameworks'],['Loading downloaded code is not allowed']),
 g('dyn-android','dynamic-loading','restricted',{platforms:['android']},['System.loadLibrary for bundled native libraries'],['Loaded libraries must ship inside the app']),
 g('dyn-browser','dynamic-loading','web-platform-api',{platforms:['browser']},['import() of JavaScript or WebAssembly modules'],['Only same-origin or CORS-allowed modules']),
 g('dyn-portable','dynamic-loading','decision-required',{platforms:['portable']},['Have the host supply plugins explicitly'],['A portable module should not load libraries by itself']),
 // Text encoding, locale, time.
 g('text-native','text-locale-time','standard-library',{platforms:[...posix,...mobile,'server','portable']},['UTF-8 strings with iconv or ICU','std::chrono / clock_gettime','Platform locale APIs (CFLocale, java.util.Locale)'],['wchar_t is 16-bit on Windows but 32-bit on macOS/Linux','ANSI code pages need explicit conversion','FILETIME counts from 1601, Unix time from 1970']),
 g('text-browser','text-locale-time','web-platform-api',{platforms:['browser']},['TextEncoder / TextDecoder','Intl APIs','Date / Temporal'],['Legacy code pages need explicit decoding']),
 // Console and standard streams.
 g('console-posix','console-stdio','standard-library',{platforms:[...posix,'server']},['stdio and termios','ANSI escape sequences for colors and cursor'],['Console code pages and Ctrl handlers differ (use signals)']),
 g('console-other','console-stdio','not-applicable',{platforms:[...mobile,'browser','portable']},['Route output to logs or the host'],['No console']),
 // C/C++ runtime.
 g('crt-native','runtime-library','standard-library',{platforms:[...posix,...mobile,'server']},['libc / libc++ of the target toolchain'],['MSVC-only functions (_s variants, _ prefixed POSIX names) need replacements','Structured exception handling (__try) needs another design']),
 g('crt-browser-portable','runtime-library','restricted',{platforms:['browser','portable']},['Compile to WebAssembly with Emscripten or WASI','Or rewrite the logic in the target language'],['Standard library coverage depends on the toolchain']),
 // Other Windows-specific facilities.
 g('os-specific-native','os-specific','decision-required',{platforms:[...posix,...mobile,'server']},['C++ exceptions or signals instead of SEH','sysctl / uname for system information','IOKit (macOS) or ioctl for devices'],['Debugger, unwind and device APIs have no portable form']),
 g('os-specific-browser-portable','os-specific','not-applicable',{platforms:['browser','portable']},['Remove or move behind a host interface'],['Not available in this environment']),
 g('unknown-modules','unknown','inspect-separately',{},['Classify the module itself (its own imports and exports)','Decide whether it is ported, replaced or dropped'],['Its behavior and dependencies are not covered by this assessment'])
];
export const ADAPTER_GUIDANCE_VERSION='carve/target-adapter-guidance@1';
export const ADAPTER_GUIDANCE_SHA256=digest(JSON.stringify(TARGET_ADAPTER_GUIDANCE));

export function adapterGuidance(category:PlatformCategory,target:TargetSpec){
 const found=TARGET_ADAPTER_GUIDANCE.find(entry=>entry.category===category&&(!entry.platforms||entry.platforms.includes(target.platform))&&(!entry.deliveries||entry.deliveries.includes(target.delivery)));
 if(!found)throw new Error(`No adapter guidance for ${category} on ${target.platform}/${target.delivery}.`);
 return found;
}

const LIST=8;
export function assessTargetAdapters(imports:readonly ClassifiedImport[],targetInput:unknown){
 const target=targetSpecSchema.parse(targetInput),cards=[];
 for(const category of Object.keys(PLATFORM_CATEGORIES) as PlatformCategory[]){
  const items=imports.filter(i=>i.category===category);if(!items.length)continue;
  const guidance=adapterGuidance(category,target),samples=items.map(i=>`${i.module}!${i.name??'#'+i.ordinal}`),modules=[...new Set(items.map(i=>i.module))];
  const sites=items.some(i=>i.callSites===null)?null:items.reduce((n,i)=>n+(i.callSites??0),0);
  cards.push({category,label:PLATFORM_CATEGORIES[category],imports:items.length,callSites:sites,availability:guidance.availability,meaning:ADAPTER_AVAILABILITY[guidance.availability],guidanceId:guidance.id,
   options:guidance.options,cautions:guidance.cautions,modules:{values:modules.slice(0,LIST),total:modules.length},samples:{values:samples.slice(0,LIST),total:samples.length}});
 }
 const byAvailability:Record<string,{categories:number;imports:number}>={};
 for(const card of cards){const entry=byAvailability[card.availability]??={categories:0,imports:0};entry.categories++;entry.imports+=card.imports;}
 return{schema:'carve/target-adapter-assessment@1',target,guidanceVersion:ADAPTER_GUIDANCE_VERSION,guidanceSha256:ADAPTER_GUIDANCE_SHA256,cards,byAvailability,
  needsDecision:cards.filter(c=>c.availability==='decision-required'||c.availability==='requires-helper'||c.availability==='inspect-separately').map(c=>c.category),
  notApplicable:cards.filter(c=>c.availability==='not-applicable').map(c=>c.category),
  assessment:'static-guidance-not-verified',
  scope:'Static guidance per dependency category for the declared target. It does not build or run anything, does not check SDK or version support, and does not show that a replacement behaves like the original. Import counts are a size hint, not effort or coverage.'};
}

type View='summary'|'cards';
export async function inspectTargetAdapters(workspace:string,options:{file:string;target:unknown;view?:View;offset?:number;limit?:number;budgetBytes?:number;signal?:AbortSignal}){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,budget=responseBudget(options.budgetBytes);
 if(!['summary','cards'].includes(view))throw new Error('Use view summary or cards.');
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use page limit 1–100 and a nonnegative offset.');
 const target=targetSpecSchema.parse(options.target),root=await realpath(workspace),file=await indexedFile(root,options.file,options.signal);
 const scan=await readPeImportCalls(file.path,{signal:options.signal}),classified=classifyPlatformDependencies(scan.metadata,scan.architecture?scan.sites:null);
 if((await hashFile(file.path,options.signal)).sha256!==file.sha256)throw new Error('Selected input changed while assessing target adapters.');
 const assessment=assessTargetAdapters(classified.imports,target);
 const provider={name:'carve-target-adapters',version:'1',parserSha256:digest(await readFile(fileURLToPath(import.meta.url))),rulesSha256:classified.rulesSha256,guidanceSha256:assessment.guidanceSha256};
 const detail={kind:'target-adapter-assessment',name:`${target.platform}/${target.delivery} adapter needs for ${options.file}`,address:'file:0',provider,assessment};
 const id=digest(JSON.stringify({file:options.file,sha256:file.sha256,detail})),evidence=path.join(root,'loader-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/target-adapter-evidence@1',file:options.file,sourceSha256:file.sha256,...detail},null,2)+'\n';
 await publishEvidence(evidence,text);
 const db=openIndex(root);
 try{recordObservation(db,{id,file:options.file,sha256:file.sha256,detail,searchText:JSON.stringify({target,needsDecision:assessment.needsDecision}),evidence,evidenceSha256:digest(text)});}finally{db.close();}
 const base={schema:'carve/target-adapters@1',workspace:root,file:options.file,sourceSha256:file.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),
  target,assessment:assessment.assessment,byAvailability:assessment.byAvailability,needsDecision:assessment.needsDecision,notApplicable:assessment.notApplicable,unreadModules:classified.unreadModules.length,view,scope:assessment.scope};
 const rows=view==='cards'?assessment.cards.map(c=>({value:c})):[];
 if(view==='cards'&&rows.length&&offset>=rows.length)throw new Error(`Use an offset below ${rows.length} for view cards.`);
 return budgetItems({...base,total:rows.length,offset},rows.slice(offset,offset+limit),budget);
}
