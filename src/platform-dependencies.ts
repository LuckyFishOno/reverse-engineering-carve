import {realpath,readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {indexedFile,hashFile,openIndex} from './survey.js';
import {digest} from './artifact.js';
import {budgetItems,responseBudget} from './context-budget.js';
import {readPeLoader,publishEvidence,recordObservation,type PeMetadata} from './pe-loader.js';
import {readPeImportCalls,type PeCallSite} from './pe-calls.js';

// Source-platform dependencies of a Windows PE image, from its declared imports. Each import is
// placed in one category by the first matching rule of an ordered, versioned table, and the rule id
// is reported with it so every classification can be traced and challenged. Categories describe
// what a function name is documented to belong to; they are not observed behavior, they do not
// say a replacement exists on the target platform, and they never mean anything was ported.
export const PLATFORM_CATEGORIES={
 'file-system':'Files, directories and paths','process-thread':'Processes, threads, synchronization and OS memory','network':'Network',
 'ui-graphics':'Windowed UI, graphics, input and multimedia','registry-system':'Registry, services, COM, shell and system integration',
 'crypto-security':'Cryptography, certificates, tokens and access control','dynamic-loading':'Dynamic loading and module lookup (can hide further dependencies)',
 'text-locale-time':'Text encoding, locale and time','console-stdio':'Console and standard streams',
 'runtime-library':'C/C++ runtime services (memory, strings, math, startup, exceptions)','os-specific':'Other Windows-specific facilities (exceptions, debugging, system information, devices)',
 'unknown':'No rule matched, or a non-system module whose own dependencies need separate inspection'} as const;
export type PlatformCategory=keyof typeof PLATFORM_CATEGORIES;
export type ImportSurface='windows-system'|'c-runtime'|'other-module';
type Rule={id:string;category:PlatformCategory;scope:'windows'|'c-runtime';module?:RegExp;name?:RegExp};

const crtModule=/^(msvcrt|msvcr\d+d?|msvcp\d+(_\w+)?d?|ucrtbased?|vcruntime\d+(_\d)?d?|concrt\d+d?|api-ms-win-crt-[\w-]+|libgcc_s_[\w-]+|libstdc\+\+-6|libwinpthread-1)\.dll$/;
const systemModule=new RegExp('^(kernel32|kernelbase|ntdll|advapi32|sechost|user32|gdi32|gdiplus|comctl32|comdlg32|uxtheme|dwmapi|d2d1|dwrite|d3d\\d+|d3dx\\w*|dxgi|ddraw|opengl32|glu32|imm32|msimg32|winmm|dsound|xinput[\\w.]*|dinput8?|mf\\w*|avrt|windowscodecs|oleacc|msftedit|riched20|hid|uiautomationcore'
 +'|ws2_32|wsock32|mswsock|winhttp|wininet|iphlpapi|dnsapi|httpapi|netapi32|mpr|urlmon|winnsi|webio|websocket|rasapi32|fwpuclnt|wlanapi'
 +'|bcrypt|ncrypt|crypt32|cryptbase|cryptsp|secur32|sspicli|wintrust|cryptui|rsaenh|dpapi|credui|cryptnet'
 +'|ole32|oleaut32|combase|olepro32|propsys|wtsapi32|userenv|wevtapi|taskschd|advpack|setupapi|cfgmgr32|newdev|powrprof|msi|sfc|activeds|ntdsapi|winspool'
 +'|shell32|shlwapi|version|psapi|dbghelp|imagehlp|rpcrt4|api-ms-win-[\\w-]+|ext-ms-[\\w-]+)\\.(dll|drv)$');
const windows=(id:string,category:PlatformCategory,match:{module?:RegExp;name?:RegExp}):Rule=>({id,category,scope:'windows',...match});
const runtime=(id:string,category:PlatformCategory,match:{module?:RegExp;name?:RegExp}):Rule=>({id,category,scope:'c-runtime',...match});
// Order matters: the first matching rule wins. Name rules see Win32 names in system modules only and
// CRT names in C/C++ runtime modules only.
export const PLATFORM_DEPENDENCY_RULES:readonly Rule[]=[
 windows('module-loading','dynamic-loading',{name:/^(LoadLibrary(Ex)?[AW]?|LoadPackagedLibrary|FreeLibrary(AndExitThread)?|GetProcAddress|GetModuleHandle(Ex)?[AW]?|GetModuleFileName(Ex)?[AW]?|LdrLoadDll|LdrGetProcedureAddress|__delayLoadHelper2)$/}),
 windows('crypto-apis','crypto-security',{name:/^(Crypt[A-Z]\w*|BCrypt\w+|NCrypt\w+|Cert[A-Z]\w*|PFXImportCertStore|WinVerifyTrust\w*|SystemFunction036|RtlGenRandom|AcquireCredentialsHandle[AW]?|InitializeSecurityContext[AW]?|AcceptSecurityContext|(Encrypt|Decrypt)Message|QuerySecurityPackageInfo[AW]?)$/}),
 windows('token-acl-sid','crypto-security',{module:/^(advapi32|sechost|kernelbase|api-ms-win-security[\w-]*)\.dll$/,name:/^((Open|Get|Set|Duplicate)(Process|Thread)?Token\w*|AdjustTokenPrivileges|LookupPrivilege\w+|LookupAccount\w+|\w*SecurityDescriptor\w*|\w*Ace|\w*Acl\w*|\w*Sid(\w*)?|ImpersonateLoggedOnUser|RevertToSelf|LogonUser\w*|SetEntriesInAcl[AW]?|GetNamedSecurityInfo[AW]?|SetNamedSecurityInfo[AW]?)$/}),
 windows('crypto-modules','crypto-security',{module:/^(bcrypt|ncrypt|crypt32|cryptbase|cryptsp|secur32|sspicli|wintrust|cryptui|rsaenh|dpapi|credui|cryptnet)\.dll$/}),
 windows('network-modules','network',{module:/^(ws2_32|wsock32|mswsock|winhttp|wininet|iphlpapi|dnsapi|httpapi|netapi32|mpr|urlmon|winnsi|webio|websocket|rasapi32|fwpuclnt|wlanapi)\.dll$/}),
 windows('user32-text','text-locale-time',{module:/^user32\.dll$/,name:/^(Char(Upper|Lower|Next|Prev)(Ex|Buff)?[AW]?|IsChar\w+|w(v)?sprintf[AW])$/}),
 windows('ui-graphics-modules','ui-graphics',{module:/^(user32|gdi32|gdiplus|comctl32|comdlg32|uxtheme|dwmapi|d2d1|dwrite|d3d\d+|d3dx\w*|dxgi|ddraw|opengl32|glu32|imm32|msimg32|winmm|dsound|xinput[\w.]*|dinput8?|mf\w*|avrt|windowscodecs|oleacc|msftedit|riched20|hid|uiautomationcore)\.dll$/}),
 windows('shell-execute','process-thread',{module:/^shell32\.dll$/,name:/^(ShellExecute(Ex)?[AW]?|CommandLineToArgvW)$/}),
 windows('shell-folders-files','file-system',{module:/^shell32\.dll$/,name:/^(SH(Get(Special)?Folder(Path|Location)\w*|GetKnownFolder\w+|FileOperation[AW]?|CreateDirectory\w*)|ILCreateFromPath[AW]?)$/}),
 windows('shell-ui','ui-graphics',{module:/^shell32\.dll$/,name:/^(DragAcceptFiles|DragQueryFile[AW]?|DragFinish|Shell_NotifyIcon[AW]?|SHBrowseForFolder[AW]?|ExtractIcon\w*|SHGetFileInfo[AW]?)$/}),
 windows('com-system-integration-modules','registry-system',{module:/^(ole32|oleaut32|combase|olepro32|propsys|wtsapi32|userenv|wevtapi|taskschd|advpack|setupapi|cfgmgr32|newdev|powrprof|msi|sfc|activeds|ntdsapi|winspool|shell32)\.(dll|drv)$/}),
 windows('shlwapi-paths','file-system',{module:/^shlwapi\.dll$/,name:/^Path\w+$/}),
 windows('shlwapi-registry','registry-system',{module:/^shlwapi\.dll$/,name:/^SHReg\w+$/}),
 windows('shlwapi-strings','text-locale-time',{module:/^shlwapi\.dll$/,name:/^(Str\w+|wnsprintf[AW]|wvnsprintf[AW])$/}),
 windows('file-version-module','file-system',{module:/^version\.dll$/}),
 windows('process-status-module','process-thread',{module:/^psapi\.dll$/}),
 windows('debug-help-modules','os-specific',{module:/^(dbghelp|imagehlp)\.dll$/}),
 windows('rpc-runtime','os-specific',{module:/^rpcrt4\.dll$/}),
 windows('registry','registry-system',{name:/^Reg[A-Z]\w*$/}),
 windows('services','registry-system',{name:/^(OpenSCManager|CreateService|OpenService|StartService(CtrlDispatcher)?|ControlService|DeleteService|QueryServiceStatus\w*|ChangeServiceConfig\w*|RegisterServiceCtrlHandler\w*|SetServiceStatus|CloseServiceHandle|EnumServicesStatus\w*)[AW]?$/}),
 windows('event-log','registry-system',{name:/^(RegisterEventSource|DeregisterEventSource|ReportEvent|OpenEventLog|ReadEventLog|CloseEventLog|EventRegister|EventWrite\w*|EventUnregister)[AW]?$/}),
 windows('profile-ini','registry-system',{name:/^(Get|Write)(Private)?Profile(String|Int|Section)[AW]?$/}),
 windows('win32-files','file-system',{name:/^(CreateFile\w*|OpenFile(ById)?|ReadFile(Ex|Scatter)?|WriteFile(Ex|Gather)?|DeleteFile[AW]?|CopyFile\w*|MoveFile\w*|ReplaceFile[AW]?|FindFirstFile\w*|FindNextFile[AW]?|FindClose|FindFirstChangeNotification[AW]?|FindNextChangeNotification|FindCloseChangeNotification|ReadDirectoryChanges\w*|GetFile\w+|GetCompressedFileSize[AW]?|SetFile\w+|SetEndOfFile|FlushFileBuffers|(Un)?LockFile(Ex)?|CreateDirectory\w*|RemoveDirectory[AW]?|GetCurrentDirectory[AW]?|SetCurrentDirectory[AW]?|GetFullPathName[AW]?|GetLongPathName[AW]?|GetShortPathName[AW]?|GetTempPath2?[AW]?|GetTempFileName[AW]?|GetDiskFreeSpace\w*|GetDriveType[AW]?|GetLogicalDrive\w*|GetVolume\w+|CreateHardLink[AW]?|CreateSymbolicLink[AW]?|GetFinalPathNameByHandle[AW]?|(Create|Open)FileMapping\w*|MapViewOfFile\w*|UnmapViewOfFile\w*|FlushViewOfFile|AreFileApisANSI|SetFileApisTo\w+|SearchPath[AW]?|GetBinaryType[AW]?)$/}),
 windows('win32-text-locale-time','text-locale-time',{name:/^(MultiByteToWideChar|WideCharToMultiByte|GetACP|GetOEMCP|GetCPInfo(Ex[AW])?|IsValidCodePage|IsDBCSLeadByte(Ex)?|GetStringType\w*|CompareString\w*|LCMapString\w*|FoldString[AW]?|GetLocaleInfo\w*|SetLocaleInfo[AW]?|GetUserDefault\w+|GetSystemDefault\w+|GetThreadLocale|SetThreadLocale|IsValidLocale(Name)?|EnumSystemLocales\w*|LocaleNameToLCID|LCIDToLocaleName|ResolveLocaleName|Get(Number|Currency|Date|Time)Format\w*|lstr\w+|GetSystemTime\w*|GetLocalTime|SetLocalTime|SetSystemTime|GetTickCount(64)?|QueryPerformance(Counter|Frequency)|GetTimeZoneInformation\w*|SystemTimeToTzSpecificLocalTime\w*|TzSpecificLocalTimeToSystemTime\w*|FileTimeTo\w+|\w+ToFileTime|CompareFileTime)$/}),
 windows('win32-console','console-stdio',{name:/^(GetStdHandle|SetStdHandle|AllocConsole|FreeConsole|AttachConsole|\w*Console\w*)$/}),
 windows('win32-exceptions-errors-debug','os-specific',{name:/^(Rtl\w+|RaiseException|SetUnhandledExceptionFilter|UnhandledExceptionFilter|(Add|Remove)Vectored(Exception|Continue)Handler|IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString[AW]|DebugBreak|IsProcessorFeaturePresent|EncodePointer|DecodePointer|InitializeSListHead|InterlockedP(ush|op)EntrySList|InterlockedFlushSList|GetLastError|SetLastError|FormatMessage[AW]|SetErrorMode|GetErrorMode)$/}),
 windows('win32-system-information-devices','os-specific',{name:/^(GetSystemInfo|GetNativeSystemInfo|GetVersion(Ex[AW])?|VerifyVersionInfo[AW]?|GlobalMemoryStatus(Ex)?|GetSystemDirectory[AW]?|GetWindowsDirectory[AW]?|GetSystemWindowsDirectory[AW]?|GetComputerName\w*|GetUserName[AW]?|DeviceIoControl|GetOverlappedResult(Ex)?|CancelIo(Ex)?)$/}),
 windows('win32-processes-threads-memory','process-thread',{name:/^(CreateProcess\w*|OpenProcess|TerminateProcess|ExitProcess|GetExitCodeProcess|GetCurrentProcess(Id)?|CreateThread|CreateRemoteThread\w*|ExitThread|TerminateThread|GetExitCodeThread|GetCurrentThread(Id)?|OpenThread|ResumeThread|SuspendThread|(Set|Get)Thread(Priority|Affinity\w*|Description)|SwitchToThread|Sleep(Ex)?|SleepConditionVariable\w+|WaitFor(Single|Multiple)Object(s|Ex)?|SignalObjectAndWait|(Create|Open)(Event|Mutex|Semaphore|WaitableTimer)\w*|(Set|Reset|Pulse)Event|ReleaseMutex|ReleaseSemaphore|SetWaitableTimer\w*|CancelWaitableTimer|(Initialize|Enter|Leave|Delete|TryEnter)CriticalSection\w*|InitializeSRWLock|(Acquire|Release|TryAcquire)SRWLock\w+|InitializeConditionVariable|Wake(All)?ConditionVariable|InitOnce\w+|Interlocked\w+|(Tls|Fls)(Alloc|Free|GetValue|SetValue)|\w*Threadpool\w*|QueueUserAPC|QueueUserWorkItem|CreateTimerQueue\w*|DeleteTimerQueue\w*|Heap\w+|GetProcessHeaps?|Virtual\w+|Local(Alloc|Free|ReAlloc|Lock|Unlock|Size)|Global(Alloc|Free|ReAlloc|Lock|Unlock|Size)|CloseHandle|DuplicateHandle|(Get|Set)HandleInformation|SetHandleCount|GetCommandLine[AW]|GetEnvironmentStrings[AW]?|FreeEnvironmentStrings[AW]|(Get|Set)EnvironmentVariable[AW]|ExpandEnvironmentStrings[AW]|GetStartupInfo[AW]|CreatePipe|PeekNamedPipe|CreateNamedPipe[AW]|(Connect|Disconnect)NamedPipe|CallNamedPipe[AW]|TransactNamedPipe|WaitNamedPipe[AW]|Get(Process|Thread)Times|(Get|Set)ProcessAffinityMask|GetCurrentProcessorNumber\w*|IsWow64Process2?|CreateJobObject[AW]?|AssignProcessToJobObject|ProcessIdToSessionId)$/}),
 runtime('crt-file-io','file-system',{name:/^(_?w?fopen(_s)?|_?w?freopen(_s)?|_w?fdopen|fclose|_fcloseall|fread(_s)?|fwrite|fseek|_fseeki64|ftell|_ftelli64|fgetpos|fsetpos|fflush|setvbuf|rewind|_w?s?open(_s)?|_close|_read|_write|_lseek(i64)?|_tell(i64)?|_chsize(_s)?|_commit|_filelength(i64)?|_w?fstat\w*|_w?stat\w*|_w?access(_s)?|_?w?remove|_?w?rename|_w?unlink|_w?mkdir|_w?rmdir|_w?chdir|_w?getcwd|_w?getdcwd|_w?findfirst\w*|_w?findnext\w*|_findclose|_w?fullpath|_w?splitpath(_s)?|_w?makepath(_s)?|tmpfile(_s)?|_?w?tmpnam(_s)?|_w?tempnam|_w?mktemp(_s)?|_fileno|_get_osfhandle|_open_osfhandle|_setmode|_locking|_w?utime\w*|fgetw?c|getw?c|fgetw?s|fputw?c|putw?c|fputw?s|ungetw?c|feof|ferror|clearerr|__?pioinfo)$/}),
 runtime('crt-stdio','console-stdio',{name:/^(_?w?printf(_s)?|v_?w?printf(_s)?|_?w?puts|_putws|putw?char|getw?char|_?w?scanf(_s)?|_?f?w?printf(_s)?|vfw?printf(_s)?|__stdio_common_vf\w+|__acrt_iob_func|__iob_func|_iob|_c(w)?printf\w*|_getw?che?|_kbhit|_putw?ch|__p__commode|_commode|_set_fmode|_fmode|_get_fmode)$/}),
 runtime('crt-string-formatting','text-locale-time',{name:/^(_?s(n)?w?printf(_s)?|_?v?s(n)?w?printf(_[sp])?|_vsc?w?printf\w*|__stdio_common_vs\w+|_?s?w?scanf(_s)?|sscanf(_s)?|swscanf(_s)?)$/}),
 runtime('crt-process-environment','process-thread',{name:/^(_beginthread(ex)?|_endthread(ex)?|exit|_exit|_Exit|quick_exit|abort|_c?exit|_c_exit|atexit|_onexit|__dllonexit|_crt_atexit|_register_onexit_function|_initialize_onexit_table|_execute_onexit_table|_register_thread_local_exe_atexit_callback|_w?system|_w?spawn\w+|_w?exec\w+|_getpid|_cwait|_pipe|_w?popen|_pclose|_?w?getenv(_s)?|_w?dupenv_s|_w?putenv(_s)?|__p___w?argv|__p___argc|__w?getmainargs|_configure_(wide|narrow)_argv|_get_initial_(wide|narrow)_environment|_initialize_(wide|narrow)_environment|__w?initenv|signal|raise|_lock|_unlock|_mtlock|_mtunlock)$/}),
 runtime('crt-locale-time','text-locale-time',{name:/^(_?w?setlocale|localeconv|_configthreadlocale|___lc_\w+|__mb_cur_max|_get_current_locale|_create_locale|_free_locale|w?cscoll|strcoll|strxfrm|wcsxfrm|_?to(w)?(upper|lower)(_l)?|is\w+|_isctype\w*|mbstowcs(_s)?|wcstombs(_s)?|mbr?towc|wcr?tomb|_mbs\w+|time|_time(32|64)|clock|difftime\w*|_?mktime\w*|_?localtime\w*|_?gmtime\w*|strftime|wcsftime|_strftime_l|_?asctime\w*|_?w?ctime\w*|_tzset|_get_timezone|_get_daylight|_ftime\w*)$/}),
 runtime('crt-runtime','runtime-library',{module:crtModule}),
 windows('api-set-file','file-system',{module:/^api-ms-win-core-file-[\w-]+\.dll$/}),
 windows('api-set-process-thread','process-thread',{module:/^api-ms-win-core-(synch|processthreads|heap|memory|threadpool|fibers|interlocked|handle|processenvironment|namedpipe)-[\w-]+\.dll$/}),
 windows('api-set-registry','registry-system',{module:/^api-ms-win-core-registry-[\w-]+\.dll$/}),
 windows('api-set-library-loader','dynamic-loading',{module:/^api-ms-win-core-libraryloader-[\w-]+\.dll$/}),
 windows('api-set-text-locale-time','text-locale-time',{module:/^api-ms-win-core-(localization|string|datetime|timezone|realtime)-[\w-]+\.dll$/}),
 windows('api-set-console','console-stdio',{module:/^api-ms-win-core-console-[\w-]+\.dll$/}),
 windows('api-set-security','crypto-security',{module:/^api-ms-win-security-[\w-]+\.dll$/}),
 windows('advapi32-other','registry-system',{module:/^(advapi32|sechost)\.dll$/}),
 windows('windows-core-other','os-specific',{module:/^(kernel32|kernelbase|ntdll|shlwapi|api-ms-win-[\w-]+|ext-ms-[\w-]+)\.dll$/})
];
export const PLATFORM_RULES_VERSION='carve/platform-rules@1';
export const PLATFORM_RULES_SHA256=digest(JSON.stringify(PLATFORM_DEPENDENCY_RULES.map(r=>({id:r.id,category:r.category,scope:r.scope,module:r.module?.source??null,name:r.name?.source??null}))));

export function classifyImport(module:string,name?:string){
 const lower=module.toLowerCase(),surface:ImportSurface=crtModule.test(lower)?'c-runtime':systemModule.test(lower)?'windows-system':'other-module';
 if(surface==='other-module')return{category:'unknown' as PlatformCategory,surface,ruleId:'non-system-module'};
 const scope=surface==='c-runtime'?'c-runtime':'windows';
 for(const rule of PLATFORM_DEPENDENCY_RULES){
  if(rule.scope!==scope||rule.module&&!rule.module.test(lower))continue;
  if(rule.name){if(name===undefined||!rule.name.test(name))continue;}
  return{category:rule.category,surface,ruleId:rule.id};
 }
 return{category:'unknown' as PlatformCategory,surface,ruleId:'no-rule'};
}

export type ClassifiedImport={module:string;importKind:'import'|'delay-import';name?:string;ordinal?:number;slotRva:number;category:PlatformCategory;surface:ImportSurface;ruleId:string;callSites:number|null};
export function classifyPlatformDependencies(metadata:PeMetadata,sites?:PeCallSite[]|null){
 const counts=new Map<number,number>();for(const site of sites??[])counts.set(site.slotRva,(counts.get(site.slotRva)??0)+1);
 const imports:ClassifiedImport[]=metadata.imports.flatMap(module=>module.entries.map(entry=>({module:module.name,importKind:module.kind,...(entry.name!==undefined?{name:entry.name}:{ordinal:entry.ordinal}),slotRva:entry.thunkRva,
  ...classifyImport(module.name,entry.name),callSites:sites?counts.get(entry.thunkRva)??0:null})));
 // Modules whose descriptors could not be read entry by entry still name a dependency.
 const unreadModules=metadata.imports.filter(m=>m.status!=='entries-read').map(m=>({module:m.name,importKind:m.kind,status:m.status,...classifyImport(m.name)}));
 return{rulesVersion:PLATFORM_RULES_VERSION,rulesSha256:PLATFORM_RULES_SHA256,imports,unreadModules};
}

const LIST=8,parser=async()=>digest(await readFile(fileURLToPath(import.meta.url)));
type View='summary'|'categories'|'imports'|'rules';
export async function inspectPlatformDependencies(workspace:string,options:{file:string;view?:View;category?:PlatformCategory;offset?:number;limit?:number;budgetBytes?:number;signal?:AbortSignal}){
 const view=options.view??'summary',offset=options.offset??0,limit=options.limit??20,budget=responseBudget(options.budgetBytes);
 if(!['summary','categories','imports','rules'].includes(view))throw new Error('Use view summary, categories, imports or rules.');
 if(options.category!==undefined&&!(options.category in PLATFORM_CATEGORIES))throw new Error('Unknown category. Use one of: '+Object.keys(PLATFORM_CATEGORIES).join(', ')+'.');
 if(!Number.isInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(offset)||offset<0)throw new Error('Use page limit 1–100 and a nonnegative offset.');
 const root=await realpath(workspace),target=await indexedFile(root,options.file,options.signal);
 const scan=await readPeImportCalls(target.path,{signal:options.signal}),sites=scan.architecture?scan.sites:null;
 if((await hashFile(target.path,options.signal)).sha256!==target.sha256)throw new Error('Selected input changed while classifying its imports.');
 const result=classifyPlatformDependencies(scan.metadata,sites),provider={name:'carve-platform-dependencies',version:'1',parserSha256:await parser(),rulesVersion:result.rulesVersion,rulesSha256:result.rulesSha256};
 const detail={kind:'platform-dependencies',name:`PE ${scan.metadata.machineName} source platform dependencies`,address:'file:0',provider,callSitesScanned:Boolean(sites),imports:result.imports,unreadModules:result.unreadModules};
 const id=digest(JSON.stringify({file:options.file,sha256:target.sha256,detail})),evidence=path.join(root,'loader-evidence',id+'.json');
 const text=JSON.stringify({schema:'carve/platform-dependencies-evidence@1',file:options.file,sourceSha256:target.sha256,...detail},null,2)+'\n';
 await publishEvidence(evidence,text);
 const db=openIndex(root);
 try{recordObservation(db,{id,file:options.file,sha256:target.sha256,detail,searchText:JSON.stringify([...new Set(result.imports.map(i=>i.category))]),evidence,evidenceSha256:digest(text)});}finally{db.close();}
 const categories=(Object.keys(PLATFORM_CATEGORIES) as PlatformCategory[]).map(category=>{
  const items=result.imports.filter(i=>i.category===category),modules=[...new Set(items.map(i=>i.module))],samples=items.map(i=>`${i.module}!${i.name??'#'+i.ordinal}`),rules=[...new Set(items.map(i=>i.ruleId))];
  const surfaces={'windows-system':0,'c-runtime':0,'other-module':0};for(const i of items)surfaces[i.surface]++;
  return{category,label:PLATFORM_CATEGORIES[category],imports:items.length,callSites:sites?items.reduce((n,i)=>n+(i.callSites??0),0):null,surfaces,
   modules:{values:modules.slice(0,LIST),total:modules.length},samples:{values:samples.slice(0,LIST),total:samples.length},rules:{values:rules.slice(0,LIST),total:rules.length},
   unreadModules:result.unreadModules.filter(m=>m.category===category).length};
 });
 const base={schema:'carve/platform-dependencies@1',workspace:root,file:options.file,sourceSha256:target.sha256,sourceFreshlyHashed:true,executesTarget:false,provider,observationId:id,evidence,evidenceSha256:digest(text),
  format:scan.metadata.format,machine:scan.metadata.machineName,managed:scan.metadata.managed,callSitesScanned:Boolean(sites),
  summary:Object.fromEntries(categories.filter(c=>c.imports||c.unreadModules).map(c=>[c.category,{imports:c.imports,callSites:c.callSites}])),
  totals:{imports:result.imports.length,unknown:result.imports.filter(i=>i.category==='unknown').length,otherModules:new Set(result.imports.filter(i=>i.surface==='other-module').map(i=>i.module)).size,unreadModules:result.unreadModules.length},view,
  scope:'Declared imports classified by an ordered rule table (rule id and table hash reported). A category is what a function or module name is documented to belong to, not observed behavior; it does not say a target-platform replacement exists or that anything was ported. Dynamic loading, GetProcAddress, COM and other modules can add dependencies not listed here. Call-site counts are byte-pattern candidates (x86/x86-64 only).'+(scan.metadata.managed?' This is a managed (.NET) image: its native imports are only the runtime stub.':'')};
 const rows:{value:unknown}[]=view==='categories'?categories.filter(c=>c.imports||c.unreadModules).map(c=>({value:c}))
  :view==='imports'?result.imports.filter(i=>!options.category||i.category===options.category).map(i=>({value:i}))
  :view==='rules'?PLATFORM_DEPENDENCY_RULES.map((r,order)=>({value:{order,id:r.id,category:r.category,scope:r.scope,module:r.module?.source??null,name:r.name?.source??null}})):[];
 if(view!=='summary'&&rows.length&&offset>=rows.length)throw new Error(`Use an offset below ${rows.length} for view ${view}.`);
 return budgetItems({...base,total:rows.length,offset},rows.slice(offset,offset+limit),budget);
}
