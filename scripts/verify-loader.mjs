import assert from 'node:assert/strict';import {mkdir,mkdtemp,cp,readFile,writeFile,realpath} from 'node:fs/promises';
import {execFile} from 'node:child_process';import {promisify} from 'node:util';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {survey,hashFile} from '../dist/survey.js';import {inspectLoader} from '../dist/loader.js';import {readObservation} from '../dist/native.js';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),exec=promisify(execFile);
if(process.platform!=='darwin'||process.arch!=='arm64')throw new Error('This actual Apple toolchain/installed-binary check currently requires macOS arm64.');
const out=await mkdtemp(path.join(root,'artifacts/loader-e2e-')),app=path.join(out,'app'),workspace=path.join(out,'work');for(const dir of ['bin','lib','decoy'])await mkdir(path.join(app,dir),{recursive:true});
const program=path.join(app,'bin/quote'),library=path.join(app,'lib/libcharge.dylib');
for(const [directory,source] of [['lib','split-charge.c'],['decoy','split-decoy.c']])await exec('xcrun',['clang','-O1','-g0','-dynamiclib',path.join(root,'examples/native-app',source),'-Wl,-install_name,@rpath/libcharge.dylib','-o',path.join(app,directory,'libcharge.dylib')]);
await exec('xcrun',['clang','-O1','-g0',path.join(root,'examples/native-app/split-main.c'),'-L'+path.join(app,'lib'),'-lcharge','-Wl,-rpath,@loader_path/../lib','-Wl,-rpath,@executable_path/../decoy','-o',program]);
const loaded=await exec(program,['16','1','1'],{env:{PATH:process.env.PATH,DYLD_PRINT_LIBRARIES:'1'}});assert.equal(loaded.stdout.trim(),'47');assert.ok(loaded.stderr.includes(library));await writeFile(path.join(out,'actual-library-load.log'),loaded.stderr);
const universal=path.join(app,'universal.dylib');await exec('xcrun',['clang','-arch','arm64','-arch','x86_64','-O1','-g0','-dynamiclib',path.join(root,'examples/native-app/split-charge.c'),'-Wl,-install_name,@rpath/libuniversal.dylib','-o',universal]);const architectures=(await exec('xcrun',['lipo','-archs',universal])).stdout.trim();assert.match(architectures,/arm64/);assert.match(architectures,/x86_64/);
const originalProgram=await realpath('/opt/homebrew/bin/rg'),originalLibrary=await realpath('/opt/homebrew/opt/pcre2/lib/libpcre2-8.0.dylib'),sources=[];
for(const [source,file] of [[originalProgram,'bin/rg'],[originalLibrary,'lib/libpcre2-8.0.dylib']]){const h=await hashFile(source);await cp(source,path.join(app,file));sources.push({source,file,sha256:h.sha256,bytes:h.bytes});}
await survey(app,{workspace});
function expected(text){
 const result={dependencies:[],rpaths:[],installNames:[]};for(const section of text.split(/\nLoad command \d+\n/).slice(1)){
  const cmd=/^\s+cmd (LC_\S+)$/m.exec(section)?.[1];const name=/^\s+(?:name|path) (.*?) \(offset \d+\)$/m.exec(section)?.[1];
  if(cmd==='LC_RPATH')result.rpaths.push(name);else if(cmd==='LC_ID_DYLIB')result.installNames.push(name);else if(['LC_LOAD_DYLIB','LC_LOAD_WEAK_DYLIB','LC_REEXPORT_DYLIB','LC_LAZY_LOAD_DYLIB','LC_LOAD_UPWARD_DYLIB'].includes(cmd))result.dependencies.push(name);
 }return result;
}
const observations=[],comparisons=[];
for(const [file,slice] of [['bin/quote'],['lib/libcharge.dylib'],['bin/rg'],['lib/libpcre2-8.0.dylib'],['universal.dylib',0],['universal.dylib',1]]){
 // lipo may reorder slices; use the reader's CPU identity to choose otool's
 // independent architecture selector, not assumptions about index order.
 const result=await inspectLoader(workspace,{file,slice,limit:100});observations.push(result);
 const selectedArch=file==='universal.dylib'?(result.selectedSlice.cpuType===0x100000c?'arm64':'x86_64'):undefined;
 const actual=await exec('/usr/bin/otool',[...(selectedArch?['-arch',selectedArch]:[]),'-l',path.join(app,file)]);const reference=expected(actual.stdout);await writeFile(path.join(out,file.replaceAll('/','-')+'-'+(slice??0)+'-otool.log'),actual.stdout);
 assert.deepEqual(result.dependencies.map(r=>r.name),reference.dependencies);assert.deepEqual(result.rpaths.map(r=>r.name),reference.rpaths);assert.deepEqual(result.installNames.map(r=>r.name),reference.installNames);assert.equal((await readObservation(workspace,result.observationId)).kind,'native-loader');
 comparisons.push({file,slice:result.selectedSlice.index,cpuType:result.selectedSlice.cpuType,dependencyCommands:reference.dependencies.length,rpaths:reference.rpaths.length,installNames:reference.installNames.length,matchedIndependentOtool:true});
}
const owned=observations.find(r=>r.file==='bin/quote'),feature=owned.dependencies.find(r=>r.name==='@rpath/libcharge.dylib');assert.deepEqual(feature.paths.map(p=>p.candidate.file),['lib/libcharge.dylib','decoy/libcharge.dylib']);assert.equal(feature.runtimeLoading,'unverified');
const installed=observations.find(r=>r.file==='bin/rg'),pcre=installed.dependencies.find(r=>r.name.includes('libpcre2-8'));assert.ok(pcre);assert.equal(pcre.paths[0].status,'outside-inventory','copied input must not read original absolute dependency path');
await assert.rejects(()=>inspectLoader(workspace,{file:'universal.dylib'}),/explicitly/);
for(const source of sources)assert.equal((await hashFile(source.source)).sha256,source.sha256);
const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version,report={schema:'carve/loader-check@1',status:'passed',checkedAt:new Date().toISOString(),version,out,workspace,sources,architectures,comparisons,observations,actualLoad:{program,library,output:47,log:path.join(out,'actual-library-load.log'),scope:'Owned executable actual dyld log; static candidates deliberately keep the alternative rpath library.'},scope:'Real Homebrew ripgrep/PCRE2 and Apple-toolchain thin/universal Mach-O command comparison against independent otool. Static path expansion preserves ambiguity and external-input boundaries. This does not reconstruct regex functionality, resolve symbol ordinals or prove complete runtime loader behavior.'};
await writeFile(path.join(out,'report.json'),JSON.stringify(report,null,2)+'\n');await writeFile(path.join(root,'artifacts/loader-verification-summary.json'),JSON.stringify({status:'passed',version,report:path.join(out,'report.json'),commandComparisons:comparisons.length},null,2)+'\n');console.log(JSON.stringify({status:'passed',report:path.join(out,'report.json'),commandComparisons:comparisons.length}));
