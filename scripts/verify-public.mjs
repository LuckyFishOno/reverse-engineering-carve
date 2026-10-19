import { mkdtemp, mkdir, writeFile, readFile, cp } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { extract } from '../dist/extract.js';
import { verify } from '../dist/verify.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
await mkdir(path.join(root, 'artifacts'), { recursive: true });
const run = await mkdtemp(path.join(root, 'artifacts', 'public-'));
const cases = [
  { name: 'pretty-bytes', version: '7.2.0', module: 'node_modules/pretty-bytes/index.js', export: 'default',
    tests: [
      { name: 'documented format', args: [1337], expected: '1.34 kB' }, { name: 'zero', args: [0], expected: '0 B' },
      { name: 'binary boundary', args: [1024, {binary:true}], expected: '1 KiB' },
      { name: 'bits', args: [1337, {bits:true}], expected: '1.34 kbit' },
      { name: 'signed', args: [42, {signed:true}], expected: '+42 B' },
      { name: 'German locale', args: [1337, {locale:'de'}], expected: '1,34 kB' },
      { name: 'wrong type', args: ['1337'], expectedError: {name:'TypeError'} }
    ] },
  { name: 'camelcase', version: '10.0.0', module: 'node_modules/camelcase/index.js', export: 'default',
    tests: [
      { name: 'hyphen', args: ['foo-bar'], expected: 'fooBar' }, { name: 'underscore', args: ['foo_bar'], expected: 'fooBar' },
      { name: 'array', args: [['foo','bar']], expected: 'fooBar' }, { name: 'Pascal', args: ['foo-bar',{pascalCase:true}], expected:'FooBar' },
      { name: 'preserve acronym', args:['foo-BAR',{preserveConsecutiveUppercase:true}],expected:'fooBAR' },
      { name: 'Unicode', args:['розовый_пушистый_единорог'],expected:'розовыйПушистыйЕдинорог' },
      { name: 'wrong type', args:[42],expectedError:{name:'TypeError'} }
    ] },
  { name: 'change-case', version:'5.4.4', module:'node_modules/change-case/dist/index.js',export:'camelCase',
    tests:[
      { name:'space',args:['test value'],expected:'testValue' }, {name:'constant',args:['TEST_VALUE'],expected:'testValue'},
      { name:'hyphen',args:['test-value'],expected:'testValue' }, {name:'empty',args:[''],expected:''},
      { name:'single',args:['test'],expected:'test' }, {name:'wrong type',args:[42],expectedError:{name:'TypeError'}}
    ] },
  { name:'@sindresorhus/slugify',version:'3.0.1',module:'node_modules/@sindresorhus/slugify/index.js',export:'default',
    tests:[
      {name:'symbol replacement',args:['I ♥ Dogs'],expected:'i-love-dogs'},
      {name:'diacritics',args:['  Déjà Vu!  '],expected:'deja-vu'},
      {name:'camel words',args:['fooBar 123 $#%'],expected:'foo-bar-123'},
      {name:'apostrophe',args:['Conway’s Law'],expected:'conways-law'},
      {name:'Russian',args:['я люблю единорогов'],expected:'ya-lyublyu-edinorogov'},
      {name:'custom separator',args:['BAR and baz',{separator:'_'}],expected:'bar_and_baz'},
      {name:'preserve case',args:['Déjà Vu!',{lowercase:false}],expected:'Deja-Vu'},
      {name:'empty',args:[''],expected:''}, {name:'wrong type',args:[42],expectedError:{name:'TypeError'}}
    ] }
];
cases.push(
 {name:'bytes',version:'3.1.2',module:'node_modules/bytes/index.js',export:'default',tests:[
  {name:'format',args:[1024],expected:'1KB'}, {name:'parse',args:['1KB'],expected:1024},
  {name:'zero',args:[0],expected:'0B'}, {name:'negative',args:[-1024],expected:'-1KB'},
  {name:'custom separator',args:[1024,{unitSeparator:' '}],expected:'1 KB'},
  {name:'decimal parse',args:['1.5MB'],expected:1572864}, {name:'invalid',args:['oops'],expected:null}
 ]},
 {name:'fast-json-stable-stringify',version:'2.1.0',module:'node_modules/fast-json-stable-stringify/index.js',export:'default',tests:[
  {name:'sorted keys',args:[{b:2,a:1}],expected:'{"a":1,"b":2}'},
  {name:'nested keys',args:[{b:{d:4,c:3},a:[2,1]}],expected:'{"a":[2,1],"b":{"c":3,"d":4}}'},
  {name:'empty',args:[{}],expected:'{}'}, {name:'null',args:[null],expected:'null'},
  {name:'Unicode',args:[{word:'\u4f60\u597d'}],expected:'{"word":"\u4f60\u597d"}'}
 ]},
 {name:'ms',version:'2.1.3',module:'node_modules/ms/index.js',export:'default',tests:[
  {name:'seconds',args:['2 seconds'],expected:2000}, {name:'numeric format',args:[60000],expected:'1m'},
  {name:'long format',args:[60000,{long:true}],expected:'1 minute'},
  {name:'fraction',args:['1.5h'],expected:5400000}, {name:'negative',args:[-60000],expected:'-1m'},
  {name:'empty invalid',args:[''],expectedError:{name:'Error'}}
 ]}
);
const results=[];
for(const item of cases){
  const slug=item.name.replace(/[^a-zA-Z0-9-]/g,'-'); const out=path.join(run,slug);
  const casesPath=path.join(run,slug+'.cases.json'); await writeFile(casesPath,JSON.stringify(item.tests,null,2));
  const start=performance.now();
  try {
    const extraction=await extract(root,{file:item.module,selector:{kind:'export',name:item.export},out});
    const report=await verify(out,{cases:casesPath,execute:true});
    if(report.status!=='passed') throw new Error(JSON.stringify(report.results.filter(r=>!r.passed)));
    // Run the output with no application/node_modules anywhere in its ancestor
    // path: a separate OS temp directory, rather than this project’s artifacts.
    const {tmpdir}=await import('node:os'); const isolated=await mkdtemp(path.join(tmpdir(),'carve-public-output-'));
    try {
      await cp(out,path.join(isolated,'tool'),{recursive:true});
      const value=JSON.parse(execFileSync(process.execPath,[path.join(isolated,'tool/cli.mjs'),JSON.stringify(item.tests[0].args)],{cwd:isolated,encoding:'utf8'}));
      if(JSON.stringify(value)!==JSON.stringify(item.tests[0].expected)) throw new Error('Independent output differed');
    } finally {const {rm}=await import('node:fs/promises');await rm(isolated,{recursive:true});}
    const outputBytes=(await readFile(path.join(out,'index.mjs'))).length;
    results.push({name:item.name,version:item.version,status:'passed',cases:report.total,modules:extraction.manifest.modules.length,
      sourceBytes:extraction.manifest.modules.reduce((sum,m)=>sum+m.bytes,0),outputBytes,
      capturedNotices:extraction.manifest.licenses.reduce((sum,p)=>sum+p.files.length,0),independentSmokePassed:true,elapsedMs:Math.round(performance.now()-start),out});
  } catch(error) {results.push({name:item.name,version:item.version,status:'failed',error:error.message});}
}
const report={scope:'Seven pinned public npm packages (ESM and CommonJS); selected JSON behaviors only. Not an ecosystem success-rate sample or desktop-app cloning claim.',
  passed:results.filter(r=>r.status==='passed').length,total:results.length,results};
await writeFile(path.join(run,'verification.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({...report,report:path.join(run,'verification.json')},null,2));
if(report.passed!==report.total) process.exitCode=1;
