import {readdir,readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const skipped=new Set(['.git','node_modules','dist','artifacts','functions']);
const removed=/(?:\bcsv\b|\bx[os]_[a-z]+|\bxshell\b|\bkoloda\b|\bxo(?:\b|[_-]|\d))/i;
const problems=[];let checked=0;
async function walk(dir){for(const e of await readdir(dir,{withFileTypes:true})){
 if(e.isSymbolicLink()||skipped.has(e.name))continue;
 const p=path.join(dir,e.name);
 if(e.isDirectory()){await walk(p);continue;}
 if(!/\.(?:md|json|ts|mjs|js|c|java|py|sh)$/.test(e.name))continue;
 const relative=path.relative(root,p),s=await readFile(p,'utf8');checked++;
 if(!/^README(?:\.zh-TW)?\.md$/.test(relative)&&/\p{Script=Han}/u.test(s))problems.push(`${relative}: non-English prose; use English or escaped Unicode test data`);
 if(removed.test(s))problems.push(`${relative}: removed example reference`);
}}
await walk(root);
if(problems.length){process.stderr.write(problems.join('\n')+'\n');process.exitCode=1;}
else console.log(`Content hygiene passed: ${checked} text files.`);
