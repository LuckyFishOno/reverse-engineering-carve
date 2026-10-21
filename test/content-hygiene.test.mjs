import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {mkdtemp,mkdir,writeFile,copyFile,rm} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
test('content hygiene excludes private root records while still checking nested product research',async t=>{
 const root=await mkdtemp(path.join(tmpdir(),'carve-hygiene-'));t.after(()=>rm(root,{recursive:true,force:true}));
 for(const folder of ['scripts','.agent-memory','research','docs/research'])await mkdir(path.join(root,folder),{recursive:true});
 const script=path.join(root,'scripts/check-content.mjs');await copyFile(new URL('../scripts/check-content.mjs',import.meta.url),script);
 for(const name of ['.agent-memory/status.md','research/historical.md','AGENTS.md'])await writeFile(path.join(root,name),'\u6e2c\u8a66');
 const exec=promisify(execFile),passed=await exec(process.execPath,[script]);assert.match(passed.stdout,/Content hygiene passed/);
 await writeFile(path.join(root,'docs/research/public.md'),'\u6e2c\u8a66');await assert.rejects(exec(process.execPath,[script]),e=>e.code===1&&e.stderr.includes('docs/research/public.md: non-English prose'));
});
