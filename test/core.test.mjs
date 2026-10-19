import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, access, mkdir, rename, symlink } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createPackage } from '@electron/asar';
import { loadSource, inventory, digest } from '../dist/artifact.js';
import { analyze } from '../dist/analyze.js';
import { extract } from '../dist/extract.js';
import { verify } from '../dist/verify.js';
import { confined } from '../dist/mcp.js';

const selector = { kind: 'export', name: 'format' };
async function workspace(t, code = 'export function format(x) { return x * 2; }') {
  const dir = await mkdtemp(path.join(tmpdir(), 'carve-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'bundle.mjs');
  await writeFile(input, code);
  const out = path.join(dir, 'out');
  const cases = path.join(dir, 'cases.json');
  await writeFile(cases, JSON.stringify([{ name: 'normal', args: [3], expected: 6 }]));
  return { dir, input, out, cases };
}
const issues = analysis => analysis.plan.issues.map(i => i.code);

test('lexical closure follows helpers and constants, preserves shadowing, and removes startup without executing it', async t => {
  const { input, out } = await workspace(t, `const factor=2; const poison=doesNotExist(); function helper(x){return x*factor} export function format(x){const factor=10; return helper(x)+factor} export function editor(){return poison}`);
  const source = await loadSource(input);
  const analysis = analyze(source, selector);
  assert.equal(analysis.plan.status, 'extractable');
  assert.deepEqual(analysis.plan.retained.map(i => i.name), ['factor', 'helper', 'format']);
  await extract(input, { selector, out });
  const code = await readFile(path.join(out, 'index.mjs'), 'utf8');
  assert.doesNotMatch(code, /poison|doesNotExist|editor/);
  assert.equal(JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[3]'], { encoding: 'utf8' })), 16);
});

test('minified export aliases, destructuring and recursive helpers retain a runnable dependency closure', async t => {
  const { input, out } = await workspace(t, 'const {factor:f,other:q}={factor:2,other:9};function h(x){return x===0?0:f+h(x-1)}const a=x=>h(x);export{a as format};');
  await extract(input, { selector, out });
  assert.equal(JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[3]'], { encoding: 'utf8' })), 6);
});

test('imports, dynamic imports and ambient application globals produce blockers', async t => {
  for (const [code, expected] of [
    ['import { helper } from "./missing.js"; export function format(x){return helper(x)}', 'module-dependency'],
    ['export function format(x){return window.bridge(x)}', 'unresolved-global'],
    ['export async function format(x){return import(x)}', 'dynamic-import'],
    ['export function format(){return import.meta.url}', 'module-context'],
    ['export function format(){secret=42;return 1}', 'global-write'],
    ['export function format(){for(secret of [1,2]){}return 1}', 'global-write'],
    ['export function format(){return <div>hello</div>}', 'jsx-runtime']
  ]) {
    const { input, out } = await workspace(t, code);
    assert.ok(issues(analyze(await loadSource(input), selector)).includes(expected));
    await assert.rejects(() => extract(input, { selector, out }), /Extraction blocked/);
    await assert.rejects(() => access(out), /ENOENT/);
  }
});

test('external assignment, member mutation and initialization interactions cannot silently disappear', async t => {
  for (const code of [
    'let offset=0;offset=4;export function format(x){return x+offset}',
    'const state={offset:0};state.offset=4;export function format(x){return x+state.offset}',
    'const state={offset:0};configure(state);export function format(x){return x+state.offset}'
  ]) {
    const { input } = await workspace(t, code);
    assert.equal(analyze(await loadSource(input), selector).plan.status, 'blocked');
  }
});

test('write-only captured state is retained and cross-call state remains explicitly unverified', async t => {
  const { input, out, cases } = await workspace(t, 'let cache;export function format(x){cache=x;return x*2}');
  await extract(input, { selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});

test('captured loop assignment targets are retained even without a read', async t => {
  const { input, out, cases } = await workspace(t, 'let cache;export function format(x){for(cache of [1,2]){}return x*2}');
  await extract(input, { selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});

test('CommonJS named exports can be selected and compared', async t => {
  const { input, out, cases } = await workspace(t);
  const cjs = input.replace('.mjs', '.cjs');
  await writeFile(cjs, 'function format(x){return x*2}module.exports={format};');
  await extract(cjs, { selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});

test('source-selected symbol works with an explicit exported reference harness', async t => {
  const { input, out, cases, dir } = await workspace(t, 'function hidden(x){return x*2}');
  await extract(input, { selector: { kind: 'symbol', name: 'hidden' }, out });
  const reference = path.join(dir, 'reference.mjs');
  await writeFile(reference, 'export function expected(x){return x*2}');
  assert.equal((await verify(out, { cases, execute: true, reference, referenceExport: 'expected' })).status, 'passed');
});

test('ASAR source extraction is independent of both original archive and directory', async t => {
  const { dir, input, out, cases } = await workspace(t);
  const app = path.join(dir, 'app'); await mkdir(app);
  await writeFile(path.join(app, 'main.mjs'), await readFile(input));
  const archive = path.join(dir, 'app.asar'); await createPackage(app, archive);
  assert.deepEqual((await inventory(archive)).modules, ['main.mjs']);
  await extract(archive, { file: 'main.mjs', selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
  await rename(archive, archive + '.removed'); await rm(app, { recursive: true }); await rm(input);
  assert.equal(JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[3]'], { cwd: out, encoding: 'utf8' })), 6);
  assert.deepEqual(JSON.parse(await readFile(path.join(out, 'package.json'))).dependencies, {});
});

test('verification needs explicit execution, detects mismatches and records only tested cases', async t => {
  const { input, out, cases, dir } = await workspace(t);
  await extract(input, { selector, out });
  await assert.rejects(() => verify(out, { cases, execute: false }), /--execute/);
  const reference = path.join(dir, 'different.mjs'); await writeFile(reference, 'export function format(x){return x*3}');
  const report = await verify(out, { cases, execute: true, reference });
  assert.equal(report.status, 'failed'); assert.equal(report.passed, 0);
  assert.equal(report.candidateEnvironment.securitySandbox, false);
  assert.equal(report.casesSha256, digest(await readFile(cases)));
});

test('matching unexpected errors and import failures do not become a passing comparison', async t => {
  const { input, out, cases } = await workspace(t, 'export function format(){throw new TypeError("bad input")}');
  await extract(input, { selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'failed');
  await writeFile(cases, JSON.stringify([{ name: 'expected error', args: [], expectedError: { name: 'TypeError', message: 'bad input' } }]));
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});

test('an original application import failure remains a failed verification', async t => {
  const { input, out, cases } = await workspace(t, 'desktopRuntimeIsMissing();export function format(x){return x*2}');
  await extract(input, { selector, out });
  const report = await verify(out, { cases, execute: true });
  assert.equal(report.status, 'failed');
  assert.equal(report.results[0].original.kind, 'harness-error');
  assert.equal(report.results[0].candidate.kind, 'return');
});

test('large Unicode results preserve UTF-8 across process pipe chunks', async t => {
  const { input, out, cases } = await workspace(t, 'export function format(x){return x}');
  await extract(input, { selector, out });
  const text = '\u4e2d\u6587🚀'.repeat(15_000);
  await writeFile(cases, JSON.stringify([{ name: 'Unicode', args: [text], expected: text }]));
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});

test('hanging implementations hit a bounded deadline and do not count as an equivalent error', async t => {
  const { input, out, cases } = await workspace(t, 'export function format(){while(true){}}');
  await extract(input, { selector, out });
  const result = await verify(out, { cases, execute: true, timeoutMs: 100 });
  assert.equal(result.status, 'failed'); assert.match(result.results[0].candidate.detail, /timed out/);
});

test('source or output tampering invalidates a comparison, and existing output is never overwritten', async t => {
  const { input, out, cases } = await workspace(t);
  await extract(input, { selector, out });
  await assert.rejects(() => extract(input, { selector, out }), /EEXIST/);
  await writeFile(input, 'export function format(){return 99}');
  await assert.rejects(() => verify(out, { cases, execute: true }), /Original source changed/);
  await writeFile(path.join(out, 'index.mjs'), 'export const capability=()=>99;');
  await assert.rejects(() => verify(out, { cases, execute: true }), /Package changed/);
});

test('MCP paths and artifact module selectors reject escapes and symlinks', async t => {
  const { dir, input } = await workspace(t);
  await assert.rejects(() => loadSource(dir, '../escape.mjs'), /relative path/);
  await assert.rejects(() => confined(dir, '../outside'), /outside/);
  await symlink(tmpdir(), path.join(dir, 'escape'));
  await assert.rejects(() => confined(dir, 'escape/new/file', true), /outside/);
  await symlink(input, path.join(dir, 'link.mjs'));
  await assert.rejects(() => loadSource(dir, 'link.mjs'), /symlink/);
});

test('original license comments survive extraction without relicensing the output', async t => {
  const { input, out } = await workspace(t, '/*! Copyright Example; MIT license */ export function format(x){return x*2}');
  await extract(input, { selector, out });
  assert.match(await readFile(path.join(out, 'index.mjs'), 'utf8'), /Copyright Example; MIT license/);
  assert.equal(JSON.parse(await readFile(path.join(out, 'package.json'))).license, 'UNLICENSED');
});
