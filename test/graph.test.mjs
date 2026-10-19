import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createPackage } from '@electron/asar';
import { extract } from '../dist/extract.js';
import { verify } from '../dist/verify.js';
import { plan } from '../dist/mcp.js';
import { createFeature, readFeature } from '../dist/feature.js';
import { discover } from '../dist/discover.js';

async function setup(t, files) {
  const root = await mkdtemp(path.join(tmpdir(), 'carve-graph-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const app = path.join(root, 'app'); await mkdir(app);
  for (const [name, text] of Object.entries({ 'package.json': '{"type":"module"}', ...files })) {
    await mkdir(path.dirname(path.join(app, name)), { recursive: true }); await writeFile(path.join(app, name), text);
  }
  const cases = path.join(root, 'cases.json'); await writeFile(cases, JSON.stringify([{ name: 'value', args: [3], expected: 6 }]));
  return { root, app, cases, out: path.join(root, 'output') };
}
const selector = { kind: 'export', name: 'format' };
test('cross-module aliases and re-exports preserve only the chosen capability', async t => {
  const { app, cases, out } = await setup(t, {
    'index.js': 'export { default as format } from "./format.js";export {editor} from "./editor.js";',
    'format.js': 'import {double as d} from "./math.js";export default value=>d(value);',
    'math.js': 'const factor=2;export function double(x){return x*factor}export function unrelated(){return document.title}',
    'editor.js': 'export function editor(){return window.title}'
  });
  const result = await extract(app, { file: 'index.js', selector, out });
  assert.equal(result.manifest.modules.length, 3);
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
  assert.doesNotMatch(await readFile(path.join(out, 'index.mjs'), 'utf8'), /window|document|unrelated/);
  await rm(app, { recursive: true });
  assert.equal(JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[3]'], { cwd: out, encoding: 'utf8' })), 6);
});
test('necessary loop initialization is preserved while unrelated application startup is omitted', async t => {
  const { app, out, cases } = await setup(t, {
    'index.js': 'const cache=new Map();for(const value of [1,2,3]){cache.set(value,value*2)}const gui=window.editor;export function format(x){return cache.get(x)}'
  });
  await extract(app,{file:'index.js',selector,out});
  assert.doesNotMatch(await readFile(path.join(out,'index.mjs'),'utf8'),/window|editor/);
  const reference = path.join(path.dirname(app),'reference.mjs');
  await writeFile(reference,'const cache=new Map();for(const value of [1,2,3]){cache.set(value,value*2)}export function format(x){return cache.get(x)}');
  assert.equal((await verify(out,{cases,execute:true,reference})).status,'passed');
});
test('ASAR replays a multi-module reference with JSON and package metadata', async t => {
  const { root, app, out, cases } = await setup(t, {
    'index.js': 'import config from "./config.json" with {type:"json"};import * as helpers from "./math.js";export function format(x){return helpers.multiply(x,config.factor)}',
    'math.js': 'export function multiply(a,b){return a*b}export function gui(){return window.title}', 'config.json': '{"factor":2}'
  });
  const archive = path.join(root, 'app.asar'); await createPackage(app, archive);
  await extract(archive, { file: 'index.js', selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
  await rm(archive); await rm(app, { recursive: true });
  assert.equal(JSON.parse(execFileSync(process.execPath, [path.join(out, 'cli.mjs'), '[3]'], { encoding: 'utf8' })), 6);
});
test('package exports and in-artifact node_modules resolve without installing output dependencies', async t => {
  const { app, out, cases } = await setup(t, {
    'index.js': 'import {double} from "fixture-math";export function format(x){return double(x)}',
    'node_modules/fixture-math/package.json': '{"name":"fixture-math","type":"module","exports":{".":{"import":"./math.js","default":"./bad.js"}}}',
    'node_modules/fixture-math/math.js': 'export const double=x=>x*2;'
  });
  await extract(app, { file: 'index.js', selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
  assert.deepEqual(JSON.parse(await readFile(path.join(out, 'package.json'))).dependencies, {});
});
test('export-star resolution rejects ambiguous providers and handles named chains', async t => {
  const { app, out, cases } = await setup(t, { 'index.js': 'export * from "./math.js";', 'math.js': 'export const format=x=>x*2;' });
  await extract(app, { file: 'index.js', selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
  await writeFile(path.join(app, 'other.js'), 'export const format=x=>x*3;');
  await writeFile(path.join(app, 'index.js'), 'export * from "./math.js";export * from "./other.js";');
  const result = await plan(app, 'index.js', selector);
  assert.equal(result.plan.status, 'blocked'); assert.match(result.plan.issues[0].detail, /Ambiguous/);
});
test('namespace reflection and circular function dependencies remain executable', async t => {
  const { app, out, cases } = await setup(t, {
    'index.js': 'import * as math from "./math.js";export function format(x){return math[Object.keys(math)[0]](x)}',
    'math.js': 'import {check} from "./check.js";export function double(x){return check(x)?x*2:0}',
    'check.js': 'import {double} from "./math.js";export function check(x){return x>0||double(1)>0}'
  });
  await extract(app, { file: 'index.js', selector, out });
  assert.equal((await verify(out, { cases, execute: true })).status, 'passed');
});
test('changed dependency bytes invalidate verification and escaping imports stay blocked', async t => {
  const { app, out, cases } = await setup(t, { 'index.js': 'import {double} from "./math.js";export const format=double;', 'math.js': 'export const double=x=>x*2;' });
  await extract(app, { file: 'index.js', selector, out });
  await writeFile(path.join(app, 'math.js'), 'export const double=x=>x*3;');
  await assert.rejects(() => verify(out, { cases, execute: true }), /Original source changed/);
  await writeFile(path.join(app, 'index.js'), 'import {double} from "../outside.js";export const format=double;');
  assert.equal((await plan(app, 'index.js', selector)).plan.status, 'blocked');
});
test('a behavior contract produces candidates and is embedded without claiming semantic confirmation', async t => {
  const { root, app, out } = await setup(t, {
    'index.js': 'export function format(x){return x*2}export function editor(x){return window.bridge(x)}'
  });
  const specPath = path.join(root, 'feature.json');
  const draft = await createFeature('Extract the local format feature', specPath, app);
  assert.equal(draft.status, 'draft'); assert.ok(draft.missing.length);
  await writeFile(specPath, JSON.stringify({ ...draft.feature, steps: ['Open the formatter'], searchTerms: ['format'],
    acceptance: ['Double the numeric input'], exclusions: ['Editor UI'], examples: [{ name: 'sample', args: [3], expected: 6 }] }));
  const spec = await readFeature(specPath); assert.equal(spec.status, 'ready-for-probe');
  const result = await discover(app, { feature: specPath });
  assert.equal(result.candidates[0].selector.name, 'format'); assert.equal(result.semanticMatch, 'unconfirmed');
  assert.equal(result.candidates[0].status, 'requires-behavioral-probe');
  await extract(app, { file: 'index.js', selector, out, feature: specPath });
  const verified = await verify(out, { execute: true });
  assert.equal(verified.status, 'passed'); assert.equal(verified.featureMatch, 'tested-examples-only');
  await writeFile(path.join(out, 'carve.feature.json'), '{}');
  await assert.rejects(() => verify(out, { execute: true }), /Package changed/);
});
test('discovery reports no match and incomplete coverage instead of inventing a confident selector', async t => {
  const { app } = await setup(t, { 'one.js': 'export function x(a){return a*2}', 'two.js': 'export function y(a){return a*3}' });
  const result = await discover(app, { query: 'clipboard-specific-unseen-feature', scanLimit: 1 });
  assert.equal(result.status, 'no-lexical-match'); assert.equal(result.coverage.complete, false);
  assert.deepEqual(result.candidates, []); assert.match(result.nextAction, /Do not invent/);
});
