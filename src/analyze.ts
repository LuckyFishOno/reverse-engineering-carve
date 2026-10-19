import { parse } from '@babel/parser';
import traverse, { type Binding, type NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Source } from './artifact.js';

export interface Selector { kind: 'export' | 'symbol'; name: string }
export interface Issue { code: string; name?: string; detail: string }
interface Unit { name: string; path: NodePath; start: number; end: number; text: string }
export interface ImportDependency { source: string; imported: string; local: string; members: string[] | null }
export interface Reexport { source: string; imported: string; exported: string }
export interface AnalyzeOptions { imports?: 'block' | 'preserve'; values?: boolean; initialization?: 'include' | 'block'; receivers?: 'block' | 'internal' }
import { standardGlobals as globals } from './globals.js';
import { inspectCommonJs } from './commonjs.js';

const nameOf = (node: t.Identifier | t.StringLiteral) => t.isIdentifier(node) ? node.name : node.value;
function isCjsTarget(node: t.Node): boolean {
  return t.isMemberExpression(node) && !node.computed && (
    t.isIdentifier(node.object, { name: 'exports' })
    || (t.isIdentifier(node.object, { name: 'module' }) && t.isIdentifier(node.property, { name: 'exports' }))
    || (t.isMemberExpression(node.object) && isCjsTarget(node.object))
  );
}

export function analyze(source: Source, selector?: Selector, options: AnalyzeOptions = {}) {
  const ast = parse(source.code, { sourceType: 'unambiguous', plugins: ['jsx'], errorRecovery: false });
  let program!: NodePath<t.Program>;
  traverse(ast, { Program(p) { program = p; p.stop(); } });
  program.scope.crawl();
  const bindings = program.scope.bindings;
  const exports = new Map<string, string>();
  const reexports: Reexport[] = [];
  const synthetic = new Map<string, NodePath>();
  const unresolvedExports: string[] = [];
  for (const [index, statement] of ast.program.body.entries()) {
    if (t.isExportNamedDeclaration(statement)) {
      if (t.isVariableDeclaration(statement.declaration)) for (const name of Object.keys(t.getBindingIdentifiers(statement.declaration))) exports.set(name, name);
      else if ((t.isFunctionDeclaration(statement.declaration) || t.isClassDeclaration(statement.declaration)) && statement.declaration.id) exports.set(statement.declaration.id.name, statement.declaration.id.name);
      for (const specifier of statement.specifiers) {
        if (t.isExportSpecifier(specifier) && !statement.source) exports.set(nameOf(specifier.exported), nameOf(specifier.local));
        else if (statement.source && t.isExportSpecifier(specifier)) reexports.push({ source: statement.source.value, imported: nameOf(specifier.local), exported: nameOf(specifier.exported) });
        else if (statement.source && t.isExportNamespaceSpecifier(specifier)) reexports.push({ source: statement.source.value, imported: '*', exported: nameOf(specifier.exported) });
      }
    } else if (t.isExportDefaultDeclaration(statement)) {
      const declaration = statement.declaration;
      if (t.isIdentifier(declaration)) exports.set('default', declaration.name);
      else if ((t.isFunctionDeclaration(declaration) || t.isClassDeclaration(declaration)) && declaration.id) exports.set('default', declaration.id.name);
      else {
        const name = program.scope.generateUidIdentifier('carve_default').name;
        exports.set('default', name);
        synthetic.set(name, program.get('body')[index]!.get('declaration') as NodePath);
      }
    } else if (t.isExportAllDeclaration(statement)) reexports.push({ source: statement.source.value, imported: '*', exported: '*' });
    else if (t.isExpressionStatement(statement) && t.isAssignmentExpression(statement.expression, { operator: '=' })) {
      const { left, right } = statement.expression;
      if (isCjsTarget(left) && t.isMemberExpression(left) && !left.computed) {
        if (t.isIdentifier(left.object, { name: 'module' }) && t.isIdentifier(left.property, { name: 'exports' }) && t.isObjectExpression(right)) {
          for (const property of right.properties) {
            if (t.isObjectProperty(property) && !property.computed && t.isIdentifier(property.value)
              && (t.isIdentifier(property.key) || t.isStringLiteral(property.key))) exports.set(nameOf(property.key), property.value.name);
          }
        } else if (t.isIdentifier(right) && t.isIdentifier(left.property)) {
          const name = t.isIdentifier(left.object, { name: 'module' }) ? 'default' : left.property.name;
          exports.set(name, right.name);
        }
      }
    }
  }
  const symbols = Object.entries(bindings).map(([name, binding]) => ({
    name, kind: binding.kind, line: binding.identifier.loc?.start.line ?? null,
    start: binding.path.node.start ?? 0, end: binding.path.node.end ?? 0,
    callable: binding.path.isFunctionDeclaration() || (binding.path.isVariableDeclarator()
      && (t.isFunctionExpression(binding.path.node.init) || t.isArrowFunctionExpression(binding.path.node.init)))
  }));
  for (const [name, p] of synthetic) symbols.push({ name, kind: 'const', line: p.node.loc?.start.line ?? null,
    start: p.node.start ?? 0, end: p.node.end ?? 0,
    callable: p.isFunctionDeclaration() || p.isFunctionExpression() || p.isArrowFunctionExpression() });
  const commonjs = inspectCommonJs(source, ast);
  const base = { commonjs, source: { target: source.target, kind: source.kind, module: source.module, sha256: source.sha256, bytes: source.bytes },
    exports: commonjs ? commonjs.exports.map(e => ({ name: e.name, local: e.local ?? `<commonjs:${e.name}>` })) : [...exports].map(([name, local]) => ({ name, local })), reexports, symbols, unresolvedExports,
    notices: (ast.comments ?? []).filter(c => /@license|@preserve|copyright|SPDX-License-Identifier|\blicense\b/i.test(c.value)).map(c => source.code.slice(c.start!, c.end!)).join('\n'),
    directives: ast.program.directives.map(d => source.code.slice(d.start!, d.end!)).join('\n'),
    sideEffectImports: ast.program.body.filter((n): n is t.ImportDeclaration => t.isImportDeclaration(n) && !n.specifiers.length).map(n => n.source.value),
    executesTarget: false };
  if (!selector) return { ...base, plan: null, code: null, fragments: [] as { start: number; end: number; text: string }[] };
  const local = selector.kind === 'export' ? exports.get(selector.name) : selector.name;
  if (!local || (!bindings[local] && !synthetic.has(local))) throw new Error(`Unknown ${selector.kind} ${JSON.stringify(selector.name)}. Use inspect to see available exports and symbols.`);
  if (!options.values && !symbols.find(s => s.name === local)?.callable && !bindings[local]?.path.isVariableDeclarator()) {
    throw new Error('Select a function declaration or a variable holding a callable.');
  }
  const units = new Map<string, Unit>();
  const issues: Issue[] = [];
  const edges: { from: string; to: string }[] = [];
  const free = new Set<string>();
  const imports: ImportDependency[] = [];
  function add(name: string) {
    if (units.has(name)) return;
    const binding = bindings[name];
    const p = binding?.path ?? synthetic.get(name);
    if (!p) return;
    const start = p.node.start;
    const end = p.node.end;
    if (start == null || end == null) throw new Error('Parser did not retain source ranges.');
    if (p.isImportSpecifier() || p.isImportDefaultSpecifier() || p.isImportNamespaceSpecifier()) {
      if (options.imports === 'preserve') {
        const declaration = p.parentPath!.node as t.ImportDeclaration;
        const imported = p.isImportSpecifier() ? nameOf(p.node.imported) : p.isImportDefaultSpecifier() ? 'default' : '*';
        const specifier = imported === '*' ? `* as ${name}` : imported === 'default' ? name : `{ ${JSON.stringify(imported)} as ${name} }`;
        imports.push({ source: declaration.source.value, imported, local: name, members: null });
        units.set(name, { name, path: p, start, end, text: `import ${specifier} from ${JSON.stringify(declaration.source.value)};` });
        return;
      }
      issues.push({ code: 'module-dependency', name, detail: `Binding ${name} requires ${p.parentPath?.isImportDeclaration() ? p.parentPath.node.source.value : 'an imported module'}. Bundle that dependency or have the agent replace it before extraction.` });
      return;
    }
    if (!synthetic.has(name) && !p.isFunctionDeclaration() && !p.isClassDeclaration() && !p.isVariableDeclarator()) {
      issues.push({ code: 'unsupported-binding', name, detail: `Unsupported declaration for ${name}.` });
      return;
    }
    const text = synthetic.has(name) ? `const ${name} = ${source.code.slice(start, end)};`
      : p.isVariableDeclarator() ? `${(p.parentPath!.node as t.VariableDeclaration).kind} ${source.code.slice(start, end)};` : source.code.slice(start, end);
    units.set(name, { name, path: p, start, end, text });
    visit(p, name);
  }
  function visit(p: NodePath, name: string) {
    function trackWrites(write: NodePath, left: t.Node) {
      for (const refName of Object.keys(t.getBindingIdentifiers(left))) {
        const resolved = write.scope.getBinding(refName);
        if (resolved && resolved === bindings[refName]) { edges.push({ from: name, to: refName }); add(refName); }
        else if (!resolved) issues.push({ code: 'global-write', name: refName, detail: `A retained function writes undeclared/global binding ${refName}.` });
      }
    }
    p.traverse({
      ReferencedIdentifier(reference) {
        const refName = reference.node.name;
        const resolved = reference.scope.getBinding(refName);
        if (resolved && resolved === bindings[refName]) {
          edges.push({ from: name, to: refName });
          add(refName);
        } else if (!resolved && !globals.has(refName)) {
          if (refName === 'arguments' && reference.findParent(q => q.isFunction() && !q.isArrowFunctionExpression())) return;
          free.add(refName);
        }
      },
      AssignmentExpression(assignment) { trackWrites(assignment, assignment.node.left); },
      UpdateExpression(update) { trackWrites(update, update.node.argument); },
      ForOfStatement(loop) { trackWrites(loop, loop.node.left); },
      ForInStatement(loop) { trackWrites(loop, loop.node.left); },
      JSXElement() { issues.push({ code: 'jsx-runtime', name, detail: 'Compile JSX and include its runtime before extracting this declaration.' }); },
      JSXFragment() { issues.push({ code: 'jsx-runtime', name, detail: 'Compile JSX and include its runtime before extracting this declaration.' }); },
      MetaProperty() { issues.push({ code: 'module-context', name, detail: 'A retained declaration depends on import.meta or new.target context.' }); },
      ThisExpression(p) { if (options.receivers === 'internal' && p.findParent(q => q.isFunction() && !q.isArrowFunctionExpression())) return; issues.push({ code: 'receiver-dependency', name, detail: 'A retained declaration uses this; an explicit receiver contract is required.' }); },
      Super() { issues.push({ code: 'receiver-dependency', name, detail: 'A retained declaration uses super.' }); },
      ImportExpression() { issues.push({ code: 'dynamic-import', name, detail: 'A retained declaration dynamically imports another module.' }); }
    });
  }
  add(local);
  const contains = (p: NodePath) => [...units.values()].some(u => (p.node.start ?? -1) >= u.start && (p.node.end ?? Infinity) <= u.end);
  if (options.initialization === 'include') {
    let initializers = 0;
    const include = (reference: NodePath) => {
      if (contains(reference) || reference.getFunctionParent() || reference.isExportNamedDeclaration() || reference.isExportDefaultDeclaration()) return;
      if (reference.findParent(p => p.isExportSpecifier() || p.isExportDefaultDeclaration()
        || (p.isAssignmentExpression() && isCjsTarget(p.node.left)))) return;
      const declaration = reference.findParent(p => p.isVariableDeclarator() && Boolean(p.parentPath?.parentPath?.isProgram() || p.parentPath?.parentPath?.isExportNamedDeclaration()));
      if (declaration?.isVariableDeclarator()) {
        for (const name of Object.keys(t.getBindingIdentifiers(declaration.node.id))) add(name);
        return;
      }
      const statement = reference.findParent(p => Boolean(p.parentPath?.isProgram()));
      if (!statement || statement.isImportDeclaration() || statement.isExportDeclaration()) return;
      const start = statement.node.start!; const end = statement.node.end!; const name = `<initialization:${start}>`;
      if (units.has(name)) return;
      if (++initializers > 256) { issues.push({ code: 'initialization-limit', detail: 'More than 256 top-level initialization statements are required.' }); return; }
      units.set(name, { name, start, end, path: statement, text: source.code.slice(start, end) });
      visit(statement, name);
    };
    // Map iteration sees dependencies appended by included statements. Actual
    // mutation checks run after the complete initialization closure is built.
    for (const name of units.keys()) {
      const binding = bindings[name]; if (!binding) continue;
      for (const ref of [...binding.referencePaths, ...binding.constantViolations]) include(ref);
    }
  }
  const retained: Unit[] = [];
  for (const unit of [...new Map([...units.values()].map(u => [`${u.start}:${u.end}`, u])).values()].sort((a, b) => a.start - b.start || b.end - a.end)) {
    if (!retained.some(outer => outer.start <= unit.start && outer.end >= unit.end)) retained.push(unit);
  }
  for (const [name, unit] of units) {
    const binding: Binding | undefined = bindings[name];
    if (!binding) continue;
    for (const write of binding.constantViolations) if (!contains(write)) {
      issues.push({ code: 'external-mutation', name, detail: `${name} is assigned outside the extracted dependency closure (line ${write.node.loc?.start.line ?? '?'}).` });
    }
    for (const reference of binding.referencePaths) {
      if (contains(reference) || reference.getFunctionParent()) continue;
      if (reference.isExportNamedDeclaration() || reference.isExportDefaultDeclaration()) continue;
      if (reference.findParent(p => p.isExportSpecifier() || p.isExportDefaultDeclaration())) continue;
      if (reference.findParent(p => p.isAssignmentExpression() && isCjsTarget(p.node.left))) continue;
      issues.push({ code: 'top-level-interaction', name, detail: `${name} is used by omitted top-level code (line ${reference.node.loc?.start.line ?? '?'}); move that interaction into the selected function or include its effect explicitly.` });
    }
    void unit;
  }
  for (const dependency of imports) {
    if (dependency.imported !== '*') continue;
    const refs = bindings[dependency.local]!.referencePaths.filter(contains);
    const members = new Set<string>(); let dynamic = !refs.length;
    for (const ref of refs) {
      const parent = ref.parentPath;
      if (parent?.isMemberExpression() && parent.node.object === ref.node) {
        if (!parent.node.computed && t.isIdentifier(parent.node.property)) members.add(parent.node.property.name);
        else if (parent.node.computed && t.isStringLiteral(parent.node.property)) members.add(parent.node.property.value);
        else dynamic = true;
      } else dynamic = true;
    }
    dependency.members = dynamic ? null : [...members].sort();
  }
  for (const name of free) issues.push({ code: 'unresolved-global', name, detail: `${name} is not a local binding or an admitted standard JavaScript global.` });
  const uniqueIssues = [...new Map(issues.map(i => [JSON.stringify(i), i])).values()];
  const removedTopLevelStatements = ast.program.body.filter(node => !retained.some(u => u.start >= (node.start ?? 0) && u.end <= (node.end ?? 0))).length;
  const warnings = [
    'Static dependency closure is not a proof of behavioral equivalence. Verify with representative cases.',
    'Unrelated top-level initialization is omitted. Effects on global objects or prototypes may be outside this analysis.'
  ];
  const comments = (ast.comments ?? []).filter(c => /@license|@preserve|copyright|SPDX-License-Identifier|\blicense\b/i.test(c.value));
  const notices = comments.map(c => source.code.slice(c.start!, c.end!)).join('\n');
  const code = `${notices ? notices + '\n' : ''}${ast.program.directives.map(d => source.code.slice(d.start!, d.end!)).join('\n')}\n${retained.map(u => u.text).join('\n\n')}\nexport { ${local} as capability };\n`;
  return { ...base, plan: {
    selector, local, imports, status: uniqueIssues.length ? 'blocked' as const : 'extractable' as const,
    extractionKind: 'source-extraction' as const,
    retained: retained.map(u => ({ name: u.name, start: u.start, end: u.end, line: u.path.node.loc?.start.line ?? null })),
    dependencyEdges: [...new Map(edges.map(e => [`${e.from}:${e.to}`, e])).values()],
    removedTopLevelStatements, issues: uniqueIssues, warnings,
    verification: { status: 'not-run' as const }
  }, code, fragments: retained.map(u => ({ start: u.start, end: u.end, text: u.text })) };
}
