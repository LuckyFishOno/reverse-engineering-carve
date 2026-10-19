import { parse } from '@babel/parser';
import traverse, { type NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import type { Source } from './artifact.js';
import type { Issue } from './analyze.js';
import { standardGlobals } from './globals.js';

const property = (node: t.MemberExpression) => !node.computed && t.isIdentifier(node.property) ? node.property.name
  : node.computed && t.isStringLiteral(node.property) ? node.property.value : undefined;
const unbound = (p: NodePath, name: string) => !p.scope.getBinding(name);
function moduleExports(node: t.Node, p: NodePath): boolean {
  return t.isMemberExpression(node) && t.isIdentifier(node.object, { name: 'module' }) && property(node) === 'exports' && unbound(p, 'module');
}
function exportProperty(node: t.Node, p: NodePath) {
  if (!t.isMemberExpression(node)) return undefined;
  if ((t.isIdentifier(node.object, { name: 'exports' }) && unbound(p, 'exports')) || moduleExports(node.object, p)) return property(node);
  return undefined;
}
/** Whole CommonJS capsules preserve initialization/export mutation order. They
 * are never described as declaration-minimal slices, and never run in analysis. */
export function inspectCommonJs(source: Source, parsed?: ReturnType<typeof parse>) {
  const ast = parsed ?? parse(source.code, { sourceType: 'unambiguous', plugins: ['jsx'] });
  const esm = ast.program.body.some(n => t.isImportDeclaration(n) || t.isExportDeclaration(n));
  let detected = source.module.endsWith('.cjs');
  let declarationExports = true;
  const dependencies: { source: string; start: number; end: number }[] = [];
  const issues: Issue[] = [];
  const exports = new Map<string, { name: string; local: string | null; callable: boolean | null; start: number; end: number; line: number | null }>();
  const entry = (name: string, value: t.Node, p: NodePath) => {
    const binding = t.isIdentifier(value) ? p.scope.getBinding(value.name) : undefined;
    const definition = binding?.path.isVariableDeclarator() ? binding.path.node.init : binding?.path.node ?? value;
    exports.set(name, { name, local: t.isIdentifier(value) ? value.name : null,
      callable: t.isFunction(definition) ? true : t.isObjectExpression(definition) || t.isLiteral(definition) || t.isClass(definition) ? false : null,
      start: value.start ?? 0, end: value.end ?? source.code.length, line: value.loc?.start.line ?? null });
  };
  const block = (code: string, detail: string, name?: string) => issues.push({ code, detail, ...(name ? { name } : {}) });
  traverse(ast, {
    enter(p) {
      // Bundlers emit `0 && (module.exports = {originalNames})` as a Node
      // export hint. Those identifiers may be renamed and are never executed.
      if (p.key === 'right' && p.parentPath?.isLogicalExpression()) {
        const { left, operator } = p.parentPath.node;
        if (t.isNumericLiteral(left) || t.isBooleanLiteral(left) || t.isStringLiteral(left) || t.isNullLiteral(left)) {
          const truthy = t.isNullLiteral(left) ? false : Boolean(left.value);
          if ((operator === '&&' && !truthy) || (operator === '||' && truthy)) p.skip();
        }
      }
    },
    ReferencedIdentifier(p) {
      const name = p.node.name;
      if (!unbound(p, name)) return;
      if (['module', 'exports', 'require'].includes(name)) detected = true;
      if (name === 'require') {
        if (!(p.parentPath.isCallExpression() && p.parentPath.node.callee === p.node)) block('require-context', 'Only direct, literal require() calls can be bundled.');
        return;
      }
      if (name === 'module' || name === 'exports') {
        const assignment = p.findParent(q => q.isAssignmentExpression());
        if (!assignment?.isAssignmentExpression() || !assignment.parentPath?.isExpressionStatement() || !assignment.parentPath.parentPath?.isProgram()
          || (p.node.start ?? 0) > (assignment.node.left.end ?? -1)
          || !(t.isIdentifier(assignment.node.right) || (t.isObjectExpression(assignment.node.right) && assignment.node.right.properties.every(item => t.isObjectProperty(item) && !item.computed && t.isIdentifier(item.value))))) declarationExports = false;
      }
      if (name === 'module') {
        if (!(p.parentPath.isMemberExpression() && p.parentPath.node.object === p.node && property(p.parentPath.node) === 'exports')) block('module-context', 'CommonJS module context other than module.exports is unsupported.');
        return;
      }
      if (name === 'exports' || standardGlobals.has(name)) return;
      if (name === 'arguments' && p.findParent(q => q.isFunction() && !q.isArrowFunctionExpression())) return;
      block('unresolved-global', `${name} is not a local binding or an admitted standard JavaScript global.`, name);
    },
    CallExpression(p) {
      if (!t.isIdentifier(p.node.callee, { name: 'require' }) || !unbound(p, 'require')) return;
      detected = true;
      if (p.node.arguments.length !== 1 || !t.isStringLiteral(p.node.arguments[0])) block('dynamic-require', 'A CommonJS capsule requires a non-literal or unsupported require() call.');
      else dependencies.push({ source: p.node.arguments[0].value, start: p.node.start!, end: p.node.end! });
    },
    AssignmentExpression(p) {
      if (p.node.operator !== '=') return;
      if (moduleExports(p.node.left, p)) {
        entry('default', p.node.right, p);
        if (t.isObjectExpression(p.node.right)) for (const item of p.node.right.properties) {
          if (t.isObjectProperty(item) && !item.computed && (t.isIdentifier(item.key) || t.isStringLiteral(item.key))) entry(t.isIdentifier(item.key) ? item.key.name : item.key.value, item.value, p);
        }
      } else {
        const name = exportProperty(p.node.left, p); if (name !== undefined) entry(name, p.node.right, p);
      }
      for (const name of Object.keys(t.getBindingIdentifiers(p.node.left))) if (unbound(p, name)) block('global-write', `CommonJS capsule writes undeclared binding ${name}.`, name);
    },
    UpdateExpression(p) { if (t.isIdentifier(p.node.argument) && unbound(p, p.node.argument.name)) block('global-write', 'CommonJS capsule updates an undeclared binding.', p.node.argument.name); },
    ImportExpression() { block('dynamic-import', 'Dynamic imports in CommonJS capsules are unsupported.'); },
    MetaProperty() { block('module-context', 'CommonJS capsules depending on import.meta or new.target need an explicit harness.'); },
    JSXElement() { block('jsx-runtime', 'Compile JSX before extracting a CommonJS capsule.'); },
    JSXFragment() { block('jsx-runtime', 'Compile JSX before extracting a CommonJS capsule.'); }
  });
  if (!detected || esm) return null;
  if (!exports.has('default')) exports.set('default', { name: 'default', local: null, callable: false, start: 0, end: source.code.length, line: 1 });
  return { exports: [...exports.values()], dependencies, issues: [...new Map(issues.map(i => [JSON.stringify(i), i])).values()],
    declarationExports, retention: 'whole-commonjs-module' as const, executesTarget: false };
}
