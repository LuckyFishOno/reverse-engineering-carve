import { inventory } from './artifact.js';
import { Artifact } from './modules.js';
import { analyze } from './analyze.js';
import { readFeature } from './feature.js';
import { bindReaEvidence } from './evidence.js';
import { digest } from './artifact.js';

// Escaped multilingual search aliases preserve non-English user input.
const aliases: Record<string, string[]> = {
  '\u532f\u51fa': ['export', 'serialize', 'stringify'], '\u532f\u5165': ['import', 'parse', 'decode'],
  '\u683c\u5f0f\u5316': ['format'], '\u8f49\u63db': ['convert', 'transform'], '\u58d3\u7e2e': ['compress', 'deflate'],
  '\u641c\u5c0b': ['search', 'find', 'query'], '\u6392\u5e8f': ['sort', 'compare'], '\u9a57\u8b49': ['validate', 'verify'],
  '\u52a0\u5bc6': ['encrypt', 'cipher'], '\u89e3\u5bc6': ['decrypt'], '\u547d\u540d': ['name', 'slug', 'case'], '\u526a\u8cbc\u7c3f': ['clipboard', 'copy']
};
export function searchTerms(query: string, extra: string[] = []) {
  const text = query.replace(/([a-z])([A-Z])/g, '$1 $2');
  const words = [...new Intl.Segmenter('zh-Hant', { granularity: 'word' }).segment(text)].filter(s => s.isWordLike).map(s => s.segment.toLowerCase());
  for (const [term, translations] of Object.entries(aliases)) if (query.includes(term)) words.push(...translations);
  return [...new Set([...extra.map(s => s.toLowerCase()), ...words].filter(s => [...s].length >= 2))].slice(0, 60);
}
export async function discover(input: string, options: { query?: string; feature?: string; file?: string; evidence?: string; limit?: number; scanLimit?: number }) {
  const feature = options.feature ? await readFeature(options.feature) : undefined;
  const query = options.query ?? feature?.feature.description;
  if (!query?.trim()) throw new Error('Supply --query or --feature with a behavior description.');
  const limit = options.limit ?? 12; const scanLimit = options.scanLimit ?? 1000;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(scanLimit) || scanLimit < 1 || scanLimit > 2000) throw new Error('Candidate limit must be 1–100; scan limit must be 1–2000.');
  const artifact = await Artifact.open(input);
  const listed = options.file ? [options.file] : artifact.defaultEntry ? [artifact.defaultEntry] : (await inventory(input)).modules;
  const terms = searchTerms(query, feature?.feature.searchTerms);
  const candidates: { id: string; module: string; sourceSha256: string; selector: { kind: 'export' | 'symbol'; name: string }; line: number | null;
    score: number; evidence: { kind: string; term: string; line: number | null; excerpt: string }[]; status: string }[] = [];
  const errors: { module: string; error: string }[] = [];
  const sources: { module: string; sha256: string }[] = [];
  for (const module of listed.slice(0, scanLimit)) {
    try {
      const source = await artifact.source(module); sources.push({ module, sha256: source.sha256 });
      const analysis = analyze(source);
      const entities = analysis.commonjs
        ? analysis.commonjs.exports.filter(e => e.callable !== false).map(e => ({ ...e, name: e.local ?? e.name, names: [e.name] }))
        : analysis.symbols.filter(s => s.callable).map(s => ({ ...s, names: analysis.exports.filter(e => e.local === s.name).map(e => e.name) }));
      for (const symbol of entities) {
        const names = symbol.names;
        const body = analysis.commonjs ? source.code : source.code.slice(symbol.start, symbol.end);
        const bodyStart = analysis.commonjs ? 0 : symbol.start;
        const evidence: { kind: string; term: string; line: number | null; excerpt: string }[] = [];
        let score = 0;
        for (const term of terms) {
          if (names.some(n => n.toLowerCase().includes(term)) || symbol.name.toLowerCase().includes(term)) {
            score += 8; evidence.push({ kind: 'identifier', term, line: symbol.line, excerpt: [...names, symbol.name].join(', ') });
          }
          if (module.toLowerCase().includes(term)) { score += 3; evidence.push({ kind: 'module-path', term, line: null, excerpt: module }); }
          const offset = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'iu').exec(body)?.index ?? -1;
          if (offset >= 0) {
            score += 2; const prefix = source.code.slice(0, bodyStart + offset);
            evidence.push({ kind: 'source-text', term, line: prefix.split('\n').length, excerpt: body.slice(Math.max(0, offset - 50), offset + term.length + 80).replace(/\s+/g, ' ') });
          }
        }
        if (!score) continue;
        const selector = names.length ? { kind: 'export' as const, name: names[0]! } : { kind: 'symbol' as const, name: symbol.name };
        candidates.push({ id: digest(`${module}\0${source.sha256}\0${JSON.stringify(selector)}`).slice(0, 20), module, sourceSha256: source.sha256, selector,
          line: symbol.line, score, evidence, status: 'requires-behavioral-probe' });
      }
    } catch (error) { errors.push({ module, error: (error as Error).message }); }
  }
  candidates.sort((a, b) => b.score - a.score || a.module.localeCompare(b.module) || a.selector.name.localeCompare(b.selector.name));
  const rea = options.evidence ? await bindReaEvidence(options.evidence, artifact, sources) : null;
  return { schema: 'carve/discovery@1', target: artifact.target, query, terms, featureSha256: feature?.sha256 ?? null,
    featureStatus: feature?.status ?? null, featureMissing: feature?.missing ?? [],
    status: candidates.length ? 'candidates-found' : 'no-lexical-match', semanticMatch: 'unconfirmed', executesTarget: false,
    ranking: 'Identifier=8, module path=3, source-text=2 per matching term; scores are ordering signals, not probabilities.',
    coverage: { totalModules: listed.length, scannedModules: Math.min(listed.length, scanLimit), parsedModules: sources.length - errors.filter(e => sources.some(s => s.module === e.module)).length,
      complete: listed.length <= scanLimit && !errors.length, candidateCount: candidates.length, returnedCandidates: Math.min(candidates.length, limit), scanLimit, errors },
    candidates: candidates.slice(0, limit).map(candidate => ({ ...candidate,
      reaNodeIds: rea?.modules.find(m => m.module === candidate.module)?.nodeIds ?? [] })), rea,
    nextAction: candidates.length ? 'Inspect candidate code, use REA for call/context evidence, then compare the requested examples against the original before claiming a match.'
      : 'No lexical candidate was found. Use REA to trace the UI action, IPC, string or API boundary; add observed technical terms or narrow --file. Do not invent a match.' };
}
