import type { OsvVulnerability } from './types.js';

/**
 * Prose words that look like identifiers but are not package APIs. Advisory
 * text often back-quotes type names and concepts (`` `Object` ``,
 * `` `prototype` ``); these would otherwise produce false matches.
 */
const STOP_WORDS: ReadonlySet<string> = new Set([
  'object',
  'array',
  'string',
  'number',
  'boolean',
  'function',
  'prototype',
  'constructor',
  'null',
  'undefined',
  'true',
  'false',
  'error',
  'promise',
  'class',
  'module',
  'package',
  'version',
  'versions',
  'npm',
  'node',
  'the',
  'this',
  'affected',
  'vulnerable',
  'attacker',
  'user',
]);

/**
 * Extracts the code identifiers (function / method names) an advisory's text
 * mentions, so they can be cross-referenced against the exports a project
 * actually uses. Deliberately conservative — it favours missing a real API
 * over inventing one, since a false match would mislead triage.
 *
 * Two high-confidence patterns are used; bare prose tokens are never taken:
 * - back-quoted identifiers (`` `defaultsDeep` ``, `` `lodash.merge()` ``)
 * - dotted call forms in prose (`_.merge()`), unless the receiver is a stop word
 *
 * Returns the distinct identifiers in first-seen order; empty when none.
 */
export function extractAdvisoryApis(vuln: OsvVulnerability): readonly string[] {
  const text = [vuln.summary, vuln.details]
    .filter((part): part is string => part !== undefined)
    .join('\n');
  if (text === '') {
    return [];
  }

  const candidates = [...extractBacktickIdentifiers(text), ...extractDottedCalls(text)];

  const seen = new Set<string>();
  const result: string[] = [];
  for (const name of candidates) {
    if (!seen.has(name)) {
      seen.add(name);
      result.push(name);
    }
  }
  return result;
}

/** Rule A — identifiers wrapped in back-quotes, the most reliable signal. */
function extractBacktickIdentifiers(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(/`([^`]+)`/g)) {
    const raw = match[1];
    if (raw === undefined) continue;
    const candidate = normalizeCandidate(raw);
    if (isPlausibleIdentifier(candidate)) {
      found.push(candidate);
    }
  }
  return found;
}

/**
 * Rule B — dotted call forms in prose (`_.merge()`). A thin safety net for
 * advisories without back-quotes; matches whose receiver is a stop word
 * (`Object.keys()`, `Array.from()`) are dropped to curb false positives.
 */
function extractDottedCalls(text: string): string[] {
  const found: string[] = [];
  for (const match of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(/g)) {
    const receiver = match[1];
    const method = match[2];
    if (receiver === undefined || method === undefined) continue;
    if (STOP_WORDS.has(receiver.toLowerCase())) continue;
    if (isPlausibleIdentifier(method)) {
      found.push(method);
    }
  }
  return found;
}

/**
 * Normalizes a back-quoted candidate to a bare identifier: strips an empty
 * trailing call (`merge()` -> `merge`) and reduces a member path to its last
 * segment (`lodash.merge` -> `merge`).
 */
function normalizeCandidate(raw: string): string {
  const withoutCall = raw.trim().replace(/\(\s*\)$/, '');
  const lastDot = withoutCall.lastIndexOf('.');
  return lastDot === -1 ? withoutCall : withoutCall.slice(lastDot + 1);
}

/** True when a candidate is a valid, non-trivial JS identifier and not a stop word. */
function isPlausibleIdentifier(candidate: string): boolean {
  if (!/^[A-Za-z_$][\w$]*$/.test(candidate)) return false;
  if (candidate.length < 2 || candidate.length > 40) return false;
  return !STOP_WORDS.has(candidate.toLowerCase());
}
