import { describe, it, expect } from 'vitest';
import { extractAdvisoryApis } from '../src/core/advisory-api.js';
import type { OsvVulnerability } from '../src/core/types.js';

/** Builds a vulnerability carrying only the given advisory text. */
function vuln(parts: { summary?: string; details?: string }): OsvVulnerability {
  return { id: 'X', ...parts };
}

describe('extractAdvisoryApis', () => {
  it('extracts a single back-quoted identifier', () => {
    expect(extractAdvisoryApis(vuln({ details: 'The function `defaultsDeep` allows ...' }))).toEqual(
      ['defaultsDeep'],
    );
  });

  it('extracts every back-quoted identifier in a list', () => {
    const details =
      'The functions `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` allow ...';
    expect(extractAdvisoryApis(vuln({ details }))).toEqual([
      'pick',
      'set',
      'setWith',
      'update',
      'updateWith',
      'zipObjectDeep',
    ]);
  });

  it('reduces a back-quoted member path to its last segment', () => {
    expect(extractAdvisoryApis(vuln({ details: 'Affects `lodash.merge` and `_.defaultsDeep()`.' }))).toEqual(
      ['merge', 'defaultsDeep'],
    );
  });

  it('drops a back-quoted stop word such as Object', () => {
    expect(extractAdvisoryApis(vuln({ details: 'pollutes the prototype of `Object`.' }))).toEqual(
      [],
    );
  });

  it('drops a back-quoted code snippet that is not an identifier', () => {
    expect(
      extractAdvisoryApis(vuln({ details: 'payload `{constructor: {prototype: {x: 1}}}` ...' })),
    ).toEqual([]);
  });

  it('returns an empty array when the text mentions no identifier', () => {
    expect(
      extractAdvisoryApis(vuln({ details: 'Vulnerable due to improper input sanitization.' })),
    ).toEqual([]);
  });

  it('returns an empty array when there is no advisory text', () => {
    expect(extractAdvisoryApis({ id: 'X' })).toEqual([]);
  });

  it('reads both summary and details', () => {
    expect(
      extractAdvisoryApis(vuln({ summary: 'ReDoS in `trim`', details: 'also `trimEnd`' })),
    ).toEqual(['trim', 'trimEnd']);
  });

  it('de-duplicates while preserving first-seen order', () => {
    expect(
      extractAdvisoryApis(vuln({ details: '`merge` is affected; `merge` again, then `get`.' })),
    ).toEqual(['merge', 'get']);
  });

  it('extracts a dotted call form in prose, skipping stop-word receivers', () => {
    expect(extractAdvisoryApis(vuln({ details: 'calling the _.merge() helper is unsafe' }))).toEqual(
      ['merge'],
    );
    expect(extractAdvisoryApis(vuln({ details: 'using Object.keys() is fine' }))).toEqual([]);
  });
});
