import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig, applyIgnoreRules } from '../src/core/config.js';
import type { ScanSummary } from '../src/core/scan.js';

/** Runs `run` against a throwaway directory, cleaning it up afterwards. */
function withDir(run: (dir: string) => void): void {
  const dir = mkdtempSync(resolve(tmpdir(), 'vuln-symtrace-ts-config-'));
  try {
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeConfig(dir: string, config: unknown): void {
  writeFileSync(resolve(dir, '.symtracerc.json'), JSON.stringify(config));
}

describe('loadConfig', () => {
  it('returns an empty config when no file is present', () => {
    withDir((dir) => {
      expect(loadConfig(dir)).toEqual({});
    });
  });

  it('parses a valid config', () => {
    withDir((dir) => {
      writeConfig(dir, { ignore: [{ id: 'GHSA-x', reason: 'accepted' }] });
      expect(loadConfig(dir).ignore).toEqual([{ id: 'GHSA-x', reason: 'accepted' }]);
    });
  });

  it('throws on malformed JSON', () => {
    withDir((dir) => {
      writeFileSync(resolve(dir, '.symtracerc.json'), '{ not json');
      expect(() => loadConfig(dir)).toThrow(/Failed to parse/);
    });
  });

  it('throws when a rule is missing its reason', () => {
    withDir((dir) => {
      writeConfig(dir, { ignore: [{ id: 'GHSA-x' }] });
      expect(() => loadConfig(dir)).toThrow(/Invalid/);
    });
  });

  it('throws when expires is not an ISO date', () => {
    withDir((dir) => {
      writeConfig(dir, { ignore: [{ id: 'GHSA-x', reason: 'r', expires: '01/01/2026' }] });
      expect(() => loadConfig(dir)).toThrow(/Invalid/);
    });
  });
});

const SUMMARY: ScanSummary = {
  totalPackages: 2,
  directCount: 1,
  vulnerablePackages: [
    {
      pkg: { name: 'lodash', version: '4.17.20', isDirect: true },
      vulnerabilities: [
        { id: 'GHSA-1', summary: 'ReDoS', aliases: ['CVE-2020-1'] },
        { id: 'GHSA-2', summary: 'Prototype Pollution' },
      ],
      impact: 'needs-review',
      usages: [],
      usedExports: [],
    },
  ],
};

describe('applyIgnoreRules', () => {
  const now = new Date('2026-05-21T12:00:00Z');

  it('suppresses a vulnerability matched by its OSV id', () => {
    const { ignored } = applyIgnoreRules(SUMMARY, [{ id: 'GHSA-1', reason: 'accepted' }], now);
    expect(ignored.get('GHSA-1')).toBe('accepted');
    expect(ignored.has('GHSA-2')).toBe(false);
  });

  it('suppresses a vulnerability matched by an alias', () => {
    const { ignored } = applyIgnoreRules(SUMMARY, [{ id: 'CVE-2020-1', reason: 'via cve' }], now);
    expect(ignored.get('GHSA-1')).toBe('via cve');
  });

  it('does not suppress with an expired rule, and reports it as expired', () => {
    const { ignored, expired } = applyIgnoreRules(
      SUMMARY,
      [{ id: 'GHSA-1', reason: 'r', expires: '2026-01-01' }],
      now,
    );
    expect(ignored.has('GHSA-1')).toBe(false);
    expect(expired).toHaveLength(1);
  });

  it('still suppresses when the rule expires later today', () => {
    const { ignored, expired } = applyIgnoreRules(
      SUMMARY,
      [{ id: 'GHSA-1', reason: 'r', expires: '2026-05-21' }],
      now,
    );
    expect(ignored.get('GHSA-1')).toBe('r');
    expect(expired).toHaveLength(0);
  });
});
