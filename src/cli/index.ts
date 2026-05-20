#!/usr/bin/env node

import { resolve } from 'node:path';
import { Command } from 'commander';
import { findLockfile } from '../core/lockfile.js';
import { scanProject, type ScanSummary } from '../core/scan.js';
import { queryByPackage } from '../adapters/osv.js';
import { getSeverity, meetsThreshold } from '../core/severity.js';
import { formatConsole, formatJson } from '../reporters/console.js';
import type { SeverityLevel } from '../core/types.js';

function parseSeverity(value: string): SeverityLevel {
  if (value === 'low' || value === 'moderate' || value === 'high' || value === 'critical') {
    return value;
  }
  throw new Error(`Invalid --severity "${value}". Use one of: low, moderate, high, critical.`);
}

/** A non-zero exit is warranted when a needs-review package carries a vuln at or above the threshold. */
function hasCiFailure(summary: ScanSummary, threshold: SeverityLevel): boolean {
  return summary.vulnerablePackages.some(
    (vp) =>
      vp.impact === 'needs-review' &&
      vp.vulnerabilities.some((v) => meetsThreshold(getSeverity(v), threshold)),
  );
}

const program = new Command();

program
  .name('vuln-scope')
  .description('Detect whether your code is actually affected by known vulnerabilities.')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a project for vulnerability impact')
  .option('-p, --path <dir>', 'project directory to scan', '.')
  .option('-t, --tsconfig <file>', 'tsconfig path, relative to --path', 'tsconfig.json')
  .option('-s, --severity <level>', 'severity threshold for the CI exit code', 'moderate')
  .option('--json', 'output JSON instead of human-readable text')
  .action(async (opts: { path: string; tsconfig: string; severity: string; json?: boolean }) => {
    const lockfilePath = findLockfile(opts.path);
    const tsConfigFilePath = resolve(opts.path, opts.tsconfig);
    const threshold = parseSeverity(opts.severity);

    if (opts.json !== true) {
      console.log(`\n🔍 Scanning "${opts.path}"...\n`);
    }

    const summary = await scanProject({ lockfilePath, tsConfigFilePath });

    console.log(opts.json === true ? formatJson(summary) : formatConsole(summary));

    if (hasCiFailure(summary, threshold)) {
      process.exitCode = 1;
    }
  });

program
  .command('check')
  .description('Quick check: query OSV for a package without code analysis')
  .requiredOption('-p, --package <name>', 'npm package name')
  .option('-v, --version <version>', 'specific version to check')
  .action(async (opts: { package: string; version?: string }) => {
    const vulns = await queryByPackage('npm', opts.package, opts.version);

    if (vulns.length === 0) {
      console.log(
        `✅ No known vulnerabilities for ${opts.package}${opts.version !== undefined ? `@${opts.version}` : ''}`,
      );
      return;
    }

    console.log(
      `\n⚠️  ${vulns.length.toString()} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found:\n`,
    );
    for (const v of vulns) {
      console.log(`  ${v.id}`);
      console.log(`    ${v.summary ?? '(no summary)'}`);
      if (v.severity !== undefined && v.severity.length > 0) {
        console.log(`    Severity: ${v.severity[0]?.score ?? 'unknown'}`);
      }
      console.log();
    }
  });

program.parse();
