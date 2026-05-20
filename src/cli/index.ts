#!/usr/bin/env node

import { Command } from 'commander';
import { queryByPackage } from '../adapters/osv.js';
import { runScan } from './run-scan.js';

const program = new Command();

program
  .name('symtrace')
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
    const json = opts.json === true;
    if (!json) {
      console.log(`\n🔍 Scanning "${opts.path}"...\n`);
    }

    const { output, exitCode } = await runScan({
      path: opts.path,
      tsconfig: opts.tsconfig,
      severity: opts.severity,
      json,
    });

    console.log(output);
    process.exitCode = exitCode;
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
