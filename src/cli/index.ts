#!/usr/bin/env node

import { Command } from 'commander';
import { analyzeUsages } from '../core/analyzer.js';
import { queryByPackage } from '../adapters/osv.js';

const program = new Command();

program
  .name('vuln-scope')
  .description('Detect whether your code is actually affected by known vulnerabilities.')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan a project for vulnerability impact')
  .requiredOption('-p, --package <name>', 'npm package name to check')
  .option('-t, --tsconfig <path>', 'path to tsconfig.json', './tsconfig.json')
  .option('--apis <apis...>', 'specific APIs to check (e.g. res.redirect)')
  .action(async (opts: { package: string; tsconfig: string; apis?: string[] }) => {
    console.log(`\n🔍 Querying OSV for vulnerabilities in "${opts.package}"...\n`);

    const vulns = await queryByPackage('npm', opts.package);

    if (vulns.length === 0) {
      console.log('✅ No known vulnerabilities found.');
      return;
    }

    console.log(`⚠️  Found ${vulns.length.toString()} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'}:\n`);
    for (const v of vulns) {
      const aliases = v.aliases?.join(', ') ?? 'none';
      console.log(`  ${v.id} — ${v.summary ?? '(no summary)'}`);
      console.log(`    Aliases: ${aliases}\n`);
    }

    console.log(`\n🔬 Analyzing code usage in project (${opts.tsconfig})...\n`);

    const usages = analyzeUsages({
      tsConfigFilePath: opts.tsconfig,
      packageName: opts.package,
      affectedApis: opts.apis,
    });

    if (usages.length === 0) {
      console.log('✅ Package is in dependencies but no affected API usage found.');
    } else {
      console.log(`🔴 Found ${usages.length.toString()} usage(s):\n`);
      for (const u of usages) {
        console.log(`  ${u.file}:${u.line.toString()}:${u.column.toString()}`);
        console.log(`    ${u.code}\n`);
      }
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
      console.log(`✅ No known vulnerabilities for ${opts.package}${opts.version !== undefined ? `@${opts.version}` : ''}`);
      return;
    }

    console.log(`\n⚠️  ${vulns.length.toString()} vulnerabilit${vulns.length === 1 ? 'y' : 'ies'} found:\n`);
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
