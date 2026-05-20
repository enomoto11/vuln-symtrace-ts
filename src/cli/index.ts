#!/usr/bin/env node

import { resolve } from 'node:path';
import { Command } from 'commander';
import { scanProject } from '../core/scan.js';
import { queryByPackage } from '../adapters/osv.js';

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
  .action(async (opts: { path: string; tsconfig: string }) => {
    const lockfilePath = resolve(opts.path, 'pnpm-lock.yaml');
    const tsConfigFilePath = resolve(opts.path, opts.tsconfig);
    console.log(`\n🔍 Scanning "${opts.path}"...\n`);

    const summary = await scanProject({ lockfilePath, tsConfigFilePath });
    const transitiveCount = summary.totalPackages - summary.directCount;

    console.log(
      `📦 ${summary.totalPackages.toString()} dependencies ` +
        `(direct: ${summary.directCount.toString()}, transitive: ${transitiveCount.toString()})`,
    );

    if (summary.vulnerablePackages.length === 0) {
      console.log('\n✅ No known vulnerabilities found.');
      return;
    }

    console.log(`\n⚠️  ${summary.vulnerablePackages.length.toString()} vulnerable package(s):\n`);
    for (const vp of summary.vulnerablePackages) {
      const count = vp.vulnerabilities.length;
      console.log(
        `  [${vp.impact}] ${vp.pkg.name}@${vp.pkg.version} — ${count.toString()} vulnerabilit${count === 1 ? 'y' : 'ies'}`,
      );
      if (vp.impact === 'transitive') {
        console.log('    ↳ transitive dependency — import analysis skipped');
      } else if (vp.impact === 'not-affected') {
        console.log('    ↳ direct dependency, but not imported in code');
      } else {
        for (const u of vp.usages) {
          console.log(`    ↳ imported at ${u.file}:${u.line.toString()}`);
        }
      }
      for (const v of vp.vulnerabilities) {
        console.log(`      ${v.id} — ${v.summary ?? '(no summary)'}`);
      }
      console.log();
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
