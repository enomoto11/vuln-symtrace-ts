# vuln-symtrace-ts

An OSV-based vulnerability scanner that adds a triage step: it tells you which vulnerable dependencies your code actually imports, so you can focus on the alerts that represent real exposure.

> Status: in development, not yet published to npm · CLI: `symtrace`

## Problem

`npm audit` and Dependabot flag every vulnerable package in your dependency tree with the same urgency. In practice, most alerts come from transitive dependencies your code never touches. Teams either chase every alert (wasting time) or ignore them all (missing real risks). Both outcomes hurt.

## What symtrace does

symtrace scans your dependency tree, queries the OSV database for known vulnerabilities itself, and then cross-references each vulnerable package against your actual source code using TypeScript AST analysis (ts-morph) to classify it:

| Level          | Meaning                                                         |
| -------------- | --------------------------------------------------------------- |
| `needs-review` | Direct dependency that your code imports                        |
| `not-affected` | Direct dependency that is never imported                        |
| `transitive`   | Indirect dependency; the report shows which direct dependency pulls it in |

This lets you focus on the handful of alerts that represent real exposure instead of treating all of them equally.

## How it works

1. Detect and parse the project's lockfile (`pnpm-lock.yaml`, `package-lock.json`, or `yarn.lock`)
2. Query the OSV API for every dependency, direct and transitive
3. For each vulnerable package, use ts-morph to check whether your code imports it
4. Classify impact and report results

Import detection covers static imports, dynamic `import()`, `require()`, and re-exports (`export ... from`), including subpath imports such as `lodash/get` and scoped subpaths like `@scope/pkg/sub` — these are resolved back to their package. Type-only imports are ignored since they are erased at compile time.

## Usage

### Scan a project

```
symtrace scan -p ./my-project
```

Options:

- `-p, --path <dir>` — project directory to scan (default: `.`)
- `-t, --tsconfig <file>` — tsconfig path, relative to `--path` (default: `tsconfig.json`)
- `-s, --severity <level>` — minimum severity for a non-zero exit code: `low` | `moderate` | `high` | `critical` (default: `moderate`)
- `--json` — output JSON instead of human-readable text

Exits with code `1` when a `needs-review` package has a vulnerability at or above the severity threshold, making it usable as a CI gate.

### Suppressing alerts

To stop a specific vulnerability from failing the CI gate — for example one you have reviewed and accepted — add a `.symtracerc.json` file to the scanned project directory:

```json
{
  "ignore": [
    {
      "id": "GHSA-jf85-cpcp-j695",
      "reason": "not reachable — only the unaffected API is used",
      "expires": "2026-12-31"
    }
  ]
}
```

- `id` — the OSV id, GHSA id, or a CVE alias of the vulnerability to suppress.
- `reason` — required, so every suppression stays documented.
- `expires` — optional ISO date (`YYYY-MM-DD`). After it passes, the rule stops suppressing and symtrace prints a warning, forcing periodic re-review.

Suppressed vulnerabilities are still listed in the report (annotated with their reason); they are only excluded from the exit code.

### Check a single package

```
symtrace check -p lodash
symtrace check -p lodash -v 4.17.20
```

Queries the OSV API for a package without code analysis.

## Severity

A vulnerability's severity is taken from the GitHub Advisory Database label when present, and otherwise computed from the CVSS v3 vector. CVSS v4 is not yet supported.

## Supported package managers

pnpm, npm, and yarn v1 (classic). Yarn Berry (v2+) is not yet supported.

## Requirements

Node.js >= 20.

## Scope and limitations

symtrace does not replace `npm audit` or Dependabot — it adds a triage step. Current limitations:

- Detects whether a vulnerable package is imported, not whether a specific vulnerable API is called. A `needs-review` result means "your code uses this package; verify manually." Deeper call-level analysis is planned.
- Transitive dependencies are flagged but not analyzed for code usage, since your code typically does not import them directly. The report shows the dependency chain that pulls each one in.
- Workspaces / monorepos are not yet supported. symtrace analyzes a single package against one `tsconfig`, so in a pnpm/npm/yarn workspace with multiple packages the direct/transitive classification and import analysis can be inaccurate. Run symtrace once per package directory instead.
- JavaScript-only (non-TypeScript) projects are supported via `allowJs`, but symbol resolution accuracy is lower without type information.

## Status

Early development, not yet published to npm. Single-repo scanning only.

## License

MIT
