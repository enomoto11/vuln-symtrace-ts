# vuln-symtrace-ts

Triage layer for `npm audit` and Dependabot — tells you which vulnerability alerts actually matter by checking whether your code imports the affected package.

> npm package: `vuln-symtrace-ts` · CLI: `symtrace`

## Problem

`npm audit` and Dependabot flag every vulnerable package in your dependency tree with the same urgency. In practice, most alerts come from transitive dependencies your code never touches. Teams either chase every alert (wasting time) or ignore them all (missing real risks). Both outcomes hurt.

## What symtrace does

symtrace sits on top of your existing vulnerability tooling. It takes the list of known-vulnerable packages and cross-references it against your actual source code using TypeScript AST analysis (ts-morph), then classifies each one:

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

Early development. Single-repo scanning only.

## License

MIT
