# symtrace

A vulnerability scanner that checks whether your code is **actually affected** — not just whether a vulnerable package exists in your dependency tree.

> npm package: `vuln-symtrace-ts` · CLI: `symtrace`

## Problem

`npm audit` and Dependabot tell you a vulnerable package is in your dependencies. They don't tell you whether you actually use it. Most of the time the vulnerable package is pulled in transitively, or imported nowhere in your code — but the warning looks just as urgent as the ones that matter.

## How it works

1. Detect and parse the project's lockfile (`pnpm-lock.yaml`, `package-lock.json`, or `yarn.lock`)
2. Query the OSV API for every dependency, direct and transitive
3. For each vulnerable package, use **ts-morph** to check whether your code imports it
4. Classify the impact of each vulnerable package

## Impact levels

| Level | Meaning |
|---|---|
| `needs-review` | Direct dependency that your code imports |
| `not-affected` | Direct dependency that is never imported |
| `transitive` | Indirect dependency (import analysis is skipped) |

Import detection covers static imports, dynamic `import()`, `require()`, and re-exports (`export ... from`). Type-only imports are ignored, since they are erased at compile time and cannot trigger a vulnerability at runtime.

## Usage

### Scan a project

```sh
symtrace scan -p ./my-project
```

Options:

- `-p, --path <dir>` — project directory to scan (default: `.`)
- `-t, --tsconfig <file>` — tsconfig path, relative to `--path` (default: `tsconfig.json`)
- `-s, --severity <level>` — severity threshold for the CI exit code: `low` | `moderate` | `high` | `critical` (default: `moderate`)
- `--json` — output JSON instead of human-readable text

The process exits with code `1` when a `needs-review` package carries a vulnerability at or above the severity threshold, making it usable as a CI gate.

### Check a single package

```sh
symtrace check -p lodash
symtrace check -p lodash -v 4.17.20
```

Queries the OSV API for a package without any code analysis.

## Severity

A vulnerability's severity is taken from the GitHub Advisory Database label when present, and otherwise computed from the advisory's CVSS v3 vector. CVSS v4 vectors are not yet supported.

## Supported package managers

pnpm, npm, and yarn v1 (classic). Yarn Berry (v2+) is not yet supported.

## Requirements

Node.js >= 20.

## Status

Early development. Scans a single repository. The impact model is `needs-review` / `not-affected` / `transitive` — detecting whether a *specific* vulnerable API is actually called is planned for a later phase.

## License

MIT
