# vuln-scope

A vulnerability scanner that checks whether your code is **actually affected** — not just whether a vulnerable package exists in your dependency tree.

## Problem

`npm audit` and Dependabot tell you a vulnerable package is in your dependencies. They don't tell you whether you're calling the dangerous API. Most of the time, you aren't.

## Approach

1. Fetch advisories from OSV API / GitHub Advisory Database
2. Resolve which repos contain the affected package
3. Use **ts-morph** to analyze code and detect usage of the vulnerable API via AST + symbol resolution
4. Report impact per repo: affected, needs review, or not affected

## Features

- CLI (`vuln-scope scan` / `vuln-scope check`) and library usage
- Multi-repo scanning
- Severity-based filtering

## Status

Early development.

## License

MIT