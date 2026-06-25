# TrustBoundary Technical Design

## Architecture
TrustBoundary is a TypeScript monorepo with separate packages for scanner core, CLI, GitHub Action, rules, and report generation.

## Package structure
- packages/core: file walking, stack detection, evidence graph, finding model, scanner rules
- packages/cli: runs scans from terminal
- packages/action: GitHub Action wrapper
- packages/rules: embedded deterministic rules
- packages/report: static HTML report

## Core model
The scanner builds findings from committed evidence.

Finding fields:
- id
- ruleId
- severity
- confidence
- file
- line
- message
- exploitPath
- patch

## Confidence model
- Confirmed: direct evidence proves the issue
- Likely: strong pattern but missing context
- Unverified: scanner lacks required evidence

## Default gating
- all branches: block only Confirmed Critical
- suppressed critical findings remain visible in reports but do not fail CI
- V1 has no automated advisory rules

## V1 engine strategy
Use deterministic parsing first:
- file walking over committed repository evidence only
- deterministic text and structure matching for `TB001`, `TB002`, and `TB003`
- no execution of scanned code
- no imports from scanned repos
- no scanned-repo script execution

Default ignored reference content such as docs, tests, fixtures, and examples must be configurable and bypassable in tests so insecure fixtures can still be scanned.

## Report strategy
Generate one self-contained HTML file with escaped content and no external dependencies.

## Security rules for the scanner itself
- Do not execute scanned project code.
- Do not import scanned project files.
- Do not run npm scripts from scanned repos.
- Treat scanned files as untrusted input.
- Escape HTML report content.
