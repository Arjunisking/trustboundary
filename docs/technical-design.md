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
- main branch: block Confirmed Critical
- pull requests: warn, block only Confirmed Critical by default
- dev branches: warn only

## V1 engine strategy
Use deterministic parsing first:
- file walking
- regex and string rules for secrets
- TypeScript AST later for unsafe mutations and authorization flow

## Report strategy
Generate one self-contained HTML file with escaped content and no external dependencies.

## Security rules for the scanner itself
- Do not execute scanned project code.
- Do not import scanned project files.
- Do not run npm scripts from scanned repos.
- Treat scanned files as untrusted input.
- Escape HTML report content.
