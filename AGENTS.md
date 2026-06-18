@'
# AGENTS.md

## Project overview
- Project: TrustBoundary
- Type: Open-source TypeScript security scanner
- Target users: vibe coders, AI automation agencies, fast-moving builders, and workflow developers
- Main goal: detect the most dangerous AI-generated security mistakes before deployment
- Package manager: pnpm
- Language: TypeScript
- Runtime: Node.js

## Packages
- packages/core: scanner engine, evidence graph, rules, findings
- packages/cli: command-line interface
- packages/action: GitHub Action wrapper
- packages/rules: embedded deterministic rules and fixtures
- packages/report: static HTML report generator

## Common commands
- Install: pnpm install
- Build: pnpm build
- Test: pnpm test
- Typecheck: pnpm typecheck
- Format: pnpm format

## Engineering rules
- Keep v1 deterministic.
- Do not use LLMs as the source of truth for findings.
- Do not add dependencies without justification.
- Never hardcode secrets.
- Never log secrets, tokens, credentials, or PII.
- Prefer small, reviewable changes.
- Add tests for scanner rules and report generation.
- Escape all user-controlled content in generated HTML.

## Product rules
- Never claim the app is secure.
- Say "No Confirmed Critical issues found" instead.
- Block only Confirmed Critical issues by default.
- Warn on Likely and Unverified risks.
- Evidence over assumptions.
- Fixes over lectures.

## V1 scope
TrustBoundary V1 detects:
1. Exposed secrets
2. Unsafe mutations
3. Broken authorization
4. Supabase/Firebase rule failures
5. Webhook and AI-agent abuse

## Done means
- TypeScript passes.
- Relevant tests pass.
- Build passes.
- Generated report escapes content safely.
- Final response lists files changed, checks run, and remaining risks.
'@ | Set-Content AGENTS.md