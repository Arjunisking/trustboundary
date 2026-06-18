---
name: trustboundary-builder
description: Build, review, test, and document TrustBoundary scanner work with deterministic rules, safe HTML reports, and small vertical slices.
---

# TrustBoundary Builder

## Mission
Build TrustBoundary as a deterministic TypeScript pre-deploy scanner for AI-built apps. Prefer evidence over guesses. Keep V1 narrow and high-signal.

## Hard Rules
- Use TypeScript.
- Read `AGENTS.md` and docs first.
- Do not rely on LLM judgment for findings.
- Do not execute or import scanned repo code.
- Treat all scanned content as hostile input.
- Keep package boundaries clean.
- Make small, reviewable changes.
- Add docs when behavior changes.

## V1 Scope
- Exposed secrets
- Unsafe mutations
- Broken authorization
- Supabase/Firebase rule failures
- Webhook and AI-agent abuse

## Architecture Boundaries
- `packages/core`: scanner engine, file walker, evidence graph, findings, rule execution.
- `packages/cli`: command wrapper.
- `packages/action`: GitHub Action wrapper.
- `packages/rules`: embedded deterministic rules and fixtures.
- `packages/report`: static HTML report generator.
- `docs`: PRD, technical design, MVP rules.

## Security Rules
- Deterministic evidence over AI guesses.
- Never hardcode secrets.
- Never log secrets, tokens, credentials, or PII.
- Never claim the app is secure.
- Use `No Confirmed Critical issues found`.
- Block Confirmed Critical only by default.
- Warn on Likely and Unverified.

## HTML Report Rules
- Escape all user-controlled content.
- Treat file names, paths, code, messages, and metadata as untrusted.
- Prevent script injection, HTML injection, and attribute injection.

## Testing Rules
- Add or update tests for scanner rules and report generation.
- Run `pnpm build`.
- Run `pnpm test`.
- Run `pnpm typecheck` when available.
- Run `pnpm install` only when needed.

## Codex Work Loop
1. Read `AGENTS.md` and docs.
2. Summarize current state briefly.
3. Plan the smallest safe slice.
4. Edit minimal files.
5. Add or update tests.
6. Run verification commands.
7. Fix only in-scope failures.
8. Keep output concise and factual.

## Required Final Response
- Files changed
- What changed
- Commands run
- Test results
- Remaining risks
