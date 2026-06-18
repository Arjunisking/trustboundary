# AGENTS.md

## Project Overview
- Project: TrustBoundary
- Type: Open-source TypeScript security scanner
- Goal: block dangerous AI-generated security mistakes before deploy
- Users: vibe coders, AI automation agencies, fast-moving builders
- Package manager: pnpm
- Runtime: Node.js

## Workspace
- `packages/core`: scanner types, engine contracts, findings
- `packages/cli`: command wrapper
- `packages/action`: GitHub Action wrapper
- `packages/rules`: deterministic rules and fixtures
- `packages/report`: static HTML report generator
- `examples/insecure-next-supabase`: fixture repo for first vertical slice
- `docs`: PRD, technical design, MVP rules

## Commands
- `pnpm install`
- `pnpm typecheck`
- `pnpm test`
- `pnpm build`

## Security Rules
- Keep findings deterministic.
- Do not use LLM output as finding truth.
- Do not execute scanned repo code.
- Do not import scanned repo files.
- Do not run package-manager scripts inside scanned repos.
- Treat scanned files as hostile input.
- Escape all user-controlled HTML report content.
- Never hardcode or log secrets, tokens, credentials, PII.
- Never claim the app is secure.
- Use `No Confirmed Critical issues found`.
- Block Confirmed Critical only by default.
- Warn on Likely and Unverified.

## Review Guidelines
- Prefer small, reviewable vertical slices.
- Keep package boundaries clean.
- Avoid unnecessary dependencies.
- Require tests for scanner rules and report escaping.
- Prefer evidence, exploit path, and fix guidance over broad claims.
- Reject out-of-scope features for V1:
  - dashboards
  - IDE extensions
  - remote rule feeds
  - automatic patch commits

## Done Criteria
- `pnpm install` passes.
- `pnpm typecheck` passes.
- `pnpm test` passes.
- `pnpm build` passes.
- Report output escapes hostile content safely.
- Final response lists files changed, commands run, results, remaining risks.
