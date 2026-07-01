---
name: trustboundary-secret-boundary-hardener
description: Review and fix client-side secret exposure, NEXT_PUBLIC misuse, browser-delivered provider keys, Supabase service-role leakage, unsafe env boundaries, and secret placement mistakes in Next.js, frontend, webhook, and AI-built apps. Use when Codex needs to harden secret handling without expanding TrustBoundary scanner enforcement.
---

# TrustBoundary Secret Boundary Hardener

## Trigger conditions
- Review browser-exposed env usage such as `NEXT_PUBLIC_*`, `VITE_*`, or `PUBLIC_*`.
- Fix hardcoded secrets in frontend code, components, pages, or client bundles.
- Move Supabase service-role access out of client code.
- Separate publishable keys from privileged keys.
- Tighten server-only env boundaries in examples, docs, or app code.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/rules.md`, `docs/enforcement-model.md`, `docs/false-positive-policy.md`, and `docs/report-language.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect `packages/rules/src/index.ts` for current `TB001` boundaries before changing scanner-adjacent copy.
- Inspect relevant app files for client markers, frontend placement, and env usage.

## Review checklist
- Confirm whether secret is browser-exposed or server-only.
- Confirm whether env name crosses public/private boundary.
- Check for hardcoded provider keys, admin tokens, service-role values, and JWT-like privileged tokens.
- Check whether docs or examples describe secret handling accurately without implying broader enforcement.
- Check whether report copy, patches, or comments stay defensive and never claim app is secure.
- Keep `TB001` scope narrow if touching scanner-adjacent text.

## Safe patch guidance
- Move privileged keys to server-only code or secret manager.
- Replace browser-visible privileged keys with publishable or anon keys where product design allows.
- Rename env variables to preserve server-only intent.
- Route privileged actions through server handlers with least privilege.
- Remove hardcoded secrets from examples, logs, docs, and screenshots.

## Unsafe content rules
- Do not include secret samples that look live.
- Do not include offensive guidance or request recipes.
- Do not imply every secret-looking string is an active blocker.
- Do not expand scanner behavior beyond existing `TB001` boundaries.
- Do not change rule IDs, CLI behavior, JSON output, GitHub Action behavior, or clean report wording.

## Output format
- State whether issue is current blocker, advisory context, or docs-only.
- List exact files and boundary mistakes found.
- Describe fix in prevention-first language.
- Call out any remaining ambiguity instead of overstating certainty.

## Done criteria
- Client-side secret exposure is removed or isolated behind server-only boundaries.
- Public env usage contains only intended public values.
- Scanner-adjacent text stays consistent with current `TB001` behavior.
- No new enforcement claims appear.
