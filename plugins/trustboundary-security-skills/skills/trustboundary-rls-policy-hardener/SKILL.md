---
name: trustboundary-rls-policy-hardener
description: Review and fix Supabase, Postgres, Firebase, Firestore, storage, and database policy boundaries with focus on destructive public writes, ownership checks, tenant scoping, auth guards, and narrow rule text. Use when Codex needs to harden policy files or database access controls without broadening TrustBoundary blocker scope.
---

# TrustBoundary RLS Policy Hardener

## Trigger conditions
- Review Supabase or Postgres policy SQL.
- Fix Firebase, Firestore, or storage rules.
- Harden ownership checks, tenant scope, or auth guard logic.
- Tighten destructive public write access.
- Compare safe and unsafe policy examples in fixtures or docs.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/rules.md`, `docs/enforcement-model.md`, `docs/false-positive-policy.md`, and `docs/non-goals.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect `packages/rules/src/index.ts` for current `TB002` matcher boundaries.
- Inspect relevant SQL or rules files plus related safe fixture examples.

## Review checklist
- Identify whether rule grants destructive public or anon access.
- Check for missing or ineffective guards.
- Check for ownership, tenant, auth, or provider checks close to write permission.
- Distinguish public create flows from destructive public update or delete flows.
- Avoid promoting complex or ambiguous policies to blocker claims.
- Keep docs and comments aligned with current `TB002` limits.

## Safe patch guidance
- Add explicit ownership, tenant, or authenticated-user guards for destructive writes.
- Remove literal-true destructive public rules.
- Keep public create flows narrow and pair them with abuse controls when product requires them.
- Prefer simple, reviewable policy text over broad, unclear rules.
- Preserve safe examples that demonstrate scoped access patterns.

## Unsafe content rules
- Do not describe ways to tamper with production data.
- Do not imply complex policy logic is unsafe unless committed evidence proves it.
- Do not broaden `TB002` to cover every policy smell.
- Do not change scanner contracts, rule IDs, CLI behavior, JSON output, or GitHub Action behavior.

## Output format
- State whether finding maps to current blocker, advisory context, or docs-only.
- Summarize exact policy boundary failure.
- Describe replacement guard pattern in prevention-first language.
- Note uncertainty when safety depends on hidden helpers or runtime config.

## Done criteria
- Destructive public write paths are removed or tightly guarded.
- Ownership and tenant scope are explicit where needed.
- Policy guidance stays consistent with current `TB002` scope.
- No enforcement drift appears in docs or examples.
