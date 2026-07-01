---
name: trustboundary-authz-hardener
description: Review and fix broken authorization, object ID tampering risk, admin route abuse, missing ownership checks, tenant scope failures, role checks, and sensitive route access in Next.js, API, and app code. Use when Codex needs to harden server-side authorization boundaries without implying those patterns are active TrustBoundary blockers.
---

# TrustBoundary Authz Hardener

## Trigger conditions
- Review sensitive read or write routes.
- Fix missing ownership or tenant scoping.
- Harden admin or role-protected routes.
- Reduce cross-account access risk from user-controlled identifiers.
- Improve docs or examples that explain authorization boundaries.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/non-goals.md`, `docs/enforcement-model.md`, and `docs/false-positive-policy.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect relevant route handlers, server actions, middleware, and safe fixture examples.

## Review checklist
- Check whether route verifies authenticated subject before sensitive access.
- Check whether record access is scoped by ownership, tenant, or role.
- Check whether admin actions enforce explicit server-side role checks.
- Check whether user-controlled identifiers are resolved through trusted subject context.
- Keep distinction clear between manual review, future advisory, and current blockers.

## Safe patch guidance
- Add server-side auth gates before sensitive reads or writes.
- Scope queries and mutations by current subject ownership or tenant membership.
- Require explicit role checks for admin paths.
- Keep authorization decisions close to data access and side effects.
- Prefer narrow, auditable checks over hidden assumptions from UI or route naming.

## Unsafe content rules
- Do not provide walkthroughs for reaching another account's data.
- Do not include ID-tampering test instructions.
- Do not present authz issues as active blocker rules unless repo behavior proves it.
- Do not change scanner enforcement, rule IDs, CLI behavior, JSON output, or GitHub Action behavior.

## Output format
- Label issue as advisory or docs-only unless it maps to an existing active blocker through another surface.
- Name exact route or action boundary that is missing.
- Describe ownership, tenant, or role fix in prevention-first language.
- Note hidden-middleware uncertainty instead of overstating proof.

## Done criteria
- Sensitive routes enforce explicit server-side authorization.
- Ownership and tenant scope are visible and reviewable.
- Admin actions require clear elevated-role checks.
- Language never implies broken authorization is current automated blocker coverage.
