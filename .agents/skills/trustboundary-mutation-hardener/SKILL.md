---
name: trustboundary-mutation-hardener
description: Review and fix unsafe mutations, raw request-body writes, broad object spreads, mass assignment, missing validation, missing allowlists, and server-owned field control in API and app code. Use when Codex needs to harden write paths without claiming these patterns are active TrustBoundary blockers.
---

# TrustBoundary Mutation Hardener

## Trigger conditions
- Review insert, update, upsert, create, or delete paths fed by request data.
- Fix broad object writes or spreads.
- Add validation and explicit writable-field control.
- Protect server-owned fields such as role, owner, tenant, status, and billing state.
- Improve example code that contrasts safe and unsafe mutation patterns.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/non-goals.md`, `docs/false-positive-policy.md`, and `docs/security-master-checklist.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect relevant route handlers and safe fixture examples in `examples/insecure-next-supabase`.

## Review checklist
- Identify direct request-body flow into writes.
- Check for broad object spread into model data.
- Check for missing schema validation or missing writable-field allowlist.
- Check whether privileged fields remain server-controlled.
- Check whether mutation path also needs auth or ownership tightening.
- Keep these patterns classified as advisory unless repo behavior changes elsewhere.

## Safe patch guidance
- Parse and validate request body before mutation.
- Build explicit writable object instead of forwarding raw body.
- Keep role, owner, tenant, system, and billing fields under server control.
- Combine validation with auth and ownership checks where mutation affects sensitive records.
- Preserve clear contrast between safe examples and unsafe examples in docs or fixtures.

## Unsafe content rules
- Do not include misuse recipes for mass assignment.
- Do not teach how to smuggle privileged fields.
- Do not imply unsafe mutation is current automated blocker coverage.
- Do not change scanner enforcement, rule IDs, CLI behavior, JSON output, or GitHub Action behavior.

## Output format
- Label issue as advisory or docs-only.
- Name exact mutation boundary problem.
- Describe validation, allowlist, and server-owned field fix.
- Mention adjacent auth or ownership needs when directly relevant.

## Done criteria
- Raw request-body writes are removed or tightly controlled.
- Writable fields are explicit and narrow.
- Server-owned fields stay server-controlled.
- Skill output stays prevention-first and does not drift into offensive content.
