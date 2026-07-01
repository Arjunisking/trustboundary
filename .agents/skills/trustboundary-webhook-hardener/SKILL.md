---
name: trustboundary-webhook-hardener
description: Review and fix Stripe, Clerk, Shopify, GitHub, and similar webhook handlers with focus on signature verification, side-effect boundaries, replay resistance, idempotency, trusted event-body handling, and dangerous sinks. Use when Codex needs to harden webhook code or docs without changing TrustBoundary current webhook blocker rules.
---

# TrustBoundary Webhook Hardener

## Trigger conditions
- Review known-provider webhook routes.
- Fix missing signature verification.
- Add replay resistance or idempotency.
- Reduce dangerous writes, external calls, or queue dispatch before verification.
- Harden webhook examples, docs, or report copy.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/rules.md`, `docs/enforcement-model.md`, `docs/false-positive-policy.md`, and `docs/report-language.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect `packages/rules/src/index.ts` for current `TB003` provider, route, and verification boundaries.
- Inspect relevant route files and safe fixture variants.

## Review checklist
- Confirm route belongs to supported provider or broader webhook surface.
- Confirm verification happens before state changes or external side effects.
- Check for clear local verification helper names when verification is abstracted.
- Check replay resistance, idempotency, and event dedupe where product flow needs them.
- Check whether event body handling stays narrow after verification.
- Keep current blocker claims limited to present `TB003` matcher behavior.

## Safe patch guidance
- Verify signatures before writes, billing actions, account changes, or queue dispatch.
- Keep verification close to body read and side effects.
- Add event dedupe, freshness checks, or idempotent processing for replay resistance.
- Isolate dangerous sinks behind trusted, validated event handling.
- Keep provider-specific examples precise but defensive.

## Unsafe content rules
- Do not include request recipes, offensive walkthroughs, or forged-event guidance.
- Do not use wording that teaches replay execution.
- Do not expand `TB003` into unsupported providers or ambiguous verification patterns unless repo behavior actually changes.
- Do not change rule IDs, CLI behavior, JSON output, GitHub Action behavior, or clean report wording.

## Output format
- State whether issue maps to current blocker, advisory context, or docs-only.
- List route, trust boundary gap, and risky side effect.
- Describe verification and replay-hardening fix in prevention-first language.
- Call out unsupported-provider or custom-helper ambiguity clearly.

## Done criteria
- Verification happens before dangerous side effects.
- Replay resistance and idempotency are improved where needed.
- Webhook docs stay accurate about current `TB003` scope.
- No enforcement drift or offensive wording appears.
