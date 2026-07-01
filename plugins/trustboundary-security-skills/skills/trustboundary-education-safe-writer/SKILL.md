---
name: trustboundary-education-safe-writer
description: Write and revise TrustBoundary docs, report text, website explanations, exploitPath text, patch guidance, attack-pattern explanations, and educational security copy with strict defensive wording, coverage accuracy, and blocker/advisory/docs-only separation. Use when Codex needs to produce safe security education without offensive detail or enforcement drift.
---

# TrustBoundary Education Safe Writer

## Trigger conditions
- Write or revise docs under `docs/`.
- Write scanner finding copy, `exploitPath`, or patch guidance.
- Draft future website explanations or report education sections.
- Review security learning content for wording safety and coverage accuracy.
- Normalize blocker, advisory, and docs-only labeling.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/rules.md`, `docs/enforcement-model.md`, `docs/report-language.md`, `docs/false-positive-policy.md`, and `docs/non-goals.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect current finding copy in `packages/rules/src/index.ts` and report rendering in `packages/report/src/index.ts` when writing scanner-adjacent language.

## Review checklist
- Confirm every claim about detection matches current repo behavior.
- Keep `TB001`, `TB002`, and `TB003` as only active automated blockers unless code actually changes elsewhere.
- Label broader patterns as advisory or docs-only clearly.
- Keep clean result wording exactly `No Confirmed Critical issues found.`
- Keep prevention-first tone and avoid full-security claims.
- Keep report and docs language safe for hostile input and safe HTML rendering.

## Safe patch guidance
- Explain risk at consequence level, not execution level.
- Write `exploitPath` in defensive terms about missing boundaries and possible exposure.
- Write patch guidance as prevention steps such as ownership checks, server-only key placement, verification before side effects, allowlists, least privilege, and redaction.
- Prefer clear, founder-friendly language over hype.

## Unsafe content rules
- Do not include offensive instructions, secret-looking samples, request recipes, or real-app misuse guidance.
- Do not imply docs coverage means scanner enforcement.
- Do not change rule IDs, CLI behavior, JSON output, GitHub Action behavior, report clean wording, or scanner scope through copy alone.
- Do not use words that overclaim security such as guaranteed safety.

## Output format
- State exact classification: blocker, advisory, or docs-only.
- Quote or summarize current repo behavior when needed for accuracy.
- Provide final copy in concise, production-ready wording.
- Call out any wording risk or coverage ambiguity before finalizing.

## Done criteria
- Copy is defensive, prevention-first, and free of offensive detail.
- Detection claims match current repo behavior exactly.
- Clean wording remains `No Confirmed Critical issues found.`
- Educational text strengthens understanding without changing enforcement meaning.
