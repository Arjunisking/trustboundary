---
name: trustboundary-logs-errors-hardener
description: Review and fix secrets in logs, sensitive data in error responses, unsafe debug output, raw request logging, stack-trace exposure, and missing redaction in app code, examples, docs, and reports. Use when Codex needs to harden production logging and error boundaries without overstating TrustBoundary current enforcement.
---

# TrustBoundary Logs Errors Hardener

## Trigger conditions
- Review production logs, debug output, or error responses.
- Remove secrets, tokens, credentials, or sensitive user data from logs.
- Reduce stack-trace exposure in user-facing responses.
- Add redaction for request bodies, headers, and internal errors.
- Tighten docs or examples that demonstrate logging and error handling.

## Read-first checklist
- Read `AGENTS.md`.
- Read `README.md`, `docs/report-language.md`, `docs/false-positive-policy.md`, and `docs/non-goals.md`.
- Read `docs/security-learning-model.md`, `docs/attack-patterns.md`, and `docs/rule-to-attack-map.md`.
- Inspect relevant logging helpers, route handlers, report generation code, and examples.

## Review checklist
- Check whether logs include secrets, auth material, or full request bodies.
- Check whether user-facing errors expose stack traces or internal implementation details.
- Check whether report text or docs accidentally expose sensitive values.
- Check whether redaction happens before logs leave process boundary.
- Keep these patterns classified as advisory unless another active blocker surface is involved.

## Safe patch guidance
- Redact secrets and sensitive fields before logging.
- Keep user-facing errors short and non-sensitive.
- Send only necessary sanitized detail to internal monitoring.
- Remove debug output that reveals private implementation or user data.
- Preserve report HTML escaping and defensive wording.

## Unsafe content rules
- Do not show secret-like examples in logs.
- Do not include guidance for harvesting sensitive debug output.
- Do not imply logs or error issues are active blocker coverage unless repo behavior proves it elsewhere.
- Do not change scanner enforcement, rule IDs, CLI behavior, JSON output, GitHub Action behavior, or clean report wording.

## Output format
- Label issue as advisory or docs-only unless another active blocker surface is directly involved.
- Name exact log or error boundary problem.
- Describe redaction or safe-error fix in prevention-first language.
- Call out remaining observability uncertainty when sink behavior is external.

## Done criteria
- Sensitive values are removed or redacted before logs and errors leave trusted boundary.
- User-facing responses avoid stack traces and internal details.
- Report and doc text remain safe and escaped where required.
- No enforcement drift or offensive language appears.
