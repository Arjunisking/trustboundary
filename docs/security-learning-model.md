# TrustBoundary Security Learning Model

## Purpose
TrustBoundary is a deterministic pre-deploy scanner with intentionally narrow automated enforcement. This learning model adds defensive education around common security mistakes without changing scanner behavior, rule IDs, CLI behavior, JSON output, GitHub Action behavior, or report UI.

The goal is to help builders understand why risky patterns matter, what mistakes commonly create them, and how to patch them safely. The goal is not to teach offensive execution.

## Why TrustBoundary includes defensive education
AI-generated apps often combine fast shipping with incomplete security reasoning. Builders need two things at same time:

- narrow automated blockers they can trust in CI
- broader defensive guidance for risky patterns that are real but not yet deterministic enough for blocking

This model keeps those two jobs separate. Education improves understanding. Enforcement stays narrow.

## Scanner boundary rules
TrustBoundary scanner boundaries do not change because educational docs exist.

- TrustBoundary scans committed repository evidence only.
- TrustBoundary does not execute scanned project code.
- TrustBoundary does not import scanned project files.
- TrustBoundary does not run scripts inside scanned repositories.
- TrustBoundary blocks only `Confirmed Critical` findings by default.
- TrustBoundary V1 active automated blocker scope remains:
  - `TB001` Client-Side Secret Exposure
  - `TB002` Destructive Public RLS / DB Rules
  - `TB003` Unsigned Known Provider Webhook
- TrustBoundary must not claim an app is secure.
- Clean result wording remains:

`No Confirmed Critical issues found.`

## Pattern status model
Every educational pattern must be labeled with one of these statuses.

### Blocker
Pattern has active automated detection in current scope and can contribute to current blocking behavior when deterministic committed evidence proves issue.

Current blocker patterns:

- `TB001` client-side secret exposure, including Supabase service role exposure in browser-delivered code
- `TB002` destructive public Supabase/Postgres/Firebase rule failures
- `TB003` unsigned known-provider webhooks

### Advisory
Pattern is important and may later support non-blocking educational surfacing when committed repository evidence is strong enough, but it is not active automated enforcement now.

Advisory status means:

- no current CI blocking behavior
- no new rule ID implied
- no guarantee that repo evidence is sufficient today

### Docs-only
Pattern stays educational only because it is too runtime-dependent, too context-dependent, too broad, or too easy to overstate from deterministic repo evidence alone.

Docs-only status means:

- no current automated detection
- no implied near-term rule commitment
- explanation should focus on prevention and safe architecture choices

## Education does not mean enforcement
Educational coverage must never be described as if it expands automated rule coverage.

Required rule:

- If docs explain a pattern, that does not mean TrustBoundary detects or blocks it.

Required phrasing style:

- say what TrustBoundary can detect now
- say what TrustBoundary may explain later as advisory
- say what remains docs-only

Forbidden implication:

- implying a pattern is enforced because it appears in docs, examples, website copy, or later report education

## Safe wording rules
Use prevention-first language. Describe risk, cause, and safe remediation without teaching offensive execution.

Allowed style:

- explain impact in general terms
- describe missing ownership checks, auth gates, validation, verification, or least-privilege boundaries
- focus on reducing exposure, not exploiting it

Allowed examples:

- `A user-controlled object ID may expose another user's data if ownership is not checked.`
- `Move privileged keys to server-only code.`
- `Verify webhook signatures before side effects.`
- `Use explicit field allowlists before database writes.`

## Disallowed wording rules
Do not include any of the following in educational content:

- exploit payloads
- curl commands
- bypass strings
- step-by-step exploitation
- instructions for attacking real apps
- `how to hack` framing
- wording that teaches offensive execution

## How to write `exploitPath` safely
`exploitPath` should explain defensive consequence, not operational attack steps.

Safe `exploitPath` rules:

- describe what may happen if control is missing
- stay at consequence level
- avoid exact payload shapes, exact request construction, or exact attack sequencing
- focus on user-controlled input, missing trust boundary, and resulting exposure

Safe examples:

- `Anyone can extract the secret from browser-delivered code and use privileged access outside intended server-side controls.`
- `An unauthenticated user can modify or delete data because the committed policy text grants destructive public access with a missing or ineffective guard.`
- `A user-controlled identifier may expose another account's data when server-side ownership checks are missing.`

Unsafe examples:

- exact request bodies
- exact header sets
- exact parameter tampering examples
- exact replay sequences

## How to write patch suggestions safely
Patch suggestions should tell builders what boundary to add, tighten, or move without teaching offense.

Safe patch guidance rules:

- use direct prevention language
- name guardrail categories such as auth, ownership, verification, allowlists, validation, redaction, and least privilege
- avoid payload-driven troubleshooting
- avoid test attack instructions

Safe examples:

- `Move the secret to server-only code or a secret manager.`
- `Restrict destructive public access with explicit auth, ownership, tenant, or provider checks.`
- `Verify the provider signature before mutating data, calling external APIs, or dispatching jobs.`
- `Use explicit field allowlists before insert, update, or upsert paths.`

Unsafe examples:

- instructions to replay real provider requests
- exact steps to bypass auth wrappers
- request construction instructions for proving exploitability

## Safe vs unsafe explanation examples

### Safe
`A user-controlled object ID may expose another user's data if ownership is not checked. Add server-side scoping so requests can only access records owned by current authenticated subject.`

Why safe:

- explains risk in general terms
- names missing control
- gives prevention-focused patch guidance

### Unsafe
`Change account ID in request URL to another value, resend request, and check if another user's record appears.`

Why unsafe:

- gives operational exploitation steps
- teaches execution sequence

### Safe
`Unsigned webhook routes can trigger side effects from untrusted inputs when signature verification is missing. Verify provider signatures before writes, external calls, or queue dispatch.`

### Unsafe
`Send webhook request without signature header and trigger route manually to confirm mutation.`

## How this model connects to future report UI
Later report UI may add educational context under findings, but that future work must remain non-enforcement content.

Future report UI rules:

- educational context appears under or beside existing finding content
- current summary wording and blocker logic remain unchanged
- educational text must be clearly labeled as context, not additional enforcement
- report content must keep existing HTML escaping rules
- clean report language stays `No Confirmed Critical issues found.`

Likely future report sections:

- why this pattern matters
- common developer mistake
- safe patch guidance
- educational context only

## How this model connects to future website content
Later website content may reuse this model to explain:

- what TrustBoundary blocks today
- what TrustBoundary may explain later as advisory
- what remains docs-only
- why clean scan does not equal full security

Website content must remain consistent with scanner boundaries and must not market educational coverage as full protection.

## Full security guarantee reminder
TrustBoundary does not provide a full security guarantee.

Educational documentation, future advisory explanations, and later report or website content do not change this rule. A clean TrustBoundary result means only:

`No Confirmed Critical issues found.`
