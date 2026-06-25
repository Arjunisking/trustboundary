# TrustBoundary Enforcement Model

## V1 scope
TrustBoundary V1 automated scanner has exactly three blocking rules:

1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

There is no automated advisory rule in V1.

Rules such as Unsafe Raw Mutation, Sensitive Route Without Auth, Public INSERT Advisory, and Dangerous AI-Agent Tool detection are documentation-only in V1. They belong in `docs/security-master-checklist.md` and `docs/scanner-roadmap.md`, not automated scanner enforcement.

## Core enforcement contract
TrustBoundary scans committed repository evidence only.

It must not:
- execute scanned project code
- import scanned project files
- run scanned repo scripts

TrustBoundary blocks only `Confirmed Critical` issues.

TrustBoundary must never say an app is secure. When no blocker is found, correct wording is:

`No Confirmed Critical issues found.`

## Blocker threshold
A blocking finding requires deterministic committed evidence that directly meets one of the three V1 rule definitions.

If evidence is incomplete, ambiguous, or depends on runtime behavior not proven from committed files, TrustBoundary must not block.

## Suppression
V1 supports inline suppression only:

`trustboundary-ignore: TB001 - Reason longer than 10 characters`

Suppressed critical findings:
- still appear in report as suppressed
- do not fail CI

## Default ignored content
By default, documentation, tests, fixtures, and examples are ignored for automated rule evaluation.

Default ignore behavior must be configurable and bypassable in tests so TrustBoundary can scan its own insecure fixtures.
