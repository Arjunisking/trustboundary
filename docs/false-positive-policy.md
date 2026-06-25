# TrustBoundary False Positive Policy

## Default posture
TrustBoundary prefers misses over false blocker claims when committed evidence is ambiguous.

Rule:

`If unsure, do not block.`

## Deterministic evidence standard
TrustBoundary blocks only `Confirmed Critical` findings backed by committed repository evidence.

TrustBoundary does not:
- infer runtime behavior it cannot prove
- assume missing code means unsafe
- treat advisory concerns as blockers in V1

## Rule-specific boundaries
`TB001` must prove browser exposure plus secret exposure pattern.

`TB002` must prove destructive public rule access plus absent or literally true guard.

`TB003` must prove same-file webhook route, payload read, dangerous sink, and missing verification evidence without being contradicted by same-file checks or local helper imports.

## Ignored reference content
Docs, README files, tests, fixtures, and examples are ignored by default because they are high-noise sources for false blockers.

This ignore behavior must be configurable and bypassable in tests so TrustBoundary can scan its own insecure fixtures.

## Suppression policy
Use inline suppression only:

`trustboundary-ignore: TB001 - Reason longer than 10 characters`

Suppressed critical findings:
- remain visible in report output
- are labeled suppressed
- do not fail CI

## Triage path
When a pattern looks risky but does not meet blocker threshold:
- do not promote it to automated blocker
- capture it in `docs/security-master-checklist.md` if manual review still matters
- consider it for future roadmap work in `docs/scanner-roadmap.md`
