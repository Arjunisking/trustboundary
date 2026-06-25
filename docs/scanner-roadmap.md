# TrustBoundary Scanner Roadmap

## V1 locked scope
TrustBoundary V1 automated scanner is intentionally narrow.

Exactly three automated blocking rules:
1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

There are no automated advisory rules in V1.

## Why scope is narrow
V1 only blocks issues that can be proven from deterministic committed evidence without executing scanned code.

This keeps:
- false blockers low
- rule behavior explainable
- CI enforcement credible

## Post-V1 candidates
These items are roadmap candidates, not V1 automated enforcement:
- Unsafe Raw Mutation
- Sensitive Route Without Auth
- Public INSERT Advisory
- Dangerous AI-Agent Tool detection

Before automation, each candidate needs:
- tighter deterministic evidence thresholds
- clear false-positive boundaries
- fixture coverage for safe and unsafe variants
- report language that avoids overstating certainty

## Future expansion principles
Future rules should keep same constraints:
- committed repo evidence only
- no execution or imports of scanned project code
- no script running inside scanned repos
- blocker status only when evidence is deterministic

Warn-only or advisory automation can be reconsidered after V1, but it is out of scope for current release.
