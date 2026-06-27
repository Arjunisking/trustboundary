# TrustBoundary MVP Rules

This file is retained as a compatibility entry point.

Current released V1.1.0 automated rule source of truth:
- `docs/rules.md`

Current V1.1.0 active automated scope:
- exactly three automated blocking rules
- no automated advisory rules
- blocker evidence limited to deterministic committed repository evidence

V1 automated rules:
1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

Documentation-only, non-automated V1 areas:
- Unsafe Raw Mutation
- Sensitive Route Without Auth
- Public INSERT Advisory
- Dangerous AI-Agent Tool detection

These are manual-review or roadmap topics only. They are not active scanner enforcement.