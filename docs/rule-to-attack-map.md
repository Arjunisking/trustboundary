# TrustBoundary Rule To Attack Pattern Map

## Purpose
This document maps current TrustBoundary automated rules to broader defensive attack-pattern education. It exists to explain coverage boundaries, not to expand enforcement.

TrustBoundary current automated blocker scope remains exactly:

- `TB001` Client-Side Secret Exposure
- `TB002` Destructive Public RLS / DB Rules
- `TB003` Unsigned Known Provider Webhook

## Current automated rule coverage
TrustBoundary blocks only `Confirmed Critical` findings backed by deterministic committed repository evidence. There are no automated advisory rules in current scope.

Current blocker coverage:

- `TB001`: client-side secret exposure, including Supabase service role exposure in browser-delivered code
- `TB002`: destructive public Supabase/Postgres/Firebase rules with missing or ineffective guards
- `TB003`: unsigned known-provider webhooks with payload read, dangerous sink, and missing deterministic verification evidence

## Blocker mapping table

| Rule ID | Current automated coverage | Attack pattern | Status | Notes |
| --- | --- | --- | --- | --- |
| `TB001` | Client-side secret exposure | Supabase service role exposure | Blocker | Blocks only when browser exposure is proven from committed evidence |
| `TB002` | Destructive public Supabase/Postgres/Firebase rules | Supabase/Firebase RLS failures | Blocker | Blocks only narrow destructive public rule failures |
| `TB003` | Unsigned known-provider webhooks | Unsigned webhooks | Blocker | Blocks only supported providers with same-file proof of payload read, dangerous sink, and missing verification evidence |

## Advisory candidate mapping table

| Pattern | Current TrustBoundary area | Current coverage | Future educational surfacing |
| --- | --- | --- | --- |
| URL/object ID tampering | Manual review | No active automated detection | Non-blocking route and ownership-scope explanation where repo evidence is strong |
| Broken authorization | Manual review | No active automated detection | Non-blocking explanation for sensitive routes missing visible auth or ownership checks |
| Admin route abuse | Manual review | No active automated detection | Non-blocking explanation for privileged routes with missing visible role checks |
| Unsafe mutation | `docs/security-master-checklist.md` | No active automated detection | Non-blocking explanation for raw request data flowing into writes |
| Mass assignment | Manual review | No active automated detection | Non-blocking explanation for broad object writes into privileged models |
| Public storage bucket risk | Future advisory | No active automated detection | Non-blocking explanation for broad storage exposure patterns |
| Webhook replay risk | Future advisory | No active automated detection | Non-blocking explanation for missing freshness or idempotency signals |
| Prompt injection | Dangerous AI-Agent Tool detection | No active automated detection | Non-blocking explanation for prompt-to-tool trust boundary issues |
| Excessive AI-agent permissions | Dangerous AI-Agent Tool detection | No active automated detection | Non-blocking explanation for least-privilege failures in agent tooling |
| Sensitive data in AI context | Dangerous AI-Agent Tool detection | No active automated detection | Non-blocking explanation for sensitive context forwarding into AI systems |
| Secrets in logs/errors | Future advisory | No active automated detection | Non-blocking explanation for explicit redaction failures visible in code |

## Docs-only mapping table

| Pattern | Current coverage | Why docs-only now |
| --- | --- | --- |
| SQL/raw query injection risk | No active automated detection | Too broad across frameworks and query APIs for current deterministic blocker model |
| XSS | No active automated detection | Context-specific output handling too broad for current deterministic scope |
| CSRF | No active automated detection | Runtime auth and browser behavior too deployment-dependent |
| Open redirect | No active automated detection | Redirect safety depends on normalization and flow context |
| Path traversal | No active automated detection | Filesystem and path handling context too broad |
| SSRF | No active automated detection | Network topology and destination controls are runtime-dependent |
| CORS misconfiguration | No active automated detection | Deployment headers and browser behavior not safely inferable from repo text alone |
| Missing rate limits | No active automated detection | Proper limits depend on traffic, retries, and infrastructure controls |
| Insecure file upload | No active automated detection | Storage, scanning, serving, and processing flow too broad for current deterministic blocking |

## Current vs future coverage

| Coverage level | Current behavior | Future direction |
| --- | --- | --- |
| Blocker | Active for `TB001`, `TB002`, `TB003` only | Stays narrow unless deterministic evidence standard remains credible |
| Advisory | Not active in automated scanner | May later appear as non-blocking educational context where repo evidence is strong |
| Docs-only | Educational docs only | Remains documentation unless deterministic, low-noise evidence model becomes credible |

Important rule:

- adding education must not change enforcement behavior

## Fixture evidence map
Repo already contains fixture evidence useful for educational mapping.

| Example file | Relevant pattern | Current automated coverage |
| --- | --- | --- |
| `examples/insecure-next-supabase/app/admin/page.tsx` | Supabase service role exposure | Active blocker via `TB001` |
| `examples/insecure-next-supabase/app/api/webhooks/stripe/route.ts` | Unsigned webhooks | Active blocker via `TB003` |
| `examples/insecure-next-supabase/firestore.rules` | Supabase/Firebase destructive public rule failure | Active blocker via `TB002` |
| `examples/insecure-next-supabase/app/api/orders/route.ts` | Unsafe mutation | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/profiles/route.ts` | Unsafe mutation | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/users/route.ts` | Mass assignment / unsafe mutation | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/reports/route.ts` | Broken authorization risk | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/billing/route.ts` | Broken authorization data-scope risk | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/webhook/orders/route.ts` | Broad webhook abuse pattern | Manual review / future advisory |
| `examples/insecure-next-supabase/app/api/safe-allowlist/route.ts` | Safer field allowlist example | Not blocker; contrast example |
| `examples/insecure-next-supabase/app/api/safe-validated/route.ts` | Safer validation example | Not blocker; contrast example |
| `examples/insecure-next-supabase/app/api/session-safe/route.ts` | Safer auth scoping example | Not blocker; contrast example |
| `examples/insecure-next-supabase/app/api/supabase-safe/route.ts` | Safer ownership scoping example | Not blocker; contrast example |
| `examples/insecure-next-supabase/lib/server/supabase-admin.ts` | Valid server-only secret usage contrast | Not blocker; contrast example |
| `examples/insecure-next-supabase/supabase/policies/profile_owner_only.sql` | Safer ownership policy contrast | Not blocker; contrast example |

## Intentional non-coverage
TrustBoundary does not currently automate:

- broad authorization scanning
- unsafe mutation scanning
- mass assignment scanning
- generic webhook abuse scanning
- webhook replay scanning
- prompt injection scanning
- AI-agent permission scanning
- sensitive AI context scanning
- SQL injection scanning
- XSS scanning
- CSRF scanning
- open redirect scanning
- path traversal scanning
- SSRF scanning
- CORS scanning
- rate-limit scanning
- insecure upload scanning
- secrets in logs or errors scanning

These topics may still matter. They are excluded because current blocker model prefers false negatives over false positives when deterministic proof is weak.

## Why TrustBoundary does not block every security smell
TrustBoundary is optimized for credibility in CI. Many real security problems depend on:

- runtime auth behavior
- provider configuration
- middleware and wrapper logic
- database ownership semantics
- deployment headers and network environment
- operational controls such as rate limits, replay storage, and log redaction

If committed evidence cannot prove issue deterministically, TrustBoundary should not block it.

This design keeps:

- blocker behavior explainable
- enforcement noise low
- CI trust high

## Enforcement reminder
Educational docs, later report context, and later website content must not:

- invent active rules that do not exist
- imply advisory coverage is active scanner enforcement
- change blocker threshold
- change rule IDs
- change CLI behavior
- change JSON output
- change GitHub Action behavior

TrustBoundary still means:

- committed repository evidence only
- block only `Confirmed Critical` findings by default
- no full security guarantee
- clean result wording stays `No Confirmed Critical issues found.`
