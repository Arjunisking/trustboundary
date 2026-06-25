# TrustBoundary Rules

## V1 automated rules
TrustBoundary V1 has exactly three automated blocking rules:

1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

There are no automated advisory rules in V1.

## Default ignored paths
Automated scanning ignores low-signal reference content by default, including:
- `docs/**`
- `README*`
- `**/*.md`
- `**/__tests__/**`
- `**/*.test.*`
- `**/*.spec.*`
- `fixtures/**`
- `test/**`
- `tests/**`
- `examples/**`

This ignore set must be configurable and bypassable in tests so TrustBoundary can scan its own insecure fixtures.

## TB001 Client-Side Secret Exposure
Block only when committed browser-exposed code contains at least one of these:
- hardcoded raw secret values
- public env names exposing service, private, or server keys, such as `NEXT_PUBLIC_*`, `PUBLIC_*`, or `VITE_*` combined with `SERVICE_ROLE`, `SECRET`, `PRIVATE`, `ADMIN`, `TOKEN`, or `API_KEY`
- Supabase `service_role` JWT-like values
- known live secret prefixes

Do not block:
- `process.env.SUPABASE_SERVICE_ROLE_KEY` in client code unless committed evidence also shows public env exposure or hardcoded secret value
- docs, README files, tests, fixtures, or examples by default

If browser exposure cannot be proven from committed evidence, do not block.

## TB002 Destructive Public RLS / DB Rules
Block only when committed Supabase, Postgres, or Firebase rule text shows both:
- destructive public access: `UPDATE`, `DELETE`, or `ALL` granted to `public` or `anon`
- ineffective guard: `USING` or `WITH CHECK` is absent or literally `true`

Firebase equivalent blocker:
- `allow write: if true`
- `allow update: if true`
- `allow delete: if true`

Do not block:
- public `INSERT`
- policies using `auth.uid()`, `request.auth`, custom functions, ownership checks, JWT claims, `current_setting`, or other non-trivial SQL logic
- complex policies where safety cannot be proven deterministically

If unsure, do not block.

## TB003 Unsigned Known Provider Webhook
V1 providers only:
- Stripe
- Clerk
- Shopify
- GitHub

Block only when all of these are true in committed evidence:
- known provider webhook route is detected
- payload is read
- dangerous sink exists in same file
- no same-file provider signature verification exists
- no local crypto, auth, or webhook verification helper is imported

Dangerous sinks:
- database writes
- payment or external API calls
- queue or job trigger
- role, user, or account mutation

Do not block:
- logging only
- health-check webhook route
- local verification helper imports
- custom verification patterns that cannot be disproven from same-file evidence

If verification absence cannot be proven, do not block.

## Suppression
Inline suppression syntax:

`trustboundary-ignore: TB001 - Reason longer than 10 characters`

Suppressed critical findings still appear in reports as suppressed and do not fail CI.
