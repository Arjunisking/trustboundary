# TrustBoundary MVP Rules

## Rule 1: Exposed Supabase Service Role Key

Severity:
Critical

Confidence:
Confirmed when a Supabase service role key or service role env reference appears in client-side code.

Target evidence:
- "use client" files
- frontend directories
- NEXT_PUBLIC misuse
- process.env.SUPABASE_SERVICE_ROLE_KEY
- service_role JWT patterns

Exploit path:
Anyone can extract the key from the browser bundle and bypass database permissions.

Default enforcement:
Block on main.

## Rule 2: Unsafe Mutation

Detect request body passed directly into database create, update, or upsert calls without validation.

## Rule 3: Broken Authorization

Detect sensitive API routes without server-side session, role, or ownership checks.

## Rule 4: RLS Failure

Detect Supabase/Firebase rules that allow broad public read/write access.

## Rule 5: Webhook and AI-Agent Abuse

Detect webhook routes without signature verification and agent tools with dangerous actions but no approval gate.
