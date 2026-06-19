# TrustBoundary MVP Rules

## Rule 1: Exposed Supabase Service Role Key

Severity:
Critical

Confidence:
Confirmed when a Supabase service role key, service role env reference, or service-role JWT appears in client-side code.

Target evidence:
- `"use client"` files
- frontend directories
- `NEXT_PUBLIC` misuse
- `process.env.SUPABASE_SERVICE_ROLE_KEY`
- service-role JWT patterns

Exploit path:
Anyone can extract the key from the browser bundle and bypass database permissions.

Default enforcement:
Block on main.

## Rule 2: Unsafe Mutation

Severity:
High

Confidence:
Likely when request body data flows directly into database mutation calls without visible validation or allowlisting.

Target evidence:
- `request.json()`
- `req.body`
- direct `insert`, `update`, `upsert`, `create`, `createMany`

Exploit path:
Attackers can mutate records with unexpected fields or bypass intended validation logic.

Default enforcement:
Warn by default.

## Rule 3: Broken Authorization

Severity:
High

Confidence:
- Confirmed when a sensitive API route or server action reaches a DB sink with no visible auth control
- Likely when auth exists but ownership or tenant scoping is missing

Target evidence:
- sensitive Next.js API routes and server actions
- `prisma.*`, `db.*`, SQL calls, Supabase reads/writes
- auth/session helpers
- ownership markers such as `userId`, `ownerId`, `tenantId`

Exploit path:
Attackers can read or mutate data without server-side authorization or user-scoped access control.

Default enforcement:
Warn by default.

## Rule 4: RLS Failure

Severity:
Critical or High

Confidence:
- Confirmed when committed Supabase SQL or Firebase rule text visibly grants broad public read/write access
- Likely when a user-scoped write policy appears broad but ownership intent is unclear

Target evidence:
- `supabase/**/*.sql`
- `supabase/migrations/**/*.sql`
- `database/**/*.sql`
- `db/**/*.sql`
- `policies/**/*.sql`
- `firestore.rules`
- `firebase.rules`
- `storage.rules`

Exploit path:
Attackers can bypass intended row-level protections and read or write data directly through permissive provider rules.

Default enforcement:
Block when confirmed critical broad access is visible.

## Rule 5: Webhook and AI-Agent Abuse

Severity:
Critical or High

Confidence:
- Confirmed when a webhook route processes payloads and reaches sensitive sinks without visible signature verification
- Likely when signature material is read but verification is not visibly completed

Target evidence:
- inbound webhook route paths
- request body reads
- signature header reads
- provider verification helpers
- sensitive sinks such as DB writes or external side effects

Exploit path:
Attackers can forge webhook requests and trigger sensitive side effects without provider verification.

Default enforcement:
Block when confirmed critical missing verification is visible.
