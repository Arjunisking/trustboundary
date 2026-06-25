# TrustBoundary Implementation Boundaries

## Purpose
This document defines implementation-facing matcher boundaries for TrustBoundary V1 automated enforcement.

V1 automated scope is fixed to exactly three blocking rules:
1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

Core V1 rule:
- scan committed repository evidence only
- do not execute scanned project code
- do not import scanned project files
- do not run scanned repo scripts
- block only `Confirmed Critical` findings
- if pattern cannot be proven deterministically, it must not block
- prefer false negatives over false positives

## Normalization rules
Matchers may normalize these dimensions before comparison:
- ASCII case where source format is case-insensitive
- repeated whitespace
- line breaks
- obvious quote variants: `'`, `"`, and template-literal string content

Matchers must not rely on:
- code execution
- AST evaluation of imported files
- env resolution
- runtime routing
- dataflow across files beyond explicit same-file text and local relative import presence

## TB001 Client-Side Secret Exposure

### TB001 live secret prefix catalog
V1 `TB001` must block only when browser-exposed file contains hardcoded raw secret value or public env exposure matching categories below.

Minimum hardcoded secret catalog:
- Supabase `service_role` JWT-like values
  - matcher shape: JWT-like three-part token with provider-specific `service_role` marker in nearby text or decoded-looking payload text
  - minimum text signals: `service_role`, `supabase`, `eyJ`
  - non-blocking if token is clearly placeholder, test-only dummy, or inside ignored path
- Stripe live secret keys
  - matcher shape: `sk_live_` followed by provider token body
  - treat `rk_live_` same way if encountered
  - `sk_test_` must not block in V1
- GitHub tokens
  - matcher shape: known GitHub token prefixes such as `ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
  - must block only when value appears hardcoded in browser-exposed file
- Shopify private or admin tokens if safely detectable
  - safe matcher examples: `shpat_` hardcoded value
  - if value shape is ambiguous, it must not block
- Clerk secret keys if safely detectable
  - safe matcher examples: `sk_live_` or `sk_test_` paired with nearby `clerk` text, or `CLERK_SECRET_KEY` hardcoded raw value in browser-exposed file
  - if matcher cannot distinguish Clerk from unrelated secret text, it must not block as hardcoded Clerk secret

Generic public env exposure catalog:
- public env prefixes limited to `NEXT_PUBLIC_`, `VITE_`, `PUBLIC_`
- must block only when same identifier also contains one of these risk terms:
  - `SERVICE_ROLE`
  - `SECRET`
  - `PRIVATE`
  - `ADMIN`
  - `TOKEN`
  - `API_KEY`
  - `SERVER`
- examples that must block:
  - `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`
  - `VITE_STRIPE_SECRET_KEY`
  - `PUBLIC_ADMIN_TOKEN`
- examples that must not block:
  - `SUPABASE_SERVICE_ROLE_KEY` without public prefix
  - `NEXT_PUBLIC_SUPABASE_URL`
  - `VITE_PUBLIC_CLERK_PUBLISHABLE_KEY`

### TB001 Supabase service_role JWT-like boundary
Supabase `service_role` JWT-like blocker requires all:
- JWT-like token shape: three base64url-style segments separated by `.`
- browser-exposed file
- nearby text proves Supabase `service_role` context through one or more of:
  - `service_role`
  - `SUPABASE_SERVICE_ROLE`
  - `supabase`
  - known Supabase service role examples in same line or nearby lines

Generic JWT text with no Supabase `service_role` proof must not block.

### TB001 browser-exposed file detection
File is browser-exposed for V1 only when committed path or same-file markers place code in client bundle scope.

Must treat as browser-exposed:
- any file containing exact directive `"use client"` or `'use client'`
- Next.js `app/page.*`
- Next.js `app/layout.*`
- Next.js `pages/**/*`
- Next.js `components/**/*` only when same file contains `"use client"` or imports from clearly client-only entrypoint
- Vite frontend files under `src/**/*` with extensions typically shipped to browser: `.js`, `.jsx`, `.ts`, `.tsx`, `.vue`, `.svelte`
- Nuxt `*.vue`
- Nuxt `*.client.*`
- Svelte and SvelteKit `*.svelte`
- SvelteKit client-facing route files or components under frontend source trees
- any file referencing public env prefixes `NEXT_PUBLIC_`, `VITE_`, or `PUBLIC_` inside frontend source tree

Must not treat as browser-exposed by default:
- `pages/api/**/*`
- `app/api/**/*`
- server-only utility files with no client marker
- backend workers, migrations, scripts, config files
- shared utility file with no client marker and no committed frontend placement proof

If client exposure cannot be proven from committed path plus same-file markers, it must not block.

### TB001 default ignored paths
Default ignored paths for `TB001` include:
- `docs/`
- `README*`
- `examples/`
- `fixtures/`
- any path containing `tests`
- `*.test.*`
- `*.spec.*`
- `cypress/`
- `playwright/`

Recommended broader ignore equivalents allowed:
- `docs/**`
- `examples/**`
- `fixtures/**`
- `**/tests/**`
- `**/__tests__/**`
- `**/*.test.*`
- `**/*.spec.*`
- `cypress/**`
- `playwright/**`

Ignored paths must be configurable or bypassable for TrustBoundary's own tests so insecure fixtures can still be scanned intentionally.

### TB001 non-blocking boundaries
`TB001` must not block on:
- `process.env.SUPABASE_SERVICE_ROLE_KEY` in client file when no public env exposure and no hardcoded raw secret value exists
- placeholder strings such as `your_secret_here`, `example_token`, `sk_live_xxx` if clearly fixture-like and inside ignored path
- docs, README, examples, fixtures, or tests under default ignore configuration
- generic JWT text with no provider-specific proof
- generic env names without public prefix

## TB002 Destructive Public RLS / DB Rules

### TB002 scan targets
V1 `TB002` applies only to committed database policy text files, including typical SQL and provider rule files such as:
- `supabase/**/*.sql`
- `supabase/migrations/**/*.sql`
- `database/**/*.sql`
- `db/**/*.sql`
- `policies/**/*.sql`
- `firebase.rules`
- `firestore.rules`
- `storage.rules`

Outside committed policy text, `TB002` must not block.

### TB002 exact Supabase or Postgres block patterns
V1 SQL matcher is intentionally narrow.

Must block only when all are proven in same policy statement:
- action is `FOR UPDATE`, `FOR DELETE`, or `FOR ALL`
- audience is `TO public` or `TO anon`
- guard is unsafe by one of these exact conditions:
  - `USING (true)`
  - `USING true`
  - `WITH CHECK (true)`
  - `WITH CHECK true`
  - required guard clause is absent
- statement contains no `auth.uid()`, ownership check, JWT claim check, `current_setting`, `request.auth`, custom function, or other complex SQL evidence

Statement forms that must block:
- `FOR UPDATE TO public USING (true)`
- `FOR UPDATE TO anon USING true WITH CHECK true`
- `FOR DELETE TO public USING (true)`
- `FOR ALL TO anon USING (true)`
- `FOR ALL TO public` with missing `USING`

Missing guard rules for V1:
- `FOR UPDATE`: missing `USING` or missing `WITH CHECK` must block
- `FOR DELETE`: missing `USING` must block
- `FOR ALL`: missing `USING` or missing `WITH CHECK` must block

If parser cannot reliably isolate one policy statement, it must not block.

### TB002 exact Firebase block patterns
Must block only these literal-true public write cases:
- `allow write: if true`
- `allow update: if true`
- `allow delete: if true`

Normalization allowed:
- ignore whitespace and line breaks around `allow`, action list, `if`, and `true`
- case-sensitive provider syntax should otherwise remain literal

Must also block comma-separated forms when target action contains destructive write and condition is literal true, for example:
- `allow read, write: if true`
- `allow get, list, update: if true`
- `allow update, delete: if true`

Must not block:
- `allow create: if true`
- public insert-equivalent create-only rules
- any rule using `request.auth`
- any rule using helper function call or variable reference instead of literal `true`

### TB002 explicit non-blocking SQL boundaries
`TB002` must not block when policy text contains safety logic not literally disproven, including:
- `auth.uid()`
- `request.auth`
- ownership checks such as `user_id = auth.uid()` or `owner_id = auth.uid()`
- JWT claim checks
- `current_setting`
- custom functions
- joins, subqueries, `exists`, `in`, `coalesce`, `case`, or other complex SQL
- any non-literal boolean expression not equal to plain `true`
- public `INSERT`
- mixed statements such as `FOR UPDATE TO public USING (auth.uid() = user_id) WITH CHECK true`
- mixed statements such as `FOR UPDATE TO anon USING true WITH CHECK (owner_id = auth.uid())`

If statement is complex or safety cannot be proven absent, it must not block.

## TB003 Unsigned Known Provider Webhook

### TB003 provider scope
V1 provider route detection is limited to:
- Stripe
- Clerk
- Shopify
- GitHub

Other providers must not block in V1.

### TB003 known provider webhook route detection
Known provider webhook route requires same-file route evidence with both webhook marker and provider marker.

Accepted webhook markers:
- path segment `webhook`
- path segment `webhooks`

Accepted provider markers:
- `stripe`
- `clerk`
- `shopify`
- `github`

Route evidence may come from either:
- committed file path
- same-file literal route string

Examples that count as known provider webhook route:
- `app/api/webhooks/stripe/route.ts`
- `pages/api/webhooks/stripe.ts`
- `src/routes/api/webhooks/github/+server.ts`
- `server/api/webhook/clerk.ts`
- same-file literal `"/api/webhooks/shopify"`

Must not count as known provider webhook route:
- file path with provider name but no webhook marker
- file path with webhook marker but no supported provider name
- generic `webhook.ts` with no provider proof
- unsupported provider routes

### TB003 payload read markers
Payload read is proven only by same-file markers such as:
- `await request.json()`
- `request.json()`
- `await req.json()`
- `await request.text()`
- `request.text()`
- `await req.text()`
- `req.body`
- `request.body`
- `formData()`
- `rawBody`
- buffer helper calls for raw request body

If payload read is not proven in same file, it must not block.

### TB003 same-file signature verification markers
Same-file verification marker means same file contains provider-specific verification evidence strong enough to suppress automated block.

Markers that count for Stripe:
- `constructEvent(`
- `webhooks.constructEvent(`
- `stripe.webhooks.constructEvent(`
- same-file use of `stripe-signature` together with crypto verification call such as `createHmac(`, `timingSafeEqual(`, or explicit verify helper call

Markers that count for Clerk:
- `verifyWebhook(`
- `Webhook(` from `svix` together with `.verify(`
- same-file use of `svix-id`, `svix-timestamp`, or `svix-signature` together with verification call

Markers that count for Shopify:
- `authenticate.webhook(`
- `validateHmac(`
- `shopify.webhooks.validate(`
- same-file use of `x-shopify-hmac-sha256` together with crypto verification call

Markers that count for GitHub:
- same-file use of `x-hub-signature-256` together with `createHmac(` and `timingSafeEqual(`
- same-file helper name containing `verify` plus `signature` or `hmac` applied to GitHub webhook headers

Unknown custom verification pattern must not be treated as missing verification if file shows plausible verification intent that matcher cannot disprove.

### TB003 local helper import markers
Local verification helper import suppresses automated block when same file imports from relative path and imported name or path text strongly indicates webhook verification.

Relative import means path starts with:
- `./`
- `../`

Local helper import markers include imported binding or import path containing one or more of:
- `verifyWebhook`
- `verifySignature`
- `validateSignature`
- `validateHmac`
- `constructEvent`
- `webhook`
- `signature`
- `hmac`
- `svix`
- `stripe`
- `shopify`
- `github`
- `clerk`

Examples that suppress block:
- `import { verifyWebhook } from "../lib/webhook"`
- `import { validateHmac } from "./shopify-webhook"`
- `import { constructStripeEvent } from "../security/stripe-signature"`
- `const { verifySignature } = require("./githubWebhookAuth")`

Non-local package imports do not count as local helper import for this boundary. They may still count as same-file verification markers if verification call appears in same file.

### TB003 dangerous sink markers
Dangerous sink must exist in same file after or near payload handling. V1 sink matcher is text-based and narrow.

Database write markers:
- `.insert(`
- `.update(`
- `.upsert(`
- `.delete(`
- `.create(`
- `.createMany(`
- `.save(`
- `.set(` when used on DB-like object

External fetch or axios markers:
- `fetch(` with absolute `http://` or `https://` URL literal
- `axios(` with absolute URL literal
- `axios.get(` with absolute URL literal
- `axios.post(` with absolute URL literal
- `axios.put(` with absolute URL literal
- `axios.patch(` with absolute URL literal
- `axios.delete(` with absolute URL literal

Queue or job dispatch markers:
- identifier containing `queue`, `job`, `task`, `worker`, or `workflow` with call such as `.add(`, `.enqueue(`, `.dispatch(`, `.publish(`, `.trigger(`, `.schedule(`, `.send(`

Payment, account, user, or role mutation markers:
- identifier or string path containing `payment`, `subscription`, `account`, `user`, `member`, `customer`, `role`, or `billing` paired with mutating call such as `.create(`, `.update(`, `.delete(`, `.cancel(`, `.refund(`, `.grant(`, `.revoke(`

Must not count as dangerous sink:
- `console.log`
- `console.info`
- `console.error`
- plain response serialization
- signature header reads alone
- payload parse alone

### TB003 non-blocking boundaries
`TB003` must not block when any of these apply:
- only console logging exists
- route is health check webhook with no dangerous sink
- local verification helper import exists
- same-file provider verification marker exists
- verification pattern is custom or unclear and matcher cannot disprove it
- provider unsupported in V1
- payload never read
- route proof incomplete
- sink proof incomplete

To block `TB003`, all must be true:
- known provider webhook route
- payload read
- dangerous sink exists
- no same-file verification marker
- no local verification helper import

If any one element is missing or uncertain, it must not block.

## Required V1 Test Fixtures

### TB001 must-block fixtures
- Next.js `app/page.tsx` with hardcoded `sk_live_...`
- Next.js client component containing `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`
- Vite `src/main.ts` with hardcoded GitHub token prefix in client code
- Nuxt `.client.ts` or `.vue` file with Supabase `service_role` JWT-like value
- Svelte `.svelte` file with hardcoded `shpat_...` token

### TB001 must-pass fixtures
- `process.env.SUPABASE_SERVICE_ROLE_KEY` inside client file with no public prefix exposure
- server-only file with `SUPABASE_SERVICE_ROLE_KEY`
- `docs/README.md` containing live-looking secret sample
- `examples/` or `fixtures/` file containing live-looking secret under default ignore config
- `NEXT_PUBLIC_SUPABASE_URL`
- generic JWT in client file with no Supabase `service_role` proof

### TB002 must-block fixtures
- SQL policy `FOR UPDATE TO public USING (true)`
- SQL policy `FOR DELETE TO anon USING true`
- SQL policy `FOR ALL TO public` with missing `USING`
- Firebase rule `allow write: if true`
- Firebase rule `allow update, delete: if true`

### TB002 must-pass fixtures
- SQL public `INSERT`
- SQL `FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)`
- SQL `FOR UPDATE TO public USING (auth.uid() = user_id) WITH CHECK true`
- SQL `FOR UPDATE TO anon USING true WITH CHECK (owner_id = auth.uid())`
- SQL `FOR DELETE TO public USING (is_admin())`
- SQL policy using `current_setting`
- SQL policy using JWT claims or custom function
- Firebase `allow create: if true`
- Firebase `allow write: if request.auth != null`

### TB003 must-block fixtures
- `app/api/webhooks/stripe/route.ts` reads payload, writes DB, no verification markers, no local helper import
- `pages/api/webhooks/github.ts` reads payload, calls `fetch("https://...")`, no verification markers, no local helper import
- `server/api/webhook/clerk.ts` reads payload, triggers queue dispatch, no verification markers, no local helper import
- `src/routes/api/webhooks/shopify/+server.ts` reads payload, mutates account or billing state, no verification markers, no local helper import

### TB003 must-pass fixtures
- Stripe webhook route with `constructEvent(` in same file
- Clerk webhook route with `verifyWebhook(` in same file
- Shopify webhook route importing local `validateHmac` helper from `../lib/webhook`
- GitHub webhook route using `x-hub-signature-256` plus `createHmac(` and `timingSafeEqual(`
- webhook route with only `console.log`
- health check webhook route with no dangerous sink
- unsupported provider webhook route
- route with custom verification pattern that matcher cannot disprove

## Report reminder
When no blocking findings remain, report language stays:
- `No Confirmed Critical issues found.`

This document defines blocker boundaries only. It does not broaden V1 scope.
