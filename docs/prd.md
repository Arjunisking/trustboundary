# TrustBoundary PRD

## Summary
TrustBoundary is a pre-deploy security gatekeeper for AI-generated web apps. It scans repository evidence and blocks confirmed critical security mistakes before production deployment.

## Problem
Vibe coders and AI-assisted builders ship fast, but AI-generated code often creates dangerous security mistakes across client-side secret exposure, destructive database rules, and unsigned webhooks.

## Target users
- Vibe coders
- AI automation agencies
- Solo founders
- Local business automation builders
- Developers using Bolt, Cursor, GitHub, Supabase, Firebase, n8n, and Next.js

## Goals
- Detect exactly 3 deterministic critical AI-generated security patterns in V1.
- Generate clear exploit paths.
- Produce patch suggestions.
- Generate a static HTML audit report.
- Block Confirmed Critical issues in GitHub Actions.

## Non-goals for V1
- No dashboard.
- No IDE extension.
- No remote signed rule feed.
- No provider connectors.
- No automated advisory rules.
- No full security guarantee.
- No automatic patch commits.

## V1 findings
1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

Unsafe Raw Mutation, Sensitive Route Without Auth, Public INSERT Advisory, and Dangerous AI-Agent Tool detection are documentation-only in V1. They are not automated scanner findings.

## Success criteria
- Scanner detects exposed Supabase service role key in client-side Next.js code.
- Scanner blocks only Confirmed Critical issues from the 3-rule V1 set.
- CLI outputs JSON results.
- CLI generates static HTML report.
- GitHub Action can fail on Confirmed Critical findings.
- Report never claims full security.

## First vertical slice
Input:
An insecure Next.js example repo.

Detection:
Supabase service role key exposed in client code.

Output:
- CLI finding
- JSON result
- HTML report
- Patch placeholder
