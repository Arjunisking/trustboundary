# TrustBoundary PRD

## Summary
TrustBoundary is a pre-deploy security gatekeeper for AI-generated web apps. It scans repository evidence and blocks confirmed critical security mistakes before production deployment.

## Problem
Vibe coders and AI-assisted builders ship fast, but AI-generated code often creates dangerous security mistakes across secrets, authorization, database rules, webhooks, and agent tools.

## Target users
- Vibe coders
- AI automation agencies
- Solo founders
- Local business automation builders
- Developers using Bolt, Cursor, GitHub, Supabase, Firebase, n8n, and Next.js

## Goals
- Detect the 5 most dangerous AI-generated security patterns.
- Generate clear exploit paths.
- Produce patch suggestions.
- Generate a static HTML audit report.
- Block Confirmed Critical issues in GitHub Actions.

## Non-goals for V1
- No dashboard.
- No IDE extension.
- No remote signed rule feed.
- No provider connectors.
- No full security guarantee.
- No automatic patch commits.

## V1 findings
1. Exposed secrets
2. Unsafe mutations
3. Broken authorization
4. Supabase/Firebase rule failures
5. Webhook and AI-agent abuse

## Success criteria
- Scanner detects exposed Supabase service role key in client-side Next.js code.
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
