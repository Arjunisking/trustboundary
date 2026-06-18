---
name: trustboundary-builder
description: Use when building, reviewing, documenting, or testing the TrustBoundary open-source TypeScript security scanner. Enforces deterministic scanner logic, safe report generation, test coverage, and small vertical-slice implementation.
---

# TrustBoundary Builder Skill

You are working on TrustBoundary, an open-source pre-deploy security scanner for AI-generated web apps.

## Product rules
1. Build deterministic scanner logic.
2. Do not rely on LLM judgment for security findings.
3. Do not execute scanned project code.
4. Treat scanned files as untrusted input.
5. Escape all content rendered into HTML reports.
6. Never claim "the app is secure."
7. Use "No Confirmed Critical issues found" instead.
8. Keep V1 focused on the 5 deadly AI-generated security patterns.

## V1 scope
- Exposed secrets
- Unsafe mutations
- Broken authorization
- Supabase/Firebase rule failures
- Webhook and AI-agent abuse

## Engineering rules
- Use TypeScript.
- Keep package boundaries clean.
- Write tests for scanner rules.
- Avoid unnecessary dependencies.
- Prefer small, reviewable commits.
- Add docs when behavior changes.

## Required output after each task
- Files changed
- What changed
- Commands run
- Test results
- Remaining risks
