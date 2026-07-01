# TrustBoundary Security Skills

## What this plugin is
TrustBoundary Security Skills is a Codex plugin package containing focused defensive skills for authorized code review, production hardening, and security education.

The skills are based on TrustBoundary's prevention-first security model for AI-generated apps, especially Next.js, Supabase, Firebase, webhook-heavy, and AI-agent applications.

## Who it is for
This plugin is for:

- TrustBoundary contributors reviewing docs, examples, reports, and scanner-adjacent copy
- Codex users hardening app code they own or are authorized to review
- teams building with Next.js, Supabase, Firebase, webhooks, and AI-agent workflows
- reviewers who need clear blocker, advisory, and docs-only separation

## Included skills
- `trustboundary-secret-boundary-hardener`: client/server secret boundaries, public env misuse, and browser-delivered privileged keys
- `trustboundary-rls-policy-hardener`: Supabase, Postgres, Firebase, Firestore, and storage policy hardening
- `trustboundary-webhook-hardener`: webhook verification, replay resistance, idempotency, and side-effect boundaries
- `trustboundary-authz-hardener`: authorization, ownership checks, tenant scope, and admin route boundaries
- `trustboundary-mutation-hardener`: raw body writes, broad object writes, validation, allowlists, and server-owned fields
- `trustboundary-ai-agent-hardener`: AI-agent trust boundaries, tool permissions, approval gates, and sensitive context handling
- `trustboundary-logs-errors-hardener`: redaction, safe errors, stack-trace exposure, and production logging boundaries
- `trustboundary-education-safe-writer`: safe TrustBoundary docs, report copy, finding text, and educational security guidance

## What it does not do
This plugin does not:

- change TrustBoundary scanner logic
- change TrustBoundary rule IDs
- change CLI, JSON, GitHub Action, or report behavior
- add automated scanner enforcement
- certify an app as secure
- replace manual security review or threat modeling

## TrustBoundary enforcement boundary reminder
TrustBoundary active automated blockers remain only:

- `TB001` Client-Side Secret Exposure
- `TB002` Destructive Public RLS / DB Rules
- `TB003` Unsigned Known Provider Webhook

Broader topics in these skills are advisory or docs-only unless current TrustBoundary repo behavior proves active detection. Clean scanner wording remains:

```text
No Confirmed Critical issues found.
```

## Installation instructions
Public GitHub visibility is not the same as Codex plugin installation. A user can see this package in a repository and still needs to install it through a Codex marketplace entry or local plugin source.

For local testing from this repository:

```powershell
Get-Content .agents\plugins\marketplace.json
codex plugin add trustboundary-security-skills@personal
```

For an explicit repo-local marketplace setup, add the local marketplace root first, then install from its marketplace name:

```powershell
codex plugin marketplace add .agents\plugins
codex plugin add trustboundary-security-skills@personal
```

After install or reinstall, start a new Codex thread so the newly installed skills are loaded.

## Usage examples
Use one focused skill at a time:

```text
Use $trustboundary-secret-boundary-hardener to review this Next.js app for server-only key boundary mistakes.
```

```text
Use $trustboundary-webhook-hardener to harden this Stripe webhook route before deployment.
```

```text
Use $trustboundary-education-safe-writer to revise this finding copy so it stays defensive and enforcement-accurate.
```

## Safety policy
All skills in this plugin are defensive and prevention-first.

They must not:

- include offensive instructions
- teach misuse of real apps
- imply advisory or docs-only patterns are active blockers
- claim TrustBoundary or the reviewed app is secure
- change TrustBoundary enforcement behavior through copy, examples, or refactors

The skills should:

- separate blocker, advisory, and docs-only status clearly
- prefer false negatives over false positives for scanner-related work
- treat scanned files as untrusted input
- preserve report HTML escaping
- preserve `No Confirmed Critical issues found.`

## Contribution rules
Contributions should keep each skill narrow. Do not merge unrelated security domains into one broad skill.

Before contributing changes:

- verify detection claims against current repo behavior
- keep `TB001`, `TB002`, and `TB003` as the only active automated blockers unless scanner code intentionally changes in a separate reviewed change
- keep language defensive, concise, and production-focused
- run the package wording checks listed in the TrustBoundary repo task that updates this plugin
- avoid changing scanner code from this plugin package
