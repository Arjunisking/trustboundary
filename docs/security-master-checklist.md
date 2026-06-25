# TrustBoundary Security Master Checklist

## Purpose
This checklist covers important security review areas that are not automated scanner enforcement in V1.

TrustBoundary V1 automated scanner has exactly three rules only:
- `TB001 Client-Side Secret Exposure`
- `TB002 Destructive Public RLS / DB Rules`
- `TB003 Unsigned Known Provider Webhook`

Everything below is manual review guidance, not CI blocker logic.

## Unsafe Raw Mutation
Review for:
- request payload fields written directly into database mutations
- missing allowlists or schema validation before write paths
- broad `insert`, `update`, `upsert`, `create`, or `createMany` calls fed by raw request data

Why manual in V1:
- data-shape safety often depends on framework, schema, and helper context not provable from narrow deterministic evidence

## Sensitive Route Without Auth
Review for:
- sensitive routes or server actions with database reads or writes
- missing auth checks before account, billing, admin, or tenant-sensitive operations
- missing ownership or tenant scoping

Why manual in V1:
- auth can exist through wrappers, middleware, helpers, or framework conventions that are hard to prove safely from committed text alone

## Public INSERT Advisory
Review for:
- public or anonymous insert policies
- onboarding or intake flows where public inserts are intentional
- missing anti-abuse controls such as quotas, moderation, or validation

Why manual in V1:
- public insert is not always critical and should not be auto-blocked in V1

## Dangerous AI-Agent Tool Detection
Review for:
- agent or automation tools wired to destructive side effects
- tools with file, shell, billing, credential, or admin mutation capability
- missing human approval or scope limits around powerful tool actions

Why manual in V1:
- tool risk depends heavily on product intent, runtime guardrails, and operator workflow

## Manual review reminder
Checklist items can still be serious. They are excluded from V1 automation because blocker thresholds are not yet deterministic enough for credible CI enforcement.
