# TrustBoundary Attack Patterns

## How to use this guide
This guide explains common security mistakes in prevention-first language. It does not expand automated enforcement. TrustBoundary current automated blocker scope remains limited to deterministic committed repository evidence for `TB001`, `TB002`, and `TB003`.

Each pattern below separates:

- current automated detection
- future advisory explanation possibilities
- what remains docs-only

## Attack patterns

### URL/object ID tampering

Status:
Advisory

Defensive explanation:
User-controlled identifiers in routes, query params, or request bodies may expose another user's data or actions if server-side ownership checks are missing.

Common developer mistake:
Reading account, tenant, profile, invoice, or report records directly from user-supplied IDs without proving current subject owns or may access target resource.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Sensitive routes that read or mutate records using request-controlled identifiers without nearby auth or ownership scoping may support non-blocking educational surfacing.

What stays docs-only:
Real exploitability often depends on middleware, helpers, database policies, tenant design, and runtime auth flow that cannot be proven safely from committed text alone.

Safe patch guidance:
Add server-side ownership and tenant scoping at data access boundary. Resolve target records through authenticated subject context, not raw user-controlled identifiers alone.

Related TrustBoundary area:
Manual review, future advisory

### Broken authorization

Status:
Advisory

Defensive explanation:
Routes or actions may expose sensitive reads or writes when authenticated users can reach resources or operations outside their intended scope.

Common developer mistake:
Checking whether user is signed in, but not checking whether user may access specific account, tenant, role-protected route, or mutation target.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Non-blocking education may later highlight sensitive routes with database access or privileged operations that lack visible auth or ownership checks in same file.

What stays docs-only:
Authorization often lives in middleware, wrappers, policies, helper layers, or provider features that text-only deterministic scanning cannot fully verify.

Safe patch guidance:
Add explicit server-side authorization checks for resource ownership, tenant membership, and role scope before sensitive reads, writes, exports, billing changes, or admin actions.

Related TrustBoundary area:
Manual review, future advisory

### Admin route abuse

Status:
Advisory

Defensive explanation:
Admin-labeled routes or privileged workflows become risky when powerful actions are reachable without explicit role checks and narrow server-side scoping.

Common developer mistake:
Treating route naming, hidden UI, or client-side navigation as if it enforces admin access, while server-side role checks are missing or too broad.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Routes with admin naming, privileged data access, or high-impact mutations and no visible role check may support non-blocking educational surfacing.

What stays docs-only:
Actual admin boundaries may be enforced by middleware, edge config, provider claims, or shared helpers not safely provable from single-file evidence.

Safe patch guidance:
Require explicit server-side admin or elevated-role authorization near privileged action. Keep least-privilege boundaries narrow and re-check before side effects.

Related TrustBoundary area:
Manual review, future advisory

### Unsafe mutation

Status:
Advisory

Defensive explanation:
Database writes become risky when raw request input flows into insert, update, upsert, or create paths without validation, allowlisting, or ownership controls.

Common developer mistake:
Passing `await request.json()` or similar raw body objects straight into ORM or database mutation calls.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Non-blocking education may later call out obvious raw-body-to-write patterns in same-file route code where request data flows directly into mutations.

What stays docs-only:
Safe or unsafe outcome often depends on schema validation, field filtering, model defaults, triggers, and helper behavior not deterministically visible from narrow text patterns.

Safe patch guidance:
Validate request shape first. Use explicit writable field lists before database writes. Add auth and ownership controls before mutation paths.

Related TrustBoundary area:
Manual review, future advisory

### Mass assignment

Status:
Advisory

Defensive explanation:
Broad object writes can accidentally let request data set privileged fields such as roles, status flags, tenant IDs, or ownership columns.

Common developer mistake:
Spreading full request body into model create or update operations without filtering privileged or server-owned fields.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Later non-blocking education may highlight direct object spreads or raw body writes into user, billing, account, or admin-sensitive models.

What stays docs-only:
Whether assignment is actually dangerous depends on ORM schema, server defaults, hidden validators, allowlists, and database protections not safely inferred from text alone.

Safe patch guidance:
Use explicit field allowlists before database writes. Keep role, owner, tenant, status, and system-managed fields server-controlled.

Related TrustBoundary area:
Manual review, future advisory

### Supabase service role exposure

Status:
Blocker

Defensive explanation:
Browser-delivered privileged keys can give powerful backend access outside intended server-only controls.

Common developer mistake:
Exposing service-role or other privileged secrets through client code, public environment variables, or hardcoded browser-delivered bundles.

What TrustBoundary can detect now:
Active automated detection exists in current scope through `TB001` when committed evidence proves client-side secret exposure.

What TrustBoundary may explain later as advisory:
Later education may add non-blocking context around adjacent secret-handling mistakes that are risky but not proven browser exposure under current deterministic boundaries.

What stays docs-only:
Runtime secret leaks, deployment-only mistakes, and ambiguous secret-looking text without browser exposure proof remain outside current deterministic blocking.

Safe patch guidance:
Move privileged keys to server-only code or secret manager. Use publishable or anon keys in browser code. Keep service-role access behind server-side boundaries.

Related TrustBoundary area:
`TB001`

### Supabase/Firebase RLS failures

Status:
Blocker

Defensive explanation:
Public destructive write rules can allow unauthenticated or overly broad data modification when policy guards are missing or literally true.

Common developer mistake:
Using public or anon destructive policies with missing guard clauses, literal `true`, or oversimplified write rules in Supabase, Postgres, or Firebase policies.

What TrustBoundary can detect now:
Active automated detection exists in current scope through `TB002` for narrow deterministic destructive public rule failures.

What TrustBoundary may explain later as advisory:
Later education may add non-blocking context for risky but non-blocking policy shapes, such as public create flows or storage patterns that need abuse controls.

What stays docs-only:
Complex policy logic, helper functions, nuanced ownership checks, and runtime authorization interactions remain outside deterministic blocking when safety cannot be proven absent.

Safe patch guidance:
Add explicit auth, ownership, tenant, or provider checks. Avoid destructive public access with missing or literal-true guards. Keep policy intent narrow and reviewable.

Related TrustBoundary area:
`TB002`

### Public storage bucket risk

Status:
Advisory

Defensive explanation:
Overly broad public storage access can expose sensitive files, allow untrusted uploads, or create abuse paths when bucket or storage rules are too permissive.

Common developer mistake:
Making storage assets public by default, mixing public and private content in same bucket, or using permissive storage rules without validation and ownership controls.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Non-blocking education may later highlight clearly public storage rule text or storage configuration patterns that suggest broad write or read exposure.

What stays docs-only:
Actual file sensitivity, signed URL design, CDN behavior, moderation flow, and storage provider runtime configuration are too context-dependent for deterministic blocking today.

Safe patch guidance:
Separate public and private assets. Restrict write and read rules by ownership and purpose. Validate uploads and keep sensitive content behind server-managed access paths.

Related TrustBoundary area:
Future advisory

### Unsigned webhooks

Status:
Blocker

Defensive explanation:
Webhook routes that trust unverified provider payloads can trigger writes, external calls, or jobs from untrusted inputs.

Common developer mistake:
Reading webhook body and performing side effects without deterministic signature verification in same route or clear local helper.

What TrustBoundary can detect now:
Active automated detection exists in current scope through `TB003` for supported known-provider webhook routes with payload read, dangerous sink, and missing verification evidence.

What TrustBoundary may explain later as advisory:
Later education may add non-blocking explanation for broader webhook hygiene gaps such as dedupe, replay handling, or unsupported-provider patterns.

What stays docs-only:
Unsupported providers, custom verification systems, and runtime-only trust boundaries remain outside deterministic blocking when absence of verification cannot be proven.

Safe patch guidance:
Verify provider signatures before writes, external API calls, billing actions, account changes, or queue dispatch. Keep verification near payload handling.

Related TrustBoundary area:
`TB003`

### Webhook replay risk

Status:
Advisory

Defensive explanation:
Even verified webhooks can cause duplicate or stale side effects when routes do not reject replays or repeated event delivery.

Common developer mistake:
Verifying signature but not validating freshness, event uniqueness, or idempotent processing before side effects.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Non-blocking education may later call out supported webhook handlers that verify signatures but show no visible idempotency, timestamp, or replay-handling signals.

What stays docs-only:
Replay resistance depends on provider semantics, storage of processed event IDs, clock handling, retries, and operational flow that deterministic text scanning cannot safely prove.

Safe patch guidance:
Add idempotency and replay controls such as event ID tracking, freshness checks, and side-effect deduplication before processing.

Related TrustBoundary area:
Future advisory

### Prompt injection

Status:
Advisory

Defensive explanation:
AI systems become risky when untrusted content can influence model instructions or tool decisions beyond intended boundaries.

Common developer mistake:
Passing user-controlled or remote content into model context without separating trusted instructions, validating tool intents, or constraining side effects.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Later non-blocking education may highlight agent flows where prompts, tools, external content, and privileged actions appear tightly coupled without clear safety boundaries.

What stays docs-only:
Actual model behavior, hidden system prompts, provider guardrails, and runtime orchestration decisions are too dynamic for deterministic blocking from committed text alone.

Safe patch guidance:
Separate trusted instructions from untrusted content. Add approval gates, constrained tool inputs, output validation, and least-privilege tool access.

Related TrustBoundary area:
Manual review, future advisory

### Excessive AI-agent permissions

Status:
Advisory

Defensive explanation:
Agents with broad shell, file, admin, billing, or credential access can turn prompt mistakes or logic gaps into high-impact side effects.

Common developer mistake:
Giving agents wide tool scope with no approval boundary, limited context checks, or narrow action constraints.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Non-blocking education may later highlight tool configurations or code paths that combine agent decision-making with powerful side-effect capabilities.

What stays docs-only:
Real risk depends on runtime operator workflow, policy layer, approval design, and external agent platform controls not fully visible in repo text.

Safe patch guidance:
Apply least privilege to tools. Require human approval for destructive actions. Scope file, network, billing, and admin capabilities narrowly.

Related TrustBoundary area:
Manual review, future advisory

### Sensitive data in AI context

Status:
Advisory

Defensive explanation:
Forwarding secrets, tokens, full records, or sensitive internal context into AI systems can create unnecessary disclosure and retention risk.

Common developer mistake:
Sending raw customer data, access tokens, logs, or internal documents into model prompts or agent context without redaction and minimization.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Later non-blocking education may highlight explicit code paths that package sensitive inputs into AI prompts, agent memory, or tool context.

What stays docs-only:
Actual runtime prompt contents, provider retention settings, user consent flows, and downstream handling are too context-dependent for deterministic blocking today.

Safe patch guidance:
Minimize prompt context. Redact secrets and sensitive fields. Keep privileged data out of AI context unless explicitly required and tightly controlled.

Related TrustBoundary area:
Manual review, future advisory

### SQL/raw query injection risk

Status:
Docs-only

Defensive explanation:
Building SQL or raw query strings from untrusted input can let data become query logic instead of remaining plain values.

Common developer mistake:
Concatenating or interpolating user-controlled values into SQL or raw query builders instead of using parameters.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Query safety depends on framework APIs, parameterization semantics, wrappers, query builders, and surrounding validation that are too broad for current deterministic blocking.

Safe patch guidance:
Use parameterized queries and safe query-builder APIs. Keep untrusted values out of raw query strings.

Related TrustBoundary area:
Docs-only

### XSS

Status:
Docs-only

Defensive explanation:
Untrusted content rendered into browser execution contexts can expose user sessions, actions, or data when output encoding or HTML safety boundaries are missing.

Common developer mistake:
Injecting user-controlled text into HTML, script, URL, or attribute contexts without safe encoding or sanitization.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Safe output handling depends on rendering context, templating behavior, sanitizer policy, CSP, and framework escaping guarantees that are too broad for current deterministic blocking.

Safe patch guidance:
Use context-appropriate output encoding, avoid unsafe HTML sinks, and sanitize only when rendering trusted limited HTML is truly required.

Related TrustBoundary area:
Docs-only

### CSRF

Status:
Docs-only

Defensive explanation:
State-changing routes can process unwanted cross-site requests when server-side origin protections or anti-CSRF controls are missing.

Common developer mistake:
Relying on browser cookies for session auth on mutations without adding CSRF tokens, same-site protections, or origin validation.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Real CSRF exposure depends on auth model, cookie settings, frontend flow, browser behavior, and deployment setup that are too runtime-dependent for current deterministic blocking.

Safe patch guidance:
Use CSRF tokens where needed, enforce same-site cookie settings, and validate origin or referer on state-changing requests.

Related TrustBoundary area:
Docs-only

### Open redirect

Status:
Docs-only

Defensive explanation:
Redirect flows become risky when untrusted destinations can influence where users are sent after login, logout, billing, or workflow actions.

Common developer mistake:
Accepting redirect targets from request parameters without allowlisting or normalizing destination values.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Whether redirect behavior is exploitable depends on route flow, normalization, host checks, and provider integration details not safely provable from deterministic text alone.

Safe patch guidance:
Allowlist valid internal destinations and normalize redirect targets before use. Reject external or ambiguous destinations by default.

Related TrustBoundary area:
Docs-only

### Path traversal

Status:
Docs-only

Defensive explanation:
File reads or writes can escape intended directories when path input is accepted without validation and canonical boundary checks.

Common developer mistake:
Concatenating user-controlled file names or paths into filesystem operations without normalizing and constraining to approved roots.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Real file access risk depends on filesystem APIs, deployment layout, path normalization, storage adapters, and host environment details beyond current deterministic blocking model.

Safe patch guidance:
Normalize paths, restrict operations to approved roots, and reject path input that escapes intended directory boundaries.

Related TrustBoundary area:
Docs-only

### SSRF

Status:
Docs-only

Defensive explanation:
Server-side outbound requests become risky when untrusted input can influence internal or privileged destinations.

Common developer mistake:
Letting request data choose full URLs or hosts for server-side fetches without allowlists or network boundary controls.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Real SSRF risk depends on URL construction, internal network reachability, cloud metadata exposure, proxy behavior, and environment controls not safely inferable from committed text alone.

Safe patch guidance:
Allowlist outbound destinations, normalize URLs, block internal address ranges where appropriate, and keep server-side fetch targets tightly scoped.

Related TrustBoundary area:
Docs-only

### CORS misconfiguration

Status:
Docs-only

Defensive explanation:
Cross-origin access becomes risky when origin, method, or credential rules are broader than intended for sensitive APIs.

Common developer mistake:
Allowing wildcard or overly broad origins on endpoints that return sensitive data or accept authenticated requests.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
CORS exposure depends on deployment headers, credential mode, frontend origins, reverse proxy behavior, and browser interaction that current deterministic scanning does not model.

Safe patch guidance:
Allow only expected origins, methods, and headers. Avoid broad credentialed cross-origin access for sensitive endpoints.

Related TrustBoundary area:
Docs-only

### Missing rate limits

Status:
Docs-only

Defensive explanation:
Unaudited high-volume access can turn ordinary endpoints into abuse surfaces for brute force, scraping, replay, or cost amplification.

Common developer mistake:
Shipping auth, webhook, upload, AI, or search endpoints without request throttling, quotas, or abuse controls.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Appropriate rate limits depend on product behavior, traffic shape, provider retries, user tiers, and infrastructure controls not visible enough for deterministic blocking.

Safe patch guidance:
Add per-route throttling, quotas, dedupe, and abuse monitoring based on endpoint sensitivity and expected traffic.

Related TrustBoundary area:
Docs-only

### Insecure file upload

Status:
Docs-only

Defensive explanation:
Upload flows can expose storage, processing, and user content when type, size, ownership, or serving boundaries are too permissive.

Common developer mistake:
Accepting uploaded files without validating content type, size, storage path, ownership, or download-serving behavior.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
No advisory commitment in current scope.

What stays docs-only:
Real upload risk depends on storage design, content inspection, serving path, preview flow, and infrastructure handling outside deterministic repo evidence alone.

Safe patch guidance:
Restrict file types and sizes, isolate upload storage, validate ownership, and keep serving paths separate from executable or sensitive contexts.

Related TrustBoundary area:
Docs-only

### Secrets in logs/errors

Status:
Advisory

Defensive explanation:
Logs and error responses become risky when they expose credentials, tokens, internal identifiers, or sensitive user data beyond intended audiences.

Common developer mistake:
Logging raw request bodies, provider secrets, auth headers, stack traces, or full upstream errors into console output, observability pipelines, or API responses.

What TrustBoundary can detect now:
No active automated detection in the current scope.

What TrustBoundary may explain later as advisory:
Later non-blocking education may highlight explicit logging or error formatting patterns that appear to forward secrets or sensitive values into logs or responses.

What stays docs-only:
Actual log sinks, redaction layers, observability tooling, and runtime error surfaces are too context-dependent for deterministic blocking today.

Safe patch guidance:
Redact secrets and sensitive fields before logging. Keep user-facing errors minimal. Send only necessary sanitized detail to internal monitoring systems.

Related TrustBoundary area:
Future advisory
