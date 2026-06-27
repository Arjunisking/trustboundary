<p align="center">
  <a href="https://git.io/typing-svg">
    <img
      src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=24&duration=2800&pause=900&color=00D084&center=true&vCenter=true&width=900&lines=TrustBoundary;Deterministic+pre-deploy+security+scanner;Blocks+confirmed+critical+AI-generated+app+mistakes;No+LLM+guesswork.+No+false+confidence."
      alt="Typing SVG"
    />
  </a>
</p>

# TrustBoundary

Deterministic pre-deploy security scanner for AI-generated web apps.

TrustBoundary scans committed repository evidence for a small set of high-confidence security mistakes common in fast AI-built apps. It is designed to run before deployment, especially in GitHub Actions.

It does not execute scanned project code.
It does not import scanned project files.
It does not use LLM judgment for findings.
It does not claim your app is secure.

Clean result wording is:

```text
No Confirmed Critical issues found.
```

## Current Release

Latest V1 release:

```text
v1.1.0
```

Public GitHub Action usage:

```yaml
uses: Arjunisking/trustboundary@v1
```

For immutable pinning:

```yaml
uses: Arjunisking/trustboundary@v1.1.0
```

`v1` is the floating major tag. `v1.1.0` is the immutable release tag.

## V1 Active Automated Blockers

TrustBoundary V1 currently enforces exactly three blocking rules:

| Rule ID | Rule                              | What it detects                                                                                                                  | Severity   | Confidence  |
| ------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------- |
| `TB001` | Client-Side Secret Exposure       | Hardcoded or publicly exposed secrets in browser-delivered code                                                                  | `critical` | `confirmed` |
| `TB002` | Destructive Public RLS / DB Rules | Supabase/Postgres/Firebase policy text that allows destructive public writes or deletes                                          | `critical` | `confirmed` |
| `TB003` | Unsigned Known Provider Webhook   | Known provider webhook routes that read payloads and reach dangerous sinks without deterministic signature verification evidence | `critical` | `confirmed` |

V1 active automated enforcement is intentionally narrow.

TrustBoundary does not currently enforce:

* `TB004`
* advisory rules
* broad authentication scanning
* unsafe mutation scanning
* broken authorization scanning
* broad webhook or AI-agent abuse scanning

Those categories may exist in older planning docs or historical prototypes, but they are not active V1 automated blockers.

## Rule Boundaries

### TB001 Client-Side Secret Exposure

TB001 blocks when committed evidence shows secrets exposed to client-side code.

Examples of risky evidence:

* hardcoded Stripe live secret keys in browser-exposed files
* public env exposure such as `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`
* hardcoded Supabase service role JWT-like values with Supabase/service role proof
* hardcoded GitHub, Shopify, or Clerk secret-shaped values in browser-exposed code when safely detectable

TB001 does not block when client exposure cannot be proven.

### TB002 Destructive Public RLS / DB Rules

TB002 blocks narrow, deterministic database policy failures.

Examples of risky evidence:

* `FOR UPDATE TO public USING (true)`
* `FOR DELETE TO anon USING true`
* `FOR ALL TO public` with missing guard clauses
* Firebase rules like `allow write: if true`
* Firebase rules like `allow update, delete: if true`

TB002 does not block complex policy logic, ownership checks, custom functions, `auth.uid()`, `request.auth`, JWT claims, or public insert-only rules.

### TB003 Unsigned Known Provider Webhook

TB003 blocks only supported known provider webhook routes when all required evidence is present.

Supported V1 providers:

* Stripe
* Clerk
* Shopify
* GitHub

To block, TB003 must prove all of these in the same committed route evidence:

1. known provider webhook route
2. payload read
3. dangerous sink
4. no same-file provider verification marker
5. no clearly named local relative verification helper import

Examples of verification evidence that can suppress TB003:

* `stripe.webhooks.constructEvent(...)`
* `stripe-signature` with crypto verification
* Clerk/Svix `Webhook(...).verify(...)`
* Shopify `x-shopify-hmac-sha256` with HMAC verification
* GitHub `x-hub-signature-256` with HMAC and timing-safe comparison
* local helper imports such as `verifyWebhook`, `verifySignature`, `validateHmac`, or `constructEvent`

Unsupported providers and ambiguous webhook routes pass by design.

## GitHub Action Usage

Create `.github/workflows/trustboundary.yml`:

```yaml
name: TrustBoundary

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  trustboundary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run TrustBoundary
        id: trustboundary
        uses: Arjunisking/trustboundary@v1
        with:
          target_path: .
          enforce: "true"
          report_path: trustboundary-report.html

      - name: Print outputs
        run: |
          echo "total_findings=${{ steps.trustboundary.outputs.total_findings }}"
          echo "confirmed_critical_count=${{ steps.trustboundary.outputs.confirmed_critical_count }}"
          echo "blocked=${{ steps.trustboundary.outputs.blocked }}"
          echo "report_path=${{ steps.trustboundary.outputs.report_path }}"
```

Action behavior:

* scans the checked-out repository text
* treats scanned files as untrusted input
* does not run target repository install/build scripts
* passes when no Confirmed Critical findings exist
* fails only when Confirmed Critical findings exist and `enforce` is enabled
* emits declared outputs for CI usage
* can write a static HTML report

Action inputs:

| Input         | Default  | Description                                         |
| ------------- | -------- | --------------------------------------------------- |
| `target_path` | `.`      | Repository path to scan                             |
| `enforce`     | `"true"` | Whether Confirmed Critical findings fail the action |
| `report_path` | empty    | Optional HTML report output path                    |

Action outputs:

| Output                     | Description                                    |
| -------------------------- | ---------------------------------------------- |
| `total_findings`           | Total findings returned by active rules        |
| `confirmed_critical_count` | Number of blocking Confirmed Critical findings |
| `blocked`                  | `true` when enforcement should fail            |
| `report_path`              | HTML report path when configured               |

## Local Development

TrustBoundary is a TypeScript monorepo.

Package layout:

```text
packages/core    scanner orchestration and file walking
packages/rules   deterministic embedded rules
packages/cli     local CLI wrapper
packages/action  GitHub Action wrapper and bundled runtime
packages/report  static HTML report generation
```

Install dependencies:

```bash
pnpm install
```

Build packages:

```bash
pnpm build
```

Run tests:

```bash
pnpm test
```

Run typecheck:

```bash
pnpm typecheck
```

## CLI Usage

The local CLI is intended for repository development and manual scans.

Human-readable scan:

```bash
pnpm trustboundary scan examples/insecure-next-supabase
```

JSON output:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --json
```

HTML report:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --report trustboundary-report.html
```

Enforced exit code:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --enforce
```

CLI shape:

```text
trustboundary scan <target-directory> [--json] [--report <file>] [--enforce]
```

## JSON Output

Top-level JSON fields:

* `targetPath`
* `summary.totalFindings`
* `summary.confirmedCriticalCount`
* `summary.blocking`
* `summary.statusMessage`
* `hasBlockingFindings`
* `enforcementEnabled`
* `exitCode`
* `findings`

Finding fields include:

* `ruleId`
* `severity`
* `confidence`
* `file`
* `line`
* `message`
* `exploitPath`
* `patch`

Example shape:

```json
{
  "targetPath": "/repo",
  "summary": {
    "totalFindings": 1,
    "confirmedCriticalCount": 1,
    "blocking": true,
    "statusMessage": "Confirmed Critical findings: 1"
  },
  "hasBlockingFindings": true,
  "enforcementEnabled": true,
  "exitCode": 1,
  "findings": [
    {
      "ruleId": "TB003",
      "severity": "critical",
      "confidence": "confirmed",
      "file": "app/api/webhooks/stripe/route.ts",
      "line": 2,
      "message": "Stripe webhook route reads payload and reaches a dangerous sink without deterministic signature verification evidence."
    }
  ]
}
```

This separation avoids confusion when blocking findings exist but enforcement is off.

## HTML Report

TrustBoundary can generate a static HTML report.

Report behavior:

* generates one self-contained HTML file
* escapes untrusted file paths, messages, exploit paths, patches, and target paths
* reports deterministic repository evidence only
* does not claim the repository is secure
* uses safe clean-scan wording

Clean report status:

```text
No Confirmed Critical issues found.
```

## Example Fixture

`examples/insecure-next-supabase` is intentionally unsafe.

It exists to exercise TrustBoundary's active V1 blockers:

* TB001 client-side secret exposure
* TB002 destructive public RLS / DB rules
* TB003 unsigned known provider webhook

Do not copy fixture code into production apps.

## Release Verification

The `v1.1.0` release was verified with:

* local rule/core/CLI/action tests
* full workspace tests
* typecheck
* build
* external red test using unsigned Stripe webhook
* external green test using signed Stripe webhook
* immutable `v1.1.0` GitHub Action smoke test
* floating `v1` GitHub Action smoke test

## Release Process

For future releases:

1. Run local verification.

```bash
pnpm --filter @trustboundary/rules test
pnpm --filter @trustboundary/core test
pnpm --filter @trustboundary/cli test
pnpm --filter @trustboundary/action test
pnpm test
pnpm typecheck
pnpm build
```

2. Create immutable version tag.

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

3. Test from an external repository using the immutable tag.

```yaml
uses: Arjunisking/trustboundary@vX.Y.Z
```

4. Move floating major tag only after the immutable tag passes external smoke tests.

```bash
git tag -fa v1 -m "Move v1 to vX.Y.Z"
git push origin refs/tags/v1 --force
```

5. Test again from an external repository using:

```yaml
uses: Arjunisking/trustboundary@v1
```

## Design Principles

* Deterministic evidence over assumptions
* Confirmed Critical only for blocking
* False negatives over false positives
* No scanned-code execution
* No imported scanned files
* No LLM judgment for findings
* No full-security claims
* Clear exploit path and patch guidance
* Small V1 scope that developers can trust

## Known Limitations

TrustBoundary V1 is intentionally narrow.

It may miss:

* unsupported webhook providers
* custom verification patterns
* unusual route layouts
* cross-file dataflow
* runtime-only configuration issues
* broader authorization flaws
* general input validation bugs
* non-committed secrets or deployment misconfiguration

A clean TrustBoundary scan means only:

```text
No Confirmed Critical issues found.
```

It does not mean the application is secure.

## License

MIT
