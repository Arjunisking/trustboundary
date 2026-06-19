# TrustBoundary

Deterministic pre-deploy security scanner for AI-generated web apps.

TrustBoundary scans committed repository text for high-signal security mistakes common in fast AI-built apps. It does not execute scanned project code, does not import scanned files, and treats all scanned content as untrusted input.

## V1 Rules

| Rule | What it detects | Typical severity/confidence |
| --- | --- | --- |
| `exposed-secrets` | Supabase service role keys or service-role JWTs exposed to client-side code | `critical/confirmed` |
| `unsafe-mutation` | Request body flowing directly into database mutations without visible validation or allowlisting | `high/likely` |
| `broken-authorization` | Sensitive API routes or server actions that reach DB reads/writes without visible auth or ownership checks | `high/confirmed` or `high/likely` |
| `rls-failures` | Supabase SQL policies or Firebase rules that visibly allow broad public read/write access | `critical/confirmed`, sometimes `high/likely` |
| `webhook-and-agent-abuse` | Webhook routes that process payloads and reach sensitive sinks without visible signature verification | `critical/confirmed` or `high/likely` |

## Gating

- Blocking behavior today: `critical/confirmed` only
- CLI with `--enforce` exits `1` only when Confirmed Critical findings exist
- GitHub Action fails only when Confirmed Critical findings exist and `enforce` is enabled
- `high/confirmed`, `high/likely`, and `unverified` findings are warning-only by default
- Clean blocking status wording is always `No Confirmed Critical issues found.`

## Install

Install workspace dependencies:

```bash
pnpm install
```

Build local packages before first CLI use:

```bash
pnpm build
```

## CLI

Human summary scan:

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

CLI usage:

```text
trustboundary scan <target-directory> [--json] [--report <file>] [--enforce]
```

## JSON Output

Top-level JSON fields:

- `targetPath`: absolute or resolved scan target path
- `summary.totalFindings`: total findings returned by current rules
- `summary.confirmedCriticalCount`: findings that currently block by default
- `summary.blocking`: summary-level blocking status based on Confirmed Critical findings only
- `hasBlockingFindings`: top-level alias of `summary.blocking`
- `enforcementEnabled`: whether `--enforce` was used
- `exitCode`: actual CLI exit behavior
- `findings`: individual findings with `ruleId`, `severity`, `confidence`, `file`, `line`, `message`, `exploitPath`, and `patch`

Example shape:

```json
{
  "targetPath": "D:\\PROJECTS\\trustboundary\\examples\\insecure-next-supabase",
  "summary": {
    "totalFindings": 16,
    "confirmedCriticalCount": 6,
    "blocking": true,
    "statusMessage": "Confirmed Critical findings: 6"
  },
  "hasBlockingFindings": true,
  "enforcementEnabled": false,
  "exitCode": 0,
  "findings": []
}
```

This separation avoids confusion when blocking findings exist but enforcement is off.

## HTML Report

- Generates one self-contained HTML file
- Escapes untrusted file paths, messages, exploit paths, patches, and target paths
- Reports deterministic repository evidence only
- Does not claim the repository is secure or fully assessed

## GitHub Action

Inputs:

- `target_path`: repository path to scan, default `.`
- `enforce`: default `"true"`
- `report_path`: optional HTML report path inside workspace

Outputs:

- `total_findings`
- `confirmed_critical_count`
- `blocked`
- `report_path`

Behavior:

- passes when no Confirmed Critical findings exist
- fails only when Confirmed Critical findings exist and enforcement is enabled
- lower severities, likely, and unverified findings do not fail the action by themselves

Minimal workflow:

```yaml
name: TrustBoundary

on:
  pull_request:
  push:
    branches: [main]

jobs:
  trustboundary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install pnpm
        uses: pnpm/action-setup@v4
        with:
          version: 11.7.0

      - name: Install Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: pnpm

      - name: Install deps
        run: pnpm install --frozen-lockfile

      - name: Build
        run: pnpm build

      - name: Run TrustBoundary
        id: trustboundary
        uses: ./
        with:
          target_path: examples/insecure-next-supabase
          enforce: "true"
          report_path: trustboundary-report.html

      - name: Print outputs
        run: |
          echo "total_findings=${{ steps.trustboundary.outputs.total_findings }}"
          echo "confirmed_critical_count=${{ steps.trustboundary.outputs.confirmed_critical_count }}"
          echo "blocked=${{ steps.trustboundary.outputs.blocked }}"
          echo "report_path=${{ steps.trustboundary.outputs.report_path }}"
```

## Example Fixture

`examples/insecure-next-supabase` is intentionally unsafe. It includes API routes, webhook handlers, Supabase SQL policies, and Firebase rules that exercise all 5 V1 rules. See [examples/insecure-next-supabase/README.md](/D:/PROJECTS/trustboundary/examples/insecure-next-supabase/README.md:1).

## V1 Scope

TrustBoundary V1 focuses on 5 AI-generated security patterns:

1. Exposed secrets
2. Unsafe mutations
3. Broken authorization
4. Supabase/Firebase rule failures
5. Webhook and AI-agent abuse

## Commands

```bash
pnpm install
pnpm typecheck
pnpm test
pnpm build
```

## Philosophy

- Evidence over assumptions
- Fixes over lectures
- Block Confirmed Critical only by default
- Warn on Likely and Unverified

## License

MIT
