# TrustBoundary

Deterministic pre-deploy security scanner for AI-generated web apps.

TrustBoundary focuses on high-signal evidence. Current release slice detects exposed Supabase service role keys in client-side Next.js code, unsafe request-body mutation flows, broken authorization in sensitive Next.js API routes and server actions, broad public Supabase/Firebase policy failures, and webhook routes that perform sensitive actions without visible signature verification, returns JSON, writes escaped HTML reports, and gates CI through a GitHub Action.

## Current Slice

- Rule 1: exposed Supabase service role key in client-side Next.js code
- Rule 2: unsafe request body mutation flow into database writes
- Rule 3: broken authorization on sensitive Next.js API routes and server actions
- Rule 4 slice: Supabase/Firebase RLS failure detection from committed SQL/rule text
- Rule 5 slice: webhook signature verification on inbound webhook routes
- Blocking severity today: Confirmed Critical only
- Interfaces:
  - core scanner
  - CLI
  - self-contained HTML report
  - GitHub Action gate

## Current Commands

Install workspace deps:

```bash
pnpm install
```

Human summary:

```bash
pnpm trustboundary scan examples/insecure-next-supabase
```

JSON output:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --json
```

HTML report:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --report report.html
```

Enforcement mode:

```bash
pnpm trustboundary scan examples/insecure-next-supabase --enforce
```

Clean blocking status wording:

```text
No Confirmed Critical issues found.
```

## JSON Fields

Current CLI JSON separates finding status from process exit behavior:

- `summary.blocking`: summary-level blocking status from scanner findings
- `hasBlockingFindings`: explicit top-level alias for blocking status
- `enforcementEnabled`: whether `--enforce` was used
- `exitCode`: actual CLI exit behavior

This avoids confusion when blocking findings exist but enforcement is off.

## GitHub Action

Inputs:

- `target_path`: repo path to scan, default `.`
- `enforce`: default `"true"`
- `report_path`: optional HTML report output path

Outputs:

- `total_findings`
- `confirmed_critical_count`
- `blocked`
- `report_path`

Behavior:

- passes when no Confirmed Critical findings exist
- fails only when Confirmed Critical findings exist and enforcement is enabled
- lower severities, likely, and unverified findings do not fail action by themselves

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

## V1 Scope

TrustBoundary V1 aims at 5 deadly AI-generated security patterns:

1. Exposed secrets
2. Unsafe mutations
3. Broken authorization
4. Supabase/Firebase rule failures
5. Webhook and AI-agent abuse

Current shipped implementation covers first slice of item 1, first slice of item 2, first slice of item 3, first slice of item 4, and first slice of item 5.

## Philosophy

- Evidence over assumptions
- Fixes over lectures
- Block Confirmed Critical only by default
- Warn on Likely and Unverified

## License

MIT
