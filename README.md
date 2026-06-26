<p align="center">
  <a href="https://git.io/typing-svg">
    <img
      src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=24&duration=3000&pause=700&color=36BCF7&center=true&vCenter=true&width=850&lines=TrustBoundary;Pre-deploy+security+scanner+for+AI-generated+apps;Blocks+confirmed+critical+issues+before+production"
      alt="Typing SVG"
    />
  </a>
</p>

# TrustBoundary

Deterministic pre-deploy security scanner for AI-generated web apps.

TrustBoundary scans committed repository text for high-signal security mistakes common in fast AI-built apps. It does not execute scanned project code, does not import scanned files, and treats all scanned content as untrusted input.

## Release Model

TrustBoundary V1 is a repository and GitHub Action release.

- Workspace packages remain `private: true`
- V1 is not configured for npm publishing yet
- Future npm publishing would require public package metadata, publish configuration, and a supported distribution strategy for the CLI and action

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
  "targetPath": "/repo/examples/insecure-next-supabase",
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

Public release usage after tagging this repository:

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

- installs TrustBoundary dependencies inside the action repository
- builds TrustBoundary inside the action repository
- scans the checked-out target repository text only
- passes when no Confirmed Critical findings exist
- fails only when Confirmed Critical findings exist and enforcement is enabled
- does not require the target repository to run `pnpm install` or `pnpm build`

Action inputs:

- `target_path`: repository path to scan, default `.`
- `enforce`: default `"true"`
- `report_path`: optional HTML report path inside workspace

Action outputs:

- `total_findings`
- `confirmed_critical_count`
- `blocked`
- `report_path`

## Release Tagging

Release tags for public action use:

- Create immutable release tag `v1.0.0`
- Create or update major tag `v1` to point at same commit as `v1.0.0`
- Test from a clean external repository with `uses: Arjunisking/trustboundary@v1`

Example commands:

```bash
git tag -a v1.0.0 -m "TrustBoundary v1.0.0"
git tag -fa v1 -m "TrustBoundary v1"
git push origin v1.0.0
git push origin refs/tags/v1 --force
```

## Example Fixture

`examples/insecure-next-supabase` is intentionally unsafe. It includes API routes, webhook handlers, Supabase SQL policies, and Firebase rules that exercise all 5 V1 rules. See [examples/insecure-next-supabase/README.md](examples/insecure-next-supabase/README.md).

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

