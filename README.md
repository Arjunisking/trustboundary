# TrustBoundary

Pre-deploy security gatekeeper for AI-generated web apps.

TrustBoundary helps fast-moving builders, agencies, and vibe coders catch the dangerous security mistakes AI-generated code often creates before the app reaches production.

It focuses on practical, high-impact issues instead of dumping hundreds of generic warnings.

## What TrustBoundary Detects

TrustBoundary V1 focuses on 5 deadly AI-generated security patterns:

1. Exposed secrets
   Detects service role keys, API secrets, database URLs, and private tokens exposed in client-side code or public repositories.

2. Unsafe mutations
   Detects raw request payloads passed directly into database create, update, or upsert calls without validation.

3. Broken authorization
   Detects routes that read or mutate sensitive data without server-side ownership, role, or session checks.

4. Supabase and Firebase rule failures
   Detects disabled RLS, overly permissive policies, public writes, and weak access rules.

5. Webhook and AI-agent abuse
   Detects public webhook routes without signature verification and AI tools that can execute dangerous actions without approval gates.

## Core Idea

TrustBoundary does not promise that your app is secure.

It tells you whether it found confirmed critical issues in the evidence available inside your repository.

The goal is simple:

Block the most dangerous AI-generated security mistakes before deployment.

## How It Works

TrustBoundary scans committed project artifacts such as:

* Next.js routes and server actions
* Client components
* Supabase migrations
* Firebase rules
* n8n exported workflow JSON files
* GitHub Actions workflows
* Environment examples
* Webhook handlers
* AI SDK usage
* Database mutation logic

It builds a deterministic security evidence graph and reports:

* Confirmed critical blockers
* Likely risks
* Unverified risks
* Exploit paths
* Affected files
* Suggested patches
* Static HTML audit report

## Planned Output

The scanner will generate:

```bash
trustboundary-report.html
trustboundary.patch
trustboundary-results.json
trustboundary-results.sarif
```

The HTML report is designed to be readable by developers, founders, agencies, and stakeholders.

## MVP Status

TrustBoundary is currently in early development.

First milestone:

* TypeScript monorepo
* Core file scanner
* Stack detector
* Secret exposure rule
* CLI wrapper
* Static HTML report generator
* GitHub Action deployment gate

## Intended Usage

Future usage:

```bash
npx trustboundary scan
```

GitHub Action usage:

```yaml
name: TrustBoundary Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run TrustBoundary
        uses: trustboundary/action@v1
        with:
          mode: balanced
```

## Philosophy

Evidence over assumptions.

Fixes over lectures.

Confirmed critical issues should block production.

Unverified risks should warn, not pretend.

Security tools should be useful enough that people keep them installed.

## License

MIT
