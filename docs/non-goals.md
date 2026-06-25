# TrustBoundary V1 Non-Goals

## Scanner scope non-goals
TrustBoundary V1 does not:
- add automated advisory rules
- enforce `TB004` or any fourth automated rule
- automate Unsafe Raw Mutation detection
- automate Sensitive Route Without Auth detection
- automate Public INSERT Advisory detection
- automate Dangerous AI-Agent Tool detection
- execute scanned project code
- import scanned project files
- run scripts from scanned repositories
- certify that an application is secure

## Product non-goals
TrustBoundary V1 does not include:
- dashboards
- IDE extensions
- remote rule feeds
- automatic patch commits
- provider connectors beyond committed-repo evidence scanning

## Documentation-only areas
Unsafe Raw Mutation, Sensitive Route Without Auth, Public INSERT Advisory, and Dangerous AI-Agent Tool detection remain documentation-only in V1.

They belong in:
- `docs/security-master-checklist.md`
- `docs/scanner-roadmap.md`
