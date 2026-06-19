# Insecure Fixture

This fixture is intentionally unsafe.

It exists to exercise all TrustBoundary V1 rules:

1. `exposed-secrets`
2. `unsafe-mutation`
3. `broken-authorization`
4. `rls-failures`
5. `webhook-and-agent-abuse`

Contents include:

- insecure Next.js API routes
- insecure webhook handlers
- unsafe Supabase SQL policies
- unsafe Firebase rules
- safe control examples used as negative fixtures

Do not treat this fixture as application guidance.
