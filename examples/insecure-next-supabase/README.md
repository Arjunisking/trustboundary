# Insecure Fixture

This fixture is intentionally unsafe.

It exists to exercise TrustBoundary V1.1.0 active automated blockers:

1. `TB001 Client-Side Secret Exposure`
2. `TB002 Destructive Public RLS / DB Rules`
3. `TB003 Unsigned Known Provider Webhook`

Contents include:

- insecure Next.js API routes
- insecure webhook handlers
- unsafe Supabase SQL policies
- unsafe Firebase rules
- safe control examples used as negative fixtures

Historical categories such as unsafe mutation, broken authorization, and broad webhook or AI-agent abuse are not active V1.1.0 automated blockers.

Do not treat this fixture as application guidance.