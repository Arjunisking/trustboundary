import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import { scanRepository, walkFiles } from "../dist/index.js";

const fixtureRoot = path.resolve(process.cwd(), "../../examples/insecure-next-supabase");

test("@trustboundary/core walks fixture files as untrusted text", async () => {
  const files = await walkFiles(fixtureRoot);
  const relativePaths = files.map((file) => file.relativePath).sort();

  assert.deepEqual(relativePaths, [
    "app/admin/page.tsx",
    "app/api/billing/route.ts",
    "app/api/health/route.ts",
    "app/api/orders/route.ts",
    "app/api/prisma/route.ts",
    "app/api/profiles/route.ts",
    "app/api/reports/route.ts",
    "app/api/safe-allowlist/route.ts",
    "app/api/safe-validated/route.ts",
    "app/api/session-safe/route.ts",
    "app/api/supabase-safe/route.ts",
    "app/api/users/route.ts",
    "lib/server/supabase-admin.ts"
  ]);
});

test("@trustboundary/core detects exposed secrets, unsafe mutations, and broken authorization", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(findings.length, 11);

  const secretFinding = findings.find(
    (finding) => finding.ruleId === "exposed-secrets"
  );
  const unsafeFinding = findings.find(
    (finding) =>
      finding.ruleId === "unsafe-mutation" &&
      finding.file === "app/api/users/route.ts"
  );

  assert.deepEqual(secretFinding, {
    id: "exposed-secrets:app/admin/page.tsx:3",
    ruleId: "exposed-secrets",
    severity: "critical",
    confidence: "confirmed",
    file: "app/admin/page.tsx",
    line: 3,
    message: "Supabase service role env key referenced in client-side code.",
    exploitPath:
      "Anyone can extract the key from the browser bundle and bypass database permissions.",
    patch:
      "Move the service role key to a server-only module or API route. Remove any client-side reference and use a public anon key in browser code."
  });

  assert.deepEqual(unsafeFinding, {
    id: "unsafe-mutation:app/api/users/route.ts:3",
    ruleId: "unsafe-mutation",
    severity: "high",
    confidence: "likely",
    file: "app/api/users/route.ts",
    line: 3,
    message:
      "Request body flows directly into a database mutation without visible validation or allowlisting.",
    exploitPath:
      "An attacker can send unexpected fields in the request body and mutate database records without validation or allowlisting.",
    patch:
      "Validate and allowlist request body fields before passing data into create, update, insert, or upsert."
  });

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "broken-authorization" &&
        finding.file === "app/api/reports/route.ts"
    ),
    {
      id: "broken-authorization:app/api/reports/route.ts:2",
      ruleId: "broken-authorization",
      severity: "high",
      confidence: "confirmed",
      file: "app/api/reports/route.ts",
      line: 2,
      message:
        "Sensitive database read or write is reachable without a visible auth control in this handler.",
      exploitPath:
        "An attacker can call the route directly and reach a sensitive database operation without a visible server-side auth gate.",
      patch:
        "Add a server-side auth check such as getServerSession, auth(), requireAuth, or supabase.auth.getUser before the database read or write."
    }
  );

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "broken-authorization" &&
        finding.file === "app/api/billing/route.ts"
    ),
    {
      id: "broken-authorization:app/api/billing/route.ts:7",
      ruleId: "broken-authorization",
      severity: "high",
      confidence: "likely",
      file: "app/api/billing/route.ts",
      line: 7,
      message:
        "Handler authenticates the caller but reaches a sensitive database read or write without an ownership or tenant constraint.",
      exploitPath:
        "An authenticated attacker can read or mutate another user's records when the handler lacks an ownership or tenant constraint.",
      patch:
        "Scope the query or mutation with userId, ownerId, tenantId, orgId, organizationId, or createdBy, or require an explicit admin guard."
    }
  );
});

test("@trustboundary/core does not flag safe server-only or validated mutation usage", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(
    findings.some((finding) => finding.file === "lib/server/supabase-admin.ts"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "app/api/safe-validated/route.ts"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "app/api/safe-allowlist/route.ts"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "app/api/session-safe/route.ts"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "app/api/supabase-safe/route.ts"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "app/api/health/route.ts"),
    false
  );
});
