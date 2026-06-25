import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";

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
    "app/api/webhook/orders/route.ts",
    "app/api/webhooks/stripe/route.ts",
    "firestore.rules",
    "lib/server/supabase-admin.ts",
    "storage.rules",
    "supabase/migrations/202606190001_public_profiles.sql",
    "supabase/migrations/202606190002_public_orders_insert.sql",
    "supabase/policies/profile_owner_only.sql"
  ]);
});

test("@trustboundary/core detects exposed secrets, unsafe mutations, broken authorization, webhook abuse, and RLS failures", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(findings.length, 16);

  const secretFinding = findings.find(
    (finding) => finding.ruleId === "TB001"
  );
  const unsafeFinding = findings.find(
    (finding) =>
      finding.ruleId === "unsafe-mutation" &&
      finding.file === "app/api/users/route.ts"
  );

  assert.deepEqual(secretFinding, {
    id: "TB001:app/admin/page.tsx:3",
    ruleId: "TB001",
    severity: "critical",
    confidence: "confirmed",
    file: "app/admin/page.tsx",
    line: 3,
    message: "Public env identifier exposes server/private secret material to browser code.",
    exploitPath:
      "Anyone can extract the secret from browser-delivered code and use privileged access outside intended server-side controls.",
    patch:
      "Move the secret to server-only code or a secret manager. Do not expose service, private, admin, token, or server keys to browser bundles; use publishable or anon keys instead."
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

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "webhook-and-agent-abuse" &&
        finding.file === "app/api/webhooks/stripe/route.ts"
    ),
    {
      id: "webhook-and-agent-abuse:app/api/webhooks/stripe/route.ts:3",
      ruleId: "webhook-and-agent-abuse",
      severity: "critical",
      confidence: "confirmed",
      file: "app/api/webhooks/stripe/route.ts",
      line: 3,
      message:
        "Webhook route processes payload and reaches a sensitive sink without visible signature verification.",
      exploitPath:
        "An attacker can forge webhook requests and trigger sensitive side effects when the route processes webhook payloads without verifying the provider signature.",
      patch:
        "Verify the provider signature before processing the payload or triggering side effects. Use provider-specific verification such as stripe.webhooks.constructEvent or Webhook.verify."
    }
  );
  assert.equal(
    findings.some(
      (finding) =>
        finding.ruleId === "broken-authorization" &&
        finding.file === "app/api/webhooks/stripe/route.ts"
    ),
    false
  );

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "webhook-and-agent-abuse" &&
        finding.file === "app/api/webhook/orders/route.ts"
    ),
    {
      id: "webhook-and-agent-abuse:app/api/webhook/orders/route.ts:3",
      ruleId: "webhook-and-agent-abuse",
      severity: "critical",
      confidence: "confirmed",
      file: "app/api/webhook/orders/route.ts",
      line: 3,
      message:
        "Webhook route processes payload and reaches a sensitive sink without visible signature verification.",
      exploitPath:
        "An attacker can forge webhook requests and trigger sensitive side effects when the route processes webhook payloads without verifying the provider signature.",
      patch:
        "Verify the provider signature before processing the payload or triggering side effects. Use provider-specific verification such as stripe.webhooks.constructEvent or Webhook.verify."
    }
  );
  assert.equal(
    findings.some(
      (finding) =>
        finding.ruleId === "broken-authorization" &&
        finding.file === "app/api/webhook/orders/route.ts"
    ),
    false
  );

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "rls-failures" &&
        finding.file === "supabase/migrations/202606190001_public_profiles.sql"
    ),
    {
      id: "rls-failures:supabase/migrations/202606190001_public_profiles.sql:4",
      ruleId: "rls-failures",
      severity: "critical",
      confidence: "confirmed",
      file: "supabase/migrations/202606190001_public_profiles.sql",
      line: 4,
      message: "Supabase policy uses USING (true), allowing broad public access.",
      exploitPath:
        "An attacker can read or write data directly because the committed Supabase or Firebase rule text visibly grants broad public access.",
      patch:
        "Restrict public access with auth.uid(), request.auth, tenant ownership checks, or provider-specific role conditions before allowing reads or writes."
    }
  );

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "rls-failures" &&
        finding.file === "supabase/migrations/202606190002_public_orders_insert.sql"
    ),
    {
      id: "rls-failures:supabase/migrations/202606190002_public_orders_insert.sql:4",
      ruleId: "rls-failures",
      severity: "critical",
      confidence: "confirmed",
      file: "supabase/migrations/202606190002_public_orders_insert.sql",
      line: 4,
      message: "Supabase policy uses WITH CHECK (true), allowing broad public writes.",
      exploitPath:
        "An attacker can read or write data directly because the committed Supabase or Firebase rule text visibly grants broad public access.",
      patch:
        "Restrict public access with auth.uid(), request.auth, tenant ownership checks, or provider-specific role conditions before allowing reads or writes."
    }
  );

  assert.deepEqual(
    findings.find(
      (finding) =>
        finding.ruleId === "rls-failures" && finding.file === "firestore.rules"
    ),
    {
      id: "rls-failures:firestore.rules:5",
      ruleId: "rls-failures",
      severity: "critical",
      confidence: "confirmed",
      file: "firestore.rules",
      line: 5,
      message: "Firebase rules allow public read and write access.",
      exploitPath:
        "An attacker can read or write data directly because the committed Supabase or Firebase rule text visibly grants broad public access.",
      patch:
        "Restrict public access with auth.uid(), request.auth, tenant ownership checks, or provider-specific role conditions before allowing reads or writes."
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
  assert.equal(
    findings.some((finding) => finding.file === "supabase/policies/profile_owner_only.sql"),
    false
  );
  assert.equal(
    findings.some((finding) => finding.file === "storage.rules"),
    false
  );
});

test("@trustboundary/core ignores examples by default but can bypass ignores for internal fixtures", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "trustboundary-ignore-"));
  const nestedDir = path.join(tempRoot, "examples", "app");
  await mkdir(nestedDir, { recursive: true });
  await writeFile(
    path.join(nestedDir, "page.tsx"),
    ['"use client";', 'const secret = "sk_live_1234567890abcdef123456";'].join("\n"),
    "utf8"
  );

  const defaultFindings = await scanRepository(tempRoot);
  const bypassedFindings = await scanRepository(tempRoot, {
    useDefaultIgnorePaths: false
  });

  assert.deepEqual(defaultFindings, []);
  assert.equal(bypassedFindings.length, 1);
  assert.equal(bypassedFindings[0]?.ruleId, "TB001");
  assert.equal(bypassedFindings[0]?.file, "examples/app/page.tsx");
});
