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

test("@trustboundary/core detects only TB001 in normal V1 automated scans", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(findings.length, 1);
  assert.deepEqual(findings, [
    {
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
    }
  ]);
});

test("@trustboundary/core does not flag server-only files or dormant non-TB001 fixture cases", async () => {
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
