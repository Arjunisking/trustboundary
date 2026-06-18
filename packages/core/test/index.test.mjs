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
    "app/api/orders/route.ts",
    "app/api/prisma/route.ts",
    "app/api/profiles/route.ts",
    "app/api/safe-allowlist/route.ts",
    "app/api/safe-validated/route.ts",
    "app/api/users/route.ts",
    "lib/server/supabase-admin.ts"
  ]);
});

test("@trustboundary/core detects exposed secrets and unsafe mutations", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(findings.length, 5);

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
});
