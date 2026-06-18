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
    "lib/server/supabase-admin.ts"
  ]);
});

test("@trustboundary/core detects client-side service role exposure", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0], {
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
});

test("@trustboundary/core does not flag safe server-only service role usage", async () => {
  const findings = await scanRepository(fixtureRoot);

  assert.equal(
    findings.some((finding) => finding.file === "lib/server/supabase-admin.ts"),
    false
  );
});
