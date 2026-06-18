import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  matchExposedSupabaseServiceRoleKey
} from "../dist/index.js";

test("@trustboundary/rules exports V1 rule ids", () => {
  assert.equal(RULE_IDS.length, 5);
  assert.equal(RULE_IDS[0], "exposed-secrets");
});

test("detects client-side service role env reference", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "app/admin/page.tsx",
    content: [
      '"use client";',
      "",
      "const leaked = process.env.SUPABASE_SERVICE_ROLE_KEY;"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 3);
});

test("detects NEXT_PUBLIC service role misuse", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/components/admin-panel.tsx",
    content: [
      "export const adminConfig = {",
      '  serviceRoleKey: process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
      "};"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.match(matches[0]?.message ?? "", /NEXT_PUBLIC/);
});

test("detects client-side JWT-like service_role token", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "components/admin-token.tsx",
    content: [
      '"use client";',
      'const token = "eyJhbGciOiJIUzI1NiJ9.c2VydmljZV9yb2xl.signature";'
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 2);
});

test("does not flag safe server-only usage", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "lib/server/supabase-admin.ts",
    content: [
      "export function getAdminKey(): string {",
      '  return process.env.SUPABASE_SERVICE_ROLE_KEY ?? "";',
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});
