import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  SCANNER_RULES,
  matchDestructivePublicDbRules,
  matchExposedSupabaseServiceRoleKey
} from "../dist/index.js";

test("@trustboundary/rules exports TB001 and TB002 as the only active V1 automated rules", () => {
  assert.deepEqual(RULE_IDS, ["TB001", "TB002"]);
  assert.deepEqual(
    SCANNER_RULES.map((rule) => ({
      ruleId: rule.ruleId,
      severity: rule.severity,
      confidence: rule.confidence
    })),
    [
      {
        ruleId: "TB001",
        severity: "critical",
        confidence: "confirmed"
      },
      {
        ruleId: "TB002",
        severity: "critical",
        confidence: "confirmed"
      }
    ]
  );
});

test("detects hardcoded Stripe live secret in browser-exposed Next.js page", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "app/page.tsx",
    content: [
      '"use client";',
      'const secret = "sk_live_1234567890abcdef123456";'
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 2);
});

test("detects NEXT_PUBLIC service role misuse", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/components/admin-panel.tsx",
    content: [
      '"use client";',
      "export const adminConfig = {",
      '  serviceRoleKey: process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
      "};"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.match(matches[0]?.message ?? "", /Public env identifier/);
});

test("does not flag client-side service role env reference without public prefix", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "app/admin/page.tsx",
    content: [
      '"use client";',
      "",
      "const leaked = process.env.SUPABASE_SERVICE_ROLE_KEY;"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag NEXT_PUBLIC_SUPABASE_URL", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/main.ts",
    content: 'const url = process.env.NEXT_PUBLIC_SUPABASE_URL;'
  });

  assert.deepEqual(matches, []);
});

test("blocks SQL FOR UPDATE TO public USING (true)", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "supabase/migrations/202606260001_public_profiles_update.sql",
    content: [
      'create policy "Public profiles update"',
      "on public.profiles",
      "for update",
      "to public",
      "using (true);"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks SQL FOR DELETE TO anon USING true", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "db/policies/delete_profiles.sql",
    content: [
      'create policy "Public profile delete"',
      "on public.profiles",
      "for delete",
      "to anon",
      "using true;"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks SQL FOR ALL TO public with missing USING", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "policies/public_all.sql",
    content: [
      'create policy "Public everything"',
      "on public.orders",
      "for all",
      "to public",
      "with check (true);"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks Firebase allow write: if true", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "firestore.rules",
    content: [
      "rules_version = '2';",
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /users/{userId} {",
      "      allow write: if true;",
      "    }",
      "  }",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 5);
});

test("blocks Firebase allow update, delete: if true", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "storage.rules",
    content: [
      "rules_version = '2';",
      "service firebase.storage {",
      "  match /b/{bucket}/o {",
      "    match /uploads/{allPaths=**} {",
      "      allow update, delete: if true;",
      "    }",
      "  }",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 5);
});

test("does not block SQL public INSERT", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "supabase/migrations/202606260002_public_insert.sql",
    content: [
      'create policy "Public insert"',
      "on public.orders",
      "for insert",
      "to public",
      "with check (true);"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL FOR UPDATE TO authenticated with auth.uid ownership checks", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "supabase/policies/profile_owner_only.sql",
    content: [
      'create policy "Profile owner update"',
      "on public.profiles",
      "for update",
      "to authenticated",
      "using (auth.uid() = user_id)",
      "with check (auth.uid() = user_id);"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL FOR UPDATE TO public when USING has auth.uid ownership evidence", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "database/profile_owner_mixed.sql",
    content: [
      'create policy "Mixed profile update"',
      "on public.profiles",
      "for update",
      "to public",
      "using (auth.uid() = user_id)",
      "with check true;"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL FOR UPDATE TO anon when WITH CHECK has ownership evidence", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "database/profile_owner_mixed_anon.sql",
    content: [
      'create policy "Anon mixed update"',
      "on public.profiles",
      "for update",
      "to anon",
      "using true",
      "with check (owner_id = auth.uid());"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL FOR DELETE TO public USING custom function", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "db/delete_admin_only.sql",
    content: [
      'create policy "Admin delete"',
      "on public.profiles",
      "for delete",
      "to public",
      "using (is_admin());"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL policy using current_setting", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "policies/current_setting.sql",
    content: [
      'create policy "Tenant update"',
      "on public.accounts",
      "for update",
      "to public",
      "using (current_setting('request.jwt.claim.sub', true) = owner_id)",
      "with check (true);"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL policy using JWT claims or custom function", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "supabase/policies/jwt_claims.sql",
    content: [
      'create policy "JWT delete"',
      "on public.profiles",
      "for delete",
      "to public",
      "using (has_role(auth.jwt(), 'admin'));"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block Firebase allow create: if true", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "firebase.rules",
    content: [
      "rules_version = '2';",
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /users/{userId} {",
      "      allow create: if true;",
      "    }",
      "  }",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block Firebase allow write: if request.auth != null", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "storage.rules",
    content: [
      "rules_version = '2';",
      "service firebase.storage {",
      "  match /b/{bucket}/o {",
      "    match /uploads/{allPaths=**} {",
      "      allow write: if request.auth != null;",
      "    }",
      "  }",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL-like text outside policy target files", () => {
  const matches = matchDestructivePublicDbRules({
    relativePath: "app/api/debug/route.ts",
    content: [
      "const sql = `create policy demo on public.profiles for update to public using (true);`;",
      "export async function GET() {",
      "  return Response.json({ sql });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});
