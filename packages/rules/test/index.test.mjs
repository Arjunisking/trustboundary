import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  matchExposedSupabaseServiceRoleKey,
  matchUnsafeMutation
} from "../dist/index.js";

test("@trustboundary/rules exports V1 rule ids", () => {
  assert.equal(RULE_IDS.length, 5);
  assert.equal(RULE_IDS[0], "exposed-secrets");
  assert.equal(RULE_IDS[1], "unsafe-mutation");
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

test("detects direct request body variable flow into insert and update", () => {
  const matches = matchUnsafeMutation({
    relativePath: "app/api/users/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      '  await supabase.from("users").insert(body);',
      "  const payload = await request.json();",
      '  await supabase.from("profiles").update(payload);',
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 2);
  assert.equal(matches[0]?.line, 3);
  assert.equal(matches[1]?.line, 5);
});

test("detects direct inline request body into upsert and prisma create", () => {
  const matches = matchUnsafeMutation({
    relativePath: "app/api/orders/route.ts",
    content: [
      "export async function POST(request: Request) {",
      '  await supabase.from("orders").upsert(await request.json());',
      "  const data = await req.json();",
      "  await db.user.create({ data });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 2);
  assert.equal(matches[0]?.line, 2);
  assert.equal(matches[1]?.line, 4);
});

test("does not flag validated schema parse or safeParse", () => {
  const matches = matchUnsafeMutation({
    relativePath: "app/api/safe-validated/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      "  const parsed = schema.parse(body);",
      '  await supabase.from("users").insert(parsed);',
      "  const data = await req.json();",
      "  const validated = UserSchema.safeParse(data);",
      "  if (!validated.success) return;",
      "  await db.user.create({ data: validated.data });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag explicit allowlisted object literals", () => {
  const matches = matchUnsafeMutation({
    relativePath: "app/api/safe-allowlist/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      '  await supabase.from("users").insert({ name: body.name, email: body.email });',
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});
