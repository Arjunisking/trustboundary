import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  SCANNER_RULES,
  matchDestructivePublicDbRules,
  matchExposedSupabaseServiceRoleKey
} from "../dist/index.js";

function matchRule(ruleId, file) {
  const rule = SCANNER_RULES.find((candidate) => candidate.ruleId === ruleId);
  assert.ok(rule, `Expected active rule ${ruleId}`);
  return rule.matchFile(file);
}

test("@trustboundary/rules exports TB001, TB002, and TB003 as the only active V1 automated rules", () => {
  assert.deepEqual(RULE_IDS, ["TB001", "TB002", "TB003"]);
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
      },
      {
        ruleId: "TB003",
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
      "const sql = `create policy demo on public.profiles for update to public using (true);` ;",
      "export async function GET() {",
      "  return Response.json({ sql });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("blocks unsigned Stripe webhook route that reads payload and writes to the database", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/webhooks/stripe/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.text();",
      "  await prisma.event.create({ data: { payload: body } });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks unsigned Shopify webhook route that processes payload and mutates billing state", () => {
  const matches = matchRule("TB003", {
    relativePath: "src/app/api/webhooks/shopify/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await billingAccount.update({ data: payload });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks unsigned Clerk webhook route that reads payload and dispatches a job", () => {
  const matches = matchRule("TB003", {
    relativePath: "pages/api/webhooks/clerk.ts",
    content: [
      "export default async function handler(req, res) {",
      "  const body = req.body;",
      "  await userSyncQueue.add('clerk-sync', body);",
      "  res.status(200).json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks unsigned GitHub webhook route that reads payload and calls an external API", () => {
  const matches = matchRule("TB003", {
    relativePath: "pages/api/webhooks/github.ts",
    content: [
      "export default async function handler(req, res) {",
      "  const payload = req.body;",
      '  await fetch("https://api.example.com/sync", { method: "POST", body: JSON.stringify(payload) });',
      "  res.status(200).json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("blocks known provider webhook route with dangerous sink and no signature checks", () => {
  const matches = matchRule("TB003", {
    relativePath: "pages/api/stripe/webhook.ts",
    content: [
      "export default async function handler(req, res) {",
      "  const body = req.body;",
      "  await customerAccount.update({ data: body });",
      "  res.status(200).json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("does not block Stripe webhook route using constructEvent verification", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/webhooks/stripe/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.text();",
      '  const signature = request.headers.get("stripe-signature");',
      "  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET);",
      "  await prisma.event.create({ data: { id: event.id } });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block Shopify webhook route checking x-shopify-hmac-sha256", () => {
  const matches = matchRule("TB003", {
    relativePath: "src/app/api/webhooks/shopify/route.ts",
    content: [
      "import { createHmac, timingSafeEqual } from 'node:crypto';",
      "export async function POST(request: Request) {",
      "  const body = await request.text();",
      '  const signature = request.headers.get("x-shopify-hmac-sha256");',
      "  const digest = createHmac('sha256', process.env.SHOPIFY_WEBHOOK_SECRET).update(body).digest();",
      "  timingSafeEqual(digest, Buffer.from(signature ?? '', 'base64'));",
      "  await billingAccount.update({ data: { body } });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block Clerk webhook route using Svix verification", () => {
  const matches = matchRule("TB003", {
    relativePath: "pages/api/webhooks/clerk.ts",
    content: [
      "import { Webhook } from 'svix';",
      "export default async function handler(req, res) {",
      "  const payload = JSON.stringify(req.body);",
      "  const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);",
      "  wh.verify(payload, {",
      '    "svix-id": req.headers["svix-id"],',
      '    "svix-timestamp": req.headers["svix-timestamp"],',
      '    "svix-signature": req.headers["svix-signature"]',
      "  });",
      "  await userSyncQueue.add('clerk-sync', payload);",
      "  res.status(200).json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block GitHub webhook route checking x-hub-signature-256", () => {
  const matches = matchRule("TB003", {
    relativePath: "pages/api/webhooks/github.ts",
    content: [
      "import { createHmac, timingSafeEqual } from 'node:crypto';",
      "export default async function handler(req, res) {",
      "  const body = JSON.stringify(req.body);",
      '  const signature = req.headers["x-hub-signature-256"];',
      "  const expected = createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET).update(body).digest('hex');",
      "  timingSafeEqual(Buffer.from(expected), Buffer.from(String(signature ?? '')));",
      '  await fetch("https://api.example.com/sync", { method: "POST", body });',
      "  res.status(200).json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block non-webhook API route", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/orders/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await prisma.order.create({ data: payload });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block custom webhook route for unsupported provider", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/webhooks/resend/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await emailJobQueue.enqueue(payload);",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block GET-only webhook-looking route", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/webhooks/stripe/route.ts",
    content: [
      "export async function GET() {",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block provider name in comment only", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/webhooks/orders/route.ts",
    content: [
      "// stripe webhook handler will be added later",
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await prisma.event.create({ data: payload });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block provider SDK import without webhook route evidence", () => {
  const matches = matchRule("TB003", {
    relativePath: "app/api/orders/route.ts",
    content: [
      "import Stripe from 'stripe';",
      "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);",
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await prisma.order.create({ data: payload });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not block SQL and Firebase files under TB003 matcher", () => {
  assert.deepEqual(
    matchRule("TB003", {
      relativePath: "supabase/migrations/202606260001_public_profiles_update.sql",
      content: "create policy demo on public.profiles for update to public using (true);"
    }),
    []
  );
  assert.deepEqual(
    matchRule("TB003", {
      relativePath: "firestore.rules",
      content: "allow write: if true;"
    }),
    []
  );
});

test("TB001 matching remains unchanged alongside TB003 coverage", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "app/page.tsx",
    content: [
      '"use client";',
      'const secret = "sk_live_1234567890abcdef123456";'
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.severity, undefined);
  assert.equal(matches[0]?.confidence, undefined);
});