import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  matchBrokenAuthorization,
  matchExposedSupabaseServiceRoleKey,
  matchRlsFailures,
  matchWebhookSignatureVerification,
  matchUnsafeMutation
} from "../dist/index.js";

test("@trustboundary/rules exports V1 rule ids", () => {
  assert.equal(RULE_IDS.length, 5);
  assert.equal(RULE_IDS[0], "TB001");
  assert.equal(RULE_IDS[1], "unsafe-mutation");
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

test("detects hardcoded GitHub token in Vite client entry", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/main.ts",
    content: 'const token = "ghp_1234567890abcdef1234567890abcdef1234";'
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 1);
});

test("detects client-side JWT-like service_role token with Supabase proof", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "plugins/supabase.client.ts",
    content: [
      'const token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature";',
      'const provider = "supabase";'
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 1);
});

test("detects hardcoded Shopify admin token in Svelte component", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/routes/+page.svelte",
    content: 'const token = "shpat_1234567890abcdef123456";'
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 1);
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

test("does not flag VITE_PUBLIC_CLERK_PUBLISHABLE_KEY", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "src/main.ts",
    content: 'const key = process.env.VITE_PUBLIC_CLERK_PUBLISHABLE_KEY;'
  });

  assert.deepEqual(matches, []);
});

test("does not flag generic JWT without Supabase service_role proof", () => {
  const matches = matchExposedSupabaseServiceRoleKey({
    relativePath: "app/page.tsx",
    content: [
      '"use client";',
      'const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature";'
    ].join("\n")
  });

  assert.deepEqual(matches, []);
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

test("detects unauthenticated Prisma write in Next.js API route", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/projects/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      "  await prisma.project.create({ data: body });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 3);
  assert.equal(matches[0]?.severity, "high");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("detects unauthenticated sensitive database read in Next.js API route", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/reports/route.ts",
    content: [
      "export async function GET() {",
      '  const rows = await supabase.from("reports").select("*");',
      "  return Response.json(rows);",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 2);
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("does not flag route with getServerSession before database access", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/me/route.ts",
    content: [
      'import { getServerSession } from "next-auth";',
      "",
      "export async function GET() {",
      "  const session = await getServerSession();",
      "  if (!session?.user?.id) return Response.json({ error: 'unauthorized' }, { status: 401 });",
      "  return Response.json(await prisma.user.findUnique({ where: { userId: session.user.id } }));",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag route with supabase.auth.getUser before database access", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/profile/route.ts",
    content: [
      "export async function GET() {",
      "  const user = await supabase.auth.getUser();",
      "  if (!user.data.user) return Response.json({ error: 'unauthorized' }, { status: 401 });",
      '  return Response.json(await supabase.from("profiles").select("*").eq("userId", user.data.user.id));',
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag public health route without database sink", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/health/route.ts",
    content: [
      "export async function GET() {",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("flags auth without ownership constraint as likely broken authorization", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/billing/route.ts",
    content: [
      "export async function GET() {",
      "  const session = await getServerSession();",
      "  if (!session?.user?.id) return Response.json({ error: 'unauthorized' }, { status: 401 });",
      "  const invoices = await prisma.invoice.findMany();",
      "  return Response.json(invoices);",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 4);
  assert.equal(matches[0]?.severity, "high");
  assert.equal(matches[0]?.confidence, "likely");
});

test("does not flag insecure webhook route with broken-authorization", () => {
  const matches = matchBrokenAuthorization({
    relativePath: "app/api/webhooks/stripe/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.text();",
      "  await prisma.event.create({ data: { payload: body } });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("detects Stripe webhook raw body and DB write without constructEvent", () => {
  const matches = matchWebhookSignatureVerification({
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
  assert.equal(matches[0]?.line, 3);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("detects generic webhook JSON body and DB mutation without signature verification", () => {
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/webhook/orders/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const payload = await request.json();",
      "  await db.order.update({ data: payload });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 3);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("flags webhook signature header reads without visible verification as likely", () => {
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/webhooks/github/route.ts",
    content: [
      "export async function POST(request: Request) {",
      '  const signature = request.headers.get("x-hub-signature-256");',
      "  const payload = await request.text();",
      '  await fetch("https://example.com/process", { method: "POST", body: payload });',
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 4);
  assert.equal(matches[0]?.severity, "high");
  assert.equal(matches[0]?.confidence, "likely");
});

test("does not flag Stripe webhook with constructEvent before DB write", () => {
  const content = [
    "export async function POST(request: Request) {",
    '  const signature = request.headers.get("stripe-signature");',
    "  const body = await request.text();",
    "  const event = stripe.webhooks.constructEvent(body, signature, STRIPE_WEBHOOK_SECRET);",
    '  await prisma.event.create({ data: { eventId: event.id } });',
    "  return Response.json({ ok: true });",
    "}"
  ].join("\n");
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/webhooks/stripe-safe/route.ts",
    content
  });
  const brokenAuthMatches = matchBrokenAuthorization({
    relativePath: "app/api/webhooks/stripe-safe/route.ts",
    content
  });

  assert.deepEqual(matches, []);
  assert.deepEqual(brokenAuthMatches, []);
});

test("does not flag Clerk/Svix webhook with Webhook.verify before mutation", () => {
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/webhooks/clerk/route.ts",
    content: [
      "export async function POST(request: Request) {",
      '  const svixSignature = request.headers.get("svix-signature");',
      "  const body = await request.text();",
      "  const event = Webhook.verify(body, svixSignature);",
      "  await db.user.update({ data: { lastEventId: event.id } });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag non-webhook API route for signature verification", () => {
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/users/route.ts",
    content: [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      "  await prisma.user.create({ data: body });",
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("detects Supabase policy with USING (true)", () => {
  const matches = matchRlsFailures({
    relativePath: "supabase/migrations/202606190001_public_profiles.sql",
    content: [
      'create policy "Public profiles read"',
      "on public.profiles",
      "for select",
      "using (true);"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 4);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("detects Supabase write policy with WITH CHECK (true)", () => {
  const matches = matchRlsFailures({
    relativePath: "supabase/migrations/202606190002_public_orders_insert.sql",
    content: [
      'create policy "Public orders insert"',
      "on public.orders",
      "for insert",
      "with check (true);"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 4);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("detects Firebase public read and write rule", () => {
  const matches = matchRlsFailures({
    relativePath: "firestore.rules",
    content: [
      "rules_version = '2';",
      "service cloud.firestore {",
      "  match /databases/{database}/documents {",
      "    match /users/{userId} {",
      "      allow read, write: if true;",
      "    }",
      "  }",
      "}"
    ].join("\n")
  });

  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.line, 5);
  assert.equal(matches[0]?.severity, "critical");
  assert.equal(matches[0]?.confidence, "confirmed");
});

test("does not flag Supabase policy scoped to auth.uid() = user_id", () => {
  const matches = matchRlsFailures({
    relativePath: "supabase/policies/profile_owner_only.sql",
    content: [
      'create policy "Profile owner update"',
      "on public.profiles",
      "for update",
      "using (auth.uid() = user_id)",
      "with check (auth.uid() = user_id);"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
});

test("does not flag Firebase rules requiring request.auth != null", () => {
  const matches = matchRlsFailures({
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
