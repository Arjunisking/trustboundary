import test from "node:test";
import assert from "node:assert/strict";

import {
  RULE_IDS,
  matchBrokenAuthorization,
  matchExposedSupabaseServiceRoleKey,
  matchWebhookSignatureVerification,
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
  const matches = matchWebhookSignatureVerification({
    relativePath: "app/api/webhooks/stripe-safe/route.ts",
    content: [
      "export async function POST(request: Request) {",
      '  const signature = request.headers.get("stripe-signature");',
      "  const body = await request.text();",
      "  const event = stripe.webhooks.constructEvent(body, signature, STRIPE_WEBHOOK_SECRET);",
      '  await prisma.event.create({ data: { eventId: event.id } });',
      "  return Response.json({ ok: true });",
      "}"
    ].join("\n")
  });

  assert.deepEqual(matches, []);
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
