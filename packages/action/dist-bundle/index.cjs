#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/index.ts
var import_promises2 = require("node:fs/promises");
var import_node_path2 = __toESM(require("node:path"), 1);

// ../core/dist/index.js
var import_promises = require("node:fs/promises");
var import_node_path = __toESM(require("node:path"), 1);

// ../rules/dist/index.js
var TB001_RULE_ID = "TB001";
var TB001_EXPLOIT_PATH = "Anyone can extract the secret from browser-delivered code and use privileged access outside intended server-side controls.";
var TB001_PATCH = "Move the secret to server-only code or a secret manager. Do not expose service, private, admin, token, or server keys to browser bundles; use publishable or anon keys instead.";
var TB002_RULE_ID = "TB002";
var TB002_EXPLOIT_PATH = "An unauthenticated user can modify or delete data because the committed policy text grants destructive public access with a missing or ineffective guard.";
var TB002_PATCH = "Restrict destructive public access with explicit auth, ownership, tenant, or provider checks. Do not use literal true guards for UPDATE, DELETE, ALL, or public write rules.";
var TB003_RULE_ID = "TB003";
var TB003_EXPLOIT_PATH = "An attacker can forge a provider webhook event and trigger state changes because the route processes webhook payloads without deterministic signature verification evidence.";
var TB003_PATCH = "Verify the provider signature in the same route or through a clearly named local verification helper before mutating data, calling external APIs, or dispatching jobs.";
var NEXT_APP_CLIENT_ENTRY_PATH_PATTERNS = [
  /^(?:src\/)?app\/(?:.+\/)?(?:page|layout)\.[cm]?[jt]sx?$/
];
var NEXT_PAGES_CLIENT_PATH_PATTERNS = [/^(?:src\/)?pages\/.+\.[cm]?[jt]sx?$/];
var VITE_CLIENT_ENTRY_PATH_PATTERNS = [
  /^src\/(?:main|app)\.[cm]?[jt]sx?$/,
  /^src\/(?:components|pages|routes|app)\/.+\.(?:[cm]?[jt]sx?|vue|svelte)$/
];
var NUXT_CLIENT_PATH_PATTERNS = [/\.client\.[^/]+$/, /\.vue$/];
var SVELTE_CLIENT_PATH_PATTERNS = [/\.svelte$/];
var SERVER_ONLY_PATH_PATTERNS = [
  /^app\/api\//,
  /^pages\/api\//,
  /^src\/app\/api\//,
  /^src\/pages\/api\//,
  /(^|\/)(route|middleware|instrumentation)\.[cm]?[jt]sx?$/,
  /(^|\/)(server|scripts)\//
];
var SQL_POLICY_TARGET_PATH_PATTERNS = [
  /^supabase\/.+\.sql$/,
  /^database\/.+\.sql$/,
  /^db\/.+\.sql$/,
  /^policies\/.+\.sql$/
];
var FIREBASE_RULE_TARGET_PATH_PATTERNS = [
  /(^|\/)firebase\.rules$/,
  /(^|\/)firestore\.rules$/,
  /(^|\/)storage\.rules$/
];
var TB003_SUPPORTED_ROUTE_PATH_PATTERNS = [
  /^(?:src\/)?app\/api\/.+\/route\.[cm]?[jt]sx?$/,
  /^(?:src\/)?pages\/api\/.+\.[cm]?[jt]sx?$/,
  /^src\/routes\/api\/.+\/\+server\.[cm]?[jt]s$/,
  /^server\/api\/.+\.[cm]?[jt]sx?$/
];
var PUBLIC_ENV_RISKY_IDENTIFIER = /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|ADMIN|TOKEN|API_KEY|SERVER)[A-Z0-9_]*\b/;
var JWT_LIKE_TOKEN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/;
var SUPABASE_SERVICE_ROLE_PROOF = /(service_role|SUPABASE_SERVICE_ROLE|supabase|c2VydmljZV9yb2xl)/i;
var STRIPE_LIVE_SECRET_PATTERN = /\b(?:sk_live|rk_live)_[A-Za-z0-9]{10,}\b/;
var GITHUB_TOKEN_PATTERN = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}\b|\bgithub_pat_[A-Za-z0-9_]{10,}\b/;
var SHOPIFY_ADMIN_TOKEN_PATTERN = /\bshpat_[A-Za-z0-9]{10,}\b/;
var CLERK_SECRET_ASSIGNMENT_PATTERN = /\bCLERK_SECRET_KEY\b[^"'\r\n]*["'](?:sk_(?:live|test)_[A-Za-z0-9]{10,})["']/i;
var CLERK_NEARBY_SECRET_PATTERN = /\bclerk\b.*\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b|\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b.*\bclerk\b/i;
var USE_CLIENT = /^['"]use client['"];?\s*$/m;
var TB003_WEBHOOK_TOKENS = /* @__PURE__ */ new Set(["webhook", "webhooks"]);
var TB003_PROVIDERS = ["stripe", "clerk", "shopify", "github"];
var TB003_PROVIDER_LABELS = {
  stripe: "Stripe",
  clerk: "Clerk",
  shopify: "Shopify",
  github: "GitHub"
};
var TB003_ROUTE_LITERAL_PATTERN = /["'`][^"'`\r\n]*(?:\/api\/|webhooks?)[^"'`\r\n]*["'`]/g;
var TB003_RELATIVE_IMPORT_PATTERN = /(?:import[\s\S]*?from\s*["'](\.{1,2}\/[^"']+)["']|require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\))/g;
var TB003_LOCAL_HELPER_MARKER = /(verifyWebhook|verifySignature|validateSignature|validateHmac|constructEvent|webhook|signature|hmac|svix|stripe|shopify|github|clerk)/i;
var TB003_PAYLOAD_READ_PATTERNS = [
  /\bawait\s+(?:request|req)\.json\s*\(\s*\)/i,
  /\b(?:request|req)\.json\s*\(\s*\)/i,
  /\bawait\s+(?:request|req)\.text\s*\(\s*\)/i,
  /\b(?:request|req)\.text\s*\(\s*\)/i,
  /\b(?:req|request)\.body\b/i,
  /\bformData\s*\(\s*\)/i,
  /\brawBody\b/i,
  /\b(?:getRawBody|buffer)\s*\(/i
];
var TB003_DANGEROUS_SINK_PATTERNS = [
  /\.(?:insert|update|upsert|delete|create|createMany|save)\s*\(/i,
  /\b[a-z0-9_]*(?:db|database|prisma|supabase|repo|repository|model|table|collection)[a-z0-9_]*\s*\.\s*set\s*\(/i,
  /\bfetch\s*\(\s*["'`]https?:\/\//i,
  /\baxios(?:\.(?:get|post|put|patch|delete))?\s*\(\s*["'`]https?:\/\//i,
  /\b[a-z0-9_]*(?:queue|job|task|worker|workflow)[a-z0-9_]*\s*\.\s*(?:add|enqueue|dispatch|publish|trigger|schedule|send)\s*\(/i,
  /\b[a-z0-9_]*(?:payment|subscription|account|user|member|customer|role|billing)[a-z0-9_]*\s*\.\s*(?:create|update|delete|cancel|refund|grant|revoke)\s*\(/i
];
var TB003_VERIFY_CALL_PATTERN = /\b(?:verify|validate)[A-Za-z0-9_]*(?:Webhook|Signature|Hmac|Event)?\s*\(/i;
var TB003_CRYPTO_VERIFY_PATTERN = /\b(?:createHmac|timingSafeEqual)\s*\(/i;
var TB003_SIGNATURE_INTENT_PATTERN = /\b(?:verify|validate)[A-Za-z0-9_]*(?:Webhook|Signature|Hmac|Event)|\b(?:signature|hmac|webhookSecret|webhook_secret)\b/i;
function normalizePath(relativePath) {
  return relativePath.replaceAll("\\", "/");
}
function lineNumberFromIndex(content, index) {
  return content.slice(0, index).split(/\r?\n/).length;
}
function isServerOnlyPath(relativePath) {
  return SERVER_ONLY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isNextClientEntryPath(relativePath) {
  return NEXT_APP_CLIENT_ENTRY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath)) || NEXT_PAGES_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isViteClientEntryPath(relativePath) {
  return VITE_CLIENT_ENTRY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isNuxtClientPath(relativePath) {
  return NUXT_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isSvelteClientPath(relativePath) {
  return SVELTE_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isClientSideFile(file) {
  const relativePath = normalizePath(file.relativePath);
  if (isServerOnlyPath(relativePath)) {
    return false;
  }
  if (USE_CLIENT.test(file.content)) {
    return true;
  }
  return isNextClientEntryPath(relativePath) || isViteClientEntryPath(relativePath) || isNuxtClientPath(relativePath) || isSvelteClientPath(relativePath);
}
function hasNearbySupabaseServiceRoleProof(lines, lineIndex) {
  const start = Math.max(0, lineIndex - 2);
  const end = Math.min(lines.length, lineIndex + 3);
  const nearbyText = lines.slice(start, end).join("\n");
  return SUPABASE_SERVICE_ROLE_PROOF.test(nearbyText);
}
function detectKnownSecretMessage(line) {
  if (SHOPIFY_ADMIN_TOKEN_PATTERN.test(line)) {
    return "Shopify admin/private token embedded in browser-exposed code.";
  }
  if (GITHUB_TOKEN_PATTERN.test(line)) {
    return "GitHub token embedded in browser-exposed code.";
  }
  if (CLERK_SECRET_ASSIGNMENT_PATTERN.test(line) || CLERK_NEARBY_SECRET_PATTERN.test(line)) {
    return "Clerk secret key embedded in browser-exposed code.";
  }
  if (STRIPE_LIVE_SECRET_PATTERN.test(line)) {
    return "Known live secret prefix embedded in browser-exposed code.";
  }
  return null;
}
function detectLineMatch(lines, lineIndex) {
  const line = lines[lineIndex] ?? "";
  if (PUBLIC_ENV_RISKY_IDENTIFIER.test(line)) {
    return "Public env identifier exposes server/private secret material to browser code.";
  }
  if (JWT_LIKE_TOKEN.test(line) && hasNearbySupabaseServiceRoleProof(lines, lineIndex)) {
    return "Supabase service_role JWT-like token embedded in browser-exposed code.";
  }
  return detectKnownSecretMessage(line);
}
function isSqlPolicyTargetPath(relativePath) {
  return SQL_POLICY_TARGET_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function isFirebaseRuleTargetPath(relativePath) {
  return FIREBASE_RULE_TARGET_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function createTb002Match(line, message) {
  return {
    line,
    message,
    exploitPath: TB002_EXPLOIT_PATH,
    patch: TB002_PATCH,
    severity: "critical",
    confidence: "confirmed"
  };
}
function createTb003Match(provider, content, payloadIndex) {
  return {
    line: lineNumberFromIndex(content, payloadIndex),
    message: `${TB003_PROVIDER_LABELS[provider]} webhook route reads payload and reaches a dangerous sink without deterministic signature verification evidence.`,
    exploitPath: TB003_EXPLOIT_PATH,
    patch: TB003_PATCH,
    severity: "critical",
    confidence: "confirmed"
  };
}
function collectPolicyStatements(content) {
  const statements = [];
  for (const match of content.matchAll(/create\s+policy[\s\S]*?(?:;|$)/gi)) {
    statements.push({
      statement: match[0],
      startIndex: match.index ?? 0
    });
  }
  return statements;
}
function hasSafeOrComplexSqlEvidence(statement) {
  const normalized = statement.toLowerCase();
  if (/\bauth\.uid\s*\(/i.test(statement) || /\brequest\.auth\b/i.test(statement) || /\bcurrent_setting\s*\(/i.test(statement) || /\bauth\.jwt\s*\(/i.test(statement) || /\bjwt\b/i.test(normalized)) {
    return true;
  }
  if (/\b(?:exists|select|join|coalesce|case)\b/i.test(normalized) || /\bin\s*\(/i.test(statement)) {
    return true;
  }
  return /\b(?!using\b)(?!check\b)(?!create\b)(?!policy\b)(?!for\b)(?!to\b)(?!on\b)(?!as\b)[a-z_][a-z0-9_\.]*\s*\(/i.test(statement);
}
function getSqlPolicyMatch(file, statement, startIndex) {
  if ((statement.match(/create\s+policy/gi)?.length ?? 0) !== 1) {
    return null;
  }
  const actionMatch = statement.match(/\bfor\s+(update|delete|all)\b/i);
  if (!actionMatch) {
    return null;
  }
  if (!/\bto\s+[^;]*\b(?:public|anon)\b/i.test(statement)) {
    return null;
  }
  const action = actionMatch[1]?.toLowerCase();
  const usingMatch = statement.match(/\busing\s*(?:\(\s*true\s*\)|true\b)/i);
  const withCheckMatch = statement.match(/\bwith\s+check\s*(?:\(\s*true\s*\)|true\b)/i);
  const hasUsing = /\busing\b/i.test(statement);
  const hasWithCheck = /\bwith\s+check\b/i.test(statement);
  const missingRequiredGuard = action === "delete" ? !hasUsing : !hasUsing || !hasWithCheck;
  if (!usingMatch && !withCheckMatch && !missingRequiredGuard) {
    return null;
  }
  if (hasSafeOrComplexSqlEvidence(statement)) {
    return null;
  }
  const relevantIndex = usingMatch?.index ?? withCheckMatch?.index ?? 0;
  const line = lineNumberFromIndex(file.content, missingRequiredGuard ? startIndex : startIndex + relevantIndex);
  return createTb002Match(line, `Destructive public SQL policy allows ${action?.toUpperCase()} with a missing or ineffective guard.`);
}
function collectSqlPolicyFindings(file) {
  const findings = [];
  for (const { statement, startIndex } of collectPolicyStatements(file.content)) {
    const finding = getSqlPolicyMatch(file, statement, startIndex);
    if (finding) {
      findings.push(finding);
    }
  }
  return findings;
}
function collectFirebaseRuleFindings(file) {
  const findings = [];
  for (const match of file.content.matchAll(/allow\s+([^:]+)\s*:\s*if\s+true\s*;/g)) {
    const actions = (match[1] ?? "").split(",").map((action) => action.trim()).filter(Boolean);
    if (!actions.some((action) => action === "write" || action === "update" || action === "delete")) {
      continue;
    }
    findings.push(createTb002Match(lineNumberFromIndex(file.content, match.index ?? 0), "Firebase rule allows destructive public writes with literal true."));
  }
  return findings;
}
function isTb003SupportedRouteFile(relativePath) {
  return TB003_SUPPORTED_ROUTE_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function tokenizeWebhookEvidence(value) {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
function getKnownWebhookProvider(value) {
  const tokens = tokenizeWebhookEvidence(value);
  if (!tokens.some((token) => TB003_WEBHOOK_TOKENS.has(token))) {
    return null;
  }
  for (const provider of TB003_PROVIDERS) {
    if (tokens.includes(provider)) {
      return provider;
    }
  }
  return null;
}
function getTb003RouteProvider(file) {
  const relativePath = normalizePath(file.relativePath);
  if (!isTb003SupportedRouteFile(relativePath)) {
    return null;
  }
  const providerFromPath = getKnownWebhookProvider(relativePath);
  if (providerFromPath) {
    return providerFromPath;
  }
  for (const match of file.content.matchAll(TB003_ROUTE_LITERAL_PATTERN)) {
    const providerFromLiteral = getKnownWebhookProvider(match[0]);
    if (providerFromLiteral) {
      return providerFromLiteral;
    }
  }
  return null;
}
function findFirstMatchIndex(content, patterns) {
  let earliestIndex = Number.POSITIVE_INFINITY;
  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if ((match?.index ?? Number.POSITIVE_INFINITY) < earliestIndex) {
      earliestIndex = match?.index ?? Number.POSITIVE_INFINITY;
    }
  }
  return Number.isFinite(earliestIndex) ? earliestIndex : -1;
}
function hasRelativeVerificationHelperImport(content) {
  for (const match of content.matchAll(TB003_RELATIVE_IMPORT_PATTERN)) {
    const snippet = match[0] ?? "";
    const importPath = match[1] ?? match[2] ?? "";
    if (!importPath.startsWith("./") && !importPath.startsWith("../")) {
      continue;
    }
    if (TB003_LOCAL_HELPER_MARKER.test(snippet)) {
      return true;
    }
  }
  return false;
}
function hasStripeVerification(content) {
  if (/(?:^|\W)(?:constructEvent\(|webhooks\.constructEvent\(|stripe\.webhooks\.constructEvent\()/i.test(content)) {
    return true;
  }
  return /stripe-signature/i.test(content) && (TB003_CRYPTO_VERIFY_PATTERN.test(content) || TB003_VERIFY_CALL_PATTERN.test(content));
}
function hasClerkVerification(content) {
  if (/\bverifyWebhook\s*\(/i.test(content)) {
    return true;
  }
  const hasSvixWebhook = /(from\s+["']svix["']|require\(\s*["']svix["']\s*\))/i.test(content) && /\bWebhook\s*\(/i.test(content) && /\.verify\s*\(/i.test(content);
  if (hasSvixWebhook) {
    return true;
  }
  const hasSvixHeaders = /svix-id/i.test(content) || /svix-timestamp/i.test(content) || /svix-signature/i.test(content);
  return hasSvixHeaders && (TB003_VERIFY_CALL_PATTERN.test(content) || /\.verify\s*\(/i.test(content));
}
function hasShopifyVerification(content) {
  if (/\bauthenticate\.webhook\s*\(/i.test(content)) {
    return true;
  }
  if (/\bvalidateHmac\s*\(/i.test(content) || /\bshopify\.webhooks\.validate\s*\(/i.test(content)) {
    return true;
  }
  return /x-shopify-hmac-sha256/i.test(content) && TB003_CRYPTO_VERIFY_PATTERN.test(content);
}
function hasGithubVerification(content) {
  if (/x-hub-signature-256/i.test(content) && /createHmac\s*\(/i.test(content) && /timingSafeEqual\s*\(/i.test(content)) {
    return true;
  }
  return /x-hub-signature-256/i.test(content) && /\bverify[A-Za-z0-9_]*(?:Signature|Hmac)\s*\(/i.test(content);
}
function hasPlausibleCustomVerificationIntent(provider, content) {
  const providerMarkers = {
    stripe: /stripe-signature|constructEvent|STRIPE_WEBHOOK_SECRET/i,
    clerk: /svix-(?:id|timestamp|signature)|CLERK_WEBHOOK_SECRET|verifyWebhook/i,
    shopify: /x-shopify-hmac-sha256|SHOPIFY_WEBHOOK_SECRET|validateHmac/i,
    github: /x-hub-signature-256|GITHUB_WEBHOOK_SECRET|verify[A-Za-z0-9_]*(?:Signature|Hmac)/i
  };
  return providerMarkers[provider].test(content) && TB003_SIGNATURE_INTENT_PATTERN.test(content);
}
function hasProviderVerification(provider, content) {
  switch (provider) {
    case "stripe":
      return hasStripeVerification(content);
    case "clerk":
      return hasClerkVerification(content);
    case "shopify":
      return hasShopifyVerification(content);
    case "github":
      return hasGithubVerification(content);
  }
}
function matchExposedSupabaseServiceRoleKey(file) {
  if (!isClientSideFile(file)) {
    return [];
  }
  const findings = [];
  const lines = file.content.split(/\r?\n/);
  for (const [index] of lines.entries()) {
    const message = detectLineMatch(lines, index);
    if (!message) {
      continue;
    }
    findings.push({
      line: index + 1,
      message,
      exploitPath: TB001_EXPLOIT_PATH,
      patch: TB001_PATCH
    });
  }
  return findings;
}
function matchDestructivePublicDbRules(file) {
  const relativePath = normalizePath(file.relativePath);
  if (isSqlPolicyTargetPath(relativePath)) {
    return collectSqlPolicyFindings(file);
  }
  if (isFirebaseRuleTargetPath(relativePath)) {
    return collectFirebaseRuleFindings(file);
  }
  return [];
}
function matchUnsignedKnownProviderWebhook(file) {
  const provider = getTb003RouteProvider(file);
  if (!provider) {
    return [];
  }
  const payloadIndex = findFirstMatchIndex(file.content, TB003_PAYLOAD_READ_PATTERNS);
  if (payloadIndex === -1) {
    return [];
  }
  const dangerousSinkIndex = findFirstMatchIndex(file.content, TB003_DANGEROUS_SINK_PATTERNS);
  if (dangerousSinkIndex === -1 || dangerousSinkIndex < payloadIndex) {
    return [];
  }
  if (hasRelativeVerificationHelperImport(file.content)) {
    return [];
  }
  if (hasProviderVerification(provider, file.content)) {
    return [];
  }
  if (hasPlausibleCustomVerificationIntent(provider, file.content)) {
    return [];
  }
  return [createTb003Match(provider, file.content, payloadIndex)];
}
var EXPOSED_SUPABASE_SERVICE_ROLE_RULE = {
  ruleId: TB001_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchExposedSupabaseServiceRoleKey
};
var DESTRUCTIVE_PUBLIC_DB_RULE = {
  ruleId: TB002_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchDestructivePublicDbRules
};
var UNSIGNED_KNOWN_PROVIDER_WEBHOOK_RULE = {
  ruleId: TB003_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchUnsignedKnownProviderWebhook
};
var SCANNER_RULES = [
  EXPOSED_SUPABASE_SERVICE_ROLE_RULE,
  DESTRUCTIVE_PUBLIC_DB_RULE,
  UNSIGNED_KNOWN_PROVIDER_WEBHOOK_RULE
];

// ../core/dist/index.js
var NO_CONFIRMED_CRITICAL_MESSAGE = "No Confirmed Critical issues found.";
var SOURCE_FILE_PATTERN = /\.[cm]?[jt]sx?$/;
var SQL_FILE_PATTERN = /\.sql$/;
var FIREBASE_RULE_FILE_PATTERN = /(^|\/)(firestore|firebase|storage)\.rules$/;
var SKIPPED_DIRECTORIES = /* @__PURE__ */ new Set([
  ".git",
  ".next",
  "coverage",
  "dist",
  "node_modules"
]);
var DEFAULT_IGNORED_PATH_PATTERNS = [
  /^docs\//i,
  /(^|\/)README[^/]*$/i,
  /^examples\//i,
  /^fixtures\//i,
  /(^|\/)[^/]*tests[^/]*\//i,
  /(^|\/)__tests__\//i,
  /\.test\.[^/]+$/i,
  /\.spec\.[^/]+$/i,
  /(^|\/)cypress\//i,
  /(^|\/)playwright\//i
];
async function walkFiles(rootPath, options = {}) {
  const normalizedRoot = import_node_path.default.resolve(rootPath);
  const entries = await walkDirectory(normalizedRoot, normalizedRoot);
  return entries.filter((entry) => isScannableFilePath(entry.relativePath) && !isIgnoredPath(entry.relativePath, options));
}
async function walkDirectory(rootPath, currentPath) {
  const directoryEntries = await (0, import_promises.readdir)(currentPath, { withFileTypes: true });
  const collected = [];
  for (const entry of directoryEntries) {
    if (SKIPPED_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const absolutePath = import_node_path.default.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      collected.push(...await walkDirectory(rootPath, absolutePath));
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const content = await (0, import_promises.readFile)(absolutePath, "utf8");
    collected.push({
      absolutePath,
      relativePath: import_node_path.default.relative(rootPath, absolutePath).replaceAll("\\", "/"),
      content
    });
  }
  return collected;
}
function isScannableFilePath(relativePath) {
  return SOURCE_FILE_PATTERN.test(relativePath) || SQL_FILE_PATTERN.test(relativePath) || FIREBASE_RULE_FILE_PATTERN.test(relativePath);
}
function isIgnoredPath(relativePath, options) {
  if (options.useDefaultIgnorePaths === false) {
    return false;
  }
  return DEFAULT_IGNORED_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}
function createFindingId(ruleId, relativePath, line) {
  return `${ruleId}:${relativePath}:${line}`;
}
async function scanRepository(rootPath, options = {}) {
  const files = await walkFiles(rootPath, options);
  const findings = [];
  for (const file of files) {
    for (const rule of SCANNER_RULES) {
      const matches = rule.matchFile({
        relativePath: file.relativePath,
        content: file.content
      });
      for (const match of matches) {
        findings.push({
          id: createFindingId(rule.ruleId, file.relativePath, match.line),
          ruleId: rule.ruleId,
          severity: match.severity ?? rule.severity,
          confidence: match.confidence ?? rule.confidence,
          file: file.relativePath,
          line: match.line,
          message: match.message,
          exploitPath: match.exploitPath,
          patch: match.patch
        });
      }
    }
  }
  return findings.sort((left, right) => {
    const fileCompare = left.file.localeCompare(right.file);
    if (fileCompare !== 0) {
      return fileCompare;
    }
    const lineCompare = (left.line ?? 0) - (right.line ?? 0);
    if (lineCompare !== 0) {
      return lineCompare;
    }
    return left.ruleId.localeCompare(right.ruleId);
  });
}
function getConfirmedCriticalFindings(findings) {
  return findings.filter((finding) => finding.severity === "critical" && finding.confidence === "confirmed");
}
function summarizeFindings(findings) {
  const confirmedCriticalCount = getConfirmedCriticalFindings(findings).length;
  return {
    totalFindings: findings.length,
    confirmedCriticalCount,
    blocking: confirmedCriticalCount > 0,
    statusMessage: confirmedCriticalCount > 0 ? `Confirmed Critical findings: ${confirmedCriticalCount}` : NO_CONFIRMED_CRITICAL_MESSAGE
  };
}

// ../report/dist/index.js
function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}
function renderSummaryList(summary, targetPath) {
  return [
    '<dl class="summary-grid">',
    `<div><dt>Target</dt><dd>${escapeHtml(targetPath)}</dd></div>`,
    `<div><dt>Total findings</dt><dd>${summary.totalFindings}</dd></div>`,
    `<div><dt>Confirmed Critical</dt><dd>${summary.confirmedCriticalCount}</dd></div>`,
    `<div><dt>Status</dt><dd>${escapeHtml(summary.statusMessage)}</dd></div>`,
    "</dl>"
  ].join("");
}
function renderFindingCard(finding) {
  return [
    '<article class="finding-card">',
    `<h3>${escapeHtml(finding.id)}</h3>`,
    '<dl class="finding-grid">',
    `<div><dt>ruleId</dt><dd>${escapeHtml(finding.ruleId)}</dd></div>`,
    `<div><dt>severity</dt><dd>${escapeHtml(finding.severity)}</dd></div>`,
    `<div><dt>confidence</dt><dd>${escapeHtml(finding.confidence)}</dd></div>`,
    `<div><dt>file</dt><dd>${escapeHtml(finding.file)}</dd></div>`,
    `<div><dt>line</dt><dd>${finding.line ?? ""}</dd></div>`,
    `<div><dt>message</dt><dd>${escapeHtml(finding.message)}</dd></div>`,
    `<div><dt>exploitPath</dt><dd>${escapeHtml(finding.exploitPath ?? "")}</dd></div>`,
    `<div><dt>patch</dt><dd>${escapeHtml(finding.patch ?? "")}</dd></div>`,
    "</dl>",
    "</article>"
  ].join("");
}
function renderHtmlReport(input) {
  const title = input.findings.length > 0 ? `TrustBoundary findings: ${input.summary.totalFindings}` : "No Confirmed Critical issues found";
  const findingsMarkup = input.findings.map((finding) => {
    return renderFindingCard(finding);
  }).join("");
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(title)}</title>`,
    "<style>",
    ":root { color-scheme: light; font-family: Georgia, 'Times New Roman', serif; }",
    "body { margin: 0; background: #f4efe7; color: #1a1714; }",
    "main { max-width: 980px; margin: 0 auto; padding: 40px 20px 64px; }",
    "h1, h2, h3 { margin: 0; }",
    "p { line-height: 1.5; }",
    ".hero { background: linear-gradient(135deg, #fff8ec, #f3dfc3); border: 1px solid #d6b98e; border-radius: 20px; padding: 24px; box-shadow: 0 18px 40px rgba(66, 38, 8, 0.08); }",
    ".status { margin-top: 16px; font-weight: 700; }",
    ".summary-grid, .finding-grid { display: grid; gap: 12px; }",
    ".summary-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin: 24px 0 0; }",
    ".summary-grid div, .finding-grid div { background: rgba(255,255,255,0.7); border: 1px solid #dcc4a2; border-radius: 14px; padding: 12px; }",
    "dt { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #7a6043; }",
    "dd { margin: 8px 0 0; font-weight: 600; white-space: pre-wrap; overflow-wrap: anywhere; }",
    ".section { margin-top: 28px; }",
    ".finding-list { display: grid; gap: 16px; }",
    ".finding-card { background: #fffdf9; border: 1px solid #d9c09e; border-radius: 18px; padding: 18px; }",
    ".finding-card h3 { font-size: 18px; margin-bottom: 14px; }",
    ".empty { background: #fffdf9; border: 1px dashed #b89b73; border-radius: 16px; padding: 18px; }",
    "</style>",
    "</head>",
    "<body>",
    "<main>",
    '<section class="hero">',
    `<h1>${escapeHtml(title)}</h1>`,
    "<p>Deterministic repository evidence scan. This report is limited in scope and not a full assessment.</p>",
    `<p class="status">${escapeHtml(input.summary.statusMessage)}</p>`,
    renderSummaryList(input.summary, input.targetPath),
    "</section>",
    '<section class="section">',
    "<h2>Findings</h2>",
    input.findings.length === 0 ? `<div class="empty">${escapeHtml("No Confirmed Critical issues found.")}</div>` : `<div class="finding-list">${findingsMarkup}</div>`,
    "</section>",
    "</main>",
    "</body>",
    "</html>"
  ].join("");
}

// src/index.ts
function parseBooleanInput(value, fallback) {
  if (value === void 0 || value.trim() === "") {
    return fallback;
  }
  return value.trim().toLowerCase() !== "false";
}
function parseActionInputs(env = process.env) {
  const workspace = env.GITHUB_WORKSPACE ? import_node_path2.default.resolve(env.GITHUB_WORKSPACE) : process.cwd();
  const rawTargetPath = env.INPUT_TARGET_PATH?.trim() || ".";
  return {
    targetPath: import_node_path2.default.resolve(workspace, rawTargetPath),
    enforce: parseBooleanInput(env.INPUT_ENFORCE, true),
    ...env.INPUT_REPORT_PATH?.trim() ? {
      reportPath: import_node_path2.default.resolve(workspace, env.INPUT_REPORT_PATH.trim())
    } : {}
  };
}
async function runAction(inputs) {
  const findings = await scanRepository(inputs.targetPath);
  const summary = summarizeFindings(findings);
  const blocked = inputs.enforce && summary.blocking;
  let reportPath;
  if (inputs.reportPath) {
    reportPath = import_node_path2.default.resolve(inputs.reportPath);
    await (0, import_promises2.mkdir)(import_node_path2.default.dirname(reportPath), { recursive: true });
    await (0, import_promises2.writeFile)(
      reportPath,
      renderHtmlReport({
        targetPath: inputs.targetPath,
        summary,
        findings
      }),
      "utf8"
    );
  }
  return {
    targetPath: inputs.targetPath,
    summary,
    findings,
    enforcementEnabled: inputs.enforce,
    blocked,
    ...reportPath ? { reportPath } : {},
    exitCode: blocked ? 1 : 0
  };
}
function createActionOutputs(result) {
  return {
    total_findings: String(result.summary.totalFindings),
    confirmed_critical_count: String(result.summary.confirmedCriticalCount),
    blocked: String(result.blocked),
    ...result.reportPath ? { report_path: result.reportPath } : {}
  };
}
async function writeActionOutputs(outputs, outputFilePath) {
  if (!outputFilePath) {
    return;
  }
  const lines = Object.entries(outputs).map(([key, value]) => `${key}=${value}`);
  await (0, import_promises2.appendFile)(outputFilePath, `${lines.join("\n")}
`, "utf8");
}
function formatActionSummary(result) {
  const lines = [
    "TrustBoundary action complete.",
    `Target: ${result.targetPath}`,
    `Findings: ${result.summary.totalFindings}`,
    `Confirmed Critical: ${result.summary.confirmedCriticalCount}`,
    result.summary.blocking ? result.summary.statusMessage : NO_CONFIRMED_CRITICAL_MESSAGE
  ];
  if (result.findings.length > 0) {
    lines.push("");
    lines.push("Findings:");
    for (const finding of result.findings) {
      lines.push(
        `- ${finding.id} ${finding.file}:${finding.line ?? "?"} ${finding.message}`
      );
    }
  }
  return lines.join("\n");
}

// src/bin.ts
async function main() {
  const inputs = parseActionInputs(process.env);
  const result = await runAction(inputs);
  await writeActionOutputs(createActionOutputs(result), process.env.GITHUB_OUTPUT);
  process.stdout.write(`${formatActionSummary(result)}
`);
  process.exitCode = result.exitCode;
}
main().catch((error) => {
  const message = error instanceof Error ? error.message : "Unknown action error";
  process.stderr.write(`${message}
`);
  process.exitCode = 1;
});
