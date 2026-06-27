export const RULE_IDS = ["TB001", "TB002", "TB003"] as const;

export type RuleId = (typeof RULE_IDS)[number];
export type RuleSeverity = "critical" | "high" | "medium" | "low" | "info";
export type RuleConfidence = "confirmed" | "likely" | "unverified";

export interface RuleFile {
  relativePath: string;
  content: string;
}

export interface RuleMatch {
  line: number;
  message: string;
  exploitPath: string;
  patch: string;
  severity?: RuleSeverity;
  confidence?: RuleConfidence;
}

export interface ScannerRuleDefinition {
  ruleId: RuleId;
  severity: RuleSeverity;
  confidence: RuleConfidence;
  matchFile: (file: RuleFile) => RuleMatch[];
}

const TB001_RULE_ID = "TB001";
const TB001_EXPLOIT_PATH =
  "Anyone can extract the secret from browser-delivered code and use privileged access outside intended server-side controls.";
const TB001_PATCH =
  "Move the secret to server-only code or a secret manager. Do not expose service, private, admin, token, or server keys to browser bundles; use publishable or anon keys instead.";

const TB002_RULE_ID = "TB002";
const TB002_EXPLOIT_PATH =
  "An unauthenticated user can modify or delete data because the committed policy text grants destructive public access with a missing or ineffective guard.";
const TB002_PATCH =
  "Restrict destructive public access with explicit auth, ownership, tenant, or provider checks. Do not use literal true guards for UPDATE, DELETE, ALL, or public write rules.";

const TB003_RULE_ID = "TB003";
const TB003_EXPLOIT_PATH =
  "An attacker can forge a provider webhook event and trigger state changes because the route processes webhook payloads without deterministic signature verification evidence.";
const TB003_PATCH =
  "Verify the provider signature in the same route or through a clearly named local verification helper before mutating data, calling external APIs, or dispatching jobs.";

const NEXT_APP_CLIENT_ENTRY_PATH_PATTERNS = [
  /^(?:src\/)?app\/(?:.+\/)?(?:page|layout)\.[cm]?[jt]sx?$/
] as const;
const NEXT_PAGES_CLIENT_PATH_PATTERNS = [/^(?:src\/)?pages\/.+\.[cm]?[jt]sx?$/] as const;
const VITE_CLIENT_ENTRY_PATH_PATTERNS = [
  /^src\/(?:main|app)\.[cm]?[jt]sx?$/,
  /^src\/(?:components|pages|routes|app)\/.+\.(?:[cm]?[jt]sx?|vue|svelte)$/
] as const;
const NUXT_CLIENT_PATH_PATTERNS = [/\.client\.[^/]+$/, /\.vue$/] as const;
const SVELTE_CLIENT_PATH_PATTERNS = [/\.svelte$/] as const;
const SERVER_ONLY_PATH_PATTERNS = [
  /^app\/api\//,
  /^pages\/api\//,
  /^src\/app\/api\//,
  /^src\/pages\/api\//,
  /(^|\/)(route|middleware|instrumentation)\.[cm]?[jt]sx?$/,
  /(^|\/)(server|scripts)\//
] as const;
const SQL_POLICY_TARGET_PATH_PATTERNS = [
  /^supabase\/.+\.sql$/,
  /^database\/.+\.sql$/,
  /^db\/.+\.sql$/,
  /^policies\/.+\.sql$/
] as const;
const FIREBASE_RULE_TARGET_PATH_PATTERNS = [
  /(^|\/)firebase\.rules$/,
  /(^|\/)firestore\.rules$/,
  /(^|\/)storage\.rules$/
] as const;
const TB003_SUPPORTED_ROUTE_PATH_PATTERNS = [
  /^(?:src\/)?app\/api\/.+\/route\.[cm]?[jt]sx?$/,
  /^(?:src\/)?pages\/api\/.+\.[cm]?[jt]sx?$/,
  /^src\/routes\/api\/.+\/\+server\.[cm]?[jt]s$/,
  /^server\/api\/.+\.[cm]?[jt]sx?$/
] as const;

const PUBLIC_ENV_RISKY_IDENTIFIER =
  /\b(?:NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE|ADMIN|TOKEN|API_KEY|SERVER)[A-Z0-9_]*\b/;
const JWT_LIKE_TOKEN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/;
const SUPABASE_SERVICE_ROLE_PROOF =
  /(service_role|SUPABASE_SERVICE_ROLE|supabase|c2VydmljZV9yb2xl)/i;
const STRIPE_LIVE_SECRET_PATTERN = /\b(?:sk_live|rk_live)_[A-Za-z0-9]{10,}\b/;
const GITHUB_TOKEN_PATTERN =
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}\b|\bgithub_pat_[A-Za-z0-9_]{10,}\b/;
const SHOPIFY_ADMIN_TOKEN_PATTERN = /\bshpat_[A-Za-z0-9]{10,}\b/;
const CLERK_SECRET_ASSIGNMENT_PATTERN =
  /\bCLERK_SECRET_KEY\b[^"'\r\n]*["'](?:sk_(?:live|test)_[A-Za-z0-9]{10,})["']/i;
const CLERK_NEARBY_SECRET_PATTERN =
  /\bclerk\b.*\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b|\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b.*\bclerk\b/i;
const USE_CLIENT = /^['"]use client['"];?\s*$/m;

const TB003_WEBHOOK_TOKENS = new Set(["webhook", "webhooks"]);
const TB003_PROVIDERS = ["stripe", "clerk", "shopify", "github"] as const;
type Tb003Provider = (typeof TB003_PROVIDERS)[number];
const TB003_PROVIDER_LABELS: Record<Tb003Provider, string> = {
  stripe: "Stripe",
  clerk: "Clerk",
  shopify: "Shopify",
  github: "GitHub"
};
const TB003_ROUTE_LITERAL_PATTERN = /["'`][^"'`\r\n]*(?:\/api\/|webhooks?)[^"'`\r\n]*["'`]/g;
const TB003_RELATIVE_IMPORT_PATTERN =
  /(?:import[\s\S]*?from\s*["'](\.{1,2}\/[^"']+)["']|require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\))/g;
const TB003_LOCAL_HELPER_MARKER =
  /(verifyWebhook|verifySignature|validateSignature|validateHmac|constructEvent|webhook|signature|hmac|svix|stripe|shopify|github|clerk)/i;
const TB003_PAYLOAD_READ_PATTERNS = [
  /\bawait\s+(?:request|req)\.json\s*\(\s*\)/i,
  /\b(?:request|req)\.json\s*\(\s*\)/i,
  /\bawait\s+(?:request|req)\.text\s*\(\s*\)/i,
  /\b(?:request|req)\.text\s*\(\s*\)/i,
  /\b(?:req|request)\.body\b/i,
  /\bformData\s*\(\s*\)/i,
  /\brawBody\b/i,
  /\b(?:getRawBody|buffer)\s*\(/i
] as const;
const TB003_DANGEROUS_SINK_PATTERNS = [
  /\.(?:insert|update|upsert|delete|create|createMany|save)\s*\(/i,
  /\b[a-z0-9_]*(?:db|database|prisma|supabase|repo|repository|model|table|collection)[a-z0-9_]*\s*\.\s*set\s*\(/i,
  /\bfetch\s*\(\s*["'`]https?:\/\//i,
  /\baxios(?:\.(?:get|post|put|patch|delete))?\s*\(\s*["'`]https?:\/\//i,
  /\b[a-z0-9_]*(?:queue|job|task|worker|workflow)[a-z0-9_]*\s*\.\s*(?:add|enqueue|dispatch|publish|trigger|schedule|send)\s*\(/i,
  /\b[a-z0-9_]*(?:payment|subscription|account|user|member|customer|role|billing)[a-z0-9_]*\s*\.\s*(?:create|update|delete|cancel|refund|grant|revoke)\s*\(/i
] as const;
const TB003_VERIFY_CALL_PATTERN = /\b(?:verify|validate)[A-Za-z0-9_]*(?:Webhook|Signature|Hmac|Event)?\s*\(/i;
const TB003_CRYPTO_VERIFY_PATTERN = /\b(?:createHmac|timingSafeEqual)\s*\(/i;
const TB003_SIGNATURE_INTENT_PATTERN =
  /\b(?:verify|validate)[A-Za-z0-9_]*(?:Webhook|Signature|Hmac|Event)|\b(?:signature|hmac|webhookSecret|webhook_secret)\b/i;

function normalizePath(relativePath: string): string {
  return relativePath.replaceAll("\\", "/");
}

function lineNumberFromIndex(content: string, index: number): number {
  return content.slice(0, index).split(/\r?\n/).length;
}

function isServerOnlyPath(relativePath: string): boolean {
  return SERVER_ONLY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isNextClientEntryPath(relativePath: string): boolean {
  return (
    NEXT_APP_CLIENT_ENTRY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath)) ||
    NEXT_PAGES_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath))
  );
}

function isViteClientEntryPath(relativePath: string): boolean {
  return VITE_CLIENT_ENTRY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isNuxtClientPath(relativePath: string): boolean {
  return NUXT_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isSvelteClientPath(relativePath: string): boolean {
  return SVELTE_CLIENT_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isClientSideFile(file: RuleFile): boolean {
  const relativePath = normalizePath(file.relativePath);
  if (isServerOnlyPath(relativePath)) {
    return false;
  }

  if (USE_CLIENT.test(file.content)) {
    return true;
  }

  return (
    isNextClientEntryPath(relativePath) ||
    isViteClientEntryPath(relativePath) ||
    isNuxtClientPath(relativePath) ||
    isSvelteClientPath(relativePath)
  );
}

function hasNearbySupabaseServiceRoleProof(lines: string[], lineIndex: number): boolean {
  const start = Math.max(0, lineIndex - 2);
  const end = Math.min(lines.length, lineIndex + 3);
  const nearbyText = lines.slice(start, end).join("\n");

  return SUPABASE_SERVICE_ROLE_PROOF.test(nearbyText);
}

function detectKnownSecretMessage(line: string): string | null {
  if (SHOPIFY_ADMIN_TOKEN_PATTERN.test(line)) {
    return "Shopify admin/private token embedded in browser-exposed code.";
  }

  if (GITHUB_TOKEN_PATTERN.test(line)) {
    return "GitHub token embedded in browser-exposed code.";
  }

  if (
    CLERK_SECRET_ASSIGNMENT_PATTERN.test(line) ||
    CLERK_NEARBY_SECRET_PATTERN.test(line)
  ) {
    return "Clerk secret key embedded in browser-exposed code.";
  }

  if (STRIPE_LIVE_SECRET_PATTERN.test(line)) {
    return "Known live secret prefix embedded in browser-exposed code.";
  }

  return null;
}

function detectLineMatch(lines: string[], lineIndex: number): string | null {
  const line = lines[lineIndex] ?? "";

  if (PUBLIC_ENV_RISKY_IDENTIFIER.test(line)) {
    return "Public env identifier exposes server/private secret material to browser code.";
  }

  if (JWT_LIKE_TOKEN.test(line) && hasNearbySupabaseServiceRoleProof(lines, lineIndex)) {
    return "Supabase service_role JWT-like token embedded in browser-exposed code.";
  }

  return detectKnownSecretMessage(line);
}

function isSqlPolicyTargetPath(relativePath: string): boolean {
  return SQL_POLICY_TARGET_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isFirebaseRuleTargetPath(relativePath: string): boolean {
  return FIREBASE_RULE_TARGET_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function createTb002Match(line: number, message: string): RuleMatch {
  return {
    line,
    message,
    exploitPath: TB002_EXPLOIT_PATH,
    patch: TB002_PATCH,
    severity: "critical",
    confidence: "confirmed"
  };
}

function createTb003Match(provider: Tb003Provider, content: string, payloadIndex: number): RuleMatch {
  return {
    line: lineNumberFromIndex(content, payloadIndex),
    message: `${TB003_PROVIDER_LABELS[provider]} webhook route reads payload and reaches a dangerous sink without deterministic signature verification evidence.`,
    exploitPath: TB003_EXPLOIT_PATH,
    patch: TB003_PATCH,
    severity: "critical",
    confidence: "confirmed"
  };
}

function collectPolicyStatements(content: string): Array<{ statement: string; startIndex: number }> {
  const statements: Array<{ statement: string; startIndex: number }> = [];

  for (const match of content.matchAll(/create\s+policy[\s\S]*?(?:;|$)/gi)) {
    statements.push({
      statement: match[0],
      startIndex: match.index ?? 0
    });
  }

  return statements;
}

function hasSafeOrComplexSqlEvidence(statement: string): boolean {
  const normalized = statement.toLowerCase();

  if (
    /\bauth\.uid\s*\(/i.test(statement) ||
    /\brequest\.auth\b/i.test(statement) ||
    /\bcurrent_setting\s*\(/i.test(statement) ||
    /\bauth\.jwt\s*\(/i.test(statement) ||
    /\bjwt\b/i.test(normalized)
  ) {
    return true;
  }

  if (/\b(?:exists|select|join|coalesce|case)\b/i.test(normalized) || /\bin\s*\(/i.test(statement)) {
    return true;
  }

  return /\b(?!using\b)(?!check\b)(?!create\b)(?!policy\b)(?!for\b)(?!to\b)(?!on\b)(?!as\b)[a-z_][a-z0-9_\.]*\s*\(/i.test(statement);
}

function getSqlPolicyMatch(file: RuleFile, statement: string, startIndex: number): RuleMatch | null {
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
  const missingRequiredGuard =
    action === "delete" ? !hasUsing : !hasUsing || !hasWithCheck;

  if (!usingMatch && !withCheckMatch && !missingRequiredGuard) {
    return null;
  }

  if (hasSafeOrComplexSqlEvidence(statement)) {
    return null;
  }

  const relevantIndex = usingMatch?.index ?? withCheckMatch?.index ?? 0;
  const line = lineNumberFromIndex(
    file.content,
    missingRequiredGuard ? startIndex : startIndex + relevantIndex
  );

  return createTb002Match(
    line,
    `Destructive public SQL policy allows ${action?.toUpperCase()} with a missing or ineffective guard.`
  );
}

function collectSqlPolicyFindings(file: RuleFile): RuleMatch[] {
  const findings: RuleMatch[] = [];

  for (const { statement, startIndex } of collectPolicyStatements(file.content)) {
    const finding = getSqlPolicyMatch(file, statement, startIndex);
    if (finding) {
      findings.push(finding);
    }
  }

  return findings;
}

function collectFirebaseRuleFindings(file: RuleFile): RuleMatch[] {
  const findings: RuleMatch[] = [];

  for (const match of file.content.matchAll(/allow\s+([^:]+)\s*:\s*if\s+true\s*;/g)) {
    const actions = (match[1] ?? "")
      .split(",")
      .map((action) => action.trim())
      .filter(Boolean);

    if (!actions.some((action) => action === "write" || action === "update" || action === "delete")) {
      continue;
    }

    findings.push(
      createTb002Match(
        lineNumberFromIndex(file.content, match.index ?? 0),
        "Firebase rule allows destructive public writes with literal true."
      )
    );
  }

  return findings;
}

function isTb003SupportedRouteFile(relativePath: string): boolean {
  return TB003_SUPPORTED_ROUTE_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function tokenizeWebhookEvidence(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}

function getKnownWebhookProvider(value: string): Tb003Provider | null {
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

function getTb003RouteProvider(file: RuleFile): Tb003Provider | null {
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

function findFirstMatchIndex(content: string, patterns: readonly RegExp[]): number {
  let earliestIndex = Number.POSITIVE_INFINITY;

  for (const pattern of patterns) {
    const match = pattern.exec(content);
    if ((match?.index ?? Number.POSITIVE_INFINITY) < earliestIndex) {
      earliestIndex = match?.index ?? Number.POSITIVE_INFINITY;
    }
  }

  return Number.isFinite(earliestIndex) ? earliestIndex : -1;
}

function hasRelativeVerificationHelperImport(content: string): boolean {
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

function hasStripeVerification(content: string): boolean {
  if (/(?:^|\W)(?:constructEvent\(|webhooks\.constructEvent\(|stripe\.webhooks\.constructEvent\()/i.test(content)) {
    return true;
  }

  return /stripe-signature/i.test(content) && (TB003_CRYPTO_VERIFY_PATTERN.test(content) || TB003_VERIFY_CALL_PATTERN.test(content));
}

function hasClerkVerification(content: string): boolean {
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

function hasShopifyVerification(content: string): boolean {
  if (/\bauthenticate\.webhook\s*\(/i.test(content)) {
    return true;
  }

  if (/\bvalidateHmac\s*\(/i.test(content) || /\bshopify\.webhooks\.validate\s*\(/i.test(content)) {
    return true;
  }

  return /x-shopify-hmac-sha256/i.test(content) && TB003_CRYPTO_VERIFY_PATTERN.test(content);
}

function hasGithubVerification(content: string): boolean {
  if (/x-hub-signature-256/i.test(content) && /createHmac\s*\(/i.test(content) && /timingSafeEqual\s*\(/i.test(content)) {
    return true;
  }

  return /x-hub-signature-256/i.test(content) && /\bverify[A-Za-z0-9_]*(?:Signature|Hmac)\s*\(/i.test(content);
}

function hasPlausibleCustomVerificationIntent(provider: Tb003Provider, content: string): boolean {
  const providerMarkers: Record<Tb003Provider, RegExp> = {
    stripe: /stripe-signature|constructEvent|STRIPE_WEBHOOK_SECRET/i,
    clerk: /svix-(?:id|timestamp|signature)|CLERK_WEBHOOK_SECRET|verifyWebhook/i,
    shopify: /x-shopify-hmac-sha256|SHOPIFY_WEBHOOK_SECRET|validateHmac/i,
    github: /x-hub-signature-256|GITHUB_WEBHOOK_SECRET|verify[A-Za-z0-9_]*(?:Signature|Hmac)/i
  };

  return providerMarkers[provider].test(content) && TB003_SIGNATURE_INTENT_PATTERN.test(content);
}

function hasProviderVerification(provider: Tb003Provider, content: string): boolean {
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

export function matchExposedSupabaseServiceRoleKey(file: RuleFile): RuleMatch[] {
  if (!isClientSideFile(file)) {
    return [];
  }

  const findings: RuleMatch[] = [];
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

export function matchDestructivePublicDbRules(file: RuleFile): RuleMatch[] {
  const relativePath = normalizePath(file.relativePath);

  if (isSqlPolicyTargetPath(relativePath)) {
    return collectSqlPolicyFindings(file);
  }

  if (isFirebaseRuleTargetPath(relativePath)) {
    return collectFirebaseRuleFindings(file);
  }

  return [];
}

export function matchUnsignedKnownProviderWebhook(file: RuleFile): RuleMatch[] {
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

export const EXPOSED_SUPABASE_SERVICE_ROLE_RULE: ScannerRuleDefinition = {
  ruleId: TB001_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchExposedSupabaseServiceRoleKey
};

export const DESTRUCTIVE_PUBLIC_DB_RULE: ScannerRuleDefinition = {
  ruleId: TB002_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchDestructivePublicDbRules
};

export const UNSIGNED_KNOWN_PROVIDER_WEBHOOK_RULE: ScannerRuleDefinition = {
  ruleId: TB003_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchUnsignedKnownProviderWebhook
};

export const SCANNER_RULES: ScannerRuleDefinition[] = [
  EXPOSED_SUPABASE_SERVICE_ROLE_RULE,
  DESTRUCTIVE_PUBLIC_DB_RULE,
  UNSIGNED_KNOWN_PROVIDER_WEBHOOK_RULE
];