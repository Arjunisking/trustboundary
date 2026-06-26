export const RULE_IDS = ["TB001", "TB002"] as const;

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

export const SCANNER_RULES: ScannerRuleDefinition[] = [
  EXPOSED_SUPABASE_SERVICE_ROLE_RULE,
  DESTRUCTIVE_PUBLIC_DB_RULE
];

