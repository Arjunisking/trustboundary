export const RULE_IDS = [
  "exposed-secrets",
  "unsafe-mutations",
  "broken-authorization",
  "rls-failures",
  "webhook-and-agent-abuse"
] as const;

export type RuleId = (typeof RULE_IDS)[number];

export interface RuleFile {
  relativePath: string;
  content: string;
}

export interface RuleMatch {
  line: number;
  message: string;
  exploitPath: string;
  patch: string;
}

const EXPOSED_SUPABASE_SERVICE_ROLE_RULE_ID = "exposed-secrets";
const EXPLOIT_PATH =
  "Anyone can extract the key from the browser bundle and bypass database permissions.";
const PATCH =
  "Move the service role key to a server-only module or API route. Remove any client-side reference and use a public anon key in browser code.";

const FRONTEND_PATH_PATTERNS = [
  /^app\//,
  /^pages\//,
  /^components\//,
  /^src\/app\//,
  /^src\/pages\//,
  /^src\/components\//
] as const;

const SERVER_ONLY_PATH_PATTERNS = [
  /^app\/api\//,
  /^pages\/api\//,
  /^src\/app\/api\//,
  /^src\/pages\/api\//,
  /(^|\/)(route|middleware|instrumentation)\.[cm]?[jt]sx?$/,
  /(^|\/)(server|scripts)\//
] as const;

const SERVICE_ROLE_ENV_REF = /\bprocess\.env\.SUPABASE_SERVICE_ROLE_KEY\b/;
const NEXT_PUBLIC_SERVICE_ROLE_MISUSE =
  /\bNEXT_PUBLIC_[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*\b/;
const JWT_LIKE_TOKEN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/;
const SERVICE_ROLE_JWT_MARKERS = /(service_role|c2VydmljZV9yb2xl)/i;
const USE_CLIENT = /^['"]use client['"];?\s*$/m;

function normalizePath(relativePath: string): string {
  return relativePath.replaceAll("\\", "/");
}

function isFrontendPath(relativePath: string): boolean {
  return FRONTEND_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isServerOnlyPath(relativePath: string): boolean {
  return SERVER_ONLY_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isClientSideFile(file: RuleFile): boolean {
  const relativePath = normalizePath(file.relativePath);
  if (isServerOnlyPath(relativePath)) {
    return false;
  }

  return USE_CLIENT.test(file.content) || isFrontendPath(relativePath);
}

function detectLineMatch(line: string): string | null {
  if (SERVICE_ROLE_ENV_REF.test(line)) {
    return "Supabase service role env key referenced in client-side code.";
  }

  if (NEXT_PUBLIC_SERVICE_ROLE_MISUSE.test(line)) {
    return "NEXT_PUBLIC service role key reference exposes privileged Supabase access to the browser.";
  }

  if (JWT_LIKE_TOKEN.test(line) && SERVICE_ROLE_JWT_MARKERS.test(line)) {
    return "Supabase service_role JWT-like token embedded in client-side code.";
  }

  return null;
}

export function matchExposedSupabaseServiceRoleKey(file: RuleFile): RuleMatch[] {
  if (!isClientSideFile(file)) {
    return [];
  }

  const findings: RuleMatch[] = [];
  const lines = file.content.split(/\r?\n/);

  for (const [index, line] of lines.entries()) {
    const message = detectLineMatch(line);
    if (!message) {
      continue;
    }

    findings.push({
      line: index + 1,
      message,
      exploitPath: EXPLOIT_PATH,
      patch: PATCH
    });
  }

  return findings;
}

export const EXPOSED_SUPABASE_SERVICE_ROLE_RULE = {
  ruleId: EXPOSED_SUPABASE_SERVICE_ROLE_RULE_ID,
  matchFile: matchExposedSupabaseServiceRoleKey
};
