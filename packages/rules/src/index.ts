export const RULE_IDS = [
  "exposed-secrets",
  "unsafe-mutation",
  "broken-authorization",
  "rls-failures",
  "webhook-and-agent-abuse"
] as const;

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
}

export interface ScannerRuleDefinition {
  ruleId: RuleId;
  severity: RuleSeverity;
  confidence: RuleConfidence;
  matchFile: (file: RuleFile) => RuleMatch[];
}

const EXPOSED_SUPABASE_SERVICE_ROLE_RULE_ID = "exposed-secrets";
const EXPLOIT_PATH =
  "Anyone can extract the key from the browser bundle and bypass database permissions.";
const PATCH =
  "Move the service role key to a server-only module or API route. Remove any client-side reference and use a public anon key in browser code.";
const UNSAFE_MUTATION_RULE_ID = "unsafe-mutation";
const UNSAFE_MUTATION_EXPLOIT_PATH =
  "An attacker can send unexpected fields in the request body and mutate database records without validation or allowlisting.";
const UNSAFE_MUTATION_PATCH =
  "Validate and allowlist request body fields before passing data into create, update, insert, or upsert.";

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
const REQUEST_BODY_SOURCE =
  /(?:await\s+(?:request|req|event\.request)\.json\(\)|(?:request|req)\.body)/;
const REQUEST_BODY_ASSIGNMENT =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(await\s+(?:request|req|event\.request)\.json\(\)|(?:request|req)\.body)\s*;?/g;
const DIRECT_MUTATION_CALL = new RegExp(
  String.raw`\.(insert|update|upsert)\(\s*(await\s+(?:request|req|event\.request)\.json\(\)|(?:request|req)\.body|[A-Za-z_$][\w$]*)\s*\)`,
  "g"
);
const CREATE_DATA_MUTATION_CALL = new RegExp(
  String.raw`\.(create|createMany)\(\s*\{\s*data\s*:\s*(await\s+(?:request|req|event\.request)\.json\(\)|(?:request|req)\.body|[A-Za-z_$][\w$]*)\s*[,}]`,
  "g"
);
const CREATE_DATA_SHORTHAND_MUTATION_CALL = new RegExp(
  String.raw`\.(create|createMany)\(\s*\{\s*data\s*\}\s*\)`,
  "g"
);

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

function lineNumberFromIndex(content: string, index: number): number {
  return content.slice(0, index).split(/\r?\n/).length;
}

function collectUnsafeRequestBodyVariables(content: string): Set<string> {
  const unsafeVariables = new Set<string>();

  for (const match of content.matchAll(REQUEST_BODY_ASSIGNMENT)) {
    const variableName = match[1];
    if (variableName) {
      unsafeVariables.add(variableName);
    }
  }

  return unsafeVariables;
}

function isUnsafeMutationSource(
  source: string,
  unsafeVariables: Set<string>
): boolean {
  return REQUEST_BODY_SOURCE.test(source) || unsafeVariables.has(source);
}

function createUnsafeMutationMatch(
  content: string,
  index: number
): RuleMatch {
  return {
    line: lineNumberFromIndex(content, index),
    message:
      "Request body flows directly into a database mutation without visible validation or allowlisting.",
    exploitPath: UNSAFE_MUTATION_EXPLOIT_PATH,
    patch: UNSAFE_MUTATION_PATCH
  };
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

export function matchUnsafeMutation(file: RuleFile): RuleMatch[] {
  const unsafeVariables = collectUnsafeRequestBodyVariables(file.content);
  const findings: RuleMatch[] = [];
  const seenLines = new Set<number>();

  for (const match of file.content.matchAll(DIRECT_MUTATION_CALL)) {
    const source = match[2];
    const matchIndex = match.index ?? 0;
    if (!source || !isUnsafeMutationSource(source, unsafeVariables)) {
      continue;
    }

    const finding = createUnsafeMutationMatch(file.content, matchIndex);
    if (seenLines.has(finding.line)) {
      continue;
    }
    seenLines.add(finding.line);
    findings.push(finding);
  }

  for (const match of file.content.matchAll(CREATE_DATA_MUTATION_CALL)) {
    const source = match[2];
    const matchIndex = match.index ?? 0;
    if (!source || !isUnsafeMutationSource(source, unsafeVariables)) {
      continue;
    }

    const finding = createUnsafeMutationMatch(file.content, matchIndex);
    if (seenLines.has(finding.line)) {
      continue;
    }
    seenLines.add(finding.line);
    findings.push(finding);
  }

  for (const match of file.content.matchAll(CREATE_DATA_SHORTHAND_MUTATION_CALL)) {
    const matchIndex = match.index ?? 0;
    if (!unsafeVariables.has("data")) {
      continue;
    }

    const finding = createUnsafeMutationMatch(file.content, matchIndex);
    if (seenLines.has(finding.line)) {
      continue;
    }
    seenLines.add(finding.line);
    findings.push(finding);
  }

  return findings;
}

export const EXPOSED_SUPABASE_SERVICE_ROLE_RULE: ScannerRuleDefinition = {
  ruleId: EXPOSED_SUPABASE_SERVICE_ROLE_RULE_ID,
  severity: "critical",
  confidence: "confirmed",
  matchFile: matchExposedSupabaseServiceRoleKey
};

export const UNSAFE_MUTATION_RULE: ScannerRuleDefinition = {
  ruleId: UNSAFE_MUTATION_RULE_ID,
  severity: "high",
  confidence: "likely",
  matchFile: matchUnsafeMutation
};

export const SCANNER_RULES: ScannerRuleDefinition[] = [
  EXPOSED_SUPABASE_SERVICE_ROLE_RULE,
  UNSAFE_MUTATION_RULE
];
