import ts from "typescript";

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
  severity?: RuleSeverity;
  confidence?: RuleConfidence;
}

export interface ScannerRuleDefinition {
  ruleId: RuleId;
  severity: RuleSeverity;
  confidence: RuleConfidence;
  matchFile: (file: RuleFile) => RuleMatch[];
}

interface HandlerCandidate {
  body: ts.ConciseBody;
  name: string;
}

interface ControlMarker {
  position: number;
  admin: boolean;
}

interface SensitiveSink {
  end: number;
  line: number;
  node: ts.Node;
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
const BROKEN_AUTHORIZATION_RULE_ID = "broken-authorization";
const BROKEN_AUTHORIZATION_NO_AUTH_EXPLOIT_PATH =
  "An attacker can call the route directly and reach a sensitive database operation without a visible server-side auth gate.";
const BROKEN_AUTHORIZATION_NO_AUTH_PATCH =
  "Add a server-side auth check such as getServerSession, auth(), requireAuth, or supabase.auth.getUser before the database read or write.";
const BROKEN_AUTHORIZATION_OWNERSHIP_EXPLOIT_PATH =
  "An authenticated attacker can read or mutate another user's records when the handler lacks an ownership or tenant constraint.";
const BROKEN_AUTHORIZATION_OWNERSHIP_PATCH =
  "Scope the query or mutation with userId, ownerId, tenantId, orgId, organizationId, or createdBy, or require an explicit admin guard.";

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

const API_ROUTE_PATH_PATTERNS = [
  /^(?:src\/)?app\/api(?:\/.+)?\/route\.tsx?$/
] as const;

const HTTP_HANDLER_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const AUTH_CONTROL_NAMES = new Set([
  "getServerSession",
  "auth",
  "currentUser",
  "clerkClient",
  "requireAuth",
  "requireUser",
  "requireAdmin",
  "getUser",
  "getSession"
]);
const ADMIN_AUTH_CONTROL_NAMES = new Set(["requireAdmin"]);
const OWNERSHIP_CONTROL_NAMES = new Set([
  "userId",
  "ownerId",
  "tenantId",
  "orgId",
  "organizationId",
  "createdBy"
]);
const PRISMA_DB_METHOD_NAMES = new Set([
  "findUnique",
  "findUniqueOrThrow",
  "findFirst",
  "findFirstOrThrow",
  "findMany",
  "count",
  "aggregate",
  "groupBy",
  "create",
  "createMany",
  "update",
  "updateMany",
  "upsert",
  "delete",
  "deleteMany",
  "queryRaw",
  "$queryRaw",
  "$queryRawUnsafe",
  "executeRaw",
  "$executeRaw",
  "$executeRawUnsafe"
]);
const SUPABASE_SINK_METHOD_NAMES = new Set([
  "select",
  "single",
  "maybeSingle",
  "insert",
  "update",
  "upsert",
  "delete"
]);

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

function getScriptKind(relativePath: string): ts.ScriptKind {
  if (relativePath.endsWith(".tsx")) {
    return ts.ScriptKind.TSX;
  }

  if (relativePath.endsWith(".jsx")) {
    return ts.ScriptKind.JSX;
  }

  if (relativePath.endsWith(".js")) {
    return ts.ScriptKind.JS;
  }

  return ts.ScriptKind.TS;
}

function createSourceFile(file: RuleFile): ts.SourceFile {
  const normalizedPath = normalizePath(file.relativePath);

  return ts.createSourceFile(
    normalizedPath,
    file.content,
    ts.ScriptTarget.Latest,
    true,
    getScriptKind(normalizedPath)
  );
}

function isBrokenAuthorizationTargetPath(relativePath: string): boolean {
  return API_ROUTE_PATH_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function isDirectiveStatement(
  statement: ts.Statement | ts.Expression
): statement is ts.ExpressionStatement {
  return (
    ts.isExpressionStatement(statement) &&
    ts.isStringLiteral(statement.expression) &&
    statement.expression.text === "use server"
  );
}

function hasFileLevelUseServerDirective(sourceFile: ts.SourceFile): boolean {
  return sourceFile.statements.some((statement) => isDirectiveStatement(statement));
}

function hasFunctionLevelUseServerDirective(body: ts.ConciseBody): boolean {
  return (
    ts.isBlock(body) &&
    body.statements.length > 0 &&
    isDirectiveStatement(body.statements[0]!)
  );
}

function hasExportModifier(node: ts.Node): boolean {
  return (ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Export) !== 0;
}

function isAsyncFunctionLike(node: ts.FunctionLikeDeclarationBase): boolean {
  return (ts.getCombinedModifierFlags(node as ts.Declaration) & ts.ModifierFlags.Async) !== 0;
}

function getHandlerName(name: ts.PropertyName | ts.BindingName | undefined): string | null {
  return name && ts.isIdentifier(name) ? name.text : null;
}

function getExportedApiHandlers(sourceFile: ts.SourceFile): HandlerCandidate[] {
  const handlers: HandlerCandidate[] = [];

  for (const statement of sourceFile.statements) {
    if (
      ts.isFunctionDeclaration(statement) &&
      hasExportModifier(statement) &&
      statement.name &&
      HTTP_HANDLER_NAMES.has(statement.name.text) &&
      statement.body
    ) {
      handlers.push({
        name: statement.name.text,
        body: statement.body
      });
      continue;
    }

    if (!ts.isVariableStatement(statement) || !hasExportModifier(statement)) {
      continue;
    }

    for (const declaration of statement.declarationList.declarations) {
      const handlerName = getHandlerName(declaration.name);
      const initializer = declaration.initializer;
      if (!handlerName || !HTTP_HANDLER_NAMES.has(handlerName) || !initializer) {
        continue;
      }

      if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
        handlers.push({
          name: handlerName,
          body: initializer.body
        });
      }
    }
  }

  return handlers;
}

function getExportedServerActions(sourceFile: ts.SourceFile): HandlerCandidate[] {
  const handlers: HandlerCandidate[] = [];
  const fileLevelUseServer = hasFileLevelUseServerDirective(sourceFile);

  for (const statement of sourceFile.statements) {
    if (
      ts.isFunctionDeclaration(statement) &&
      hasExportModifier(statement) &&
      statement.body &&
      isAsyncFunctionLike(statement) &&
      (fileLevelUseServer || hasFunctionLevelUseServerDirective(statement.body))
    ) {
      handlers.push({
        name: statement.name?.text ?? "default",
        body: statement.body
      });
      continue;
    }

    if (!ts.isVariableStatement(statement) || !hasExportModifier(statement)) {
      continue;
    }

    for (const declaration of statement.declarationList.declarations) {
      const handlerName = getHandlerName(declaration.name);
      const initializer = declaration.initializer;
      if (!handlerName || !initializer) {
        continue;
      }

      if (
        (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) &&
        isAsyncFunctionLike(initializer) &&
        (fileLevelUseServer || hasFunctionLevelUseServerDirective(initializer.body))
      ) {
        handlers.push({
          name: handlerName,
          body: initializer.body
        });
      }
    }
  }

  return handlers;
}

function getIdentifierChain(expression: ts.Expression): string[] {
  const names: string[] = [];
  let current: ts.Expression = expression;

  while (true) {
    if (ts.isPropertyAccessExpression(current)) {
      names.unshift(current.name.text);
      current = current.expression;
      continue;
    }

    if (ts.isCallExpression(current)) {
      current = current.expression;
      continue;
    }

    if (ts.isElementAccessExpression(current)) {
      current = current.expression;
      continue;
    }

    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current)) {
      current = current.expression;
      continue;
    }

    if (ts.isIdentifier(current)) {
      names.unshift(current.text);
    }

    return names;
  }
}

function getCallBaseIdentifier(node: ts.CallExpression): string | null {
  const names = getIdentifierChain(node.expression);
  return names[0] ?? null;
}

function getCallTerminalName(node: ts.CallExpression): string | null {
  const names = getIdentifierChain(node.expression);
  return names.at(-1) ?? null;
}

function isSupabaseFromChain(node: ts.CallExpression): boolean {
  const names = getIdentifierChain(node.expression);
  return (
    (names[0] === "supabase" || names[0] === "createClient") && names.includes("from")
  );
}

function isSupabaseAuthGetUserCall(node: ts.CallExpression): boolean {
  const names = getIdentifierChain(node.expression);
  return names[0] === "supabase" && names.includes("auth") && names.at(-1) === "getUser";
}

function isSqlSink(
  node: ts.CallExpression | ts.TaggedTemplateExpression
): boolean {
  const expression = ts.isCallExpression(node) ? node.expression : node.tag;
  const names = getIdentifierChain(expression);
  return names[0]?.startsWith("sql") ?? false;
}

function getSensitiveSinkNode(node: ts.Node): SensitiveSink | null {
  const line =
    node.getSourceFile().getLineAndCharacterOfPosition(node.getStart()).line + 1;
  const end = getContainingStatementEnd(node);

  if (ts.isTaggedTemplateExpression(node) && isSqlSink(node)) {
    return {
      node,
      line,
      end
    };
  }

  if (!ts.isCallExpression(node)) {
    return null;
  }

  const baseIdentifier = getCallBaseIdentifier(node);
  const terminalName = getCallTerminalName(node);

  if (isSupabaseAuthGetUserCall(node)) {
    return null;
  }

  if (isSupabaseFromChain(node) && terminalName && SUPABASE_SINK_METHOD_NAMES.has(terminalName)) {
    return {
      node,
      line,
      end
    };
  }

  if (
    (baseIdentifier === "prisma" || baseIdentifier === "db") &&
    terminalName &&
    PRISMA_DB_METHOD_NAMES.has(terminalName)
  ) {
    return {
      node,
      line,
      end
    };
  }

  if (isSqlSink(node)) {
    return {
      node,
      line,
      end
    };
  }

  return null;
}

function getContainingStatementEnd(node: ts.Node): number {
  let current: ts.Node | undefined = node;

  while (current) {
    if (ts.isStatement(current)) {
      return current.getEnd();
    }

    current = current.parent;
  }

  return node.getEnd();
}

function collectSensitiveSinks(body: ts.ConciseBody): SensitiveSink[] {
  const sinks: SensitiveSink[] = [];
  const seenPositions = new Set<number>();

  function visit(node: ts.Node): void {
    const sink = getSensitiveSinkNode(node);
    if (sink && !seenPositions.has(sink.node.getStart())) {
      seenPositions.add(sink.node.getStart());
      sinks.push(sink);
    }

    ts.forEachChild(node, visit);
  }

  visit(body);

  return sinks.sort((left, right) => left.node.getStart() - right.node.getStart());
}

function collectAuthControls(body: ts.ConciseBody): ControlMarker[] {
  const controls: ControlMarker[] = [];

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      const baseIdentifier = getCallBaseIdentifier(node);
      const terminalName = getCallTerminalName(node);

      if (isSupabaseAuthGetUserCall(node)) {
        controls.push({
          position: node.getStart(),
          admin: false
        });
      } else if (
        baseIdentifier === "clerkClient" ||
        (terminalName !== null && AUTH_CONTROL_NAMES.has(terminalName))
      ) {
        controls.push({
          position: node.getStart(),
          admin: terminalName !== null && ADMIN_AUTH_CONTROL_NAMES.has(terminalName)
        });
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(body);

  return controls.sort((left, right) => left.position - right.position);
}

function getOwnershipMarkerText(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) {
    return node.text;
  }

  if (
    ts.isStringLiteral(node) ||
    ts.isNoSubstitutionTemplateLiteral(node) ||
    ts.isPrivateIdentifier(node)
  ) {
    return node.text;
  }

  return null;
}

function collectOwnershipMarkers(body: ts.ConciseBody): number[] {
  const markers: number[] = [];

  function visit(node: ts.Node): void {
    const markerText = getOwnershipMarkerText(node);
    if (markerText && OWNERSHIP_CONTROL_NAMES.has(markerText)) {
      markers.push(node.getStart());
    }

    ts.forEachChild(node, visit);
  }

  visit(body);

  return markers.sort((left, right) => left - right);
}

function createBrokenAuthorizationNoAuthMatch(line: number): RuleMatch {
  return {
    line,
    message:
      "Sensitive database read or write is reachable without a visible auth control in this handler.",
    exploitPath: BROKEN_AUTHORIZATION_NO_AUTH_EXPLOIT_PATH,
    patch: BROKEN_AUTHORIZATION_NO_AUTH_PATCH,
    severity: "high",
    confidence: "confirmed"
  };
}

function createBrokenAuthorizationOwnershipMatch(line: number): RuleMatch {
  return {
    line,
    message:
      "Handler authenticates the caller but reaches a sensitive database read or write without an ownership or tenant constraint.",
    exploitPath: BROKEN_AUTHORIZATION_OWNERSHIP_EXPLOIT_PATH,
    patch: BROKEN_AUTHORIZATION_OWNERSHIP_PATCH,
    severity: "high",
    confidence: "likely"
  };
}

function analyzeHandlerAuthorization(handler: HandlerCandidate): RuleMatch[] {
  const sinks = collectSensitiveSinks(handler.body);
  if (sinks.length === 0) {
    return [];
  }

  const controls = collectAuthControls(handler.body);
  const ownershipMarkers = collectOwnershipMarkers(handler.body);
  const findings: RuleMatch[] = [];

  for (const sink of sinks) {
    const authBeforeSink = controls.some((control) => control.position < sink.node.getStart());
    if (!authBeforeSink) {
      findings.push(createBrokenAuthorizationNoAuthMatch(sink.line));
      continue;
    }

    const adminAuthBeforeSink = controls.some(
      (control) => control.admin && control.position < sink.node.getStart()
    );
    if (adminAuthBeforeSink) {
      continue;
    }

    const ownershipBeforeSink = ownershipMarkers.some((position) => position < sink.end);
    if (!ownershipBeforeSink) {
      findings.push(createBrokenAuthorizationOwnershipMatch(sink.line));
    }
  }

  return findings;
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

export function matchBrokenAuthorization(file: RuleFile): RuleMatch[] {
  const sourceFile = createSourceFile(file);
  const relativePath = normalizePath(file.relativePath);
  const isRouteFile = isBrokenAuthorizationTargetPath(relativePath);
  const isServerActionFile = hasFileLevelUseServerDirective(sourceFile);

  if (!isRouteFile && !isServerActionFile) {
    return [];
  }

  const handlers = isRouteFile
    ? getExportedApiHandlers(sourceFile)
    : getExportedServerActions(sourceFile);

  const findings: RuleMatch[] = [];
  const seenKeys = new Set<string>();

  for (const handler of handlers) {
    for (const finding of analyzeHandlerAuthorization(handler)) {
      const key = `${handler.name}:${finding.line}:${finding.message}`;
      if (seenKeys.has(key)) {
        continue;
      }

      seenKeys.add(key);
      findings.push(finding);
    }
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

export const BROKEN_AUTHORIZATION_RULE: ScannerRuleDefinition = {
  ruleId: BROKEN_AUTHORIZATION_RULE_ID,
  severity: "high",
  confidence: "likely",
  matchFile: matchBrokenAuthorization
};

export const SCANNER_RULES: ScannerRuleDefinition[] = [
  EXPOSED_SUPABASE_SERVICE_ROLE_RULE,
  UNSAFE_MUTATION_RULE,
  BROKEN_AUTHORIZATION_RULE
];
