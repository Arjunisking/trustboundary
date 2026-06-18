import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { EXPOSED_SUPABASE_SERVICE_ROLE_RULE } from "@trustboundary/rules";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "confirmed" | "likely" | "unverified";

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line?: number;
  message: string;
  exploitPath?: string;
  patch?: string;
}

export interface RuleResult {
  ruleId: string;
  findings: Finding[];
}

export interface ScanFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

export const NO_FINDINGS: Finding[] = [];

const TEXT_FILE_PATTERN = /\.[cm]?[jt]sx?$/;
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".next",
  "coverage",
  "dist",
  "node_modules"
]);

export async function walkFiles(rootPath: string): Promise<ScanFile[]> {
  const normalizedRoot = path.resolve(rootPath);
  const entries = await walkDirectory(normalizedRoot, normalizedRoot);

  return entries.filter((entry) => TEXT_FILE_PATTERN.test(entry.relativePath));
}

async function walkDirectory(
  rootPath: string,
  currentPath: string
): Promise<ScanFile[]> {
  const directoryEntries = await readdir(currentPath, { withFileTypes: true });
  const collected: ScanFile[] = [];

  for (const entry of directoryEntries) {
    if (SKIPPED_DIRECTORIES.has(entry.name)) {
      continue;
    }

    const absolutePath = path.join(currentPath, entry.name);

    if (entry.isDirectory()) {
      collected.push(...(await walkDirectory(rootPath, absolutePath)));
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const content = await readFile(absolutePath, "utf8");
    collected.push({
      absolutePath,
      relativePath: path.relative(rootPath, absolutePath).replaceAll("\\", "/"),
      content
    });
  }

  return collected;
}

function createFindingId(ruleId: string, relativePath: string, line: number): string {
  return `${ruleId}:${relativePath}:${line}`;
}

export async function scanRepository(rootPath: string): Promise<Finding[]> {
  const files = await walkFiles(rootPath);
  const findings: Finding[] = [];

  for (const file of files) {
    const matches = EXPOSED_SUPABASE_SERVICE_ROLE_RULE.matchFile({
      relativePath: file.relativePath,
      content: file.content
    });

    for (const match of matches) {
      findings.push({
        id: createFindingId(
          EXPOSED_SUPABASE_SERVICE_ROLE_RULE.ruleId,
          file.relativePath,
          match.line
        ),
        ruleId: EXPOSED_SUPABASE_SERVICE_ROLE_RULE.ruleId,
        severity: "critical",
        confidence: "confirmed",
        file: file.relativePath,
        line: match.line,
        message: match.message,
        exploitPath: match.exploitPath,
        patch: match.patch
      });
    }
  }

  return findings;
}
