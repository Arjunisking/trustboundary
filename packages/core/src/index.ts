import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { SCANNER_RULES } from "@trustboundary/rules";

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

export interface ScanSummary {
  totalFindings: number;
  confirmedCriticalCount: number;
  blocking: boolean;
  statusMessage: string;
}

export interface ScanFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

export const NO_FINDINGS: Finding[] = [];
export const NO_CONFIRMED_CRITICAL_MESSAGE = "No Confirmed Critical issues found.";

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
    for (const rule of SCANNER_RULES) {
      const matches = rule.matchFile({
        relativePath: file.relativePath,
        content: file.content
      });

      for (const match of matches) {
        findings.push({
          id: createFindingId(rule.ruleId, file.relativePath, match.line),
          ruleId: rule.ruleId,
          severity: rule.severity,
          confidence: rule.confidence,
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

export function getConfirmedCriticalFindings(findings: Finding[]): Finding[] {
  return findings.filter(
    (finding) =>
      finding.severity === "critical" && finding.confidence === "confirmed"
  );
}

export function summarizeFindings(findings: Finding[]): ScanSummary {
  const confirmedCriticalCount = getConfirmedCriticalFindings(findings).length;

  return {
    totalFindings: findings.length,
    confirmedCriticalCount,
    blocking: confirmedCriticalCount > 0,
    statusMessage:
      confirmedCriticalCount > 0
        ? `Confirmed Critical findings: ${confirmedCriticalCount}`
        : NO_CONFIRMED_CRITICAL_MESSAGE
  };
}
