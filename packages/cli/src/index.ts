import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  type Finding,
  type ScanSummary,
  NO_CONFIRMED_CRITICAL_MESSAGE,
  scanRepository,
  summarizeFindings
} from "@trustboundary/core";
import { renderHtmlReport } from "@trustboundary/report";

export interface ScanCommandOptions {
  enforce?: boolean;
  json?: boolean;
  reportPath?: string;
}

export interface CliScanResult {
  targetPath: string;
  summary: ScanSummary;
  findings: Finding[];
  hasBlockingFindings: boolean;
  enforcementEnabled: boolean;
  reportPath?: string;
  exitCode: number;
}

export async function runScanCommand(
  targetPath: string,
  options: ScanCommandOptions = {}
): Promise<CliScanResult> {
  const findings = await scanRepository(targetPath);
  const summary = summarizeFindings(findings);
  const enforcementEnabled = options.enforce ?? false;
  let reportPath: string | undefined;

  if (options.reportPath) {
    reportPath = path.resolve(options.reportPath);
    await mkdir(path.dirname(reportPath), { recursive: true });
    await writeFile(
      reportPath,
      renderHtmlReport({
        targetPath,
        summary,
        findings
      }),
      "utf8"
    );
  }

  return {
    targetPath,
    summary,
    findings,
    hasBlockingFindings: summary.blocking,
    enforcementEnabled,
    ...(reportPath ? { reportPath } : {}),
    exitCode: enforcementEnabled && summary.blocking ? 1 : 0
  };
}

export function formatHumanSummary(result: CliScanResult): string {
  const lines = [
    "TrustBoundary scan complete.",
    `Target: ${result.targetPath}`,
    `Findings: ${result.summary.totalFindings}`,
    `Confirmed Critical: ${result.summary.confirmedCriticalCount}`,
    result.summary.blocking
      ? result.summary.statusMessage
      : NO_CONFIRMED_CRITICAL_MESSAGE
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

  if (result.reportPath) {
    lines.push("");
    lines.push(`Report written: ${result.reportPath}`);
  }

  return lines.join("\n");
}

export function formatJsonResult(result: CliScanResult): string {
  return JSON.stringify(result, null, 2);
}

export interface ParsedCliArgs {
  command: "scan";
  targetPath: string;
  options: ScanCommandOptions;
}

export function parseCliArgs(argv: string[]): ParsedCliArgs {
  const [command, targetPath, ...rest] = argv;

  if (command !== "scan" || !targetPath) {
    throw new Error(
      "Usage: trustboundary scan <target-directory> [--json] [--report <file>] [--enforce]"
    );
  }

  const options: ScanCommandOptions = {};

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];

    if (arg === "--json") {
      options.json = true;
      continue;
    }

    if (arg === "--enforce") {
      options.enforce = true;
      continue;
    }

    if (arg === "--report") {
      const reportPath = rest[index + 1];
      if (!reportPath) {
        throw new Error("--report requires a file path");
      }
      options.reportPath = reportPath;
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return {
    command: "scan",
    targetPath,
    options
  };
}
