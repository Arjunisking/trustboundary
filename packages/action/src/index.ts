import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  NO_CONFIRMED_CRITICAL_MESSAGE,
  scanRepository,
  summarizeFindings,
  type Finding,
  type ScanSummary
} from "@trustboundary/core";
import { renderHtmlReport } from "@trustboundary/report";

export interface ActionInputs {
  targetPath: string;
  enforce: boolean;
  reportPath?: string;
}

export interface ActionResult {
  targetPath: string;
  summary: ScanSummary;
  findings: Finding[];
  enforcementEnabled: boolean;
  blocked: boolean;
  reportPath?: string;
  exitCode: number;
}

export function parseBooleanInput(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === "") {
    return fallback;
  }

  return value.trim().toLowerCase() !== "false";
}

export function parseActionInputs(
  env: NodeJS.ProcessEnv = process.env
): ActionInputs {
  const workspace = env.GITHUB_WORKSPACE
    ? path.resolve(env.GITHUB_WORKSPACE)
    : process.cwd();
  const rawTargetPath = env.INPUT_TARGET_PATH?.trim() || ".";

  return {
    targetPath: path.resolve(workspace, rawTargetPath),
    enforce: parseBooleanInput(env.INPUT_ENFORCE, true),
    ...(env.INPUT_REPORT_PATH?.trim()
      ? {
          reportPath: path.resolve(workspace, env.INPUT_REPORT_PATH.trim())
        }
      : {})
  };
}

export async function runAction(inputs: ActionInputs): Promise<ActionResult> {
  const findings = await scanRepository(inputs.targetPath);
  const summary = summarizeFindings(findings);
  const blocked = inputs.enforce && summary.blocking;
  let reportPath: string | undefined;

  if (inputs.reportPath) {
    reportPath = path.resolve(inputs.reportPath);
    await mkdir(path.dirname(reportPath), { recursive: true });
    await writeFile(
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
    ...(reportPath ? { reportPath } : {}),
    exitCode: blocked ? 1 : 0
  };
}

export interface ActionOutputs {
  total_findings: string;
  confirmed_critical_count: string;
  blocked: string;
  report_path?: string;
}

export function createActionOutputs(result: ActionResult): ActionOutputs {
  return {
    total_findings: String(result.summary.totalFindings),
    confirmed_critical_count: String(result.summary.confirmedCriticalCount),
    blocked: String(result.blocked),
    ...(result.reportPath ? { report_path: result.reportPath } : {})
  };
}

export async function writeActionOutputs(
  outputs: ActionOutputs,
  outputFilePath: string | undefined
): Promise<void> {
  if (!outputFilePath) {
    return;
  }

  const lines = Object.entries(outputs).map(([key, value]) => `${key}=${value}`);
  await appendFile(outputFilePath, `${lines.join("\n")}\n`, "utf8");
}

export function formatActionSummary(result: ActionResult): string {
  const lines = [
    "TrustBoundary action complete.",
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

  return lines.join("\n");
}
