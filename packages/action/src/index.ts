import path from "node:path";

import {
  NO_CONFIRMED_CRITICAL_MESSAGE,
  scanRepository,
  summarizeFindings,
  type Finding,
  type ScanSummary
} from "@trustboundary/core";

export interface ActionInputs {
  targetPath: string;
  enforce: boolean;
}

export interface ActionResult {
  targetPath: string;
  summary: ScanSummary;
  findings: Finding[];
  blocked: boolean;
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
    enforce: parseBooleanInput(env.INPUT_ENFORCE, true)
  };
}

export async function runAction(inputs: ActionInputs): Promise<ActionResult> {
  const findings = await scanRepository(inputs.targetPath);
  const summary = summarizeFindings(findings);
  const blocked = inputs.enforce && summary.blocking;

  return {
    targetPath: inputs.targetPath,
    summary,
    findings,
    blocked,
    exitCode: blocked ? 1 : 0
  };
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
