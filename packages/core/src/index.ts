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

export const NO_FINDINGS: Finding[] = [];
