export const RULE_IDS = [
  "exposed-secrets",
  "unsafe-mutations",
  "broken-authorization",
  "rls-failures",
  "webhook-and-agent-abuse"
] as const;

export type RuleId = (typeof RULE_IDS)[number];
