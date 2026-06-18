export interface ActionSummary {
  blocked: boolean;
  reason: string;
}

export function createActionSummary(): ActionSummary {
  return {
    blocked: false,
    reason: "No Confirmed Critical issues found"
  };
}
