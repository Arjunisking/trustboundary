export interface CliRunSummary {
  targetPath: string;
  status: "not-implemented";
}

export function createCliRunSummary(targetPath: string): CliRunSummary {
  return {
    targetPath,
    status: "not-implemented"
  };
}
