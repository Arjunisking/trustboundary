#!/usr/bin/env node

import {
  formatHumanSummary,
  formatJsonResult,
  parseCliArgs,
  runScanCommand
} from "./index.js";

try {
  const parsed = parseCliArgs(process.argv.slice(2));
  const result = await runScanCommand(parsed.targetPath, parsed.options);
  const output = parsed.options.json
    ? formatJsonResult(result)
    : formatHumanSummary(result);

  process.stdout.write(`${output}\n`);
  process.exitCode = result.exitCode;
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown CLI error";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
