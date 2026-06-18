#!/usr/bin/env node

import { formatActionSummary, parseActionInputs, runAction } from "./index.js";

try {
  const inputs = parseActionInputs(process.env);
  const result = await runAction(inputs);

  process.stdout.write(`${formatActionSummary(result)}\n`);
  process.exitCode = result.exitCode;
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown action error";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
