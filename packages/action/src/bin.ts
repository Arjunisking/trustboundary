#!/usr/bin/env node

import {
  createActionOutputs,
  formatActionSummary,
  parseActionInputs,
  runAction,
  writeActionOutputs
} from "./index.js";

try {
  const inputs = parseActionInputs(process.env);
  const result = await runAction(inputs);
  await writeActionOutputs(createActionOutputs(result), process.env.GITHUB_OUTPUT);

  process.stdout.write(`${formatActionSummary(result)}\n`);
  process.exitCode = result.exitCode;
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown action error";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
