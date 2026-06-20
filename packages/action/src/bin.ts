#!/usr/bin/env node

import {
  createActionOutputs,
  formatActionSummary,
  parseActionInputs,
  runAction,
  writeActionOutputs
} from "./index.js";

async function main() {
  const inputs = parseActionInputs(process.env);
  const result = await runAction(inputs);
  await writeActionOutputs(createActionOutputs(result), process.env.GITHUB_OUTPUT);

  process.stdout.write(`${formatActionSummary(result)}\n`);
  process.exitCode = result.exitCode;
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "Unknown action error";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
