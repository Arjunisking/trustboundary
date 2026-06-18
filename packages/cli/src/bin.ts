#!/usr/bin/env node

import { createCliRunSummary } from "./index.js";

const targetPath = process.argv[2] ?? ".";
const summary = createCliRunSummary(targetPath);

process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
