import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";

import {
  createActionOutputs,
  formatActionSummary,
  parseActionInputs,
  runAction,
  writeActionOutputs
} from "../dist/index.js";

const repoRoot = path.resolve(process.cwd(), "../..");
const insecureFixture = path.join(repoRoot, "examples/insecure-next-supabase");

test("@trustboundary/action parses inputs with default enforcement", () => {
  const inputs = parseActionInputs({
    GITHUB_WORKSPACE: repoRoot,
    INPUT_TARGET_PATH: "examples/insecure-next-supabase"
  });

  assert.deepEqual(inputs, {
    targetPath: insecureFixture,
    enforce: true
  });
});

test("@trustboundary/action fails for Confirmed Critical findings", async () => {
  const result = await runAction({
    targetPath: insecureFixture,
    enforce: true
  });

  assert.equal(result.blocked, true);
  assert.equal(result.exitCode, 1);
  assert.equal(result.enforcementEnabled, true);
  assert.equal(result.summary.confirmedCriticalCount, 1);
  assert.match(formatActionSummary(result), /Confirmed Critical findings: 1/);
});

test("@trustboundary/action passes for clean scans", async () => {
  const safeDir = await mkdtemp(path.join(os.tmpdir(), "trustboundary-action-safe-"));
  await writeFile(
    path.join(safeDir, "page.tsx"),
    ['"use client";', 'const publicKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;'].join(
      "\n"
    ),
    "utf8"
  );
  const result = await runAction({
    targetPath: safeDir,
    enforce: true
  });

  assert.equal(result.blocked, false);
  assert.equal(result.exitCode, 0);
  assert.equal(result.summary.confirmedCriticalCount, 0);
  assert.match(formatActionSummary(result), /No Confirmed Critical issues found\./);
  assert.equal(formatActionSummary(result).includes("the app is secure"), false);
});

test("@trustboundary/action can disable enforcement", async () => {
  const result = await runAction({
    targetPath: insecureFixture,
    enforce: false
  });

  assert.equal(result.blocked, false);
  assert.equal(result.exitCode, 0);
});

test("@trustboundary/action writes declared outputs", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "trustboundary-action-output-"));
  const outputFile = path.join(tempDir, "github-output.txt");
  const reportPath = path.join(tempDir, "report.html");
  const result = await runAction({
    targetPath: insecureFixture,
    enforce: true,
    reportPath
  });
  await writeActionOutputs(createActionOutputs(result), outputFile);
  const outputContents = await readFile(outputFile, "utf8");

  assert.match(outputContents, /^total_findings=1/m);
  assert.match(outputContents, /^confirmed_critical_count=1/m);
  assert.match(outputContents, /^blocked=true/m);
  assert.match(outputContents, /^report_path=.*report\.html/m);
});
