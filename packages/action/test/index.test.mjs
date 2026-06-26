import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { access, mkdtemp, readFile, writeFile } from "node:fs/promises";

import {
  createActionOutputs,
  formatActionSummary,
  parseActionInputs,
  runAction,
  writeActionOutputs
} from "../dist/index.js";

const repoRoot = path.resolve(process.cwd(), "../..");
const insecureFixture = path.join(repoRoot, "examples/insecure-next-supabase");
const actionMetadataPath = path.join(repoRoot, "action.yml");
const bundledEntryPath = path.join(repoRoot, "packages/action/dist-bundle/index.cjs");
const bundledSourceMapPath = path.join(repoRoot, "packages/action/dist-bundle/index.cjs.map");

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

test("@trustboundary/action metadata uses bundled node24 release path", async () => {
  const actionMetadata = await readFile(actionMetadataPath, "utf8");

  assert.match(actionMetadata, /using: node24/);
  assert.match(actionMetadata, /main: packages\/action\/dist-bundle\/index\.cjs/);
  assert.equal(actionMetadata.includes("pnpm install"), false);
  assert.equal(actionMetadata.includes("pnpm build"), false);
});

test("@trustboundary/action build emits bundled artifact without sourcemap file", async () => {
  await access(bundledEntryPath);
  await assert.rejects(access(bundledSourceMapPath));
});

test("@trustboundary/action fails for Confirmed Critical findings", async () => {
  const result = await runAction({
    targetPath: insecureFixture,
    enforce: true
  });

  assert.equal(result.blocked, true);
  assert.equal(result.exitCode, 1);
  assert.equal(result.enforcementEnabled, true);
  assert.equal(result.summary.confirmedCriticalCount, 2);
  assert.match(formatActionSummary(result), /Confirmed Critical findings: 2/);
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

test("@trustboundary/action does not block a fixture without TB001 or TB002 evidence", async () => {
  const unmatchedDir = await mkdtemp(path.join(os.tmpdir(), "trustboundary-action-unmatched-"));
  await writeFile(
    path.join(unmatchedDir, "route.ts"),
    [
      "export async function POST(request: Request) {",
      "  const body = await request.json();",
      '  return Response.json({ body });',
      "}"
    ].join("\n"),
    "utf8"
  );
  const result = await runAction({
    targetPath: unmatchedDir,
    enforce: true
  });

  assert.equal(result.summary.totalFindings, 0);
  assert.equal(result.summary.confirmedCriticalCount, 0);
  assert.deepEqual(result.findings, []);
  assert.equal(result.blocked, false);
  assert.equal(result.exitCode, 0);
  assert.match(formatActionSummary(result), /No Confirmed Critical issues found\./);
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

  assert.match(outputContents, /^total_findings=2/m);
  assert.match(outputContents, /^confirmed_critical_count=2/m);
  assert.match(outputContents, /^blocked=true/m);
  assert.match(outputContents, /^report_path=.*report\.html/m);
});
