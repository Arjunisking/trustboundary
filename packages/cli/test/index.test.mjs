import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile } from "node:fs/promises";

import {
  formatHumanSummary,
  formatJsonResult,
  parseCliArgs,
  runScanCommand
} from "../dist/index.js";

const repoRoot = path.resolve(process.cwd(), "../..");
const insecureFixture = path.join(repoRoot, "examples/insecure-next-supabase");

test("@trustboundary/cli parses scan args", () => {
  assert.deepEqual(parseCliArgs(["scan", "examples/insecure-next-supabase", "--json"]), {
    command: "scan",
    targetPath: "examples/insecure-next-supabase",
    options: {
      json: true
    }
  });
});

test("@trustboundary/cli returns stable JSON output", async () => {
  const result = await runScanCommand(insecureFixture, { json: true });
  const json = JSON.parse(formatJsonResult(result));

  assert.equal(json.targetPath, insecureFixture);
  assert.equal(json.summary.totalFindings, 3);
  assert.equal(json.summary.confirmedCriticalCount, 3);
  assert.equal(json.hasBlockingFindings, true);
  assert.equal(json.enforcementEnabled, false);
  assert.equal(json.exitCode, 0);
  assert.equal(json.findings.length, 3);
  assert.deepEqual(
    json.findings.map((finding) => finding.ruleId),
    ["TB001", "TB003", "TB002"]
  );
  assert.deepEqual(
    json.findings.map((finding) => finding.confidence),
    ["confirmed", "confirmed", "confirmed"]
  );
});

test("@trustboundary/cli uses safe summary wording for clean scans", async () => {
  const emptyDir = await mkdtemp(path.join(os.tmpdir(), "trustboundary-clean-"));
  const result = await runScanCommand(emptyDir);

  assert.equal(result.exitCode, 0);
  assert.match(formatHumanSummary(result), /No Confirmed Critical issues found\./);
});

test("@trustboundary/cli writes escaped HTML report", async () => {
  const tempDir = await mkdtemp(path.join(os.tmpdir(), "trustboundary-report-"));
  const reportPath = path.join(tempDir, "report.html");
  const result = await runScanCommand(insecureFixture, { reportPath });
  const html = await readFile(reportPath, "utf8");

  assert.equal(result.reportPath, reportPath);
  assert.match(html, /TrustBoundary findings: 3/);
  assert.match(html, /app\/admin\/page\.tsx/);
  assert.match(html, /app\/api\/webhooks\/stripe\/route\.ts/);
  assert.match(html, /firestore\.rules/);
  assert.match(html, /TB001/);
  assert.match(html, /TB002/);
  assert.match(html, /TB003/);
  assert.equal(html.includes("TB001"), true);
  assert.equal(html.includes("TB002"), true);
  assert.equal(html.includes("TB003"), true);
});

test("@trustboundary/cli enforces Confirmed Critical findings only in enforce mode", async () => {
  const normal = await runScanCommand(insecureFixture);
  const enforced = await runScanCommand(insecureFixture, { enforce: true });

  assert.equal(normal.hasBlockingFindings, true);
  assert.equal(normal.enforcementEnabled, false);
  assert.equal(normal.exitCode, 0);
  assert.equal(enforced.enforcementEnabled, true);
  assert.equal(enforced.exitCode, 1);
});