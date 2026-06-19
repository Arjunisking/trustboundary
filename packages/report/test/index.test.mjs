import test from "node:test";
import assert from "node:assert/strict";

import { escapeHtml, renderHtmlReport } from "../dist/index.js";

test("@trustboundary/report escapes hostile HTML", () => {
  assert.equal(
    escapeHtml('<script>alert("x")</script>'),
    "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
  );
});

test("@trustboundary/report renders escaped findings", () => {
  const html = renderHtmlReport({
    targetPath: "examples/insecure-next-supabase",
    summary: {
      totalFindings: 1,
      confirmedCriticalCount: 1,
      blocking: true,
      statusMessage: "Confirmed Critical findings: 1"
    },
    findings: [
      {
        id: "finding-1",
        ruleId: "exposed-secrets",
        severity: "critical",
        confidence: "confirmed",
        file: "app/page.tsx",
        line: 7,
        message: `<img src=x onerror="alert('x')">`,
        exploitPath: `path <script>alert("x")</script>`,
        patch: `remove "key"`
      }
    ]
  });

  assert.match(
    html,
    /&lt;img src=x onerror=&quot;alert\(&#39;x&#39;\)&quot;&gt;/
  );
  assert.equal(html.includes("<img src=x onerror="), false);
  assert.equal(html.includes("<script>alert(\"x\")</script>"), false);
});

test("@trustboundary/report uses safe summary wording for clean scans", () => {
  const html = renderHtmlReport({
    targetPath: "examples/clean",
    summary: {
      totalFindings: 0,
      confirmedCriticalCount: 0,
      blocking: false,
      statusMessage: "No Confirmed Critical issues found."
    },
    findings: []
  });

  assert.match(html, /No Confirmed Critical issues found\./);
  assert.equal(html.includes("the app is secure"), false);
});

test("@trustboundary/report keeps findings title when only non-blocking findings exist", () => {
  const html = renderHtmlReport({
    targetPath: "examples/insecure-next-supabase",
    summary: {
      totalFindings: 1,
      confirmedCriticalCount: 0,
      blocking: false,
      statusMessage: "No Confirmed Critical issues found."
    },
    findings: [
      {
        id: "finding-2",
        ruleId: "broken-authorization",
        severity: "high",
        confidence: "likely",
        file: "app/api/billing/route.ts",
        line: 7,
        message: "Ownership check missing.",
        exploitPath: "Cross-tenant read possible.",
        patch: "Add user-scoped where clause."
      }
    ]
  });

  assert.match(html, /TrustBoundary findings: 1/);
  assert.match(html, /No Confirmed Critical issues found\./);
  assert.equal(html.includes("the app is secure"), false);
});
