import test from "node:test";
import assert from "node:assert/strict";

import { escapeHtml, renderPlaceholderReport } from "../dist/index.js";

test("@trustboundary/report escapes hostile HTML", () => {
  assert.equal(
    escapeHtml('<script>alert("x")</script>'),
    "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
  );
});

test("@trustboundary/report renders escaped findings", () => {
  const html = renderPlaceholderReport([
    {
      ruleId: "exposed-secrets",
      severity: "critical",
      file: "app/page.tsx",
      message: `<img src=x onerror="alert('x')">`
    }
  ]);

  assert.match(
    html,
    /&lt;img src=x onerror=&quot;alert\(&#39;x&#39;\)&quot;&gt;/
  );
  assert.equal(html.includes("<img src=x onerror="), false);
});
