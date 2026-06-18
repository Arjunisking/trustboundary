import test from "node:test";
import assert from "node:assert/strict";

import { createActionSummary } from "../dist/index.js";

test("@trustboundary/action exports default gate summary", () => {
  assert.deepEqual(createActionSummary(), {
    blocked: false,
    reason: "No Confirmed Critical issues found"
  });
});
