import test from "node:test";
import assert from "node:assert/strict";

import { createCliRunSummary } from "../dist/index.js";

test("@trustboundary/cli creates placeholder summary", () => {
  assert.deepEqual(createCliRunSummary("examples/insecure-next-supabase"), {
    targetPath: "examples/insecure-next-supabase",
    status: "not-implemented"
  });
});
