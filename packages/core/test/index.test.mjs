import test from "node:test";
import assert from "node:assert/strict";

import { NO_FINDINGS } from "../dist/index.js";

test("@trustboundary/core exports placeholder findings", () => {
  assert.deepEqual(NO_FINDINGS, []);
});
