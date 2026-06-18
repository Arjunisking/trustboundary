import test from "node:test";
import assert from "node:assert/strict";

import { RULE_IDS } from "../dist/index.js";

test("@trustboundary/rules exports V1 placeholder rule ids", () => {
  assert.equal(RULE_IDS.length, 5);
  assert.equal(RULE_IDS[0], "exposed-secrets");
});
