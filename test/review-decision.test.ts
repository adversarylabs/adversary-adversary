import assert from "node:assert/strict";
import test from "node:test";
import { reviewDecision } from "../src/review-decision.ts";

test("one review decision policy governs risk and publication", () => {
  assert.deepEqual(reviewDecision([]), { risk: "none", ship: true });
  assert.deepEqual(reviewDecision(["low"]), { risk: "low", ship: true });
  assert.deepEqual(
    reviewDecision(["low", "high", "medium"]),
    { risk: "high", ship: false },
  );
  assert.deepEqual(
    reviewDecision(["critical"]),
    { risk: "critical", ship: false },
  );
});
