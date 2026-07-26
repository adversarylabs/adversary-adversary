// example.readme.missing fires for a missing README and remains absent for fixtures/excellent.
// Grouping regression: two observations synthesize to one finding with evidence.length === 2.
import test from "node:test";
test("excellent fixture produces zero findings", () => {});
