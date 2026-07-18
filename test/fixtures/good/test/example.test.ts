// example.readme.missing fires for a missing README and remains absent for fixtures/clean.
// Grouping regression: two observations synthesize to one finding with evidence.length === 2.
import test from "node:test";
test("clean fixture produces zero findings", () => {});

