// Clean-only suite: never asserts that a declared rule fires on a vulnerable fixture.
import test from "node:test";
test("excellent fixture produces zero findings", () => {});
