import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";

test("declares deterministic automatic detection", async () => {
  const source = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");
  const manifest = parseAdversaryManifest(source);

  assert.deepEqual(manifest.detection?.files, [
    "adversary.yaml",
    ".adversaryignore",
    "package.json",
    "tsconfig.json",
    "Dockerfile",
    "src/**/*.ts",
    "test/**/*.ts",
    "tests/**/*.ts"
  ]);
  assert.equal(manifest.detection?.entrypoint, undefined);
  assert.equal(manifest.permissions?.model, true);
});
