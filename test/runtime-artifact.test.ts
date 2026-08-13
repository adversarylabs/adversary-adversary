import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("bundled runtime executes without node_modules and reports its release version", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "adversary-artifact-"));
  const target = await mkdtemp(join(tmpdir(), "adversary-target-"));
  await mkdir(join(artifact, "dist"), { recursive: true });
  await cp(join(projectRoot, "dist", "index.js"), join(artifact, "dist", "index.js"));
  await cp(join(projectRoot, "schema"), join(artifact, "schema"), { recursive: true });
  await cp(join(projectRoot, "schemas"), join(artifact, "schemas"), { recursive: true });
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');
  await writeFile(join(target, "package.json"), '{"name":"unrelated-app","version":"1.0.0"}\n');

  const runtime = await import(pathToFileURL(join(artifact, "dist", "index.js")).href) as {
    createApp(): {
      run(options: { input: unknown }): Promise<{
        adversary: { name: string; version?: string };
        findings: unknown[];
      }>;
    };
  };
  const result = await runtime.createApp().run({ input: { source: { path: target } } });
  assert.equal(result.adversary.name, "adversarylabs/adversary");
  assert.equal(result.adversary.version, "0.0.25");
  assert.deepEqual(result.findings, []);
});
