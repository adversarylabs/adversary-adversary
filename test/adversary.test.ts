import assert from "node:assert/strict";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { TerminalRenderer, createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { discoverProject } from "../src/discover.ts";
import { createApp } from "../src/index.ts";

const RULE_IDS = [
  "adversary.typescript.identity.mismatch",
  "adversary.typescript.manifest.invalid",
  "adversary.typescript.sdk.legacy-api",
  "adversary.typescript.presentation.manual",
  "adversary.typescript.rule.id-quality",
  "adversary.typescript.rule.grouping",
  "adversary.typescript.observation.evidence",
  "adversary.typescript.confidence.calibration",
  "adversary.typescript.recommendation.weak",
  "adversary.typescript.sdk.reimplementation",
  "adversary.typescript.tests.missing-clean-fixture",
  "adversary.typescript.tests.missing-vulnerable-fixture",
  "adversary.typescript.tests.rule-coverage",
  "adversary.typescript.tests.grouping",
  "adversary.typescript.build.output",
  "adversary.typescript.package.contents",
  "adversary.typescript.package.dependencies",
  "adversary.typescript.permissions.broad",
  "adversary.typescript.publish.metadata",
  "adversary.typescript.llm.no-evidence-gate",
  "adversary.typescript.name.not-domain",
  "adversary.typescript.determinism.unstable-output",
] as const;

const fixtures = new URL("./fixtures/", import.meta.url).pathname;

async function withFixture<T>(overlay: string | undefined, run: (path: string) => Promise<T>): Promise<T> {
  const path = await mkdtemp(join(tmpdir(), "adversary-review-"));
  try {
    await cp(join(fixtures, "good"), path, { recursive: true, force: true });
    if (overlay) await cp(join(fixtures, overlay), path, { recursive: true, force: true });
    return await run(path);
  } finally { await rm(path, { recursive: true, force: true }); }
}

async function review(overlay?: string) {
  return withFixture(overlay, (path) => createApp().run({ input: { source: { path } }, includeRawObservations: true, review: { includeInformational: true } }));
}

async function finding(overlay: string, ruleId: string) {
  const output = await review(overlay);
  const result = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(result, `${overlay} should produce ${ruleId}; got ${output.findings.map((item) => item.ruleId).join(", ")}`);
  return result;
}

test("recognizes a valid SDK TypeScript adversary and ignores an unrelated TypeScript project", async () => {
  await withFixture(undefined, async (path) => assert.equal((await discoverProject(path)).recognized, true));
  const unrelated = await discoverProject(join(fixtures, "unrelated"));
  assert.equal(unrelated.recognized, false);
  const output = await createApp().run({ input: { source: { path: join(fixtures, "unrelated") } } });
  assert.deepEqual(output.findings, []);
  assert.equal(output.opinion?.ship, undefined);
});

test("clean adversary produces no material findings and concrete positives", async () => {
  const output = await review();
  assert.deepEqual(output.findings, []);
  assert.equal(output.opinion?.ship, true);
  assert.deepEqual(output.positives.map((item) => item.key), [
    "adversary.typescript.identity.aligned",
    "adversary.typescript.sdk.structured",
  ]);
});

test("canonical manifest violations group with precise evidence", async () => {
  const result = await finding("invalid-manifest", "adversary.typescript.manifest.invalid");
  assert.equal(result.severity, "high");
  assert.ok(result.evidence.length >= 4);
  assert.equal(result.evidence.every((item) => item.location?.file === "adversary.yaml" && (item.location?.line ?? 0) > 0), true);
  const runtimeName = result.evidence.find((item) => item.data?.field === "runtime.name");
  assert.equal(runtimeName?.location?.line, 5);
});

test("manifest and package identity disagreements group", async () => {
  const result = await finding("identity-mismatch", "adversary.typescript.identity.mismatch");
  assert.equal(result.evidence.length, 2);
  assert.deepEqual(
    result.evidence.map((item) => item.location?.line),
    [6, 7],
  );
});

test("legacy SDK entry points are detected", async () => {
  const result = await finding("legacy-sdk", "adversary.typescript.sdk.legacy-api");
  assert.equal(result.evidence.length, 2);
});

test("manual rendering and direct output writes are detected", async () => {
  const result = await finding("manual-rendering", "adversary.typescript.presentation.manual");
  assert.ok(result.evidence.length >= 3);
});

test("weak rule IDs and generic recommendations are detected", async () => {
  assert.ok((await finding("weak-rule-ids", "adversary.typescript.rule.id-quality")).evidence.length >= 1);
  await finding("weak-rule-ids", "adversary.typescript.recommendation.weak");
  await finding("generic-recommendation", "adversary.typescript.recommendation.weak");
});

test("stable domain-concern rule IDs do not require an extra namespace segment", async () => {
  const output = await review("two-part-rule-id");
  assert.equal(
    output.findings.some((item) =>
      item.ruleId === "adversary.typescript.rule.id-quality"),
    false,
  );
});

test("repeated observations without a grouping boundary are detected", async () => {
  await finding("weak-grouping", "adversary.typescript.rule.grouping");
});

test("observations without location and evidence are detected", async () => {
  const result = await finding("poor-evidence", "adversary.typescript.observation.evidence");
  assert.ok((result.evidence[0]?.location?.line ?? 0) > 0);
  assert.equal(result.evidence[0]?.location?.file, "src/index.ts");
});

test("an EvidenceInput location does not require a duplicate evidence field", async () => {
  const output = await review("evidence-input-location");
  assert.equal(
    output.findings.some((item) =>
      item.ruleId === "adversary.typescript.observation.evidence"),
    false,
  );
});

test("obviously heuristic high confidence is detected", async () => {
  await finding("confidence-mismatch", "adversary.typescript.confidence.calibration");
});

test("SDK ranking and confidence reimplementation is detected", async () => {
  const result = await finding("duplicated-sdk-logic", "adversary.typescript.sdk.reimplementation");
  assert.ok(result.evidence.length >= 2);
});

test("missing clean, rule coverage, and grouping regressions are detected", async () => {
  await finding("missing-clean-fixture", "adversary.typescript.tests.missing-clean-fixture");
  await finding("missing-clean-fixture", "adversary.typescript.tests.rule-coverage");
  await finding("missing-grouping-test", "adversary.typescript.tests.grouping");
});

test("missing positive vulnerable fixtures are detected", async () => {
  const result = await finding(
    "missing-vulnerable-fixture",
    "adversary.typescript.tests.missing-vulnerable-fixture",
  );
  assert.ok(
    Array.isArray(result.evidence[0]?.data?.missingPositive) &&
      (result.evidence[0]?.data?.missingPositive as string[]).includes("example.readme.missing"),
  );
  await finding("missing-vulnerable-fixture", "adversary.typescript.tests.rule-coverage");
});

test("flat catalog names are detected", async () => {
  const result = await finding("name-not-domain", "adversary.typescript.name.not-domain");
  assert.equal(result.evidence[0]?.location?.file, "adversary.yaml");
  assert.equal(result.evidence[0]?.data?.name, "example");
});

test("model review without an evidence gate is detected", async () => {
  const result = await finding("no-evidence-gate", "adversary.typescript.llm.no-evidence-gate");
  assert.ok(result.evidence.length >= 1);
});

test("non-deterministic finding identity sources are detected", async () => {
  const result = await finding("unstable-output", "adversary.typescript.determinism.unstable-output");
  assert.ok(result.evidence.length >= 2);
});

test("release-built entrypoints are not required in the source checkout", async () => {
  const output = await review("stale-build");
  assert.equal(
    output.findings.some((item) => item.ruleId === "adversary.typescript.build.output"),
    false,
  );
});

test("a missing release build command is detected", async () => {
  await finding("missing-build-script", "adversary.typescript.build.output");
});

test("unsafe package contents and runtime dependency gaps are detected", async () => {
  await finding("unsafe-package", "adversary.typescript.package.contents");
  const dependency = await finding("runtime-dependency", "adversary.typescript.package.dependencies");
  assert.equal(dependency.evidence[0]?.data?.dependency, "left-pad");
});

test("unused broad permissions are detected", async () => {
  const result = await finding("broad-permissions", "adversary.typescript.permissions.broad");
  assert.equal(result.evidence.length, 3);
  assert.deepEqual(
    result.evidence.map((item) => item.location?.line),
    [8, 9, 11],
  );
});

test("incomplete publish metadata is detected", async () => {
  const result = await finding("publish-metadata", "adversary.typescript.publish.metadata");
  assert.match(JSON.stringify(result.evidence[0]?.data?.missing), /repository URL|usage/);
});

test("finding ordering is deterministic", async () => {
  const first = await review("invalid-manifest");
  const second = await review("invalid-manifest");
  assert.deepEqual(first.findings, second.findings);
});

test("terminal rendering hides raw metadata and JSON uses the canonical review protocol", async () => {
  const output = await review("identity-mismatch");
  const rendered: string[] = [];
  new TerminalRenderer((text) => rendered.push(text)).render(output);
  assert.doesNotMatch(rendered.join(""), /rawObservations|groupKey|synthesisSource/);
  const envelope = createAdversaryRunEnvelope(output);
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "adversarylabs/adversary");
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(envelope)));
});

test("every v0.1.0 rule has a focused behavioral assertion", () => {
  assert.equal(RULE_IDS.length, 22);
});
