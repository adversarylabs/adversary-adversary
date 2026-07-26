import assert from "node:assert/strict";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ModelReviewError,
  type ModelReviewRequest,
  type ReviewModel,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixtures = new URL("./fixtures/", import.meta.url).pathname;

test("hybrid review sends deterministic evidence and emits a grounded product finding", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-review-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    await cp(join(fixtures, "broad-permissions"), root, { recursive: true, force: true });
    let request: ModelReviewRequest | undefined;
    const model: ReviewModel = {
      async review<T>(input: ModelReviewRequest) {
        request = input;
        const citations = (input.input as {
          citations: Array<{
            citationId: string;
            path: string;
            startLine: number;
            endLine: number;
          }>;
        }).citations;
        const readme = citations.find((citation) => citation.path === "README.md");
        assert.ok(readme);
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "medium",
              ship: false,
              summary: "The implementation is structurally sound, but its authority is too broad to be trustworthy.",
              primaryConcern: "an unbounded review authority",
            },
            observations: [{
              id: "authority-boundary",
              title: "Unbounded review authority",
              category: "product-quality",
              severity: "medium",
              confidence: "high",
              summary: "The documentation does not establish what this adversary deliberately leaves to specialists.",
              whyItMatters: "Unbounded authority produces overlap and noisy, contradictory reviews.",
              recommendation: "Document explicit owned and excluded concerns, then constrain the prompt to that boundary.",
              evidence: [{
                citationId: readme.citationId,
                line: readme.startLine,
                detail: "The prepared documentation lacks an explicit authority boundary.",
              }],
            }],
            strengths: [{
              summary: "Deterministic observations use the structured SDK model.",
              citationIds: [readme.citationId],
            }],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: {
        source: { path: root },
        change: {
          scan_mode: "changed",
          changed_files: ["README.md", "src/index.ts"],
          base_ref: "base",
          head_ref: "head",
        },
      },
      model,
    });

    assert.ok(request);
    const prepared = request.input as {
      deterministicSignals: unknown[];
      citations: Array<{
        citationId: string;
        path: string;
        startLine: number;
        endLine: number;
        content: string;
      }>;
    };
    assert.ok(prepared.citations.length > 0);
    assert.equal(
      new Set(prepared.citations.map((item) => item.citationId)).size,
      prepared.citations.length,
    );
    assert.ok(prepared.citations.every((item) =>
      item.content.length <= 4_000 &&
      item.endLine >= item.startLine &&
      item.endLine - item.startLine < 60
    ));
    assert.ok(prepared.deterministicSignals.length > 0);
    const finding = result.findings.find((item) =>
      item.ruleId === "adversary.model.product-quality");
    assert.ok(finding);
    assert.equal(finding.evidence.length, 1);
    assert.equal(result.assessment?.risk, "medium");
    assert.equal(result.opinion?.ship, false);
    assert.match(result.opinion?.summary ?? "", /unbounded review authority/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("material deterministic findings remain visible when model observations are rejected", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-veto-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    await cp(join(fixtures, "invalid-manifest"), root, { recursive: true, force: true });
    const model: ReviewModel = {
      async review<T>() {
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "none",
              ship: true,
              summary: "No model-only concerns.",
              primaryConcern: "",
            },
            observations: [{
              id: "no-action",
              title: "No manifest action required",
              category: "manifest-quality",
              severity: "low",
              confidence: "high",
              summary: "There is no current defect that warrants a separate model-backed manifest finding.",
              whyItMatters: "Reviewers should avoid duplicating deterministic manifest findings with weaker model commentary.",
              recommendation: "No change is needed for this model observation because deterministic validation already owns it.",
              evidence: [{
                citationId: "src:1:1",
                line: 1,
                detail: "The manifest is already covered by deterministic validation.",
              }],
            }],
            strengths: [],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });
    assert.equal(result.assessment?.risk, "high");
    assert.match(result.assessment?.summary ?? "", /invalid adversary manifest/);
    assert.equal(result.opinion?.ship, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("malformed model output receives one bounded repair attempt", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-repair-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    let calls = 0;
    const model: ReviewModel = {
      async review<T>(request: ModelReviewRequest) {
        calls += 1;
        if (calls === 1) {
          throw new ModelReviewError("model output does not match requested schema", {
            code: "invalid_model_output",
            retryable: false,
          });
        }
        assert.match(request.prompt, /REPAIR REQUIREMENT/);
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "none",
              ship: true,
              summary: "The adversary is coherent, narrowly scoped, and supported by prepared evidence.",
              primaryConcern: "",
            },
            observations: [],
            strengths: [],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 2);
    assert.equal(result.opinion?.ship, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a model timeout falls back immediately to the deterministic review", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-timeout-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    await cp(join(fixtures, "invalid-manifest"), root, { recursive: true, force: true });
    let calls = 0;
    const model: ReviewModel = {
      async review() {
        calls += 1;
        throw new ModelReviewError("Model review exceeded its 120000ms timeout.", {
          code: "model_timeout",
          retryable: true,
        });
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 1);
    assert.equal(result.assessment?.risk, "high");
    assert.equal(
      result.findings.some((item) =>
        item.ruleId === "adversary.typescript.manifest.invalid"),
      true,
    );
    assert.equal(result.opinion?.ship, false);
    assert.equal(
      result.observations.some((item) =>
        item.key === "adversary.model.transient-unavailable" &&
        /timed out/.test(item.summary)),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a timeout during model-output repair falls back without a third call", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-repair-timeout-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    let calls = 0;
    const model: ReviewModel = {
      async review() {
        calls += 1;
        if (calls === 1) {
          throw new ModelReviewError("model output does not match requested schema", {
            code: "invalid_model_output",
            retryable: false,
          });
        }
        throw new ModelReviewError("Model review exceeded its 120000ms timeout.", {
          code: "model_timeout",
          retryable: true,
        });
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 2);
    assert.equal(result.assessment?.risk, "none");
    assert.equal(result.opinion?.ship, true);
    assert.equal(
      result.observations.some((item) =>
        item.key === "adversary.model.transient-unavailable" &&
        /timed out/.test(item.summary)),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unknown prepared citation is omitted and falls back to deterministic review", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-evidence-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    let calls = 0;
    const model: ReviewModel = {
      async review<T>() {
        calls += 1;
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "medium",
              ship: false,
              summary: "The adversary allegedly lacks an explicit and coherent authority boundary.",
              primaryConcern: "the missing authority boundary",
            },
            observations: [{
              id: "invented-authority",
              title: "Missing authority boundary",
              category: "product-quality",
              severity: "medium",
              confidence: "high",
              summary: "The documentation allegedly claims responsibility for every engineering concern.",
              whyItMatters: "Unbounded authority would create overlapping, noisy, and contradictory reviews.",
              recommendation: "Constrain the documented authority to the adversary's supported domain.",
              evidence: [{
                citationId: "invented:README.md",
                line: 1,
                detail: "This citation ID was not included in the prepared input.",
              }],
            }],
            strengths: [],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 2);
    assert.equal(
      result.findings.some((item) => item.ruleId === "adversary.model.product-quality"),
      false,
    );
    assert.equal(
      result.observations.some((item) =>
        item.key === "adversary.model.evidence-unavailable"),
      true,
    );
    assert.equal(result.assessment?.risk, "none");
    assert.equal(result.opinion?.ship, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a prepared citation grounds evidence without copied source text", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-prepared-citation-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    let calls = 0;
    const model: ReviewModel = {
      async review<T>(request: ModelReviewRequest) {
        calls += 1;
        const citations = (request.input as {
          citations: Array<{
            citationId: string;
            path: string;
            startLine: number;
          }>;
        }).citations;
        const readme = citations.find((citation) => citation.path === "README.md");
        assert.ok(readme);
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "low",
              ship: true,
              summary: "The adversary is coherent, with one small documentation improvement available.",
              primaryConcern: "",
            },
            observations: [{
              id: "authority-detail",
              title: "Authority boundary could be more explicit",
              category: "product-quality",
              severity: "low",
              confidence: "high",
              summary: "The README explains usage but gives little detail about specialist boundaries.",
              whyItMatters: "A clear authority boundary helps teams predict overlap and review cost.",
              recommendation: "Add a short owned-versus-excluded concerns section to the README.",
              evidence: [{
                citationId: readme.citationId,
                line: readme.startLine,
                detail: "The README begins with only a general product heading.",
              }],
            }],
            strengths: [],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 1);
    assert.equal(
      result.findings.some((item) => item.ruleId === "adversary.model.product-quality"),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an invalid first citation can be repaired once", async () => {
  const root = await mkdtemp(join(tmpdir(), "adversary-model-evidence-repair-"));
  try {
    await cp(join(fixtures, "good"), root, { recursive: true });
    let calls = 0;
    const model: ReviewModel = {
      async review<T>(request: ModelReviewRequest) {
        calls += 1;
        if (calls === 2) assert.match(request.prompt, /select a citationId included/);
        const citations = (request.input as {
          citations: Array<{
            citationId: string;
            path: string;
            startLine: number;
          }>;
        }).citations;
        const readme = citations.find((citation) => citation.path === "README.md");
        assert.ok(readme);
        return {
          output: {
            schemaVersion: 1,
            assessment: {
              risk: "low",
              ship: true,
              summary: "The adversary is coherent, with one small documentation improvement available.",
              primaryConcern: "",
            },
            observations: [{
              id: "authority-detail",
              title: "Authority boundary could be more explicit",
              category: "product-quality",
              severity: "low",
              confidence: "high",
              summary: "The README explains usage but gives little detail about specialist boundaries.",
              whyItMatters: "A clear authority boundary helps teams predict overlap and review cost.",
              recommendation: "Add a short owned-versus-excluded concerns section to the README.",
              evidence: [{
                citationId: readme.citationId,
                line: calls === 1 ? readme.startLine - 1 : readme.startLine,
                detail: "The README begins with only a general product heading.",
              }],
            }],
            strengths: [],
          } as T,
          provider: "fixture",
          model: "fixture",
        };
      },
    };

    const result = await createApp().run({
      input: { source: { path: root } },
      model,
    });

    assert.equal(calls, 2);
    assert.equal(
      result.findings.some((item) => item.ruleId === "adversary.model.product-quality"),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
