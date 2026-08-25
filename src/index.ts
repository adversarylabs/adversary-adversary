#!/usr/bin/env node

import { Adversary } from "@adversarylabs/sdk";
import { analyzeProject, applyDeterministicAssessment, reviewedFileCount } from "./analyze.js";
import { discoverProject } from "./discover.js";
import { runModelAdversaryReview } from "./model-review.js";
import { registerRules } from "./rules/definitions.js";

export function createApp(): Adversary {
  const app = new Adversary({ name: "adversarylabs/adversary", version: "0.0.25", review: { maximumFindings: 8 } });
  registerRules(app);
  app.rule("adversary.typescript.review", async (ctx) => {
    const project = await discoverProject(ctx.repoPath);
    ctx.summary.files_scanned = reviewedFileCount(ctx, project);
    const detections = analyzeProject(ctx, project);
    if (detections === null) return;
    const modelStatus = await runModelAdversaryReview(ctx, project, detections);
    if (modelStatus === "unavailable") applyDeterministicAssessment(ctx, detections);
  });
  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) await createApp().runFromEnvironment();
