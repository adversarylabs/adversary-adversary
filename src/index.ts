#!/usr/bin/env node

import { Adversary } from "@adversarylabs/sdk";
import { analyzeProject } from "./analyze.js";
import { discoverProject } from "./discover.js";
import { registerRules } from "./rules/definitions.js";

export function createApp(): Adversary {
  const app = new Adversary({ name: "adversary", version: "0.1.0", review: { maximumFindings: 8 } });
  registerRules(app);
  app.rule("adversary.typescript.review", async (ctx) => {
    const project = await discoverProject(ctx.repoPath);
    ctx.summary.files_scanned = project.files.length;
    analyzeProject(ctx, project);
  });
  return app;
}

if (process.argv[1] !== undefined && import.meta.url === new URL(process.argv[1], "file:").href) await createApp().runFromEnvironment();
