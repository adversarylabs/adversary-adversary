import { Adversary, type EvidenceInput } from "@adversarylabs/sdk";

const app = new Adversary({ name: "example" });
app.rule("example.cache.weak", (ctx) => {
  const evidence: EvidenceInput = {
    location: { file: "cache.ts", line: 7 },
    message: "The cache has no invalidation boundary.",
    snippet: "const cache = new Map();",
  };
  ctx.observe({
    ruleId: "example.cache.weak",
    subject: "cache",
    groupKey: "example.cache.weak",
    title: "Cache is weak",
    category: "reliability",
    severity: "low",
    confidence: "high",
    location: evidence,
    recommendation: "Add an explicit invalidation boundary.",
  });
});
