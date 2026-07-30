import { Adversary, Confidence, Severity } from "@adversarylabs/sdk";
import schema from "../schema/model.schema.json" with { type: "json" };

export function createApp() {
  const app = new Adversary({ name: "example", version: "1.0.0" });
  app.defineRule({
    id: "example.readme.missing",
    category: "documentation",
    defaultSeverity: Severity.Low,
    defaultConfidence: Confidence.High,
  });
  app.rule("example.review.run", async (ctx) => {
    const { output } = await ctx.model.review<{
      observations: Array<{ title: string; summary: string }>;
    }>({
      prompt: "Review this adversary and list concerns.",
      schema: schema as Record<string, unknown>,
    });
    for (const observation of output.observations ?? []) {
      // Intentionally no evidence/citation gate — hallucination risk.
      ctx.finding({
        ruleId: "example.readme.missing",
        subject: observation.title,
        title: observation.title,
        category: "documentation",
        severity: Severity.Low,
        confidence: Confidence.High,
        summary: observation.summary,
      });
    }
  });
  return app;
}
