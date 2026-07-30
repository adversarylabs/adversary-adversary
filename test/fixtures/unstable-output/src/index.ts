import { Adversary, Confidence, Severity } from "@adversarylabs/sdk";

export function createApp() {
  const app = new Adversary({ name: "example", version: "1.0.0" });
  app.defineRule({
    id: "example.readme.missing",
    category: "documentation",
    defaultSeverity: Severity.Low,
    defaultConfidence: Confidence.High,
  });
  app.rule("example.review.run", async (ctx) => {
    const id = crypto.randomUUID();
    const noise = Math.random();
    if (!(await ctx.glob("README.md")).length) {
      ctx.observe({
        ruleId: "example.readme.missing",
        subject: `README.md:${id}`,
        groupKey: `example.readme.missing:${noise}`,
        title: "README is missing",
        category: "documentation",
        severity: Severity.Low,
        confidence: Confidence.High,
        location: { file: "README.md", line: 1, label: "README.md was not discovered" },
        evidence: { label: "missing repository documentation", data: { expected: "README.md", id } },
        recommendation: "Add README.md with installation and usage instructions.",
      });
    }
  });
  return app;
}
