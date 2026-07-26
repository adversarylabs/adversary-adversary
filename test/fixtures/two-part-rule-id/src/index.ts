import { Adversary, Confidence, Severity } from "@adversarylabs/sdk";

const app = new Adversary({ name: "example" });

app.defineRule({
  id: "example.readme",
  category: "documentation",
  defaultSeverity: Severity.Low,
  defaultConfidence: Confidence.High,
});

app.rule("example.review", async (ctx) => {
  if (!(await ctx.glob("README.md")).length) {
    ctx.observe({
      ruleId: "example.readme",
      subject: "README.md",
      groupKey: "example.readme:repository",
      title: "README is missing",
      category: "documentation",
      severity: Severity.Low,
      confidence: Confidence.High,
      location: { file: "README.md", line: 1 },
      evidence: { expected: "README.md" },
      recommendation: "Add README.md with installation and usage instructions.",
    });
  }
});
