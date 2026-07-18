import { Adversary } from "@adversarylabs/sdk";
const app = new Adversary({ name: "example" });
app.rule("example.actions.unpinned", (ctx) => {
  for (const action of ["one", "two"]) ctx.observe({
    ruleId: "example.actions.unpinned", subject: action,
    title: "Action is unpinned", category: "security", severity: "low", confidence: "high",
    location: { file: "workflow.yml", line: 1 }, evidence: { label: action }
  });
});

