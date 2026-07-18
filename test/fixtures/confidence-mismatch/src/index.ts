import { Adversary } from "@adversarylabs/sdk";
const app = new Adversary({ name: "example" });
app.rule("example.agent.overlap", (ctx) => ctx.observe({
  ruleId: "example.agent.overlap", subject: "agents", title: "Agents likely overlap based on a name-based heuristic",
  category: "maintainability", severity: "low", confidence: "high",
  location: { file: "agent.yml", line: 1 }, evidence: { label: "inferred from similar names" }
}));

