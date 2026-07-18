import { Adversary } from "@adversarylabs/sdk";
const app = new Adversary({ name: "example" });
app.rule("example.cache.weak", (ctx) => ctx.observe({
  ruleId: "example.cache.weak", subject: "cache", title: "Cache is weak",
  category: "reliability", severity: "low", confidence: "high"
}));

