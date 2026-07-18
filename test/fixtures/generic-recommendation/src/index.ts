import { Adversary } from "@adversarylabs/sdk";
const app = new Adversary({ name: "example" });
app.defineRule({
  id: "example.security.configuration",
  aggregate() { return { recommendation: "Improve security." }; }
});

