import { Adversary } from "@adversarylabs/sdk";
const app = new Adversary({ name: "example" });
app.defineRule({ id: "rule1", recommendation: "Fix this." } as never);
app.rule("check-cache", () => {});

