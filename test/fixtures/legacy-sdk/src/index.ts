import { Adversary, defineRule, ruleRegistry } from "@adversarylabs/sdk";
defineRule({ id: "example.legacy.rule" });
export const app = new Adversary({ name: "example" });
void ruleRegistry;

