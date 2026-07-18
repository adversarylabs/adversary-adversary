import { Adversary, TerminalRenderer, writeOutput } from "@adversarylabs/sdk";
export const app = new Adversary({ name: "example" });
new TerminalRenderer().render({} as never);
await writeOutput({ findings: [] });
console.log("Summary: review findings");

