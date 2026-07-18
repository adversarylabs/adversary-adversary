import { Adversary, normalizeConfidence, rankFindings } from "@adversarylabs/sdk";
export const app = new Adversary({ name: "example" });
export const order = (findings: never[]) => rankFindings(findings);
export const confidence = normalizeConfidence(0.8);

