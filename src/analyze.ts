import { type RuleContext } from "@adversarylabs/sdk";
import { type AdversaryProject, type Detection } from "./model.js";
import { observation, severity } from "./rules/definitions.js";
import { packageDetections } from "./rules/package.js";
import { projectDetections } from "./rules/project.js";
import { qualityDetections } from "./rules/quality.js";
import { sdkDetections } from "./rules/sdk.js";
import { testDetections } from "./rules/tests.js";

export function analyzeProject(ctx: RuleContext, project: AdversaryProject): void {
  if (!project.recognized) {
    ctx.review.observe({ key: "adversary.typescript.not-applicable", summary: "This repository is not a TypeScript adversary using the Adversary SDK." });
    ctx.review.assessment({ risk: "none", summary: "No supported TypeScript adversary project was available for review." });
    ctx.review.opinion({ summary: "Package and publish readiness was not assessed." });
    return;
  }
  const detections = [
    ...projectDetections(project), ...sdkDetections(project), ...qualityDetections(project),
    ...testDetections(project), ...packageDetections(project),
  ];
  detections.sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.file.localeCompare(right.file) || left.line - right.line || left.subject.localeCompare(right.subject));
  for (const item of detections) ctx.observe(observation(item));
  positives(ctx, project, detections);
  assessment(ctx, detections);
}

function positives(ctx: RuleContext, project: AdversaryProject, detections: Detection[]): void {
  const lacks = (prefix: string) => !detections.some((item) => item.ruleId === prefix);
  if (lacks("adversary.typescript.manifest.invalid") && lacks("adversary.typescript.identity.mismatch")) ctx.review.positive({
    key: "adversary.typescript.identity.aligned", summary: "Manifest, package identity, runtime, and TypeScript output configuration agree.",
    evidence: [{ file: "adversary.yaml", line: 1, label: project.manifest.name }, { file: "package.json", line: 1, label: project.package?.name }],
  });
  if (lacks("adversary.typescript.sdk.legacy-api") && lacks("adversary.typescript.presentation.manual") && /ctx\.(?:observe|finding|review\.)/.test(project.sourceFiles.map((file) => file.content).join("\n"))) ctx.review.positive({
    key: "adversary.typescript.sdk.structured", summary: "Uses the current structured SDK review model without direct presentation logic.",
  });
  if (lacks("adversary.typescript.tests.missing-clean-fixture") && lacks("adversary.typescript.tests.rule-coverage")) ctx.review.positive({
    key: "adversary.typescript.tests.behavioral", summary: "Includes clean and firing behavioral coverage for the declared rules.",
  });
  if (project.tsconfig && typeof project.tsconfig.compilerOptions === "object" && project.tsconfig.compilerOptions !== null && (project.tsconfig.compilerOptions as Record<string, unknown>).strict === true) ctx.review.positive({
    key: "adversary.typescript.types.strict", summary: "Builds the analyzer with strict TypeScript enabled.", evidence: [{ file: "tsconfig.json", line: 1 }],
  });
}

function assessment(ctx: RuleContext, detections: Detection[]): void {
  const rank = { low: 1, medium: 2, high: 3 } as const;
  let risk: "none" | "low" | "medium" | "high" = "none";
  for (const item of detections) { const level = severity(item.ruleId); if (rank[level] > (risk === "none" ? 0 : rank[risk])) risk = level; }
  if (risk === "none") {
    ctx.review.assessment({ risk, summary: "The project uses the current SDK model, has credible behavioral tests, and is ready for deterministic packaging." });
    ctx.review.opinion({ ship: true, summary: "I would package and publish this TypeScript adversary as-is." });
  } else if (risk === "low") {
    ctx.review.assessment({ risk, summary: "The adversary is structurally sound, with a small number of rule-quality, test, permission, or metadata improvements available." });
    ctx.review.opinion({ ship: true, summary: "I would package this adversary and address the low-risk authoring improvements before wider publication." });
  } else {
    ctx.review.assessment({ risk, summary: "SDK, manifest, build, dependency, or package-contract issues prevent a confident publication." });
    ctx.review.opinion({ ship: false, summary: "I would address the material findings before packaging and publishing this adversary." });
  }
}

