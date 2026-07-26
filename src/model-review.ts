import {
  formatOpinionAsync,
  ModelUnavailableError,
  type ChangeContext,
  type EvidenceInput,
  type ModelReviewRequest,
  type RuleContext,
  type Severity,
} from "@adversarylabs/sdk";
import modelSchema from "../schema/adversary-review.model.v1.schema.json" with { type: "json" };
import type { AdversaryProject, Detection, SourceFile } from "./model.js";
import { severity } from "./rules/definitions.js";

const MAX_SOURCES = 20;
const MAX_SOURCE_CHARACTERS = 10_000;
const MAX_TOTAL_CHARACTERS = 140_000;
const MAX_MODEL_OBSERVATIONS = 3;

const MODEL_PROMPT = `You are adversary-adversary, the Staff-level reviewer for first-party Adversary Labs adversaries.

Mission:
Decide whether engineers would enable and trust this adversary. Review the adversary as a product, not merely as a TypeScript package.

Authority:
- manifest metadata, detection, supported ecosystems, versioning, and coherent domain ownership
- prompt clarity, hallucination resistance, authority boundaries, conflicting instructions, review philosophy, and excessive prompt size
- review quality: duplicate findings, synthesis, prioritization, confidence, evidence, and actionable recommendations
- efficient current SDK usage, structured outputs, deterministic observations, model usage, and graceful failures
- overall product value, likely noise, overlap with specialist adversaries, and whether the review justifies its cost

Method:
- Treat deterministic signals as prepared facts. Do not repeat them as separate findings.
- Use source excerpts to make engineering judgments deterministic rules cannot make.
- Return zero to three important, high-confidence observations.
- Synthesize related evidence into one concern with one remediation.
- Cite only evidence IDs in the prepared input and use a real 1-based source line.
- Do not invent runtime behavior, catalog policy, files, or user requirements.
- Prefer silence over style feedback, speculative advice, or generic best practices.
- primaryConcern must be an empty string when ship=true; otherwise it must be a short noun phrase suitable after "I would address", with no terminal punctuation.

Return JSON matching the supplied schema and nothing else.`;

interface PreparedEvidence {
  id: string;
  path: string;
  line: number;
  message: string;
  snippet: string;
  source?: SourceFile;
}

interface ModelEvidence {
  evidenceId: string;
  line: number;
  detail: string;
}

interface ModelObservation {
  id: string;
  title: string;
  category:
    | "manifest-quality"
    | "prompt-quality"
    | "review-quality"
    | "sdk-usage"
    | "product-quality";
  severity: "low" | "medium" | "high" | "critical";
  confidence: "medium" | "high";
  summary: string;
  whyItMatters: string;
  recommendation: string;
  evidence: ModelEvidence[];
}

interface AdversaryModelOutput {
  schemaVersion: 1;
  assessment: {
    risk: "none" | "low" | "medium" | "high" | "critical";
    ship: boolean;
    summary: string;
    primaryConcern: string;
  };
  observations: ModelObservation[];
  strengths: Array<{ summary: string; evidenceIds: string[] }>;
}

interface PreparedReview {
  request: ModelReviewRequest;
  evidence: Map<string, PreparedEvidence>;
}

export function buildModelAdversaryReviewRequest(
  change: ChangeContext | null,
  project: AdversaryProject,
  detections: Detection[],
): PreparedReview {
  const evidence = new Map<string, PreparedEvidence>();
  const deterministicSignals = detections.slice(0, 60).map((detection, index) => {
    const id = `det:${index + 1}`;
    evidence.set(id, {
      id,
      path: detection.file,
      line: detection.line,
      message: detection.label,
      snippet: detection.snippet,
    });
    return {
      id,
      ruleId: detection.ruleId,
      severity: severity(detection.ruleId),
      confidence: detection.confidence ?? "high",
      path: detection.file,
      line: detection.line,
      observation: detection.label,
      data: detection.data ?? {},
    };
  });
  const sources = selectSources(project, change).map((source, index) => {
    const id = `source:${index + 1}`;
    const content = source.content.slice(0, MAX_SOURCE_CHARACTERS);
    evidence.set(id, {
      id,
      path: source.path,
      line: 1,
      message: `Prepared source excerpt for ${source.path}`,
      snippet: content.split(/\r?\n/).slice(0, 3).join("\n").slice(0, 300),
      source: { ...source, content },
    });
    return {
      id,
      path: source.path,
      changed: change?.changedFiles.includes(source.path) ?? false,
      truncated: content.length < source.content.length,
      content,
    };
  });
  return {
    evidence,
    request: {
      prompt: MODEL_PROMPT,
      input: {
        reviewScope: {
          scanMode: change?.scanMode ?? "all",
          changedFiles: [...(change?.changedFiles ?? [])].slice(0, 100),
          ...(change?.baseRef === undefined ? {} : { baseRef: change.baseRef }),
          ...(change?.headRef === undefined ? {} : { headRef: change.headRef }),
          worktree: change?.worktree ?? false,
        },
        project: {
          manifestName: project.manifest.name,
          manifestDescription: project.manifest.description,
          packageName: project.package?.name,
          rules: project.rules.map((rule) => rule.id).slice(0, 100),
          sourceFiles: project.sourceFiles.length,
          testFiles: project.testFiles.length,
          fixturePaths: project.fixturePaths.slice(0, 100),
        },
        deterministicSignals,
        sources,
      },
      schema: modelSchema as Record<string, unknown>,
      budget: {
        maximumOutputTokens: 5_000,
        timeoutMs: 120_000,
      },
    },
  };
}

export async function runModelAdversaryReview(
  ctx: RuleContext,
  project: AdversaryProject,
  detections: Detection[],
): Promise<"applied" | "unavailable"> {
  const prepared = buildModelAdversaryReviewRequest(ctx.change, project, detections);
  let output: AdversaryModelOutput;
  try {
    ({ output } = await ctx.model.review<AdversaryModelOutput>(prepared.request));
  } catch (error) {
    if (error instanceof ModelUnavailableError) return "unavailable";
    throw error;
  }

  const accepted = output.observations
    .slice(0, MAX_MODEL_OBSERVATIONS)
    .filter((observation) => emitModelObservation(ctx, observation, prepared.evidence));
  const staticRisk = maxRisk(detections.map((item) => severity(item.ruleId)));
  const modelRisk = maxRisk([
    output.assessment.risk,
    ...accepted.map((item) => item.severity),
  ]);
  const risk = maxRisk([staticRisk, modelRisk]);
  const blocking = riskRank(staticRisk) >= riskRank("medium") ||
    accepted.some((item) => riskRank(item.severity) >= riskRank("medium"));
  const ship = output.assessment.ship && !blocking;

  ctx.review.assessment({ risk, summary: output.assessment.summary });
  for (const [index, strength] of output.strengths.slice(0, 3).entries()) {
    const evidence = strength.evidenceIds
      .map((id) => prepared.evidence.get(id))
      .filter((item): item is PreparedEvidence => item !== undefined)
      .map((item) => evidenceInput(item, item.line, item.message));
    ctx.review.positive({
      key: `adversary.model.strength.${index + 1}`,
      summary: strength.summary,
      ...(evidence.length === 0 ? {} : { evidence }),
      metadata: { source: "model" },
    });
  }

  const topModel = accepted.slice().sort(
    (left, right) => riskRank(right.severity) - riskRank(left.severity) ||
      left.id.localeCompare(right.id),
  )[0];
  const concern = output.assessment.primaryConcern.trim() || topModel?.title ||
    staticConcern(detections);
  ctx.review.opinion(await formatOpinionAsync({
    ship,
    ...(ship || concern === undefined ? {} : { concern }),
    change: ctx.change,
    model: ctx.model,
  }));
  return "applied";
}

function emitModelObservation(
  ctx: RuleContext,
  observation: ModelObservation,
  catalog: ReadonlyMap<string, PreparedEvidence>,
): boolean {
  const evidence = observation.evidence
    .map((item) => {
      const prepared = catalog.get(item.evidenceId);
      if (prepared === undefined) return undefined;
      const line = prepared.source === undefined ? prepared.line : item.line;
      if (
        !Number.isInteger(line) ||
        line < 1 ||
        (prepared.source !== undefined && line > prepared.source.content.split(/\r?\n/).length)
      ) {
        return undefined;
      }
      return evidenceInput(prepared, line, item.detail);
    })
    .filter((item): item is EvidenceInput => item !== undefined)
    .slice(0, 8);
  if (evidence.length === 0) return false;

  for (const item of evidence) {
    ctx.observe({
      ruleId: `adversary.model.${observation.category}`,
      subject: observation.title,
      groupKey: `adversary.model.${observation.id}`,
      deduplicate: true,
      category: observation.category,
      severity: observation.severity as Severity,
      confidence: observation.confidence,
      title: { singular: observation.title, plural: observation.title },
      summary: { singular: observation.summary, grouped: observation.summary },
      whyItMatters: observation.whyItMatters,
      location: item,
      recommendation: observation.recommendation,
      remediation: {
        complexity: observation.severity === "low"
          ? "small"
          : observation.severity === "medium"
            ? "medium"
            : "large",
      },
      tags: ["adversary-authoring", "model-backed", observation.category],
      metadata: { source: "model", observationId: observation.id },
    });
  }
  return true;
}

function evidenceInput(
  prepared: PreparedEvidence,
  line: number,
  message: string,
): EvidenceInput {
  const lines = prepared.source?.content.split(/\r?\n/);
  const snippet = lines === undefined
    ? prepared.snippet
    : lines.slice(Math.max(0, line - 2), line + 1).join("\n").slice(0, 500);
  return {
    location: { file: prepared.path, line },
    message,
    ...(snippet === "" ? {} : { snippet }),
    data: { evidenceId: prepared.id },
  };
}

function selectSources(
  project: AdversaryProject,
  change: ChangeContext | null,
): SourceFile[] {
  const changed = new Set(change?.changedFiles ?? []);
  const candidates = project.files.filter((file) =>
    !file.path.startsWith("dist/") &&
    !file.path.includes("/fixtures/") &&
    (
      /^(?:adversary\.yaml|package\.json|tsconfig\.json|README\.md|AGENTS\.md)$/.test(file.path) ||
      /^(?:src|test|tests|docs)\/.*\.(?:ts|tsx|mts|cts|md)$/.test(file.path)
    ),
  );
  candidates.sort((left, right) => {
    const changedOrder = Number(changed.has(right.path)) - Number(changed.has(left.path));
    if (changedOrder !== 0) return changedOrder;
    return sourcePriority(left.path) - sourcePriority(right.path) ||
      left.path.localeCompare(right.path);
  });
  const selected: SourceFile[] = [];
  let total = 0;
  for (const candidate of candidates) {
    if (selected.length >= MAX_SOURCES || total >= MAX_TOTAL_CHARACTERS) break;
    const remaining = MAX_TOTAL_CHARACTERS - total;
    const content = candidate.content.slice(0, Math.min(MAX_SOURCE_CHARACTERS, remaining));
    selected.push({ ...candidate, content });
    total += content.length;
  }
  return selected;
}

function sourcePriority(path: string): number {
  if (path === "adversary.yaml") return 0;
  if (/prompt/i.test(path)) return 1;
  if (path === "README.md" || path === "AGENTS.md") return 2;
  if (path.startsWith("src/")) return 3;
  if (path.startsWith("test/") || path.startsWith("tests/")) return 4;
  return 5;
}

function maxRisk(
  risks: Array<"none" | "low" | "medium" | "high" | "critical">,
): "none" | "low" | "medium" | "high" | "critical" {
  return risks.reduce((best, current) =>
    riskRank(current) > riskRank(best) ? current : best, "none");
}

function riskRank(risk: "none" | "low" | "medium" | "high" | "critical"): number {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[risk];
}

function staticConcern(detections: Detection[]): string | undefined {
  const top = detections.slice().sort(
    (left, right) => riskRank(severity(right.ruleId)) - riskRank(severity(left.ruleId)),
  )[0];
  if (top === undefined) return undefined;
  if (top.ruleId === "adversary.typescript.manifest.invalid") return "the invalid adversary manifest";
  if (top.ruleId === "adversary.typescript.package.dependencies") return "undeclared runtime dependencies";
  if (top.ruleId === "adversary.typescript.build.output") return "unreliable build output";
  return "the material adversary authoring findings";
}
