import { type AdversaryProject, type Detection, type RuleUse, type SourceFile, snippetAt } from "../model.js";
import { detection } from "./project.js";

const WEAK_RECOMMENDATION = /^(?:fix (?:this|it)|improve (?:security|this|quality)|follow best practices|review the (?:configuration|code)|address this)[.!]?$/i;
const MODEL_REVIEW = /\bctx\.model\.review\b|\.model\.review\s*[<(]/;
const UNSTABLE_RANDOM = /\b(?:Math\.random|crypto\.randomUUID|randomUUID)\s*\(/g;
const UNSTABLE_CLOCK = /\bDate\.now\s*\(|\bnew\s+Date\s*\(/g;
const EVIDENCE_GATE = /evidence\.length\s*[>!]=\s*0|filter\s*\(\s*(?:item|observation|obs|entry)\s*=>[\s\S]{0,120}?evidence|\.filter\s*\([^)]*evidence|invalidEvidence|citationIds?|prepareModelObservation|"evidence"\s*(?:,|\])/;

export function qualityDetections(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  for (const use of project.rules) {
    const source = project.sourceFiles.find((file) => file.path === use.file)?.content ?? "";
    const publicRuleId = use.declared || /\bruleId\s*:/.test(source.split(/\r?\n/)[use.line - 1] ?? "");
    if (!publicRuleId) continue;
    if (weakId(use.id)) result.push(forRule(project, use, "adversary.typescript.rule.id-quality", "ids", `${use.id} is not a stable namespaced rule ID`, { rule: use.id }));
    if (use.recommendation && WEAK_RECOMMENDATION.test(use.recommendation.trim())) result.push(forRule(project, use, "adversary.typescript.recommendation.weak", "recommendations", `${use.id} uses a generic recommendation`, { rule: use.id, recommendation: use.recommendation }));
  }
  result.push(...grouping(project));
  result.push(...llmEvidenceGate(project));
  result.push(...determinism(project));
  return result;
}

function llmEvidenceGate(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  for (const file of project.files) {
    if (!/(?:^|\/)schema\/|\.schema\.json$/i.test(file.path) && !/model.*\.(?:json|ts)$/i.test(file.path)) continue;
    if (!/"observations"/.test(file.content)) continue;
    if (schemaRequiresObservationEvidence(file.content)) continue;
    const line = lineMatching(file.content, /"observations"/) ?? 1;
    result.push(detection(
      "adversary.typescript.llm.no-evidence-gate",
      file.path,
      "llm-schema",
      file.path,
      line,
      snippetAt(file.content, line),
      "model observation schema does not require evidence or citationIds",
      { path: file.path, reason: "schema" },
    ));
  }

  for (const file of project.sourceFiles) {
    if (!MODEL_REVIEW.test(file.content)) continue;
    const emits = /\bctx\.(?:observe|finding)\s*\(/.test(file.content);
    if (!emits) continue;
    const gated = EVIDENCE_GATE.test(file.content) || sourceRequiresCitationEvidence(file);
    if (gated) continue;
    const match = MODEL_REVIEW.exec(file.content);
    const index = match?.index ?? 0;
    const line = file.content.slice(0, index).split(/\r?\n/).length;
    result.push(detection(
      "adversary.typescript.llm.no-evidence-gate",
      file.path,
      "llm-emit",
      file.path,
      line,
      snippetAt(file.content, line),
      "model-review path emits findings without an evidence or citation gate",
      { path: file.path, reason: "ungated-emit" },
    ));
  }

  for (const file of project.sourceFiles) {
    if (!MODEL_REVIEW.test(file.content) && !/model-review|ModelObservation|model\.review/i.test(file.path + file.content.slice(0, 200))) {
      // Still inspect finding calls that look model-backed without evidence arrays.
    }
    for (const call of objectCalls(file.content, /\bctx\.finding\s*\(/g)) {
      const hasEvidence = /\bevidence\s*:/.test(call.text) || /\bcitationIds?\s*:/.test(call.text);
      if (hasEvidence) continue;
      // Only flag finding() without evidence when the file participates in model review.
      if (!MODEL_REVIEW.test(file.content) && !/\bmodel\b/i.test(file.path)) continue;
      result.push(detection(
        "adversary.typescript.llm.no-evidence-gate",
        `finding-${call.line}`,
        "llm-finding",
        file.path,
        call.line,
        snippetAt(file.content, call.line),
        "ctx.finding in a model-review path omits evidence or citationIds",
        { path: file.path, reason: "finding-without-evidence" },
      ));
    }
  }
  return uniqueDetections(result);
}

function schemaRequiresObservationEvidence(source: string): boolean {
  try {
    const value: unknown = JSON.parse(source);
    const required = observationRequiredFields(value);
    if (required === undefined) {
      // Not a JSON schema we understand; fall through to text heuristics.
    } else {
      return required.includes("evidence") || required.includes("citationIds") || required.includes("citationId");
    }
  } catch {
    // TypeScript or non-JSON schema sources use text heuristics below.
  }
  const observationBlock = source.match(/"observations"\s*:\s*\{[\s\S]{0,4000}?"items"\s*:\s*\{[\s\S]{0,4000}?"required"\s*:\s*\[([^\]]*)\]/);
  if (observationBlock?.[1] !== undefined) {
    return /["']evidence["']|["']citationIds?["']/.test(observationBlock[1]);
  }
  // Interface-style: evidence: ModelEvidence[] as a required field on observations
  if (/evidence\s*:\s*(?:ModelEvidence|Array|\[)/.test(source) && /citationId/.test(source)) return true;
  return false;
}

function observationRequiredFields(value: unknown): string[] | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const root = value as Record<string, unknown>;
  const props = (root.properties ?? root) as Record<string, unknown>;
  const observations = (props as { observations?: unknown }).observations;
  if (typeof observations !== "object" || observations === null) return undefined;
  const items = (observations as { items?: unknown }).items;
  if (typeof items !== "object" || items === null) return undefined;
  const required = (items as { required?: unknown }).required;
  return Array.isArray(required) ? required.filter((item): item is string => typeof item === "string") : [];
}

function sourceRequiresCitationEvidence(file: SourceFile): boolean {
  // Location-carrying EvidenceInput patterns used when emitting model observations.
  return /location\s*:\s*item\b|evidenceInput\s*\(|for\s*\(\s*const\s+\w+\s+of\s+evidence\b/.test(file.content);
}

function determinism(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  for (const file of project.sourceFiles) {
    for (const match of file.content.matchAll(UNSTABLE_RANDOM)) {
      const index = match.index ?? 0;
      const line = file.content.slice(0, index).split(/\r?\n/).length;
      result.push(detection(
        "adversary.typescript.determinism.unstable-output",
        `${file.path}:${line}`,
        "determinism",
        file.path,
        line,
        snippetAt(file.content, line),
        `${match[0].replace(/\s*\($/, "()")} makes finding identity non-deterministic`,
        { api: match[0].replace(/\s*\($/, "") },
      ));
    }
    for (const match of file.content.matchAll(UNSTABLE_CLOCK)) {
      const index = match.index ?? 0;
      const start = Math.max(0, index - 160);
      const end = Math.min(file.content.length, index + 160);
      const window = file.content.slice(start, end);
      if (!/\b(?:id|subject|groupKey|ruleId|finding|observation)\b/i.test(window)) continue;
      const line = file.content.slice(0, index).split(/\r?\n/).length;
      result.push(detection(
        "adversary.typescript.determinism.unstable-output",
        `${file.path}:${line}`,
        "determinism",
        file.path,
        line,
        snippetAt(file.content, line),
        "wall-clock time is used near finding identity construction",
        { api: match[0].replace(/\s*\($/, "") },
      ));
    }

    // Multi-observation emission without a stable sort of the collected findings/detections.
    const multiEmit = /(?:detections|findings|observations|results)\s*(?:\.\s*push\s*\(|\s*=\s*\[)/.test(file.content) &&
      /\bctx\.(?:observe|finding)\s*\(/.test(file.content);
    const sorts = /\.sort\s*\(/.test(file.content);
    const loopObserve = /(?:for\s*\(|\.map\s*\(|for\s+await)[\s\S]{0,400}?\bctx\.(?:observe|finding)\s*\(/.test(file.content);
    if (multiEmit && loopObserve && !sorts) {
      const match = /\bctx\.(?:observe|finding)\s*\(/.exec(file.content);
      const index = match?.index ?? 0;
      const line = file.content.slice(0, index).split(/\r?\n/).length;
      result.push(detection(
        "adversary.typescript.determinism.unstable-output",
        `${file.path}:unsorted`,
        "determinism-order",
        file.path,
        line,
        snippetAt(file.content, line),
        "multiple findings are emitted without a stable sort",
        { reason: "unsorted-multi-emit" },
      ));
    }
  }
  return uniqueDetections(result);
}

function objectCalls(source: string, pattern: RegExp): Array<{ text: string; index: number; line: number }> {
  const result: Array<{ text: string; index: number; line: number }> = [];
  for (const match of source.matchAll(pattern)) {
    const index = match.index ?? 0;
    const open = source.indexOf("{", index + match[0].length);
    if (open < 0 || source.slice(index, open).includes(")")) continue;
    let depth = 0;
    let quote = "";
    for (let cursor = open; cursor < source.length; cursor += 1) {
      const char = source[cursor] ?? "";
      const previous = source[cursor - 1] ?? "";
      if (quote) { if (char === quote && previous !== "\\") quote = ""; continue; }
      if (char === '"' || char === "'" || char === "`") { quote = char; continue; }
      if (char === "{") depth += 1;
      if (char === "}") depth -= 1;
      if (depth === 0) { result.push({ text: source.slice(open, cursor + 1), index, line: source.slice(0, index).split(/\r?\n/).length }); break; }
    }
  }
  return result;
}

function lineMatching(source: string, pattern: RegExp): number | undefined {
  const match = pattern.exec(source);
  if (match?.index === undefined) return undefined;
  return source.slice(0, match.index).split(/\r?\n/).length;
}

function uniqueDetections(items: Detection[]): Detection[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.ruleId}:${item.file}:${item.line}:${item.subject}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function grouping(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  for (const file of project.sourceFiles) {
    const lines = file.content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      if (!/\bgroupKey\s*:/.test(line)) continue;
      const value = line.match(/groupKey\s*:\s*([^,}\n]+)/)?.[1] ?? "";
      if (/\$\{\s*(?:subject|task\.id|job(?:Name|\.id)|stage(?:Name|\.id)|observation\.subject)\s*\}/.test(value)) {
        result.push(detection("adversary.typescript.rule.grouping", `${file.path}:${index + 1}`, "grouping", file.path, index + 1, line.trim(), "groupKey includes the individual evidence subject", { groupKey: value.trim(), suggestedBoundary: "rule, file, job, or shared remediation key" }));
      }
    }
    const loopObserve = /(?:for\s*\(|\.map\s*\()[\s\S]{0,500}?ctx\.observe\s*\(\s*\{/.exec(file.content);
    if (loopObserve) {
      const block = file.content.slice(loopObserve.index, loopObserve.index + loopObserve[0].length + 500);
      if (!/group(?:Key|By)\s*:/.test(block)) {
        const line = file.content.slice(0, loopObserve.index).split(/\r?\n/).length;
        result.push(detection("adversary.typescript.rule.grouping", `${file.path}:${line}`, "grouping", file.path, line, snippetAt(file.content, line), "a repeated observation path has no explicit grouping boundary", { suggestedBoundary: "choose rule, file, subject, or an explicit shared key" }));
      }
    }
  }
  return result;
}

function weakId(id: string): boolean {
  const parts = id.split(".");
  return parts.length < 2 ||
    parts.some((part) => part.trim() === "") ||
    /^(?:rule|check|test)\d*$/i.test(id) ||
    /(?:^|[.-])(?:rule|check)[-_]?\d+$|(?:src|lib|index)[.-](?:line[-_.]?)?\d+/i.test(id);
}

function forRule(project: AdversaryProject, use: RuleUse, ruleId: Detection["ruleId"], suffix: string, label: string, data: Record<string, unknown>): Detection {
  const source = project.sourceFiles.find((file) => file.path === use.file)?.content ?? "";
  return detection(ruleId, use.id, suffix, use.file, use.line, snippetAt(source, use.line), label, data);
}
