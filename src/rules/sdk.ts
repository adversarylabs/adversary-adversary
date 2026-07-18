import { type AdversaryProject, type Detection, type SourceFile, lineOf, snippetAt } from "../model.js";
import { detection } from "./project.js";

const LEGACY = [
  ["defineRule", /import\s*\{[^}]*\bdefineRule\b[^}]*\}\s*from\s*["']@adversary(?:labs)?\/sdk/],
  ["replaceRule", /import\s*\{[^}]*\breplaceRule\b[^}]*\}\s*from\s*["']@adversary(?:labs)?\/sdk/],
  ["ruleRegistry", /import\s*\{[^}]*\bruleRegistry\b[^}]*\}\s*from\s*["']@adversary(?:labs)?\/sdk/],
] as const;

export function sdkDetections(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  for (const file of project.sourceFiles) {
    for (const [api, pattern] of LEGACY) {
      const match = pattern.exec(file.content);
      if (match) result.push(at(file, "adversary.typescript.sdk.legacy-api", api, "legacy", match.index, `${api} is a deprecated global SDK entry point`, { api }));
    }
    for (const candidate of presentation(file)) result.push(candidate);
    for (const candidate of reimplementation(file)) result.push(candidate);
    for (const candidate of observationEvidence(file)) result.push(candidate);
    for (const candidate of confidence(file)) result.push(candidate);
  }
  return result;
}

function presentation(file: SourceFile): Detection[] {
  const patterns: Array<[string, RegExp, string]> = [
    ["renderer", /new\s+(?:TerminalRenderer|JsonRenderer)\s*\(/g, "source invokes an SDK renderer directly"],
    ["runtime-output", /\bwriteOutput\s*\(|(?:writeFile|writeFileSync)\s*\([^\n]*(?:ADVERSARY_OUTPUT|\/adversary\/output\.json)/g, "source writes the runtime result directly"],
    ["console-review", /console\.(?:log|info)\s*\([^\n]*(?:Summary|Evidence|Recommendation|Severity|finding|review)/gi, "console output manually formats review presentation"],
    ["markdown-review", /[`"']#{1,3}\s*(?:Summary|Evidence|Recommendation|Findings|Overall assessment)/gi, "source contains a handcrafted review section"],
  ];
  return patterns.flatMap(([subject, pattern, label]) => [...file.content.matchAll(pattern)].map((match) => at(file, "adversary.typescript.presentation.manual", subject, "presentation", match.index ?? 0, label, { pattern: subject })));
}

function reimplementation(file: SourceFile): Detection[] {
  const patterns: Array<[string, RegExp, string]> = [
    ["ranking", /\b(?:rankFindings|sortFindings|rankedFindings)\s*\(/g, "source manually ranks findings"],
    ["confidence", /\bnormalizeConfidence\s*\(/g, "source manually normalizes confidence"],
    ["deduplication", /\b(?:deduplicateFindings|dedupeFindings|uniqueFindings)\s*\(/g, "source manually deduplicates findings"],
    ["suppression", /\b(?:suppressFindings|applySuppression)\s*\(/g, "source manually applies finding suppression"],
    ["title-pluralization", /title\s*:[^\n]*observations\.length\s*===?\s*1\s*\?/g, "rule aggregation manually selects singular and plural titles"],
  ];
  return patterns.flatMap(([subject, pattern, label]) => [...file.content.matchAll(pattern)].map((match) => at(file, "adversary.typescript.sdk.reimplementation", subject, "sdk", match.index ?? 0, label, { mechanism: subject })));
}

function observationEvidence(file: SourceFile): Detection[] {
  const result: Detection[] = [];
  for (const call of objectCalls(file.content, /ctx\.observe\s*\(/g)) {
    if (!/\blocation\s*:/.test(call.text) || !/\bevidence\s*:/.test(call.text)) {
      result.push(at(file, "adversary.typescript.observation.evidence", `observation-${call.line}`, "evidence", call.index, "observation does not include both location and evidence", { locationPresent: /\blocation\s*:/.test(call.text), evidencePresent: /\bevidence\s*:/.test(call.text) }));
    } else if (/evidence\s*:\s*\{\s*(?:metadata|data)\s*:/.test(call.text) && !/(?:label|snippet|message)\s*:/.test(call.text)) {
      result.push(at(file, "adversary.typescript.observation.evidence", `observation-${call.line}`, "evidence", call.index, "observation evidence is only opaque structured data", { opaqueOnly: true }));
    }
  }
  return result;
}

function confidence(file: SourceFile): Detection[] {
  const result: Detection[] = [];
  for (const call of objectCalls(file.content, /ctx\.observe\s*\(/g)) {
    if (/(?:confidence\s*:\s*(?:Confidence\.)?High|confidence\s*:\s*["']high["'])/.test(call.text) && /(?:heuristic|likely|appears|name-based|guess|infer)/i.test(call.text)) {
      result.push(at(file, "adversary.typescript.confidence.calibration", `observation-${call.line}`, "confidence", call.index, "heuristic observation is explicitly high-confidence", { confidence: "high", method: "heuristic language in detection" }));
    }
  }
  return result;
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

function at(file: SourceFile, ruleId: Detection["ruleId"], subject: string, suffix: string, index: number, label: string, data?: Record<string, unknown>): Detection {
  const line = file.content.slice(0, index).split(/\r?\n/).length;
  return detection(ruleId, subject, suffix, file.path, line, snippetAt(file.content, line), label, data);
}
