import { type AdversaryProject, type Detection, type RuleUse, snippetAt } from "../model.js";
import { detection } from "./project.js";

const WEAK_RECOMMENDATION = /^(?:fix (?:this|it)|improve (?:security|this|quality)|follow best practices|review the (?:configuration|code)|address this)[.!]?$/i;

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
  return result;
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
  return parts.length < 3 || /^(?:rule|check|test)\d*$/i.test(id) || /(?:^|[.-])(?:rule|check)[-_]?\d+$|(?:src|lib|index)[.-](?:line[-_.]?)?\d+/i.test(id);
}

function forRule(project: AdversaryProject, use: RuleUse, ruleId: Detection["ruleId"], suffix: string, label: string, data: Record<string, unknown>): Detection {
  const source = project.sourceFiles.find((file) => file.path === use.file)?.content ?? "";
  return detection(ruleId, use.id, suffix, use.file, use.line, snippetAt(source, use.line), label, data);
}
