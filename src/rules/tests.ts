import { type AdversaryProject, type Detection, snippetAt } from "../model.js";
import { detection } from "./project.js";

export function testDetections(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  const tests = project.testFiles.map((file) => file.content).join("\n");
  const fixtureNames = new Set(project.fixturePaths.map((path) => path.split("/").find((part) => /^(?:good|clean)$/i.test(part))).filter(Boolean));
  const cleanAssertion = /(?:findings(?:\.length)?[^\n]*(?:0|\[\]|no material|zero)|deepEqual\([^\n]*findings[^\n]*\[\]\)|(?:0|zero|no material)[^\n]*findings)/i.test(tests);
  const cleanSnapshots = project.files.filter((file) => {
    if (!/(?:^|\/)fixtures?\/[^/]+\/expected\.review\.json$/.test(file.path)) return false;
    try {
      const value: unknown = JSON.parse(file.content);
      return typeof value === "object" && value !== null &&
        Array.isArray((value as { findings?: unknown }).findings) &&
        (value as { findings: unknown[] }).findings.length === 0;
    } catch {
      return false;
    }
  });
  const coveredCleanSnapshot = cleanSnapshots.some((file) => {
    const fixture = file.path.split("/").at(-2);
    return fixture !== undefined && tests.includes(fixture);
  });
  const hasClean = (fixtureNames.size > 0 && cleanAssertion) || coveredCleanSnapshot;
  if (!hasClean) {
    const file = project.testFiles[0];
    result.push(detection("adversary.typescript.tests.missing-clean-fixture", "clean-fixture", "tests", file?.path ?? "test/", 1, snippetAt(file?.content ?? "", 1), "tests do not demonstrate a representative clean fixture with zero material findings", { cleanFixtureDirectory: fixtureNames.size > 0, zeroFindingAssertion: cleanAssertion, coveredCleanSnapshot }));
  }

  const declared = [...new Set(project.rules.filter((item) => item.declared && item.id.split(".").length >= 3).map((item) => item.id))].sort();
  const missingPositive = declared.filter((id) => !tests.includes(id));
  const missingNegative = hasClean ? [] : declared;
  if (missingPositive.length > 0 || missingNegative.length > 0) {
    const file = project.testFiles[0];
    result.push(detection("adversary.typescript.tests.rule-coverage", "rule-coverage", "tests", file?.path ?? "test/", 1, snippetAt(file?.content ?? "", 1), `${missingPositive.length + missingNegative.length} behavioral rule-coverage gap(s) remain`, { missingPositive, missingNegative }));
  }

  const grouped = [...new Set(project.rules.filter((item) => item.declared && item.grouped).map((item) => item.id))].sort();
  const groupingSignals = /rawObservations|evidence\.length|observations\.length|groupKey|one finding|toHaveLength\(1\)/i.test(tests) && /(?:evidence|observations)[^\n]*(?:2|3|multiple)/i.test(tests);
  const missingGrouping = grouped.filter((id) => !tests.includes(id) || !groupingSignals);
  if (missingGrouping.length > 0) {
    const file = project.testFiles[0];
    result.push(detection("adversary.typescript.tests.grouping", "grouping-tests", "tests", file?.path ?? "test/", 1, snippetAt(file?.content ?? "", 1), `${missingGrouping.length} grouped rule(s) lack a multi-observation regression`, { rules: missingGrouping }));
  }
  return result;
}
