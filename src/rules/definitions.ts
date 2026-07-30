import { Adversary, Confidence, Severity, type ObservationInit } from "@adversarylabs/sdk";
import { type Detection, type RuleId } from "../model.js";

interface Language {
  id: RuleId;
  category: string;
  severity: "low" | "medium" | "high";
  title: { singular: string; plural: string };
  summary: string;
  why: string;
  impact: string;
  recommendation: string;
  complexity: "trivial" | "small" | "medium" | "large";
}

const RULES: Language[] = [
  rule("adversary.typescript.identity.mismatch", "correctness", "medium", "Project identity is inconsistent", "Project identity fields are inconsistent", "Manifest, package, runtime, and built output do not describe one publishable artifact.", "Identity drift makes local builds and published execution refer to different names, versions, or entrypoints.", "Packaging may fail or publish an artifact whose runtime behavior cannot be correlated with its source release.", "Align manifest and package name/version fields, and make the declared runtime command match the TypeScript build output.", "small"),
  rule("adversary.typescript.manifest.invalid", "correctness", "high", "Adversary manifest is invalid", "Adversary manifest fields are invalid", "The canonical adversary.manifest.v1 schema rejects part of the project manifest.", "The manifest is the runtime and permission contract used during validation, packaging, and execution.", "The project cannot be packaged reliably, or may request a contract the runtime will reject.", "Correct the reported manifest field using the canonical v1 schema, then run `adversary validate .`.", "small"),
  rule("adversary.typescript.sdk.legacy-api", "sdk-usage", "medium", "Source uses a legacy SDK API", "Source uses legacy SDK APIs", "The implementation calls a deprecated or review-model-bypassing SDK entry point.", "Current instance-scoped definitions and structured review APIs preserve isolation and SDK-owned synthesis.", "An SDK upgrade can break the adversary or produce output that no longer follows the canonical review model.", "Replace the reported API with `app.defineRule`, `ctx.observe`, `ctx.finding`, or the corresponding `ctx.review` method.", "small"),
  rule("adversary.typescript.presentation.manual", "sdk-usage", "medium", "Adversary manually renders review output", "Adversary manually renders review output", "Source code constructs terminal, Markdown, JSON, or result-file presentation directly.", "Adversaries should report structured facts while the SDK/runtime owns consistent presentation.", "Handcrafted output can bypass grouping, suppression, schema validation, and renderer improvements.", "Emit structured observations and review notes; remove terminal formatting and direct runtime-result writes.", "medium"),
  rule("adversary.typescript.rule.id-quality", "rule-design", "low", "Rule ID is weak or unstable", "Rule IDs are weak or unstable", "A declared or emitted rule ID is generic, unnamespaced, or coupled to an implementation detail.", "Rule IDs are durable API keys for overrides, suppression, aggregation, and historical comparison.", "Renaming prose or moving code can break consumer policy and fragment the same concern across identifiers.", "Use a stable `<domain>.<concern>` or `<domain>.<area>.<concern>` identifier based on reviewed behavior rather than code location or wording.", "trivial"),
  rule("adversary.typescript.rule.grouping", "finding-quality", "low", "Rule grouping is likely too narrow", "Rule grouping is likely too narrow", "Observation grouping appears to include each evidence subject or is absent in a repeated-emission path.", "A repository review is more useful when evidence sharing one remediation becomes one concise finding.", "Users can receive one finding per occurrence and lose the higher-level engineering pattern.", "Choose an explicit grouping boundary—rule, file, job, subject, or shared key—that matches the remediation scope.", "small"),
  rule("adversary.typescript.observation.evidence", "finding-quality", "low", "Observation lacks useful evidence", "Observations lack useful evidence", "A structured observation does not identify both the source location and concern-specific evidence.", "Reviewers need to understand what was observed and where without reconstructing analyzer state.", "The finding can be correct but difficult to verify or act on.", "Add a precise location plus a label, snippet, or small structured data object tied directly to the concern.", "small"),
  rule("adversary.typescript.confidence.calibration", "finding-quality", "low", "Confidence is inconsistent with detection", "Confidence is inconsistent with detection", "A clearly heuristic detection is declared high-confidence.", "Confidence should communicate how directly the evidence supports the conclusion, independently of severity.", "Overstated confidence makes speculative findings crowd out deterministic problems.", "Lower heuristic inference to medium or low confidence, or strengthen it with parser or cross-file evidence.", "trivial"),
  rule("adversary.typescript.recommendation.weak", "finding-quality", "low", "Recommendation is not actionable", "Recommendations are not actionable", "A rule recommendation only asks the user to fix, improve, review, or follow best practices.", "A useful review should identify the concrete engineering change that resolves the observed concern.", "The user must repeat the analysis before they can begin remediation.", "Replace generic advice with the specific field, API, grouping boundary, permission, or test behavior to change.", "trivial"),
  rule("adversary.typescript.sdk.reimplementation", "sdk-usage", "medium", "Source reimplements an SDK responsibility", "Source reimplements SDK responsibilities", "The adversary duplicates ranking, deduplication, suppression, confidence normalization, or presentation owned by the SDK.", "Central SDK mechanics keep every adversary deterministic and make author upgrades inexpensive.", "Local copies drift from the canonical review contract and create inconsistent behavior across adversaries.", "Delete the local mechanism and express domain policy through rule definitions, grouping keys, and review configuration.", "medium"),
  rule("adversary.typescript.tests.missing-clean-fixture", "tests", "low", "Project has no representative clean fixture", "Project has no representative clean fixture", "Tests exercise detections but do not prove a realistic project can produce no material findings.", "A clean fixture is the most direct regression guard against an adversary becoming a false-positive generator.", "Rules may only be tested for firing and regress into reporting valid authoring patterns.", "Add a small clean adversary fixture and assert that its review contains no material findings.", "small"),
  rule("adversary.typescript.tests.missing-vulnerable-fixture", "tests", "low", "Rule lacks a positive vulnerable fixture", "Rules lack positive vulnerable fixtures", "Declared rules are never asserted to fire against a vulnerable fixture.", "Positive fixtures prove each rule still detects the failure mode it claims to own.", "A rule can silently stop firing while tests continue to pass on clean or unrelated cases.", "For each declared rule ID, add a vulnerable fixture and assert that the review emits that finding.", "medium"),
  rule("adversary.typescript.tests.rule-coverage", "tests", "low", "Rule lacks behavioral test coverage", "Rules lack behavioral test coverage", "Declared rules lack positive or clean negative behavioral evidence in the tests.", "Rule-level fixtures establish both sensitivity and restraint without relying on numerical code coverage.", "A rule can silently stop firing or begin flagging valid projects.", "For each listed rule ID, add a fixture where it fires and include it in a clean or focused negative assertion.", "medium"),
  rule("adversary.typescript.tests.grouping", "tests", "low", "Grouped rule lacks a grouping regression", "Grouped rules lack grouping regressions", "A rule designed to aggregate repeated observations has no multi-occurrence one-finding assertion.", "Single-occurrence tests do not exercise the grouping key or aggregation contract.", "A small group-key change can flood reviews with duplicate findings without failing tests.", "Add two or more related observations and assert that they synthesize into one finding with multiple evidence items.", "small"),
  rule("adversary.typescript.build.output", "packaging", "medium", "Build output is not publish-ready", "Build output is not publish-ready", "The project lacks a deterministic build command required to produce its runtime entrypoint during packaging.", "The runtime can only execute the JavaScript artifact named by the manifest after the package build completes.", "Packaging fails or ships source that cannot produce the declared runtime artifact.", "Provide a deterministic build script that produces the declared entrypoint during CLI packaging.", "small"),
  rule("adversary.typescript.package.contents", "packaging", "medium", "Package intent includes unnecessary or sensitive content", "Package intent includes unnecessary or sensitive content", "The effective package intent can include secrets, local state, or authoring-only fixtures.", "A published adversary should contain only runtime code, dependencies, manifest support files, license, and useful documentation.", "Sensitive data can be disclosed and unnecessary content increases package size and attack surface.", "Add precise `.adversaryignore` entries and remove credentials or transient files from the project before packaging.", "small"),
  rule("adversary.typescript.package.dependencies", "packaging", "high", "Runtime dependency is undeclared", "Runtime dependencies are undeclared", "Source imports a runtime package that is absent from production dependencies or exists only in devDependencies.", "Packed JavaScript must be able to resolve every non-bundled runtime import in a clean execution environment.", "The adversary can build locally yet fail immediately after packaging or publication.", "Move each reported package into `dependencies`, or bundle it and document that packaging step.", "small"),
  rule("adversary.typescript.permissions.broad", "security", "low", "Manifest permission appears broader than implementation", "Manifest permissions appear broader than implementation", "A requested network, write, or environment capability has no corresponding implementation use.", "Least-privilege manifests contain mistakes and compromised analyzers without limiting ordinary read-only review.", "The packaged adversary receives capabilities that its reviewed behavior does not require.", "Remove the unused capability or narrow it to the exact path or environment variable consumed by the implementation.", "trivial"),
  rule("adversary.typescript.publish.metadata", "publish-readiness", "low", "Publish metadata is incomplete", "Publish metadata is incomplete", "The project omits documentation or identity metadata expected from a credible published adversary.", "Users need a license, repository provenance, description, runtime, and usage example to evaluate and operate the package.", "The artifact may run correctly but remain difficult to adopt, audit, or maintain.", "Add the reported README usage, license, repository URL, description, version, or supported runtime metadata.", "small"),
  rule("adversary.typescript.llm.no-evidence-gate", "finding-quality", "high", "Model review can emit findings without evidence", "Model review can emit findings without evidence", "A model-review path emits findings without requiring citation or evidence arrays.", "Ungrounded model findings are a primary hallucination and trust failure mode for published adversaries.", "Users cannot verify claims, and false positives become expensive to suppress or refute.", "Require citationIds or evidence on model observation schemas, and drop observations that fail evidence validation before calling ctx.observe or ctx.finding.", "medium"),
  rule("adversary.typescript.name.not-domain", "correctness", "high", "Manifest name is not domain/name form", "Manifest names are not domain/name form", "The adversary.yaml name field is a flat or legacy identifier instead of catalog domain/name form.", "Free catalog identity is domain/name (for example meta/adversary), which drives install and run references.", "Flat names cannot be published on the free catalog path and fragment identity across tools.", "Set adversary.yaml name to `<domain>/<name>` using a stable domain such as go, ci, container, security, review, infra, deps, meta, cloud, or lang.", "trivial"),
  rule("adversary.typescript.determinism.unstable-output", "correctness", "high", "Analyzer uses non-deterministic output sources", "Analyzer uses non-deterministic output sources", "Source in analyze or review paths uses Math.random, crypto.randomUUID, or similar entropy when building findings.", "Identical inputs must produce identical findings for caching, diffs, suppression, and regression tests.", "Finding identities and ordering drift across runs, breaking trust and automated comparison.", "Remove randomness and wall-clock entropy from finding identity; sort multi-finding emission by a stable key before observe.", "small"),
];

function rule(id: RuleId, category: string, severity: "low" | "medium" | "high", singular: string, plural: string, summary: string, why: string, impact: string, recommendation: string, complexity: Language["complexity"]): Language {
  return { id, category, severity, title: { singular, plural }, summary, why, impact, recommendation, complexity };
}

const BY_ID = new Map(RULES.map((item) => [item.id, item]));

export function registerRules(app: Adversary): void {
  for (const item of RULES) app.defineRule({
    id: item.id, category: item.category, defaultSeverity: item.severity, defaultConfidence: Confidence.High,
    aggregate(observations) {
      return {
        category: item.category,
        summary: `${item.summary} (${observations.length} observation${observations.length === 1 ? "" : "s"}).`,
        whyItMatters: item.why, impact: item.impact, recommendation: item.recommendation,
        remediation: { complexity: item.complexity }, tags: ["adversary-authoring", item.category],
      };
    },
  });
}

export function observation(detection: Detection): ObservationInit {
  const item = BY_ID.get(detection.ruleId);
  if (item === undefined) throw new Error(`Unknown rule ${detection.ruleId}`);
  return {
    ruleId: detection.ruleId, subject: detection.subject, groupKey: detection.groupKey,
    title: item.title, category: item.category, severity: item.severity,
    confidence: detection.confidence ?? Confidence.High,
    location: { file: detection.file, line: detection.line, snippet: detection.snippet, label: detection.label },
    evidence: { label: detection.label, ...detection.data },
    recommendation: item.recommendation, tags: ["adversary-authoring", item.category],
  };
}

export function severity(ruleId: RuleId): "low" | "medium" | "high" {
  return BY_ID.get(ruleId)?.severity ?? Severity.Low;
}
