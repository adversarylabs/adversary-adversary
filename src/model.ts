export type JsonMap = Record<string, unknown>;

export interface SourceFile {
  path: string;
  content: string;
  mtimeMs: number;
}

export interface PackageModel {
  name?: string;
  version?: string;
  description?: string;
  license?: string;
  repository?: unknown;
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  raw: JsonMap;
}

export interface ManifestModel {
  raw?: JsonMap;
  source?: SourceFile;
  errors: ManifestError[];
  name?: string;
  version?: string;
  description?: string;
  runtimeName?: string;
  runtimeVersion?: string;
  entrypoint?: string;
  filesystemRead: string[];
  filesystemWrite: string[];
  network?: boolean;
  environmentAllow: string[];
}

export interface ManifestError {
  message: string;
  line: number;
  snippet: string;
  field?: string;
}

export interface RuleUse {
  id: string;
  file: string;
  line: number;
  declared: boolean;
  defaultConfidence?: string;
  recommendation?: string;
  grouped: boolean;
}

export interface AdversaryProject {
  root: string;
  recognized: boolean;
  sdkConfirmed: boolean;
  files: SourceFile[];
  sourceFiles: SourceFile[];
  testFiles: SourceFile[];
  manifest: ManifestModel;
  package?: PackageModel;
  tsconfig?: JsonMap;
  rules: RuleUse[];
  fixturePaths: string[];
  ignorePatterns: string[];
}

export interface Detection {
  ruleId: RuleId;
  subject: string;
  groupKey: string;
  file: string;
  line: number;
  snippet: string;
  label: string;
  data?: Record<string, unknown>;
  confidence?: "low" | "medium" | "high";
}

export type RuleId =
  | "adversary.typescript.identity.mismatch"
  | "adversary.typescript.manifest.invalid"
  | "adversary.typescript.sdk.legacy-api"
  | "adversary.typescript.presentation.manual"
  | "adversary.typescript.rule.id-quality"
  | "adversary.typescript.rule.grouping"
  | "adversary.typescript.observation.evidence"
  | "adversary.typescript.confidence.calibration"
  | "adversary.typescript.recommendation.weak"
  | "adversary.typescript.sdk.reimplementation"
  | "adversary.typescript.tests.missing-clean-fixture"
  | "adversary.typescript.tests.rule-coverage"
  | "adversary.typescript.tests.grouping"
  | "adversary.typescript.build.output"
  | "adversary.typescript.package.contents"
  | "adversary.typescript.package.dependencies"
  | "adversary.typescript.permissions.broad"
  | "adversary.typescript.publish.metadata";

export function isRecord(value: unknown): value is JsonMap {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function lineOf(source: string, needle: string): number {
  const index = source.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index < 0 ? 1 : index + 1;
}

export function snippetAt(source: string, line: number): string {
  return source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "";
}

