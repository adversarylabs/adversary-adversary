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
  locations: Record<string, number>;
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
  | "adversary.typescript.tests.missing-vulnerable-fixture"
  | "adversary.typescript.tests.rule-coverage"
  | "adversary.typescript.tests.grouping"
  | "adversary.typescript.build.output"
  | "adversary.typescript.package.contents"
  | "adversary.typescript.package.dependencies"
  | "adversary.typescript.permissions.broad"
  | "adversary.typescript.publish.metadata"
  | "adversary.typescript.llm.no-evidence-gate"
  | "adversary.typescript.name.not-domain"
  | "adversary.typescript.determinism.unstable-output";

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

export function topLevelJsonPropertyLine(source: string, property: string): number {
  let objectDepth = 0;
  let line = 1;
  for (let index = 0; index < source.length;) {
    const character = source[index];
    if (character === "\n") {
      line += 1;
      index += 1;
      continue;
    }
    if (character === "{") {
      objectDepth += 1;
      index += 1;
      continue;
    }
    if (character === "}") {
      objectDepth -= 1;
      index += 1;
      continue;
    }
    if (character !== "\"") {
      index += 1;
      continue;
    }

    const tokenLine = line;
    const tokenStart = index;
    index += 1;
    let escaped = false;
    while (index < source.length) {
      const tokenCharacter = source[index];
      if (tokenCharacter === "\n") line += 1;
      if (!escaped && tokenCharacter === "\"") {
        index += 1;
        break;
      }
      escaped = !escaped && tokenCharacter === "\\";
      if (tokenCharacter !== "\\") escaped = false;
      index += 1;
    }
    if (objectDepth !== 1) continue;

    let cursor = index;
    while (cursor < source.length && /\s/.test(source[cursor] ?? "")) cursor += 1;
    if (source[cursor] !== ":") continue;
    try {
      if (JSON.parse(source.slice(tokenStart, index)) === property) return tokenLine;
    } catch {
      return 1;
    }
  }
  return 1;
}

export function snippetAt(source: string, line: number): string {
  return source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "";
}
