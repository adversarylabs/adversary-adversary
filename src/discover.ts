import { readFile, readdir, stat } from "node:fs/promises";
import { join, sep } from "node:path";
import { parseManifest } from "./manifest.js";
import { type AdversaryProject, type JsonMap, type PackageModel, type RuleUse, type SourceFile, isRecord } from "./model.js";

const MAX_FILES = 5000;
const SKIP = new Set([".git", "node_modules", ".cache", "coverage"]);

export async function discoverProject(root: string): Promise<AdversaryProject> {
  const files = await inventory(root);
  const byPath = new Map(files.map((file) => [file.path, file]));
  const sourceFiles = files.filter((file) => /^src\/.*\.(?:ts|tsx|mts|cts)$/.test(file.path));
  const testFiles = files.filter((file) => /^(?:test|tests)\/.*\.(?:ts|tsx|mts|cts|js|mjs)$/.test(file.path));
  const manifest = await parseManifest(byPath.get("adversary.yaml"));
  const packageModel = parsePackage(byPath.get("package.json"));
  const tsconfig = parseJson(byPath.get("tsconfig.json"));
  const sdkDependency = packageModel !== undefined && Object.keys({ ...packageModel.dependencies, ...packageModel.devDependencies })
    .some((name) => name === "@adversarylabs/sdk" || name === "@adversary/sdk");
  const sdkImport = sourceFiles.some((file) => /from\s+["']@adversary(?:labs)?\/sdk["']|require\(["']@adversary(?:labs)?\/sdk["']\)/.test(file.content));
  const required = ["adversary.yaml", "package.json", "tsconfig.json"].every((path) => byPath.has(path)) && sourceFiles.length > 0;
  const fixturePaths = files.map((file) => file.path).filter((path) => /(?:^|\/)(?:fixtures?|test\/fixtures|tests\/fixtures)\//.test(path));
  const ignorePatterns = byPath.get(".adversaryignore")?.content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#")) ?? [];
  return {
    root,
    recognized: required && (sdkDependency || sdkImport),
    sdkConfirmed: sdkDependency || sdkImport,
    files,
    sourceFiles,
    testFiles,
    manifest,
    package: packageModel,
    tsconfig,
    rules: extractRules(sourceFiles),
    fixturePaths,
    ignorePatterns,
  };
}

async function inventory(root: string): Promise<SourceFile[]> {
  const result: SourceFile[] = [];
  async function visit(directory: string): Promise<void> {
    if (result.length >= MAX_FILES) return;
    let entries;
    try { entries = await readdir(join(root, directory), { withFileTypes: true }); } catch { return; }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (result.length >= MAX_FILES) break;
      const path = posix(directory ? join(directory, entry.name) : entry.name);
      if (entry.isDirectory()) {
        if (!SKIP.has(entry.name)) await visit(path);
      } else if (entry.isFile() && shouldRead(path)) {
        const absolute = join(root, path);
        const info = await stat(absolute);
        if (info.size <= 2_000_000) result.push({ path, content: await readFile(absolute, "utf8"), mtimeMs: info.mtimeMs });
      }
    }
  }
  await visit("");
  return result.sort((left, right) => left.path.localeCompare(right.path));
}

function shouldRead(path: string): boolean {
  return path.length > 0;
}

function parsePackage(file: SourceFile | undefined): PackageModel | undefined {
  const raw = parseJson(file);
  if (raw === undefined) return undefined;
  return {
    name: typeof raw.name === "string" ? raw.name : undefined,
    version: typeof raw.version === "string" ? raw.version : undefined,
    description: typeof raw.description === "string" ? raw.description : undefined,
    license: typeof raw.license === "string" ? raw.license : undefined,
    repository: raw.repository,
    scripts: stringMap(raw.scripts),
    dependencies: stringMap(raw.dependencies),
    devDependencies: stringMap(raw.devDependencies),
    raw,
  };
}

function parseJson(file: SourceFile | undefined): JsonMap | undefined {
  if (file === undefined) return undefined;
  try { const value: unknown = JSON.parse(file.content); return isRecord(value) ? value : undefined; } catch { return undefined; }
}

function stringMap(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

function extractRules(files: SourceFile[]): RuleUse[] {
  const uses: RuleUse[] = [];
  for (const file of files) {
    const lines = file.content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? "";
      const definition = line.match(/\bid\s*:\s*["'`]([^"'`$]+)["'`]/);
      const handler = line.match(/\.rule\(\s*["'`]([^"'`$]+)["'`]/);
      const helperDefinition = line.match(/\brule\(\s*["'`]([^"'`$]+)["'`]/);
      const observation = line.match(/\bruleId\s*:\s*["'`]([^"'`$]+)["'`]/);
      const match = definition ?? handler ?? helperDefinition ?? observation;
      if (match?.[1] === undefined) continue;
      const window = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 18)).join("\n");
      uses.push({
        id: match[1], file: file.path, line: index + 1,
        declared: definition !== null || (helperDefinition !== null && handler === null),
        defaultConfidence: window.match(/defaultConfidence\s*:\s*(?:Confidence\.)?(\w+)/)?.[1]?.toLowerCase(),
        recommendation: window.match(/recommendation\s*:\s*["'`]([^"'`]+)["'`]/)?.[1],
        grouped: /group(?:Key|By)\s*:/.test(window),
      });
    }
  }
  return unique(uses, (item) => `${item.file}:${item.line}:${item.id}`);
}

function unique<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => { const value = key(item); if (seen.has(value)) return false; seen.add(value); return true; });
}

function posix(path: string): string { return path.split(sep).join("/"); }
