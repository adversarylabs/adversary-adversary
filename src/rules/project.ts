import {
  type AdversaryProject,
  type Detection,
  snippetAt,
  topLevelJsonPropertyLine,
} from "../model.js";

export function projectDetections(project: AdversaryProject): Detection[] {
  return [...manifest(project), ...identity(project), ...nameDomain(project), ...build(project), ...metadata(project)];
}

/**
 * Catalog identity is domain/name (e.g. go/security, review/engineering).
 * The first-party self-reviewer uses the publisher path adversarylabs/adversary.
 * Do not use meta/* — that domain is retired.
 */
const DOMAIN_NAME = /^[a-z0-9][a-z0-9-]*\/[a-z0-9][a-z0-9-]*$/;
const PUBLISHER_PATH = /^adversarylabs\/[a-z0-9][a-z0-9-]*$/;
const RETIRED_META = /^meta\//;

function isValidCatalogName(name: string): boolean {
  if (RETIRED_META.test(name)) return false;
  return DOMAIN_NAME.test(name) || PUBLISHER_PATH.test(name);
}

function nameDomain(project: AdversaryProject): Detection[] {
  const name = project.manifest.name;
  if (name === undefined || name.trim() === "") return [];
  if (isValidCatalogName(name)) return [];
  const source = project.manifest.source?.content ?? "";
  const line = project.manifest.locations.name ?? 1;
  const expected = RETIRED_META.test(name)
    ? "domain/name (not meta/*); first-party self-reviewer is adversarylabs/adversary"
    : "domain/name or adversarylabs/<name>";
  return [detection(
    "adversary.typescript.name.not-domain",
    name,
    "name",
    "adversary.yaml",
    line,
    snippetAt(source, line),
    RETIRED_META.test(name)
      ? `manifest name ${name} uses retired meta/* catalog domain`
      : `manifest name ${name} is not valid catalog form`,
    { name, expected },
  )];
}

function manifest(project: AdversaryProject): Detection[] {
  return project.manifest.errors.map((error) => detection(
    "adversary.typescript.manifest.invalid", error.field ?? "adversary.yaml", "manifest",
    "adversary.yaml", error.line, error.snippet, error.message,
    { field: error.field, error: error.message },
  ));
}

function identity(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  const manifest = project.manifest;
  const pkg = project.package;
  if (pkg === undefined) return result;
  if (manifest.name && pkg.name && !packageNameMatchesCatalog(manifest.name, pkg.name)) {
    const line = packageLine(project, "name");
    result.push(detection("adversary.typescript.identity.mismatch", "name", "identity", "package.json", line, packageSnippet(project, line), `package name ${pkg.name} disagrees with manifest name ${manifest.name}`, { manifest: manifest.name, package: pkg.name }));
  }
  if (manifest.version && pkg.version && manifest.version !== pkg.version) {
    const line = packageLine(project, "version");
    result.push(detection("adversary.typescript.identity.mismatch", "version", "identity", "package.json", line, packageSnippet(project, line), `package version ${pkg.version} disagrees with manifest version ${manifest.version}`, { manifest: manifest.version, package: pkg.version }));
  }
  const outDir = compilerString(project, "outDir") ?? "dist";
  const rootDir = compilerString(project, "rootDir") ?? "src";
  if (manifest.runtimeName === "node" && manifest.entrypoint && !manifest.entrypoint.startsWith(`${outDir}/`)) {
    const source = manifest.source?.content ?? "";
    const line = manifest.locations["runtime.command"] ?? 1;
    result.push(detection("adversary.typescript.identity.mismatch", "entrypoint", "identity", "adversary.yaml", line, snippetAt(source, line), `runtime entrypoint ${manifest.entrypoint} is outside TypeScript outDir ${outDir}`, { entrypoint: manifest.entrypoint, outDir, rootDir }));
  }
  return result;
}

function packageNameMatchesCatalog(manifestName: string, packageName: string): boolean {
  if (manifestName === packageName) return true;
  if (!isValidCatalogName(manifestName) || packageName.includes("/") || packageName.startsWith("@")) return false;
  return manifestName.replace("/", "-") === packageName;
}

function build(project: AdversaryProject): Detection[] {
  const result: Detection[] = [];
  const pkg = project.package;
  const hasBuild = Boolean(pkg?.scripts.build);
  if (!hasBuild) {
    const line = packageLine(project, "scripts");
    result.push(detection("adversary.typescript.build.output", "build-script", "build", "package.json", line, packageSnippet(project, line), "package.json has no build script", { expected: "a deterministic TypeScript build command" }));
  }
  const entrypoint = project.manifest.entrypoint;
  if (entrypoint && !hasBuild) {
    const built = project.files.find((file) => file.path === entrypoint);
    if (built === undefined) {
      const source = project.manifest.source?.content ?? "";
      const line = project.manifest.locations["runtime.command"] ?? 1;
      result.push(detection("adversary.typescript.build.output", entrypoint, "build", "adversary.yaml", line, snippetAt(source, line), `declared entrypoint ${entrypoint} does not exist`, { entrypoint }));
    } else {
      const newer = project.sourceFiles.filter((file) => file.mtimeMs > built.mtimeMs + 1000);
      const distIntended = project.files.some((file) => file.path.startsWith("dist/"));
      if (distIntended && newer.length > 0) result.push(detection("adversary.typescript.build.output", entrypoint, "build", newer[0]?.path ?? entrypoint, 1, snippetAt(newer[0]?.content ?? "", 1), `${newer.length} source file(s) are newer than the declared build output and no release build is configured`, { entrypoint, newerSources: newer.slice(0, 10).map((file) => file.path) }));
    }
  }
  return result;
}

function metadata(project: AdversaryProject): Detection[] {
  const missing: string[] = [];
  if (!project.manifest.description && !project.package?.description) missing.push("description");
  if (!project.manifest.version && !project.package?.version) missing.push("version");
  if (!project.manifest.runtimeName) missing.push("supported runtime");
  if (!project.files.some((file) => /^README\.md$/i.test(file.path))) missing.push("README");
  if (!project.files.some((file) => /^LICENSE(?:\..*)?$/i.test(file.path))) missing.push("license");
  if (project.package?.repository === undefined) missing.push("repository URL");
  const readme = project.files.find((file) => /^README\.md$/i.test(file.path));
  if (readme && !/(?:adversary\s+run|##\s+(?:Usage|Running)|npm\s+(?:test|run))/i.test(readme.content)) missing.push("README usage example");
  if (missing.length === 0) return [];
  const file = readme?.path ?? "package.json";
  return [detection("adversary.typescript.publish.metadata", "metadata", "metadata", file, 1, snippetAt(readme?.content ?? "", 1), `publish metadata is missing ${missing.join(", ")}`, { missing })];
}

function compilerString(project: AdversaryProject, key: string): string | undefined {
  const compiler = project.tsconfig?.compilerOptions;
  return typeof compiler === "object" && compiler !== null && !Array.isArray(compiler) && typeof (compiler as Record<string, unknown>)[key] === "string" ? (compiler as Record<string, string>)[key] : undefined;
}

function packageLine(project: AdversaryProject, property: string): number {
  return topLevelJsonPropertyLine(
    project.files.find((file) => file.path === "package.json")?.content ?? "",
    property,
  );
}
function packageSnippet(project: AdversaryProject, line: number): string { return snippetAt(project.files.find((file) => file.path === "package.json")?.content ?? "", line); }

export function detection(ruleId: Detection["ruleId"], subject: string, suffix: string, file: string, line: number, snippet: string, label: string, data?: Record<string, unknown>): Detection {
  return { ruleId, subject, groupKey: `${ruleId}:${suffix}`, file, line, snippet, label, data };
}
