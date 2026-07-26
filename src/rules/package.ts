import { type AdversaryProject, type Detection, type SourceFile, lineOf, snippetAt } from "../model.js";
import { detection } from "./project.js";

const BUILTINS = new Set(["assert", "buffer", "child_process", "crypto", "events", "fs", "http", "https", "module", "net", "os", "path", "process", "stream", "url", "util", "worker_threads", "zlib"]);

export function packageDetections(project: AdversaryProject): Detection[] {
  return [...dependencies(project), ...contents(project), ...permissions(project)];
}

function dependencies(project: AdversaryProject): Detection[] {
  const imported = new Map<string, SourceFile>();
  for (const file of project.sourceFiles) {
    for (const match of file.content.matchAll(/import\s+(?!type\b)(?:[\s\S]*?\s+from\s+)?["']([^"']+)["']|require\(\s*["']([^"']+)["']\s*\)|import\(\s*["']([^"']+)["']\s*\)/g)) {
      const specifier = match[1] ?? match[2] ?? match[3];
      if (!specifier || specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("node:")) continue;
      const root = packageRoot(specifier);
      if (!BUILTINS.has(root)) imported.set(root, file);
    }
  }
  const result: Detection[] = [];
  for (const [name, file] of [...imported].sort(([left], [right]) => left.localeCompare(right))) {
    if (project.package?.dependencies[name] !== undefined) continue;
    const devOnly = project.package?.devDependencies[name] !== undefined;
    const line = lineOf(file.content, name);
    result.push(detection("adversary.typescript.package.dependencies", name, "dependencies", file.path, line, snippetAt(file.content, line), `${name} is imported at runtime but ${devOnly ? "is only a devDependency" : "is not declared in dependencies"}`, { dependency: name, devOnly }));
  }
  return result;
}

function contents(project: AdversaryProject): Detection[] {
  const suspicious: Array<{ path: string; reason: string }> = [];
  for (const file of project.files) {
    if (/^(?:secrets?|credentials?)(?:\/|\.)|\.(?:pem|key|p12|pfx)$|(?:^|\/)id_rsa$/i.test(file.path) && !ignored(file.path, project.ignorePatterns)) suspicious.push({ path: file.path, reason: "credential-like file is not excluded" });
  }
  const hasFixtures = project.fixturePaths.length > 0;
  if (hasFixtures && !project.ignorePatterns.some((pattern) => /(?:test|tests|fixtures?)\/?/.test(pattern))) suspicious.push({ path: project.fixturePaths[0] ?? "test/fixtures", reason: "authoring fixtures are not excluded from the runtime package" });
  if (suspicious.length === 0) return [];
  return suspicious.map((item) => detection("adversary.typescript.package.contents", item.path, "contents", item.path, 1, item.path, item.reason, item));
}

function permissions(project: AdversaryProject): Detection[] {
  const source = project.sourceFiles.map((file) => file.content).join("\n");
  const result: Detection[] = [];
  const manifestSource = project.manifest.source?.content ?? "";
  if (project.manifest.network === true && !/(?:\bfetch\s*\(|node:(?:https?|net)|from\s+["'](?:axios|undici|got)["'])/.test(source)) result.push(permission(project, "network", "network access is enabled but no network API is used", {}));
  if (project.manifest.filesystemWrite.length > 0 && !/(?:writeFile|appendFile|mkdir|rename|rm|unlink|createWriteStream)/.test(source)) result.push(permission(project, "write", "filesystem write access is declared but source appears read-only", { paths: project.manifest.filesystemWrite }));
  const consumed = [...source.matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[["']([A-Za-z_][A-Za-z0-9_]*)["']\]/g)].map((match) => match[1] ?? match[2]);
  const unused = project.manifest.environmentAllow.filter((name) => !consumed.includes(name));
  if (unused.length > 0) result.push(permission(project, "environment", "environment variables are allowed but not consumed", { unused }));
  return result;
}

function permission(project: AdversaryProject, subject: string, label: string, data: Record<string, unknown>): Detection {
  const source = project.manifest.source?.content ?? "";
  const field = {
    network: "permissions.network",
    write: "permissions.filesystem.write",
    environment: "permissions.environment.allow",
  }[subject];
  const line = field === undefined ? 1 : project.manifest.locations[field] ?? 1;
  return detection("adversary.typescript.permissions.broad", subject, "permissions", "adversary.yaml", line, snippetAt(source, line), label, data);
}

function packageRoot(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0] ?? specifier;
}

function ignored(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) => {
    const normalized = pattern.replace(/^\//, "").replace(/\*\*/g, "").replace(/\*/g, "");
    return normalized.endsWith("/") ? path.startsWith(normalized) : path === normalized || path.endsWith(normalized);
  });
}
