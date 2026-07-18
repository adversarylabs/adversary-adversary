import { readFile } from "node:fs/promises";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import { LineCounter, parseDocument } from "yaml";
import { type JsonMap, type ManifestError, type ManifestModel, type SourceFile, isRecord, snippetAt, strings } from "./model.js";

let validatorPromise: Promise<ValidateFunction> | undefined;

export async function parseManifest(source: SourceFile | undefined): Promise<ManifestModel> {
  const empty: ManifestModel = { errors: [], filesystemRead: [], filesystemWrite: [], environmentAllow: [] };
  if (source === undefined) return { ...empty, errors: [{ message: "adversary.yaml is required", line: 1, snippet: "" }] };
  const counter = new LineCounter();
  const document = parseDocument(source.content, { lineCounter: counter, strict: true, uniqueKeys: true });
  if (document.errors.length > 0) {
    return { ...empty, source, errors: document.errors.map((error) => {
      const point = error.linePos?.[0] ?? counter.linePos(error.pos[0]);
      return { message: `YAML ${error.code.toLowerCase().replaceAll("_", " ")}: ${error.message.replace(/ at line.*$/s, "")}`, line: point.line, snippet: snippetAt(source.content, point.line) };
    }) };
  }
  let value: unknown;
  try { value = document.toJS({ maxAliasCount: 0 }); } catch (error) {
    return { ...empty, source, errors: [{ message: error instanceof Error ? error.message : "manifest YAML could not be normalized", line: 1, snippet: snippetAt(source.content, 1) }] };
  }
  if (!isRecord(value)) return { ...empty, source, errors: [{ message: "manifest must be a mapping", line: 1, snippet: snippetAt(source.content, 1) }] };
  const validate = await canonicalValidator();
  validate(value);
  const errors = (validate.errors ?? []).map((error) => schemaError(source, error));
  errors.push(...semanticErrors(source, value));
  const runtime = isRecord(value.runtime) ? value.runtime : {};
  const permissions = isRecord(value.permissions) ? value.permissions : {};
  const filesystem = isRecord(permissions.filesystem) ? permissions.filesystem : {};
  const environment = isRecord(permissions.environment) ? permissions.environment : {};
  return {
    raw: value, source, errors: uniqueErrors(errors),
    name: typeof value.name === "string" ? value.name : undefined,
    version: typeof value.version === "string" ? value.version : undefined,
    description: typeof value.description === "string" ? value.description : undefined,
    runtimeName: typeof runtime.name === "string" ? runtime.name : undefined,
    runtimeVersion: typeof runtime.version === "string" ? runtime.version : undefined,
    entrypoint: Array.isArray(runtime.command) && typeof runtime.command[0] === "string" ? runtime.command[0] : undefined,
    filesystemRead: strings(filesystem.read), filesystemWrite: strings(filesystem.write),
    network: typeof permissions.network === "boolean" ? permissions.network : undefined,
    environmentAllow: strings(environment.allow),
  };
}

async function canonicalValidator() {
  validatorPromise ??= readFile(new URL("../schema/adversary.manifest.v1.schema.json", import.meta.url), "utf8")
    .then((source) => new Ajv2020({ allErrors: true, strict: true, strictRequired: false }).compile(JSON.parse(source)));
  return validatorPromise;
}

function schemaError(source: SourceFile, error: ErrorObject): ManifestError {
  const missing = typeof error.params.missingProperty === "string" ? error.params.missingProperty : undefined;
  const extra = typeof error.params.additionalProperty === "string" ? error.params.additionalProperty : undefined;
  const field = [...error.instancePath.split("/").filter(Boolean), missing ?? extra].filter(Boolean).join(".");
  const line = locateField(source.content, missing ?? extra ?? error.instancePath.split("/").filter(Boolean).at(-1));
  return { field, line, snippet: snippetAt(source.content, line), message: `${field || "manifest"} ${error.message ?? "is invalid"}` };
}

function semanticErrors(source: SourceFile, raw: JsonMap): ManifestError[] {
  const result: ManifestError[] = [];
  const permissions = isRecord(raw.permissions) ? raw.permissions : {};
  const filesystem = isRecord(permissions.filesystem) ? permissions.filesystem : {};
  const overlap = strings(filesystem.read).filter((path) => strings(filesystem.write).includes(path));
  for (const path of overlap) result.push(fieldError(source, "filesystem", `permissions.filesystem read and write both declare ${path}`));
  const runtime = isRecord(raw.runtime) ? raw.runtime : {};
  const command = Array.isArray(runtime.command) ? runtime.command : [];
  if (runtime.name === "node" && typeof command[0] === "string" && (!/\.(?:c|m)?js$/.test(command[0]) || command[0].startsWith("/") || command[0].split("/").includes(".."))) {
    result.push(fieldError(source, "command", "runtime.command[0] must be a portable JavaScript entrypoint within the project"));
  }
  return result;
}

function fieldError(source: SourceFile, field: string, message: string): ManifestError {
  const line = locateField(source.content, field);
  return { field, message, line, snippet: snippetAt(source.content, line) };
}

function locateField(source: string, field: string | undefined): number {
  if (!field) return 1;
  const pattern = new RegExp(`^\\s*${field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`, "m");
  const match = pattern.exec(source);
  return match === null ? 1 : source.slice(0, match.index).split(/\r?\n/).length;
}

function uniqueErrors(errors: ManifestError[]): ManifestError[] {
  const seen = new Set<string>();
  return errors.filter((error) => { const key = `${error.line}:${error.message}`; if (seen.has(key)) return false; seen.add(key); return true; });
}
