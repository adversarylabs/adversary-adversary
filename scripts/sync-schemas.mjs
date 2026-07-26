import { copyFile } from "node:fs/promises";

await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.manifest.v1.schema.json",
  "schema/adversary.manifest.v1.schema.json",
);
