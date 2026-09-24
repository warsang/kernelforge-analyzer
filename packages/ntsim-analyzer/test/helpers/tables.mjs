/**
 * Locate the Vergilius struct tables for tests.
 *
 * Two checkout layouts exist:
 *   monorepo:  <repo>/packages/ntsim-assets/data/vergilius/windows-10/22h2
 *   split:     <repo>/node_modules/@kernelforge/ntsim-assets/data/...
 * (the split repo installs ntsim-assets from npm, so the sibling path is gone).
 */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

export function tablesDir() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "../../../ntsim-assets/data/vergilius/windows-10/22h2"),
    path.resolve(here, "../../../../node_modules/@kernelforge/ntsim-assets/data/vergilius/windows-10/22h2"),
    path.resolve(here, "../../../node_modules/@kernelforge/ntsim-assets/data/vergilius/windows-10/22h2"),
    path.resolve(here, "../../node_modules/@kernelforge/ntsim-assets/data/vergilius/windows-10/22h2"),
  ];
  for (const c of candidates) {
    if (existsSync(path.join(c, "_EPROCESS.json"))) return c;
  }
  throw new Error(
    `Vergilius tables not found; checked:\n  ${candidates.join("\n  ")}\n` +
    `Run \`npm install\` (split) or use the monorepo checkout.`,
  );
}
