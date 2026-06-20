import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(scriptDir, "..");
const bundleDir = path.join(packageDir, "dist-bundle");
const entryPath = path.join(packageDir, "src", "bin.ts");

await rm(bundleDir, { recursive: true, force: true });
await mkdir(bundleDir, { recursive: true });

await build({
  entryPoints: [entryPath],
  outfile: path.join(bundleDir, "index.cjs"),
  bundle: true,
  format: "cjs",
  minify: false,
  packages: "bundle",
  platform: "node",
  sourcemap: false,
  target: "node24"
});
