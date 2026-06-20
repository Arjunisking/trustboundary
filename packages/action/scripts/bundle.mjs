import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ncc = require("@vercel/ncc");

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(scriptDir, "..");
const bundleDir = path.join(packageDir, "dist-bundle");
const entryPath = path.join(packageDir, "dist", "bin.js");

const { code, assets } = await ncc(entryPath, {
  esm: false,
  filename: "index.cjs",
  minify: false,
  sourceMap: false
});

await rm(bundleDir, { recursive: true, force: true });
await mkdir(bundleDir, { recursive: true });

await writeFile(path.join(bundleDir, "index.cjs"), code, "utf8");

for (const [assetName, asset] of Object.entries(assets)) {
  const assetPath = path.join(bundleDir, assetName);
  await mkdir(path.dirname(assetPath), { recursive: true });
  await writeFile(assetPath, asset.source);
}
