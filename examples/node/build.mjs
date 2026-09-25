// Bundles src/md2html.js and its dependencies into one file,
// build/md2html.mjs, which runs without node_modules.
import { build } from "esbuild";

await build({
  entryPoints: ["src/md2html.js"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  outfile: "build/md2html.mjs",
  // Some dependencies (yaml's Node build) are CommonJS and call require(),
  // which an ES module does not have.
  banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
  logLevel: "info",
});
