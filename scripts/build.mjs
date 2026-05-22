import { mkdir } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let esbuild;
try {
  esbuild = await import("esbuild");
} catch {
  const fallback = "D:/nodejs/node_global/node_modules/vite/node_modules/esbuild/lib/main.js";
  esbuild = await import(pathToFileURL(fallback).href);
}

await mkdir(resolve(root, "dist"), { recursive: true });

await esbuild.build({
  entryPoints: [resolve(root, "index.ts")],
  outfile: resolve(root, "dist/index.js"),
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  sourcemap: true,
  external: ["openclaw", "openclaw/*"],
  banner: {
    js: [
      "import { createRequire as __yzjCreateRequire } from 'node:module';",
      "const require = __yzjCreateRequire(import.meta.url);",
    ].join("\n"),
  },
  define: {
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "production"),
  },
});

console.log("built dist/index.js");
