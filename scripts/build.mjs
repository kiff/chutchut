// The functions' bundles (deploy/aws.sh deploys dist/*.mjs). One place for the options, so the test that loads a built
// bundle (test/bundle.test.ts) builds exactly what's deployed.
import { build } from "esbuild";

// An ES module bundle has no `require`, but some of mailparser's dependencies call require("stream") as CommonJS:
// without one, every function that parses mail crashed at load ("Dynamic require of "stream" is not supported").
export const banner = { js: "import { createRequire as __chutchutRequire } from 'node:module'; const require = __chutchutRequire(import.meta.url);" };

export const options = {
  bundle: true, platform: "node", target: "node22", format: "esm", outExtension: { ".js": ".mjs" },
  external: ["@aws-sdk/*"], sourcemap: true, banner,
};

export const entries = ["src/lambda/webhook.ts", "src/lambda/reader.ts", "src/lambda/stale.ts", "src/lambda/provider.ts"];

// Run as `npm run build`; imported by the test, it builds nothing.
if (process.argv[1] && process.argv[1].endsWith("build.mjs")) {
  await build({ ...options, entryPoints: entries, outdir: "dist" });
}
