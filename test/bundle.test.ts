import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { afterAll, describe, expect, it } from "vitest";
// @ts-expect-error a plain module, no types
import { entries, options } from "../scripts/build.mjs";

// What's deployed is the bundle, not the TypeScript: the reader crashed at load on every message once bundled
// ("Dynamic require of "stream" is not supported", from mailparser's CommonJS dependencies), while every source test passed.
// So this builds the mail parsing as the functions are built, and parses a real message with that bundle in a plain Node
// process, as Lambda runs it: not in this test's own runtime, which has a `require` of its own and would hide the crash.
describe("bundle", () => {
  const dir = mkdtempSync(join(tmpdir(), "chutchut-bundle-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("parses a real message from the built bundle in plain Node, as the reader and provider do", async () => {
    const entry = join(dir, "entry.ts");
    writeFileSync(entry, `export { receivedJson } from ${JSON.stringify(join(process.cwd(), "src", "provider.ts"))};\n`);
    await build({ ...options, entryPoints: [entry], outdir: dir });
    const run = join(dir, "run.mjs");
    writeFileSync(run, [
      'import { receivedJson } from "./entry.mjs";',
      'const raw = Buffer.from([\'From: "Ana Doe" <ana@example.test>\', "To: support@kiff.test", "Subject: Refund please",',
      '  "Message-ID: <m1@example.test>", "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", "Hello, order 42 please.", ""].join("\\r\\n"));',
      'console.log(JSON.stringify(await receivedJson("0100abc", raw, { at: "2026-11-28T03:40:00.000Z" })));',
    ].join("\n"));
    const j = JSON.parse(execFileSync(process.execPath, [run], { encoding: "utf8" }));
    expect(j).toMatchObject({ id: "0100abc", subject: "Refund please", message_id: "<m1@example.test>" });
    expect(String(j.text).trim()).toBe("Hello, order 42 please.");
  }, 60_000);
});

// Every function, built as it's deployed, loads in plain Node: the next CommonJS dependency anywhere is caught here, not on
// the first message. Outside AWS each stops at its first missing setting, which is past where a bundle fails to load.
describe("every bundle", () => {
  // Inside the project, so the AWS SDK the bundles leave out (Lambda has it) resolves from node_modules.
  const dir = mkdtempSync(join(process.cwd(), ".bundle-test-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("loads each function's bundle in plain Node, stopping only at a missing setting", async () => {
    await build({ ...options, entryPoints: entries.map((e: string) => join(process.cwd(), e)), outdir: dir });
    for (const name of ["webhook", "reader", "stale", "provider"]) {
      const run = join(dir, `load-${name}.mjs`);
      writeFileSync(run, `try { await import("./${name}.mjs"); console.log("loaded"); } catch (e) { console.log(String(e && e.message)); }\n`);
      const said = execFileSync(process.execPath, [run], { encoding: "utf8", env: { PATH: process.env.PATH ?? "" } }).trim();
      expect(said === "loaded" || /isn't set$/.test(said), `${name}: ${said}`).toBe(true);
    }
  }, 120_000);
});
