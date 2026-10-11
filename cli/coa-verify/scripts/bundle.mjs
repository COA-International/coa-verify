// Bundles coa-verify and verify-core (with @noble/curves and @noble/hashes) into single files:
//   bundle/coa-verify.mjs  ES module with a shebang: the npm "bin" and the plain download (any Node >= 22)
//   bundle/coa-verify.cjs  CommonJS: the script embedded in the stand-alone executables (scripts/build-sea.mjs)
// plus LICENSE, NOTICE and THIRD_PARTY_NOTICES.md, so every distributed copy carries its notices.
import { build } from "esbuild";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI_DIR = join(PKG_DIR, "..");
const OUT = join(PKG_DIR, "bundle");

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const common = {
  entryPoints: [join(PKG_DIR, "src", "main.ts")],
  bundle: true,
  platform: "node",
  target: "node22",
  // Bundle verify-core from source so the shipped file is exactly the reviewed code.
  alias: { "@coa/verify-core": join(CLI_DIR, "verify-core", "src", "index.ts") },
  legalComments: "eof",
  minify: false, // readable on purpose: people should be able to inspect what they run
  logLevel: "warning",
};
await build({ ...common, format: "esm", outfile: join(OUT, "coa-verify.mjs") }); // keeps main.ts's shebang
await build({ ...common, format: "cjs", outfile: join(OUT, "coa-verify.cjs") });

// The bundle must not reach anything outside Node built-ins.
for (const f of ["coa-verify.mjs", "coa-verify.cjs"]) {
  const src = readFileSync(join(OUT, f), "utf8");
  const external = [...src.matchAll(/(?:from\s+|require\()\s*["']([^"']+)["']/g)]
    .map((m) => m[1])
    .filter((s) => !s.startsWith("node:"));
  if (external.length) throw new Error(`${f} imports non-builtin modules: ${[...new Set(external)].join(", ")}`);
}

copyFileSync(join(CLI_DIR, "LICENSE"), join(OUT, "LICENSE"));
copyFileSync(join(CLI_DIR, "NOTICE"), join(OUT, "NOTICE"));
const third = ["@noble/curves", "@noble/hashes"].map((name) => {
  const dir = join(CLI_DIR, "node_modules", name); // workspace install hoists them here
  const { version } = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  return `## ${name} ${version}\n\n${readFileSync(join(dir, "LICENSE"), "utf8").trim()}\n`;
});
writeFileSync(
  join(OUT, "THIRD_PARTY_NOTICES.md"),
  `# Third-party software bundled in coa-verify\n\n${third.join("\n")}`,
);
console.log(`bundle written to ${OUT}`);
