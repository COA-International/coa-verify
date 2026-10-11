// Builds a stand-alone coa-verify executable for the CURRENT platform (Node single executable
// application: the running `node` binary with bundle/coa-verify.cjs embedded). CI runs it on each
// operating system; output: sea-out/coa-verify-<version>-<os>-<arch>[.exe]. Run `npm run bundle` first.
// The executables are not code-signed (macOS gets an ad-hoc signature, which it requires to run);
// users check them against the published SHA-256 checksums.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inject } from "postject";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(PKG_DIR, "sea-out");
const main = join(PKG_DIR, "bundle", "coa-verify.cjs");
if (!existsSync(main)) throw new Error("bundle/coa-verify.cjs missing: run `npm run bundle` first");

const { version } = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf8"));
const os = { win32: "windows", darwin: "macos", linux: "linux" }[process.platform];
if (!os) throw new Error(`unsupported platform ${process.platform}`);
const exe = join(OUT, `coa-verify-${version}-${os}-${process.arch}${os === "windows" ? ".exe" : ""}`);

mkdirSync(OUT, { recursive: true });
const blob = join(OUT, "sea-prep.blob");
const config = join(OUT, "sea-config.json");
writeFileSync(config, JSON.stringify({
  main,
  output: blob,
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: false,
}));
execFileSync(process.execPath, ["--experimental-sea-config", config], { stdio: "inherit" });

rmSync(exe, { force: true });
copyFileSync(process.execPath, exe);
if (os === "macos") execFileSync("codesign", ["--remove-signature", exe], { stdio: "inherit" });
if (os === "windows") {
  // node.exe's Authenticode signature would be broken by the injection: strip it so the file is
  // plainly unsigned rather than carrying a corrupt signature. CI puts signtool on PATH.
  try {
    execFileSync("signtool", ["remove", "/s", exe], { stdio: "inherit" });
  } catch {
    console.warn("signtool not found: the executable keeps node.exe's (now invalid) signature");
  }
}
await inject(exe, "NODE_SEA_BLOB", readFileSync(blob), {
  sentinelFuse: "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
  ...(os === "macos" ? { machoSegmentName: "NODE_SEA" } : {}),
});
if (os === "macos") execFileSync("codesign", ["--sign", "-", exe], { stdio: "inherit" });
rmSync(blob);
rmSync(config);
console.log(exe);
