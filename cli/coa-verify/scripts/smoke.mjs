// Smoke test for a BUILT coa-verify (bundle, npm install or stand-alone executable) against the
// protocol vectors. Usage: node scripts/smoke.mjs <executable> [args prefix...]
//   node scripts/smoke.mjs node bundle/coa-verify.mjs
//   node scripts/smoke.mjs ./sea-out/coa-verify-1.0.0-linux-x64
// Exits non-zero with a message on the first failed expectation.
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const V1 = join(PKG_DIR, "..", "..", "fixtures", "vectors", "v1");
// Relative paths are resolved here: the checks run inside a temporary directory.
const abs = (p) => (p && existsSync(p) ? resolve(p) : p);
const [exe, ...prefix] = process.argv.slice(2).map(abs);
if (!exe) {
  console.error("usage: node scripts/smoke.mjs <executable> [args prefix...]");
  process.exit(64);
}
const { version } = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf8"));
const keys = JSON.parse(readFileSync(join(V1, "keys.json"), "utf8")).keys;
const publicKeyDoc = (keyId) => {
  const { private_seed_hex, seed_label, ...pub } = keys.find((k) => k.key_id === keyId);
  return JSON.stringify({ ...pub, algorithm: "Ed25519" });
};

const work = mkdtempSync(join(tmpdir(), "coa-verify-smoke-"));
const bundle = join(work, "bundle");
mkdirSync(bundle);
cpSync(join(V1, "envelopes", "valid-basic.json"), join(bundle, "signed-record.json"));
cpSync(join(V1, "files", "original-report.pdf"), join(bundle, "original-report.pdf"));
cpSync(join(V1, "files", "store-document.pdf"), join(bundle, "store-document.pdf"));
// a customer bundle ships the signing key as a CANDIDATE only
writeFileSync(join(bundle, "public-key.json"), publicKeyDoc("demo-program-k1"));
writeFileSync(join(work, "other-tenant-key.json"), publicKeyDoc("second-demo-program-k1"));
const fp = (keyId) => keys.find((k) => k.key_id === keyId).fingerprint;

let failures = 0;
function check(name, args, expectCode, expectOut) {
  // Windows npm shims (.cmd) can only be started through a shell; the arguments here contain no spaces.
  const r = spawnSync(exe, [...prefix, ...args], { cwd: work, encoding: "utf8", shell: /\.(cmd|bat)$/i.test(exe) });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const ok = r.status === expectCode && (!expectOut || expectOut.test(out));
  console.log(`${ok ? "ok  " : "FAIL"} ${name} (exit ${r.status}${r.error ? `, ${r.error.message}` : ""})`);
  if (!ok) {
    failures++;
    console.log(out.split("\n").map((l) => `     | ${l}`).join("\n"));
  }
}

const TS = ["--trust-store", "trust.json"];
check("--version", ["--version"], 0, new RegExp(`^${version.replace(/\./g, "\\.")}\\s*$`));
const add = (file, program, fingerprint) =>
  ["trust", "add", "--store", "trust.json", "--key-file", file, "--fingerprint", fingerprint, "--program-id", program, "--environment", "demo"];
check("trust add refuses a wrong fingerprint", add(join(bundle, "public-key.json"), "demo-program", "00".repeat(32)), 65, /fingerprint/i);
check("trust add with the pinned fingerprint", add(join(bundle, "public-key.json"), "demo-program", fp("demo-program-k1")), 0, /matched the value you pinned/);
check("trust add for a second tenant", add("other-tenant-key.json", "second-demo-program", fp("second-demo-program-k1")), 0, /matched the value you pinned/);
check("bundle without a trust store is not trusted", ["verify", "--bundle", "bundle"], 2, /Issuer NOT trusted/);
check("bundle with the trust store", ["verify", "--bundle", "bundle", ...TS], 0, /Issuer trusted/);
check("tampered store document", ["verify", join(bundle, "signed-record.json"), ...TS, "--document", join(V1, "files", "store-document.one-byte-changed.pdf")], 3, /does not match|mismatch/i);
check("cross-tenant forgery is not trusted", ["verify", join(V1, "envelopes", "cross-tenant-forgery.json"), ...TS], 2, /Issuer NOT trusted/);
check("json report", ["verify", "--bundle", "bundle", ...TS, "--json"], 0, /"report_version": "1"/);

if (failures) {
  console.error(`${failures} smoke check(s) failed`);
  process.exit(1);
}
console.log("all smoke checks passed");
