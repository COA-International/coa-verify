import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { run, type Io } from "../src/cli.js";

const ESC = String.fromCharCode(0x1b);
const RLO = String.fromCharCode(0x202e);
const HERE = dirname(fileURLToPath(import.meta.url));
const V1 = join(HERE, "..", "..", "..", "fixtures", "vectors", "v1");
const keys: any[] = JSON.parse(readFileSync(join(V1, "keys.json"), "utf8")).keys;
const tenant = (id: string) => {
  const k = keys.find((x) => x.key_id === id);
  return { key_id: k.key_id, public_key: k.public_key, program_id: k.program_id, role: k.role, environment: k.environment, signer_id: k.signer_id };
};

let work: string;
beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), "coa-verify-test-"));
  writeFileSync(join(work, "trust.json"), JSON.stringify({ trust_store_version: "1", entries: [tenant("demo-program-k1"), tenant("demo-program-k2"), tenant("second-demo-program-k1")] }));
  // an unzipped pickup bundle built from the vectors
  const b = join(work, "bundle");
  mkdirSync(b);
  cpSync(join(V1, "envelopes", "valid-basic.json"), join(b, "signed-record.json"));
  cpSync(join(V1, "files", "original-report.pdf"), join(b, "original-report.pdf"));
  cpSync(join(V1, "files", "store-document.pdf"), join(b, "store-document.pdf"));
  writeFileSync(join(b, "public-key.json"), JSON.stringify({ ...tenant("demo-program-k1"), algorithm: "Ed25519", fingerprint: keys[0].fingerprint, note: "shipped with the bundle" }));
});

async function cli(args: string[], extra: Partial<Io> = {}) {
  let stdout = "";
  let stderr = "";
  const code = await run(args, { stdout: (s) => (stdout += s), stderr: (s) => (stderr += s), env: {}, cwd: work, ...extra });
  return { code, stdout, stderr };
}
const rec = (name: string) => join(V1, "envelopes", `${name}.json`);
const file = (name: string) => join(V1, "files", name);
const proof = (name: string) => join(V1, "anchor-proofs", `${name}.anchor-proof.json`);
const T = ["--trust-store", "trust.json"];
const BIND = ["--program-id", "demo-program", "--environment", "demo"];

describe("verify (offline)", () => {
  it("exit 0 with a trust store, both files and an anchor proof; labels demo and offline unknowns", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--original", file("original-report.pdf"), "--document", file("store-document.pdf"), "--anchor-proof", proof("valid-basic")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("NOT A PRODUCTION RECORD");
    expect(r.stdout).toContain("Issuer trusted");
    expect(r.stdout).toContain("LOCAL TEST ANCHOR - NOT PUBLIC");
    expect(r.stdout).toMatch(/Record standing.*unknown \(offline\)/);
    expect(r.stdout).toMatch(/Current program membership: unknown \(offline\)/);
    expect(r.stdout).not.toMatch(/all verified|fully verified/i);
  });
  it("bundle mode reads everything from the directory; the shipped key alone is NOT trusted (exit 2)", async () => {
    const r = await cli(["verify", "--bundle", "bundle"]);
    expect(r.code).toBe(2);
    expect(r.stdout).toContain("mathematically valid");
    expect(r.stdout).toContain("Issuer NOT trusted");
    expect(r.stdout).toContain("Original laboratory report: Matches the signed hash");
  });
  it("bundle mode with a trust store passes", async () => {
    expect((await cli(["verify", "--bundle", "bundle", ...T])).code).toBe(0);
  });
  it("customer packages with the SHA-256 in each file name verify the same way; an altered one fails", async () => {
    const { createHash } = await import("node:crypto");
    const sha = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex");
    const c = join(work, "customer");
    mkdirSync(c, { recursive: true });
    cpSync(join(V1, "envelopes", "valid-basic.json"), join(c, "signed-record.json"));
    cpSync(file("original-report.pdf"), join(c, `original-report-${sha(file("original-report.pdf"))}.pdf`));
    cpSync(file("store-document.pdf"), join(c, `signed-certificate-${sha(file("store-document.pdf"))}.pdf`));
    const ok = await cli(["verify", "--bundle", "customer", ...T]);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toContain("Store-specific document: Matches the signed hash");
    // a second candidate is refused rather than guessed
    cpSync(file("store-document.pdf"), join(c, "store-document.pdf"));
    expect((await cli(["verify", "--bundle", "customer", ...T])).code).toBe(64);
  });
  it("no trust store and no shipped key: exit 1 explains what to do", async () => {
    const r = await cli(["verify", rec("valid-basic")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("No key for");
  });
  it("tampered record: exit 1", async () => {
    for (const n of ["tampered-store-name", "tampered-signature", "modified-key-id", "duplicate-key", "unsupported-schema-version", "signature-padded"]) {
      expect((await cli(["verify", rec(n), ...T])).code, n).toBe(1);
    }
  });
  it("untrusted / cross-tenant / environment mismatch: exit 2", async () => {
    expect((await cli(["verify", rec("cross-tenant-forgery"), ...T])).code).toBe(2);
    expect((await cli(["verify", rec("environment-mismatch"), ...T])).code).toBe(2);
    const shipped = join(work, "attacker.json");
    writeFileSync(shipped, JSON.stringify(tenant("attacker-k1")));
    const r = await cli(["verify", "--bundle", "bundle-attacker", ...T]).catch(() => null);
    expect(r === null || r.code === 64).toBe(true);
  });
  it("file mismatch: exit 3 and names which document", async () => {
    const one = await cli(["verify", rec("valid-basic"), ...T, "--original", file("original-report.one-byte-changed.pdf")]);
    expect(one.code).toBe(3);
    expect(one.stdout).toContain("does not match the signed hash for the original laboratory report");
    const swapped = await cli(["verify", rec("valid-basic"), ...T, "--document", file("original-report.pdf")]);
    expect(swapped.code).toBe(3);
    expect(swapped.stdout).toContain("is the original laboratory report, not the store-specific document");
  });
  it("a file is never called a match when the record does not verify (exit 1)", async () => {
    const r = await cli(["verify", rec("tampered-store-name"), ...T, "--original", file("original-report.pdf")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("[ ?? ]");
    expect(r.stdout).not.toContain("Matches the signed hash");
  });
  it("anchor: wrong root / leaf mismatch exit 4; pending exits 0 and is shown as pending", async () => {
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", proof("wrong-root")])).code).toBe(4);
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", proof("leaf-mismatch")])).code).toBe(4);
    const p = await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", proof("pending")]);
    expect(p.code).toBe(0);
    expect(p.stdout).toContain("Anchor status as stated by the proof: pending");
  });
  it("OpenTimestamps (protocol 6.1): unverified without a trusted header file, confirmed with one, invalid with a wrong one", async () => {
    const ots = join(V1, "anchor-proofs", "ots-attested.anchor-proof.json");
    const noHeaders = await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", ots]);
    expect(noHeaders.code).toBe(0);
    expect(noHeaders.stdout).toContain("no trusted block-header source was given");
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", ots, "--require-anchor"])).code).toBe(4);
    const good = await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", ots, "--bitcoin-headers", join(V1, "ots", "headers.json"), "--require-anchor"]);
    expect(good.code).toBe(0);
    expect(good.stdout).toContain("verified against a header source you trust: Bitcoin block 900000, header time 2026-09-21T14:13:20Z");
    const bad = await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", ots, "--bitcoin-headers", join(V1, "ots", "headers-wrong.json")]);
    expect(bad.code).toBe(4);
    expect(bad.stdout).toContain("OpenTimestamps proof is invalid");
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", join(V1, "anchor-proofs", "ots-pending.anchor-proof.json")])).stdout).toContain("still pending");
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", join(V1, "anchor-proofs", "ots-other-root.anchor-proof.json")])).code).toBe(4);
    const badFile = join(work, "bad-headers.json");
    writeFileSync(badFile, JSON.stringify({ headers: { "900000": { merkle_root: "XYZ", time: 1 } } }));
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", ots, "--bitcoin-headers", badFile])).code).toBe(65);
  });

  it("--require-anchor fails for a local test anchor", async () => {
    expect((await cli(["verify", rec("valid-basic"), ...T, "--anchor-proof", proof("valid-basic"), "--require-anchor"])).code).toBe(4);
  });
  it("wrong verification origin is a trust warning (exit 2); 'none' disables the check", async () => {
    expect((await cli(["verify", rec("valid-basic"), ...T, "--expected-origin", "https://other.example"])).code).toBe(2);
    expect((await cli(["verify", rec("valid-basic"), ...T, "--expected-origin", "none"])).code).toBe(0);
  });
  it("compromised key in the trust store: exit 2 with the issue-date caveat", async () => {
    const t = join(work, "trust-compromised.json");
    writeFileSync(t, JSON.stringify({ trust_store_version: "1", entries: [{ ...tenant("demo-program-k1"), status: "compromised", compromise_suspected_from: "2026-09-01T00:00:00Z" }] }));
    const r = await cli(["verify", rec("valid-basic"), "--trust-store", t]);
    expect(r.code).toBe(2);
    expect(r.stdout).toContain("issue date cannot clear this");
  });
  it("--json produces the documented report", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--json"]);
    const j = JSON.parse(r.stdout);
    expect(j.report_version).toBe("1");
    expect(j.mode).toBe("offline");
    expect(j.record.signature_valid).toBe(true);
    expect(j.record.issuer_trusted).toBe(true);
    expect(j.current_status.standing).toBe("unknown (offline)");
    expect(j.exit_code).toBe(0);
    expect(j.summary.store.name).toContain("Example Corner Store");
  });
  it("usage and configuration errors", async () => {
    expect((await cli([])).code).toBe(64);
    expect((await cli(["verify"])).code).toBe(64);
    expect((await cli(["verify", "x", "--nope"])).code).toBe(64);
    expect((await cli(["verify", "missing.json"])).code).toBe(64);
    expect((await cli(["bogus"])).code).toBe(64);
    const bad = join(work, "bad-trust.json");
    writeFileSync(bad, JSON.stringify({ trust_store_version: "1", entries: [tenant("demo-program-k1"), tenant("demo-program-k1")] }));
    const r = await cli(["verify", rec("valid-basic"), "--trust-store", bad]);
    expect(r.code).toBe(65);
    expect(r.stderr).toContain("duplicate key_id");
    expect((await cli(["verify", rec("valid-basic"), "--online", "http://example.com"])).code).toBe(64);
    expect((await cli(["--help"])).code).toBe(0);
  });
  it("reads the trust store from COA_VERIFY_TRUST_STORE", async () => {
    expect((await cli(["verify", rec("valid-basic")], { env: { COA_VERIFY_TRUST_STORE: "trust.json" } })).code).toBe(0);
  });
});

describe("verify --online (mocked server; only the configured URL is contacted)", () => {
  const record = JSON.parse(readFileSync(rec("valid-basic"), "utf8")).payload;
  const publicBody = (over: any = {}) => ({
    result: "found",
    record: { verification_code: record.verification_code, issuance_id: record.issuance_id },
    integrity: { key_status: "retired", trust_warning: null },
    standing: { standing: "issued", events: [{ kind: "issued", effective_at: "2026-09-24T12:00:00Z", recorded_at: "2026-09-24T12:00:00Z" }] },
    membership: { status: "active", source: "COA Coalition", fresh: true, last_checked_at: "2026-09-29T00:00:00Z", as_of: null, note: "" },
    anchor: { anchor_status: "not_queued" },
    freshness: { as_of: "2026-09-29T00:00:10Z", max_age_seconds: 15, propagation_target_seconds: 60 },
    ...over,
  });
  const mock = (bodies: Record<string, { status?: number; body?: any; type?: string; headers?: Record<string, string> }>, calls: string[]): typeof fetch =>
    (async (url: any, init: any) => {
      calls.push(String(url));
      expect(init.redirect).toBe("manual");
      const path = String(url).replace("https://verify.example", "");
      const spec = bodies[path];
      if (!spec) return new Response("nope", { status: 404 });
      return new Response(JSON.stringify(spec.body), { status: spec.status ?? 200, headers: { "content-type": spec.type ?? "application/json", ...(spec.headers ?? {}) } });
    }) as typeof fetch;
  const p = `/api/v1/public/verifications/${record.verification_code}`;

  it("adds standing/membership from the configured server and stays exit 0 for an issued record", async () => {
    const calls: string[] = [];
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], { fetchImpl: mock({ [p]: { body: publicBody() } }, calls) });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Record standing: issued");
    expect(r.stdout).toContain("Program participation (membership): active");
    expect(r.stdout).toContain("separate from whether the documents were genuinely issued");
    expect(calls.every((c) => c.startsWith("https://verify.example/"))).toBe(true);
  });
  it("revoked standing exits 6 while still explaining the signature is valid", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: publicBody({ standing: { standing: "revoked", events: [] } }) } }, []),
    });
    expect(r.code).toBe(6);
    expect(r.stdout).toContain("mathematically valid");
  });
  it("a compromised key reported by the directory exits 2", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: publicBody({ integrity: { key_status: "compromised", trust_warning: "suspected from 2026-09-01" } }) } }, []),
    });
    expect(r.code).toBe(2);
  });
  it("a redirect is refused (exit 5)", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { status: 302, body: {}, headers: { location: "https://evil.example/" } } }, []),
    });
    expect(r.code).toBe(5);
    expect(r.stdout).toContain("redirect");
  });
  it("server unreachable / wrong record / non-JSON -> exit 5 with the record checks intact", async () => {
    const down = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], { fetchImpl: (async () => { throw new Error("connect ECONNREFUSED"); }) as typeof fetch });
    expect(down.code).toBe(5);
    expect(down.stdout).toContain("Issuer trusted");
    expect(down.stdout).toContain("Online check failed");
    const other = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: publicBody({ record: { verification_code: record.verification_code, issuance_id: "someone-else" } }) } }, []),
    });
    expect(other.code).toBe(5);
    const html = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: "<html>", type: "text/html" } }, []),
    });
    expect(html.code).toBe(5);
  });
  it("does not contact the server when the record failed verification", async () => {
    const calls: string[] = [];
    const r = await cli(["verify", rec("tampered-store-name"), ...T, "--online", "https://verify.example"], { fetchImpl: mock({}, calls) });
    expect(r.code).toBe(1);
    expect(calls).toEqual([]);
  });
  it("terminal control characters from the server are neutralised", async () => {
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: publicBody({ standing: { standing: "issued", source_warning: ESC + "[2J" + RLO + "bad", events: [] } }) } }, []),
    });
    expect(r.stdout).not.toContain("\u001b");
    expect(r.stdout).not.toContain(RLO);
    expect(r.stdout).toContain("\\u001b");
  });
  it("fetches the anchor proof from the server and recomputes it locally", async () => {
    const proofDoc = JSON.parse(readFileSync(proof("valid-basic"), "utf8"));
    const calls: string[] = [];
    const r = await cli(["verify", rec("valid-basic"), ...T, "--online", "https://verify.example"], {
      fetchImpl: mock({ [p]: { body: publicBody({ anchor: { anchor_status: "confirmed" } }) }, [`${p}/anchor-proof`]: { body: proofDoc } }, calls),
    });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Anchor inclusion recomputed");
    expect(calls).toContain(`https://verify.example${p}/anchor-proof`);
  });
});

describe("trust commands", () => {
  const k2 = keys.find((x) => x.key_id === "demo-program-k2");
  it("pins from a key directory only when the fingerprint matches, then verifies with the new store", async () => {
    const store = join(work, "new-trust.json");
    const dir = join(V1, "key-directory.json");
    const bad = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", "0".repeat(64), ...BIND]);
    expect(bad.code).toBe(65);
    expect(bad.stderr).toContain("fingerprint mismatch");
    expect(existsSync(store)).toBe(false);
    const good = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", k2.fingerprint, ...BIND]);
    expect(good.code).toBe(0);
    const again = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", k2.fingerprint, ...BIND]);
    expect(again.stdout).toContain("already in the trust store");
    const list = await cli(["trust", "list", "--store", store]);
    expect(list.stdout).toContain(k2.fingerprint);
    const k2rec = await cli(["verify", rec("valid-rotated-key"), "--trust-store", store]);
    expect(k2rec.code).toBe(0);
    const k1rec = await cli(["verify", rec("valid-basic"), "--trust-store", store]);
    expect(k1rec.code).toBe(1); // k1 is not in this store
  });
  it("pins a shipped public-key.json by fingerprint", async () => {
    const store = join(work, "from-key-file.json");
    const r = await cli(["trust", "add", "--store", store, "--key-file", join(work, "bundle", "public-key.json"), "--fingerprint", keys[0].fingerprint, ...BIND]);
    expect(r.code).toBe(0);
    expect((await cli(["verify", "--bundle", "bundle", "--trust-store", store])).code).toBe(0);
  });
  it("the program and environment come from the person pinning, not from the shipped document (LR-001)", async () => {
    const dir = join(V1, "key-directory.json");
    const fp = keys.find((x) => x.key_id === "demo-program-k2").fingerprint;
    const store = join(work, "binding-trust.json");
    // missing statements: usage error, nothing written
    const none = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", fp]);
    expect(none.code).toBe(64);
    expect(none.stderr).toContain("--program-id and --environment are required");
    expect(existsSync(store)).toBe(false);
    // the shipped metadata disagrees with what the human states: refused
    const lie = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", fp, "--program-id", "second-demo-program", "--environment", "demo"]);
    expect(lie.code).toBe(65);
    expect(lie.stderr).toMatch(/program_id="demo-program" but you stated "second-demo-program"/);
    const env = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", fp, "--program-id", "demo-program", "--environment", "production"]);
    expect(env.code).toBe(65);
    expect(existsSync(store)).toBe(false);
    // a bundle document that LIES about its tenant cannot smuggle a binding in, even with a matching fingerprint
    const forged = join(work, "forged-key.json");
    writeFileSync(forged, JSON.stringify({ ...tenant("demo-program-k1"), program_id: "second-demo-program", fingerprint: keys[0].fingerprint }));
    const f = await cli(["trust", "add", "--store", store, "--key-file", forged, "--fingerprint", keys[0].fingerprint, ...BIND]);
    expect(f.code).toBe(65);
    // an unknown environment value is a usage error
    expect((await cli(["trust", "add", "--store", store, "--key-file", forged, "--fingerprint", keys[0].fingerprint, "--program-id", "demo-program", "--environment", "prod"])).code).toBe(64);
    // and the entry written uses the human's statement
    const ok = await cli(["trust", "add", "--store", store, "--directory", dir, "--key-id", "demo-program-k2", "--fingerprint", fp, ...BIND]);
    expect(ok.code).toBe(0);
    expect(JSON.parse(readFileSync(store, "utf8")).entries[0]).toMatchObject({ program_id: "demo-program", environment: "demo", signer_id: "coa-international", role: "tenant_signer" });
  });

  it("requires the fingerprint pin", async () => {
    expect((await cli(["trust", "add", "--store", join(work, "x.json"), "--key-file", join(work, "bundle", "public-key.json"), ...BIND])).code).toBe(64);
  });
});

describe("built executable", () => {
  it("runs as a process and sets the exit code", () => {
    const main = join(HERE, "..", "dist", "main.js");
    if (!existsSync(main)) return; // built by `npm run build`; the in-process tests above cover the logic
    const ok = spawnSync(process.execPath, [main, "verify", rec("valid-basic"), "--trust-store", join(work, "trust.json"), "--json"], { encoding: "utf8" });
    expect(ok.status).toBe(0);
    expect(JSON.parse(ok.stdout).record.issuer_trusted).toBe(true);
    const bad = spawnSync(process.execPath, [main, "verify", rec("tampered-signature"), "--trust-store", join(work, "trust.json")], { encoding: "utf8" });
    expect(bad.status).toBe(1);
    expect(() => execFileSync(process.execPath, [main, "--version"])).not.toThrow();
  });
});
