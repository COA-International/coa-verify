// Runs every case of fixtures/vectors/v1/vectors.json against the TypeScript verifier.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildTrustStore, canonicalBytes, checkFile, merkleRoot, parseStrictJson, sha256Hex, verifyAnchorProof,
  verifyEnvelope, verifyInclusion, anchorLeafHash, signingInput, toHex, entryFromDirectory, fingerprintOf,
  type JsonValue, type TrustEntry,
} from "../src/index.js";

const V1 = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "fixtures", "vectors", "v1");
const read = (rel: string): Uint8Array => new Uint8Array(readFileSync(join(V1, rel)));
const readJson = (rel: string): any => JSON.parse(readFileSync(join(V1, rel), "utf8"));

const vectors = readJson("vectors.json");
const keys: any[] = readJson("keys.json").keys;

function trustEntry(keyId: string): TrustEntry {
  const k = keys.find((x) => x.key_id === keyId);
  if (!k) throw new Error(`no key ${keyId}`);
  return {
    key_id: k.key_id, public_key: k.public_key, program_id: k.program_id, role: k.role,
    environment: k.environment, signer_id: k.signer_id,
  };
}

describe("envelope vectors", () => {
  for (const c of vectors.envelope_cases) {
    it(c.id, () => {
      const trustStore = buildTrustStore((c.trust as string[]).map((id) => trustEntry(id) as unknown as JsonValue));
      const candidate = c.candidate
        ? (() => {
            const k = keys.find((x) => x.key_id === c.candidate);
            return { key_id: k.key_id, public_key: k.public_key };
          })()
        : undefined;
      const r = verifyEnvelope(read(c.envelope), { trustStore, candidateKey: candidate, expectedVerificationOrigin: null });
      const e = c.expect;
      expect(r.parse_ok).toBe(e.parse_ok);
      if (e.error_code) expect(r.error_code).toBe(e.error_code);
      if (!e.parse_ok) return;
      expect(r.schema_version_supported).toBe(e.schema_version_supported);
      expect(r.structure_valid).toBe(e.structure_valid);
      expect(r.signature_valid).toBe(e.signature_valid);
      expect(r.issuer_trusted).toBe(e.issuer_trusted);
      if (c.canonical_payload_utf8_sha256) {
        expect(sha256Hex(canonicalBytes(r.payload as JsonValue))).toBe(c.canonical_payload_utf8_sha256);
      }
    });
  }
});

describe("canonical form vector", () => {
  it("valid-basic payload canonicalises to the published bytes and signing input", () => {
    const parsed = parseStrictJson(read("envelopes/valid-basic.json"));
    if (!parsed.ok) throw new Error("parse");
    const payload = (parsed.value as any).payload as JsonValue;
    expect(new TextDecoder().decode(canonicalBytes(payload))).toBe(
      new TextDecoder().decode(read("canonical/valid-basic.payload.canonical.json")).replace(/\n$/, ""),
    );
    expect(toHex(signingInput(payload))).toBe(toHex(read("canonical/valid-basic.signing-input.bin")));
  });
});

describe("file vectors", () => {
  const env = verifyEnvelope(read("envelopes/valid-basic.json"), {
    trustStore: [trustEntry("demo-program-k1")], expectedVerificationOrigin: null,
  });
  for (const c of vectors.file_cases) {
    it(c.id, () => {
      const r = checkFile(read(c.file), env.payload, env.signature_valid, null);
      expect(r.matches).toBe(c.expect.matches);
    });
  }
  it("names which expected document a wrong-slot file fails to match", () => {
    const r = checkFile(read("files/original-report.pdf"), env.payload, true, "store_document");
    expect(r.status).toBe("mismatch");
    expect(r.matches).toBe("original_report");
    expect(r.message).toContain("not the store-specific document");
  });
  it("does not call a match evidence when the signature did not verify", () => {
    const r = checkFile(read("files/original-report.pdf"), env.payload, false, "original_report");
    expect(r.status).toBe("unverified");
  });
});

describe("anchor vectors (Merkle path and OpenTimestamps, protocol 6)", () => {
  const env = verifyEnvelope(read("envelopes/valid-basic.json"), {
    trustStore: [trustEntry("demo-program-k1")], expectedVerificationOrigin: null,
  });
  for (const c of vectors.anchor_cases) {
    it(c.id, () => {
      const headers = c.headers ? readJson(c.headers).headers : undefined;
      const r = verifyAnchorProof(read(c.proof), env.payload as JsonValue, { headers });
      expect(r.inclusion_valid).toBe(c.expect.inclusion_valid);
      if ("anchor_status" in c.expect) expect(r.anchor_status).toBe(c.expect.anchor_status);
      if ("public" in c.expect) expect(r.public).toBe(c.expect.public);
      if (r.method === "local-test") expect(r.label).toMatch(/not public/);
      if (c.expect.ots) {
        expect(r.ots?.status).toBe(c.expect.ots.status);
        if ("block_height" in c.expect.ots) expect(r.ots?.block_height).toBe(c.expect.ots.block_height);
        if ("block_time" in c.expect.ots) expect(r.ots?.block_time).toBe(c.expect.ots.block_time);
        // only an attested proof against a trusted header may count as confirmed public timing evidence
        expect(r.ots_verified).toBe(c.expect.ots.status === "attested");
        expect(r.timing_evidence).toBe(c.expect.ots.status === "attested" ? "verified" : "not_verified");
      }
    });
  }
});

describe("merkle vectors (RFC 9162)", () => {
  const cases = readJson("merkle.json").cases;
  for (const c of cases) {
    it(`tree of ${c.tree_size}`, () => {
      const leafHashes: string[] = c.leaves.map((l: any) => {
        expect(anchorLeafHash(l.document_sha256, l.payload_sha256)).toBe(l.leaf_hash);
        return l.leaf_hash;
      });
      expect(merkleRoot(leafHashes)).toBe(c.root);
      c.inclusion_paths.forEach((path: string[], i: number) => {
        expect(verifyInclusion(leafHashes[i]!, i, c.tree_size, path, c.root)).toBe(true);
        // a proof presented for a different leaf index must fail
        if (c.tree_size > 1) expect(verifyInclusion(leafHashes[i]!, (i + 1) % c.tree_size, c.tree_size, path, c.root)).toBe(false);
      });
    });
  }
});

describe("key directory vector", () => {
  const dir = readJson("key-directory.json");
  it("builds a trust entry only when the out-of-band fingerprint matches", () => {
    const k = keys.find((x) => x.key_id === "demo-program-k2");
    const entry = entryFromDirectory(dir, "demo-program-k2", k.fingerprint, { program_id: "demo-program", environment: "demo" });
    expect(entry.public_key).toBe(k.public_key);
    expect(fingerprintOf(entry.public_key)).toBe(k.fingerprint);
    expect(() => entryFromDirectory(dir, "demo-program-k2", "00".repeat(32), { program_id: "demo-program", environment: "demo" })).toThrow(/mismatch/);
    expect(() => entryFromDirectory(dir, "demo-program-k2", k.fingerprint)).toThrow(/state its program/);
    expect(() => entryFromDirectory(dir, "demo-program-k2", k.fingerprint, { program_id: "other", environment: "demo" })).toThrow(/you stated "other"/);
  });
});
