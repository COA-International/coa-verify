import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import {
  buildTrustStore, canonicalize, fromBase64UrlStrict, parseStrictJson, parseTrustStoreFile, sha256Hex,
  validateEnvelopeStructure, verifyEnvelope, verifyInclusion, toBase64Url, TrustStoreError,
  type JsonValue, type TrustEntry,
} from "../src/index.js";

const EMOJI = String.fromCodePoint(0x1f600);
const FULLWIDTH_TILDE = String.fromCharCode(0xff5e);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const V1 = join(ROOT, "fixtures", "vectors", "v1");
const text = (p: string): string => readFileSync(p, "utf8");
const keys: any[] = JSON.parse(text(join(V1, "keys.json"))).keys;
const entryOf = (id: string): TrustEntry => {
  const k = keys.find((x) => x.key_id === id);
  return { key_id: k.key_id, public_key: k.public_key, program_id: k.program_id, role: k.role, environment: k.environment, signer_id: k.signer_id };
};
const valid = readFileSync(join(V1, "envelopes", "valid-basic.json"));

describe("strict JSON parser", () => {
  const code = (s: string | Uint8Array): string => {
    const r = parseStrictJson(s);
    return r.ok ? "ok" : r.error_code;
  };
  it("accepts ordinary documents", () => {
    expect(code('{"a":[1,-2,0,true,false,null,"x"]}')).toBe("ok");
    expect(code("  \n{}\t")).toBe("ok");
  });
  it("rejects fractions, exponents, non-finite numbers", () => {
    expect(code('{"a":1.0}')).toBe("float_not_allowed");
    expect(code('{"a":1e2}')).toBe("float_not_allowed");
    expect(code('{"a":-0.5}')).toBe("float_not_allowed");
    expect(code('{"a":NaN}')).toBe("float_not_allowed");
    expect(code('{"a":Infinity}')).toBe("float_not_allowed");
  });
  it("enforces the safe-integer range", () => {
    expect(code('{"a":9007199254740991}')).toBe("ok");
    expect(code('{"a":-9007199254740991}')).toBe("ok");
    expect(code('{"a":9007199254740992}')).toBe("integer_out_of_range");
    expect(code('{"a":-9007199254740992}')).toBe("integer_out_of_range");
  });
  it("rejects malformed numbers and leading zeros", () => {
    expect(code('{"a":01}')).toBe("invalid_json");
    expect(code('{"a":+1}')).toBe("invalid_json");
    expect(code('{"a":1-2}')).toBe("invalid_json");
    expect(code('{"a":.5}')).toBe("invalid_json");
  });
  it("rejects duplicate members at any depth, including via escapes", () => {
    expect(code('{"a":1,"a":2}')).toBe("duplicate_key");
    expect(code('{"o":{"x":1,"x":2}}')).toBe("duplicate_key");
    expect(code('{"a":1,"\\u0061":2}')).toBe("duplicate_key");
  });
  it("handles __proto__ as an ordinary member", () => {
    const r = parseStrictJson('{"__proto__":{"polluted":1},"b":2}');
    expect(r.ok).toBe(true);
    expect(({} as any).polluted).toBeUndefined();
    if (r.ok) expect(Object.keys(r.value as object)).toEqual(["__proto__", "b"]);
  });
  it("rejects BOM, invalid UTF-8, and oversize documents", () => {
    expect(code(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]))).toBe("bom_not_allowed");
    expect(code(new Uint8Array([0x7b, 0x22, 0xc3, 0x28, 0x22, 0x3a, 0x31, 0x7d]))).toBe("invalid_utf8");
    expect(code(new Uint8Array([0x22, 0xed, 0xa0, 0x80, 0x22]))).toBe("invalid_utf8"); // CESU surrogate bytes
    expect(code(new Uint8Array(1024 * 1024 + 1))).toBe("too_large");
  });
  it("enforces the depth limit of 32", () => {
    const nest = (n: number): string => "[".repeat(n) + "]".repeat(n);
    expect(code(nest(32))).toBe("ok");
    expect(code(nest(33))).toBe("too_deep");
    expect(code(nest(50000))).toBe("too_deep"); // must not blow the stack
  });
  it("rejects unpaired surrogate escapes but accepts pairs", () => {
    expect(code('"\\ud800"')).toBe("invalid_unicode");
    expect(code('"\\udc00"')).toBe("invalid_unicode");
    expect(code('"\\ud800x"')).toBe("invalid_unicode");
    expect(code('"\\ud83d\\ude00"')).toBe("ok");
  });
  it("applies the string rules to member names as well as values", () => {
    expect(code('{"a\\u200bb":1}')).toBe("forbidden_character");
    expect(code('{"a":" x"}')).toBe("edge_whitespace");
    expect(code('{"a":"x\\u00a0"}')).toBe("edge_whitespace");
    expect(code('{"a":"e\\u0301"}')).toBe("not_nfc");
    expect(code('{"a":"\\u0000"}')).toBe("forbidden_character");
  });
  it("rejects raw control characters, trailing data and bad escapes", () => {
    expect(code('"a\nb"')).toBe("invalid_json");
    expect(code("{} x")).toBe("invalid_json");
    expect(code('"\\x"')).toBe("invalid_json");
    expect(code("")).toBe("invalid_json");
    expect(code('{"a":1,}')).toBe("invalid_json");
  });
});

describe("RFC 8785 canonicalisation", () => {
  it("sorts members by UTF-16 code units and uses minimal escapes", () => {
    const v = { b: 1, a: { d: "x", c: [3, 2, 1] }, [EMOJI]: 1, [FULLWIDTH_TILDE]: 2, "": 0 } as unknown as JsonValue;
    // U+FF5E (BMP) sorts after U+1F600's high surrogate D83D by UTF-16 code units
    expect(canonicalize(v)).toBe('{"":0,"a":{"c":[3,2,1],"d":"x"},"b":1,"' + EMOJI + '":1,"' + FULLWIDTH_TILDE + '":2}');
    const raw = "a" + String.fromCharCode(0x0b) + String.fromCharCode(0x22, 0x5c, 0x0a, 0x7f, 0x2028);
    const BS = String.fromCharCode(0x5c);
    const want = '"a' + BS + "u000b" + BS + '"' + BS + BS + BS + "n" + String.fromCharCode(0x7f, 0x2028) + '"';
    expect(canonicalize(raw)).toBe(want);
  });
});

describe("base64url strictness", () => {
  it("round-trips and rejects non-canonical forms", () => {
    const bytes = new Uint8Array(64).map((_, i) => (i * 7) & 255);
    const enc = toBase64Url(bytes);
    expect(enc).toHaveLength(86);
    expect(fromBase64UrlStrict(enc)).toEqual(bytes);
    expect(fromBase64UrlStrict(enc + "=")).toBeNull();
    expect(fromBase64UrlStrict(enc.slice(0, -1) + "B")).toBeNull(); // non-zero trailing bits
    expect(fromBase64UrlStrict("ab+/")).toBeNull();
    expect(fromBase64UrlStrict("a")).toBeNull();
  });
});

describe("envelope verification behaviour", () => {
  const trust = [entryOf("demo-program-k1"), entryOf("demo-program-k2"), entryOf("second-demo-program-k1")];
  it("verifies and reports separate results with the default origin check", () => {
    const r = verifyEnvelope(valid, { trustStore: trust });
    expect(r.issuer_trusted).toBe(true);
    // the demo vector's URL is on coa.international, so the default origin passes
    expect(r.verification_origin.matches).toBe(true);
    expect(r.warnings.map((w) => w.code)).toEqual(["non_production_environment"]);
  });
  it("flags a verification URL on an unexpected origin", () => {
    const r = verifyEnvelope(valid, { trustStore: trust, expectedVerificationOrigin: "https://elsewhere.example" });
    expect(r.verification_origin.matches).toBe(false);
    expect(r.warnings.some((w) => w.code === "verification_origin_mismatch" && w.severity === "trust")).toBe(true);
  });
  it("is not trusted without any trust store, but the signature still needs a key", () => {
    const none = verifyEnvelope(valid);
    expect(none.signature_valid).toBe(false);
    expect(none.issuer_trusted).toBe(false);
    expect(none.key_source).toBe("none");
  });
  it("a candidate (shipped) key yields signature_valid but never issuer_trusted", () => {
    const k = keys.find((x) => x.key_id === "demo-program-k1");
    const r = verifyEnvelope(valid, { candidateKey: { key_id: k.key_id, public_key: k.public_key } });
    expect(r.signature_valid).toBe(true);
    expect(r.issuer_trusted).toBe(false);
    expect(r.key_source).toBe("candidate");
  });
  it("prefers the trust store key over a differing candidate and warns", () => {
    const attacker = keys.find((x) => x.key_id === "attacker-k1");
    const r = verifyEnvelope(valid, { trustStore: trust, candidateKey: { key_id: "demo-program-k1", public_key: attacker.public_key } });
    expect(r.issuer_trusted).toBe(true);
    expect(r.warnings.some((w) => w.code === "candidate_key_differs_from_trusted_key")).toBe(true);
  });
  it("a role/tuple mismatch in the trust entry blocks trust", () => {
    for (const patch of [{ program_id: "second-demo-program" }, { environment: "production" as const }, { signer_id: "someone-else" }]) {
      const r = verifyEnvelope(valid, { trustStore: [{ ...entryOf("demo-program-k1"), ...patch }] });
      expect(r.signature_valid).toBe(true);
      expect(r.issuer_trusted).toBe(false);
    }
  });
  it("compromised keys produce a trust warning even though the mathematics are valid", () => {
    const r = verifyEnvelope(valid, { trustStore: [{ ...entryOf("demo-program-k1"), status: "compromised", compromise_suspected_from: "2026-09-30T00:00:00Z" }] });
    expect(r.signature_valid).toBe(true);
    expect(r.issuer_trusted).toBe(true);
    const w = r.warnings.find((x) => x.code === "key_compromised");
    expect(w?.severity).toBe("trust");
    expect(w?.message).toMatch(/issue date cannot clear/);
  });
  it("rejects a trust store with duplicate key_ids as a configuration error", () => {
    expect(() => verifyEnvelope(valid, { trustStore: [entryOf("demo-program-k1"), entryOf("demo-program-k1")] })).toThrow(/two entries/);
    expect(() => buildTrustStore([entryOf("demo-program-k1"), entryOf("demo-program-k1")] as unknown as JsonValue[])).toThrow(TrustStoreError);
  });
  it("never surfaces a payload that failed the structure rules", () => {
    const bad = JSON.parse(valid.toString("utf8"));
    bad.payload.extra = 1;
    const r = verifyEnvelope(JSON.stringify(bad), { trustStore: trust });
    expect(r.structure_valid).toBe(false);
    expect(r.payload).toBeNull();
    expect(r.signature_valid).toBe(false);
  });
  it("any single-character change in the payload breaks the signature", () => {
    const original = valid.toString("utf8");
    const at = original.indexOf("Example Corner Store");
    const tampered = original.slice(0, at) + "Exampla" + original.slice(at + 7);
    const r = verifyEnvelope(tampered, { trustStore: trust });
    expect(r.structure_valid).toBe(true);
    expect(r.signature_valid).toBe(false);
  });
});

describe("trust store file", () => {
  it("parses a valid file and rejects unknown members and versions", () => {
    const file = JSON.stringify({ trust_store_version: "1", entries: [entryOf("demo-program-k1")] });
    expect(parseTrustStoreFile(file)).toHaveLength(1);
    expect(() => parseTrustStoreFile(JSON.stringify({ trust_store_version: "2", entries: [] }))).toThrow(/unsupported/);
    expect(() => parseTrustStoreFile(JSON.stringify({ trust_store_version: "1", entries: [{ ...entryOf("demo-program-k1"), extra: 1 }] }))).toThrow(/unknown member/);
    expect(() => parseTrustStoreFile(JSON.stringify({ trust_store_version: "1", entries: [{ ...entryOf("demo-program-k1"), role: "laboratory" }] }))).toThrow(/tenant_signer/);
    expect(() => parseTrustStoreFile('{"trust_store_version":"1","entries":[],"entries":[]}')).toThrow(/duplicate_key/);
  });
});

describe("RFC 9162 inclusion proof edge cases", () => {
  it("rejects out-of-range indexes, empty and over-long paths", () => {
    const h = "aa".repeat(32);
    expect(verifyInclusion(h, 0, 1, [], h)).toBe(true);
    expect(verifyInclusion(h, 1, 1, [], h)).toBe(false);
    expect(verifyInclusion(h, 0, 1, [h], h)).toBe(false);
    expect(verifyInclusion(h, -1, 4, [h, h], h)).toBe(false);
    expect(verifyInclusion(h, 0, 4, [h], h)).toBe(false);
  });
});

// The hand-written structure rules must agree with the published JSON Schemas.
describe("structure validation agrees with the published JSON Schemas", () => {
  const schemaDir = join(ROOT, "schemas", "signed-record", "v2.0");
  const ajv = new Ajv2020({ strict: false, allErrors: true, unicodeRegExp: true });
  for (const f of ["defs", "payload", "envelope"]) ajv.addSchema(JSON.parse(text(join(schemaDir, `${f}.schema.json`))));
  const validate = ajv.getSchema("https://coa.international/schemas/signed-record/v2.0/envelope.schema.json")!;
  const base = JSON.parse(valid.toString("utf8"));

  const mutations: Array<[string, (e: any) => void]> = [
    ["unchanged", () => {}],
    ["drop store", (e) => delete e.payload.store],
    ["extra member", (e) => (e.payload.extra = 1)],
    ["bad environment", (e) => (e.payload.environment = "staging")],
    ["bad sha256", (e) => (e.payload.document.sha256 = "ABC")],
    ["byte_length zero", (e) => (e.payload.document.byte_length = 0)],
    ["page_count 10001", (e) => (e.payload.report.page_count = 10001)],
    ["presentation pages 21", (e) => (e.payload.document.presentation_page_count = 21)],
    ["total pages 1", (e) => (e.payload.document.total_page_count = 1)],
    ["timestamp with millis", (e) => (e.payload.issued_at = "2026-09-24T12:00:00.000Z")],
    ["timestamp offset", (e) => (e.payload.issued_at = "2026-09-24T12:00:00+00:00")],
    ["hour 24", (e) => (e.payload.issued_at = "2026-09-24T24:00:00Z")],
    ["month 13", (e) => (e.payload.report.report_date = "2026-13-01")],
    ["bad template", (e) => (e.payload.document.template_version = "v1")],
    ["http url", (e) => (e.payload.verification_url = "http://coa.international/v/7K3M9Q2XWD8FTN4RVB6HJC5P0YZA")],
    ["short code", (e) => (e.payload.verification_code = "7K3M")],
    ["code with I", (e) => (e.payload.verification_code = "7K3M9Q2XWD8FTN4RVB6HJC5P0YZI")],
    ["wrong signature length", (e) => (e.signature = e.signature.slice(1))],
    ["padded signature", (e) => (e.signature = e.signature + "=")],
    ["issuer role", (e) => (e.payload.issuer.role = "verifier")],
    ["empty lot", (e) => (e.payload.batch.lot = "")],
    ["identifier with space", (e) => (e.payload.batch.id = "a b")],
    ["algorithm", (e) => (e.payload.signature_algorithm = "RSA")],
    ["supersedes ok", (e) => (e.payload.supersedes = { issuance_id: "iss_1", verification_code: "7K3M9Q2XWD8FTN4RVB6HJC5P0YZA" })],
    ["supersedes bad", (e) => (e.payload.supersedes = { issuance_id: "iss_1" })],
    ["expiry date ok", (e) => (e.payload.batch.expiry_date = "2028-02-29")],
    ["expiry date bad calendar", (e) => (e.payload.batch.expiry_date = "2027-02-29")],
  ];
  for (const [name, mutate] of mutations) {
    it(name, () => {
      const e = structuredClone(base);
      mutate(e);
      const schemaOk = validate(e) as boolean;
      const ours = validateEnvelopeStructure(e as JsonValue);
      // The JSON Schema cannot express calendar validity or the issuer/url semantic checks; our result
      // may only be STRICTER than the schema, never looser.
      if (!schemaOk) expect(ours.valid).toBe(false);
      if (name === "expiry date bad calendar") expect(ours.valid).toBe(false);
      else if (schemaOk) expect(ours.valid).toBe(true);
    });
  }
  it("agrees on every published envelope vector that parses", () => {
    for (const f of readdirSync(join(V1, "envelopes"))) {
      const parsed = parseStrictJson(new Uint8Array(readFileSync(join(V1, "envelopes", f))));
      if (!parsed.ok) continue;
      const schemaOk = validate(JSON.parse(readFileSync(join(V1, "envelopes", f), "utf8"))) as boolean;
      const ours = validateEnvelopeStructure(parsed.value);
      if (!schemaOk) expect(ours.valid, f).toBe(false);
    }
  });
  it("sha256Hex matches a known answer", () => {
    expect(sha256Hex(new TextEncoder().encode("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

// ---------------------------------------------------------------------------------------------------------------------
// OpenTimestamps proof parsing (protocol 6.1): hostile and malformed inputs must give `invalid`, never throw or hang.
import { verifyOtsProof } from "../src/index.js";

describe("OpenTimestamps proof robustness", () => {
  const MAGIC = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
  const ROOT = "11".repeat(32);
  const b64 = (parts: Buffer[]) => Buffer.concat(parts).toString("base64");
  const header = (digest = Buffer.alloc(32, 0x11)) => [MAGIC, Buffer.from([0x01, 0x08]), digest];
  const status = (parts: Buffer[], headers?: any) => verifyOtsProof(b64(parts), ROOT, headers).status;

  it("rejects wrong magic, version, digest type, digest mismatch and trailing data", () => {
    expect(status([Buffer.from("not a proof")])).toBe("invalid");
    expect(status([MAGIC, Buffer.from([0x02, 0x08]), Buffer.alloc(32, 0x11), Buffer.from([0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0])])).toBe("invalid");
    expect(status([MAGIC, Buffer.from([0x01, 0x02]), Buffer.alloc(20, 0x11)])).toBe("invalid");
    expect(status([...header(Buffer.alloc(32, 0x22)), Buffer.from("00" + "83dfe30d2ef90c8e" + "0100", "hex")])).toBe("invalid");
    const pending = Buffer.from("00" + "83dfe30d2ef90c8e" + "0a" + "09" + "68747470733a2f2f78", "hex");
    expect(status([...header(), pending])).toBe("pending");
    expect(status([...header(), pending, Buffer.from([0x99])])).toBe("invalid");
  });

  it("rejects truncation, unknown operations, absurd lengths and endless varints", () => {
    const full = Buffer.concat([...header(), Buffer.from("00" + "83dfe30d2ef90c8e" + "0a" + "09" + "68747470733a2f2f78", "hex")]);
    for (let n = 0; n < full.length; n += 7) expect(verifyOtsProof(full.subarray(0, n).toString("base64"), ROOT).status).toBe("invalid");
    expect(status([...header(), Buffer.from([0x77])])).toBe("invalid");
    expect(status([...header(), Buffer.from([0xf0, 0xff, 0xff, 0xff, 0xff, 0x0f])])).toBe("invalid");
    expect(status([...header(), Buffer.from([0xf0]), Buffer.alloc(12, 0x80)])).toBe("invalid");
    expect(verifyOtsProof("!!!not base64!!!", ROOT).status).toBe("invalid");
    expect(verifyOtsProof(b64(header()), "abc").status).toBe("invalid");
  });

  it("rejects an intermediate message over 4096 bytes before building it (hexlify bomb, big append/prepend)", () => {
    // 32 -> 64 -> ... -> 4096 is allowed; the next doubling is not. 40 hexlify ops would otherwise need terabytes.
    const okDoublings = Buffer.alloc(7, 0xf3); // 32 * 2^7 = 4096
    expect(status([...header(), okDoublings, Buffer.from("00" + "83dfe30d2ef90c8e" + "0a" + "09" + "68747470733a2f2f78", "hex")])).toBe("pending");
    expect(status([...header(), Buffer.alloc(8, 0xf3)])).toBe("invalid");
    const started = Date.now();
    expect(status([...header(), Buffer.alloc(40, 0xf3)])).toBe("invalid");
    expect(Date.now() - started).toBeLessThan(1000);
    const arg = (n: number) => Buffer.concat([Buffer.from([n & 0x7f | 0x80, n >> 7]), Buffer.alloc(n, 0xaa)]);
    const pend = Buffer.from("00" + "83dfe30d2ef90c8e" + "0a" + "09" + "68747470733a2f2f78", "hex");
    expect(status([...header(), Buffer.from([0xf0]), arg(4064), pend])).toBe("pending"); // 32 + 4064 = 4096: at the bound
    expect(status([...header(), Buffer.from([0xf0]), arg(4065), pend])).toBe("invalid");
    expect(status([...header(), Buffer.from([0xf1]), arg(4065), pend])).toBe("invalid");
  });

  it("requires a Bitcoin attestation payload to be exactly one varint", () => {
    const trailing = Buffer.from("00" + "0588960d73d71901" + "03" + "a06100", "hex");
    expect(status([...header(), trailing])).toBe("invalid");
  });

  it("survives a proof nested far deeper than any real one", () => {
    const deep = Buffer.concat([...header(), Buffer.alloc(5000, 0x08)]);
    expect(verifyOtsProof(deep.toString("base64"), ROOT).status).toBe("invalid");
  });

  it("a Bitcoin attestation needs a trusted header to count, and a mismatching header makes it invalid", () => {
    const att = Buffer.from("00" + "0588960d73d71901" + "02" + "a061", "hex"); // payload is a 2-byte varint: 0x20 + (0x61<<7)
    const proof = [...header(), att];
    const result = verifyOtsProof(b64(proof), ROOT);
    expect(result.status).toBe("attested_unverified");
    expect(result.block_time).toBeNull();
    const height = result.block_height!;
    expect(verifyOtsProof(b64(proof), ROOT, { [String(height)]: { merkle_root: ROOT, time: 1_790_000_000 } }).status).toBe("attested");
    expect(verifyOtsProof(b64(proof), ROOT, { [String(height)]: { merkle_root: "22".repeat(32), time: 1 } }).status).toBe("invalid");
    expect(verifyOtsProof(b64(proof), ROOT, () => null).status).toBe("attested_unverified");
    expect(verifyOtsProof(b64(proof), ROOT, { [String(height)]: { merkle_root: "1111", time: 1 } }).status).toBe("invalid"); // malformed header root
  });

  it("never contacts anything: verification is a pure function of its inputs", () => {
    const realFetch = globalThis.fetch;
    let called = 0;
    globalThis.fetch = (() => { called++; throw new Error("no network"); }) as typeof fetch;
    try {
      const url = Buffer.from("https://alice.btc.calendar.opentimestamps.org");
      const pending = Buffer.concat([Buffer.from("0083dfe30d2ef90c8e", "hex"), Buffer.from([url.length + 1, url.length]), url]);
      expect(status([...header(), pending])).toBe("pending");
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(called).toBe(0);
  });
});
