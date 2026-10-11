// Envelope verification and file checks (docs/protocol/signed-record-v1.md sections 3-5 and 7).
import { ed25519 } from "@noble/curves/ed25519.js";
import { concatBytes, fromBase64UrlStrict, sha256Hex, utf8 } from "./bytes.js";
import { canonicalBytes } from "./jcs.js";
import { parseStrictJson, type JsonValue, type ParseErrorCode } from "./strict-json.js";
import { originOf, validateEnvelopeStructure, type StructureIssue } from "./structure.js";
import { decodePublicKey, fingerprintOf, type CandidateKey, type TrustEntry } from "./trust.js";

export const SIGNING_DOMAIN = "COA-INTL-ISSUANCE-v1\n";
export const DEFAULT_VERIFICATION_ORIGIN = "https://coa.international";

export interface VerifyOptions {
  /** Out-of-band trust store. Empty/absent means nothing can be `issuer_trusted`. */
  trustStore?: TrustEntry[];
  /** A key shipped with the record (bundle public-key.json): can only ever produce `signature_valid`. */
  candidateKey?: CandidateKey;
  /** Expected origin of payload.verification_url; `null` disables the check. Default https://coa.international. */
  expectedVerificationOrigin?: string | null;
}

export type Warning = {
  code:
    | "non_production_environment"
    | "key_compromised"
    | "key_retired"
    | "verification_origin_mismatch"
    | "candidate_key_differs_from_trusted_key";
  severity: "info" | "trust";
  message: string;
};

export type KeySource = "trust_store" | "candidate" | "none";

export interface EnvelopeResult {
  parse_ok: boolean;
  error_code: ParseErrorCode | null;
  schema_version_supported: boolean;
  structure_valid: boolean;
  structure_issues: StructureIssue[];
  signature_valid: boolean;
  issuer_trusted: boolean;
  key_source: KeySource;
  key_id: string | null;
  key_fingerprint: string | null;
  /** Populated only when structure_valid (a payload that failed structural rules is never surfaced as data). */
  payload: { [k: string]: JsonValue } | null;
  /** SHA-256 of RFC 8785(payload), the anchoring `payload_sha256`. Only when structure_valid. */
  payload_sha256: string | null;
  environment: string | null;
  verification_origin: { expected: string | null; actual: string | null; matches: boolean | null };
  warnings: Warning[];
}

function emptyResult(): EnvelopeResult {
  return {
    parse_ok: false, error_code: null, schema_version_supported: false, structure_valid: false, structure_issues: [],
    signature_valid: false, issuer_trusted: false, key_source: "none", key_id: null, key_fingerprint: null,
    payload: null, payload_sha256: null, environment: null,
    verification_origin: { expected: null, actual: null, matches: null }, warnings: [],
  };
}

export function signingInput(payload: JsonValue): Uint8Array {
  return concatBytes(utf8(SIGNING_DOMAIN), canonicalBytes(payload));
}

function ed25519Verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function verifyEnvelope(input: Uint8Array | string, options: VerifyOptions = {}): EnvelopeResult {
  const result = emptyResult();
  const trustStore = options.trustStore ?? [];
  const seen = new Set<string>();
  for (const e of trustStore) {
    if (seen.has(e.key_id)) throw new Error(`trust store has two entries for key_id "${e.key_id}"`);
    seen.add(e.key_id);
  }

  const parsed = parseStrictJson(input);
  if (!parsed.ok) {
    result.error_code = parsed.error_code;
    return result;
  }
  result.parse_ok = true;

  const structure = validateEnvelopeStructure(parsed.value);
  result.schema_version_supported = structure.schema_version_supported;
  result.structure_valid = structure.valid;
  result.structure_issues = structure.issues;
  if (!structure.valid) return result;

  const envelope = parsed.value as { payload: { [k: string]: JsonValue }; signature: string };
  const payload = envelope.payload;
  result.payload = payload;
  result.payload_sha256 = sha256Hex(canonicalBytes(payload));
  result.environment = payload.environment as string;
  const keyId = payload.key_id as string;
  result.key_id = keyId;

  const expected =
    options.expectedVerificationOrigin === undefined ? DEFAULT_VERIFICATION_ORIGIN : options.expectedVerificationOrigin;
  const actualOrigin = originOf(payload.verification_url as string);
  result.verification_origin = {
    expected,
    actual: actualOrigin,
    matches: expected === null ? null : expected.replace(/\/+$/, "") === actualOrigin,
  };
  if (result.verification_origin.matches === false) {
    result.warnings.push({
      code: "verification_origin_mismatch",
      severity: "trust",
      message: `The record's verification URL is on ${actualOrigin}, not the expected ${expected}.`,
    });
  }
  if (payload.environment !== "production") {
    result.warnings.push({
      code: "non_production_environment",
      severity: "info",
      message: `NOT A PRODUCTION RECORD: environment is "${payload.environment as string}".`,
    });
  }

  // Resolve the key BY key_id in the trust store. A candidate key can only yield signature_valid.
  const entry = trustStore.find((e) => e.key_id === keyId);
  let keyBytes: Uint8Array | null = null;
  if (entry) {
    keyBytes = decodePublicKey(entry.public_key);
    result.key_source = "trust_store";
    if (options.candidateKey && options.candidateKey.key_id === keyId && options.candidateKey.public_key !== entry.public_key) {
      result.warnings.push({
        code: "candidate_key_differs_from_trusted_key",
        severity: "trust",
        message: "The key shipped with this record differs from the key in your trust store; the trust store key was used.",
      });
    }
  } else if (options.candidateKey && options.candidateKey.key_id === keyId) {
    keyBytes = decodePublicKey(options.candidateKey.public_key);
    result.key_source = "candidate";
  }
  if (!keyBytes) return result;
  result.key_fingerprint = fingerprintOf(entry ? entry.public_key : options.candidateKey!.public_key);

  const signature = fromBase64UrlStrict(envelope.signature);
  if (!signature || signature.length !== 64) return result; // structure check already guarantees this shape
  result.signature_valid = ed25519Verify(signature, signingInput(payload), keyBytes);
  if (!result.signature_valid) return result;

  const signer = payload.signer as { id: string };
  result.issuer_trusted =
    entry !== undefined &&
    entry.role === "tenant_signer" &&
    entry.program_id === payload.program_id &&
    entry.environment === payload.environment &&
    entry.signer_id === signer.id;

  if (entry?.status === "compromised") {
    result.warnings.push({
      code: "key_compromised",
      severity: "trust",
      message:
        "This key is marked compromised in your trust store. The signature is mathematically valid, but the record " +
        "must not be relied on without review" +
        (entry.compromise_suspected_from ? ` (suspected from ${entry.compromise_suspected_from}; the issue date cannot clear this).` : "."),
    });
  } else if (entry?.status === "retired") {
    result.warnings.push({
      code: "key_retired",
      severity: "info",
      message: "This key has been retired (rotated out); records it signed remain verifiable.",
    });
  }
  return result;
}

// ---------------------------------------------------------------------------------------------------
// File checks

export type ExpectedFile = "original_report" | "store_document";

export interface FileCheck {
  slot: ExpectedFile | null;
  sha256: string;
  byte_length: number;
  /** `match`/`mismatch` only when the envelope's signature verified; otherwise `unverified`. */
  status: "match" | "mismatch" | "unverified";
  /** Which signed hash(es) the bytes actually equal (independent of `slot`). */
  matches: ExpectedFile | null;
  message: string;
}

const LABEL: Record<ExpectedFile, string> = {
  original_report: "the original laboratory report",
  store_document: "the store-specific document",
};

/**
 * Compare file bytes to the hashes in a payload. `slot` says which document the user believes this is;
 * with `slot = null` the file is compared to both. A match is only evidence when `signatureValid`.
 */
export function checkFile(
  bytes: Uint8Array,
  payload: { [k: string]: JsonValue } | null,
  signatureValid: boolean,
  slot: ExpectedFile | null,
): FileCheck {
  return classifyDigest(sha256Hex(bytes), bytes.length, payload, signatureValid, slot);
}

/**
 * Same comparison as `checkFile` for a digest computed elsewhere (for example incrementally in a browser, so that a
 * large file never has to be held in memory and its bytes never leave the machine).
 */
export function classifyDigest(
  sha: string,
  byteLength: number,
  payload: { [k: string]: JsonValue } | null,
  signatureValid: boolean,
  slot: ExpectedFile | null,
): FileCheck {
  const bytes = { length: byteLength };
  const base = { slot, sha256: sha, byte_length: bytes.length };
  if (!payload || !signatureValid) {
    return {
      ...base, status: "unverified", matches: null,
      message: "The signed record could not be verified, so this file's hash is not compared as evidence.",
    };
  }
  const report = payload.report as { sha256: string; byte_length: number };
  const document = payload.document as { sha256: string; byte_length: number };
  const equalsOriginal = sha === report.sha256 && bytes.length === report.byte_length;
  const equalsDocument = sha === document.sha256 && bytes.length === document.byte_length;
  const matches: ExpectedFile | null = equalsOriginal ? "original_report" : equalsDocument ? "store_document" : null;
  if (slot === null) {
    return {
      ...base, matches, status: matches ? "match" : "mismatch",
      message: matches
        ? `This file is byte-for-byte ${LABEL[matches]} that the record signs.`
        : "This file matches neither the original report nor the store-specific document in the signed record.",
    };
  }
  if (matches === slot) {
    return { ...base, matches, status: "match", message: `Matches the signed hash for ${LABEL[slot]}.` };
  }
  if (matches) {
    return {
      ...base, matches, status: "mismatch",
      message: `This file is ${LABEL[matches]}, not ${LABEL[slot]} it was checked against.`,
    };
  }
  return {
    ...base, matches: null, status: "mismatch",
    message:
      `This file does not match the signed hash for ${LABEL[slot]}. It is not the same file that was signed, ` +
      "so it must not be relied on as that document.",
  };
}
