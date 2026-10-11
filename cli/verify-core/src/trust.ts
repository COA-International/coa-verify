// Trust store (docs/protocol/signed-record-v1.md section 5). A trust entry is obtained OUT OF BAND;
// nothing that arrives with a record or bundle may become one without an explicit human decision.
import { fromBase64UrlStrict, sha256Hex } from "./bytes.js";
import { parseStrictJson, type JsonValue } from "./strict-json.js";

export type Environment = "production" | "demo" | "development";

export interface TrustEntry {
  key_id: string;
  /** Raw 32-byte Ed25519 public key, base64url without padding. */
  public_key: string;
  program_id: string;
  role: "tenant_signer";
  environment: Environment;
  signer_id: string;
  /** Optional operator-maintained status. `compromised` yields a trust warning on every record. */
  status?: "active" | "retired" | "compromised";
  compromise_suspected_from?: string;
}

/** A key that arrived with the record (bundle public-key.json, directory fetch): never trusted by itself. */
export interface CandidateKey {
  key_id: string;
  public_key: string;
}

export class TrustStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustStoreError";
  }
}

const ASSIGNED_ID = /^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$/;
const ENVIRONMENTS = ["production", "demo", "development"];
const STATUSES = ["active", "retired", "compromised"];
const ENTRY_MEMBERS = [
  "key_id", "public_key", "program_id", "role", "environment", "signer_id", "status", "compromise_suspected_from", "note",
];

export function fingerprintOf(publicKeyBase64Url: string): string | null {
  const raw = fromBase64UrlStrict(publicKeyBase64Url);
  return raw && raw.length === 32 ? sha256Hex(raw) : null;
}

export function decodePublicKey(publicKeyBase64Url: string): Uint8Array | null {
  const raw = fromBase64UrlStrict(publicKeyBase64Url);
  return raw && raw.length === 32 ? raw : null;
}

function isObj(v: JsonValue | undefined): v is { [k: string]: JsonValue } {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate one entry; throws TrustStoreError describing the first problem. */
export function normalizeTrustEntry(value: JsonValue, where = "trust entry"): TrustEntry {
  if (!isObj(value)) throw new TrustStoreError(`${where}: must be an object`);
  for (const k of Object.keys(value)) {
    if (!ENTRY_MEMBERS.includes(k)) throw new TrustStoreError(`${where}: unknown member "${k}"`);
  }
  const str = (k: string): string => {
    const v = value[k];
    if (typeof v !== "string") throw new TrustStoreError(`${where}: "${k}" must be a string`);
    return v;
  };
  const key_id = str("key_id");
  if (!ASSIGNED_ID.test(key_id)) throw new TrustStoreError(`${where}: key_id must match [a-z0-9-]`);
  const public_key = str("public_key");
  if (!decodePublicKey(public_key)) throw new TrustStoreError(`${where}: public_key must be a 32-byte base64url key`);
  const program_id = str("program_id");
  if (!ASSIGNED_ID.test(program_id)) throw new TrustStoreError(`${where}: program_id must match [a-z0-9-]`);
  if (str("role") !== "tenant_signer") throw new TrustStoreError(`${where}: role must be tenant_signer`);
  const environment = str("environment");
  if (!ENVIRONMENTS.includes(environment)) throw new TrustStoreError(`${where}: unknown environment`);
  const signer_id = str("signer_id");
  const entry: TrustEntry = {
    key_id, public_key, program_id, role: "tenant_signer", environment: environment as Environment, signer_id,
  };
  if (value.status !== undefined) {
    const status = str("status");
    if (!STATUSES.includes(status)) throw new TrustStoreError(`${where}: unknown status`);
    entry.status = status as TrustEntry["status"];
  }
  if (value.compromise_suspected_from !== undefined) entry.compromise_suspected_from = str("compromise_suspected_from");
  return entry;
}

/** Validate a list of entries: duplicate key_id is a configuration error (section 5). */
export function buildTrustStore(entries: JsonValue[]): TrustEntry[] {
  const seen = new Set<string>();
  return entries.map((e, i) => {
    const entry = normalizeTrustEntry(e, `entry ${i}`);
    if (seen.has(entry.key_id)) throw new TrustStoreError(`duplicate key_id "${entry.key_id}" in trust store`);
    seen.add(entry.key_id);
    return entry;
  });
}

export const TRUST_STORE_VERSION = "1";

/** Parse a trust-store file: {"trust_store_version":"1","entries":[...]} */
export function parseTrustStoreFile(bytes: Uint8Array | string): TrustEntry[] {
  const parsed = parseStrictJson(bytes);
  if (!parsed.ok) throw new TrustStoreError(`trust store is not valid strict JSON (${parsed.error_code})`);
  const doc = parsed.value;
  if (!isObj(doc)) throw new TrustStoreError("trust store must be a JSON object");
  for (const k of Object.keys(doc)) {
    if (!["trust_store_version", "entries", "note"].includes(k)) throw new TrustStoreError(`unknown member "${k}"`);
  }
  if (doc.trust_store_version !== TRUST_STORE_VERSION) {
    throw new TrustStoreError(`unsupported trust_store_version (expected "${TRUST_STORE_VERSION}")`);
  }
  if (!Array.isArray(doc.entries)) throw new TrustStoreError('"entries" must be an array');
  return buildTrustStore(doc.entries);
}

export function serializeTrustStore(entries: TrustEntry[]): string {
  return JSON.stringify(
    {
      trust_store_version: TRUST_STORE_VERSION,
      note: "Entries were pinned by a human who confirmed each fingerprint out of band. Do not add keys because they arrived with a document.",
      entries,
    },
    null,
    2,
  ) + "\n";
}

/**
 * What the HUMAN asserts about a key they are pinning. These values become the trust entry; the shipped document's own
 * `program_id` / `environment` / `signer_id` are unauthenticated metadata and are only cross-checked, never adopted.
 */
export interface PinBinding {
  program_id: string;
  environment: Environment;
  /** Defaults to `coa-international`, the only signer in release 1. */
  signer_id?: string;
}

export const DEFAULT_SIGNER_ID = "coa-international";

function requireBinding(b: PinBinding | undefined): Required<PinBinding> {
  if (!b || !b.program_id || !b.environment) {
    throw new TrustStoreError("pinning a key needs you to state its program (--program-id) and environment (--environment)");
  }
  return { program_id: b.program_id, environment: b.environment, signer_id: b.signer_id ?? DEFAULT_SIGNER_ID };
}

function crossCheck(doc: { [k: string]: JsonValue }, want: Required<PinBinding>, where: string): void {
  const pairs: Array<[string, string]> = [["program_id", want.program_id], ["environment", want.environment], ["signer_id", want.signer_id]];
  for (const [k, expected] of pairs) {
    if (doc[k] !== undefined && doc[k] !== expected) {
      throw new TrustStoreError(`${where} says ${k}="${String(doc[k])}" but you stated "${expected}"; check which is right before trusting this key`);
    }
  }
  if (doc.role !== undefined && doc.role !== "tenant_signer") throw new TrustStoreError(`${where} is not a tenant_signer key`);
}

/**
 * Build a trust entry for `keyId` from a downloaded key directory: the fingerprint must equal the one the human pinned out
 * of band, and the human states the program and environment (the directory's copies must agree, but are not the source).
 */
export function entryFromDirectory(
  directory: JsonValue,
  keyId: string,
  pinnedFingerprint: string,
  binding?: PinBinding,
): TrustEntry {
  const pin = pinnedFingerprint.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new TrustStoreError("fingerprint must be 64 hex characters");
  const want = requireBinding(binding);
  if (!isObj(directory) || !Array.isArray(directory.tenants)) throw new TrustStoreError("not a key directory v1 document");
  for (const tenant of directory.tenants) {
    if (!isObj(tenant) || !isObj(tenant.roles)) continue;
    const signers = tenant.roles.tenant_signer;
    if (!Array.isArray(signers)) continue;
    for (const k of signers) {
      if (!isObj(k) || k.key_id !== keyId) continue;
      if (typeof k.public_key !== "string") throw new TrustStoreError("directory key has no public_key");
      const actual = fingerprintOf(k.public_key);
      if (actual !== pin) {
        throw new TrustStoreError(`fingerprint mismatch for ${keyId}: pinned ${pin}, directory key has ${actual ?? "(invalid key)"}`);
      }
      crossCheck(k, want, `directory key ${keyId}`);
      return normalizeTrustEntry(
        { key_id: keyId, public_key: k.public_key, program_id: want.program_id, role: "tenant_signer", environment: want.environment, signer_id: want.signer_id },
        `directory key ${keyId}`,
      );
    }
  }
  throw new TrustStoreError(`key_id "${keyId}" not found in the directory`);
}

/**
 * Build a trust entry from a single key document (bundle public-key.json shape): the fingerprint must equal the one the human
 * pinned out of band, and the human states the program and environment. Metadata inside the document (which arrived with the
 * record) is cross-checked against the human's statement and never adopted.
 */
export function entryFromKeyDocument(doc: JsonValue, pinnedFingerprint: string, binding?: PinBinding): TrustEntry {
  const pin = pinnedFingerprint.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pin)) throw new TrustStoreError("fingerprint must be 64 hex characters");
  const want = requireBinding(binding);
  if (!isObj(doc) || typeof doc.public_key !== "string" || typeof doc.key_id !== "string") throw new TrustStoreError("not a public key document");
  const actual = fingerprintOf(doc.public_key);
  if (actual !== pin) {
    throw new TrustStoreError(`fingerprint mismatch: pinned ${pin}, key document has ${actual ?? "(invalid key)"}`);
  }
  crossCheck(doc, want, "key document");
  return normalizeTrustEntry(
    { key_id: doc.key_id, public_key: doc.public_key, program_id: want.program_id, role: "tenant_signer", environment: want.environment, signer_id: want.signer_id },
    "key document",
  );
}
