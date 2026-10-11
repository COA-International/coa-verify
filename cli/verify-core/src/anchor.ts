// Anchor proof verification (docs/protocol/signed-record-v1.md section 6).
// The leaf and the root are ALWAYS recomputed from the verified payload and the inclusion path; the
// proof's own `leaf`, `root` and `anchor.status` members are never trusted on their own.
import { sha256Hex } from "./bytes.js";
import { canonicalBytes } from "./jcs.js";
import { anchorLeafHash, verifyInclusion } from "./merkle.js";
import { verifyOtsProof, type HeaderSource, type OtsResult } from "./ots.js";
import { parseStrictJson, type JsonValue } from "./strict-json.js";

export type AnchorMethod = "opentimestamps-bitcoin" | "local-test";
export type ReportedAnchorStatus = "pending" | "confirmed" | "failed";

export interface AnchorOptions {
  /** A TRUSTED source of Bitcoin block headers (protocol 6.1). Without it a public anchor can only be `attested_unverified`. */
  headers?: HeaderSource;
}

export interface AnchorResult {
  /** The proof document is well-formed strict JSON matching anchor-proof v1. */
  proof_well_formed: boolean;
  proof_errors: string[];
  /** Leaf recomputed from the verified payload is included under `root` via `inclusion_path`. */
  inclusion_valid: boolean;
  method: AnchorMethod | null;
  /** Derived from `method`; a contradicting `public` member in the proof is ignored. */
  public: boolean;
  /** Status the proof claims, when the inclusion check passed and the method is verifiable here. */
  anchor_status: ReportedAnchorStatus | "unverified" | "invalid" | null;
  batch_id: string | null;
  root: string | null;
  tree_size: number | null;
  leaf_index: number | null;
  /** For opentimestamps-bitcoin: result of verifying the OTS proof over `root` (protocol 6.1); null for other methods. */
  ots: OtsResult | null;
  /** True only when the OTS proof was `attested` against a trusted header. */
  ots_verified: boolean | null;
  /** Bitcoin header time of the verified block; only when `ots_verified` (accurate to about +/- 2 hours). */
  block_time: string | null;
  /** Timing evidence comes only from a verified OpenTimestamps attestation; never from proof members. */
  timing_evidence: "none" | "not_verified" | "verified";
  label: string | null;
  notes: string[];
}

const HEX64 = /^[0-9a-f]{64}$/;
const TS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

type Obj = { [k: string]: JsonValue };
const isObj = (v: JsonValue | undefined): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function validateProof(doc: JsonValue): string[] {
  const errs: string[] = [];
  if (!isObj(doc)) return ["proof must be an object"];
  const required = [
    "anchor_proof_version", "batch_id", "method", "public", "leaf", "leaf_hash", "tree_size", "leaf_index",
    "inclusion_path", "root", "batch_closed_at", "anchor",
  ];
  for (const k of required) if (!(k in doc)) errs.push(`${k} is required`);
  for (const k of Object.keys(doc)) if (!required.includes(k)) errs.push(`${k} is not an allowed member`);
  if (doc.anchor_proof_version !== "1") errs.push('anchor_proof_version must be "1"');
  if (typeof doc.batch_id !== "string" || !/^[!-~]{1,128}$/.test(doc.batch_id)) errs.push("batch_id invalid");
  if (doc.method !== "opentimestamps-bitcoin" && doc.method !== "local-test") errs.push("method unsupported");
  if (typeof doc.public !== "boolean") errs.push("public must be boolean");
  if (isObj(doc.leaf)) {
    for (const k of Object.keys(doc.leaf)) if (k !== "document_sha256" && k !== "payload_sha256") errs.push(`leaf.${k} not allowed`);
    for (const k of ["document_sha256", "payload_sha256"]) {
      const v = doc.leaf[k];
      if (typeof v !== "string" || !HEX64.test(v)) errs.push(`leaf.${k} must be 64 lowercase hex`);
    }
  } else errs.push("leaf must be an object");
  for (const k of ["leaf_hash", "root"]) {
    const v = doc[k];
    if (typeof v !== "string" || !HEX64.test(v)) errs.push(`${k} must be 64 lowercase hex`);
  }
  const ts = doc.tree_size;
  if (typeof ts !== "number" || !Number.isInteger(ts) || ts < 1 || ts > 1048576) errs.push("tree_size out of range");
  const li = doc.leaf_index;
  if (typeof li !== "number" || !Number.isInteger(li) || li < 0) errs.push("leaf_index invalid");
  const path = doc.inclusion_path;
  if (!Array.isArray(path) || path.length > 64 || path.some((h) => typeof h !== "string" || !HEX64.test(h))) {
    errs.push("inclusion_path must be up to 64 lowercase hex hashes");
  }
  if (typeof doc.batch_closed_at !== "string" || !TS.test(doc.batch_closed_at)) errs.push("batch_closed_at invalid");
  const a = doc.anchor;
  if (isObj(a)) {
    const allowed = [
      "status", "submitted_at", "confirmed_at", "network", "block_height", "block_time", "transaction_id",
      "explorer_url", "ots_proof_base64", "local_attestation",
    ];
    for (const k of Object.keys(a)) if (!allowed.includes(k)) errs.push(`anchor.${k} not allowed`);
    if (!["pending", "confirmed", "failed"].includes(a.status as string)) errs.push("anchor.status invalid");
    for (const k of ["submitted_at", "confirmed_at", "block_time"]) {
      if (k in a && (typeof a[k] !== "string" || !TS.test(a[k] as string))) errs.push(`anchor.${k} invalid`);
    }
    if ("network" in a && !["bitcoin-mainnet", "bitcoin-testnet", "local"].includes(a.network as string)) errs.push("anchor.network invalid");
    if ("transaction_id" in a && (typeof a.transaction_id !== "string" || !HEX64.test(a.transaction_id))) errs.push("anchor.transaction_id invalid");
    if ("explorer_url" in a && (typeof a.explorer_url !== "string" || !a.explorer_url.startsWith("https://") || a.explorer_url.length > 300)) errs.push("anchor.explorer_url invalid");
    if ("block_height" in a && (typeof a.block_height !== "number" || !Number.isInteger(a.block_height) || a.block_height < 0)) errs.push("anchor.block_height invalid");
    if (doc.method === "local-test" && "network" in a && a.network !== "local") errs.push("local-test proofs must use network local");
  } else errs.push("anchor must be an object");
  return errs;
}

function blank(): AnchorResult {
  return {
    proof_well_formed: false, proof_errors: [], inclusion_valid: false, method: null, public: false,
    anchor_status: null, batch_id: null, root: null, tree_size: null, leaf_index: null, ots: null, ots_verified: null,
    block_time: null, timing_evidence: "none", label: null, notes: [],
  };
}

/**
 * @param verifiedPayload payload of an envelope whose signature verified (callers must not pass anything else)
 */
export function verifyAnchorProof(proofBytes: Uint8Array | string, verifiedPayload: JsonValue, options: AnchorOptions = {}): AnchorResult {
  const result = blank();
  const parsed = parseStrictJson(proofBytes);
  if (!parsed.ok) {
    result.proof_errors = [`not valid strict JSON (${parsed.error_code})`];
    return result;
  }
  const errs = validateProof(parsed.value);
  if (errs.length > 0 || !isObj(parsed.value)) {
    result.proof_errors = errs;
    return result;
  }
  const proof = parsed.value;
  result.proof_well_formed = true;
  result.method = proof.method as AnchorMethod;
  result.public = proof.method === "opentimestamps-bitcoin"; // derived from method, never from the `public` member
  result.batch_id = proof.batch_id as string;
  result.root = proof.root as string;
  result.tree_size = proof.tree_size as number;
  result.leaf_index = proof.leaf_index as number;
  if (proof.public !== result.public) result.notes.push("proof `public` member contradicts `method`; ignored");
  if (!result.public) result.label = "local test anchor - not public";

  // Recompute the leaf from the VERIFIED payload, never from proof.leaf.
  if (!isObj(verifiedPayload) || !isObj(verifiedPayload.document) || typeof verifiedPayload.document.sha256 !== "string") {
    result.proof_errors.push("payload has no document.sha256");
    return result;
  }
  const payloadSha = sha256Hex(canonicalBytes(verifiedPayload));
  const leafHash = anchorLeafHash(verifiedPayload.document.sha256, payloadSha);
  if (leafHash !== proof.leaf_hash) result.notes.push("leaf_hash in the proof is not this record's leaf");
  const leaf = proof.leaf as Obj;
  if (leaf.document_sha256 !== verifiedPayload.document.sha256 || leaf.payload_sha256 !== payloadSha) {
    result.notes.push("leaf members in the proof do not describe this record");
  }
  const included =
    leafHash === proof.leaf_hash &&
    verifyInclusion(leafHash, proof.leaf_index as number, proof.tree_size as number, proof.inclusion_path as string[], proof.root as string);
  result.inclusion_valid = included;
  if (!included) return result;

  const anchor = proof.anchor as Obj;
  if (proof.method === "local-test") {
    result.anchor_status = anchor.status as ReportedAnchorStatus;
    result.timing_evidence = "none";
    result.notes.push("local test anchor: carries no timing evidence and is not public");
  } else {
    // opentimestamps-bitcoin: Merkle path verified above; now the OpenTimestamps proof over the root (protocol 6.1).
    const b64 = typeof anchor.ots_proof_base64 === "string" ? anchor.ots_proof_base64 : null;
    if (b64 === null) {
      result.ots_verified = false;
      result.anchor_status = anchor.status === "failed" ? "failed" : "unverified";
      result.timing_evidence = "not_verified";
      result.notes.push("This public anchor carries no OpenTimestamps proof, so the anchor time is not established.");
    } else {
      const ots = verifyOtsProof(b64, proof.root as string, options.headers);
      result.ots = ots;
      result.ots_verified = ots.status === "attested";
      result.block_time = ots.block_time;
      result.timing_evidence = ots.status === "attested" ? "verified" : "not_verified";
      result.anchor_status =
        ots.status === "attested" ? "confirmed" : ots.status === "pending" ? "pending" : ots.status === "attested_unverified" ? "unverified" : "invalid";
      if (ots.status === "attested") {
        result.notes.push(`OpenTimestamps proof verified against a trusted header: Bitcoin block ${ots.block_height} (time ${ots.block_time}, accurate to about +/- 2 hours).`);
      } else if (ots.status === "attested_unverified") {
        result.notes.push(`A Bitcoin attestation at block ${ots.block_height} is present but no trusted block-header source was configured, so the anchor time is not established.`);
      } else if (ots.status === "pending") {
        result.notes.push("The proof holds only pending calendar attestations: the batch is not yet anchored in a block.");
      } else {
        result.notes.push(`The OpenTimestamps proof is invalid: ${ots.reason}.`);
      }
    }
  }
  return result;
}
