// Turns verify-core results into the CLI report (also the --json output) and picks the exit code.
import {
  checkFile, verifyAnchorProof, verifyEnvelope, type AnchorResult, type EnvelopeResult, type FileCheck,
  type JsonValue, type TrustEntry, type CandidateKey, type HeaderSource,
} from "@coa/verify-core";
import { EXIT, EXIT_TEXT } from "./exit-codes.js";
import type { OnlineStatus } from "./online.js";

export const REPORT_VERSION = "1";

export interface Inputs {
  envelope: Uint8Array;
  trustStore: TrustEntry[];
  candidateKey?: CandidateKey;
  expectedVerificationOrigin?: string | null;
  originalReport?: Uint8Array;
  storeDocument?: Uint8Array;
  anchorProof?: Uint8Array;
  /** A Bitcoin header source the user trusts (protocol 6.1). */
  bitcoinHeaders?: HeaderSource;
  requireAnchor?: boolean;
}

export type OnlineOutcome =
  | { requested: false }
  | { requested: true; ok: true; status: OnlineStatus; anchor_from_server: AnchorResult | null }
  | { requested: true; ok: false; reason: string; message: string };

export interface Report {
  report_version: typeof REPORT_VERSION;
  mode: "offline" | "online";
  record: EnvelopeResult;
  summary: Record<string, unknown> | null;
  files: { original_report: FileCheck | null; store_document: FileCheck | null };
  anchor: AnchorResult | null;
  current_status: {
    source: "unknown_offline" | "online";
    standing: string;
    membership: string;
    key_compromise: string;
    detail: OnlineStatus | null;
    error: { reason: string; message: string } | null;
  };
  exit_code: number;
  exit_reason: string;
  problems: string[];
}

const OFFLINE_UNKNOWN = "unknown (offline)";

function summarise(payload: { [k: string]: JsonValue }): Record<string, unknown> {
  const named = (o: JsonValue | undefined) => o as { id: string; name: string };
  return {
    issuer: payload.issuer,
    signer: payload.signer,
    store: named(payload.store),
    distributor: named(payload.distributor),
    product: named(payload.product),
    batch: payload.batch,
    report: payload.report,
    purchase_event: payload.purchase_event,
    document: payload.document,
    issuance_id: payload.issuance_id,
    verification_code: payload.verification_code,
    verification_url: payload.verification_url,
    issued_at: payload.issued_at,
    environment: payload.environment,
    supersedes: payload.supersedes ?? null,
  };
}

export function verifyRecord(inputs: Inputs): EnvelopeResult {
  return verifyEnvelope(inputs.envelope, {
    trustStore: inputs.trustStore,
    candidateKey: inputs.candidateKey,
    expectedVerificationOrigin: inputs.expectedVerificationOrigin,
  });
}

/** Pure computation; the online part is fetched by the caller (after the signature verified) and passed in. */
export function buildReport(inputs: Inputs, record: EnvelopeResult, online: OnlineOutcome): Report {
  const problems: string[] = [];
  const evidence = record.signature_valid;

  const files = {
    original_report: inputs.originalReport ? checkFile(inputs.originalReport, record.payload, evidence, "original_report") : null,
    store_document: inputs.storeDocument ? checkFile(inputs.storeDocument, record.payload, evidence, "store_document") : null,
  };

  let anchor: AnchorResult | null = null;
  if (inputs.anchorProof && record.payload && evidence) anchor = verifyAnchorProof(inputs.anchorProof, record.payload, { headers: inputs.bitcoinHeaders });
  else if (online.requested && online.ok && online.anchor_from_server) anchor = online.anchor_from_server;

  const current_status: Report["current_status"] = {
    source: "unknown_offline",
    standing: OFFLINE_UNKNOWN,
    membership: OFFLINE_UNKNOWN,
    key_compromise: `${OFFLINE_UNKNOWN}; only what your trust store says${record.key_id ? ` about ${record.key_id}` : ""}`,
    detail: null,
    error: null,
  };
  if (online.requested) {
    if (online.ok) {
      const s = online.status;
      current_status.source = "online";
      current_status.detail = s;
      current_status.standing = s.standing ?? "not reported";
      current_status.membership = s.membership?.status ?? "not reported";
      current_status.key_compromise = s.key_status === "compromised" ? `compromised (${s.trust_warning ?? "see key directory"})` : `key status: ${s.key_status ?? "not reported"}`;
    } else {
      current_status.error = { reason: online.reason, message: online.message };
    }
  }

  // ---- exit code selection (priority 1, 2, 6, 3, 4, 5)
  let exit: number = EXIT.OK;
  const priority = [EXIT.RECORD_INVALID, EXIT.NOT_TRUSTED, EXIT.STANDING_NOT_ISSUED, EXIT.FILE_MISMATCH, EXIT.ANCHOR_PROBLEM, EXIT.ONLINE_PROBLEM];
  const found: number[] = [];
  const note = (code: number, problem: string): void => {
    found.push(code);
    problems.push(problem);
  };

  if (!record.parse_ok) note(EXIT.RECORD_INVALID, `signed record could not be parsed (${record.error_code})`);
  else if (!record.schema_version_supported) note(EXIT.RECORD_INVALID, "unsupported schema version");
  else if (!record.structure_valid) note(EXIT.RECORD_INVALID, "signed record does not match the schema");
  else if (!record.signature_valid) {
    note(
      EXIT.RECORD_INVALID,
      record.key_source === "none"
        ? `no key is available for key_id "${record.key_id}": add it to your trust store (or pass the shipped key for a signature-only check)`
        : "signature does not verify",
    );
  } else if (!record.issuer_trusted) {
    note(
      EXIT.NOT_TRUSTED,
      record.key_source === "candidate"
        ? "signature is valid for the shipped key, but that key is not in your trust store"
        : "signature is valid, but the trust-store entry does not match this record's program, environment or signer",
    );
  }
  for (const w of record.warnings) if (w.severity === "trust") note(EXIT.NOT_TRUSTED, w.message);

  for (const f of Object.values(files)) if (f && f.status !== "match") note(record.signature_valid ? EXIT.FILE_MISMATCH : EXIT.RECORD_INVALID, `file check: ${f.message}`);

  if (inputs.anchorProof && anchor && (!anchor.proof_well_formed || !anchor.inclusion_valid)) {
    note(EXIT.ANCHOR_PROBLEM, "anchor proof is malformed or does not include this record");
  } else if (anchor?.ots && anchor.ots.status === "invalid") {
    note(EXIT.ANCHOR_PROBLEM, `the OpenTimestamps proof is invalid: ${anchor.ots.reason}`);
  }
  if (inputs.anchorProof && !anchor && !record.signature_valid) {
    note(EXIT.RECORD_INVALID, "anchor proof was not evaluated because the signed record did not verify");
  }
  if (inputs.requireAnchor) {
    const ok = anchor !== null && anchor.inclusion_valid && anchor.public && anchor.ots_verified === true;
    if (!ok) note(EXIT.ANCHOR_PROBLEM, "--require-anchor: no fully verified public anchor is available");
  }

  if (online.requested) {
    if (!online.ok) note(EXIT.ONLINE_PROBLEM, `online status unavailable: ${online.message}`);
    else {
      const s = online.status;
      if (!s.record_matches_local) note(EXIT.ONLINE_PROBLEM, `server response does not match the verified record (${s.mismatch_reasons.join("; ")})`);
      if (s.standing && s.standing !== "issued") note(EXIT.STANDING_NOT_ISSUED, `current standing is "${s.standing}"`);
      if (s.key_status === "compromised") note(EXIT.NOT_TRUSTED, "the key directory reports this signing key as compromised");
    }
  }

  const chosen = priority.find((c) => found.includes(c));
  if (chosen !== undefined) exit = chosen;

  return {
    report_version: REPORT_VERSION,
    mode: online.requested ? "online" : "offline",
    record,
    summary: record.payload && record.structure_valid ? summarise(record.payload) : null,
    files,
    anchor,
    current_status,
    exit_code: exit,
    exit_reason: EXIT_TEXT[exit] ?? "",
    problems,
  };
}
