// Plain-language report. Text labels only (no colour dependence), and each result is stated separately:
// there is deliberately no single "verified" line for the whole record.
import { safeText as t } from "./sanitize.js";
import type { Report } from "./report.js";

export const TOOL_NAME = "coa-verify";

const TAG = { pass: "[PASS]", fail: "[FAIL]", info: "[INFO]", unknown: "[ ?? ]", warn: "[WARN]" } as const;

function line(tag: keyof typeof TAG, text: string): string {
  return `  ${TAG[tag]} ${text}`;
}

export function formatHuman(r: Report, version: string): string {
  const out: string[] = [];
  const rec = r.record;
  out.push(`COA signed-record check (${TOOL_NAME} ${version}) - ${r.mode === "online" ? "ONLINE status check requested" : "OFFLINE"}`);

  if (rec.environment && rec.environment !== "production") {
    out.push("", `*** NOT A PRODUCTION RECORD: environment is "${t(rec.environment)}". It has no real-world standing. ***`);
  }

  if (r.summary) {
    const s = r.summary as any;
    out.push(
      "",
      "Record (as signed - these are assertions the program operator supplied, not facts COA International witnessed)",
      `  Program operator (issuer): ${t(s.issuer.name)}  [id ${t(s.issuer.id)}]`,
      `  Named store:               ${t(s.store.name)}  [id ${t(s.store.id)}]`,
      `  Distributor:               ${t(s.distributor.name)}`,
      `  Product:                   ${t(s.product.name)}`,
      `  Batch / lot:               ${t(s.batch.lot)}`,
      `  Laboratory (as reported):  ${t(s.report.lab_name_as_reported)}, report ${t(s.report.reference)}`,
      `  Purchase event:            ${t(s.purchase_event.statement)} (${t(s.purchase_event.purchase_date)})`,
      `  Signer:                    ${t(s.signer.name)} (${t(s.signer.role)}) using key ${t(rec.key_id)}`,
      `  Issued:                    ${t(s.issued_at)}`,
      `  Verification page:         ${t(s.verification_url)}`,
    );
    if (s.supersedes) out.push(`  Supersedes:                issuance ${t(s.supersedes.issuance_id)}`);
  }

  out.push("", "Checks");
  if (!rec.parse_ok) out.push(line("fail", `The signed record could not be read (${t(rec.error_code)}).`));
  else {
    out.push(line("pass", "The signed record was read under the strict parsing rules."));
    out.push(
      rec.structure_valid
        ? line("pass", "Structure matches schema 2.0.")
        : line("fail", rec.schema_version_supported ? `Structure does not match schema 2.0: ${t(rec.structure_issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join("; "))}` : "Unsupported schema version - this tool only understands 2.0."),
    );
    if (rec.structure_valid) {
      if (rec.signature_valid) {
        out.push(line("pass", `The Ed25519 signature is mathematically valid for key ${t(rec.key_id)} (fingerprint ${t(rec.key_fingerprint)}).`));
        out.push(
          rec.issuer_trusted
            ? line("pass", "Issuer trusted: the key is in YOUR trust store and its program, environment and signer match this record.")
            : line("fail", rec.key_source === "candidate"
                ? "Issuer NOT trusted: this key came with the record, and a key that arrives with a document proves nothing about who holds it. Pin its fingerprint from a source you trust (see: trust add)."
                : "Issuer NOT trusted: the trust-store entry does not match this record's program, environment or signer."),
        );
      } else if (rec.key_source === "none") {
        out.push(line("fail", `No key for "${t(rec.key_id)}" is available, so the signature could not be checked.`));
      } else {
        out.push(line("fail", "The signature does NOT verify: the record was altered or was not signed by this key."));
      }
    }
  }
  for (const w of rec.warnings) out.push(line(w.severity === "trust" ? "warn" : "info", t(w.message)));

  const fileLabel: Record<string, string> = { original_report: "Original laboratory report", store_document: "Store-specific document" };
  for (const [slot, f] of Object.entries(r.files)) {
    if (!f) continue;
    const tag = f.status === "match" ? "pass" : f.status === "unverified" ? "unknown" : "fail";
    out.push(line(tag, `${fileLabel[slot]}: ${t(f.message)}`));
    out.push(`         SHA-256 ${f.sha256} (${f.byte_length} bytes)`);
  }
  if (!r.files.original_report && !r.files.store_document) {
    out.push(line("info", "No files were supplied, so no document was compared to the signed hashes (use --original / --document or --bundle)."));
  }

  if (r.anchor) {
    const a = r.anchor;
    if (!a.proof_well_formed) out.push(line("fail", `Anchor proof is malformed: ${t(a.proof_errors.slice(0, 4).join("; "))}`));
    else if (!a.inclusion_valid) out.push(line("fail", "Anchor proof does NOT include this record (the leaf recomputed from the signed record is not under the proof's root)."));
    else {
      out.push(line("pass", `Anchor inclusion recomputed: this record's leaf is under batch root ${a.root!.slice(0, 16)}... (batch ${t(a.batch_id)}, position ${a.leaf_index! + 1} of ${a.tree_size}).`));
      if (!a.public) out.push(line("warn", "LOCAL TEST ANCHOR - NOT PUBLIC: this is a development/demo anchor and gives no independent timing evidence."));
      else if (a.ots?.status === "attested") out.push(line("pass", `OpenTimestamps proof verified against a header source you trust: Bitcoin block ${a.ots.block_height}, header time ${t(a.ots.block_time)} (accurate to about +/- 2 hours).`));
      else if (a.ots?.status === "attested_unverified") out.push(line("warn", `A Bitcoin attestation at block ${a.ots.block_height} is in the proof, but no trusted block-header source was given (--bitcoin-headers), so the anchor time is NOT established.`));
      else if (a.ots?.status === "pending") out.push(line("info", "The OpenTimestamps proof is still pending: the batch is not yet anchored in a Bitcoin block."));
      else if (a.ots?.status === "invalid") out.push(line("fail", `The OpenTimestamps proof is invalid: ${t(a.ots.reason)}.`));
      else out.push(line("warn", "This public anchor carries no OpenTimestamps proof, so the anchor time is NOT established."));
      out.push(line("info", a.public ? `Anchor result: ${t(a.anchor_status)}. Pending or failed anchoring is an operational fact, not a signature failure.` : `Anchor status as stated by the proof: ${t(a.anchor_status)}. Pending or failed anchoring is an operational fact, not a signature failure.`));
    }
  } else {
    out.push(line("info", "No anchor proof was checked. The signature stands on its own; the anchor only adds evidence about when the hash existed."));
  }

  out.push("", r.mode === "online" ? "Current status (from the server YOU configured; not part of the signed record)" : "Not established by an offline check");
  const cs = r.current_status;
  if (cs.source === "online" && cs.detail) {
    const d = cs.detail;
    out.push(`  Source: ${t(d.base_url)}   as of ${t(d.as_of)}`);
    out.push(line(d.standing === "issued" ? "pass" : "warn", `Record standing: ${t(cs.standing)}${d.source_warning ? ` - source warning: ${t(d.source_warning)}` : ""}${d.replacement_verification_code ? ` - replaced by ${t(d.replacement_verification_code)}` : ""}`));
    out.push(line("info", `Program participation (membership): ${t(cs.membership)}${d.membership ? ` (source ${t(d.membership.source)}, last checked ${t(d.membership.last_checked_at)}, fresh: ${t(d.membership.fresh)})` : ""}. This is separate from whether the documents were genuinely issued.`));
    out.push(line(d.key_status === "compromised" ? "warn" : "info", `Signing key: ${t(cs.key_compromise)}`));
    if (!d.record_matches_local) out.push(line("fail", `The server's response does not describe this record: ${t(d.mismatch_reasons.join("; "))}`));
  } else {
    if (cs.error) out.push(line("fail", `Online check failed: ${t(cs.error.message)}`));
    out.push(line("unknown", `Record standing (issued / disputed / superseded / revoked): ${cs.standing}`));
    out.push(line("unknown", `Current program membership: ${cs.membership}`));
    out.push(line("unknown", `Key compromise notices: ${cs.key_compromise}`));
    if (r.mode === "offline") out.push("         A valid signature can coexist with a revoked record or a lapsed membership; check the verification page above for current status.");
  }

  out.push(
    "",
    "What the results mean",
    "  - A valid signature shows the record is consistent with the key. It shows who holds the key only if YOU trust that key independently.",
    "  - A matching file hash shows your file is byte-for-byte what was signed. A mismatch means your file is NOT the file that was signed.",
    "",
    `Exit code ${r.exit_code}: ${r.exit_reason}`,
  );
  if (r.problems.length) for (const p of r.problems) out.push(`  - ${t(p)}`);
  return out.join("\n") + "\n";
}
