// Structural validation of a signed-record envelope: a hand-written transcription of
// schemas/signed-record/v2.0/*.schema.json plus the section 2.2 semantic checks of
// docs/protocol/signed-record-v1.md. (Hand-written so it runs under a strict browser CSP; a test
// cross-checks it against the published JSON Schemas with Ajv.)
import type { JsonValue } from "./strict-json.js";

export interface StructureIssue {
  path: string;
  message: string;
}

type Obj = { [key: string]: JsonValue };

const IDENTIFIER = /^[!-~]{1,128}$/;
const ASSIGNED_ID = /^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$/;
const TIMESTAMP = /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$/;
const DATE = /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const CODE = /^[0-9A-HJKMNP-TV-Z]{28}$/;
const URL_PATTERN = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?\/v\/[0-9A-HJKMNP-TV-Z]{28}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{85}[AQgw]$/;
const TEMPLATE_VERSION = /^[0-9]{1,4}\.[0-9]{1,4}$/;

export const SCHEMA_VERSION = "2.0";

function isObj(v: JsonValue | undefined): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function codePoints(s: string): number {
  let n = 0;
  for (const _ of s) n++;
  return n;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

function realDate(y: string, m: string, d: string): boolean {
  const year = Number(y);
  const month = Number(m);
  return Number(d) >= 1 && Number(d) <= daysInMonth(year, month);
}

class Checker {
  issues: StructureIssue[] = [];

  fail(path: string, message: string): void {
    this.issues.push({ path, message });
  }

  object(v: JsonValue | undefined, path: string, required: string[], optional: string[] = []): Obj | null {
    if (!isObj(v)) {
      this.fail(path, "must be an object");
      return null;
    }
    for (const k of required) if (!(k in v)) this.fail(`${path}/${k}`, "is required");
    for (const k of Object.keys(v)) {
      if (!required.includes(k) && !optional.includes(k)) this.fail(`${path}/${k}`, "is not an allowed member");
    }
    return v;
  }

  identifier(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string" || !IDENTIFIER.test(v)) this.fail(path, "must be 1-128 printable ASCII characters");
  }

  assignedId(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string" || !ASSIGNED_ID.test(v)) this.fail(path, "must match [a-z0-9-] (assigned identifier)");
  }

  displayText(v: JsonValue | undefined, path: string): void {
    // Forbidden code points / edge whitespace / NFC were already enforced by the strict parser for every string.
    if (typeof v !== "string") return this.fail(path, "must be a string");
    const n = codePoints(v);
    if (n < 1 || n > 300) this.fail(path, "must be 1-300 code points");
  }

  timestamp(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string") return this.fail(path, "must be an RFC 3339 UTC timestamp");
    const m = TIMESTAMP.exec(v);
    if (!m) return this.fail(path, "must be an RFC 3339 UTC timestamp at whole-second precision with Z");
    if (!realDate(m[1]!, m[2]!, m[3]!)) this.fail(path, "is not a real calendar date");
  }

  date(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string") return this.fail(path, "must be a YYYY-MM-DD date");
    const m = DATE.exec(v);
    if (!m) return this.fail(path, "must be a YYYY-MM-DD date");
    if (!realDate(m[1]!, m[2]!, m[3]!)) this.fail(path, "is not a real calendar date");
  }

  sha256(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string" || !SHA256_HEX.test(v)) this.fail(path, "must be 64 lowercase hex characters");
  }

  integer(v: JsonValue | undefined, path: string, min: number, max: number): void {
    if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
      this.fail(path, `must be an integer between ${min} and ${max}`);
    }
  }

  code(v: JsonValue | undefined, path: string): void {
    if (typeof v !== "string" || !CODE.test(v)) this.fail(path, "must be 28 Crockford base32 characters");
  }

  literal(v: JsonValue | undefined, path: string, expected: string): void {
    if (v !== expected) this.fail(path, `must be "${expected}"`);
  }

  oneOf(v: JsonValue | undefined, path: string, allowed: string[]): void {
    if (typeof v !== "string" || !allowed.includes(v)) this.fail(path, `must be one of ${allowed.join(", ")}`);
  }

  namedEntity(v: JsonValue | undefined, path: string): void {
    const o = this.object(v, path, ["id", "name"]);
    if (!o) return;
    this.identifier(o.id, `${path}/id`);
    this.displayText(o.name, `${path}/name`);
  }
}

export interface StructureResult {
  valid: boolean;
  schema_version_supported: boolean;
  issues: StructureIssue[];
}

export function validateEnvelopeStructure(envelope: JsonValue): StructureResult {
  const c = new Checker();
  const env = c.object(envelope, "", ["payload", "signature"]);
  let supported = false;
  if (env) {
    if (typeof env.signature !== "string" || !SIGNATURE.test(env.signature)) {
      c.fail("/signature", "must be 86 base64url characters without padding and with zero unused bits");
    }
    const p = env.payload;
    if (isObj(p)) supported = p.schema_version === SCHEMA_VERSION;
    if (!supported) c.fail("/payload/schema_version", `unsupported schema_version (this verifier supports ${SCHEMA_VERSION})`);
    validatePayload(c, p);
  }
  return { valid: c.issues.length === 0, schema_version_supported: supported, issues: c.issues };
}

function validatePayload(c: Checker, value: JsonValue | undefined): void {
  const P = "/payload";
  const p = c.object(
    value,
    P,
    [
      "schema_version", "purpose", "environment", "issuer", "signer", "program_id", "issuance_id",
      "verification_code", "verification_url", "issued_at", "key_id", "signature_algorithm",
      "canonicalization", "store", "distributor", "product", "batch", "report", "purchase_event", "document",
    ],
    ["supersedes"],
  );
  if (!p) return;
  c.literal(p.purpose, `${P}/purpose`, "store_coa_issuance");
  c.oneOf(p.environment, `${P}/environment`, ["production", "demo", "development"]);

  const issuer = c.object(p.issuer, `${P}/issuer`, ["id", "name", "role"]);
  if (issuer) {
    c.identifier(issuer.id, `${P}/issuer/id`);
    c.displayText(issuer.name, `${P}/issuer/name`);
    c.literal(issuer.role, `${P}/issuer/role`, "program_operator");
  }
  const signer = c.object(p.signer, `${P}/signer`, ["id", "name", "role"]);
  if (signer) {
    c.identifier(signer.id, `${P}/signer/id`);
    c.displayText(signer.name, `${P}/signer/name`);
    c.literal(signer.role, `${P}/signer/role`, "independent_verifier");
  }
  c.assignedId(p.program_id, `${P}/program_id`);
  c.identifier(p.issuance_id, `${P}/issuance_id`);
  c.code(p.verification_code, `${P}/verification_code`);
  if (typeof p.verification_url !== "string" || p.verification_url.length > 300 || !URL_PATTERN.test(p.verification_url)) {
    c.fail(`${P}/verification_url`, "must be an https URL ending /v/ + a 28-character verification code");
  }
  c.timestamp(p.issued_at, `${P}/issued_at`);
  c.assignedId(p.key_id, `${P}/key_id`);
  c.literal(p.signature_algorithm, `${P}/signature_algorithm`, "Ed25519");
  c.literal(p.canonicalization, `${P}/canonicalization`, "RFC8785");
  c.namedEntity(p.store, `${P}/store`);
  c.namedEntity(p.distributor, `${P}/distributor`);
  c.namedEntity(p.product, `${P}/product`);

  const batch = c.object(p.batch, `${P}/batch`, ["id", "lot"], ["expiry_date"]);
  if (batch) {
    c.identifier(batch.id, `${P}/batch/id`);
    c.displayText(batch.lot, `${P}/batch/lot`);
    if ("expiry_date" in batch) c.date(batch.expiry_date, `${P}/batch/expiry_date`);
  }

  const report = c.object(
    p.report,
    `${P}/report`,
    ["id", "version_id", "lab_name_as_reported", "reference", "provenance_basis", "sha256", "byte_length", "page_count"],
    ["report_date"],
  );
  if (report) {
    c.identifier(report.id, `${P}/report/id`);
    c.identifier(report.version_id, `${P}/report/version_id`);
    c.displayText(report.lab_name_as_reported, `${P}/report/lab_name_as_reported`);
    c.displayText(report.reference, `${P}/report/reference`);
    if ("report_date" in report) c.date(report.report_date, `${P}/report/report_date`);
    c.oneOf(report.provenance_basis, `${P}/report/provenance_basis`, ["submitted_report_reviewed", "lab_signed"]);
    c.sha256(report.sha256, `${P}/report/sha256`);
    c.integer(report.byte_length, `${P}/report/byte_length`, 1, Number.MAX_SAFE_INTEGER);
    c.integer(report.page_count, `${P}/report/page_count`, 1, 10000);
  }

  const purchase = c.object(p.purchase_event, `${P}/purchase_event`, ["id", "statement", "purchase_date", "received_at"]);
  if (purchase) {
    c.identifier(purchase.id, `${P}/purchase_event/id`);
    c.displayText(purchase.statement, `${P}/purchase_event/statement`);
    c.date(purchase.purchase_date, `${P}/purchase_event/purchase_date`);
    c.timestamp(purchase.received_at, `${P}/purchase_event/received_at`);
  }

  const doc = c.object(p.document, `${P}/document`, [
    "sha256", "byte_length", "template_version", "presentation_page_count", "total_page_count",
  ]);
  if (doc) {
    c.sha256(doc.sha256, `${P}/document/sha256`);
    c.integer(doc.byte_length, `${P}/document/byte_length`, 1, Number.MAX_SAFE_INTEGER);
    if (typeof doc.template_version !== "string" || !TEMPLATE_VERSION.test(doc.template_version)) {
      c.fail(`${P}/document/template_version`, "must look like 1.0");
    }
    c.integer(doc.presentation_page_count, `${P}/document/presentation_page_count`, 1, 20);
    c.integer(doc.total_page_count, `${P}/document/total_page_count`, 2, 10020);
  }

  if ("supersedes" in p) {
    const s = c.object(p.supersedes, `${P}/supersedes`, ["issuance_id", "verification_code"]);
    if (s) {
      c.identifier(s.issuance_id, `${P}/supersedes/issuance_id`);
      c.code(s.verification_code, `${P}/supersedes/verification_code`);
    }
  }

  // Section 2.2 semantic checks
  if (isObj(p.issuer) && typeof p.issuer.id === "string" && typeof p.program_id === "string" && p.issuer.id !== p.program_id) {
    c.fail(`${P}/issuer/id`, "must equal program_id");
  }
  if (
    typeof p.verification_url === "string" &&
    typeof p.verification_code === "string" &&
    !p.verification_url.endsWith(`/v/${p.verification_code}`)
  ) {
    c.fail(`${P}/verification_url`, "must end with /v/ + verification_code");
  }
}

/** Origin (scheme://host[:port]) of a verification_url that already passed the pattern check. */
export function originOf(url: string): string {
  const m = /^(https:\/\/[^/]+)\//.exec(url);
  return m ? m[1]! : "";
}
