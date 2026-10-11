import { existsSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import {
  TrustStoreError, entryFromDirectory, entryFromKeyDocument, fingerprintOf, parseStrictJson, parseTrustStoreFile,
  serializeTrustStore, verifyAnchorProof, type CandidateKey, type Environment, type HeaderSource, type JsonValue, type TrustEntry,
} from "@coa/verify-core";
import { EXIT, EXIT_TEXT } from "./exit-codes.js";
import { formatHuman } from "./format.js";
import { OnlineError, fetchOnlineStatus, normalizeBaseUrl, type OnlineFetchOptions } from "./online.js";
import { buildReport, verifyRecord, type Inputs, type OnlineOutcome } from "./report.js";
import { safeText } from "./sanitize.js";

export const VERSION = "1.0.0";
const MAX_FILE_BYTES = 256 * 1024 * 1024;

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  env: Record<string, string | undefined>;
  cwd: string;
  fetchImpl?: typeof fetch;
}

class UsageError extends Error {}
class ConfigError extends Error {}

const HELP = `coa-verify ${VERSION} - independent verifier for COA signed records

USAGE
  coa-verify verify <signed-record.json> [options]
  coa-verify verify --bundle <dir> [options]
  coa-verify trust add   --store <file> (--directory <key-directory.json> --key-id <id> | --key-file <public-key.json>)
                         --fingerprint <sha256-hex> --program-id <id> --environment <production|demo|development> [--signer-id <id>]
  coa-verify trust list  --store <file>
  coa-verify --help | --version

VERIFY OPTIONS
  --trust-store <file>     Trust store you built out of band (or env COA_VERIFY_TRUST_STORE). Without one nothing
                           can be "issuer trusted"; a key shipped with the record is only checked for signature validity.
  --bundle <dir>           Unzipped bundle: reads signed-record.json, original-report[-<sha256>].pdf, store-document.pdf or
                           signed-certificate-<sha256>.pdf,
                           public-key.json (candidate key only), anchor-proof.json when present.
  --original <file>       Original laboratory report PDF to compare with the signed hash.
  --document <file>       Store-specific PDF to compare with the signed hash.
  --anchor-proof <file>   anchor-proof.json to recompute and check.
  --bitcoin-headers <file> A Bitcoin block-header file YOU trust ({"headers": {"<height>": {"merkle_root": "<hex of header bytes 36-67>",
                           "time": <unix>}}}). Without one, a public anchor's Bitcoin attestation is reported but never confirmed.
  --require-anchor        Fail (exit 4) unless a fully verified public anchor is available.
  --expected-origin <url> Expected origin of the record's verification URL (default https://coa.international;
                           use "none" to skip the check, e.g. for a local demo).
  --online <base-url>     Also ask THIS server for current standing/membership/key status. Only this URL is contacted;
                           https only (http allowed for localhost). Redirects are refused.
  --json                  Machine-readable report on stdout (report_version 1).

EXIT CODES
${Object.entries(EXIT_TEXT).map(([c, m]) => `  ${c.padStart(2)}  ${m}`).join("\n")}
  When several apply, the first of 1, 2, 6, 3, 4, 5 is returned. Exit 0 means only that every check you
  requested passed; it never means the laboratory result, purchase or membership is true.
`;

function readCapped(path: string, what: string, cwd: string): Uint8Array {
  const full = resolve(cwd, path);
  if (!existsSync(full)) throw new UsageError(`${what} not found: ${path}`);
  const st = statSync(full);
  if (!st.isFile()) throw new UsageError(`${what} is not a file: ${path}`);
  if (st.size > MAX_FILE_BYTES) throw new UsageError(`${what} is larger than ${MAX_FILE_BYTES / 1024 / 1024} MiB: ${path}`);
  return new Uint8Array(readFileSync(full));
}

function loadTrustStore(path: string | undefined, cwd: string): TrustEntry[] {
  if (!path) return [];
  const full = resolve(cwd, path);
  if (!existsSync(full)) throw new ConfigError(`trust store not found: ${path}`);
  try {
    return parseTrustStoreFile(new Uint8Array(readFileSync(full)));
  } catch (e) {
    if (e instanceof TrustStoreError) throw new ConfigError(`trust store ${path}: ${e.message}`);
    throw e;
  }
}

function loadHeaders(path: string, cwd: string): HeaderSource {
  const parsed = parseStrictJson(readCapped(path, "Bitcoin header file", cwd));
  const doc = parsed.ok && typeof parsed.value === "object" && parsed.value !== null && !Array.isArray(parsed.value) ? (parsed.value as { [k: string]: JsonValue }) : null;
  const headers = doc?.headers;
  if (!parsed.ok || typeof headers !== "object" || headers === null || Array.isArray(headers)) {
    throw new ConfigError(`${path}: expected {"headers": {"<height>": {"merkle_root": "<hex>", "time": <unix>}}}`);
  }
  const out: Record<string, { merkle_root: string; time: number }> = {};
  for (const [h, v] of Object.entries(headers)) {
    if (!/^[0-9]{1,9}$/.test(h) || typeof v !== "object" || v === null || Array.isArray(v) || typeof v.merkle_root !== "string" || !/^[0-9a-f]{64}$/.test(v.merkle_root) || typeof v.time !== "number") {
      throw new ConfigError(`${path}: header for height ${h} is malformed (merkle_root must be 64 lowercase hex characters, time a Unix time)`);
    }
    out[h] = { merkle_root: v.merkle_root, time: v.time };
  }
  return out;
}

function candidateFrom(bytes: Uint8Array): CandidateKey | undefined {
  const parsed = parseStrictJson(bytes);
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) return undefined;
  const v = parsed.value as { [k: string]: JsonValue };
  if (typeof v.key_id === "string" && typeof v.public_key === "string") return { key_id: v.key_id, public_key: v.public_key };
  return undefined;
}

async function cmdVerify(args: string[], io: Io): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      "trust-store": { type: "string" },
      bundle: { type: "string" },
      original: { type: "string" },
      document: { type: "string" },
      "anchor-proof": { type: "string" },
      "bitcoin-headers": { type: "string" },
      "require-anchor": { type: "boolean" },
      "expected-origin": { type: "string" },
      online: { type: "string" },
      json: { type: "boolean" },
    },
  });
  if (positionals.length > 1) throw new UsageError("verify takes at most one signed-record file");
  if (positionals.length === 0 && !values.bundle) throw new UsageError("give a signed-record.json file or --bundle <dir>");
  if (positionals.length === 1 && values.bundle) throw new UsageError("give either a signed-record.json file or --bundle, not both");

  const cwd = io.cwd;
  let recordPath = positionals[0];
  let originalPath = values.original;
  let documentPath = values.document;
  let anchorPath = values["anchor-proof"];
  let candidate: CandidateKey | undefined;
  if (values.bundle) {
    const dir = resolve(cwd, values.bundle);
    if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new UsageError(`bundle directory not found: ${values.bundle} (unzip the bundle first)`);
    const inBundle = (name: string): string | undefined => (existsSync(join(dir, name)) ? join(dir, name) : undefined);
    recordPath = inBundle("signed-record.json");
    if (!recordPath) throw new UsageError(`no signed-record.json in ${values.bundle}`);
    // Provider bundles use fixed names; customer packages carry the file's own SHA-256 in its name.
    const named = (exact: string, stem: string): string | undefined => {
      const plain = inBundle(exact);
      const pattern = new RegExp(`^${stem}-[0-9a-f]{64}\\.pdf$`);
      const hashed = readdirSync(dir).filter((f) => pattern.test(f));
      if (hashed.length + (plain ? 1 : 0) > 1) {
        throw new UsageError(`more than one ${stem} file in ${values.bundle}; keep one, or pass it explicitly`);
      }
      return plain ?? (hashed[0] ? join(dir, hashed[0]) : undefined);
    };
    originalPath ??= named("original-report.pdf", "original-report");
    documentPath ??= named("store-document.pdf", "signed-certificate");
    anchorPath ??= inBundle("anchor-proof.json");
    const keyFile = inBundle("public-key.json");
    if (keyFile) candidate = candidateFrom(readCapped(keyFile, "public-key.json", cwd));
  }

  const trustStore = loadTrustStore(values["trust-store"] ?? io.env.COA_VERIFY_TRUST_STORE, cwd);
  let expectedOrigin: string | null | undefined;
  if (values["expected-origin"] !== undefined) {
    if (values["expected-origin"].toLowerCase() === "none") expectedOrigin = null;
    else {
      try {
        const u = new URL(values["expected-origin"]);
        if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme");
        expectedOrigin = u.origin;
      } catch {
        throw new UsageError(`--expected-origin must be an absolute URL or "none": ${values["expected-origin"]}`);
      }
    }
  }
  if (values.online !== undefined) {
    try {
      normalizeBaseUrl(values.online);
    } catch (e) {
      throw new UsageError((e as Error).message);
    }
  }

  const inputs: Inputs = {
    envelope: readCapped(recordPath!, "signed record", cwd),
    trustStore,
    candidateKey: candidate,
    expectedVerificationOrigin: expectedOrigin,
    originalReport: originalPath ? readCapped(originalPath, "original report", cwd) : undefined,
    storeDocument: documentPath ? readCapped(documentPath, "store document", cwd) : undefined,
    anchorProof: anchorPath ? readCapped(anchorPath, "anchor proof", cwd) : undefined,
    requireAnchor: values["require-anchor"] === true,
    bitcoinHeaders: values["bitcoin-headers"] ? loadHeaders(values["bitcoin-headers"], cwd) : undefined,
  };

  const record = verifyRecord(inputs);

  let online: OnlineOutcome = { requested: false };
  if (values.online !== undefined) {
    if (!record.signature_valid || !record.payload) {
      online = { requested: true, ok: false, reason: "skipped", message: "skipped: the signed record did not verify, so there is nothing trustworthy to look up" };
    } else {
      const opts: OnlineFetchOptions = { baseUrl: values.online, fetchImpl: io.fetchImpl };
      try {
        const status = await fetchOnlineStatus(record.payload.verification_code as string, record.payload.issuance_id as string, opts, inputs.anchorProof === undefined);
        const anchor = status.proof && record.payload ? verifyAnchorProof(JSON.stringify(status.proof), record.payload, { headers: inputs.bitcoinHeaders }) : null;
        online = { requested: true, ok: true, status: { ...status, proof: null }, anchor_from_server: anchor };
      } catch (e) {
        if (e instanceof OnlineError) online = { requested: true, ok: false, reason: e.reason, message: e.message };
        else throw e;
      }
    }
  }

  const report = buildReport(inputs, record, online);
  io.stdout(values.json ? JSON.stringify(report, null, 2) + "\n" : formatHuman(report, VERSION));
  return report.exit_code;
}

function readTrustFileIfPresent(path: string, cwd: string): TrustEntry[] {
  return existsSync(resolve(cwd, path)) ? loadTrustStore(path, cwd) : [];
}

function cmdTrust(args: string[], io: Io): number {
  const sub = args[0];
  const { values } = parseArgs({
    args: args.slice(1),
    options: {
      store: { type: "string" },
      directory: { type: "string" },
      "key-id": { type: "string" },
      "key-file": { type: "string" },
      fingerprint: { type: "string" },
      "program-id": { type: "string" },
      environment: { type: "string" },
      "signer-id": { type: "string" },
    },
  });
  if (!values.store) throw new UsageError("--store <file> is required");
  if (sub === "list") {
    const entries = loadTrustStore(values.store, io.cwd);
    if (entries.length === 0) io.stdout("(trust store is empty)\n");
    for (const e of entries) {
      io.stdout(`${e.key_id}  program=${e.program_id} environment=${e.environment} signer=${e.signer_id} role=${e.role}${e.status ? ` status=${e.status}` : ""}\n  fingerprint ${fingerprintOf(e.public_key)}\n`);
    }
    return EXIT.OK;
  }
  if (sub !== "add") throw new UsageError(`unknown trust subcommand "${sub ?? ""}" (use add or list)`);
  if (!values.fingerprint) throw new UsageError("--fingerprint <sha256-hex> is required: pin the fingerprint you confirmed out of band");
  if (!values["program-id"] || !values.environment) {
    throw new UsageError("--program-id and --environment are required: state which program and environment this key is for (metadata shipped with a key is not trusted to say so)");
  }
  if (!["production", "demo", "development"].includes(values.environment)) throw new UsageError("--environment must be production, demo or development");
  const binding = { program_id: values["program-id"], environment: values.environment as Environment, ...(values["signer-id"] ? { signer_id: values["signer-id"] } : {}) };
  let entry: TrustEntry;
  try {
    if (values.directory) {
      if (!values["key-id"]) throw new UsageError("--key-id is required with --directory");
      const parsed = parseStrictJson(readCapped(values.directory, "key directory", io.cwd));
      if (!parsed.ok) throw new UsageError(`key directory is not valid strict JSON (${parsed.error_code})`);
      entry = entryFromDirectory(parsed.value, values["key-id"], values.fingerprint, binding);
    } else if (values["key-file"]) {
      const parsed = parseStrictJson(readCapped(values["key-file"], "key file", io.cwd));
      if (!parsed.ok) throw new UsageError(`key file is not valid strict JSON (${parsed.error_code})`);
      entry = entryFromKeyDocument(parsed.value, values.fingerprint, binding);
    } else {
      throw new UsageError("give --directory <file> --key-id <id>, or --key-file <public-key.json>");
    }
  } catch (e) {
    if (e instanceof TrustStoreError) throw new ConfigError(e.message);
    throw e;
  }
  const existing = readTrustFileIfPresent(values.store, io.cwd);
  const dupe = existing.find((x) => x.key_id === entry.key_id);
  if (dupe) {
    if (dupe.public_key === entry.public_key) {
      io.stdout(`${entry.key_id} is already in the trust store (fingerprint ${fingerprintOf(entry.public_key)}); nothing changed.\n`);
      return EXIT.OK;
    }
    throw new ConfigError(`the store already has a different key for key_id "${entry.key_id}"; remove it deliberately first`);
  }
  const full = resolve(io.cwd, values.store);
  const tmp = `${full}.${process.pid}.tmp`;
  writeFileSync(tmp, serializeTrustStore([...existing, entry]));
  renameSync(tmp, full);
  io.stdout(`Added ${entry.key_id} (program ${entry.program_id}, environment ${entry.environment}) to ${basename(full)}.\nFingerprint ${fingerprintOf(entry.public_key)} matched the value you pinned.\n`);
  return EXIT.OK;
}

export async function run(argv: string[], io: Io): Promise<number> {
  try {
    const [cmd, ...rest] = argv;
    if (cmd === undefined || cmd === "--help" || cmd === "-h" || cmd === "help") {
      io.stdout(HELP);
      return cmd === undefined ? EXIT.USAGE : EXIT.OK;
    }
    if (cmd === "--version" || cmd === "-v") {
      io.stdout(`${VERSION}\n`);
      return EXIT.OK;
    }
    if (cmd === "verify") return await cmdVerify(rest, io);
    if (cmd === "trust") return cmdTrust(rest, io);
    throw new UsageError(`unknown command "${safeText(cmd, 40)}"`);
  } catch (e) {
    if (e instanceof UsageError || (e instanceof TypeError && /Unknown option|argument/i.test(e.message)) || (e as { code?: string }).code?.startsWith("ERR_PARSE_ARGS")) {
      io.stderr(`error: ${safeText((e as Error).message)}\nRun "coa-verify --help" for usage.\n`);
      return EXIT.USAGE;
    }
    if (e instanceof ConfigError) {
      io.stderr(`configuration error: ${safeText(e.message)}\n`);
      return EXIT.CONFIG;
    }
    throw e;
  }
}
