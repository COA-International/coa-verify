// OpenTimestamps detached proof (.ots) verification, protocol section 6.1. Written from the published file format
// (magic header, LEB128 varints, op tags, attestation tags); it never contacts a calendar or a block explorer.
//
// A proof over the batch root is `attested` only when a Bitcoin attestation's commitment equals the Merkle root of that
// block's header from a header source THE VERIFIER TRUSTS (its own node's data, a pinned header file, ...). Never from the proof,
// the anchor-proof JSON, or the record.
import { fromBase64Standard, fromHex32, sha256, toHex } from "./bytes.js";

export type OtsStatus = "attested" | "attested_unverified" | "pending" | "invalid";

export interface OtsResult {
  status: OtsStatus;
  /** Lowest verified (or, when unverified, lowest attested) Bitcoin block height. */
  block_height: number | null;
  /** Header time of the verified block, RFC 3339 UTC; only when `attested`. Accurate to roughly +/- 2 hours. */
  block_time: string | null;
  reason: string | null;
  /** Bitcoin attestations found: height and whether a trusted header confirmed it. */
  attestations: Array<{ height: number; verified: boolean | null }>;
  pending_calendars: number;
}

/**
 * A trusted source of Bitcoin block headers. `merkle_root` is the hex of header bytes 36-67 in INTERNAL byte order, exactly as the
 * proof's commitment appears (protocol 6.1); note that block explorers display this value byte-reversed. `time` is the header
 * time (bytes 68-71) in Unix seconds.
 */
export type HeaderSource = Record<string, { merkle_root: string; time: number }> | ((height: number) => { merkle_root: string; time: number } | null);

const MAGIC = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00,
  0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
const ATT_BITCOIN = "0588960d73d71901";
const ATT_PENDING = "83dfe30d2ef90c8e";
const MAX_DEPTH = 256;
const MAX_NODES = 50_000;
const MAX_VARBYTES = 8192;
/** Protocol 6.1: no intermediate message may exceed this many bytes (checked before it is built). */
const MAX_MESSAGE = 4096;

class Bad extends Error {}

function boundMessage(length: number): void {
  if (length > MAX_MESSAGE) throw new Bad(`an intermediate message would exceed ${MAX_MESSAGE} bytes`);
}

class Reader {
  pos = 0;
  constructor(readonly b: Uint8Array) {}
  u8(): number {
    if (this.pos >= this.b.length) throw new Bad("truncated proof");
    return this.b[this.pos++]!;
  }
  bytes(n: number): Uint8Array {
    if (n < 0 || this.pos + n > this.b.length) throw new Bad("truncated proof");
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = this.u8();
      value += (byte & 0x7f) * 2 ** shift;
      if (value > Number.MAX_SAFE_INTEGER) throw new Bad("varint out of range");
      if ((byte & 0x80) === 0) return value;
      shift += 7;
      if (shift > 49) throw new Bad("varint too long");
    }
  }
  varbytes(max = MAX_VARBYTES): Uint8Array {
    const n = this.varuint();
    if (n > max) throw new Bad("field too long");
    return this.bytes(n);
  }
}

function concat(...p: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of p) {
    out.set(x, o);
    o += x.length;
  }
  return out;
}

interface Walk {
  bitcoin: Array<{ height: number; commitment: Uint8Array }>;
  pending: number;
  unsupported: number;
  nodes: number;
}

function walk(r: Reader, msg: Uint8Array, depth: number, w: Walk): void {
  if (depth > MAX_DEPTH) throw new Bad("proof nested too deeply");
  for (;;) {
    let tag = r.u8();
    const more = tag === 0xff;
    if (more) tag = r.u8();
    if (++w.nodes > MAX_NODES) throw new Bad("proof too large");
    if (tag === 0x00) {
      const att = toHex(r.bytes(8));
      const payload = new Reader(r.varbytes());
      if (att === ATT_BITCOIN) {
        const height = payload.varuint();
        if (payload.pos !== payload.b.length) throw new Bad("Bitcoin attestation payload has trailing bytes");
        w.bitcoin.push({ height, commitment: msg });
      } else if (att === ATT_PENDING) {
        payload.varbytes(1000); // calendar URI: read for well-formedness only, never contacted
        w.pending++;
      } else {
        w.unsupported++; // some other chain's attestation: not something this verifier confirms
      }
    } else {
      let next: Uint8Array | null;
      switch (tag) {
        case 0x08:
          next = sha256(msg);
          break;
        case 0xf0: {
          const arg = r.varbytes();
          boundMessage(msg.length + arg.length);
          next = concat(msg, arg);
          break;
        }
        case 0xf1: {
          const arg = r.varbytes();
          boundMessage(arg.length + msg.length);
          next = concat(arg, msg);
          break;
        }
        case 0xf3:
          boundMessage(msg.length * 2);
          next = new TextEncoder().encode(toHex(msg));
          break;
        case 0xf2:
          next = Uint8Array.from(msg).reverse();
          break;
        case 0x02:
        case 0x03:
        case 0x67:
          next = null; // sha1 / ripemd160 / keccak: not needed for Bitcoin proofs
          break;
        default:
          throw new Bad(`unknown operation 0x${tag.toString(16)}`);
      }
      if (next === null) {
        w.unsupported++;
        skipSubtree(r, depth + 1, w);
      } else {
        walk(r, next, depth + 1, w);
      }
    }
    if (!more) return;
  }
}

/** Consume a subtree we cannot evaluate, counting nothing verifiable from it. */
function skipSubtree(r: Reader, depth: number, w: Walk): void {
  if (depth > MAX_DEPTH) throw new Bad("proof nested too deeply");
  for (;;) {
    let tag = r.u8();
    const more = tag === 0xff;
    if (more) tag = r.u8();
    if (++w.nodes > MAX_NODES) throw new Bad("proof too large");
    if (tag === 0x00) {
      r.bytes(8);
      r.varbytes();
    } else if (tag === 0xf0 || tag === 0xf1) {
      r.varbytes();
      skipSubtree(r, depth + 1, w);
    } else if ([0x08, 0xf2, 0xf3, 0x02, 0x03, 0x67].includes(tag)) {
      skipSubtree(r, depth + 1, w);
    } else {
      throw new Bad(`unknown operation 0x${tag.toString(16)}`);
    }
    if (!more) return;
  }
}

function lookup(headers: HeaderSource | undefined, height: number): { merkle_root: string; time: number } | null {
  if (!headers) return null;
  const h = typeof headers === "function" ? headers(height) : headers[String(height)];
  return h ?? null;
}

const invalid = (reason: string): OtsResult => ({ status: "invalid", block_height: null, block_time: null, reason, attestations: [], pending_calendars: 0 });

export function verifyOtsProof(proofBase64: string, rootHex: string, headers?: HeaderSource): OtsResult {
  const root = fromHex32(rootHex);
  const bytes = fromBase64Standard(proofBase64);
  if (!root) return invalid("root is not 64 lowercase hex characters");
  if (!bytes) return invalid("ots_proof_base64 is not valid base64");
  const r = new Reader(bytes);
  const w: Walk = { bitcoin: [], pending: 0, unsupported: 0, nodes: 0 };
  try {
    const magic = r.bytes(MAGIC.length);
    if (!magic.every((b, i) => b === MAGIC[i])) throw new Bad("not an OpenTimestamps proof");
    if (r.varuint() !== 1) throw new Bad("unsupported OpenTimestamps version");
    if (r.u8() !== 0x08) throw new Bad("proof is not over a SHA-256 digest");
    const digest = r.bytes(32);
    if (toHex(digest) !== toHex(root)) throw new Bad("the proof commits to a different digest than the batch root");
    walk(r, digest, 0, w);
    if (r.pos !== bytes.length) throw new Bad("trailing data after the proof");
  } catch (e) {
    if (e instanceof Bad) return invalid(e.message);
    throw e;
  }

  const attestations: OtsResult["attestations"] = [];
  let bestVerified: { height: number; time: number } | null = null;
  let anyChecked = false;
  let anyMismatch = false;
  for (const a of w.bitcoin) {
    const header = lookup(headers, a.height);
    if (!header) {
      attestations.push({ height: a.height, verified: null });
      continue;
    }
    anyChecked = true;
    const ok = /^[0-9a-f]{64}$/.test(header.merkle_root) && header.merkle_root === toHex(a.commitment);
    attestations.push({ height: a.height, verified: ok });
    if (ok) {
      if (!bestVerified || a.height < bestVerified.height) bestVerified = { height: a.height, time: header.time };
    } else {
      anyMismatch = true;
    }
  }
  const base = { attestations, pending_calendars: w.pending };
  if (bestVerified) {
    return {
      ...base, status: "attested", block_height: bestVerified.height, reason: null,
      block_time: new Date(bestVerified.time * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
    };
  }
  if (anyChecked && anyMismatch) {
    return { ...base, status: "invalid", block_height: null, block_time: null, reason: "the attested commitment does not match the trusted block header's Merkle root" };
  }
  if (w.bitcoin.length > 0) {
    const lowest = Math.min(...w.bitcoin.map((a) => a.height));
    return { ...base, status: "attested_unverified", block_height: lowest, block_time: null, reason: "a Bitcoin attestation is present but no trusted block-header source covers it" };
  }
  if (w.pending > 0) return { ...base, status: "pending", block_height: null, block_time: null, reason: "only pending calendar attestations: not yet anchored in a block" };
  return invalid(w.unsupported > 0 ? "the proof has no Bitcoin or pending attestation this verifier understands" : "the proof contains no attestation");
}
