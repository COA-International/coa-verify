// RFC 9162 section 2.1 Merkle tree hashing and inclusion-proof verification, with the COA anchor
// leaf construction of docs/protocol/signed-record-v1.md section 6.
import { concatBytes, fromHex32, sha256, toHex, utf8 } from "./bytes.js";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);
const LEAF_DOMAIN = utf8("COA-INTL-ANCHOR-LEAF-v1\n");

/** leaf_hash = SHA-256(0x00 || "COA-INTL-ANCHOR-LEAF-v1\n" || raw32(document_sha256) || raw32(payload_sha256)). */
export function anchorLeafHash(documentSha256Hex: string, payloadSha256Hex: string): string {
  const doc = fromHex32(documentSha256Hex);
  const payload = fromHex32(payloadSha256Hex);
  if (!doc || !payload) throw new Error("leaf hashes must be 64 lowercase hex characters");
  return toHex(sha256(concatBytes(LEAF_PREFIX, LEAF_DOMAIN, doc, payload)));
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

/** Merkle tree hash (RFC 9162 section 2.1.1) over already-hashed leaves. */
export function merkleRoot(leafHashesHex: string[]): string {
  if (leafHashesHex.length === 0) throw new Error("empty tree");
  const leaves = leafHashesHex.map((h) => {
    const b = fromHex32(h);
    if (!b) throw new Error("bad leaf hash");
    return b;
  });
  const mth = (lo: number, hi: number): Uint8Array => {
    const n = hi - lo;
    if (n === 1) return leaves[lo]!;
    let k = 1;
    while (k * 2 < n) k *= 2; // largest power of two strictly less than n
    return nodeHash(mth(lo, lo + k), mth(lo + k, hi));
  };
  return toHex(mth(0, leaves.length));
}

/**
 * RFC 9162 section 2.1.3.2: does `path` prove that `leafHashHex` is the leaf at `leafIndex`
 * in a tree of `treeSize` leaves with root `rootHex`?
 */
export function verifyInclusion(
  leafHashHex: string,
  leafIndex: number,
  treeSize: number,
  path: string[],
  rootHex: string,
): boolean {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize) || leafIndex < 0 || treeSize < 1) return false;
  if (leafIndex >= treeSize) return false;
  let r = fromHex32(leafHashHex);
  const root = fromHex32(rootHex);
  if (!r || !root) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  for (const hex of path) {
    const p = fromHex32(hex);
    if (!p) return false;
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && toHex(r) === toHex(root);
}
