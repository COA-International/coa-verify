// RFC 8785 (JSON Canonicalization Scheme) for the protocol's restricted value space:
// no floats, integers within +/-(2^53-1) (enforced by strict-json.ts), so number output is plain decimal.
import { utf8 } from "./bytes.js";
import type { JsonValue } from "./strict-json.js";

export function canonicalize(value: JsonValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value)) throw new RangeError("only safe integers are canonicalisable");
      return String(value === 0 ? 0 : value);
    case "string":
      return JSON.stringify(value); // JSON.stringify escaping is exactly RFC 8785 section 3.2.2.2
    default:
      break;
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  // Members sorted by the UTF-16 code units of their names, which is JavaScript's default string order.
  const names = Object.keys(value).sort();
  return "{" + names.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k]!)).join(",") + "}";
}

export function canonicalBytes(value: JsonValue): Uint8Array {
  return utf8(canonicalize(value));
}
