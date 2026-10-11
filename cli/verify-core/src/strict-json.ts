// Strict JSON parsing per docs/protocol/signed-record-v1.md sections 2.1 and 3.
// Not JSON.parse: duplicate names, fractions/exponents, huge integers, unpaired surrogate escapes and
// the section 2.1 string rules must be rejected with specific error codes.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export type ParseErrorCode =
  | "invalid_utf8"
  | "bom_not_allowed"
  | "too_large"
  | "too_deep"
  | "duplicate_key"
  | "float_not_allowed"
  | "integer_out_of_range"
  | "invalid_unicode"
  | "forbidden_character"
  | "edge_whitespace"
  | "not_nfc"
  | "invalid_json";

export type ParseResult = { ok: true; value: JsonValue } | { ok: false; error_code: ParseErrorCode; detail?: string };

export const MAX_DOCUMENT_BYTES = 1024 * 1024;
export const MAX_DEPTH = 32;
const MAX_SAFE = 9007199254740991n;

// Section 2.1: Cc, the frozen Unicode 15.1 Cf list, Zl, Zp, surrogates.
const FORBIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x0600, 0x0605], [0x061c, 0x061c],
  [0x06dd, 0x06dd], [0x070f, 0x070f], [0x0890, 0x0891], [0x08e2, 0x08e2], [0x180e, 0x180e],
  [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2064], [0x2066, 0x206f], [0xd800, 0xdfff],
  [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0x110bd, 0x110bd], [0x110cd, 0x110cd], [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0001, 0xe0001], [0xe0020, 0xe007f],
];

const EDGE_WHITESPACE: ReadonlyArray<readonly [number, number]> = [
  [0x0020, 0x0020], [0x00a0, 0x00a0], [0x1680, 0x1680], [0x2000, 0x200a], [0x202f, 0x202f],
  [0x205f, 0x205f], [0x3000, 0x3000],
];

function inRanges(cp: number, ranges: ReadonlyArray<readonly [number, number]>): boolean {
  for (const [lo, hi] of ranges) if (cp >= lo && cp <= hi) return true;
  return false;
}

/** Applies the section 2.1 string rules; returns an error code or null. Surrogates are the caller's concern. */
export function checkStringRules(s: string): ParseErrorCode | null {
  for (const ch of s) {
    if (inRanges(ch.codePointAt(0)!, FORBIDDEN_RANGES)) return "forbidden_character";
  }
  if (s.length > 0) {
    // Every edge-whitespace character is in the BMP, so comparing UTF-16 units at both ends is exact.
    const first = s.charCodeAt(0);
    const last = s.charCodeAt(s.length - 1);
    if (inRanges(first, EDGE_WHITESPACE) || inRanges(last, EDGE_WHITESPACE)) return "edge_whitespace";
  }
  if (s.normalize("NFC") !== s) return "not_nfc";
  return null;
}

class Failure extends Error {
  constructor(
    public code: ParseErrorCode,
    public detail?: string,
  ) {
    super(code);
  }
}

class Parser {
  private i = 0;
  constructor(private readonly text: string) {}

  parseDocument(): JsonValue {
    this.skipWs();
    const value = this.parseValue(0);
    this.skipWs();
    if (this.i !== this.text.length) throw new Failure("invalid_json", "trailing data");
    return value;
  }

  private skipWs(): void {
    while (this.i < this.text.length) {
      const c = this.text.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  private parseValue(depth: number): JsonValue {
    const c = this.text[this.i];
    if (c === "{") return this.parseObject(depth + 1);
    if (c === "[") return this.parseArray(depth + 1);
    if (c === '"') return this.parseString();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.parseNumber();
    if (this.text.startsWith("true", this.i)) {
      this.i += 4;
      return true;
    }
    if (this.text.startsWith("false", this.i)) {
      this.i += 5;
      return false;
    }
    if (this.text.startsWith("null", this.i)) {
      this.i += 4;
      return null;
    }
    if (this.text.startsWith("NaN", this.i) || this.text.startsWith("Infinity", this.i)) {
      throw new Failure("float_not_allowed", "non-finite number");
    }
    throw new Failure("invalid_json", `unexpected character at offset ${this.i}`);
  }

  private parseObject(depth: number): JsonValue {
    if (depth > MAX_DEPTH) throw new Failure("too_deep");
    this.i++; // {
    const obj: { [key: string]: JsonValue } = Object.create(null);
    this.skipWs();
    if (this.text[this.i] === "}") {
      this.i++;
      return obj;
    }
    for (;;) {
      this.skipWs();
      if (this.text[this.i] !== '"') throw new Failure("invalid_json", "expected member name");
      const name = this.parseString();
      if (Object.prototype.hasOwnProperty.call(obj, name)) throw new Failure("duplicate_key", name);
      this.skipWs();
      if (this.text[this.i] !== ":") throw new Failure("invalid_json", "expected ':'");
      this.i++;
      this.skipWs();
      obj[name] = this.parseValue(depth);
      this.skipWs();
      const sep = this.text[this.i++];
      if (sep === "}") return obj;
      if (sep !== ",") throw new Failure("invalid_json", "expected ',' or '}'");
    }
  }

  private parseArray(depth: number): JsonValue {
    if (depth > MAX_DEPTH) throw new Failure("too_deep");
    this.i++; // [
    const arr: JsonValue[] = [];
    this.skipWs();
    if (this.text[this.i] === "]") {
      this.i++;
      return arr;
    }
    for (;;) {
      this.skipWs();
      arr.push(this.parseValue(depth));
      this.skipWs();
      const sep = this.text[this.i++];
      if (sep === "]") return arr;
      if (sep !== ",") throw new Failure("invalid_json", "expected ',' or ']'");
    }
  }

  private parseNumber(): JsonValue {
    const m = /^-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.text.slice(this.i, this.i + 400));
    if (!m) throw new Failure("invalid_json", "malformed number");
    if (m[1] !== undefined || m[2] !== undefined) throw new Failure("float_not_allowed", m[0]);
    const next = this.text[this.i + m[0].length];
    if (next !== undefined && /[0-9.eE+-]/.test(next)) throw new Failure("invalid_json", "malformed number");
    const magnitude = BigInt(m[0].startsWith("-") ? m[0].slice(1) : m[0]);
    if (magnitude > MAX_SAFE) throw new Failure("integer_out_of_range", m[0]);
    this.i += m[0].length;
    const n = Number(m[0]);
    return n === 0 ? 0 : n; // normalise -0
  }

  private parseString(): string {
    this.i++; // opening quote
    let out = "";
    for (;;) {
      if (this.i >= this.text.length) throw new Failure("invalid_json", "unterminated string");
      const ch = this.text[this.i]!;
      const code = ch.charCodeAt(0);
      if (ch === '"') {
        this.i++;
        break;
      }
      if (code < 0x20) throw new Failure("invalid_json", "raw control character in string");
      if (ch === "\\") {
        const esc = this.text[this.i + 1];
        this.i += 2;
        switch (esc) {
          case '"': out += '"'; break;
          case "\\": out += "\\"; break;
          case "/": out += "/"; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const unit = this.readHex4();
            if (unit >= 0xd800 && unit <= 0xdbff) {
              if (this.text[this.i] === "\\" && this.text[this.i + 1] === "u") {
                this.i += 2;
                const low = this.readHex4();
                if (low < 0xdc00 || low > 0xdfff) throw new Failure("invalid_unicode", "unpaired high surrogate");
                out += String.fromCharCode(unit, low);
              } else {
                throw new Failure("invalid_unicode", "unpaired high surrogate");
              }
            } else if (unit >= 0xdc00 && unit <= 0xdfff) {
              throw new Failure("invalid_unicode", "unpaired low surrogate");
            } else {
              out += String.fromCharCode(unit);
            }
            break;
          }
          default:
            throw new Failure("invalid_json", "invalid escape");
        }
        continue;
      }
      // Literal characters: a lone surrogate can only come from a JS-string input, never from valid UTF-8.
      if (code >= 0xd800 && code <= 0xdbff) {
        const low = this.text.charCodeAt(this.i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          out += ch + this.text[this.i + 1];
          this.i += 2;
          continue;
        }
        throw new Failure("invalid_unicode", "unpaired surrogate");
      }
      if (code >= 0xdc00 && code <= 0xdfff) throw new Failure("invalid_unicode", "unpaired surrogate");
      out += ch;
      this.i++;
    }
    const rule = checkStringRules(out);
    if (rule) throw new Failure(rule);
    return out;
  }

  private readHex4(): number {
    const hex = this.text.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Failure("invalid_json", "bad \\u escape");
    this.i += 4;
    return parseInt(hex, 16);
  }
}

export function parseStrictJson(input: Uint8Array | string): ParseResult {
  let text: string;
  if (typeof input === "string") {
    if (input.length > MAX_DOCUMENT_BYTES) return { ok: false, error_code: "too_large" };
    text = input;
  } else {
    if (input.length > MAX_DOCUMENT_BYTES) return { ok: false, error_code: "too_large" };
    if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
      return { ok: false, error_code: "bom_not_allowed" };
    }
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      return { ok: false, error_code: "invalid_utf8" };
    }
  }
  if (text.charCodeAt(0) === 0xfeff) return { ok: false, error_code: "bom_not_allowed" };
  try {
    return { ok: true, value: new Parser(text).parseDocument() };
  } catch (e) {
    if (e instanceof Failure) return { ok: false, error_code: e.code, detail: e.detail };
    if (e instanceof RangeError) return { ok: false, error_code: "too_deep" }; // engine stack guard
    throw e;
  }
}
