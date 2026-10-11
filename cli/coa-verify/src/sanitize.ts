// Untrusted text (server responses, file names, JSON member values) must never be able to drive the
// terminal: escape control characters, bidi controls, and other invisible formatting characters.
// Ranges are numeric on purpose (no escape sequences in this source; some editors/tools decode them).
const UNSAFE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x0600, 0x0605], [0x061c, 0x061c], [0x06dd, 0x06dd],
  [0x070f, 0x070f], [0x0890, 0x0891], [0x08e2, 0x08e2], [0x180e, 0x180e], [0x200b, 0x200f], [0x2028, 0x202e],
  [0x2060, 0x2064], [0x2066, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb],
];

function unsafe(cp: number): boolean {
  return UNSAFE_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi);
}

export function safeText(value: unknown, maxLength = 400): string {
  let s = typeof value === "string" ? value : JSON.stringify(value);
  if (s === undefined) s = "";
  if (s.length > maxLength) s = s.slice(0, maxLength) + "...";
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    out += unsafe(cp) ? "\\u" + cp.toString(16).padStart(4, "0") : ch;
  }
  return out;
}
