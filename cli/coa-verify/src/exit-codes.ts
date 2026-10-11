// Documented exit codes (docs/manual, `coa-verify --help`). When several problems apply the FIRST matching
// code in this priority order is returned: 1, 2, 6, 3, 4, 5. Usage/configuration errors (64/65) win over all.
export const EXIT = {
  /** Record valid, issuer trusted, every supplied file matches, no trust warnings. */
  OK: 0,
  /** Record could not be verified: parse/structure error, unsupported version, or invalid/unresolvable signature. */
  RECORD_INVALID: 1,
  /** Signature valid, but issuer not trusted (no/insufficient trust entry) or a trust warning applies. */
  NOT_TRUSTED: 2,
  /** A supplied file's SHA-256 does not match the signed record. (A mismatch is not proof of fraud.) */
  FILE_MISMATCH: 3,
  /** A supplied anchor proof is malformed or does not include this record; or --require-anchor was not satisfied. */
  ANCHOR_PROBLEM: 4,
  /** --online was requested but the configured server was unreachable, refused, or returned inconsistent data. */
  ONLINE_PROBLEM: 5,
  /** Online status shows standing other than "issued" (disputed, superseded, revoked). */
  STANDING_NOT_ISSUED: 6,
  /** Bad command line. */
  USAGE: 64,
  /** Trust store or other configuration file invalid / unreadable. */
  CONFIG: 65,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

export const EXIT_TEXT: Record<number, string> = {
  0: "every requested check passed",
  1: "record invalid or signature not verifiable",
  2: "signature valid but issuer not trusted, or a trust warning applies",
  3: "a supplied file does not match the signed record",
  4: "anchor proof invalid, or anchor requirement not met",
  5: "online status check failed or was inconsistent",
  6: "online status shows the record is not in standing \"issued\"",
  64: "usage error",
  65: "configuration error",
};
