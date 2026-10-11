# coa-verify: independent verifier for COA signed records

`cli/verify-core` (library, also used by the public site's browser file check) and `cli/coa-verify`
(command line) implement the signed-record protocol from `docs/protocol/signed-record-v1.md` and
`schemas/`. They are built **only** from the published protocol document, JSON Schemas and
`fixtures/vectors/v1/`. They never import or copy `service/` code (ADR 0008). Cryptography comes from
`@noble/curves` (Ed25519) and `@noble/hashes` (SHA-256).

```sh
cd cli
npm install
npm run build          # tsc for both packages
npm test               # vectors + strict-parser + CLI tests (needs fixtures/vectors/v1)
node coa-verify/dist/main.js --help
```

Requires Node 22 or newer.

## Trust model (read this first)

A valid signature proves the record is consistent with a key. It does not prove who holds the key. The tool
therefore never trusts a key because it arrived with the record:

* **Trust store**: a file you build *out of band*, listing keys as tuples
  `(key_id, public_key, program_id, role=tenant_signer, environment, signer_id)`. `issuer_trusted` is true
  only when the signature verifies with the trust-store key **and** the payload's `program_id`, `environment`
  and `signer.id` equal the entry. A record for tenant A signed with tenant B's key is never trusted, even
  when both keys are in the store.
* **Shipped key** (a bundle's `public-key.json`, or a downloaded key directory): a *candidate*. It can only
  produce `signature_valid`, never `issuer_trusted`.
* **Building a trust store**: pin a fingerprint you obtained from a source you trust (for example from
  COA International directly), then let the tool copy the rest of the entry from the key document:

  ```sh
  coa-verify trust add --store trust.json --key-file bundle/public-key.json --fingerprint <sha256-hex> --program-id demo-program --environment demo
  coa-verify trust add --store trust.json --directory key-directory.json --key-id demo-program-k2 --fingerprint <sha256-hex> --program-id demo-program --environment demo
  coa-verify trust list --store trust.json
  ```

  **You** state the program and environment (and optionally `--signer-id`, default `coa-international`): the key document arrived with the
  record, so its own metadata is not trusted to say which tenant the key belongs to. The metadata is only cross-checked, and a
  disagreement is refused. The command also refuses when the key's actual fingerprint differs from the one you pinned. A trust store
  containing two entries for one `key_id` is rejected as a configuration error (exit 65).
* A trust entry may carry `"status": "compromised"` (and `compromise_suspected_from`). Records signed by such a
  key still show the mathematical result, but get a trust warning (exit 2). A record's own issue date can
  never clear it, because an attacker holding a stolen key can backdate.

## Verify

```sh
coa-verify verify signed-record.json --trust-store trust.json \
    --original original-report.pdf --document store-document.pdf [--anchor-proof anchor-proof.json]
coa-verify verify --bundle ./unzipped-bundle --trust-store trust.json   # reads every file it finds
```

Offline (the default) states plainly that current record standing, membership and key-compromise notices
are **unknown (offline)**. `--online <base-url>` additionally asks that one server (https, or http only for
localhost; redirects refused; 1 MiB and 10 s caps) for current standing, membership, key status and the anchor
proof. The code and issuance id come from the *verified* payload; nothing else in a record, bundle or server
response is ever fetched. Server text is escaped before printing.

Other options: `--expected-origin <url|none>` (verification URL origin check, default
`https://coa.international`), `--require-anchor`, `--json`, env `COA_VERIFY_TRUST_STORE`.

### What each check means

| Result | Meaning |
|---|---|
| `parse_ok` | strict parse: valid UTF-8, no BOM, no duplicate members, no floats, safe integers only, section 2.1 string rules, size and depth limits |
| `structure_valid` | shape, value patterns, calendar dates, `issuer.id == program_id`, URL ends with the code, signature encoding is canonical base64url |
| `signature_valid` | Ed25519 verification with the resolved key over `"COA-INTL-ISSUANCE-v1\n" + RFC 8785(payload)` |
| `issuer_trusted` | trust rule above |
| file `status` | `match` / `mismatch` only when the signature verified; otherwise `unverified`. A mismatch names which document the bytes actually equal, if any. It is **not** proof of fraud |
| anchor | the leaf is recomputed from the verified payload and the RFC 9162 path recomputed to the root; the proof's own `leaf`, `root`, `public` and `status` members are not trusted |

`local-test` anchors are labelled **not public** and carry no timing evidence. For `opentimestamps-bitcoin` proofs the tool also
parses the `.ots` proof (protocol section 6.1) and checks that it commits to the batch root. It reports one of `attested`,
`attested_unverified`, `pending` or `invalid`:

* `attested` needs a **Bitcoin header source you trust**: `--bitcoin-headers headers.json`
  (`{"headers": {"<height>": {"merkle_root": "<hex of header bytes 36-67, internal byte order>", "time": <unix>}}}`; note explorers display that
  root byte-reversed). The attested time is the header time, accurate to about +/- 2 hours. Headers are never taken from the proof or the record.
* `attested_unverified`: a Bitcoin attestation is present but no header source was given, so the anchor time is **not** established.
* `pending`: only pending calendar attestations. `invalid`: a digest mismatch, malformed proof, or header mismatch (exit 4).

The tool never contacts an OpenTimestamps calendar or a block explorer. `--require-anchor` passes only for `attested`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | every requested check passed (never: "the lab result, purchase or membership is true") |
| 1 | record invalid: parse/structure error, unsupported version, signature invalid or no key available |
| 2 | signature valid but issuer not trusted, or a trust warning applies (compromised key, unexpected verification origin, key differs from the trust store) |
| 3 | a supplied file does not match the signed hash |
| 4 | anchor proof malformed / does not include the record, or `--require-anchor` not met |
| 5 | `--online` requested but the server was unreachable, redirected, returned non-JSON, or described a different record |
| 6 | `--online` shows standing other than `issued` (disputed, superseded, revoked) |
| 64 | usage error |
| 65 | configuration error (trust store invalid, fingerprint mismatch when pinning) |

When several apply, the first of 1, 2, 6, 3, 4, 5 is returned.

## `--json` report (`report_version` "1")

`record` (all `verifyEnvelope` fields: `parse_ok`, `error_code`, `schema_version_supported`, `structure_valid`,
`signature_valid`, `issuer_trusted`, `key_source`, `key_id`, `key_fingerprint`, `environment`,
`verification_origin`, `warnings[]`, `structure_issues[]`), `summary` (the signed facts, only when the
structure is valid), `files.original_report` / `files.store_document` (`status`, `matches`, `sha256`,
`byte_length`, `message`), `anchor` (or null), `current_status` (`standing`, `membership`, `key_compromise`,
`source`: `unknown_offline` or `online`), `exit_code`, `exit_reason`, `problems[]`.

## Layout

* `verify-core/src`: `strict-json.ts` (parser), `jcs.ts` (RFC 8785), `structure.ts` (schema + semantic checks),
  `verify.ts` (envelope, trust, file checks), `merkle.ts` and `anchor.ts` (RFC 9162 and anchor proofs),
  `trust.ts` (trust store, pinning). Runs unchanged in browsers (no Node APIs).
* `coa-verify/src`: `cli.ts` (commands), `report.ts` (report and exit code), `format.ts` (plain-language output),
  `online.ts` (bounded fetch), `sanitize.ts` (terminal-safe text).
* Tests: every case of `fixtures/vectors/v1/vectors.json`, plus parser edge cases, Ajv cross-check of the
  hand-written structure rules against the published schemas, trust rules, and CLI behaviour with a mocked server.
