# COA signed-record protocol v1 (payload schema_version 2.0)

Status: **frozen for release 1** (M0, revised after checkpoint-1 design review —
`docs/reviews/checkpoint-1-design.md`). Normative. Changes require an ADR and a
`docs/HANDOFF.md` announcement. Machine-readable parts: `schemas/signed-record/v2.0/`,
`schemas/anchor-proof/v1/`, `schemas/key-directory/v1/`. Test vectors:
`fixtures/vectors/v1/` (regenerate with `python -m coa_service.tools.generate_vectors`).
Reference implementation: `service/src/coa_service/protocol/`.

The key words MUST, MUST NOT, SHOULD are used as in RFC 2119.

## 1. Objects

| Object | File name in bundle | Schema |
|---|---|---|
| Envelope (signed record) | `signed-record.json` | `signed-record/v2.0/envelope.schema.json` |
| Payload | inside the envelope | `signed-record/v2.0/payload.schema.json` |
| Anchor proof | `anchor-proof.json` (published after anchoring) | `anchor-proof/v1/anchor-proof.schema.json` |
| Key directory | `GET /api/v1/public/keys` | `key-directory/v1/key-directory.schema.json` |

The payload is immutable. Current membership, record standing (disputed / superseded /
revoked), file locations, and anchor data are **never** part of it; they are separate,
dated, out-of-band facts.

## 2. Payload rules

- `additionalProperties: false` everywhere: unknown members make a payload invalid.
- Identifiers: 1–128 printable ASCII characters (`!`–`~`). COA International–assigned ids
  (`program_id`, `key_id`) are further restricted to `[a-z0-9-]`. Program operators SHOULD
  use opaque (non-sequential) ids for reports, purchase events, stores and batches, because
  every signed id is public forever.
- Display text: 1–300 **code points** (not UTF-16 units), §2.1 string rules.
- Timestamps: RFC 3339 UTC at **whole-second precision** with literal `Z`. Dates: `YYYY-MM-DD`.
  Both MUST be real calendar values (`2026-02-31` is invalid). `report.report_date`,
  `purchase_event.purchase_date` and `batch.expiry_date` are distinct facts; optional ones are
  present only if supplied, never invented.
- Hashes: lowercase 64-hex SHA-256 of the exact file bytes. Integers only, within ±(2^53−1).
- `environment`: `production`, `demo`, or `development`. Verifiers MUST display a prominent
  non-production warning for anything but `production`.
- `issuer` is the program operator (`role: program_operator`) and `issuer.id` MUST equal
  `program_id`. `signer` is COA International (`role: independent_verifier`), signing with its
  per-tenant `tenant_signer` key named by `key_id`.
- `verification_url` MUST end with `/v/` + `verification_code`. Verifiers configured with an
  expected verification origin (default `https://coa.international`) MUST also check the origin.
- `supersedes` appears only on a correction and names the replaced issuance.
- The purchase event carries no quantity (sales volume is not published).
- `verification_code`: 28 Crockford base32 characters (alphabet
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 140 random bits), displayed as seven groups of four
  separated by `-`. Lookup accepts ASCII input only and normalizes case, spaces and hyphens
  only; it MUST NOT map `O→0` or `I/L→1` or otherwise guess.

### 2.1 String rules (every string and member name in any protocol document)

A string MUST NOT contain any code point in these ranges (Cc, the Unicode 15.1 Cf list —
frozen here so all verifiers agree regardless of their Unicode database — Zl, Zp, and
surrogates):

```
U+0000–001F  U+007F–009F  U+00AD  U+0600–0605  U+061C  U+06DD  U+070F  U+0890–0891  U+08E2
U+180E  U+200B–200F  U+2028–202E  U+2060–2064  U+2066–206F  U+D800–DFFF  U+FEFF  U+FFF9–FFFB
U+110BD  U+110CD  U+13430–1343F  U+1BCA0–1BCA3  U+1D173–1D17A  U+E0001  U+E0020–E007F
```

A string MUST NOT begin or end with U+0020, U+00A0, U+1680, U+2000–200A, U+202F, U+205F, or
U+3000, and MUST be in Unicode NFC. (The JSON Schema `display_text` pattern encodes the BMP
part of these rules; the list above is normative.)

### 2.2 Semantic checks (beyond JSON Schema)

Real calendar dates/timestamps; `issuer.id == program_id`; `verification_url` suffix matches
`verification_code`. Failing any of these makes `structure_valid` false.

## 3. JSON parsing and canonicalization

Verifiers MUST parse strictly and reject (`parse_ok = false`, with the error code shown):
invalid UTF-8 (`invalid_utf8`), a leading BOM (`bom_not_allowed`), documents over 1 MiB
(`too_large`) or nested deeper than 32 (`too_deep`), duplicate member names at any depth
(`duplicate_key`), any number with a fraction or exponent and `NaN`/`Infinity`
(`float_not_allowed`), integers outside ±(2^53−1) (`integer_out_of_range`), an escape that
yields an unpaired surrogate (`invalid_unicode`), §2.1 violations (`forbidden_character`,
`edge_whitespace`, `not_nfc`), and anything else malformed (`invalid_json`).

Canonical bytes are RFC 8785 (JCS) applied to the parsed payload, encoded as UTF-8.

## 4. Signature

```
signing_input = UTF8("COA-INTL-ISSUANCE-v1\n") || JCS(payload)     ; "\n" is the single byte 0x0A
signature     = Ed25519(tenant_signer_private_key, signing_input) ; RFC 8032, pure Ed25519
envelope      = {"payload": payload, "signature": base64url_nopad(signature)}
```

- `signature` MUST match `^[A-Za-z0-9_-]{85}[AQgw]$` (86 chars, no padding, zero unused
  bits). Anything else — padding, non-canonical trailing bits, wrong length — sets
  `structure_valid = false` (not merely `signature_valid = false`). JavaScript verifiers MUST
  NOT rely on lenient decoders such as `Buffer.from(s, "base64url")` without this check.
- `signed-record.json` as issued is `JCS(envelope)` followed by one `0x0A`. Verifiers MUST NOT
  depend on this serialization: reordered or re-indented envelopes verify identically.
- `payload_sha256` (used by anchoring) = SHA-256(JCS(payload)), without the domain prefix.
- COA International's signing providers refuse to sign any input not starting with the domain prefix.

## 5. Keys and trust

- Public keys are raw 32-byte Ed25519 keys, base64url without padding (43 chars).
  Fingerprint = lowercase hex SHA-256 of the raw 32 bytes.
- The key directory is scoped by `program_id` and `role` (`tenant_signer` populated;
  `laboratory` reserved and empty in release 1). Retired and compromised keys are kept forever.
- **Trust store.** A trust entry is the tuple
  `(key_id, public_key, program_id, role = tenant_signer, environment, signer_id)`, obtained out
  of band (CLI trust-store file, `--trust` pin, or verifier configuration). A verifier resolves
  the key **by the payload's `key_id` in its trust store**; a key that arrives with the PDF, the
  bundle, or a directory fetched at verification time is at most a *candidate* key and can only
  ever yield `signature_valid`, never `issuer_trusted`. A trust store with two entries for the
  same `key_id` is invalid and MUST be rejected as a configuration error.
- `issuer_trusted` is true only if the signature verifies with the trust entry's key **and**
  `payload.program_id`, `payload.environment` and `payload.signer.id` equal the entry's values
  and the entry's role is `tenant_signer`. A record for tenant A signed with tenant B's key is
  therefore never trusted, even when both keys are in the store (vector `cross-tenant-forgery`).
- A key marked `compromised` produces a trust warning on every record it signed. An
  `issued_at` earlier than `compromise_suspected_from` MUST NOT clear the warning (an attacker
  can backdate). The only independent timing evidence is a **verified** OpenTimestamps
  attestation of a batch root containing the record's leaf, using the attested Bitcoin block
  header time minus a 2-hour tolerance; `confirmed_at`/`block_time` JSON fields are never
  evidence. Even then the display states the evidence rather than hiding the warning.
- Rotation does not invalidate earlier signatures; keys are selected by `key_id`.

## 6. Anchoring

```
leaf_data = UTF8("COA-INTL-ANCHOR-LEAF-v1\n") || raw32(document.sha256) || raw32(payload_sha256)
leaf_hash = SHA-256(0x00 || leaf_data)
node_hash = SHA-256(0x01 || left || right)
```

The batch tree and inclusion proofs follow RFC 9162 §2.1 (split point = largest power of two
strictly less than n; proof verification per §2.1.3.2). Verifiers MUST recompute `leaf_hash`
from the **verified payload** (never from the proof's `leaf` members), MUST recompute the root
from `inclusion_path`, and MUST compare it to `root` (vector `anchor-leaf-mismatch`). For
`method: opentimestamps-bitcoin` verifiers MUST additionally verify `ots_proof_base64` as an
OpenTimestamps proof over the raw 32-byte `root`. `public` is derived from `method`
(`local-test` → not public, labelled "local test anchor — not public" wherever shown).

**Operator leaves (2026-10-12, independent review F5 and R6).** A batch may also contain COA International's own
facts in positions that would otherwise be random padding:

```
operator_leaf_data = UTF8("COA-INTL-OPERATOR-LEAF-v1\n") || UTF8(kind) || 0x0A || raw32(sha256)
```

`kind` is `key-directory` (SHA-256 of the RFC 8785 canonical key directory without `generated_at`, published
with its proof at `GET /api/v1/public/anchors/key-directory`) or `audit-head` (the newest audit-chain
`entry_hash`, checked privately with `python -m coa_service.tools.audit_anchor`). The different domain label
means an operator leaf can never be read as a record leaf. Record proofs are unchanged: verifiers treat these
positions like any other sibling hash.

### 6.1 OpenTimestamps proofs (`method: opentimestamps-bitcoin`)

`ots_proof_base64` is a standard OpenTimestamps detached proof (`.ots`, SHA-256 file hash) whose file
digest MUST equal the raw 32-byte `root`. Walk it with a maintained OpenTimestamps implementation:

- A `BitcoinBlockHeaderAttestation` at height *h* is **valid** only if the commitment reached at that
  attestation equals the Merkle root of block *h* in **internal byte order** (header bytes 36–67,
  i.e. the reverse of the hex that block explorers display). The attested time is that header's time
  (header bytes 68–71, little-endian); treat it as accurate to about ±2 hours.
- Block headers MUST come from a source the verifier trusts: its own Bitcoin node, a pinned header file,
  or an explicitly configured explorer URL. Never from the proof, the anchor-proof JSON, or the record.
- Result per proof: `attested` (header matched), `attested_unverified` (attestation present, but no trusted
  header covers any attested height), `pending` (only pending calendar attestations), or `invalid`
  (malformed, wrong digest, or a trusted header contradicts every attestation). Verifiers MUST bound
  every intermediate message to 4096 bytes and treat a longer one as `invalid`. Only
  `attested` may be displayed as a confirmed public anchor; `confirmed_at`/`block_time` JSON fields are
  informational.
- Verifiers MUST NOT contact calendar URIs found inside a proof unless the user explicitly asks to
  upgrade a pending proof, and then only https calendars on an allowlist.

Vectors: `ots-attested`, `ots-attested-no-headers`, `ots-wrong-header`, `ots-pending`,
`ots-proof-for-other-root` with SYNTHETIC header files under `fixtures/vectors/v1/ots/` standing in for
the trusted header source (heights/roots there are not real Bitcoin blocks). Reference implementation:
`coa_service.anchoring.ots.verify_ots`.

`anchor.status` is `pending`, `confirmed`, or `failed`. Pending or failed anchoring is an
operational fact and never a signature failure. Only hashes ever leave COA International.

## 7. Verifier result model

| Result | Meaning |
|---|---|
| `parse_ok` (+ `error_code`) | §3 rules passed |
| `schema_version_supported` | `schema_version` is `2.0` |
| `structure_valid` | Envelope shape, signature encoding (§4), payload schema, §2.2 checks, algorithm `Ed25519`, canonicalization `RFC8785` |
| `signature_valid` | Ed25519 verification succeeded with the resolved (trusted or candidate) key |
| `issuer_trusted` | §5 trust rule satisfied |
| file match | For each checked file: `original_report`, `store_document`, or no match — say **which** expected document it fails to match |
| `inclusion_valid` / anchor status | §6 |
| live standing / membership | Only from an explicitly configured trusted URL; offline verifiers say "unknown (offline)" or "as of <snapshot date>" |

Each later field is false when an earlier one is false. A hash mismatch is reported as a
mismatch, never as proof of fraud.

## 8. Vectors

`fixtures/vectors/v1/vectors.json` lists envelope cases (each with a `trust` list naming
trust-store entries in `keys.json` and an optional untrusted `candidate`), file-hash cases,
anchor-proof cases, and Merkle trees of size 1–7. All keys are **test-only**, derived from
public seeds, and rejected by production readiness checks.
