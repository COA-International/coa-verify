# coa-verify

The independent verifier for **COA International** signed certificates.

COA International signs a record for each certificate it issues: which laboratory report, which product
batch, which store, and the SHA-256 hashes of the original report and the store's document. The record is
signed with Ed25519 and its hash is anchored publicly (OpenTimestamps / Bitcoin). The QR code and the
website at coa.international let anyone check a certificate quickly. This tool is for auditors,
regulators, laboratories and technical buyers who want to check one **without trusting the website**:

* it works **offline**: nothing is fetched unless you ask for `--online`;
* a record counts as "issued by COA International" only when it is signed by a key **you** pinned, by
  fingerprint, from a source you trust; a key shipped alongside the record is never trusted on its own;
* the code is open (Apache-2.0) so you can read exactly what it checks, and build it yourself.

## Install

**With Node.js 22 or newer:**

```sh
npx coa-verify --help          # or: npm install -g coa-verify
```

**Stand-alone program (no Node.js):** download the file for your system from
[Releases](https://github.com/COA-International/coa-verify/releases), together with `SHA256SUMS.txt`, and
check it before running it:

| System | File | Check the download |
|---|---|---|
| Windows (x64) | `coa-verify-<version>-windows-x64.exe` | `certutil -hashfile coa-verify-<version>-windows-x64.exe SHA256` |
| macOS (Apple silicon) | `coa-verify-<version>-macos-arm64` | `shasum -a 256 -c SHA256SUMS.txt --ignore-missing` |
| macOS (Intel) | `coa-verify-<version>-macos-x64` | same |
| Linux (x64 / arm64) | `coa-verify-<version>-linux-x64` / `-linux-arm64` | `sha256sum -c SHA256SUMS.txt --ignore-missing` |
| Any system with Node.js | `coa-verify-<version>.mjs` | as above; run with `node coa-verify-<version>.mjs` |

On Windows, compare the printed hash with the line for that file in `SHA256SUMS.txt`. On macOS and Linux,
make the file executable (`chmod +x`). The programs are not code-signed yet: Windows may show "unknown
publisher", and macOS may block the first run until you allow it under System Settings, Privacy & Security.

Every release file also carries a GitHub build-provenance attestation, which shows that it was built from
this repository by its release workflow:

```sh
gh attestation verify coa-verify-<version>-linux-x64 --repo COA-International/coa-verify
```

## Verify a certificate

1. **Unzip** the customer package (it holds `signed-record.json`, the PDFs and `public-key.json`).
2. **Pin COA International's signing key once.** Take the key fingerprint for the program operator from a
   source you trust (COA International publishes them at <https://coa.international/verify-independently>;
   ask COA International directly if you want a second channel). Then:

   ```sh
   coa-verify trust add --store trust.json --key-file ./package/public-key.json \
       --fingerprint <sha256-hex> --program-id <program-id> --environment production
   ```

   You state the program operator and environment yourself: the key file came with the record, so its own
   description of whose key it is is not trusted. The command refuses a key whose fingerprint differs from
   the one you pinned.
3. **Verify:**

   ```sh
   coa-verify verify --bundle ./package --trust-store trust.json
   ```

Exit code 0 means every check you asked for passed: the record was signed with a key you trust, and the PDFs
are byte-for-byte the signed files. **It never means the laboratory result, the purchase or the store's
membership is true.** The record states what the program operator reported. Current standing (disputed,
revoked, superseded) and membership are not part of an offline check: add `--online https://coa.international`
or open the verification page printed in the report.

The full option list, the trust model, the anchor checks (`--anchor-proof`, `--bitcoin-headers`,
`--require-anchor`), the exit codes and the `--json` report are documented in [cli/README.md](cli/README.md).

## What is in this repository

| Path | What |
|---|---|
| `cli/verify-core` | The verification library: strict JSON parser, RFC 8785 canonicalisation, structure rules, Ed25519 signature and trust rules, RFC 9162 Merkle proofs, OpenTimestamps proof checks. No Node.js APIs; it also runs in browsers. |
| `cli/coa-verify` | The command-line tool, the bundler and the stand-alone build. |
| `docs/protocol/signed-record-v1.md` | The signed-record protocol the tool implements. |
| `schemas/` | The published JSON Schemas. |
| `fixtures/vectors/v1/` | Test vectors (all keys in them are **test-only**, derived from published seeds, and never trusted in production). |

The tool was written from the protocol document and the vectors alone, in a different language and with
different cryptography libraries (`@noble/curves`, `@noble/hashes`) from COA International's signing service,
which is not open source. References in the protocol document to `service/` or `coa_service` point to that
private reference implementation; nothing here depends on it.

## Build from source

```sh
cd cli
npm ci
npm run build && npm test                 # every protocol vector, parser edge cases, CLI behaviour
npm run bundle -w coa-verify              # cli/coa-verify/bundle/coa-verify.mjs
node coa-verify/scripts/smoke.mjs node coa-verify/bundle/coa-verify.mjs
npm run sea -w coa-verify                 # stand-alone executable for this system (Node.js 24)
```

## Reporting a problem

Security issues: please use GitHub's private vulnerability reporting ("Report a vulnerability" under
Security), not a public issue. See [SECURITY.md](SECURITY.md). Other problems: open an issue.

## Licence

Apache License 2.0 (see `LICENSE` and `NOTICE`). The tool bundles `@noble/curves` and `@noble/hashes`, MIT
licensed (see `THIRD_PARTY_NOTICES.md` in each release).
