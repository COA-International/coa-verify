# coa-verify

Independent, offline verifier for **COA International** signed certificates. It checks a certificate
without trusting COA International's website, or even needing it to be online.

```sh
npx coa-verify --help
```

Requires Node.js 22 or newer. Stand-alone programs for Windows, macOS and Linux (no Node.js needed), with
SHA-256 checksums, are on the [releases page](https://github.com/COA-International/coa-verify/releases).

## Check a certificate in three steps

1. **Unzip** the customer package you received (it contains `signed-record.json`, the PDFs and `public-key.json`).
2. **Pin COA International's key once.** Get the key fingerprint from a source you trust, for example
   <https://coa.international/verify-independently>, then:

   ```sh
   coa-verify trust add --store trust.json --key-file ./package/public-key.json \
       --fingerprint <sha256-hex> --program-id <program-id> --environment production
   ```

   The command refuses a key whose fingerprint differs from the one you pinned.
3. **Verify:**

   ```sh
   coa-verify verify --bundle ./package --trust-store trust.json
   ```

Exit code 0 means every check you asked for passed: the record is signed by the key you trust, and the
PDFs are byte-for-byte the signed files. It never means the laboratory result, purchase or membership is
true. Current status (revocation, membership) needs `--online https://coa.international` or the
verification page.

Full documentation, the trust model and the exit codes:
<https://github.com/COA-International/coa-verify#readme>.

Licence: Apache-2.0. Bundles `@noble/curves` and `@noble/hashes` (MIT); see `bundle/THIRD_PARTY_NOTICES.md`.
