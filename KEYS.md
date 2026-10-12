# COA International signing keys

`coa-verify` decides whether a record was signed by COA International by checking the signing key against a trust
store you build with `coa-verify trust add`. The key directory at <https://coa.international/api/v1/public/keys>
lists the keys. **Before you trust a key, check that its fingerprint also appears below.**

The two lists are published through different systems: our website, and this repository's history on GitHub. To make
you trust a false key, an attacker would have to change both, and a change here is a visible commit. If the two lists
disagree, do not add the key. Report it to the address in `SECURITY.md`.

A key is listed here when it is created and stays listed, with its current status, after it is retired or
compromised. This is how you check a record signed under an older key.

## Production keys

None yet. COA International has not issued production records.

## Demonstration keys (never trust these for real certificates)

These keys sign the public demonstration at the test address. A record signed by one of them is labelled as a
demonstration and is not a certificate.

| Program | Key ID | Status | Fingerprint (SHA-256 of the raw public key) |
|---|---|---|---|
| `coa-demo` | `coa-demo-20261001-0a076f3b` | active | `acef3d41b994e8cf8dbe37d9d4d918f684f9698099f630ab7861f1f82c846f6c` |
