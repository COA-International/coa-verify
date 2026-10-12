# Releasing

This repository is published from COA International's private repository: changes are made there
(`cli/`, `schemas/`, `fixtures/vectors/v1/`, `docs/protocol/`) and exported here with
`scripts/export-verifier.mjs`. Do not edit this repository directly; the next export would overwrite it.

1. Set the version in `cli/coa-verify/package.json` and `VERSION` in `cli/coa-verify/src/cli.ts`
   (a test checks they match), export, commit and push to `main`. Wait for `ci` to pass.
2. Tag: `git tag v<version> && git push origin v<version>`. The `release` workflow tests, builds
   the `.mjs` file and the five executables, smoke-tests each one, writes `SHA256SUMS.txt`, records
   build-provenance attestations and creates a **draft** GitHub Release.
3. Review the draft (file list, checksums) and publish it.
4. npm: the `npm` job of the same workflow waits for a maintainer to approve the `npm` environment. It checks that
   the package carries byte-for-byte the released `.mjs` bundle, then publishes with
   `npm publish --provenance` through npm trusted publishing, so no npm token exists. Check with
   `npx coa-verify@<version> --version`; the npm page shows the provenance (workflow run and commit).

One-time setup (owner), in this order:
1. In this repository's settings, create the environment `npm` with yourself as a required reviewer and a
   deployment rule allowing only tags `v*`. Do this first: if the environment does not exist when a tag is pushed,
   GitHub creates it unprotected and the job would run without approval.
2. On npmjs.com, add `COA-International/coa-verify`, workflow `release.yml`, environment `npm` as the package's
   trusted publisher, then set publishing access to "require two-factor authentication and disallow tokens".

Publishing from a laptop is retired: a compromised laptop could otherwise publish a tampered verifier.

## Keys

`KEYS.md` lists every COA International signing key's fingerprint, the second channel next to the website's key
directory. Whenever a key is created, retired or reported compromised, update `cli/public-repo/KEYS.md` in the
private repository the same day and export it. A key is not used for production records until its fingerprint
is on `main` here. Signed commits or tags for these updates are recommended once a maintainer signing key exists.
