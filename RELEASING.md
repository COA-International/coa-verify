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
4. npm: from a clean checkout of the tag, `cd cli && npm ci && npm test`, then
   `npm publish -w coa-verify` while signed in as COA International's npm account (`prepack` builds
   the bundle). Check with `npx coa-verify@<version> --version`.

Once the package exists on npm, consider npm "trusted publishing" from the release workflow
(publishing with provenance, no long-lived token).
