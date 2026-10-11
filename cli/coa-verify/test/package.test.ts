import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { VERSION } from "../src/cli.js";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf8"));

describe("published package", () => {
  it("--version reports the package version", () => {
    expect(VERSION).toBe(pkg.version);
  });
  it("is Apache-2.0, has no runtime dependencies (verify-core and @noble are bundled) and ships the notices", () => {
    expect(pkg.license).toBe("Apache-2.0");
    expect(pkg.dependencies ?? {}).toEqual({});
    expect(pkg.bin["coa-verify"]).toBe("bundle/coa-verify.mjs");
    for (const f of ["bundle/coa-verify.mjs", "bundle/LICENSE", "bundle/NOTICE", "bundle/THIRD_PARTY_NOTICES.md"]) {
      expect(pkg.files).toContain(f);
    }
  });
  it("verify-core stays private (it is shipped only inside the bundle)", () => {
    const core = JSON.parse(readFileSync(join(PKG_DIR, "..", "verify-core", "package.json"), "utf8"));
    expect(core.private).toBe(true);
  });
});
