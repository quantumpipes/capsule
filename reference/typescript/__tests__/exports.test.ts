/**
 * Public package exports (FR-002, FR-003).
 */

import { describe, expect, it } from "vitest";
import * as pkg from "../src/index.js";

describe("package exports", () => {
  it("exports FR-002 validation API", () => {
    expect(typeof pkg.validateCapsuleDict).toBe("function");
  });

  it("exports FR-003 verifyDetailed", () => {
    expect(typeof pkg.verifyDetailed).toBe("function");
    expect(typeof pkg.verify).toBe("function");
  });
});
