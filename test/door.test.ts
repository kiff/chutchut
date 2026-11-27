import { describe, expect, it } from "vitest";
import { door, normalize, pairing } from "../src/door.js";

describe("door", () => {
  // Built from an address as someone typed it: pairing keys it as the door does.
  const paired = pairing([" Ana@Example.test"]);

  it("lets a paired sender through only when its mail is DMARC-aligned", () => {
    expect(door({ address: "ana@example.test", dmarcAligned: true }, paired)).toBe("paired");
    // A spoofed From: the address is paired, but the mail didn't prove it.
    expect(door({ address: "ana@example.test", dmarcAligned: false }, paired)).toBe("knock");
  });

  it("makes anyone else knock", () => {
    expect(door({ address: "someone@example.test", dmarcAligned: true }, paired)).toBe("knock");
    expect(door({ address: "", dmarcAligned: true }, paired)).toBe("knock");
  });

  it("keys an address trimmed and lower-cased", () => {
    expect(normalize("  Ana@Example.TEST ")).toBe("ana@example.test");
    expect(door({ address: "ANA@example.test", dmarcAligned: true }, paired)).toBe("paired");
  });
});
