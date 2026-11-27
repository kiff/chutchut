import { describe, expect, it } from "vitest";
import { mailboxes, sender } from "../src/from.js";

describe("from", () => {
  it("reads the address, never the display name", () => {
    expect(sender("ana@example.test")).toBe("ana@example.test");
    expect(sender("Ana Doe <ana@example.test>")).toBe("ana@example.test");
    // A display name that looks like a paired address is still only a name.
    expect(sender('"ana@example.test" <mallory@example.test>')).toBe("mallory@example.test");
    expect(sender("ana@example.test <mallory@example.test>")).toBe("mallory@example.test");
  });

  it("keeps a quoted comma or bracket inside the display name", () => {
    expect(mailboxes('"Doe, Ana" <ana@example.test>')).toEqual(["ana@example.test"]);
    expect(mailboxes('"<ana@example.test>, x" <mallory@example.test>')).toEqual(["mallory@example.test"]);
    expect(mailboxes("Ana (support, <b@example.test>) <ana@example.test>")).toEqual(["ana@example.test"]);
  });

  it("has no sender for several mailboxes, a group, or none", () => {
    expect(mailboxes("a@example.test, Bob <b@example.test>")).toEqual(["a@example.test", "b@example.test"]);
    expect(sender("a@example.test, b@example.test")).toBeUndefined();
    expect(mailboxes("team: a@example.test, b@example.test;")).toEqual(["a@example.test", "b@example.test"]);
    expect(sender("team: a@example.test;")).toBe("a@example.test");
    expect(sender("undisclosed-recipients:;")).toBeUndefined();
    expect(sender(undefined)).toBeUndefined();
    expect(sender("")).toBeUndefined();
  });

  it("has no sender when a Sender names someone else", () => {
    expect(sender("ana@example.test", "ana@example.test")).toBe("ana@example.test");
    expect(sender("ana@example.test", "Ana <ANA@example.test>")).toBe("ana@example.test");
    expect(sender("ana@example.test", "mallory@example.test")).toBeUndefined();
    expect(sender("ana@example.test", "not an address")).toBeUndefined();
  });

  it("refuses what doesn't read as addresses", () => {
    expect(mailboxes("a@example.test b@example.test")).toBeUndefined();
    expect(mailboxes("<a@example.test")).toBeUndefined();
    expect(mailboxes('"unclosed <a@example.test>')).toBeUndefined();
    expect(mailboxes("Ana (unclosed <a@example.test>")).toBeUndefined();
    expect(mailboxes("<<a@example.test>>")).toBeUndefined();
    expect(mailboxes("ana@localhost")).toBeUndefined();
    expect(mailboxes('<"quoted local"@example.test>')).toBeUndefined();
  });
});
