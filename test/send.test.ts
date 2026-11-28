import { describe, expect, it } from "vitest";
import { sendReply, type Reply, type Sending } from "../src/send.js";

const now = new Date("2026-11-27T18:00:00Z");

function setup(over: Partial<{ state: string; shown: boolean; clean: boolean; purgeAt: string; perDay: number; accountPerDay: number; noticesPerDay: number; noticesPerRecipient: number; failSend: number }> = {}) {
  const sent: unknown[] = [];
  const keys = new Map<string, "sending" | "sent" | "failed">();
  const counts = new Map<string, number>();
  let failing = over.failSend ?? 0;
  const s: Sending = {
    async thread(id) { return id === "<m1@example.test>" ? { messageId: "m1", from: "Ana@Example.test", recipient: "support@kiff.test" } : undefined; },
    async item(id) {
      return id === "m1" ? { state: over.state ?? "clean", shown: over.shown, clean: over.clean, purgeAt: over.purgeAt ?? "2026-12-27T18:00:00.000Z" } : undefined;
    },
    async claim(key) {
      const k = keys.get(key);
      if (k === "sent") return "sent";
      if (k === "sending") return "busy";
      keys.set(key, "sending");
      return k === "failed" ? "retry" : "new";
    },
    async done(key, ok) { keys.set(key, ok ? "sent" : "failed"); },
    async bump(c) { const n = (counts.get(c) ?? 0) + 1; counts.set(c, n); return n; },
    async transport(r) { if (failing > 0) { failing -= 1; throw new Error("ses down"); } sent.push(r); },
    perDay: over.perDay ?? 100,
    accountPerDay: over.accountPerDay ?? 1000,
    noticesPerDay: over.noticesPerDay ?? 5000,
    noticesPerRecipient: over.noticesPerRecipient ?? 100,
    entries: ["kiff.test"],
    now: () => now,
  };
  return { s, sent };
}

const reply = (over: Partial<Reply> = {}): Reply => ({
  from: "Support <support@kiff.test>", to: ["ana@example.test"], subject: "Re: Refund", text: "Done.",
  inReplyTo: "<m1@example.test>", references: "<r0@example.test>", idempotencyKey: "run-1:reply", ...over,
});

describe("send", () => {
  it("sends a reply to whoever wrote, from the address it came to, threaded under the message", async () => {
    const { s, sent } = setup();
    expect(await sendReply(reply(), s)).toEqual({ status: 200, said: "sent" });
    expect(sent).toEqual([{
      from: "support@kiff.test", to: "ana@example.test", subject: "Re: Refund", text: "Done.",
      inReplyTo: "<m1@example.test>", references: "<r0@example.test> <m1@example.test>",
    }]);
  });

  it("sends once per idempotency key, and again only after a failed send", async () => {
    const { s, sent } = setup({ failSend: 1 });
    await expect(sendReply(reply(), s)).rejects.toThrow("ses down");
    expect(await sendReply(reply(), s)).toEqual({ status: 200, said: "sent" });
    expect(await sendReply(reply(), s)).toEqual({ status: 200, said: "sent before" });
    expect(sent).toHaveLength(1);
  });

  it("never sends to anyone but the thread's writer, or from another address of ours", async () => {
    const { s, sent } = setup();
    expect(await sendReply(reply({ to: ["mallory@example.test"] }), s)).toMatchObject({ status: 403, said: "only to whoever wrote it" });
    expect(await sendReply(reply({ to: ["ana@example.test", "mallory@example.test"] }), s)).toMatchObject({ status: 400 });
    expect(await sendReply(reply({ to: ["Ana <ana@example.test>, m@example.test"] }), s)).toMatchObject({ status: 400 });
    expect(await sendReply(reply({ from: "billing@kiff.test" }), s)).toMatchObject({ status: 403, said: "only from the address it was written to" });
    expect(sent).toEqual([]);
  });

  it("sends only a reply to a message that came here, was scanned clean and is within its 30 days", async () => {
    for (const over of [{ inReplyTo: undefined }, { inReplyTo: "<other@example.test>" }, { inReplyTo: "m1@example.test" }]) {
      const { s, sent } = setup();
      expect(await sendReply(reply(over), s)).toMatchObject({ status: 403 });
      expect(sent).toEqual([]);
    }
    for (const item of [{ state: "pending_scan" }, { state: "knock", shown: true }, { state: "held" }, { state: "refused" }, { purgeAt: "2026-11-27T00:00:00.000Z" }, { purgeAt: "" }, { purgeAt: "not a date" }]) {
      const { s, sent } = setup(item);
      expect(await sendReply(reply(), s), JSON.stringify(item)).toMatchObject({ status: 403 });
      expect(sent).toEqual([]);
    }
    const knock = setup({ state: "knock", shown: true, clean: true });
    expect(await sendReply(reply(), knock.s)).toMatchObject({ status: 200 });
  });

  it("holds replies past the day's cap from an address, and asks for a key", async () => {
    const { s, sent } = setup({ perDay: 1 });
    await sendReply(reply(), s);
    expect(await sendReply(reply({ idempotencyKey: "run-2:reply" }), s)).toMatchObject({ status: 429 });
    expect(sent).toHaveLength(1);
    expect(await sendReply(reply({ idempotencyKey: undefined }), s)).toMatchObject({ status: 400 });
    expect(await sendReply(reply({ subject: "Re: x\r\nBcc: m@example.test", idempotencyKey: "run-3:reply" }), s)).toMatchObject({ status: 400 });
  });

  it("takes only Message-IDs in References, nothing that could carry a header", async () => {
    const { s, sent } = setup();
    for (const references of ["<a@x> bcc:m@example.test", "<a@x>\r\nBcc: m@example.test", "plain", "<a@x> <b <c>"]) {
      expect(await sendReply(reply({ references }), s), references).toMatchObject({ status: 400 });
    }
    expect(sent).toEqual([]);
  });

  it("counts the send cap by the configured entry and for the whole account", async () => {
    const { s, sent } = setup({ perDay: 5, accountPerDay: 1 });
    await sendReply(reply(), s);
    expect(await sendReply(reply({ idempotencyKey: "run-9:reply" }), s)).toMatchObject({ status: 429 });
    expect(sent).toHaveLength(1);
  });

  // tafs's own mail that answers no message: the owner's copy of a door's answer, a report to support.
  const notice = (over: Partial<Reply> = {}): Reply => ({
    from: "Support <support@kiff.test>", to: ["owner@company.test"], subject: "Support: answered Ana", text: "Support answered Ana.",
    idempotencyKey: "door-owner:1", notice: true, ...over,
  });

  it("sends a notice to one address, from one of ours, never threaded", async () => {
    const { s, sent } = setup();
    expect(await sendReply(notice(), s)).toEqual({ status: 200, said: "sent" });
    expect(sent).toEqual([{ from: "support@kiff.test", to: "owner@company.test", subject: "Support: answered Ana", text: "Support answered Ana.", inReplyTo: "", references: "" }]);
    expect(await sendReply(notice(), s)).toEqual({ status: 200, said: "sent before" });
    expect(sent).toHaveLength(1);
  });

  it("never sends a notice from an address that isn't ours, to more than one, or past the day's cap", async () => {
    const { s, sent } = setup({ noticesPerDay: 1 });
    expect(await sendReply(notice({ from: "boss@elsewhere.test" }), s)).toMatchObject({ status: 403, said: "only from an address of ours" });
    expect(await sendReply(notice({ to: ["a@x.test", "b@x.test"] }), s)).toMatchObject({ status: 400 });
    expect(await sendReply(notice({ idempotencyKey: "n" }), s)).toMatchObject({ status: 400 });
    expect(await sendReply(notice({ idempotencyKey: "door-owner:1" }), s)).toEqual({ status: 200, said: "sent" });
    expect(await sendReply(notice({ idempotencyKey: "door-owner:2" }), s)).toMatchObject({ status: 429, said: "over the day's notices" });
    expect(sent).toHaveLength(1);
  });

  it("caps notices to any one address apart from the total, so one busy owner never takes another's", async () => {
    const { s, sent } = setup({ noticesPerRecipient: 1 });
    expect(await sendReply(notice({ idempotencyKey: "door-owner:1" }), s)).toEqual({ status: 200, said: "sent" });
    expect(await sendReply(notice({ idempotencyKey: "door-owner:2" }), s)).toMatchObject({ status: 429, said: "over the day's notices to this address" });
    expect(await sendReply(notice({ idempotencyKey: "door-owner:3", to: ["other@company.test"] }), s)).toEqual({ status: 200, said: "sent" });
    expect(sent).toHaveLength(2);
  });

  it("keeps a reply a reply: without notice, a mail that answers no message is still refused", async () => {
    const { s, sent } = setup();
    expect(await sendReply(notice({ notice: undefined }), s)).toMatchObject({ status: 403, said: "only a reply to a message that came here" });
    expect(sent).toHaveLength(0);
  });
});
