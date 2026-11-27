import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { describe, expect, it } from "vitest";
import { authorized, readable, receivedJson, signedReceived } from "../src/provider.js";

// tafs cloud's own check of its provider's webhook (runtime/src/cloud/doors/sign.ts, signedWebhook), as written there.
function tafsChecks(secret: string, h: Record<string, string>, body: string, now: Date): boolean {
  const ts = Number(h["svix-timestamp"]);
  if (!Number.isInteger(ts) || Math.abs(now.getTime() / 1000 - ts) > 300) return false;
  const key = secret.startsWith("whsec_") ? Buffer.from(secret.slice("whsec_".length), "base64") : Buffer.from(secret, "utf8");
  const want = createHmac("sha256", key).update(`${h["svix-id"]}.${h["svix-timestamp"]}.${body}`).digest();
  return h["svix-signature"]!.split(/\s+/).some((part) => {
    const sig = Buffer.from(part.slice(part.indexOf(",") + 1), "base64");
    return sig.length === want.length && timingSafeEqual(sig, want);
  });
}

const now = new Date("2026-11-27T18:00:00Z");
const secret = "whsec_" + Buffer.from("a test secret of thirty-two bytes!").toString("base64");

describe("provider", () => {
  it("signs email.received as tafs cloud checks it, naming only the message", () => {
    const { body, headers } = signedReceived(secret, "0100abc", now);
    expect(JSON.parse(body)).toEqual({ type: "email.received", created_at: now.toISOString(), data: { email_id: "0100abc" } });
    expect(tafsChecks(secret, headers, body, now)).toBe(true);
    expect(tafsChecks(secret, headers, body.replace("0100abc", "0100abd"), now)).toBe(false);
    expect(tafsChecks("whsec_" + Buffer.from("another secret").toString("base64"), headers, body, now)).toBe(false);
    expect(tafsChecks(secret, headers, body, new Date(now.getTime() + 301_000))).toBe(false);
  });

  it("lets tafs read only what the scan cleared: clean mail, or a shown knock marked clean", () => {
    expect(readable({ state: "clean" })).toBe(true);
    expect(readable({ state: "knock", shown: true, clean: true })).toBe(true);
    for (const item of [{ state: "pending_scan" }, { state: "knock", shown: true }, { state: "knock", shown: false, clean: true }, { state: "held" }, { state: "refused" }, { state: "mail" }]) {
      expect(readable(item), JSON.stringify(item)).toBe(false);
    }
  });

  it("takes only the read key, compared by its hash", () => {
    const key = "ck_" + "x".repeat(40);
    const hash = createHash("sha256").update(key).digest("hex");
    expect(authorized(`Bearer ${key}`, hash)).toBe(true);
    for (const h of [undefined, "", key, `Bearer ${key}x`, `bearer ${key}`, `Bearer ${"y".repeat(43)}`, `Bearer short`]) {
      expect(authorized(h, hash), String(h)).toBe(false);
    }
    expect(authorized(`Bearer ${key}`, "not-a-hash")).toBe(false);
  });

  it("answers one message as tafs cloud reads it, with the sender check only when proven here", async () => {
    const raw = Buffer.from([
      'From: "Ana Doe" <ana@example.test>', "To: support@kiff.test", "Subject: Refund please",
      "Message-ID: <m1@example.test>", "In-Reply-To: <r0@kiff.test>", "References: <r0@kiff.test>",
      "MIME-Version: 1.0", 'Content-Type: multipart/mixed; boundary="b"', "", "--b", "Content-Type: text/plain; charset=utf-8", "",
      "Hello, order 42 please.", "--b", "Content-Type: application/pdf", 'Content-Disposition: attachment; filename="r.pdf"', "", "JVBERi0=", "--b--", "",
    ].join("\r\n"));
    const auth = { spf: "pass", dkim: "pass", dmarc: "pass" };
    const j = await receivedJson("0100abc", raw, { at: "2026-11-27T17:59:00.000Z", auth, from: "ana@example.test", recipient: "support@kiff.test" });
    expect(j).toMatchObject({
      id: "0100abc", from: "ana@example.test", to: ["support@kiff.test"], received_for: ["support@kiff.test"], subject: "Refund please",
      message_id: "<m1@example.test>", headers: { references: "<r0@kiff.test>", "in-reply-to": "<r0@kiff.test>" },
      authentication: auth, created_at: "2026-11-27T17:59:00.000Z",
    });
    expect(String(j.text).trim()).toBe("Hello, order 42 please.");
    expect(j.attachments).toEqual([{ content_disposition: "attachment" }]);
    expect((await receivedJson("0100abc", raw, { at: "t" })).authentication).toBeNull();
  });

  it("answers the filed sender and the address SES delivered to, never a looser reading of the headers", async () => {
    const raw = (from: string, to: string) => Buffer.from([`From: ${from}`, `To: ${to}`, "Subject: s", "Message-ID: <m2@example.test>", "", "hi", ""].join("\r\n"));
    const auth = { spf: "pass", dkim: "pass", dmarc: "pass" };
    // Bcc'd to the door: the header names someone else; the door is where SES delivered it.
    const bcc = await receivedJson("id1", raw("ana@example.test", "someone@else.test"), { at: "t", auth, from: "ana@example.test", recipient: "support@kiff.test" });
    expect(bcc).toMatchObject({ to: ["support@kiff.test"], received_for: ["support@kiff.test"], authentication: auth });
    // A To naming another door of ours can't win over the real delivery.
    const other = await receivedJson("id2", raw("ana@example.test", "billing@kiff.test"), { at: "t", auth, from: "ana@example.test", recipient: "support@kiff.test" });
    expect(other.to).toEqual(["support@kiff.test"]);
    // If the raw From reads as someone other than the proven address, no sender check goes.
    const differs = await receivedJson("id3", raw("mallory@example.test", "support@kiff.test"), { at: "t", auth, from: "ana@example.test", recipient: "support@kiff.test" });
    expect(differs).toMatchObject({ from: "ana@example.test", authentication: null });
    // A knock: no proven address, no sender check, the raw From as written.
    const knock = await receivedJson("id4", raw("Bob <bob@stranger.test>", "support@kiff.test"), { at: "t", recipient: "support@kiff.test" });
    expect(knock).toMatchObject({ from: "\"Bob\" <bob@stranger.test>", authentication: null });
  });
});
