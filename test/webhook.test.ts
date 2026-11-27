import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { pairing } from "../src/door.js";
import { stringToSign, type SnsMessage } from "../src/sns.js";
import { entry, subscribeURL, webhook, type Filed, type Store, type Webhook } from "../src/webhook.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const topicArn = "arn:aws:sns:eu-west-1:000000000000:chutchut-inbound";
const bucket = "chutchut-inbound-test";
const now = new Date("2026-11-27T18:00:00Z");

function sns(fields: Partial<SnsMessage>): string {
  const m: SnsMessage = {
    Type: "Notification", MessageId: "n-1", TopicArn: topicArn, Message: "", Timestamp: "2026-11-27T17:59:30.000Z",
    SignatureVersion: "2", Signature: "", SigningCertURL: "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-0000.pem", ...fields,
  };
  m.Signature = sign("RSA-SHA256", Buffer.from(stringToSign(m)), privateKey).toString("base64");
  return JSON.stringify(m);
}

function mail(id: string, from: string, verdicts: Record<string, string> = {}, to = "support@example.test"): string {
  const v = { spam: "PASS", virus: "PASS", dkim: "PASS", spf: "PASS", dmarc: "PASS", ...verdicts };
  return sns({
    MessageId: `n-${id}`,
    Message: JSON.stringify({
      notificationType: "Received",
      mail: { messageId: id, headersTruncated: false, headers: [{ name: "From", value: from }], commonHeaders: { from: [from] } },
      receipt: {
        spamVerdict: { status: v.spam }, virusVerdict: { status: v.virus }, dkimVerdict: { status: v.dkim },
        spfVerdict: { status: v.spf }, dmarcVerdict: { status: v.dmarc }, recipients: [to],
        action: { type: "S3", bucketName: bucket, objectKey: `in/${id}` },
      },
    }),
  });
}

function memory(failures = 0): Store & { items: Filed[] } {
  const counts = new Map<string, number>();
  const items: Filed[] = [];
  let failing = failures;
  return {
    items,
    async filed(id) { return items.some((f) => f.messageId === id); },
    async bump(c) { const n = (counts.get(c) ?? 0) + 1; counts.set(c, n); return n; },
    async file(item) {
      if (failing > 0) { failing -= 1; throw new Error("store down"); }
      if (items.some((f) => f.messageId === item.messageId)) return false;
      items.push(item);
      return true;
    },
  };
}

function setup(limits: Partial<Webhook["limits"]> = {}, failures = 0) {
  const store = memory(failures);
  const confirmed: string[] = [];
  const w: Webhook = {
    sns: { topicArn, now: () => now, certificate: async () => pem },
    bucket, store, paired: async () => pairing(["ana@example.test"]),
    limits: { inboundPerDay: 100, accountPerDay: 1000, knocksPerSender: 1, knocksPerDomain: 3, knocksPerDay: 50, ...limits },
    confirm: async (url) => { confirmed.push(url); },
  };
  return { w, store, confirmed };
}

describe("webhook", () => {
  it("files a paired sender's mail as waiting for its malware scan, never read before", async () => {
    const { w, store } = setup();
    expect(await webhook(mail("m1", "Ana <ana@example.test>"), w)).toEqual({ status: 200, said: "filed" });
    expect(store.items).toEqual([{ messageId: "m1", objectKey: "in/m1", at: now.toISOString(), purgeAt: "2026-12-27T18:00:00.000Z", from: "ana@example.test", state: "pending_scan" }]);
  });

  it("refuses what doesn't check, and files nothing", async () => {
    const { w, store } = setup();
    const forged = JSON.parse(mail("m1", "ana@example.test"));
    forged.Message = forged.Message.replace("m1", "m2");
    expect((await webhook(JSON.stringify(forged), w)).status).toBe(403);
    expect((await webhook("{}", w)).status).toBe(403);
    expect(store.items).toEqual([]);
  });

  it("files a message SNS sends twice only once", async () => {
    const { w, store } = setup();
    await webhook(mail("m1", "ana@example.test"), w);
    expect(await webhook(mail("m1", "ana@example.test"), w)).toEqual({ status: 200, said: "filed before" });
    expect(store.items).toHaveLength(1);
  });

  it("files a message whose first write failed when SNS sends it again: nothing is lost", async () => {
    const { w, store } = setup({}, 1);
    await expect(webhook(mail("m1", "ana@example.test"), w)).rejects.toThrow("store down");
    expect(store.items).toEqual([]);
    expect(await webhook(mail("m1", "ana@example.test"), w)).toEqual({ status: 200, said: "filed" });
    expect(store.items.map((f) => f.messageId)).toEqual(["m1"]);
  });

  it("counts a sender's knocks case-insensitively", async () => {
    const { w, store } = setup();
    await webhook(mail("k1", "Spam@Stranger.test"), w);
    await webhook(mail("k2", "spam@stranger.test"), w);
    expect(store.items.map((f) => f.state === "knock" && f.shown)).toEqual([true, false]);
  });

  it("keeps a stranger's mail as a knock for 30 days, shown once a day per sender, the rest for the digest", async () => {
    const { w, store } = setup();
    await webhook(mail("k1", "bob@stranger.test"), w);
    await webhook(mail("k2", "bob@stranger.test"), w);
    expect(store.items.map((f) => f.state === "knock" && f.shown)).toEqual([true, false]);
    expect(store.items[0]).toMatchObject({ state: "knock", purgeAt: "2026-12-27T18:00:00.000Z", from: "bob@stranger.test" });
  });

  it("caps a sender domain's knocks, and one noisy sender never uses up others' room", async () => {
    const { w, store } = setup({ knocksPerDomain: 2, knocksPerDay: 3 });
    for (const [id, from] of [["a", "x@spam.test"], ["b", "x@spam.test"], ["c", "x@spam.test"], ["d", "y@spam.test"], ["e", "z@spam.test"], ["f", "u@ok.test"], ["g", "v@ok.test"]]) {
      await webhook(mail(id!, from!), w);
    }
    expect(store.items.map((f) => (f.state === "knock" && f.shown ? f.messageId : "-")).join("")).toBe("a--d-f-");
  });

  it("counts a catch-all domain's addresses as one entry for the per-address cap", async () => {
    const { w, store } = setup({ inboundPerDay: 2 });
    w.entries = ["example.test", "billing@other.test"];
    for (let i = 1; i <= 3; i++) await webhook(mail(`m${i}`, "ana@example.test", {}, `a${i}@example.test`), w);
    expect(store.items.map((f) => f.state)).toEqual(["pending_scan", "pending_scan", "held"]);
    expect(entry("A9@Example.test", w.entries)).toBe("example.test");
    expect(entry("x@sub.example.test", w.entries)).toBe("example.test");
    expect(entry("billing@other.test", w.entries)).toBe("billing@other.test");
    expect(entry("else@other.test", w.entries)).toBe("else@other.test");
    expect(entry("x@notexample.test", w.entries)).toBe("x@notexample.test");
  });

  it("gives no fresh room to mail spread over many addresses of ours: the account's cap and the knock caps count across them", async () => {
    const { w, store } = setup({ accountPerDay: 3, knocksPerSender: 1, knocksPerDomain: 2 });
    for (let i = 1; i <= 5; i++) await webhook(mail(`s${i}`, "x@spam.test", {}, `a${i}@example.test`), w);
    expect(store.items.map((f) => (f.state === "knock" ? (f.shown ? "shown" : "digest") : f.state))).toEqual(["shown", "digest", "digest", "held", "held"]);
  });

  it("counts every cap per address of ours, so one busy address never holds another's mail", async () => {
    const { w, store } = setup({ inboundPerDay: 1, knocksPerSender: 1 });
    await webhook(mail("m1", "ana@example.test", {}, "support@example.test"), w);
    await webhook(mail("m2", "ana@example.test", {}, "billing@example.test"), w);
    await webhook(mail("m3", "ana@example.test", {}, "SUPPORT@example.test"), w);
    expect(store.items.map((f) => f.state)).toEqual(["pending_scan", "pending_scan", "held"]);
  });

  it("holds, never drops, mail past the day's cap", async () => {
    const { w, store } = setup({ inboundPerDay: 1 });
    await webhook(mail("m1", "ana@example.test"), w);
    expect(await webhook(mail("m2", "ana@example.test"), w)).toEqual({ status: 200, said: "filed" });
    expect(store.items[1]).toMatchObject({ messageId: "m2", state: "held", why: "over the day's mail" });
  });

  it("files a virus or spam as refused and an unfinished scan as held, without counting them", async () => {
    const { w, store } = setup({ inboundPerDay: 1 });
    await webhook(mail("v", "ana@example.test", { virus: "FAIL" }), w);
    await webhook(mail("s", "ana@example.test", { spam: "FAIL" }), w);
    await webhook(mail("g", "ana@example.test", { virus: "GRAY" }), w);
    await webhook(mail("m", "ana@example.test"), w);
    expect(store.items.map((f) => f.state)).toEqual(["refused", "refused", "held", "pending_scan"]);
    // Each is kept 30 days, and refused mail never keeps its sender's address.
    expect(store.items.every((f) => f.purgeAt === "2026-12-27T18:00:00.000Z")).toBe(true);
    expect(store.items.filter((f) => f.state === "refused").every((f) => f.from === undefined)).toBe(true);
  });

  it("confirms only chutchut's own topic subscription, at SNS in its region", async () => {
    const { w, confirmed } = setup();
    const good = `https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=${encodeURIComponent(topicArn)}&Token=t1`;
    expect(await webhook(sns({ Type: "SubscriptionConfirmation", SubscribeURL: good, Token: "t1" }), w)).toEqual({ status: 200, said: "subscribed" });
    expect(confirmed).toEqual([good]);
    for (const bad of [
      good.replace("eu-west-1.amazonaws", "us-east-1.amazonaws"),
      good.replace("https://", "http://"),
      good.replace("sns.eu-west-1.amazonaws.com", "evil.test"),
      good.replace("ConfirmSubscription", "Unsubscribe"),
      good.replace(encodeURIComponent(topicArn), encodeURIComponent(topicArn + "-other")),
      good.replace("&Token=t1", ""),
    ]) {
      expect(subscribeURL(bad, topicArn), bad).toBe(false);
      expect((await webhook(sns({ Type: "SubscriptionConfirmation", SubscribeURL: bad, Token: "t1" }), w)).status).toBe(403);
    }
    expect(confirmed).toHaveLength(1);
  });

  it("answers 400 for a checked message that isn't mail for this bucket", async () => {
    const { w, store } = setup();
    expect((await webhook(sns({ Message: '{"notificationType":"Bounce"}' }), w)).status).toBe(400);
    expect(store.items).toEqual([]);
  });
});
