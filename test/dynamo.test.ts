import { ConditionalCheckFailedException, GetItemCommand, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { describe, expect, it } from "vitest";
import { dynamoSending, dynamoStore } from "../src/dynamo.js";

const now = () => new Date("2026-11-27T18:00:00Z");
const purgeAt = "2026-12-27T18:00:00.000Z";

/** A stand-in for DynamoDB that keeps items in memory and honours the conditions the store sends. */
function fake(fail?: string) {
  const items = new Map<string, Record<string, { S?: string; N?: string }>>();
  const sent: unknown[] = [];
  return {
    items, sent,
    async send(command: unknown): Promise<any> {
      sent.push(command);
      if (fail !== undefined && command?.constructor.name === fail) throw new Error("dynamo down");
      if (command instanceof GetItemCommand) return { Item: items.get(command.input.Key!.pk!.S!) };
      if (command instanceof PutItemCommand) {
        const pk = command.input.Item!.pk!.S!;
        if (command.input.ConditionExpression === "attribute_not_exists(pk)" && items.has(pk)) {
          throw new ConditionalCheckFailedException({ message: "exists", $metadata: {} });
        }
        items.set(pk, command.input.Item as never);
        return {};
      }
      if (command instanceof UpdateItemCommand) {
        const pk = command.input.Key!.pk!.S!;
        const old = items.get(pk);
        const n = Number(old?.n?.N ?? 0) + 1;
        const expiresAt = old?.expiresAt ?? command.input.ExpressionAttributeValues![":expires"];
        items.set(pk, { pk: { S: pk }, n: { N: String(n) }, expiresAt: expiresAt as never });
        return { Attributes: { n: { N: String(n) } } };
      }
      throw new Error("unexpected command");
    },
  };
}

describe("dynamo store", () => {
  it("files a message once, by a conditional put on its id", async () => {
    const db = fake();
    const store = dynamoStore(db, "chutchut-mail", now);
    expect(await store.filed("m1")).toBe(false);
    expect(await store.file({ messageId: "m1", objectKey: "in/m1", at: now().toISOString(), purgeAt, from: "ana@example.test", state: "pending_scan" })).toBe(true);
    expect(await store.filed("m1")).toBe(true);
    expect(await store.file({ messageId: "m1", objectKey: "in/m1", at: now().toISOString(), purgeAt, state: "pending_scan" })).toBe(false);
    expect(db.items.get("msg#m1")).toMatchObject({ state: { S: "pending_scan" }, from: { S: "ana@example.test" } });
    const puts = db.sent.filter((c) => c instanceof PutItemCommand) as PutItemCommand[];
    expect(puts.every((p) => p.input.ConditionExpression === "attribute_not_exists(pk)")).toBe(true);
  });

  it("reads whether a message is filed with a consistent read", async () => {
    const db = fake();
    await dynamoStore(db, "t", now).filed("m1");
    expect((db.sent[0] as GetItemCommand).input).toMatchObject({ ConsistentRead: true, Key: { pk: { S: "msg#m1" } } });
  });

  it("lets every filed item expire at its purgeAt, and keeps why mail was held or refused", async () => {
    const db = fake();
    const store = dynamoStore(db, "t", now);
    await store.file({ messageId: "k1", objectKey: "in/k1", at: now().toISOString(), purgeAt, state: "knock", shown: false });
    await store.file({ messageId: "h1", objectKey: "in/h1", at: now().toISOString(), purgeAt, state: "held", why: "over the day's mail" });
    expect(db.items.get("msg#k1")).toMatchObject({ shown: { S: "no" }, expiresAt: { N: String(Date.parse("2026-12-27T18:00:00Z") / 1000) } });
    expect(db.items.get("msg#h1")).toMatchObject({ why: { S: "over the day's mail" } });
    expect(db.items.get("msg#h1")).toMatchObject({ expiresAt: { N: String(Date.parse(purgeAt) / 1000) } });
  });

  it("counts a day's counter up, expiring two days after it was first counted", async () => {
    const db = fake();
    const store = dynamoStore(db, "t", now);
    expect(await store.bump("2026-11-27:in")).toBe(1);
    expect(await store.bump("2026-11-27:in")).toBe(2);
    expect(db.items.get("count#2026-11-27:in")!.expiresAt).toEqual({ N: String(Date.parse("2026-11-29T18:00:00Z") / 1000) });
  });

  it("keeps a thread key only for a sender proven here, so a forged From can never be replied to", async () => {
    const db = fake();
    const store = dynamoStore(db, "t", now);
    const auth = { spf: "pass", dkim: "pass", dmarc: "pass" };
    await store.file({ messageId: "p1", objectKey: "in/p1", at: now().toISOString(), purgeAt, state: "pending_scan", from: "ana@example.test", recipient: "support@kiff.test", rfcId: "<p1@example.test>", auth });
    await store.file({ messageId: "k1", objectKey: "in/k1", at: now().toISOString(), purgeAt, state: "knock", shown: true, from: "forged@example.test", recipient: "support@kiff.test", rfcId: "<k1@example.test>" });
    expect(db.items.get("mid#<p1@example.test>")).toMatchObject({ from: { S: "ana@example.test" }, recipient: { S: "support@kiff.test" } });
    expect(db.items.has("mid#<k1@example.test>")).toBe(false);
  });

  it("lets a send key left sending after the function died be claimed again, two minutes on", async () => {
    const sent: UpdateItemCommand[] = [];
    const db = { async send(c: UpdateItemCommand): Promise<any> { sent.push(c); return { Attributes: { state: { S: "sending" } } }; } };
    expect(await dynamoSending(db, "t", now).claim("run-1:reply")).toBe("retry");
    expect(sent[0]!.input).toMatchObject({
      ConditionExpression: "attribute_not_exists(pk) OR #s = :failed OR (#s = :sending AND claimedAt < :stale)",
      ExpressionAttributeValues: { ":stale": { N: String(Date.parse("2026-11-27T18:00:00Z") / 1000 - 120) } },
    });
  });

  it("passes on a failure, so the webhook answers 500 and SNS sends it again", async () => {
    const store = dynamoStore(fake("PutItemCommand"), "t", now);
    await expect(store.file({ messageId: "m1", objectKey: "in/m1", at: now().toISOString(), purgeAt, state: "pending_scan" })).rejects.toThrow("dynamo down");
  });
});
