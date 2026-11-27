import {
  ConditionalCheckFailedException, GetItemCommand, PutItemCommand, ScanCommand, UpdateItemCommand, type AttributeValue, type DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import type { Knock, KnockShelf } from "./knocks.js";
import type { Shelf } from "./reader.js";
import type { Filed, Store } from "./webhook.js";

/**
 * The webhook's `Store` in one DynamoDB table (`deploy/aws.sh` makes it): each filed message is one item keyed
 * `msg#<id>`, each day's counter one item keyed `count#<name>`.
 *
 * - `file` is one conditional put (`attribute_not_exists(pk)`), so a message is filed once, and a put that fails
 *   leaves nothing for SNS's retry to trip on.
 * - Every filed item expires at its `purgeAt`, 30 days on (the table's TTL on `expiresAt`). DynamoDB removes expired
 *   items within about two days, so whatever lists them also leaves out any past its `purgeAt`.
 * - A day's counter expires two days after it's first counted.
 * - Nothing here stores a message's body: only what `Filed` holds (ids, the sender's address, the state).
 */
const DAY_S = 24 * 60 * 60;

export function dynamoStore(client: Pick<DynamoDBClient, "send">, table: string, now: () => Date): Store {
  return {
    async filed(messageId) {
      const got = await client.send(new GetItemCommand({
        TableName: table, Key: { pk: { S: `msg#${messageId}` } }, ProjectionExpression: "pk", ConsistentRead: true,
      }));
      return got.Item !== undefined;
    },

    async bump(counter) {
      const expires = Math.floor(now().getTime() / 1000) + 2 * DAY_S;
      const out = await client.send(new UpdateItemCommand({
        TableName: table, Key: { pk: { S: `count#${counter}` } },
        UpdateExpression: "ADD n :one SET expiresAt = if_not_exists(expiresAt, :expires)",
        ExpressionAttributeValues: { ":one": { N: "1" }, ":expires": { N: String(expires) } },
        ReturnValues: "UPDATED_NEW",
      }));
      const n = Number(out.Attributes?.n?.N);
      if (!Number.isSafeInteger(n) || n < 1) throw new Error("a counter that didn't count");
      return n;
    },

    async file(item: Filed) {
      const fields: Record<string, { S: string } | { N: string }> = {
        pk: { S: `msg#${item.messageId}` },
        messageId: { S: item.messageId }, objectKey: { S: item.objectKey }, at: { S: item.at }, state: { S: item.state },
        purgeAt: { S: item.purgeAt }, expiresAt: { N: String(Math.floor(Date.parse(item.purgeAt) / 1000)) },
      };
      if (item.from !== undefined) fields.from = { S: item.from };
      if (item.auth !== undefined) fields.auth = { S: JSON.stringify(item.auth) };
      if (item.recipient !== undefined) fields.recipient = { S: item.recipient };
      if (item.rfcId !== undefined) fields.rfcId = { S: item.rfcId };
      if (item.state === "knock") fields.shown = { S: item.shown ? "yes" : "no" };
      if (item.state === "held" || item.state === "refused") fields.why = { S: item.why };
      try {
        await client.send(new PutItemCommand({ TableName: table, Item: fields, ConditionExpression: "attribute_not_exists(pk)" }));
        // The thread's key, so a reply naming this Message-ID finds who wrote and to which address of ours. It expires
        // with the message. A Message-ID already known keeps its first writer: a second message can't take a thread over.
        // Only for a sender proven here (its sender check filed): a forged From, a knock with no proof, gets no thread,
        // so no reply can ever go to someone who didn't write.
        if (item.auth !== undefined && item.rfcId !== undefined && item.from !== undefined && item.recipient !== undefined) {
          try {
            await client.send(new PutItemCommand({
              TableName: table, ConditionExpression: "attribute_not_exists(pk)",
              Item: {
                pk: { S: `mid#${item.rfcId}` }, messageId: { S: item.messageId }, from: { S: item.from },
                recipient: { S: item.recipient }, purgeAt: fields.purgeAt!, expiresAt: fields.expiresAt!,
              },
            }));
          } catch (e) {
            if (!(e instanceof ConditionalCheckFailedException)) throw e;
          }
        }
        return true;
      } catch (e) {
        if (e instanceof ConditionalCheckFailedException) return false;
        throw e;
      }
    },
  };
}

/**
 * The reader's `Shelf` on the same table. Each change is one conditional update on the item's state, so an event
 * GuardDuty sends twice changes it once, and nothing moves an item out of a state it isn't in.
 */
export function dynamoShelf(client: Pick<DynamoDBClient, "send">, table: string): Shelf {
  const key = (id: string) => ({ pk: { S: `msg#${id}` } });
  // "state" and "from" are DynamoDB reserved words, so they're always named through #s and #from.
  async function change(id: string, update: string, values: Record<string, { S: string }>, condition: string): Promise<boolean> {
    // DynamoDB refuses a name the expressions don't use, so each is named only where it's used.
    const names: Record<string, string> = {};
    if (`${update} ${condition}`.includes("#s")) names["#s"] = "state";
    if (update.includes("#from")) names["#from"] = "from";
    try {
      await client.send(new UpdateItemCommand({
        TableName: table, Key: key(id), UpdateExpression: update, ConditionExpression: condition,
        ...(Object.keys(names).length > 0 ? { ExpressionAttributeNames: names } : {}), ExpressionAttributeValues: values,
      }));
      return true;
    } catch (e) {
      if (e instanceof ConditionalCheckFailedException) return false;
      throw e;
    }
  }
  return {
    async get(id) {
      const got = await client.send(new GetItemCommand({
        TableName: table, Key: key(id), ProjectionExpression: "#s, #at, shown, clean, notified",
        ExpressionAttributeNames: { "#s": "state", "#at": "at" }, ConsistentRead: true,
      }));
      const state = got.Item?.state?.S;
      const at = got.Item?.at?.S;
      if (state === undefined || at === undefined) return undefined;
      return { state, at, shown: got.Item?.shown?.S === "yes", clean: got.Item?.clean?.S === "yes", notified: got.Item?.notified?.S === "yes" };
    },
    // Kept mail loses its expiry: it stays until the owner deletes it.
    keep: (id, keptKey) => change(id, "SET #s = :mail, objectKey = :kept REMOVE expiresAt, purgeAt",
      { ":mail": { S: "mail" }, ":kept": { S: keptKey }, ":pending": { S: "pending_scan" } }, "#s = :pending"),
    // Refused mail never keeps its sender's address, and keeps its 30-day expiry.
    refuse: (id, why) => change(id, "SET #s = :refused, why = :why REMOVE #from, shown",
      { ":refused": { S: "refused" }, ":why": { S: why }, ":pending": { S: "pending_scan" }, ":knock": { S: "knock" }, ":held": { S: "held" } },
      "#s IN (:pending, :knock, :held)"),
    // tafs mode: mail a proven sender sent becomes clean, a shown knock is marked clean; both keep their expiry.
    async clear(id) {
      if (await change(id, "SET #s = :clean, clean = :yes", { ":clean": { S: "clean" }, ":yes": { S: "yes" }, ":pending": { S: "pending_scan" } }, "#s = :pending")) return true;
      return change(id, "SET clean = :yes", { ":yes": { S: "yes" }, ":knock": { S: "knock" }, ":shown": { S: "yes" } }, "#s = :knock AND shown = :shown");
    },
    notified: (id) => change(id, "SET notified = :yes", { ":yes": { S: "yes" } }, "attribute_not_exists(notified)"),
    hold: (id, why) => change(id, "SET #s = :held, why = :why",
      { ":held": { S: "held" }, ":why": { S: why }, ":pending": { S: "pending_scan" } }, "#s = :pending"),
    async pendingBefore(before) {
      const ids: string[] = [];
      let start: Record<string, AttributeValue> | undefined;
      do {
        const page = await client.send(new ScanCommand({
          TableName: table, FilterExpression: "#s = :pending AND #at < :before", ProjectionExpression: "messageId",
          ExpressionAttributeNames: { "#s": "state", "#at": "at" },
          ExpressionAttributeValues: { ":pending": { S: "pending_scan" }, ":before": { S: before } }, ExclusiveStartKey: start,
        }));
        for (const item of page.Items ?? []) if (item.messageId?.S !== undefined) ids.push(item.messageId.S);
        start = page.LastEvaluatedKey;
      } while (start !== undefined);
      return ids;
    },
  };
}

/** The knocks on the same table: a filtered scan, every page. At volume this becomes an index on state. */
export function dynamoKnocks(client: Pick<DynamoDBClient, "send">, table: string): KnockShelf {
  return {
    async knocks() {
      const out: Knock[] = [];
      let start: Record<string, AttributeValue> | undefined;
      do {
        const page = await client.send(new ScanCommand({
          TableName: table, FilterExpression: "#s = :knock", ProjectionExpression: "messageId, #at, purgeAt, #from, shown",
          ExpressionAttributeNames: { "#s": "state", "#at": "at", "#from": "from" },
          ExpressionAttributeValues: { ":knock": { S: "knock" } }, ExclusiveStartKey: start,
        }));
        for (const i of page.Items ?? []) {
          const messageId = i.messageId?.S, at = i.at?.S, purgeAt = i.purgeAt?.S;
          if (messageId === undefined || at === undefined || purgeAt === undefined) continue;
          out.push({ messageId, at, purgeAt, shown: i.shown?.S === "yes", ...(i.from?.S !== undefined ? { from: i.from.S } : {}) });
        }
        start = page.LastEvaluatedKey;
      } while (start !== undefined);
      return out;
    },
  };
}

/** The send's records on the same table: a thread by its Message-ID, and each idempotency key's state. */
export function dynamoSending(client: Pick<DynamoDBClient, "send">, table: string, now: () => Date) {
  return {
    async thread(rfcId: string) {
      const got = await client.send(new GetItemCommand({ TableName: table, Key: { pk: { S: `mid#${rfcId}` } }, ConsistentRead: true }));
      const i = got.Item;
      const messageId = i?.messageId?.S, from = i?.from?.S, recipient = i?.recipient?.S;
      return messageId && from && recipient ? { messageId, from, recipient } : undefined;
    },
    async item(messageId: string) {
      const got = await client.send(new GetItemCommand({
        TableName: table, Key: { pk: { S: `msg#${messageId}` } }, ConsistentRead: true,
        ProjectionExpression: "#s, shown, clean, purgeAt", ExpressionAttributeNames: { "#s": "state" },
      }));
      const i = got.Item;
      if (i?.state?.S === undefined) return undefined;
      return { state: i.state.S, shown: i.shown?.S === "yes", clean: i.clean?.S === "yes", ...(i.purgeAt?.S ? { purgeAt: i.purgeAt.S } : {}) };
    },
    /**
     * One conditional write: a new key, one whose send failed, or one left "sending" longer than a send can take (the
     * function died mid-send) becomes "sending"; anything else is answered as it stands.
     */
    async claim(key: string): Promise<"new" | "retry" | "sent" | "busy"> {
      const t = Math.floor(now().getTime() / 1000);
      try {
        const out = await client.send(new UpdateItemCommand({
          TableName: table, Key: { pk: { S: `send#${key}` } },
          UpdateExpression: "SET #s = :sending, claimedAt = :now, expiresAt = :expires",
          ConditionExpression: "attribute_not_exists(pk) OR #s = :failed OR (#s = :sending AND claimedAt < :stale)",
          ExpressionAttributeNames: { "#s": "state" },
          ExpressionAttributeValues: {
            ":sending": { S: "sending" }, ":failed": { S: "failed" }, ":now": { N: String(t) },
            ":stale": { N: String(t - 120) }, ":expires": { N: String(t + 7 * 24 * 60 * 60) },
          },
          ReturnValues: "UPDATED_OLD",
        }));
        return out.Attributes?.state?.S === undefined ? "new" : "retry";
      } catch (e) {
        if (!(e instanceof ConditionalCheckFailedException)) throw e;
        const got = await client.send(new GetItemCommand({
          TableName: table, Key: { pk: { S: `send#${key}` } }, ConsistentRead: true, ProjectionExpression: "#s", ExpressionAttributeNames: { "#s": "state" },
        }));
        return got.Item?.state?.S === "sent" ? "sent" : "busy";
      }
    },
    async done(key: string, ok: boolean) {
      await client.send(new UpdateItemCommand({
        TableName: table, Key: { pk: { S: `send#${key}` } }, UpdateExpression: "SET #s = :s",
        ExpressionAttributeNames: { "#s": "state" }, ExpressionAttributeValues: { ":s": { S: ok ? "sent" : "failed" } },
      }));
    },
  };
}
