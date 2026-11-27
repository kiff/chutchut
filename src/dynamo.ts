import { ConditionalCheckFailedException, GetItemCommand, PutItemCommand, UpdateItemCommand, type DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { Filed, Store } from "./webhook.js";

/**
 * The webhook's `Store` in one DynamoDB table (`deploy/aws.sh` makes it): each filed message is one item keyed
 * `msg#<id>`, each day's counter one item keyed `count#<name>`.
 *
 * - `file` is one conditional put (`attribute_not_exists(pk)`), so a message is filed once, and a put that fails
 *   leaves nothing for SNS's retry to trip on.
 * - A knock's item expires at its `purgeAt` (the table's TTL on `expiresAt`). DynamoDB removes expired items within
 *   about two days, so whatever lists knocks also leaves out any past its `purgeAt`.
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
      };
      if (item.from !== undefined) fields.from = { S: item.from };
      if (item.state === "knock") {
        fields.shown = { S: item.shown ? "yes" : "no" };
        fields.purgeAt = { S: item.purgeAt };
        fields.expiresAt = { N: String(Math.floor(Date.parse(item.purgeAt) / 1000)) };
      }
      if (item.state === "held" || item.state === "refused") fields.why = { S: item.why };
      try {
        await client.send(new PutItemCommand({ TableName: table, Item: fields, ConditionExpression: "attribute_not_exists(pk)" }));
        return true;
      } catch (e) {
        if (e instanceof ConditionalCheckFailedException) return false;
        throw e;
      }
    },
  };
}
