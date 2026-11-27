import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { config } from "../config.js";
import { authorized, MESSAGE_ID, readable, receivedJson } from "../provider.js";
import type { Auth } from "../ses.js";
import { secret } from "./secrets.js";

// tafs cloud's read of one message (GET /emails/receiving/{id}), behind a function URL and the read key.
const c = config(process.env);
const db = new DynamoDBClient({ region: c.region });
const s3 = new S3Client({ region: c.region });

interface UrlEvent { rawPath?: string; headers?: Record<string, string | undefined>; requestContext?: { http?: { method?: string } } }

const answer = (statusCode: number, body: unknown) => ({ statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

export async function handler(event: UrlEvent) {
  if (c.mode !== "tafs" || c.readKeyParam === undefined) return answer(404, { error: "not found" });
  if (!authorized(event.headers?.authorization, await secret(c.region, c.readKeyParam))) return answer(401, { error: "unauthorized" });
  const m = /^\/emails\/receiving\/([^/]+)$/.exec(event.rawPath ?? "");
  if (event.requestContext?.http?.method !== "GET" || m === null) return answer(404, { error: "not found" });
  const id = m[1]!;
  if (!MESSAGE_ID.test(id)) return answer(400, { error: "not an email id" });
  const got = await db.send(new GetItemCommand({
    TableName: c.table, Key: { pk: { S: `msg#${id}` } }, ConsistentRead: true,
    ProjectionExpression: "#s, #at, shown, clean, auth, objectKey, purgeAt", ExpressionAttributeNames: { "#s": "state", "#at": "at" },
  }));
  const i = got.Item;
  const item = i && { state: i.state?.S ?? "", shown: i.shown?.S === "yes", clean: i.clean?.S === "yes" };
  // Never one the scan didn't clear, or one past its 30 days: the same answer as one that isn't there.
  if (!item || !readable(item) || Date.parse(i.purgeAt?.S ?? "") <= Date.now()) return answer(404, { error: "not found" });
  const obj = await s3.send(new GetObjectCommand({ Bucket: c.bucket, Key: i.objectKey?.S ?? `in/${id}` }));
  const raw = Buffer.from(await obj.Body!.transformToByteArray());
  const auth = i.auth?.S !== undefined ? (JSON.parse(i.auth.S) as Auth) : undefined;
  return answer(200, await receivedJson(id, raw, { at: i.at?.S ?? "", ...(auth ? { auth } : {}) }));
}
