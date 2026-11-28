import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { dynamoSending, dynamoStore } from "../dynamo.js";
import { sendReply, type Reply } from "../send.js";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { config } from "../config.js";
import { authorized, MESSAGE_ID, readable, receivedJson } from "../provider.js";
import type { Auth } from "../ses.js";
import { secret } from "./secrets.js";

// tafs cloud's read of one message (GET /emails/receiving/{id}) and its replies (POST /emails), behind a function URL
// and the read key.
const c = config(process.env);
const db = new DynamoDBClient({ region: c.region });
const s3 = new S3Client({ region: c.region });
const ses = new SESv2Client({ region: c.region });
const sending = { ...dynamoSending(db, c.table, () => new Date()), bump: dynamoStore(db, c.table, () => new Date()).bump };

interface UrlEvent {
  rawPath?: string; body?: string; isBase64Encoded?: boolean;
  headers?: Record<string, string | undefined>; requestContext?: { http?: { method?: string } };
}

const answer = (statusCode: number, body: unknown) => ({ statusCode, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

export async function handler(event: UrlEvent) {
  if (c.mode !== "tafs" || c.readKeyParam === undefined) return answer(404, { error: "not found" });
  if (!authorized(event.headers?.authorization, await secret(c.region, c.readKeyParam))) return answer(401, { error: "unauthorized" });
  if (event.rawPath === "/emails" && event.requestContext?.http?.method === "POST") return send(event);
  const m = /^\/emails\/receiving\/([^/]+)$/.exec(event.rawPath ?? "");
  if (event.requestContext?.http?.method !== "GET" || m === null) return answer(404, { error: "not found" });
  const id = m[1]!;
  if (!MESSAGE_ID.test(id)) return answer(400, { error: "not an email id" });
  const got = await db.send(new GetItemCommand({
    TableName: c.table, Key: { pk: { S: `msg#${id}` } }, ConsistentRead: true,
    // `auth` is one of DynamoDB's reserved words, as `state`, `at` and `from` are: each is named through a #name.
    ProjectionExpression: "#s, #at, shown, clean, #auth, objectKey, purgeAt, #from, recipient",
    ExpressionAttributeNames: { "#s": "state", "#at": "at", "#from": "from", "#auth": "auth" },
  }));
  const i = got.Item;
  const item = i && { state: i.state?.S ?? "", shown: i.shown?.S === "yes", clean: i.clean?.S === "yes" };
  // Never one the scan didn't clear, or one past its 30 days: the same answer as one that isn't there.
  if (!item || !readable(item) || !(Date.parse(i.purgeAt?.S ?? "") > Date.now())) return answer(404, { error: "not found" });
  const obj = await s3.send(new GetObjectCommand({ Bucket: c.bucket, Key: i.objectKey?.S ?? `in/${id}` }));
  const raw = Buffer.from(await obj.Body!.transformToByteArray());
  const auth = i.auth?.S !== undefined ? (JSON.parse(i.auth.S) as Auth) : undefined;
  const filed = {
    at: i.at?.S ?? "", ...(auth ? { auth } : {}),
    ...(i.from?.S !== undefined ? { from: i.from.S } : {}), ...(i.recipient?.S !== undefined ? { recipient: i.recipient.S } : {}),
  };
  return answer(200, await receivedJson(id, raw, filed));
}

// tafs's send(): its body as it posts it, the idempotency key in its header.
async function send(event: UrlEvent) {
  const text = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : (event.body ?? "");
  if (text.length > 200_000) return answer(413, { error: "too large" });
  let b: { from?: unknown; to?: unknown; subject?: unknown; text?: unknown; headers?: Record<string, unknown>; notice?: unknown };
  try {
    b = JSON.parse(text);
  } catch {
    return answer(400, { error: "not JSON" });
  }
  const h = b.headers ?? {};
  const reply: Reply = {
    from: typeof b.from === "string" ? b.from : "", to: Array.isArray(b.to) ? b.to.filter((x): x is string => typeof x === "string") : [],
    subject: typeof b.subject === "string" ? b.subject : "", text: typeof b.text === "string" ? b.text : "",
    ...(typeof h["In-Reply-To"] === "string" ? { inReplyTo: h["In-Reply-To"] } : {}),
    ...(typeof h.References === "string" ? { references: h.References } : {}),
    ...(event.headers?.["idempotency-key"] !== undefined ? { idempotencyKey: event.headers["idempotency-key"] } : {}),
    ...(b.notice === true ? { notice: true } : {}),
  };
  const out = await sendReply(reply, {
    ...sending, perDay: c.limits.inboundPerDay, accountPerDay: c.limits.accountPerDay, noticesPerDay: c.limits.noticesPerDay, noticesPerRecipient: c.limits.noticesPerRecipient,
    entries: c.entries, now: () => new Date(),
    transport: async (r) => {
      await ses.send(new SendEmailCommand({
        FromEmailAddress: r.from, Destination: { ToAddresses: [r.to] },
        Content: { Simple: {
          Subject: { Data: r.subject, Charset: "UTF-8" }, Body: { Text: { Data: r.text, Charset: "UTF-8" } },
          // A reply is threaded under the message it answers; a notice answers none.
          ...(r.inReplyTo !== "" ? { Headers: [{ Name: "In-Reply-To", Value: r.inReplyTo }, { Name: "References", Value: r.references }] } : {}),
        } },
      }));
    },
  });
  return answer(out.status, out.status === 200 ? { id: reply.idempotencyKey } : { error: out.said });
}
