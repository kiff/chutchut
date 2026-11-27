import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { config } from "../config.js";
import { dynamoStore } from "../dynamo.js";
import { certificateURL } from "../sns.js";
import { subscribeURL, webhook } from "../webhook.js";

// The webhook behind a Lambda function URL: SNS posts each notice here.
const c = config(process.env);
const db = new DynamoDBClient({ region: c.region });
const store = dynamoStore(db, c.table, () => new Date());
const certificates = new Map<string, string>();

async function certificate(url: string): Promise<string> {
  if (!certificateURL(url)) throw new Error("a certificate from elsewhere");
  const known = certificates.get(url);
  if (known !== undefined) return known;
  const res = await fetch(url, { redirect: "error" });
  if (!res.ok) throw new Error(`certificate: ${res.status}`);
  const pem = await res.text();
  certificates.set(url, pem);
  return pem;
}

interface UrlEvent { body?: string; isBase64Encoded?: boolean; requestContext?: { http?: { method?: string } } }

export async function handler(event: UrlEvent): Promise<{ statusCode: number; body: string }> {
  if (event.requestContext?.http?.method !== "POST") return { statusCode: 405, body: "POST only" };
  const body = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : (event.body ?? "");
  // SNS's notices are small; anything large isn't one.
  if (body.length > 256 * 1024) return { statusCode: 413, body: "too large" };
  const answer = await webhook(body, {
    sns: { topicArn: c.topicArn, now: () => new Date(), certificate },
    bucket: c.bucket,
    entries: c.entries,
    paired: async () => c.paired,
    limits: c.limits,
    store,
    confirm: async (url) => {
      if (!subscribeURL(url, c.topicArn)) throw new Error("a confirmation link from elsewhere");
      const res = await fetch(url, { redirect: "error" });
      if (!res.ok) throw new Error(`confirm: ${res.status}`);
    },
  });
  return { statusCode: answer.status, body: answer.said };
}
