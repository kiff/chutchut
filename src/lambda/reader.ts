import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { CopyObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { config } from "../config.js";
import { dynamoShelf } from "../dynamo.js";
import { read } from "../reader.js";
import { signedReceived } from "../provider.js";
import { secret } from "./secrets.js";

// The reader behind an EventBridge rule: GuardDuty's scan result for each object under in/.
const c = config(process.env);
const shelf = dynamoShelf(new DynamoDBClient({ region: c.region }), c.table);
const s3 = new S3Client({ region: c.region });

// tafs mode: tafs cloud's email webhook, signed with the secret kept in SSM.
async function notify(messageId: string): Promise<void> {
  if (c.mode !== "tafs" || c.tafsWebhook === undefined || c.webhookSecretParam === undefined) throw new Error("not tafs's provider");
  const { body, headers } = signedReceived(await secret(c.region, c.webhookSecretParam), messageId, new Date());
  const res = await fetch(c.tafsWebhook, { method: "POST", headers, body, redirect: "error" });
  if (!res.ok) throw new Error(`tafs cloud answered ${res.status}`);
}

export async function handler(event: unknown): Promise<string> {
  return read(event, {
    bucket: c.bucket,
    mode: c.mode,
    notify,
    shelf,
    copy: async (from, to) => {
      await s3.send(new CopyObjectCommand({
        // The copy keeps GuardDuty's scan tag (TaggingDirective COPY, the default): the role reads it on in/ and writes it on kept/.
        Bucket: c.bucket, Key: to, CopySource: `${c.bucket}/${encodeURIComponent(from)}`, ServerSideEncryption: "AES256", TaggingDirective: "COPY",
      }));
    },
  });
}
