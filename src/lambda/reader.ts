import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { CopyObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { config } from "../config.js";
import { dynamoShelf } from "../dynamo.js";
import { read } from "../reader.js";

// The reader behind an EventBridge rule: GuardDuty's scan result for each object under in/.
const c = config(process.env);
const shelf = dynamoShelf(new DynamoDBClient({ region: c.region }), c.table);
const s3 = new S3Client({ region: c.region });

export async function handler(event: unknown): Promise<string> {
  return read(event, {
    bucket: c.bucket,
    shelf,
    copy: async (from, to) => {
      await s3.send(new CopyObjectCommand({
        Bucket: c.bucket, Key: to, CopySource: `${c.bucket}/${encodeURIComponent(from)}`, ServerSideEncryption: "AES256",
      }));
    },
  });
}
