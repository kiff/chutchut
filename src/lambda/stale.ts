import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import { config } from "../config.js";
import { dynamoShelf } from "../dynamo.js";
import { stale } from "../reader.js";

// Once a day: mail still waiting for its malware scan after three days is raised on the alerts topic, with its
// message ids only, never a sender or a subject.
const c = config(process.env);
const shelf = dynamoShelf(new DynamoDBClient({ region: c.region }), c.table);
const sns = new SNSClient({ region: c.region });

export async function handler(): Promise<number> {
  const ids = await stale(shelf, new Date());
  if (ids.length > 0) {
    await sns.send(new PublishCommand({
      TopicArn: c.alertsArn,
      Subject: "chutchut: mail waiting for its malware scan",
      Message: `${ids.length} message(s) have waited more than three days for their malware scan and expire 30 days after arriving. Ids: ${ids.slice(0, 50).join(", ")}`,
    }));
  }
  return ids.length;
}
