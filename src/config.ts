import { pairing, type Pairing } from "./door.js";
import type { Limits } from "./webhook.js";

/**
 * What a deployed function reads from its environment (`deploy/aws.sh` sets it). Each value is checked at start, so a
 * function with a missing or malformed setting fails before it touches any mail.
 */
export interface Config {
  region: string;
  bucket: string;
  table: string;
  topicArn: string;
  /** The topic the daily stale alert publishes to. */
  alertsArn: string;
  /** The paired senders' addresses, until pairing is kept in the table. */
  paired: Pairing;
  limits: Limits;
}

function need(env: Record<string, string | undefined>, name: string): string {
  const v = env[name];
  if (v === undefined || v.trim() === "") throw new Error(`${name} isn't set`);
  return v.trim();
}

function count(env: Record<string, string | undefined>, name: string, fallback: number): number {
  const v = env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name} isn't a whole number`);
  return n;
}

export function config(env: Record<string, string | undefined>): Config {
  const topicArn = need(env, "CHUTCHUT_TOPIC_ARN");
  if (!/^arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+$/.test(topicArn)) throw new Error("CHUTCHUT_TOPIC_ARN isn't a topic");
  const alertsArn = need(env, "CHUTCHUT_ALERTS_ARN");
  if (!/^arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+$/.test(alertsArn)) throw new Error("CHUTCHUT_ALERTS_ARN isn't a topic");
  const paired = (env.CHUTCHUT_PAIRED ?? "").split(",").map((a) => a.trim()).filter((a) => a !== "");
  return {
    region: need(env, "AWS_REGION"),
    bucket: need(env, "CHUTCHUT_BUCKET"),
    table: need(env, "CHUTCHUT_TABLE"),
    topicArn,
    alertsArn,
    paired: pairing(paired),
    // The Solo plan's limits by default (one address): the design's numbers.
    limits: {
      inboundPerDay: count(env, "CHUTCHUT_INBOUND_PER_DAY", 100),
      knocksPerSender: count(env, "CHUTCHUT_KNOCKS_PER_SENDER", 1),
      knocksPerDomain: count(env, "CHUTCHUT_KNOCKS_PER_DOMAIN", 10),
      knocksPerDay: count(env, "CHUTCHUT_KNOCKS_PER_DAY", 50),
    },
  };
}
