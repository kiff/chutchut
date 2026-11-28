import { anyone, pairing, type Pairing } from "./door.js";
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
  /** "inbox": chutchut's own; "tafs": tafs cloud's mail provider, where tafs keeps the pairing. */
  mode: "inbox" | "tafs";
  /** Inbox mode: the paired senders. tafs mode: every proven sender (tafs decides key or knock). */
  paired: Pairing;
  /** The addresses and domains SES receives for (CHUTCHUT_RECIPIENTS): the per-address cap counts by them. */
  entries: string[];
  /** tafs mode: tafs cloud's email webhook, and the SSM parameters holding the webhook's secret and the read key's hash. */
  tafsWebhook?: string;
  webhookSecretParam?: string;
  readKeyParam?: string;
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
  const mode = (env.CHUTCHUT_MODE ?? "inbox") as Config["mode"];
  if (mode !== "inbox" && mode !== "tafs") throw new Error("CHUTCHUT_MODE is inbox or tafs");
  let tafs = {};
  if (mode === "tafs") {
    const url = need(env, "CHUTCHUT_TAFS_WEBHOOK");
    if (!/^https:\/\/[a-z0-9.-]+(:\d+)?\/v1\/doors\/email$/.test(url)) throw new Error("CHUTCHUT_TAFS_WEBHOOK isn't tafs cloud's email webhook");
    const param = (name: string) => { const v = need(env, name); if (!/^\/[A-Za-z0-9_./-]+$/.test(v)) throw new Error(`${name} isn't an SSM parameter`); return v; };
    tafs = { tafsWebhook: url, webhookSecretParam: param("CHUTCHUT_WEBHOOK_SECRET_PARAM"), readKeyParam: param("CHUTCHUT_READ_KEY_PARAM") };
  }
  return {
    mode,
    ...tafs,
    region: need(env, "AWS_REGION"),
    bucket: need(env, "CHUTCHUT_BUCKET"),
    table: need(env, "CHUTCHUT_TABLE"),
    topicArn,
    alertsArn,
    paired: mode === "tafs" ? anyone() : pairing(paired),
    entries: (env.CHUTCHUT_RECIPIENTS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter((e) => e !== ""),
    // The Solo plan's limits by default (one address): the design's numbers.
    limits: {
      inboundPerDay: count(env, "CHUTCHUT_INBOUND_PER_DAY", 100),
      // One address on the Solo plan, so the account's cap is the address's by default.
      accountPerDay: count(env, "CHUTCHUT_ACCOUNT_PER_DAY", 100),
      knocksPerSender: count(env, "CHUTCHUT_KNOCKS_PER_SENDER", 1),
      knocksPerDomain: count(env, "CHUTCHUT_KNOCKS_PER_DOMAIN", 10),
      knocksPerDay: count(env, "CHUTCHUT_KNOCKS_PER_DAY", 50),
      noticesPerDay: count(env, "CHUTCHUT_NOTICES_PER_DAY", 50),
    },
  };
}
