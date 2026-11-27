import { createPublicKey, verify } from "node:crypto";

/**
 * An Amazon SNS message posted to loge's webhook, checked before anything in it is read: from the one topic loge
 * subscribed to, signed by SNS with a certificate fetched only from an SNS host, and fresh. Anything else is refused,
 * and a refused message is never confirmed, stored or passed on.
 */
export interface SnsMessage {
  Type: "Notification" | "SubscriptionConfirmation" | "UnsubscribeConfirmation";
  MessageId: string;
  TopicArn: string;
  Message: string;
  Timestamp: string;
  SignatureVersion: string;
  Signature: string;
  SigningCertURL: string;
  Subject?: string;
  SubscribeURL?: string;
  Token?: string;
}

export interface SnsCheck {
  /** The only topic accepted: loge's own inbound topic. */
  topicArn: string;
  /** Fetches a signing certificate (PEM) by URL. Only ever called with a URL `certificateURL` accepted. */
  certificate: (url: string) => Promise<string>;
  now: () => Date;
  /** How old a message may be. SNS retries for at most an hour by default. */
  maxAgeMs?: number;
}

export type SnsVerdict = { ok: true; message: SnsMessage } | { ok: false; why: string };

const FIELDS: Record<SnsMessage["Type"], (keyof SnsMessage)[]> = {
  Notification: ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"],
  SubscriptionConfirmation: ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"],
  UnsubscribeConfirmation: ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"],
};

/** Whether a signing certificate may be fetched from this URL: HTTPS, an SNS host in a real region, a .pem file. */
export function certificateURL(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return (
    u.protocol === "https:" &&
    u.port === "" &&
    u.username === "" &&
    u.password === "" &&
    /^sns\.[a-z]{2}(-[a-z]+)+-\d\.amazonaws\.com$/.test(u.hostname) &&
    /^\/[A-Za-z0-9._-]+\.pem$/.test(u.pathname) &&
    u.search === ""
  );
}

/** What SNS signs: each present field's name and value, a line each, in its fixed order. */
export function stringToSign(m: SnsMessage): string {
  return FIELDS[m.Type].filter((k) => m[k] !== undefined).map((k) => `${k}\n${m[k]}\n`).join("");
}

export async function checkSns(body: string, check: SnsCheck): Promise<SnsVerdict> {
  let m: SnsMessage;
  try {
    m = JSON.parse(body) as SnsMessage;
  } catch {
    return { ok: false, why: "not JSON" };
  }
  if (typeof m !== "object" || m === null || !(m.Type in FIELDS)) return { ok: false, why: "not an SNS message" };
  for (const k of FIELDS[m.Type].filter((k) => k !== "Subject")) {
    if (typeof m[k] !== "string") return { ok: false, why: `no ${k}` };
  }
  if (m.Subject !== undefined && typeof m.Subject !== "string") return { ok: false, why: "a Subject that isn't text" };
  if (m.TopicArn !== check.topicArn) return { ok: false, why: "another topic" };
  // Version 1 signs with SHA1, which loge doesn't accept: the topic is set to version 2.
  if (m.SignatureVersion !== "2") return { ok: false, why: "not signature version 2" };
  if (typeof m.SigningCertURL !== "string" || !certificateURL(m.SigningCertURL)) return { ok: false, why: "a certificate from elsewhere" };
  const at = Date.parse(m.Timestamp);
  const age = check.now().getTime() - at;
  if (!Number.isFinite(at) || age > (check.maxAgeMs ?? 60 * 60 * 1000) || age < -5 * 60 * 1000) return { ok: false, why: "not fresh" };
  let pem: string;
  try {
    pem = await check.certificate(m.SigningCertURL);
  } catch {
    return { ok: false, why: "the certificate can't be fetched" };
  }
  let good = false;
  try {
    good = verify("RSA-SHA256", Buffer.from(stringToSign(m), "utf8"), createPublicKey(pem), Buffer.from(m.Signature, "base64"));
  } catch {
    good = false;
  }
  return good ? { ok: true, message: m } : { ok: false, why: "the signature doesn't check" };
}
