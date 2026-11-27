import type { Pairing } from "./door.js";
import { route, type Route } from "./ses.js";
import { checkSns, type SnsCheck } from "./sns.js";

/**
 * loge's webhook: one POST from SNS, checked, routed and filed. Nothing in a message is read here beyond SES's
 * verdicts and its From: a message's body and attachments are read later, and only once GuardDuty has tagged it
 * NO_THREATS_FOUND (`pending_scan` until then).
 *
 * - A message that doesn't check is refused (403) and nothing is filed.
 * - SNS's subscription is confirmed only for loge's own topic, at an SNS host in the topic's region.
 * - A message filed before (SNS retries) is filed once.
 * - **Holds, not drops:** past a cap, mail is filed and held, never lost. A knock past its caps is kept for the day's
 *   digest, not shown on its own.
 * - A knock is kept 30 days, then purged, and never sent to the AI unless the owner hands it to an agent.
 */
export interface Limits {
  /** Messages a day for this address, before the rest are held. */
  inboundPerDay: number;
  /** Knocks shown a day for one sender; the rest go to the digest. */
  knocksPerSender: number;
  /** Knocks shown a day for one sender domain; the rest go to the digest. */
  knocksPerDomain: number;
  /** Knocks shown a day in all; the rest go to the digest. */
  knocksPerDay: number;
}

export type Filed = {
  messageId: string;
  objectKey: string;
  at: string;
  from?: string;
} & (
  | { state: "pending_scan" } // paired: read once GuardDuty says NO_THREATS_FOUND
  | { state: "knock"; shown: boolean; purgeAt: string }
  | { state: "held"; why: string }
  | { state: "refused"; why: string }
);

/** Where filed mail and the day's counts live. A real store is its own change; tests use memory. */
export interface Store {
  /** True the first time a message id is claimed, false after. */
  claim(messageId: string): Promise<boolean>;
  /** Adds one to a day's counter and answers the new count. */
  bump(counter: string): Promise<number>;
  file(item: Filed): Promise<void>;
}

export interface Webhook {
  sns: SnsCheck;
  bucket: string;
  paired: () => Promise<Pairing>;
  limits: Limits;
  store: Store;
  /** Confirms SNS's subscription by fetching its SubscribeURL. Only ever called with a URL `subscribeURL` accepts. */
  confirm: (url: string) => Promise<void>;
}

export type Answer = { status: 200 | 400 | 403; said: string };

const DAY_MS = 24 * 60 * 60 * 1000;

/** Whether SNS's confirmation link may be fetched: HTTPS, SNS's host in the topic's region, confirming that topic. */
export function subscribeURL(url: string, topicArn: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  const region = topicArn.split(":")[3];
  return (
    u.protocol === "https:" && u.port === "" && u.username === "" && u.password === "" &&
    region !== undefined && u.hostname === `sns.${region}.amazonaws.com` && u.pathname === "/" &&
    u.searchParams.get("Action") === "ConfirmSubscription" && u.searchParams.get("TopicArn") === topicArn &&
    (u.searchParams.get("Token") ?? "") !== ""
  );
}

export async function webhook(body: string, w: Webhook): Promise<Answer> {
  const checked = await checkSns(body, w.sns);
  if (!checked.ok) return { status: 403, said: checked.why };
  const m = checked.message;
  if (m.Type === "SubscriptionConfirmation") {
    if (typeof m.SubscribeURL !== "string" || !subscribeURL(m.SubscribeURL, w.sns.topicArn)) {
      return { status: 403, said: "a confirmation link from elsewhere" };
    }
    await w.confirm(m.SubscribeURL);
    return { status: 200, said: "subscribed" };
  }
  if (m.Type === "UnsubscribeConfirmation") return { status: 200, said: "noted" };
  const r = route(m.Message, await w.paired(), w.bucket);
  if (r === undefined) return { status: 400, said: "not a received message for this bucket" };
  if (!(await w.store.claim(r.messageId))) return { status: 200, said: "filed before" };
  const now = w.sns.now();
  const at = now.toISOString();
  const day = at.slice(0, 10);
  const base = { messageId: r.messageId, objectKey: r.objectKey, at };
  await w.store.file(await place(r, base, day, now, w));
  return { status: 200, said: "filed" };
}

async function place(r: Route, base: { messageId: string; objectKey: string; at: string }, day: string, now: Date, w: Webhook): Promise<Filed> {
  if (r.to === "refused") return { ...base, state: "refused", why: r.why };
  if (r.to === "held") return { ...base, state: "held", why: r.why };
  const sent = "from" in r ? r.from : undefined;
  const from = sent === undefined ? {} : { from: sent };
  if ((await w.store.bump(`${day}:in`)) > w.limits.inboundPerDay) {
    return { ...base, ...from, state: "held", why: "over the day's mail" };
  }
  if (r.to === "paired") return { ...base, ...from, state: "pending_scan" };
  // A knock: shown only while it's within its sender's, its domain's and the day's caps. A knock past one cap isn't
  // counted against the next, so one noisy sender can't push other strangers' knocks into the digest.
  const sender = sent ?? "(no sender)";
  const domain = sent?.split("@")[1] ?? "(no sender)";
  const shown =
    (await w.store.bump(`${day}:knock:sender:${sender}`)) <= w.limits.knocksPerSender &&
    (await w.store.bump(`${day}:knock:domain:${domain}`)) <= w.limits.knocksPerDomain &&
    (await w.store.bump(`${day}:knock`)) <= w.limits.knocksPerDay;
  return { ...base, ...from, state: "knock", shown, purgeAt: new Date(now.getTime() + 30 * DAY_MS).toISOString() };
}
