import { mailboxes } from "./from.js";
import { readable } from "./provider.js";

/**
 * A reply tafs cloud asks chutchut to send (its `send()`: `POST /emails`), checked before anything goes out:
 *
 * - **only a reply:** it names the message it answers (In-Reply-To), and that message reached us, was cleared by its
 *   malware scan, and is still within its 30 days;
 * - **only to whoever wrote it:** one recipient, the address that message came from, and nobody else;
 * - **only from the address of ours it was written to;**
 * - **once per idempotency key:** a key already sent is answered as sent, never sent twice; a key whose send failed may
 *   be tried again;
 * - **under the per-address cap:** at most so many replies a day from each address of ours (held, never sent past it).
 *
 * The words are tafs's; this checks only who it goes to, from where, and how often.
 */
export interface Reply {
  from: string;
  to: string[];
  subject: string;
  text: string;
  inReplyTo?: string;
  references?: string;
  idempotencyKey?: string;
}

export interface Thread { messageId: string; from: string; recipient: string }

export interface Sending {
  /** The message a Message-ID names, as it was filed. */
  thread(rfcId: string): Promise<Thread | undefined>;
  item(messageId: string): Promise<{ state: string; shown?: boolean; clean?: boolean; purgeAt?: string } | undefined>;
  /** Claims an idempotency key: "new" (or "retry" after a failed send) to send now, "sent" if it went, "busy" if a send is under way. */
  claim(key: string): Promise<"new" | "retry" | "sent" | "busy">;
  done(key: string, ok: boolean): Promise<void>;
  bump(counter: string): Promise<number>;
  transport(reply: { from: string; to: string; subject: string; text: string; inReplyTo: string; references: string }): Promise<void>;
  perDay: number;
  now: () => Date;
}

export type Sent = { status: 200; said: "sent" | "sent before" } | { status: 400 | 403 | 409 | 429; said: string };

const ONE = (header: string): string | undefined => {
  const all = mailboxes(header);
  return all?.length === 1 ? all[0]!.toLowerCase() : undefined;
};

export async function sendReply(r: Reply, s: Sending): Promise<Sent> {
  if (typeof r.idempotencyKey !== "string" || !/^[A-Za-z0-9._:-]{8,200}$/.test(r.idempotencyKey)) return { status: 400, said: "an idempotency key is needed" };
  if (!Array.isArray(r.to) || r.to.length !== 1) return { status: 400, said: "one recipient only" };
  const to = ONE(r.to[0] ?? "");
  const from = ONE(r.from ?? "");
  if (to === undefined || from === undefined) return { status: 400, said: "not an address" };
  if (typeof r.subject !== "string" || typeof r.text !== "string" || r.text.length > 100_000 || /[\r\n]/.test(r.subject)) return { status: 400, said: "not a reply" };
  const inReplyTo = (r.inReplyTo ?? "").trim();
  if (!/^<[^<>\s]{1,250}>$/.test(inReplyTo)) return { status: 403, said: "only a reply to a message that came here" };
  const thread = await s.thread(inReplyTo);
  const item = thread && (await s.item(thread.messageId));
  if (thread === undefined || item === undefined || !readable(item) || !(Date.parse(item.purgeAt ?? "") > s.now().getTime())) {
    return { status: 403, said: "only a reply to a message that came here" };
  }
  if (thread.from.toLowerCase() !== to) return { status: 403, said: "only to whoever wrote it" };
  if (thread.recipient.toLowerCase() !== from) return { status: 403, said: "only from the address it was written to" };
  const claimed = await s.claim(r.idempotencyKey);
  if (claimed === "sent") return { status: 200, said: "sent before" };
  if (claimed === "busy") return { status: 409, said: "being sent" };
  const day = s.now().toISOString().slice(0, 10);
  if ((await s.bump(`${day}:${from}:sent`)) > s.perDay) {
    await s.done(r.idempotencyKey, false);
    return { status: 429, said: "over the day's replies from this address" };
  }
  // Threaded as the message it answers: its references, then its own id.
  const references = [(r.references ?? "").trim(), inReplyTo].filter((x) => x !== "").join(" ").split(/\s+/).filter((x, i, all) => all.indexOf(x) === i).join(" ");
  try {
    await s.transport({ from, to, subject: r.subject, text: r.text, inReplyTo, references });
  } catch (e) {
    await s.done(r.idempotencyKey, false);
    throw e;
  }
  await s.done(r.idempotencyKey, true);
  return { status: 200, said: "sent" };
}
