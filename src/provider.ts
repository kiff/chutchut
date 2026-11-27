import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { simpleParser } from "mailparser";
import type { Auth } from "./ses.js";

/**
 * chutchut as tafs cloud's mail provider: the same three things tafs cloud asks of its provider today.
 *
 * - `signedReceived`: the `email.received` webhook, signed as tafs cloud checks it (HMAC-SHA256 over
 *   "<id>.<timestamp>.<body>", base64, "v1,<signature>"), naming the message and nothing else.
 * - `receivedJson`: one message as tafs cloud reads it (`parseReceived`): its text and HTML from the scanned raw
 *   copy, its threading headers, how many attachments, and SES's sender checks only for a sender proven here.
 * - `authorized`: the read API's bearer key, compared by its SHA-256 in constant time.
 *
 * Only mail the scan cleared is ever readable (`readable`).
 */

/** The webhook's body and headers for one readable message. */
export function signedReceived(secret: string, messageId: string, now: Date): { body: string; headers: Record<string, string> } {
  const body = JSON.stringify({ type: "email.received", created_at: now.toISOString(), data: { email_id: messageId } });
  const id = `msg_${createHash("sha256").update(messageId).digest("hex").slice(0, 24)}`;
  const timestamp = String(Math.floor(now.getTime() / 1000));
  const key = secret.startsWith("whsec_") ? Buffer.from(secret.slice("whsec_".length), "base64") : Buffer.from(secret, "utf8");
  const signature = createHmac("sha256", key).update(`${id}.${timestamp}.${body}`).digest("base64");
  return { body, headers: { "content-type": "application/json", "svix-id": id, "svix-timestamp": timestamp, "svix-signature": `v1,${signature}` } };
}

/** Whether a filed item may be read by tafs: cleared by the scan, as mail a proven sender sent or a shown knock. */
export function readable(item: { state: string; shown?: boolean; clean?: boolean }): boolean {
  return item.state === "clean" || (item.state === "knock" && item.shown === true && item.clean === true);
}

/** The read API's key: `Authorization: Bearer <key>`, checked against the key's SHA-256 (hex). */
export function authorized(header: string | undefined, keySha256: string): boolean {
  const m = /^Bearer ([A-Za-z0-9._~+/=-]{16,512})$/.exec(header ?? "");
  if (m === null || !/^[0-9a-f]{64}$/.test(keySha256)) return false;
  const got = createHash("sha256").update(m[1]!).digest();
  return timingSafeEqual(got, Buffer.from(keySha256, "hex"));
}

/** The message ids tafs cloud asks for: SES's, which tafs's own check accepts. */
export const MESSAGE_ID = /^[A-Za-z0-9-]{1,100}$/;

/** One readable message as tafs cloud's `parseReceived` reads it. */
/**
 * `filed` is what chutchut proved and filed: the sender's address (for a proven sender), SES's sender check, and the
 * address of ours SES delivered it to. tafs reads the sender and the door from these, never from a looser reading of
 * the raw headers: the From is the filed address, and the door is the address SES delivered to (so mail Bcc'd or
 * forwarded to a door still reaches it, and a To header naming another door can't win over the real delivery).
 */
export async function receivedJson(messageId: string, raw: Buffer, filed: { at: string; auth?: Auth; from?: string; recipient?: string }): Promise<Record<string, unknown>> {
  const m = await simpleParser(raw, { skipHtmlToText: false, skipImageLinks: true, skipTextToHtml: true });
  const one = (v: unknown) => (typeof v === "string" ? v : Array.isArray(v) ? (typeof v[0] === "string" ? v[0] : "") : "");
  const header = (name: string) => one(m.headers.get(name));
  const list = (a: unknown) => (Array.isArray(a) ? a : a ? [a] : []).flatMap((x: { value?: { address?: string }[] }) => x.value ?? []).map((v) => v.address ?? "").filter((x) => x !== "");
  return {
    id: messageId,
    from: filed.from ?? m.from?.text ?? "",
    to: filed.recipient !== undefined && filed.recipient !== "(no recipient)" ? [filed.recipient] : list(m.to),
    ...(filed.recipient !== undefined && filed.recipient !== "(no recipient)" ? { received_for: [filed.recipient] } : {}),
    subject: m.subject ?? "",
    message_id: m.messageId ?? "",
    text: typeof m.text === "string" ? m.text : null,
    html: typeof m.html === "string" ? m.html : null,
    headers: { references: one(m.references !== undefined ? [].concat(m.references as never).join(" ") : header("references")), "in-reply-to": m.inReplyTo ?? "" },
    attachments: m.attachments.map((a) => ({ content_disposition: a.contentDisposition ?? "attachment" })),
    // Only for a sender proven here: anything else reaches tafs with none, so it can only knock there.
    authentication: filed.auth !== undefined && agrees(m.from?.value, filed.from) ? filed.auth : null,
    created_at: filed.at,
  };
}

/** Whether the raw message's own From names exactly the proven address: if the readings differ, no sender check goes. */
function agrees(raw: { address?: string }[] | undefined, proven: string | undefined): boolean {
  return proven !== undefined && raw?.length === 1 && (raw[0]?.address ?? "").toLowerCase() === proven.toLowerCase();
}
