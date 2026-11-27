import { door, type Door, type Pairing } from "./door.js";
import { mailboxes, sender } from "./from.js";

/**
 * What SES says about one received message (its "Received" notification, inside a checked SNS message), and where the
 * message goes because of it. Nothing here reads the body: only SES's verdicts and the message's own From and Sender.
 *
 * - A **virus** found, or **spam** found: refused. It never reaches an agent or the owner's knocks; the Record keeps
 *   its id.
 * - A virus scan that didn't finish: held, for the owner, never for an agent.
 * - Otherwise the door decides, and only mail whose DMARC passed can be a paired sender's.
 */
/** `recipient` is the address of ours it came to (SES's receipt.recipients, the first, lower-cased): caps count per address. */
/**
 * SES's sender checks as tafs's door reads them ("pass", "fail", …), kept only for a sender proven here.
 */
export interface Auth { spf: string; dkim: string; dmarc: string }

/** `rfcId`: the message's own Message-ID as SES read it, which a reply names in In-Reply-To. */
export type Route = { to: Door; messageId: string; objectKey: string; recipient: string; from: string | undefined; auth: Auth | null; rfcId?: string }
  | { to: "held" | "refused"; messageId: string; objectKey: string; recipient: string; why: string };

interface Verdict { status?: string }
interface Received {
  notificationType?: string;
  mail?: {
    messageId?: string;
    headersTruncated?: boolean;
    headers?: { name?: string; value?: string }[];
    commonHeaders?: { from?: unknown; messageId?: unknown };
  };
  receipt?: {
    recipients?: unknown;
    spamVerdict?: Verdict; virusVerdict?: Verdict; dkimVerdict?: Verdict; spfVerdict?: Verdict; dmarcVerdict?: Verdict;
    action?: { type?: string; bucketName?: string; objectKey?: string };
  };
}

/** The route for one SES notification, or undefined when it isn't a whole one (it's then refused by the caller). */
export function route(message: string, paired: Pairing, bucket: string): Route | undefined {
  let n: Received;
  try {
    n = JSON.parse(message) as Received;
  } catch {
    return undefined;
  }
  if (typeof n !== "object" || n === null || n.notificationType !== "Received") return undefined;
  const messageId = n.mail?.messageId;
  const action = n.receipt?.action;
  if (typeof messageId !== "string" || messageId === "" || action?.type !== "S3" || action.bucketName !== bucket || typeof action.objectKey !== "string") {
    return undefined;
  }
  const objectKey = action.objectKey;
  const listed = n.receipt?.recipients;
  const recipient = Array.isArray(listed) && typeof listed[0] === "string" && listed[0] !== "" ? listed[0].toLowerCase() : "(no recipient)";
  const status = (v: Verdict | undefined) => (typeof v?.status === "string" ? v.status : "MISSING");
  const virus = status(n.receipt?.virusVerdict);
  const spam = status(n.receipt?.spamVerdict);
  if (virus === "FAIL") return { to: "refused", messageId, objectKey, recipient, why: "a virus" };
  if (spam === "FAIL") return { to: "refused", messageId, objectKey, recipient, why: "spam" };
  if (virus !== "PASS") return { to: "held", messageId, objectKey, recipient, why: "the virus scan didn't finish" };
  // One header of each, as sent: a message with two From headers has no sender at all.
  const headers = (n.mail?.headers ?? []).filter((h) => typeof h?.name === "string");
  const named = (name: string) => headers.filter((h) => h.name!.toLowerCase() === name).map((h) => (typeof h.value === "string" ? h.value : ""));
  const froms = named("from");
  const senders = named("sender");
  // A cut header list may have lost a second From or a Sender: no sender then.
  const whole = n.mail?.headersTruncated === false || n.mail?.headersTruncated === undefined;
  const read = whole && froms.length === 1 && senders.length <= 1 ? sender(froms[0], senders[0]) : undefined;
  // SES's own reading of From must be one mailbox with the same address, or there's no sender: DMARC was judged on
  // SES's reading, so a reading of ours that differs must never name the sender.
  const ses = n.mail?.commonHeaders?.from;
  const sesOne = Array.isArray(ses) && ses.length === 1 && typeof ses[0] === "string" ? mailboxes(ses[0]) : undefined;
  const from = read !== undefined && sesOne?.length === 1 && sesOne[0]!.toLowerCase() === read.toLowerCase() ? read : undefined;
  // Spam that SES couldn't judge may still knock, but never passes as a paired sender's.
  const aligned = status(n.receipt?.dmarcVerdict) === "PASS" && spam === "PASS";
  const lower = (v: Verdict | undefined) => status(v).toLowerCase();
  // Sent on only for a sender proven here (one From read as SES reads it, DMARC passed, spam clean): anything else
  // reaches tafs with none, so it can only knock there, never be paired on a looser reading.
  const auth = from === undefined || !aligned ? null : { spf: lower(n.receipt?.spfVerdict), dkim: lower(n.receipt?.dkimVerdict), dmarc: lower(n.receipt?.dmarcVerdict) };
  const mid = n.mail?.commonHeaders?.messageId;
  const rfcId = typeof mid === "string" && /^<[^<>\s]{1,250}>$/.test(mid.trim()) ? { rfcId: mid.trim() } : {};
  return { to: from === undefined ? "knock" : door({ address: from, dmarcAligned: aligned }, paired), messageId, objectKey, recipient, from, auth, ...rfcId };
}
