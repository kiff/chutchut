import { door, type Door, type Pairing } from "./door.js";
import { sender } from "./from.js";

/**
 * What SES says about one received message (its "Received" notification, inside a checked SNS message), and where the
 * message goes because of it. Nothing here reads the body: only SES's verdicts and the message's own From and Sender.
 *
 * - A **virus** found, or **spam** found: refused. It never reaches an agent or the owner's knocks; the Record keeps
 *   its id.
 * - A virus scan that didn't finish: held, for the owner, never for an agent.
 * - Otherwise the door decides, and only mail whose DMARC passed can be a paired sender's.
 */
export type Route = { to: Door; messageId: string; objectKey: string; from: string | undefined }
  | { to: "held" | "refused"; messageId: string; objectKey: string; why: string };

interface Verdict { status?: string }
interface Received {
  notificationType?: string;
  mail?: { messageId?: string; headers?: { name?: string; value?: string }[] };
  receipt?: {
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
  const status = (v: Verdict | undefined) => (typeof v?.status === "string" ? v.status : "MISSING");
  const virus = status(n.receipt?.virusVerdict);
  const spam = status(n.receipt?.spamVerdict);
  if (virus === "FAIL") return { to: "refused", messageId, objectKey, why: "a virus" };
  if (spam === "FAIL") return { to: "refused", messageId, objectKey, why: "spam" };
  if (virus !== "PASS") return { to: "held", messageId, objectKey, why: "the virus scan didn't finish" };
  // One header of each, as sent: a message with two From headers has no sender at all.
  const headers = (n.mail?.headers ?? []).filter((h) => typeof h?.name === "string");
  const named = (name: string) => headers.filter((h) => h.name!.toLowerCase() === name).map((h) => (typeof h.value === "string" ? h.value : ""));
  const froms = named("from");
  const senders = named("sender");
  const from = froms.length === 1 && senders.length <= 1 ? sender(froms[0], senders[0]) : undefined;
  // Spam that SES couldn't judge may still knock, but never passes as a paired sender's.
  const aligned = status(n.receipt?.dmarcVerdict) === "PASS" && spam === "PASS";
  return { to: from === undefined ? "knock" : door({ address: from, dmarcAligned: aligned }, paired), messageId, objectKey, from };
}
