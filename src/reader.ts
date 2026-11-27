/**
 * The reader: what happens to filed mail once GuardDuty has scanned it. GuardDuty tags each object under in/ and
 * sends its result to EventBridge; this takes that event. Nothing reads a message's body before this says it's clean.
 *
 * - **No threats found**, for mail a paired sender sent (`pending_scan`): its raw copy is copied to kept/, outside the
 *   30-day lifecycle on in/, and the item becomes the owner's mail (`mail`), with its expiry removed. It's now kept
 *   until the owner deletes it.
 * - **Threats found:** the item is refused ("malware") and loses its sender's address, whatever it was waiting as.
 * - **Any other result** (unsupported, access denied, failed): mail waiting for its scan is held, for the owner.
 * - **Waiting too long:** `stale` lists mail still waiting for its scan after a few days, so it's raised before its
 *   30 days run out and nothing a paired sender sent expires unseen.
 */
export interface Shelf {
  get(messageId: string): Promise<{ state: string; at: string } | undefined>;
  /** pending_scan → mail at keptKey, its expiry removed. False if it wasn't pending_scan. */
  keep(messageId: string, keptKey: string): Promise<boolean>;
  /** pending_scan, knock or held → refused, its sender's address removed. False otherwise. */
  refuse(messageId: string, why: string): Promise<boolean>;
  /** pending_scan → held. False otherwise. */
  hold(messageId: string, why: string): Promise<boolean>;
  /** The ids of mail still pending_scan that was filed before `before`. */
  pendingBefore(before: string): Promise<string[]>;
}

export interface Reader {
  bucket: string;
  shelf: Shelf;
  /** Copies one object in the bucket (S3 CopyObject). */
  copy: (fromKey: string, toKey: string) => Promise<void>;
}

export type Read = "kept" | "refused" | "held" | "nothing to do" | "not ours";

const IN = "in/";
const KEPT = "kept/";

interface ScanEvent {
  source?: string;
  "detail-type"?: string;
  detail?: { s3ObjectDetails?: { bucketName?: string; objectKey?: string }; scanResultDetails?: { scanResultStatus?: string } };
}

export async function read(event: unknown, r: Reader): Promise<Read> {
  const e = (typeof event === "object" && event !== null ? event : {}) as ScanEvent;
  const bucket = e.detail?.s3ObjectDetails?.bucketName;
  const key = e.detail?.s3ObjectDetails?.objectKey;
  const status = e.detail?.scanResultDetails?.scanResultStatus;
  if (e.source !== "aws.guardduty" || e["detail-type"] !== "GuardDuty Malware Protection Object Scan Result") return "not ours";
  if (bucket !== r.bucket || typeof key !== "string" || !key.startsWith(IN) || typeof status !== "string") return "not ours";
  const id = key.slice(IN.length);
  if (id === "" || id.includes("/")) return "not ours";
  const item = await r.shelf.get(id);
  if (item === undefined) return "nothing to do";
  if (status === "THREATS_FOUND") return (await r.shelf.refuse(id, "malware")) ? "refused" : "nothing to do";
  if (item.state !== "pending_scan") return "nothing to do";
  if (status === "NO_THREATS_FOUND") {
    // Copied first: if keeping fails, the retry copies again and keeps; the item never points at a missing copy.
    await r.copy(key, KEPT + id);
    return (await r.shelf.keep(id, KEPT + id)) ? "kept" : "nothing to do";
  }
  return (await r.shelf.hold(id, `the malware scan said ${status.toLowerCase().replace(/_/g, " ")}`)) ? "held" : "nothing to do";
}

/** Mail still waiting for its scan `days` after it arrived: raise each, well before its 30 days end. */
export async function stale(shelf: Shelf, now: Date, days = 3): Promise<string[]> {
  return shelf.pendingBefore(new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString());
}
