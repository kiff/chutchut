/**
 * The owner's knocks: mail from someone who isn't paired, kept 30 days for the owner, never sent to the AI unless
 * the owner hands it to an agent. What's listed is the knock's sender, its time and whether it was shown, never its
 * body: a knock's text is shown to the owner only when they open it, from its scanned raw copy.
 *
 * - `shownKnocks`: the knocks shown one by one, newest first, leaving out any past its 30 days. The table's TTL can
 *   take about two days to remove an item, so the list never relies on it.
 * - `digest`: the knocks kept for the day's digest (past a cap): how many, and from which senders, each once.
 */
export interface Knock {
  messageId: string;
  at: string;
  purgeAt: string;
  from?: string;
  shown: boolean;
}

export interface KnockShelf {
  /** Every knock still in the table, past its purgeAt or not. */
  knocks(): Promise<Knock[]>;
}

const live = (k: Knock, now: Date) => Date.parse(k.purgeAt) > now.getTime();

export async function shownKnocks(shelf: KnockShelf, now: Date): Promise<Knock[]> {
  return (await shelf.knocks()).filter((k) => k.shown && live(k, now)).sort((a, b) => b.at.localeCompare(a.at));
}

export interface Digest {
  count: number;
  /** Each sender once, in the order they first knocked; "(no sender)" for mail that had none. */
  senders: string[];
}

/** The knocks not shown on their own since `since`. */
export async function digest(shelf: KnockShelf, since: Date, now: Date): Promise<Digest> {
  const held = (await shelf.knocks())
    .filter((k) => !k.shown && live(k, now) && Date.parse(k.at) >= since.getTime())
    .sort((a, b) => a.at.localeCompare(b.at));
  const senders: string[] = [];
  for (const k of held) {
    const s = k.from ?? "(no sender)";
    if (!senders.includes(s)) senders.push(s);
  }
  return { count: held.length, senders };
}
