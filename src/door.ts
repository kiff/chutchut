/**
 * What happens to mail at a door, before anything reads it.
 *
 * - A **paired** sender (proven by DMARC-aligned mail) goes to its agent, under its Card.
 * - **Anyone else knocks**: kept for the owner, not sent to the AI unless the owner hands it to an agent (Do it),
 *   and never read as instructions.
 *
 * The transports (SES first), the knocks' store and the Record come in their own changes.
 */
export type Door = "paired" | "knock";

/** A sender as the door sees it: its address, and whether this mail's From passed DMARC alignment. */
export interface Sender {
  address: string;
  dmarcAligned: boolean;
}

/**
 * Which door the mail takes. Pairing counts only DMARC-aligned mail, so a spoofed From always knocks.
 *
 * DMARC proves the From's **domain**, not the mailbox: on a domain whose own users can send as any address, one of
 * them passes as a paired sender. Pairing says so to the owner where it's set up, and a paired sender stays under its
 * Card either way.
 *
 * `paired` comes from `pairing`, so its addresses are keyed as the sender's is.
 */
export function door(sender: Sender, paired: Pairing): Door {
  return sender.dmarcAligned && paired.has(normalize(sender.address)) ? "paired" : "knock";
}

/** The paired addresses, each keyed by `normalize`: the only way to make what `door` reads. */
export type Pairing = ReadonlySet<string> & { readonly __pairing: true };

export function pairing(addresses: Iterable<string>): Pairing {
  return new Set([...addresses].map(normalize)) as unknown as Pairing;
}

/**
 * Every proven sender, for chutchut as tafs cloud's mail provider: tafs keeps the pairing, so chutchut sends every
 * proven sender's mail on and lets tafs decide key or knock. Proof is still required: an unproven sender still knocks.
 */
export function anyone(): Pairing {
  return { has: () => true, size: Infinity, [Symbol.iterator]: function* () {} } as unknown as Pairing;
}

/** An address as pairing keys it: trimmed and lower-cased (a domain is case-insensitive, and nearly every mail server treats the mailbox name so too). */
export function normalize(address: string): string {
  return address.trim().toLowerCase();
}
