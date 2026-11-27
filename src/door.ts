/**
 * What happens to mail at a door, before anything reads it.
 *
 * - A **paired** sender (proven by DMARC-aligned mail) goes to its agent, under its Card.
 * - **Anyone else knocks**: kept for the owner, never sent to the AI, never read as instructions.
 *
 * The transports (SES first), the knocks' store and the Record come in their own changes.
 */
export type Door = "paired" | "knock";

/** A sender as the door sees it: its address, and whether this mail's From passed DMARC alignment. */
export interface Sender {
  address: string;
  dmarcAligned: boolean;
}

/** Which door the mail takes. Pairing counts only DMARC-aligned mail, so a spoofed From always knocks. */
export function door(sender: Sender, paired: ReadonlySet<string>): Door {
  return sender.dmarcAligned && paired.has(normalize(sender.address)) ? "paired" : "knock";
}

/** An address as pairing keys it: trimmed and lower-cased (a domain is case-insensitive, and nearly every mail server treats the mailbox name so too). */
export function normalize(address: string): string {
  return address.trim().toLowerCase();
}
