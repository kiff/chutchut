/**
 * Who a message says it's from, read from its From (and Sender) header as sent.
 *
 * Only a message with exactly one From mailbox, and no Sender naming someone else, has a sender at all: anything else
 * (no From, a group, several mailboxes, a Sender that differs) has none, and so it knocks. What's read is the
 * address only; a display name is never trusted, so "Ana <mallory@example.test>" is mallory@example.test.
 */
export function sender(from: string | undefined, senderHeader?: string): string | undefined {
  const fromBoxes = from === undefined ? [] : mailboxes(from);
  if (fromBoxes === undefined || fromBoxes.length !== 1) return undefined;
  const one = fromBoxes[0]!;
  if (senderHeader !== undefined && senderHeader.trim() !== "") {
    const by = mailboxes(senderHeader);
    if (by === undefined || by.length !== 1 || by[0]!.toLowerCase() !== one.toLowerCase()) return undefined;
  }
  return one;
}

/**
 * The addresses in an address-list header (RFC 5322 §3.4), in order: quoted strings and comments are skipped, so a
 * comma or angle bracket inside a display name never splits or names an address. A group (`team: a@x, b@y;`) gives
 * its members. Undefined when the header doesn't read as addresses.
 */
export function mailboxes(header: string): string[] | undefined {
  const out: string[] = [];
  let i = 0;
  let current = "";
  let angle: string | undefined;
  let inAngle = false;
  const end = () => {
    const address = (angle ?? current).trim();
    if (address !== "") out.push(address);
    current = "";
    angle = undefined;
  };
  while (i < header.length) {
    const c = header[i]!;
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === '"') {
      // A quoted string: skipped whole (it's a display name, or a quoted local part, which isn't accepted).
      const close = closing(header, i + 1, '"');
      if (close < 0) return undefined;
      if (inAngle) return undefined;
      current = "";
      i = close + 1;
      continue;
    }
    if (c === "(") {
      let depth = 1;
      i += 1;
      while (i < header.length && depth > 0) {
        if (header[i] === "\\") i += 1;
        else if (header[i] === "(") depth += 1;
        else if (header[i] === ")") depth -= 1;
        i += 1;
      }
      if (depth > 0) return undefined;
      continue;
    }
    if (c === "<") {
      if (inAngle) return undefined;
      inAngle = true;
      angle = "";
      i += 1;
      continue;
    }
    if (c === ">") {
      if (!inAngle) return undefined;
      inAngle = false;
      i += 1;
      continue;
    }
    if (inAngle) {
      angle += c;
      i += 1;
      continue;
    }
    if (c === ",") {
      end();
      i += 1;
      continue;
    }
    if (c === ":") {
      // A group's name: what came before is its display name, not an address.
      current = "";
      i += 1;
      continue;
    }
    if (c === ";") {
      end();
      i += 1;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      // Words before an angle address are a display name; a bare address has no spaces.
      if (current.trim() !== "" && angle === undefined) current += " ";
      i += 1;
      continue;
    }
    current += c;
    i += 1;
  }
  if (inAngle) return undefined;
  end();
  return out.every(address) ? out : undefined;
}

function closing(text: string, from: number, quote: string): number {
  for (let i = from; i < text.length; i++) {
    if (text[i] === "\\") i += 1;
    else if (text[i] === quote) return i;
  }
  return -1;
}

/** One plain address: a local part and a domain, with no spaces and nothing quoted. */
function address(text: string): boolean {
  return /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(text);
}
