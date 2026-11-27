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
 * The addresses in an address-list header (RFC 5322 §3.4), in order, read strictly: a header that isn't a valid
 * address list gives undefined, never a guess. Mail systems read a malformed From differently, so SES could judge
 * DMARC on one domain while a looser reading here named another; strict reading means a malformed From has no sender.
 *
 * - A mailbox is an address, or a display name and then one address in angle brackets, and nothing after it but
 *   spaces and comments up to the next `,`, `;` or the end.
 * - A display name is words and quoted strings: an `@`, `<`, `>`, `[`, `]`, `:`, `;` or `\\` outside quotes isn't one.
 * - A backslash is allowed only inside a quoted string or a comment; a quoted local part isn't accepted.
 * - A group (`team: a@x, b@y;`) gives its members.
 */
export function mailboxes(header: string): string[] | undefined {
  const tokens = tokenize(header);
  if (tokens === undefined) return undefined;
  let i = 0;
  const peek = () => tokens[i];
  const special = (c: string) => peek()?.kind === "special" && peek()!.text === c;
  const out: string[] = [];

  const addrSpec = (): string | undefined => {
    const local = peek();
    if (local?.kind !== "atom") return undefined;
    i += 1;
    if (!special("@")) return undefined;
    i += 1;
    const domain = peek();
    if (domain?.kind !== "atom") return undefined;
    i += 1;
    const a = `${local.text}@${domain.text}`;
    return address(a) ? a : undefined;
  };

  const mailbox = (): string | undefined => {
    const start = i;
    // A bare address: an atom then "@".
    if (peek()?.kind === "atom" && tokens[i + 1]?.kind === "special" && tokens[i + 1]!.text === "@") return addrSpec();
    // Otherwise a display name (possibly none) and an angle address.
    while (peek()?.kind === "atom" || peek()?.kind === "quoted") i += 1;
    if (!special("<")) {
      i = start;
      return undefined;
    }
    i += 1;
    const a = addrSpec();
    if (a === undefined || !special(">")) return undefined;
    i += 1;
    return a;
  };

  while (i < tokens.length) {
    // A group: its name, ":", its members, ";".
    let j = i;
    while (tokens[j]?.kind === "atom" || tokens[j]?.kind === "quoted") j += 1;
    if (j > i && tokens[j]?.kind === "special" && tokens[j]!.text === ":") {
      i = j + 1;
      while (!special(";")) {
        const a = mailbox();
        if (a === undefined) return undefined;
        out.push(a);
        if (special(",")) i += 1;
        else if (!special(";")) return undefined;
      }
      i += 1;
    } else {
      const a = mailbox();
      if (a === undefined) return undefined;
      out.push(a);
    }
    if (i === tokens.length) break;
    if (!special(",")) return undefined;
    i += 1;
    if (i === tokens.length) return undefined;
  }
  return out;
}

type Token = { kind: "atom" | "quoted" | "special"; text: string };

/** The header's words, quoted strings and specials, with comments and spaces dropped. Undefined on anything unclosed or a stray backslash. */
function tokenize(header: string): Token[] | undefined {
  const out: Token[] = [];
  let i = 0;
  while (i < header.length) {
    const c = header[i]!;
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      i += 1;
    } else if (c === "(") {
      let depth = 1;
      i += 1;
      while (i < header.length && depth > 0) {
        if (header[i] === "\\") i += 1;
        else if (header[i] === "(") depth += 1;
        else if (header[i] === ")") depth -= 1;
        i += 1;
      }
      if (depth > 0) return undefined;
    } else if (c === '"') {
      let text = "";
      i += 1;
      for (;;) {
        if (i >= header.length) return undefined;
        if (header[i] === "\\") { text += header[i + 1] ?? ""; i += 2; continue; }
        if (header[i] === '"') { i += 1; break; }
        text += header[i];
        i += 1;
      }
      out.push({ kind: "quoted", text });
    } else if ("<>@,;:".includes(c)) {
      out.push({ kind: "special", text: c });
      i += 1;
    } else if ("[]\\)".includes(c)) {
      return undefined;
    } else {
      let text = "";
      while (i < header.length && !" \t\r\n()\"<>@,;:[]\\".includes(header[i]!)) { text += header[i]; i += 1; }
      out.push({ kind: "atom", text });
    }
  }
  return out;
}

/** One plain address: a local part and a domain, with no spaces and nothing quoted. */
function address(text: string): boolean {
  return /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(text);
}
