import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// DynamoDB refuses an expression that names an attribute by one of its reserved words ("Attribute name is a reserved
// keyword"), and only at run time, against the real table: `auth` in the provider's read failed every message tafs asked
// for, while every test passed. So every expression in the source is read here, and a reserved word left bare (not as a
// #name in ExpressionAttributeNames) fails the build.
const reserved = new Set(
  readFileSync(join(__dirname, "fixtures", "dynamodb-reserved-words.txt"), "utf8")
    .split("\n").map((l) => l.trim().toUpperCase()).filter((l) => l !== "" && !l.startsWith("#")),
);

// The expression grammar's own words and functions: these are how an expression is written, not attribute names.
const GRAMMAR = new Set([
  "SET", "ADD", "REMOVE", "DELETE", "AND", "OR", "NOT", "BETWEEN", "IN",
  "ATTRIBUTE_EXISTS", "ATTRIBUTE_NOT_EXISTS", "ATTRIBUTE_TYPE", "BEGINS_WITH", "CONTAINS", "SIZE", "IF_NOT_EXISTS", "LIST_APPEND",
]);

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return name.endsWith(".ts") ? [path] : [];
  });
}

/** Every string literal in the file that is a DynamoDB expression: a value given to an `…Expression` key, or a literal
 * written like one (it uses a #name or a :value, or starts with SET, ADD or REMOVE), as the store's helpers take. */
export function expressions(code: string): string[] {
  const found = new Set<string>();
  for (const m of code.matchAll(/(?:Projection|KeyCondition|Filter|Update|Condition)Expression\s*:\s*(["'`])((?:(?!\1).)*)\1/g)) found.add(m[2]!);
  for (const m of code.matchAll(/(["'`])((?:(?!\1)[^\n])*)\1/g)) {
    const s = m[2]!;
    if (/(^|[\s,(])[#:][A-Za-z_]/.test(s) || /^(SET|ADD|REMOVE)\s/.test(s)) found.add(s);
  }
  return [...found];
}

/** The attribute names an expression uses bare: every word that isn't a #name, a :value, or the grammar's own. */
export function bareNames(expression: string): string[] {
  return [...expression.replace(/\$\{[^}]*\}/g, " ").matchAll(/(^|[^#:A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)/g)]
    .map((m) => m[2]!)
    .filter((w) => !GRAMMAR.has(w.toUpperCase()));
}

describe("DynamoDB expressions", () => {
  it("name no attribute by a reserved word, anywhere in the source", () => {
    const bare: string[] = [];
    for (const file of sources(join(__dirname, "..", "src"))) {
      for (const e of expressions(readFileSync(file, "utf8"))) {
        for (const w of bareNames(e)) if (reserved.has(w.toUpperCase())) bare.push(`${file.split("/src/")[1]}: ${w} in "${e}"`);
      }
    }
    expect(bare).toEqual([]);
  });

  it("finds a bare reserved word, and leaves #names, :values and the grammar alone", () => {
    expect(reserved.size).toBeGreaterThan(500);
    const code = `x({ ProjectionExpression: "#s, shown, auth", UpdateExpression: "SET #s = :s, n = if_not_exists(n, :zero)" }); change(id, "REMOVE expiresAt, purgeAt");`;
    expect(expressions(code)).toEqual(expect.arrayContaining(["#s, shown, auth", "SET #s = :s, n = if_not_exists(n, :zero)", "REMOVE expiresAt, purgeAt"]));
    expect(bareNames("#s, shown, auth").filter((w) => reserved.has(w.toUpperCase()))).toEqual(["auth"]);
    expect(bareNames("SET #s = :s, n = if_not_exists(n, :zero)")).toEqual(["n", "n"]);
    expect(bareNames("attribute_not_exists(pk) OR #s = :failed")).toEqual(["pk"]);
  });
});
