import { ScanCommand } from "@aws-sdk/client-dynamodb";
import { describe, expect, it } from "vitest";
import { dynamoKnocks } from "../src/dynamo.js";
import { digest, shownKnocks, type Knock } from "../src/knocks.js";

const now = new Date("2026-11-27T18:00:00Z");
const k = (id: string, at: string, shown: boolean, from?: string, purgeAt = "2026-12-27T00:00:00.000Z"): Knock =>
  ({ messageId: id, at, purgeAt, shown, ...(from ? { from } : {}) });
const shelf = (items: Knock[]) => ({ knocks: async () => items });

describe("knocks", () => {
  it("lists the knocks shown one by one, newest first, never one past its 30 days", async () => {
    const items = [
      k("a", "2026-11-27T09:00:00Z", true, "a@x.test"),
      k("b", "2026-11-27T10:00:00Z", true, "b@x.test"),
      k("c", "2026-11-27T11:00:00Z", false, "c@x.test"),
      k("old", "2026-10-27T09:00:00Z", true, "o@x.test", "2026-11-26T09:00:00.000Z"),
    ];
    expect((await shownKnocks(shelf(items), now)).map((x) => x.messageId)).toEqual(["b", "a"]);
  });

  it("gathers the rest into the day's digest: how many, and each sender once", async () => {
    const items = [
      k("1", "2026-11-27T08:00:00Z", false, "spam@x.test"),
      k("2", "2026-11-27T09:00:00Z", false, "spam@x.test"),
      k("3", "2026-11-27T10:00:00Z", false),
      k("4", "2026-11-27T11:00:00Z", true, "shown@x.test"),
      k("5", "2026-11-25T11:00:00Z", false, "yesterday@x.test"),
    ];
    expect(await digest(shelf(items), new Date("2026-11-26T18:00:00Z"), now)).toEqual({ count: 3, senders: ["spam@x.test", "(no sender)"] });
  });

  it("reads every knock from the table, page by page, with no body", async () => {
    const sent: ScanCommand[] = [];
    const db = {
      async send(c: ScanCommand): Promise<any> {
        sent.push(c);
        return c.input.ExclusiveStartKey
          ? { Items: [{ messageId: { S: "b" }, at: { S: "t2" }, purgeAt: { S: "p" }, shown: { S: "no" } }] }
          : { Items: [{ messageId: { S: "a" }, at: { S: "t1" }, purgeAt: { S: "p" }, from: { S: "a@x.test" }, shown: { S: "yes" } }, { at: { S: "broken" } }], LastEvaluatedKey: { pk: { S: "x" } } };
      },
    };
    expect(await dynamoKnocks(db, "t").knocks()).toEqual([
      { messageId: "a", at: "t1", purgeAt: "p", from: "a@x.test", shown: true },
      { messageId: "b", at: "t2", purgeAt: "p", shown: false },
    ]);
    expect(sent[0]!.input.ProjectionExpression).toBe("messageId, #at, purgeAt, #from, shown");
  });
});
