import { ConditionalCheckFailedException, GetItemCommand, ScanCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { describe, expect, it } from "vitest";
import { dynamoShelf } from "../src/dynamo.js";
import { read, stale, type Reader, type Shelf } from "../src/reader.js";

const bucket = "chutchut-inbound-test";

type Item = { state: string; at: string; purgeAt?: string; from?: string; objectKey: string; why?: string; shown?: boolean; clean?: boolean; notified?: boolean };

/** A shelf in memory, with the same state rules as the table's conditional updates. */
function memory(items: Record<string, Item>): Shelf {
  return {
    async get(id) { const i = items[id]; return i && { state: i.state, at: i.at, shown: i.shown, clean: i.clean, notified: i.notified }; },
    async clear(id) {
      const i = items[id];
      if (i?.state === "pending_scan") { items[id] = { ...i, state: "clean", clean: true }; return true; }
      if (i?.state === "knock" && i.shown) { items[id] = { ...i, clean: true }; return true; }
      return false;
    },
    async notified(id) { const i = items[id]!; if (i.notified) return false; i.notified = true; return true; },
    async keep(id, kept) {
      const i = items[id];
      if (i?.state !== "pending_scan") return false;
      items[id] = { state: "mail", at: i.at, objectKey: kept, ...(i.from ? { from: i.from } : {}) };
      return true;
    },
    async refuse(id, why) {
      const i = items[id];
      if (!i || !["pending_scan", "knock", "held"].includes(i.state)) return false;
      items[id] = { state: "refused", at: i.at, objectKey: i.objectKey, why, ...(i.purgeAt ? { purgeAt: i.purgeAt } : {}) };
      return true;
    },
    async hold(id, why) {
      const i = items[id];
      if (i?.state !== "pending_scan") return false;
      items[id] = { ...i, state: "held", why };
      return true;
    },
    async pendingBefore(before) { return Object.entries(items).filter(([, i]) => i.state === "pending_scan" && i.at < before).map(([id]) => id); },
  };
}

function scan(key: string, status: string, over: Record<string, unknown> = {}) {
  return {
    source: "aws.guardduty", "detail-type": "GuardDuty Malware Protection Object Scan Result",
    detail: { s3ObjectDetails: { bucketName: bucket, objectKey: key }, scanResultDetails: { scanResultStatus: status } }, ...over,
  };
}

function setup(items: Record<string, Item>, mode: "inbox" | "tafs" = "inbox", failNotify = 0) {
  const copies: [string, string][] = [];
  const told: string[] = [];
  let failing = failNotify;
  const r: Reader = {
    bucket, mode, shelf: memory(items), copy: async (a, b) => { copies.push([a, b]); },
    notify: async (id) => { if (failing > 0) { failing -= 1; throw new Error("tafs down"); } told.push(id); },
  };
  return { r, items, copies, told };
}

const pending = (at = "2026-11-27T18:00:00.000Z"): Item => ({ state: "pending_scan", at, purgeAt: "2026-12-27T18:00:00.000Z", from: "ana@example.test", objectKey: "in/m1" });

describe("reader", () => {
  it("keeps a paired sender's clean mail: copied out of in/, its expiry gone, so it outlives the 30 days", async () => {
    const { r, items, copies } = setup({ m1: pending() });
    expect(await read(scan("in/m1", "NO_THREATS_FOUND"), r)).toBe("kept");
    expect(copies).toEqual([["in/m1", "kept/m1"]]);
    expect(items.m1).toEqual({ state: "mail", at: "2026-11-27T18:00:00.000Z", objectKey: "kept/m1", from: "ana@example.test" });
    expect(items.m1).not.toHaveProperty("purgeAt");
  });

  it("refuses mail with malware, whatever it waited as, and drops its sender's address", async () => {
    const { r, items } = setup({
      m1: pending(),
      k1: { state: "knock", at: "2026-11-27T18:00:00.000Z", purgeAt: "2026-12-27T18:00:00.000Z", from: "bob@stranger.test", objectKey: "in/k1" },
    });
    expect(await read(scan("in/m1", "THREATS_FOUND"), r)).toBe("refused");
    expect(await read(scan("in/k1", "THREATS_FOUND"), r)).toBe("refused");
    for (const id of ["m1", "k1"]) {
      expect(items[id]).toMatchObject({ state: "refused", why: "malware", purgeAt: "2026-12-27T18:00:00.000Z" });
      expect(items[id]).not.toHaveProperty("from");
    }
  });

  it("holds mail whose scan didn't finish, for the owner", async () => {
    for (const status of ["UNSUPPORTED", "ACCESS_DENIED", "FAILED"]) {
      const { r, items, copies } = setup({ m1: pending() });
      expect(await read(scan("in/m1", status), r)).toBe("held");
      expect(items.m1!.state).toBe("held");
      expect(copies).toEqual([]);
    }
  });

  it("never reads a knock's body because its scan was clean, and does nothing twice", async () => {
    const { r, items, copies } = setup({ k1: { state: "knock", at: "x", purgeAt: "y", objectKey: "in/k1" }, m1: pending() });
    expect(await read(scan("in/k1", "NO_THREATS_FOUND"), r)).toBe("nothing to do");
    expect(items.k1!.state).toBe("knock");
    await read(scan("in/m1", "NO_THREATS_FOUND"), r);
    expect(await read(scan("in/m1", "NO_THREATS_FOUND"), r)).toBe("nothing to do");
    expect(copies).toHaveLength(1);
  });

  it("isn't moved by an event that isn't GuardDuty's result for this bucket's in/", async () => {
    const { r, items, copies } = setup({ m1: pending() });
    for (const e of [
      scan("in/m1", "NO_THREATS_FOUND", { source: "aws.s3" }),
      scan("in/m1", "NO_THREATS_FOUND", { "detail-type": "Other" }),
      { ...scan("in/m1", "NO_THREATS_FOUND"), detail: { s3ObjectDetails: { bucketName: "other", objectKey: "in/m1" }, scanResultDetails: { scanResultStatus: "NO_THREATS_FOUND" } } },
      scan("kept/m1", "NO_THREATS_FOUND"), scan("in/", "NO_THREATS_FOUND"), scan("in/a/m1", "NO_THREATS_FOUND"),
      null, "x",
    ]) {
      expect(await read(e, r)).toBe("not ours");
    }
    expect(await read(scan("in/unknown", "NO_THREATS_FOUND"), r)).toBe("nothing to do");
    expect(items.m1!.state).toBe("pending_scan");
    expect(copies).toEqual([]);
  });

  it("raises mail still waiting for its scan after three days, well before its 30", async () => {
    const shelf = memory({ old: pending("2026-11-20T00:00:00.000Z"), fresh: pending("2026-11-27T00:00:00.000Z"), kept: { state: "mail", at: "2026-11-01T00:00:00.000Z", objectKey: "kept/kept" } });
    expect(await stale(shelf, new Date("2026-11-27T18:00:00Z"))).toEqual(["old"]);
  });
});

describe("reader, as tafs cloud's mail provider", () => {
  it("keeps nothing for good: clean mail is marked clean with its 30 days, and tafs is told once", async () => {
    const { r, items, copies, told } = setup({ m1: pending() }, "tafs");
    expect(await read(scan("in/m1", "NO_THREATS_FOUND"), r)).toBe("told");
    expect(items.m1).toMatchObject({ state: "clean", purgeAt: "2026-12-27T18:00:00.000Z", notified: true });
    expect(copies).toEqual([]);
    expect(await read(scan("in/m1", "NO_THREATS_FOUND"), r)).toBe("nothing to do");
    expect(told).toEqual(["m1"]);
  });

  it("tells tafs about a shown knock once it's clean, never one kept for the digest", async () => {
    const { r, items, told } = setup({
      k1: { state: "knock", at: "a", purgeAt: "p", objectKey: "in/k1", shown: true },
      k2: { state: "knock", at: "a", purgeAt: "p", objectKey: "in/k2", shown: false },
    }, "tafs");
    expect(await read(scan("in/k1", "NO_THREATS_FOUND"), r)).toBe("told");
    expect(await read(scan("in/k2", "NO_THREATS_FOUND"), r)).toBe("nothing to do");
    expect(told).toEqual(["k1"]);
    expect(items.k1).toMatchObject({ state: "knock", clean: true });
    expect(items.k2!.clean).toBeUndefined();
  });

  it("tells tafs on the retry when telling failed, and never before the scan", async () => {
    const { r, told } = setup({ m1: pending() }, "tafs", 1);
    await expect(read(scan("in/m1", "NO_THREATS_FOUND"), r)).rejects.toThrow("tafs down");
    expect(told).toEqual([]);
    expect(await read(scan("in/m1", "NO_THREATS_FOUND"), r)).toBe("told");
    expect(told).toEqual(["m1"]);
    const held = setup({ m2: pending() }, "tafs");
    expect(await read(scan("in/m2", "FAILED"), held.r)).toBe("held");
    expect(held.told).toEqual([]);
  });
});

describe("dynamo shelf", () => {
  function fake(conditionFails = false) {
    const sent: any[] = [];
    return {
      sent,
      async send(c: any): Promise<any> {
        sent.push(c);
        if (c instanceof UpdateItemCommand && conditionFails) throw new ConditionalCheckFailedException({ message: "no", $metadata: {} });
        if (c instanceof GetItemCommand) return { Item: { state: { S: "pending_scan" }, at: { S: "t" } } };
        if (c instanceof ScanCommand) return c.input.ExclusiveStartKey ? { Items: [{ messageId: { S: "b" } }] } : { Items: [{ messageId: { S: "a" } }], LastEvaluatedKey: { pk: { S: "x" } } };
        return {};
      },
    };
  }

  it("keeps mail by removing its expiry, only from pending_scan", async () => {
    const db = fake();
    expect(await dynamoShelf(db, "t").keep("m1", "kept/m1")).toBe(true);
    expect(db.sent[0].input).toMatchObject({
      UpdateExpression: "SET #s = :mail, objectKey = :kept REMOVE expiresAt, purgeAt", ConditionExpression: "#s = :pending",
    });
  });

  it("refuses by removing the sender's address, naming DynamoDB's reserved words", async () => {
    const db = fake();
    await dynamoShelf(db, "t").refuse("m1", "malware");
    expect(db.sent[0].input).toMatchObject({
      UpdateExpression: "SET #s = :refused, why = :why REMOVE #from, shown",
      ExpressionAttributeNames: { "#s": "state", "#from": "from" }, ConditionExpression: "#s IN (:pending, :knock, :held)",
    });
  });

  it("answers false when the item isn't in the state a change needs", async () => {
    const shelf = dynamoShelf(fake(true), "t");
    expect(await shelf.keep("m1", "kept/m1")).toBe(false);
    expect(await shelf.hold("m1", "x")).toBe(false);
  });

  it("reads every page when listing mail still waiting", async () => {
    expect(await dynamoShelf(fake(), "t").pendingBefore("2026-11-24")).toEqual(["a", "b"]);
  });
});
