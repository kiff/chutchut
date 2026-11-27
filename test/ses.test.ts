import { describe, expect, it } from "vitest";
import { pairing } from "../src/door.js";
import { route } from "../src/ses.js";

const bucket = "chutchut-inbound-test";
const paired = pairing(["ana@example.test"]);

function received(over: { verdicts?: Record<string, string>; headers?: [string, string][]; bucket?: string; type?: string; sesFrom?: unknown; truncated?: boolean } = {}): string {
  const headers = over.headers ?? [["From", "Ana <ana@example.test>"]];
  const firstFrom = headers.find(([name]) => name.toLowerCase() === "from")?.[1];
  const v = { spam: "PASS", virus: "PASS", dkim: "PASS", spf: "PASS", dmarc: "PASS", ...over.verdicts };
  return JSON.stringify({
    notificationType: over.type ?? "Received",
    mail: {
      messageId: "m-1", headersTruncated: over.truncated ?? false,
      headers: headers.map(([name, value]) => ({ name, value })),
      commonHeaders: { from: "sesFrom" in over ? over.sesFrom : firstFrom === undefined ? undefined : [firstFrom] },
    },
    receipt: {
      spamVerdict: { status: v.spam }, virusVerdict: { status: v.virus }, dkimVerdict: { status: v.dkim },
      spfVerdict: { status: v.spf }, dmarcVerdict: { status: v.dmarc },
      action: { type: "S3", bucketName: over.bucket ?? bucket, objectKey: "in/m-1" },
    },
  });
}

describe("ses", () => {
  it("sends a paired sender's clean, DMARC-passing mail to the paired door", () => {
    expect(route(received(), paired, bucket)).toEqual({ to: "paired", messageId: "m-1", objectKey: "in/m-1", from: "ana@example.test" });
  });

  it("makes it knock when DMARC didn't pass, or spam couldn't be judged", () => {
    for (const verdicts of <Record<string, string>[]>[{ dmarc: "FAIL" }, { dmarc: "GRAY" }, { dmarc: "PROCESSING_FAILED" }, { spam: "GRAY" }]) {
      expect(route(received({ verdicts }), paired, bucket)).toMatchObject({ to: "knock" });
    }
  });

  it("refuses a virus or spam, and holds mail whose virus scan didn't finish", () => {
    expect(route(received({ verdicts: { virus: "FAIL" } }), paired, bucket)).toMatchObject({ to: "refused", why: "a virus" });
    expect(route(received({ verdicts: { spam: "FAIL" } }), paired, bucket)).toMatchObject({ to: "refused", why: "spam" });
    expect(route(received({ verdicts: { virus: "GRAY" } }), paired, bucket)).toMatchObject({ to: "held" });
    expect(route(received({ verdicts: { virus: "PROCESSING_FAILED" } }), paired, bucket)).toMatchObject({ to: "held" });
  });

  it("knocks with no single From, two From headers, or a Sender naming someone else", () => {
    expect(route(received({ headers: [] }), paired, bucket)).toMatchObject({ to: "knock", from: undefined });
    expect(route(received({ headers: [["From", "ana@example.test"], ["from", "ana@example.test"]] }), paired, bucket)).toMatchObject({ to: "knock" });
    expect(route(received({ headers: [["From", "ana@example.test"], ["Sender", "mallory@example.test"]] }), paired, bucket)).toMatchObject({ to: "knock" });
    expect(route(received({ headers: [["From", '"ana@example.test" <mallory@example.test>']] }), paired, bucket)).toMatchObject({ to: "knock", from: "mallory@example.test" });
  });

  it("knocks when SES's own reading of From differs, or the header list was cut", () => {
    expect(route(received({ sesFrom: ["mallory@example.test"] }), paired, bucket)).toMatchObject({ to: "knock", from: undefined });
    expect(route(received({ sesFrom: ["ana@example.test", "b@example.test"] }), paired, bucket)).toMatchObject({ to: "knock" });
    expect(route(received({ sesFrom: [] }), paired, bucket)).toMatchObject({ to: "knock" });
    expect(route(received({ sesFrom: "ana@example.test" }), paired, bucket)).toMatchObject({ to: "knock" });
    expect(route(received({ sesFrom: ["ANA@example.test"] }), paired, bucket)).toMatchObject({ to: "paired" });
    expect(route(received({ truncated: true }), paired, bucket)).toMatchObject({ to: "knock", from: undefined });
  });

  it("is nothing for another bucket, another notification, or what isn't one", () => {
    expect(route(received({ bucket: "someone-elses" }), paired, bucket)).toBeUndefined();
    expect(route(received({ type: "Bounce" }), paired, bucket)).toBeUndefined();
    expect(route("not json", paired, bucket)).toBeUndefined();
    expect(route("null", paired, bucket)).toBeUndefined();
  });
});
