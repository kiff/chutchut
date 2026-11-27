import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { certificateURL, checkSns, stringToSign, type SnsMessage } from "../src/sns.js";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
const topicArn = "arn:aws:sns:eu-west-1:000000000000:loge-inbound";
const certURL = "https://sns.eu-west-1.amazonaws.com/SimpleNotificationService-0000.pem";
const now = new Date("2026-11-27T18:00:00Z");

function signed(fields: Partial<SnsMessage> = {}): SnsMessage {
  const m: SnsMessage = {
    Type: "Notification", MessageId: "m-1", TopicArn: topicArn, Message: '{"mail":{}}', Timestamp: "2026-11-27T17:59:00.000Z",
    SignatureVersion: "2", Signature: "", SigningCertURL: certURL, ...fields,
  };
  m.Signature = sign("RSA-SHA256", Buffer.from(stringToSign(m)), privateKey).toString("base64");
  return m;
}

const fetched: string[] = [];
const check = { topicArn, now: () => now, certificate: async (url: string) => { fetched.push(url); return pem; } };

describe("sns", () => {
  it("accepts a fresh notification from loge's topic, signed by SNS", async () => {
    const v = await checkSns(JSON.stringify(signed()), check);
    expect(v).toMatchObject({ ok: true });
    expect(await checkSns(JSON.stringify(signed({ Subject: "Amazon SES Email Receipt Notification" })), check)).toMatchObject({ ok: true });
  });

  it("refuses a message changed after it was signed", async () => {
    const m = signed();
    m.Message = '{"mail":{"forged":true}}';
    expect(await checkSns(JSON.stringify(m), check)).toEqual({ ok: false, why: "the signature doesn't check" });
  });

  it("refuses another topic, version 1, and a stale or future message", async () => {
    expect(await checkSns(JSON.stringify(signed({ TopicArn: "arn:aws:sns:eu-west-1:111111111111:other" })), check)).toEqual({ ok: false, why: "another topic" });
    expect(await checkSns(JSON.stringify(signed({ SignatureVersion: "1" })), check)).toEqual({ ok: false, why: "not signature version 2" });
    expect(await checkSns(JSON.stringify(signed({ Timestamp: "2026-11-27T16:00:00Z" })), check)).toEqual({ ok: false, why: "not fresh" });
    expect(await checkSns(JSON.stringify(signed({ Timestamp: "2026-11-27T19:00:00Z" })), check)).toEqual({ ok: false, why: "not fresh" });
  });

  it("never fetches a certificate from anywhere but an SNS host", async () => {
    fetched.length = 0;
    for (const url of [
      "http://sns.eu-west-1.amazonaws.com/a.pem",
      "https://sns.eu-west-1.amazonaws.com.evil.test/a.pem",
      "https://evil.test/sns.eu-west-1.amazonaws.com/a.pem",
      "https://sns.eu-west-1.amazonaws.com:8443/a.pem",
      "https://user@sns.eu-west-1.amazonaws.com/a.pem",
      "https://sns.eu-west-1.amazonaws.com/a.pem?x=1",
      "https://s3.eu-west-1.amazonaws.com/a.pem",
    ]) {
      expect(certificateURL(url), url).toBe(false);
      expect(await checkSns(JSON.stringify(signed({ SigningCertURL: url })), check)).toEqual({ ok: false, why: "a certificate from elsewhere" });
    }
    expect(fetched).toEqual([]);
    expect(certificateURL(certURL)).toBe(true);
  });

  it("refuses what isn't a whole SNS message", async () => {
    expect(await checkSns("nope", check)).toEqual({ ok: false, why: "not JSON" });
    expect(await checkSns("null", check)).toEqual({ ok: false, why: "not an SNS message" });
    expect(await checkSns(JSON.stringify({ ...signed(), Type: "Other" }), check)).toEqual({ ok: false, why: "not an SNS message" });
    const { MessageId: _, ...noId } = signed();
    expect(await checkSns(JSON.stringify(noId), check)).toEqual({ ok: false, why: "no MessageId" });
    expect(await checkSns(JSON.stringify(signed({ Signature: "" })), { ...check, certificate: async () => { throw new Error("down"); } })).toEqual({ ok: false, why: "the certificate can't be fetched" });
  });

  it("checks a subscription confirmation's own fields", async () => {
    const m = signed({ Type: "SubscriptionConfirmation", SubscribeURL: "https://sns.eu-west-1.amazonaws.com/?Action=ConfirmSubscription", Token: "t" });
    expect(await checkSns(JSON.stringify(m), check)).toMatchObject({ ok: true });
    expect(await checkSns(JSON.stringify({ ...m, Token: "other" }), check)).toEqual({ ok: false, why: "the signature doesn't check" });
  });
});
